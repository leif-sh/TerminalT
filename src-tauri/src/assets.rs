use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    credentials::CredentialVault,
    error::AppError,
    models::{
        AssetTransferSummary, AuthType, ConnectionAssetSnapshot, ConnectionGroup,
        ConnectionProfile, GroupNameRequest, RecentTarget, SaveConnectionRequest,
        SaveTunnelRequest, TunnelKind, TunnelProfile,
    },
};

pub const DEFAULT_GROUP_ID: &str = "default";
const SCHEMA_VERSION: u16 = 3;
const MAX_RECENT_TARGETS: usize = 10;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AssetDocument {
    schema_version: u16,
    groups: Vec<ConnectionGroup>,
    connections: Vec<ConnectionProfile>,
    recent_targets: Vec<RecentTarget>,
    #[serde(default)]
    tunnels: Vec<TunnelProfile>,
}

impl Default for AssetDocument {
    fn default() -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            schema_version: SCHEMA_VERSION,
            groups: vec![ConnectionGroup {
                id: DEFAULT_GROUP_ID.to_owned(),
                name: "默认分组".to_owned(),
                created_at: now.clone(),
                updated_at: now,
            }],
            connections: Vec::new(),
            recent_targets: Vec::new(),
            tunnels: Vec::new(),
        }
    }
}

pub struct AssetStore {
    path: PathBuf,
    vault: Arc<dyn CredentialVault>,
    lock: Mutex<()>,
}

impl AssetStore {
    pub fn new(path: PathBuf, vault: Arc<dyn CredentialVault>) -> Self {
        Self {
            path,
            vault,
            lock: Mutex::new(()),
        }
    }

    pub fn snapshot(&self) -> Result<ConnectionAssetSnapshot, AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        document.connections.sort_by(|left, right| {
            right
                .last_connected_at
                .cmp(&left.last_connected_at)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        Ok(ConnectionAssetSnapshot {
            schema_version: document.schema_version,
            default_group_id: DEFAULT_GROUP_ID.to_owned(),
            groups: document.groups,
            connections: document.connections,
            recent_targets: document.recent_targets,
            tunnels: document.tunnels,
        })
    }

    pub fn save_connection(
        &self,
        request: SaveConnectionRequest,
    ) -> Result<ConnectionProfile, AppError> {
        validate_connection(&request)?;
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        if !document
            .groups
            .iter()
            .any(|group| group.id == request.group_id)
        {
            return Err(AppError::asset_not_found("group", &request.group_id));
        }

        let now = Utc::now().to_rfc3339();
        let id = request
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let existing = document
            .connections
            .iter()
            .find(|item| item.id == id)
            .cloned();
        if request.id.is_some() && existing.is_none() {
            return Err(AppError::asset_not_found("connection", &id));
        }
        validate_jump_hosts(&document.connections, &id, &request.jump_host_ids)?;
        let created_at = existing
            .as_ref()
            .map_or_else(|| now.clone(), |item| item.created_at.clone());
        let credential_ref = (request.remember_credential
            && matches!(request.auth_type, AuthType::Password | AuthType::PrivateKey))
        .then(|| credential_reference(&id, request.auth_type));
        let prior_ref = existing
            .as_ref()
            .and_then(|item| item.credential_ref.clone());
        let prior_secret = prior_ref
            .as_deref()
            .map(|reference| self.vault.get(reference))
            .transpose()?
            .flatten();
        let proxy_credential_ref = request
            .proxy
            .as_ref()
            .filter(|proxy| proxy.remember_credential && proxy.username.is_some())
            .map(|_| proxy_credential_reference(&id));
        let prior_proxy_ref = existing
            .as_ref()
            .and_then(|item| item.proxy.as_ref())
            .and_then(|proxy| proxy.credential_ref.clone());
        let prior_proxy_secret = prior_proxy_ref
            .as_deref()
            .map(|reference| self.vault.get(reference))
            .transpose()?
            .flatten();

        if let Some(reference) = credential_ref.as_deref() {
            if let Some(secret) = request
                .secret
                .as_deref()
                .filter(|secret| !secret.is_empty())
            {
                self.vault.set(reference, secret)?;
            } else if existing
                .as_ref()
                .and_then(|item| item.credential_ref.as_deref())
                != Some(reference)
            {
                return Err(AppError::credential(
                    "CREDENTIAL-REQUIRED",
                    "请输入需要保存的凭据",
                    "remember credential requested without a secret",
                    false,
                ));
            }
        }

        if let Some(reference) = proxy_credential_ref.as_deref() {
            if let Some(password) = request
                .proxy
                .as_ref()
                .and_then(|proxy| proxy.password.as_deref())
                .filter(|password| !password.is_empty())
            {
                self.vault.set(reference, password)?;
            } else if prior_proxy_ref.as_deref() != Some(reference) {
                rollback_credential(
                    self.vault.as_ref(),
                    credential_ref.as_deref(),
                    prior_ref.as_deref(),
                    prior_secret.as_deref().map(String::as_str),
                );
                return Err(AppError::credential(
                    "PROXY-CREDENTIAL-REQUIRED",
                    "请输入需要保存的代理密码",
                    "proxy credential storage requested without a password",
                    false,
                ));
            }
        }

        let profile = ConnectionProfile {
            id: id.clone(),
            name: request.name.trim().to_owned(),
            host: request.host.trim().to_owned(),
            port: request.port,
            username: request.username.trim().to_owned(),
            auth_type: request.auth_type,
            credential_ref: credential_ref.clone(),
            private_key_path: request.private_key_path.filter(|value| !value.is_empty()),
            agent_key_fingerprint: request
                .agent_key_fingerprint
                .filter(|value| !value.is_empty()),
            proxy: request.proxy.map(|proxy| crate::models::ProxyProfile {
                proxy_type: proxy.proxy_type,
                host: proxy.host.trim().to_owned(),
                port: proxy.port,
                username: proxy
                    .username
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty()),
                credential_ref: proxy_credential_ref.clone(),
            }),
            jump_host_ids: request.jump_host_ids,
            group_id: request.group_id,
            note: request
                .note
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            timeout_seconds: request.timeout_seconds,
            last_connected_at: existing
                .as_ref()
                .and_then(|item| item.last_connected_at.clone()),
            created_at,
            updated_at: now,
        };
        document.connections.retain(|item| item.id != id);
        document.connections.push(profile.clone());

        if prior_ref != credential_ref {
            if let Some(reference) = prior_ref.as_deref() {
                if let Err(error) = self.vault.delete(reference) {
                    if let Some(reference) = credential_ref.as_deref() {
                        let _ = self.vault.delete(reference);
                    }
                    return Err(error);
                }
            }
        }
        if prior_proxy_ref != proxy_credential_ref {
            if let Some(reference) = prior_proxy_ref.as_deref() {
                if let Err(error) = self.vault.delete(reference) {
                    rollback_credential(
                        self.vault.as_ref(),
                        credential_ref.as_deref(),
                        prior_ref.as_deref(),
                        prior_secret.as_deref().map(String::as_str),
                    );
                    rollback_credential(
                        self.vault.as_ref(),
                        proxy_credential_ref.as_deref(),
                        prior_proxy_ref.as_deref(),
                        prior_proxy_secret.as_deref().map(String::as_str),
                    );
                    return Err(error);
                }
            }
        }

        if let Err(error) = self.write_document(&document) {
            rollback_credential(
                self.vault.as_ref(),
                credential_ref.as_deref(),
                prior_ref.as_deref(),
                prior_secret.as_deref().map(String::as_str),
            );
            rollback_credential(
                self.vault.as_ref(),
                proxy_credential_ref.as_deref(),
                prior_proxy_ref.as_deref(),
                prior_proxy_secret.as_deref().map(String::as_str),
            );
            return Err(error);
        }
        Ok(profile)
    }

    pub fn copy_connection(&self, id: &str) -> Result<ConnectionProfile, AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        let source = document
            .connections
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| AppError::asset_not_found("connection", id))?;
        let now = Utc::now().to_rfc3339();
        let copy = ConnectionProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name: duplicate_name(&source.name, &document.connections),
            credential_ref: None,
            proxy: source.proxy.clone().map(|mut proxy| {
                proxy.credential_ref = None;
                proxy
            }),
            last_connected_at: None,
            created_at: now.clone(),
            updated_at: now,
            ..source
        };
        document.connections.push(copy.clone());
        self.write_document(&document)?;
        Ok(copy)
    }

    pub fn delete_connection(&self, id: &str) -> Result<(), AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        let profile = document
            .connections
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| AppError::asset_not_found("connection", id))?;
        if document.connections.iter().any(|connection| {
            connection.id != id && connection.jump_host_ids.iter().any(|jump| jump == id)
        }) {
            return Err(AppError::validation("该连接正被跳板链引用，请先解除引用"));
        }
        if document
            .tunnels
            .iter()
            .any(|tunnel| tunnel.connection_id == id)
        {
            return Err(AppError::validation(
                "该连接仍有关联隧道规则，请先删除隧道规则",
            ));
        }
        let secret = profile
            .credential_ref
            .as_deref()
            .map(|reference| self.vault.get(reference))
            .transpose()?
            .flatten();
        let proxy_secret = profile
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.credential_ref.as_deref())
            .map(|reference| self.vault.get(reference))
            .transpose()?
            .flatten();
        if let Some(reference) = profile.credential_ref.as_deref() {
            self.vault.delete(reference)?;
        }
        if let Some(reference) = profile
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.credential_ref.as_deref())
        {
            if let Err(error) = self.vault.delete(reference) {
                if let (Some(reference), Some(secret)) =
                    (profile.credential_ref.as_deref(), secret.as_ref())
                {
                    let _ = self.vault.set(reference, secret);
                }
                return Err(error);
            }
        }
        document.connections.retain(|item| item.id != id);
        if let Err(error) = self.write_document(&document) {
            if let (Some(reference), Some(secret)) =
                (profile.credential_ref.as_deref(), secret.as_ref())
            {
                let _ = self.vault.set(reference, secret);
            }
            if let (Some(reference), Some(secret)) = (
                profile
                    .proxy
                    .as_ref()
                    .and_then(|proxy| proxy.credential_ref.as_deref()),
                proxy_secret.as_ref(),
            ) {
                let _ = self.vault.set(reference, secret);
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn save_group(&self, request: GroupNameRequest) -> Result<ConnectionGroup, AppError> {
        let name = request.name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(AppError::validation("分组名称长度必须为 1～64 个字符"));
        }
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        if document.groups.iter().any(|group| {
            group.name.eq_ignore_ascii_case(name) && Some(&group.id) != request.id.as_ref()
        }) {
            return Err(AppError::validation("分组名称已存在"));
        }
        let now = Utc::now().to_rfc3339();
        let group = match request.id {
            Some(id) => {
                if id == DEFAULT_GROUP_ID {
                    return Err(AppError::validation("默认分组不可重命名"));
                }
                let group = document
                    .groups
                    .iter_mut()
                    .find(|group| group.id == id)
                    .ok_or_else(|| AppError::asset_not_found("group", &id))?;
                group.name = name.to_owned();
                group.updated_at = now;
                group.clone()
            }
            None => {
                let group = ConnectionGroup {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: name.to_owned(),
                    created_at: now.clone(),
                    updated_at: now,
                };
                document.groups.push(group.clone());
                group
            }
        };
        self.write_document(&document)?;
        Ok(group)
    }

    pub fn delete_group(&self, id: &str) -> Result<(), AppError> {
        if id == DEFAULT_GROUP_ID {
            return Err(AppError::validation("默认分组不可删除"));
        }
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        if !document.groups.iter().any(|group| group.id == id) {
            return Err(AppError::asset_not_found("group", id));
        }
        document.groups.retain(|group| group.id != id);
        for connection in &mut document.connections {
            if connection.group_id == id {
                connection.group_id = DEFAULT_GROUP_ID.to_owned();
                connection.updated_at = Utc::now().to_rfc3339();
            }
        }
        self.write_document(&document)
    }

    #[cfg(test)]
    pub fn connection_request(
        &self,
        id: &str,
        temporary_secret: Option<String>,
    ) -> Result<crate::models::ConnectionRequest, AppError> {
        self.connection_route_requests(id, temporary_secret)?
            .pop()
            .ok_or_else(|| AppError::asset_not_found("connection", id))
    }

    pub fn connection_route_requests(
        &self,
        id: &str,
        temporary_secret: Option<String>,
    ) -> Result<Vec<crate::models::ConnectionRequest>, AppError> {
        let _guard = self.lock()?;
        let document = self.read_document()?;
        let target = document
            .connections
            .iter()
            .find(|item| item.id == id)
            .ok_or_else(|| AppError::asset_not_found("connection", id))?;
        let mut profile_ids = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut visiting = std::collections::HashSet::new();
        collect_route_profiles(
            &document.connections,
            target,
            &mut visited,
            &mut visiting,
            &mut profile_ids,
        )?;
        let mut route = Vec::with_capacity(profile_ids.len() + 1);
        for profile_id in profile_ids {
            let profile = document
                .connections
                .iter()
                .find(|profile| profile.id == profile_id)
                .ok_or_else(|| AppError::asset_not_found("jump-host", &profile_id))?;
            route.push(self.request_from_profile(profile, None, true)?);
        }
        route.push(self.request_from_profile(target, temporary_secret, false)?);
        Ok(route)
    }

    fn request_from_profile(
        &self,
        profile: &ConnectionProfile,
        temporary_secret: Option<String>,
        jump_host: bool,
    ) -> Result<crate::models::ConnectionRequest, AppError> {
        let secret = match temporary_secret {
            Some(secret) => Some(Zeroizing::new(secret)),
            None => profile
                .credential_ref
                .as_deref()
                .map(|reference| self.vault.get(reference))
                .transpose()?
                .flatten(),
        };
        let proxy_password = profile
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.credential_ref.as_deref())
            .map(|reference| self.vault.get(reference))
            .transpose()?
            .flatten();
        if profile.auth_type == AuthType::Password && secret.is_none()
            || profile.credential_ref.is_some() && secret.is_none()
        {
            return Err(if jump_host {
                AppError::ssh(
                    "JUMP-HOST-FAILED",
                    format!("跳板“{}”缺少已保存凭据", profile.name),
                    format!("jump host {} has no available credential", profile.id),
                    true,
                )
            } else {
                AppError::credential(
                    "CREDENTIAL-MISSING",
                    "未找到已保存凭据，请重新输入",
                    "credential reference is absent or missing from Windows Credential Manager",
                    true,
                )
            });
        }
        Ok(crate::models::ConnectionRequest {
            name: profile.name.clone(),
            host: profile.host.clone(),
            port: profile.port,
            username: profile.username.clone(),
            auth_type: profile.auth_type,
            password: (profile.auth_type == AuthType::Password).then(|| {
                secret
                    .as_ref()
                    .map(|value| value.to_string())
                    .unwrap_or_default()
            }),
            private_key_path: profile.private_key_path.clone(),
            private_key_passphrase: (profile.auth_type == AuthType::PrivateKey)
                .then(|| {
                    secret
                        .as_ref()
                        .map(|value| value.to_string())
                        .unwrap_or_default()
                })
                .filter(|value| !value.is_empty()),
            agent_key_fingerprint: profile.agent_key_fingerprint.clone(),
            proxy: profile
                .proxy
                .as_ref()
                .map(|proxy| crate::models::ProxyRequest {
                    proxy_type: proxy.proxy_type,
                    host: proxy.host.clone(),
                    port: proxy.port,
                    username: proxy.username.clone(),
                    password: proxy_password.as_ref().map(|value| value.to_string()),
                }),
            jump_hosts: Vec::new(),
            columns: 80,
            rows: 24,
            timeout_seconds: profile.timeout_seconds,
            keepalive_enabled: true,
            keepalive_seconds: 30,
        })
    }

    pub fn mark_connected(&self, id: &str) -> Result<(), AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        let profile = document
            .connections
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| AppError::asset_not_found("connection", id))?;
        profile.last_connected_at = Some(Utc::now().to_rfc3339());
        self.write_document(&document)
    }

    pub fn record_recent_target(&self, target: &str) -> Result<(), AppError> {
        let masked = mask_target(target)?;
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        document
            .recent_targets
            .retain(|item| item.display_target != masked);
        document.recent_targets.insert(
            0,
            RecentTarget {
                display_target: masked,
                last_used_at: Utc::now().to_rfc3339(),
            },
        );
        document.recent_targets.truncate(MAX_RECENT_TARGETS);
        self.write_document(&document)
    }

    pub fn clear_recent_targets(&self) -> Result<(), AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        document.recent_targets.clear();
        self.write_document(&document)
    }

    pub fn save_tunnel(&self, request: SaveTunnelRequest) -> Result<TunnelProfile, AppError> {
        validate_tunnel(&request)?;
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        if !document
            .connections
            .iter()
            .any(|connection| connection.id == request.connection_id)
        {
            return Err(AppError::asset_not_found(
                "connection",
                &request.connection_id,
            ));
        }
        let now = Utc::now().to_rfc3339();
        let id = request
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let existing = document.tunnels.iter().find(|tunnel| tunnel.id == id);
        if request.id.is_some() && existing.is_none() {
            return Err(AppError::asset_not_found("tunnel", &id));
        }
        let profile = TunnelProfile {
            id: id.clone(),
            name: request.name.trim().to_owned(),
            connection_id: request.connection_id,
            kind: request.kind,
            bind_host: request.bind_host.trim().to_owned(),
            bind_port: request.bind_port,
            target_host: request
                .target_host
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            target_port: request.target_port,
            start_policy: request.start_policy,
            created_at: existing.map_or_else(|| now.clone(), |tunnel| tunnel.created_at.clone()),
            updated_at: now,
        };
        document.tunnels.retain(|tunnel| tunnel.id != id);
        document.tunnels.push(profile.clone());
        self.write_document(&document)?;
        Ok(profile)
    }

    pub fn copy_tunnel(&self, id: &str) -> Result<TunnelProfile, AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        let source = document
            .tunnels
            .iter()
            .find(|tunnel| tunnel.id == id)
            .cloned()
            .ok_or_else(|| AppError::asset_not_found("tunnel", id))?;
        let now = Utc::now().to_rfc3339();
        let copy = TunnelProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!("{} - 副本", source.name),
            bind_port: 0,
            created_at: now.clone(),
            updated_at: now,
            ..source
        };
        document.tunnels.push(copy.clone());
        self.write_document(&document)?;
        Ok(copy)
    }

    pub fn delete_tunnel(&self, id: &str) -> Result<(), AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        if !document.tunnels.iter().any(|tunnel| tunnel.id == id) {
            return Err(AppError::asset_not_found("tunnel", id));
        }
        document.tunnels.retain(|tunnel| tunnel.id != id);
        self.write_document(&document)
    }

    pub fn tunnel(&self, id: &str) -> Result<TunnelProfile, AppError> {
        let _guard = self.lock()?;
        self.read_document()?
            .tunnels
            .into_iter()
            .find(|tunnel| tunnel.id == id)
            .ok_or_else(|| AppError::asset_not_found("tunnel", id))
    }

    pub fn automatic_tunnels(&self, connection_id: &str) -> Result<Vec<TunnelProfile>, AppError> {
        let _guard = self.lock()?;
        Ok(self
            .read_document()?
            .tunnels
            .into_iter()
            .filter(|tunnel| {
                tunnel.connection_id == connection_id
                    && tunnel.start_policy == crate::models::TunnelStartPolicy::WithConnection
            })
            .collect())
    }

    pub fn export_to(&self, path: &Path) -> Result<AssetTransferSummary, AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        document.recent_targets.clear();
        for connection in &mut document.connections {
            connection.credential_ref = None;
            if let Some(proxy) = &mut connection.proxy {
                proxy.credential_ref = None;
            }
        }
        let bytes = serde_json::to_vec_pretty(&document)
            .map_err(|error| AppError::asset_storage("无法生成导出文件", error.to_string()))?;
        atomic_write(path, &bytes)?;
        Ok(AssetTransferSummary {
            connections: document.connections.len(),
            groups: document.groups.len(),
            duplicate_names: 0,
            regenerated_ids: 0,
            path: path.display().to_string(),
        })
    }

    pub fn import_from(&self, path: &Path) -> Result<AssetTransferSummary, AppError> {
        let bytes = fs::read(path)
            .map_err(|error| AppError::asset_storage("无法读取导入文件", error.to_string()))?;
        let imported = parse_document(&bytes)?;
        for connection in &imported.connections {
            validate_imported_connection(connection)?;
        }
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        let mut group_map = std::collections::HashMap::new();
        let mut groups_added = 0;
        for group in imported
            .groups
            .into_iter()
            .filter(|group| group.id != DEFAULT_GROUP_ID)
        {
            if let Some(existing) = document
                .groups
                .iter()
                .find(|item| item.name.eq_ignore_ascii_case(&group.name))
            {
                group_map.insert(group.id, existing.id.clone());
            } else {
                let id = uuid::Uuid::new_v4().to_string();
                group_map.insert(group.id, id.clone());
                document.groups.push(ConnectionGroup { id, ..group });
                groups_added += 1;
            }
        }
        let mut duplicate_names = 0;
        let mut regenerated_ids = 0;
        let count = imported.connections.len();
        let mut connection_map = std::collections::HashMap::new();
        let mut imported_connections = imported.connections;
        for connection in &mut imported_connections {
            let source_id = connection.id.clone();
            if document
                .connections
                .iter()
                .any(|item| item.name.eq_ignore_ascii_case(&connection.name))
            {
                duplicate_names += 1;
            }
            if document
                .connections
                .iter()
                .any(|item| item.id == connection.id)
            {
                connection.id = uuid::Uuid::new_v4().to_string();
                regenerated_ids += 1;
            }
            connection_map.insert(source_id, connection.id.clone());
        }
        for mut connection in imported_connections {
            connection.group_id = group_map
                .get(&connection.group_id)
                .cloned()
                .unwrap_or_else(|| DEFAULT_GROUP_ID.to_owned());
            connection.jump_host_ids = connection
                .jump_host_ids
                .into_iter()
                .map(|id| connection_map.get(&id).cloned().unwrap_or(id))
                .collect();
            connection.credential_ref = None;
            if let Some(proxy) = &mut connection.proxy {
                proxy.credential_ref = None;
            }
            document.connections.push(connection);
        }
        for mut tunnel in imported.tunnels {
            let Some(connection_id) = connection_map.get(&tunnel.connection_id).cloned() else {
                continue;
            };
            tunnel.connection_id = connection_id;
            if document.tunnels.iter().any(|item| item.id == tunnel.id) {
                tunnel.id = uuid::Uuid::new_v4().to_string();
                regenerated_ids += 1;
            }
            document.tunnels.push(tunnel);
        }
        self.write_document(&document)?;
        Ok(AssetTransferSummary {
            connections: count,
            groups: groups_added,
            duplicate_names,
            regenerated_ids,
            path: path.display().to_string(),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, AppError> {
        self.lock
            .lock()
            .map_err(|_| AppError::asset_storage("连接数据服务不可用", "asset store lock poisoned"))
    }

    fn read_document(&self) -> Result<AssetDocument, AppError> {
        if !self.path.exists() {
            let temporary = self.path.with_extension("json.new");
            if temporary.exists() {
                let pending = fs::read(&temporary).map_err(|error| {
                    AppError::asset_storage("无法读取待恢复的连接数据", error.to_string())
                })?;
                let document = parse_document(&pending)?;
                if document_schema_version(&pending)
                    .is_some_and(|version| version < SCHEMA_VERSION.into())
                {
                    fs::write(
                        &temporary,
                        serde_json::to_vec_pretty(&document).map_err(|error| {
                            AppError::asset_storage("无法迁移连接数据", error.to_string())
                        })?,
                    )
                    .map_err(|error| {
                        AppError::asset_storage("无法写入迁移后的连接数据", error.to_string())
                    })?;
                }
                replace_atomically(&temporary, &self.path)?;
                return Ok(document);
            }
            return Ok(AssetDocument::default());
        }
        let bytes = fs::read(&self.path)
            .map_err(|error| AppError::asset_storage("无法读取连接数据", error.to_string()))?;
        if bytes.is_empty() {
            return Ok(AssetDocument::default());
        }
        match parse_document(&bytes) {
            Ok(document) => {
                if document_schema_version(&bytes)
                    .is_some_and(|version| version < SCHEMA_VERSION.into())
                {
                    let migrated = serde_json::to_vec_pretty(&document).map_err(|error| {
                        AppError::asset_storage("无法迁移连接数据", error.to_string())
                    })?;
                    atomic_write(&self.path, &migrated)?;
                }
                Ok(document)
            }
            Err(original_error) => {
                let temporary = self.path.with_extension("json.new");
                if !temporary.exists() {
                    return Err(original_error);
                }
                let pending = fs::read(&temporary).map_err(|error| {
                    AppError::asset_storage("无法读取待恢复的连接数据", error.to_string())
                })?;
                let recovered = parse_document(&pending)?;
                if document_schema_version(&pending)
                    .is_some_and(|version| version < SCHEMA_VERSION.into())
                {
                    fs::write(
                        &temporary,
                        serde_json::to_vec_pretty(&recovered).map_err(|error| {
                            AppError::asset_storage("无法迁移连接数据", error.to_string())
                        })?,
                    )
                    .map_err(|error| {
                        AppError::asset_storage("无法写入迁移后的连接数据", error.to_string())
                    })?;
                }
                replace_atomically(&temporary, &self.path)?;
                Ok(recovered)
            }
        }
    }

    fn write_document(&self, document: &AssetDocument) -> Result<(), AppError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::asset_storage("无法创建连接数据目录", error.to_string())
            })?;
        }
        let bytes = serde_json::to_vec_pretty(document)
            .map_err(|error| AppError::asset_storage("无法序列化连接数据", error.to_string()))?;
        atomic_write(&self.path, &bytes)
    }
}

fn validate_imported_connection(connection: &ConnectionProfile) -> Result<(), AppError> {
    if connection.name.trim().is_empty()
        || connection.name.chars().count() > 64
        || connection.host.trim().is_empty()
        || connection.username.trim().is_empty()
        || connection.username.chars().count() > 128
        || !(5..=60).contains(&connection.timeout_seconds)
    {
        return Err(AppError::validation(format!(
            "导入连接“{}”的字段无效",
            connection.name
        )));
    }
    Ok(())
}

fn validate_connection(request: &SaveConnectionRequest) -> Result<(), AppError> {
    if request.name.trim().is_empty() || request.name.trim().chars().count() > 64 {
        return Err(AppError::validation("连接名称长度必须为 1～64 个字符"));
    }
    if request.host.trim().is_empty()
        || request.host.len() > 255
        || request.host.contains(['\r', '\n', '\0'])
    {
        return Err(AppError::validation("主机地址无效"));
    }
    if request.username.trim().is_empty() || request.username.trim().chars().count() > 128 {
        return Err(AppError::validation("用户名长度必须为 1～128 个字符"));
    }
    if request.note.as_deref().unwrap_or_default().chars().count() > 500 {
        return Err(AppError::validation("备注不能超过 500 个字符"));
    }
    if !(5..=60).contains(&request.timeout_seconds) {
        return Err(AppError::validation("连接超时必须为 5～60 秒"));
    }
    if let Some(proxy) = &request.proxy {
        if proxy.host.trim().is_empty()
            || proxy.host.len() > 255
            || proxy.host.contains(['\r', '\n', '\0'])
        {
            return Err(AppError::validation("代理主机地址无效"));
        }
        if proxy.username.as_deref().is_some_and(|username| {
            username.trim().is_empty()
                || username.len() > 255
                || username.contains(['\r', '\n', '\0'])
        }) {
            return Err(AppError::validation("代理用户名无效"));
        }
    }
    if request.auth_type == AuthType::PrivateKey {
        let path = request.private_key_path.as_deref().unwrap_or_default();
        let metadata = fs::metadata(path)
            .map_err(|error| AppError::validation(format!("无法读取所选私钥文件：{error}")))?;
        if !metadata.is_file() {
            return Err(AppError::validation("所选私钥路径不是文件"));
        }
    }
    Ok(())
}

fn validate_tunnel(request: &SaveTunnelRequest) -> Result<(), AppError> {
    let name = request.name.trim();
    let bind_host = request.bind_host.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(AppError::validation("隧道名称长度必须为 1～64 个字符"));
    }
    if bind_host.is_empty() || bind_host.len() > 255 || bind_host.contains(['\r', '\n', '\0']) {
        return Err(AppError::validation("隧道监听地址无效"));
    }
    if (request.kind == TunnelKind::Remote || !is_loopback_host(bind_host))
        && !request.allow_non_loopback
    {
        return Err(AppError::ssh(
            "TUNNEL-RISK-CONFIRMATION-REQUIRED",
            "远程转发或非本机监听地址需要明确确认",
            "risky tunnel requested without explicit confirmation",
            false,
        ));
    }
    if request.kind != TunnelKind::Dynamic {
        let target_host = request.target_host.as_deref().unwrap_or_default().trim();
        if target_host.is_empty()
            || target_host.len() > 255
            || target_host.contains(['\r', '\n', '\0'])
            || request.target_port.unwrap_or_default() == 0
        {
            return Err(AppError::validation("隧道目标地址或端口无效"));
        }
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_jump_hosts(
    connections: &[ConnectionProfile],
    connection_id: &str,
    jump_host_ids: &[String],
) -> Result<(), AppError> {
    if jump_host_ids.len() > 8 {
        return Err(AppError::validation("跳板链最多包含 8 个连接"));
    }
    let mut unique = std::collections::HashSet::new();
    for jump_id in jump_host_ids {
        if jump_id == connection_id || !unique.insert(jump_id) {
            return Err(AppError::ssh(
                "JUMP-HOST-CYCLE",
                "跳板链不能包含自身或重复节点",
                "jump host chain contains a self-reference or duplicate",
                false,
            ));
        }
        if !connections
            .iter()
            .any(|connection| &connection.id == jump_id)
        {
            return Err(AppError::asset_not_found("jump-host", jump_id));
        }
        if jump_reaches(
            connections,
            jump_id,
            connection_id,
            &mut std::collections::HashSet::new(),
        ) {
            return Err(AppError::ssh(
                "JUMP-HOST-CYCLE",
                "跳板链存在循环引用",
                "jump host graph contains a cycle",
                false,
            ));
        }
    }
    Ok(())
}

fn collect_route_profiles(
    connections: &[ConnectionProfile],
    profile: &ConnectionProfile,
    visited: &mut std::collections::HashSet<String>,
    visiting: &mut std::collections::HashSet<String>,
    route: &mut Vec<String>,
) -> Result<(), AppError> {
    if !visiting.insert(profile.id.clone()) {
        return Err(AppError::ssh(
            "JUMP-HOST-CYCLE",
            "跳板链存在循环引用",
            "persisted jump host graph contains a cycle",
            false,
        ));
    }
    for jump_id in &profile.jump_host_ids {
        let jump = connections
            .iter()
            .find(|candidate| &candidate.id == jump_id)
            .ok_or_else(|| AppError::asset_not_found("jump-host", jump_id))?;
        collect_route_profiles(connections, jump, visited, visiting, route)?;
        if visited.insert(jump.id.clone()) {
            route.push(jump.id.clone());
        }
    }
    visiting.remove(&profile.id);
    Ok(())
}

fn jump_reaches(
    connections: &[ConnectionProfile],
    current: &str,
    target: &str,
    visited: &mut std::collections::HashSet<String>,
) -> bool {
    if current == target {
        return true;
    }
    if !visited.insert(current.to_owned()) {
        return false;
    }
    connections
        .iter()
        .find(|connection| connection.id == current)
        .is_some_and(|connection| {
            connection
                .jump_host_ids
                .iter()
                .any(|jump| jump_reaches(connections, jump, target, visited))
        })
}

fn parse_document(bytes: &[u8]) -> Result<AssetDocument, AppError> {
    let mut document: AssetDocument = serde_json::from_slice(bytes).map_err(|error| {
        AppError::asset_storage("连接数据已损坏，无法安全加载", error.to_string())
    })?;
    match document.schema_version {
        SCHEMA_VERSION => {}
        0..=2 => document.schema_version = SCHEMA_VERSION,
        version => {
            return Err(AppError::asset_storage(
                "连接数据版本暂不受支持",
                format!("unsupported schema version {version}"),
            ));
        }
    }
    if !document
        .groups
        .iter()
        .any(|group| group.id == DEFAULT_GROUP_ID)
    {
        let now = Utc::now().to_rfc3339();
        document.groups.insert(
            0,
            ConnectionGroup {
                id: DEFAULT_GROUP_ID.to_owned(),
                name: "默认分组".to_owned(),
                created_at: now.clone(),
                updated_at: now,
            },
        );
    }
    for connection in &mut document.connections {
        if !document
            .groups
            .iter()
            .any(|group| group.id == connection.group_id)
        {
            connection.group_id = DEFAULT_GROUP_ID.to_owned();
        }
    }
    Ok(document)
}

fn document_schema_version(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("schemaVersion")?
        .as_u64()
}

fn credential_reference(id: &str, auth_type: AuthType) -> String {
    let kind = if auth_type == AuthType::Password {
        "password"
    } else {
        "passphrase"
    };
    format!("TerminalT/connection/{id}/{kind}")
}

fn proxy_credential_reference(id: &str) -> String {
    format!("TerminalT/connection/{id}/proxy-password")
}

fn rollback_credential(
    vault: &dyn CredentialVault,
    new_ref: Option<&str>,
    old_ref: Option<&str>,
    old_secret: Option<&str>,
) {
    if let Some(reference) = new_ref {
        let _ = vault.delete(reference);
    }
    if let (Some(reference), Some(secret)) = (old_ref, old_secret) {
        let _ = vault.set(reference, secret);
    }
}

fn duplicate_name(name: &str, existing: &[ConnectionProfile]) -> String {
    for index in 1..=999 {
        let suffix = if index == 1 {
            "副本".to_owned()
        } else {
            format!("副本 {index}")
        };
        let suffix = format!(" - {suffix}");
        let base_limit = 64usize.saturating_sub(suffix.chars().count());
        let candidate = format!(
            "{}{suffix}",
            name.chars().take(base_limit).collect::<String>()
        );
        if !existing.iter().any(|item| item.name == candidate) {
            return candidate;
        }
    }
    format!("{} - 副本", name.chars().take(59).collect::<String>())
}

fn mask_target(target: &str) -> Result<String, AppError> {
    let (user, host) = target
        .trim()
        .split_once('@')
        .ok_or_else(|| AppError::validation("快速连接格式应为 user@host 或 user@host:port"))?;
    if user.is_empty() || host.is_empty() {
        return Err(AppError::validation(
            "快速连接格式应为 user@host 或 user@host:port",
        ));
    }
    let visible = host.chars().take(3).collect::<String>();
    Ok(format!("{user}@{visible}***"))
}

#[cfg(windows)]
fn replace_atomically(temporary: &Path, destination: &Path) -> Result<(), AppError> {
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    if !destination.exists() {
        return fs::rename(temporary, destination)
            .map_err(|error| AppError::asset_storage("无法保存连接数据", error.to_string()));
    }
    let replaced = wide_path(destination);
    let replacement = wide_path(temporary);
    let success = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if success == 0 {
        return Err(AppError::asset_storage(
            "无法原子保存连接数据",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn atomic_write(destination: &Path, bytes: &[u8]) -> Result<(), AppError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| AppError::asset_storage("无法创建数据目录", error.to_string()))?;
    }
    let temporary = destination.with_extension("json.new");
    fs::write(&temporary, bytes)
        .map_err(|error| AppError::asset_storage("无法写入临时数据", error.to_string()))?;
    replace_atomically(&temporary, destination)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::{AssetStore, DEFAULT_GROUP_ID};
    use crate::{
        credentials::CredentialVault,
        error::AppError,
        models::{
            AuthType, GroupNameRequest, ProxyType, SaveConnectionRequest, SaveProxyRequest,
            SaveTunnelRequest, TunnelKind, TunnelStartPolicy,
        },
    };
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct MemoryVault(Mutex<HashMap<String, String>>);

    struct UnavailableVault;

    impl CredentialVault for UnavailableVault {
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            Err(AppError::credential(
                "CREDENTIAL-STORE-UNAVAILABLE",
                "凭据库不可用",
                "simulated unavailable store",
                true,
            ))
        }
        fn get(&self, _: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            Ok(None)
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    impl CredentialVault for MemoryVault {
        fn set(&self, reference: &str, secret: &str) -> Result<(), AppError> {
            self.0
                .lock()
                .unwrap()
                .insert(reference.to_owned(), secret.to_owned());
            Ok(())
        }
        fn get(&self, reference: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(reference)
                .cloned()
                .map(Zeroizing::new))
        }
        fn delete(&self, reference: &str) -> Result<(), AppError> {
            self.0.lock().unwrap().remove(reference);
            Ok(())
        }
    }

    fn request(group_id: &str) -> SaveConnectionRequest {
        SaveConnectionRequest {
            id: None,
            name: "Production".to_owned(),
            host: "server.example".to_owned(),
            port: 22,
            username: "alice".to_owned(),
            auth_type: AuthType::Password,
            secret: Some("must-not-be-in-json".to_owned()),
            remember_credential: true,
            private_key_path: None,
            agent_key_fingerprint: None,
            proxy: None,
            jump_host_ids: Vec::new(),
            group_id: group_id.to_owned(),
            note: Some("primary server".to_owned()),
            timeout_seconds: 15,
        }
    }

    #[test]
    fn connections_survive_reload_without_plaintext_secret() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.json");
        let vault = std::sync::Arc::new(MemoryVault::default());
        let store = AssetStore::new(path.clone(), vault.clone());
        let saved = store.save_connection(request(DEFAULT_GROUP_ID)).unwrap();

        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("must-not-be-in-json"));
        assert!(persisted.contains("TerminalT/connection/"));

        let reloaded = AssetStore::new(path, vault);
        assert_eq!(reloaded.snapshot().unwrap().connections.len(), 1);
        assert_eq!(
            reloaded
                .connection_request(&saved.id, None)
                .unwrap()
                .password
                .as_deref(),
            Some("must-not-be-in-json")
        );

        let mut updated = request(DEFAULT_GROUP_ID);
        updated.id = Some(saved.id.clone());
        updated.secret = Some("updated-secret".to_owned());
        reloaded.save_connection(updated).unwrap();
        assert_eq!(
            reloaded
                .connection_request(&saved.id, None)
                .unwrap()
                .password
                .as_deref(),
            Some("updated-secret")
        );
        let reference = reloaded.snapshot().unwrap().connections[0]
            .credential_ref
            .clone()
            .unwrap();
        reloaded.delete_connection(&saved.id).unwrap();
        assert!(reloaded.vault.get(&reference).unwrap().is_none());
    }

    #[test]
    fn copy_gets_new_id_and_no_credential_reference() {
        let directory = tempfile::tempdir().unwrap();
        let store = AssetStore::new(
            directory.path().join("connections.json"),
            std::sync::Arc::new(MemoryVault::default()),
        );
        let saved = store.save_connection(request(DEFAULT_GROUP_ID)).unwrap();
        let copied = store.copy_connection(&saved.id).unwrap();

        assert_ne!(saved.id, copied.id);
        assert!(copied.name.contains("副本"));
        assert!(copied.credential_ref.is_none());
    }

    #[test]
    fn deleting_nonempty_group_migrates_connections_to_default() {
        let directory = tempfile::tempdir().unwrap();
        let store = AssetStore::new(
            directory.path().join("connections.json"),
            std::sync::Arc::new(MemoryVault::default()),
        );
        let group = store
            .save_group(GroupNameRequest {
                id: None,
                name: "Servers".to_owned(),
            })
            .unwrap();
        store.save_connection(request(&group.id)).unwrap();
        store.delete_group(&group.id).unwrap();

        let snapshot = store.snapshot().unwrap();
        assert!(!snapshot.groups.iter().any(|item| item.id == group.id));
        assert_eq!(snapshot.connections[0].group_id, DEFAULT_GROUP_ID);
    }

    #[test]
    fn duplicate_group_names_are_rejected_case_insensitively() {
        let directory = tempfile::tempdir().unwrap();
        let store = AssetStore::new(
            directory.path().join("connections.json"),
            std::sync::Arc::new(MemoryVault::default()),
        );
        store
            .save_group(GroupNameRequest {
                id: None,
                name: "Servers".to_owned(),
            })
            .unwrap();
        assert!(store
            .save_group(GroupNameRequest {
                id: None,
                name: "servers".to_owned()
            })
            .is_err());
    }

    #[test]
    fn unavailable_vault_never_falls_back_to_plaintext_storage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.json");
        let store = AssetStore::new(path.clone(), std::sync::Arc::new(UnavailableVault));
        let error = store
            .save_connection(request(DEFAULT_GROUP_ID))
            .unwrap_err();

        assert_eq!(error.code, "CREDENTIAL-STORE-UNAVAILABLE");
        assert!(!path.exists());
    }

    #[test]
    fn valid_pending_atomic_file_recovers_a_corrupted_primary() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.json");
        let store = AssetStore::new(path.clone(), std::sync::Arc::new(MemoryVault::default()));
        store.save_connection(request(DEFAULT_GROUP_ID)).unwrap();
        let valid = std::fs::read(&path).unwrap();
        std::fs::write(path.with_extension("json.new"), valid).unwrap();
        std::fs::write(&path, b"{ interrupted").unwrap();

        assert_eq!(store.snapshot().unwrap().connections.len(), 1);
        assert!(!path.with_extension("json.new").exists());
    }

    #[test]
    fn legacy_schemas_migrate_and_restore_the_default_group() {
        for version in [0, 1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("connections.json");
            std::fs::write(
                &path,
                format!(
                    "{{\"schemaVersion\":{version},\"groups\":[],\"connections\":[],\"recentTargets\":[]}}"
                ),
            )
            .unwrap();
            let store = AssetStore::new(path.clone(), std::sync::Arc::new(MemoryVault::default()));
            let snapshot = store.snapshot().unwrap();

            assert_eq!(snapshot.schema_version, 3);
            assert_eq!(snapshot.groups[0].id, DEFAULT_GROUP_ID);
            assert!(std::fs::read_to_string(path)
                .unwrap()
                .contains("\"schemaVersion\": 3"));
        }
    }

    #[test]
    fn export_omits_credentials_and_import_regenerates_conflicting_ids() {
        let directory = tempfile::tempdir().unwrap();
        let store = AssetStore::new(
            directory.path().join("connections.json"),
            std::sync::Arc::new(MemoryVault::default()),
        );
        store.save_connection(request(DEFAULT_GROUP_ID)).unwrap();
        let export = directory.path().join("export.json");
        store.export_to(&export).unwrap();
        let content = std::fs::read_to_string(&export).unwrap();
        assert!(!content.contains("must-not-be-in-json"));
        assert!(!content.contains("TerminalT/connection/"));
        let summary = store.import_from(&export).unwrap();
        assert_eq!(summary.connections, 1);
        assert_eq!(summary.regenerated_ids, 1);
        assert_eq!(store.snapshot().unwrap().connections.len(), 2);
    }

    #[test]
    fn future_import_version_is_rejected_transactionally() {
        let directory = tempfile::tempdir().unwrap();
        let store = AssetStore::new(
            directory.path().join("connections.json"),
            std::sync::Arc::new(MemoryVault::default()),
        );
        let import = directory.path().join("future.json");
        std::fs::write(
            &import,
            br#"{"schemaVersion":99,"groups":[],"connections":[],"recentTargets":[]}"#,
        )
        .unwrap();
        assert!(store.import_from(&import).is_err());
        assert!(store.snapshot().unwrap().connections.is_empty());
    }

    #[test]
    fn proxy_secret_is_vault_only_and_jump_cycles_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.json");
        let store = AssetStore::new(path.clone(), std::sync::Arc::new(MemoryVault::default()));
        let first = store.save_connection(request(DEFAULT_GROUP_ID)).unwrap();
        let mut second_request = request(DEFAULT_GROUP_ID);
        second_request.name = "Jump".to_owned();
        second_request.host = "jump.example".to_owned();
        second_request.proxy = Some(SaveProxyRequest {
            proxy_type: ProxyType::Socks5,
            host: "proxy.example".to_owned(),
            port: 1080,
            username: Some("proxy-user".to_owned()),
            password: Some("proxy-secret".to_owned()),
            remember_credential: true,
        });
        second_request.jump_host_ids = vec![first.id.clone()];
        let second = store.save_connection(second_request).unwrap();

        let persisted = std::fs::read_to_string(path).unwrap();
        assert!(!persisted.contains("proxy-secret"));
        assert_eq!(
            store
                .connection_request(&second.id, None)
                .unwrap()
                .proxy
                .unwrap()
                .password
                .as_deref(),
            Some("proxy-secret")
        );

        let mut cycle = request(DEFAULT_GROUP_ID);
        cycle.id = Some(first.id);
        cycle.jump_host_ids = vec![second.id];
        assert_eq!(
            store.save_connection(cycle).unwrap_err().code,
            "JUMP-HOST-CYCLE"
        );
    }

    #[test]
    fn tunnel_profiles_persist_and_non_loopback_requires_confirmation() {
        let directory = tempfile::tempdir().unwrap();
        let store = AssetStore::new(
            directory.path().join("connections.json"),
            std::sync::Arc::new(MemoryVault::default()),
        );
        let connection = store.save_connection(request(DEFAULT_GROUP_ID)).unwrap();
        let mut tunnel = SaveTunnelRequest {
            id: None,
            name: "Database".to_owned(),
            connection_id: connection.id.clone(),
            kind: TunnelKind::Local,
            bind_host: "0.0.0.0".to_owned(),
            bind_port: 15432,
            target_host: Some("db.internal".to_owned()),
            target_port: Some(5432),
            start_policy: TunnelStartPolicy::Manual,
            allow_non_loopback: false,
        };
        assert_eq!(
            store.save_tunnel(tunnel.clone()).unwrap_err().code,
            "TUNNEL-RISK-CONFIRMATION-REQUIRED"
        );
        tunnel.allow_non_loopback = true;
        let saved = store.save_tunnel(tunnel).unwrap();
        assert_eq!(store.snapshot().unwrap().tunnels.len(), 1);
        assert!(store.delete_connection(&connection.id).is_err());
        store.delete_tunnel(&saved.id).unwrap();
        store.delete_connection(&connection.id).unwrap();
    }
}

#[cfg(not(windows))]
fn replace_atomically(temporary: &Path, destination: &Path) -> Result<(), AppError> {
    fs::rename(temporary, destination)
        .map_err(|error| AppError::asset_storage("无法保存连接数据", error.to_string()))
}
