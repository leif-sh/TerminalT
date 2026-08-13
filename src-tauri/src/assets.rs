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
    },
};

pub const DEFAULT_GROUP_ID: &str = "default";
const SCHEMA_VERSION: u16 = 1;
const MAX_RECENT_TARGETS: usize = 10;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AssetDocument {
    schema_version: u16,
    groups: Vec<ConnectionGroup>,
    connections: Vec<ConnectionProfile>,
    recent_targets: Vec<RecentTarget>,
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
        let created_at = existing
            .as_ref()
            .map_or_else(|| now.clone(), |item| item.created_at.clone());
        let credential_ref = request
            .remember_credential
            .then(|| credential_reference(&id, request.auth_type));
        let prior_ref = existing
            .as_ref()
            .and_then(|item| item.credential_ref.clone());
        let prior_secret = prior_ref
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

        let profile = ConnectionProfile {
            id: id.clone(),
            name: request.name.trim().to_owned(),
            host: request.host.trim().to_owned(),
            port: request.port,
            username: request.username.trim().to_owned(),
            auth_type: request.auth_type,
            credential_ref: credential_ref.clone(),
            private_key_path: request.private_key_path.filter(|value| !value.is_empty()),
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

        if let Err(error) = self.write_document(&document) {
            rollback_credential(
                self.vault.as_ref(),
                credential_ref.as_deref(),
                prior_ref.as_deref(),
                prior_secret.as_deref().map(String::as_str),
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
        let secret = profile
            .credential_ref
            .as_deref()
            .map(|reference| self.vault.get(reference))
            .transpose()?
            .flatten();
        if let Some(reference) = profile.credential_ref.as_deref() {
            self.vault.delete(reference)?;
        }
        document.connections.retain(|item| item.id != id);
        if let Err(error) = self.write_document(&document) {
            if let (Some(reference), Some(secret)) =
                (profile.credential_ref.as_deref(), secret.as_ref())
            {
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

    pub fn connection_request(
        &self,
        id: &str,
        temporary_secret: Option<String>,
    ) -> Result<crate::models::ConnectionRequest, AppError> {
        let _guard = self.lock()?;
        let document = self.read_document()?;
        let profile = document
            .connections
            .iter()
            .find(|item| item.id == id)
            .ok_or_else(|| AppError::asset_not_found("connection", id))?;
        let secret = match temporary_secret {
            Some(secret) => Some(Zeroizing::new(secret)),
            None => profile
                .credential_ref
                .as_deref()
                .map(|reference| self.vault.get(reference))
                .transpose()?
                .flatten(),
        };
        if profile.auth_type == AuthType::Password && secret.is_none()
            || profile.credential_ref.is_some() && secret.is_none()
        {
            return Err(AppError::credential(
                "CREDENTIAL-MISSING",
                "未找到已保存凭据，请重新输入",
                "credential reference is absent or missing from Windows Credential Manager",
                true,
            ));
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

    pub fn export_to(&self, path: &Path) -> Result<AssetTransferSummary, AppError> {
        let _guard = self.lock()?;
        let mut document = self.read_document()?;
        document.recent_targets.clear();
        for connection in &mut document.connections {
            connection.credential_ref = None;
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
        for mut connection in imported.connections {
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
            connection.group_id = group_map
                .get(&connection.group_id)
                .cloned()
                .unwrap_or_else(|| DEFAULT_GROUP_ID.to_owned());
            connection.credential_ref = None;
            document.connections.push(connection);
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
                if document_schema_version(&pending) == Some(0) {
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
                if document_schema_version(&bytes) == Some(0) {
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
                if document_schema_version(&pending) == Some(0) {
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
    if request.host.trim().is_empty() {
        return Err(AppError::validation("请输入主机地址"));
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

fn parse_document(bytes: &[u8]) -> Result<AssetDocument, AppError> {
    let mut document: AssetDocument = serde_json::from_slice(bytes).map_err(|error| {
        AppError::asset_storage("连接数据已损坏，无法安全加载", error.to_string())
    })?;
    match document.schema_version {
        SCHEMA_VERSION => {}
        0 => document.schema_version = SCHEMA_VERSION,
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
        models::{AuthType, GroupNameRequest, SaveConnectionRequest},
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
    fn schema_zero_migrates_and_restores_the_default_group() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.json");
        std::fs::write(
            &path,
            br#"{"schemaVersion":0,"groups":[],"connections":[],"recentTargets":[]}"#,
        )
        .unwrap();
        let store = AssetStore::new(path.clone(), std::sync::Arc::new(MemoryVault::default()));
        let snapshot = store.snapshot().unwrap();

        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.groups[0].id, DEFAULT_GROUP_ID);
        assert!(std::fs::read_to_string(path)
            .unwrap()
            .contains("\"schemaVersion\": 1"));
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
}

#[cfg(not(windows))]
fn replace_atomically(temporary: &Path, destination: &Path) -> Result<(), AppError> {
    fs::rename(temporary, destination)
        .map_err(|error| AppError::asset_storage("无法保存连接数据", error.to_string()))
}
