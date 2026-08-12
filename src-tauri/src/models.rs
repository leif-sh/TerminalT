use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: &'static str,
    pub protocol_version: u16,
    pub app_version: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionState {
    pub id: String,
    pub title: String,
    pub status: SessionStatus,
    pub started_at: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStatus {
    Connecting,
    HostKeyCheck,
    Authenticating,
    Connected,
    Disconnected,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOutputPayload {
    pub session_id: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatusPayload {
    pub session_id: String,
    pub status: SessionStatus,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDirectoryEntry {
    pub name: String,
    pub path: String,
    pub kind: RemoteEntryKind,
    pub size: u64,
    pub modified_at: Option<String>,
    pub permissions: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDirectoryListing {
    pub path: String,
    pub parent_path: Option<String>,
    pub entries: Vec<RemoteDirectoryEntry>,
    pub truncated: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRequest {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: AuthType,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub columns: u16,
    pub rows: u16,
    pub timeout_seconds: u64,
    #[serde(default = "default_keepalive_enabled")]
    pub keepalive_enabled: bool,
    #[serde(default = "default_keepalive_seconds")]
    pub keepalive_seconds: u64,
}

impl ConnectionRequest {
    pub fn validate(&mut self) -> Result<(), &'static str> {
        self.name = self.name.trim().to_owned();
        self.host = self.host.trim().to_owned();
        self.username = self.username.trim().to_owned();
        if self.name.is_empty() || self.name.chars().count() > 64 {
            return Err("连接名称长度必须为 1～64 个字符");
        }
        if self.host.is_empty() {
            return Err("请输入主机地址");
        }
        if self.username.is_empty() || self.username.chars().count() > 128 {
            return Err("用户名长度必须为 1～128 个字符");
        }
        if !(5..=60).contains(&self.timeout_seconds) {
            return Err("连接超时必须为 5～60 秒");
        }
        if self.columns == 0 || self.rows == 0 {
            return Err("终端尺寸必须大于 0");
        }
        if self.keepalive_enabled && !(5..=300).contains(&self.keepalive_seconds) {
            return Err("SSH keepalive 间隔必须为 5～300 秒");
        }
        match self.auth_type {
            AuthType::Password if self.password.as_deref().unwrap_or_default().is_empty() => {
                Err("请输入密码")
            }
            AuthType::PrivateKey
                if self
                    .private_key_path
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty() =>
            {
                Err("请选择私钥文件")
            }
            _ => Ok(()),
        }
    }
}

fn default_keepalive_enabled() -> bool {
    true
}

fn default_keepalive_seconds() -> u64 {
    30
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthType {
    Password,
    PrivateKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionGroup {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: AuthType,
    pub credential_ref: Option<String>,
    pub private_key_path: Option<String>,
    pub group_id: String,
    pub note: Option<String>,
    pub timeout_seconds: u64,
    pub last_connected_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveConnectionRequest {
    pub id: Option<String>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: AuthType,
    pub secret: Option<String>,
    pub remember_credential: bool,
    pub private_key_path: Option<String>,
    pub group_id: String,
    pub note: Option<String>,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentTarget {
    pub display_target: String,
    pub last_used_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionAssetSnapshot {
    pub schema_version: u16,
    pub default_group_id: String,
    pub groups: Vec<ConnectionGroup>,
    pub connections: Vec<ConnectionProfile>,
    pub recent_targets: Vec<RecentTarget>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupNameRequest {
    pub id: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyInspection {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub status: HostKeyStatus,
    pub previous_fingerprint_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyStatus {
    Trusted,
    Unknown,
    Changed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyApproval {
    pub fingerprint_sha256: String,
    pub action: HostKeyAction,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepaliveSettings {
    pub enabled: bool,
    pub seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedSessionRequest {
    pub connection_id: String,
    pub temporary_secret: Option<String>,
    pub approval: HostKeyApproval,
    pub keepalive: Option<KeepaliveSettings>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconnectSavedSessionRequest {
    pub session_id: String,
    pub connection_id: String,
    pub temporary_secret: Option<String>,
    pub approval: HostKeyApproval,
    pub keepalive: Option<KeepaliveSettings>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum HostKeyAction {
    UseTrusted,
    TrustNew,
    ReplaceChanged,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTestResult {
    pub elapsed_millis: u128,
    pub host_key: HostKeyInspection,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProgressPayload {
    pub operation_id: String,
    pub status: SessionStatus,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::{AuthType, ConnectionRequest};

    fn request() -> ConnectionRequest {
        ConnectionRequest {
            name: "test".to_owned(),
            host: "example.com".to_owned(),
            port: 22,
            username: "user".to_owned(),
            auth_type: AuthType::Password,
            password: Some("secret".to_owned()),
            private_key_path: None,
            private_key_passphrase: None,
            columns: 80,
            rows: 24,
            timeout_seconds: 15,
            keepalive_enabled: true,
            keepalive_seconds: 30,
        }
    }

    #[test]
    fn keepalive_interval_is_validated_only_when_enabled() {
        let mut enabled = request();
        enabled.keepalive_seconds = 4;
        assert_eq!(
            enabled.validate(),
            Err("SSH keepalive 间隔必须为 5～300 秒")
        );

        let mut disabled = request();
        disabled.keepalive_enabled = false;
        disabled.keepalive_seconds = 0;
        assert!(disabled.validate().is_ok());
    }
}
