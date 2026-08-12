use std::{fs, path::PathBuf};

use russh::keys::{ssh_key, HashAlg};
use serde::{Deserialize, Serialize};

use crate::{
    assets::atomic_write,
    error::AppError,
    models::{HostKeyAction, HostKeyInspection, HostKeyStatus},
};

#[derive(Clone, Debug)]
pub struct HostKeyIdentity {
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub public_key: String,
}

impl HostKeyIdentity {
    pub fn from_public_key(key: &ssh_key::PublicKey) -> Result<Self, russh::Error> {
        Ok(Self {
            algorithm: key.algorithm().as_str().to_owned(),
            fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
            public_key: key.to_openssh().map_err(russh::Error::SshKey)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyRecord {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint_sha256: String,
    pub public_key: String,
    pub trusted_at: String,
}

pub struct KnownHostsStore {
    path: PathBuf,
}

impl KnownHostsStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn list(&self) -> Result<Vec<HostKeyRecord>, AppError> {
        self.read_records()
    }

    pub fn delete(&self, host: &str, port: u16) -> Result<(), AppError> {
        let mut records = self.read_records()?;
        records.retain(|record| !(record.host == host && record.port == port));
        self.write_records(&records)
    }

    pub fn inspect(
        &self,
        host: &str,
        port: u16,
        identity: &HostKeyIdentity,
    ) -> Result<HostKeyInspection, AppError> {
        let records = self.read_records()?;
        let existing = records
            .iter()
            .find(|record| record.host == host && record.port == port);
        let (status, previous_fingerprint_sha256) = match existing {
            Some(record) if record.fingerprint_sha256 == identity.fingerprint_sha256 => {
                (HostKeyStatus::Trusted, None)
            }
            Some(record) => (
                HostKeyStatus::Changed,
                Some(record.fingerprint_sha256.clone()),
            ),
            None => (HostKeyStatus::Unknown, None),
        };

        Ok(HostKeyInspection {
            host: host.to_owned(),
            port,
            algorithm: identity.algorithm.clone(),
            fingerprint_sha256: identity.fingerprint_sha256.clone(),
            status,
            previous_fingerprint_sha256,
        })
    }

    pub fn approve(
        &self,
        host: &str,
        port: u16,
        identity: &HostKeyIdentity,
        action: HostKeyAction,
    ) -> Result<(), AppError> {
        let inspection = self.inspect(host, port, identity)?;
        let action_allowed = matches!(
            (inspection.status, action),
            (HostKeyStatus::Trusted, HostKeyAction::UseTrusted)
                | (HostKeyStatus::Unknown, HostKeyAction::TrustNew)
                | (HostKeyStatus::Changed, HostKeyAction::ReplaceChanged)
        );
        if !action_allowed {
            return Err(AppError::ssh(
                "HOST-KEY-DECISION-INVALID",
                "服务器身份确认已过期，请重新检查指纹",
                "host key state no longer matches the requested approval action",
                true,
            ));
        }

        if action == HostKeyAction::UseTrusted {
            return Ok(());
        }

        let mut records = self.read_records()?;
        records.retain(|record| !(record.host == host && record.port == port));
        records.push(HostKeyRecord {
            host: host.to_owned(),
            port,
            algorithm: identity.algorithm.clone(),
            fingerprint_sha256: identity.fingerprint_sha256.clone(),
            public_key: identity.public_key.clone(),
            trusted_at: chrono::Utc::now().to_rfc3339(),
        });
        self.write_records(&records)
    }

    fn read_records(&self) -> Result<Vec<HostKeyRecord>, AppError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&self.path)
            .map_err(|error| AppError::storage("无法读取已保存的服务器指纹", error.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| AppError::storage("已保存的服务器指纹数据无法解析", error.to_string()))
    }

    fn write_records(&self, records: &[HostKeyRecord]) -> Result<(), AppError> {
        let bytes = serde_json::to_vec_pretty(records)
            .map_err(|error| AppError::storage("无法序列化服务器指纹记录", error.to_string()))?;
        atomic_write(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{HostKeyIdentity, KnownHostsStore};
    use crate::models::{HostKeyAction, HostKeyStatus};

    fn identity(fingerprint: &str) -> HostKeyIdentity {
        HostKeyIdentity {
            algorithm: "ssh-ed25519".to_owned(),
            fingerprint_sha256: fingerprint.to_owned(),
            public_key: "ssh-ed25519 test".to_owned(),
        }
    }

    #[test]
    fn unknown_key_becomes_trusted_after_approval() {
        let directory = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::new(directory.path().join("known_hosts.json"));
        let key = identity("SHA256:first");

        assert!(matches!(
            store.inspect("host", 22, &key).unwrap().status,
            HostKeyStatus::Unknown
        ));
        store
            .approve("host", 22, &key, HostKeyAction::TrustNew)
            .unwrap();
        assert!(matches!(
            store.inspect("host", 22, &key).unwrap().status,
            HostKeyStatus::Trusted
        ));
    }

    #[test]
    fn changed_key_is_blocked_without_replace_action() {
        let directory = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::new(directory.path().join("known_hosts.json"));
        let first = identity("SHA256:first");
        let second = identity("SHA256:second");
        store
            .approve("host", 22, &first, HostKeyAction::TrustNew)
            .unwrap();

        let inspection = store.inspect("host", 22, &second).unwrap();
        assert!(matches!(inspection.status, HostKeyStatus::Changed));
        assert_eq!(
            inspection.previous_fingerprint_sha256.as_deref(),
            Some("SHA256:first")
        );
        assert!(store
            .approve("host", 22, &second, HostKeyAction::TrustNew)
            .is_err());
        assert_eq!(store.list().unwrap().len(), 1);
        store.delete("host", 22).unwrap();
        assert!(store.list().unwrap().is_empty());
    }
}
