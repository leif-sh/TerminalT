use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime},
};

use chrono::Utc;
use serde::Serialize;

use crate::{assets::atomic_write, error::AppError};

const RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_TOTAL_BYTES: u64 = 10 * 1024 * 1024;

pub struct DiagnosticLog {
    directory: PathBuf,
    lock: Mutex<()>,
}

impl DiagnosticLog {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            lock: Mutex::new(()),
        }
    }
    pub fn directory(&self) -> String {
        self.directory.display().to_string()
    }
    pub fn record(&self, event: &str, code: Option<&str>, details: &str) {
        if let Ok(_guard) = self.lock.lock() {
            let _ = fs::create_dir_all(&self.directory);
            let path = self
                .directory
                .join(format!("terminalt-{}.log", Utc::now().format("%Y-%m-%d")));
            let entry = format!(
                "{} event={} code={} details={}\n",
                Utc::now().to_rfc3339(),
                sanitize(event),
                code.unwrap_or("-"),
                sanitize(details)
            );
            let _ = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut file| std::io::Write::write_all(&mut file, entry.as_bytes()));
            let _ = cleanup(&self.directory, SystemTime::now());
        }
    }
    pub fn clear(&self) -> Result<(), AppError> {
        let _guard = self.lock.lock().map_err(|_| {
            AppError::asset_storage("日志服务不可用", "diagnostic log lock poisoned")
        })?;
        if self.directory.exists() {
            for item in fs::read_dir(&self.directory)
                .map_err(|error| AppError::asset_storage("无法读取日志目录", error.to_string()))?
            {
                let path = item
                    .map_err(|error| {
                        AppError::asset_storage("无法读取日志文件", error.to_string())
                    })?
                    .path();
                if path.is_file() {
                    fs::remove_file(path).map_err(|error| {
                        AppError::asset_storage("无法清理日志", error.to_string())
                    })?;
                }
            }
        }
        Ok(())
    }
    pub fn export_filtered(&self, path: &Path) -> Result<LogExportSummary, AppError> {
        let _guard = self.lock.lock().map_err(|_| {
            AppError::asset_storage("日志服务不可用", "diagnostic log lock poisoned")
        })?;
        let mut content = String::new();
        let mut files = 0;
        if self.directory.exists() {
            for item in fs::read_dir(&self.directory)
                .map_err(|error| AppError::asset_storage("无法读取日志目录", error.to_string()))?
            {
                let path = item
                    .map_err(|error| {
                        AppError::asset_storage("无法读取日志文件", error.to_string())
                    })?
                    .path();
                if path.is_file() {
                    content.push_str(&sanitize(&fs::read_to_string(path).unwrap_or_default()));
                    files += 1;
                }
            }
        }
        atomic_write(path, content.as_bytes())?;
        Ok(LogExportSummary {
            files,
            path: path.display().to_string(),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogExportSummary {
    pub files: usize,
    pub path: String,
}

pub fn sanitize(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            if [
                "password",
                "passphrase",
                "privatekey",
                "secret",
                "credential",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                "[REDACTED]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn cleanup(directory: &Path, now: SystemTime) -> std::io::Result<()> {
    let mut files = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .filter_map(|item| {
            let meta = item.metadata().ok()?;
            meta.is_file().then(|| {
                (
                    item.path(),
                    meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    meta.len(),
                )
            })
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|item| item.1);
    let mut total = files.iter().map(|item| item.2).sum::<u64>();
    for (path, modified, size) in files {
        if now.duration_since(modified).unwrap_or_default() > RETENTION || total > MAX_TOTAL_BYTES {
            fs::remove_file(path)?;
            total = total.saturating_sub(size);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sanitize;
    #[test]
    fn removes_sensitive_fields_and_newlines() {
        let value = sanitize("password=hunter2\ncredentialRef=abc host=example.com");
        assert!(!value.contains("hunter2"));
        assert!(!value.contains("abc"));
        assert!(!value.contains('\n'));
    }
}
