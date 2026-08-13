use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use crate::{assets::atomic_write, error::AppError};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub schema_version: u16,
    pub font_family: String,
    pub font_size: u16,
    pub line_height: f32,
    pub theme: String,
    pub cursor_style: String,
    pub cursor_blink: bool,
    pub scrollback: u32,
    pub confirm_close_session: bool,
    pub connection_timeout_seconds: u64,
    pub keepalive_enabled: bool,
    pub keepalive_seconds: u64,
    pub default_download_directory: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            schema_version: 1,
            font_family: "JetBrains Mono, Cascadia Code, Consolas, monospace".to_owned(),
            font_size: 14,
            line_height: 1.2,
            theme: "dark".to_owned(),
            cursor_style: "bar".to_owned(),
            cursor_blink: true,
            scrollback: 10_000,
            confirm_close_session: true,
            connection_timeout_seconds: 15,
            keepalive_enabled: true,
            keepalive_seconds: 30,
            default_download_directory: String::new(),
        }
    }
}

impl AppSettings {
    fn validate(&self) -> Result<(), AppError> {
        if self.schema_version != 1 {
            return Err(AppError::validation("设置文件版本不受支持"));
        }
        if self.font_family.trim().is_empty() || self.font_family.chars().count() > 256 {
            return Err(AppError::validation("字体族长度必须为 1～256 个字符"));
        }
        if !(10..=32).contains(&self.font_size) {
            return Err(AppError::validation("字号必须为 10～32 px"));
        }
        if !(1.0..=2.0).contains(&self.line_height) {
            return Err(AppError::validation("行高必须为 1.0～2.0"));
        }
        if !matches!(self.theme.as_str(), "dark" | "light") {
            return Err(AppError::validation("终端主题无效"));
        }
        if !matches!(self.cursor_style.as_str(), "block" | "bar" | "underline") {
            return Err(AppError::validation("光标形状无效"));
        }
        if !(1_000..=100_000).contains(&self.scrollback) {
            return Err(AppError::validation("滚动缓冲必须为 1,000～100,000 行"));
        }
        if !(5..=60).contains(&self.connection_timeout_seconds) {
            return Err(AppError::validation("连接超时必须为 5～60 秒"));
        }
        if self.keepalive_enabled && !(5..=300).contains(&self.keepalive_seconds) {
            return Err(AppError::validation("Keepalive 间隔必须为 5～300 秒"));
        }
        Ok(())
    }
}

pub struct SettingsStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl SettingsStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }
    pub fn load(&self, fallback_download: &Path) -> Result<AppSettings, AppError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AppError::asset_storage("设置服务不可用", "settings lock poisoned"))?;
        let mut settings = if self.path.exists() {
            serde_json::from_slice::<AppSettings>(
                &fs::read(&self.path)
                    .map_err(|error| AppError::asset_storage("无法读取设置", error.to_string()))?,
            )
            .map_err(|error| AppError::asset_storage("设置文件已损坏", error.to_string()))?
        } else {
            AppSettings::default()
        };
        settings.validate()?;
        if settings.default_download_directory.is_empty()
            || !writable_directory(Path::new(&settings.default_download_directory))
        {
            settings.default_download_directory = fallback_download.display().to_string();
        }
        Ok(settings)
    }
    pub fn save(&self, settings: &AppSettings) -> Result<(), AppError> {
        settings.validate()?;
        if !writable_directory(Path::new(&settings.default_download_directory)) {
            return Err(AppError::validation("默认下载目录不存在或不可写"));
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AppError::asset_storage("设置服务不可用", "settings lock poisoned"))?;
        let bytes = serde_json::to_vec_pretty(settings)
            .map_err(|error| AppError::asset_storage("无法序列化设置", error.to_string()))?;
        atomic_write(&self.path, &bytes)
    }
    pub fn load_window(&self) -> Option<crate::models::WindowState> {
        serde_json::from_slice(&fs::read(self.path.with_file_name("window-state.json")).ok()?).ok()
    }
    pub fn save_window(&self, state: &crate::models::WindowState) -> Result<(), AppError> {
        if !(480..=10_000).contains(&state.width) || !(360..=10_000).contains(&state.height) {
            return Err(AppError::validation("窗口尺寸无效"));
        }
        let bytes = serde_json::to_vec(state)
            .map_err(|error| AppError::asset_storage("无法保存窗口状态", error.to_string()))?;
        atomic_write(&self.path.with_file_name("window-state.json"), &bytes)
    }
}

fn writable_directory(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    let probe = path.join(format!(".terminalt-write-probe-{}", uuid::Uuid::new_v4()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::AppSettings;
    #[test]
    fn validates_boundaries() {
        let mut settings = AppSettings {
            font_size: 9,
            ..AppSettings::default()
        };
        assert!(settings.validate().is_err());
        settings.font_size = 10;
        settings.connection_timeout_seconds = 60;
        assert!(settings.validate().is_ok());
    }
}
