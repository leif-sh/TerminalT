use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::{
    assets::atomic_write,
    error::AppError,
    models::{TransferStatus, TransferTask},
};

const TRANSFER_SCHEMA: u32 = 1;
const MAX_HISTORY: usize = 100;
const MAX_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferDocument {
    schema_version: u32,
    tasks: Vec<TransferTask>,
}

pub(crate) struct TransferRegistry {
    tasks: Mutex<HashMap<String, TransferTask>>,
    persist: watch::Sender<Vec<TransferTask>>,
}

impl TransferRegistry {
    pub fn new(path: PathBuf) -> Self {
        let initial = load_history(&path);
        let tasks = initial
            .iter()
            .cloned()
            .map(|task| (task.id.clone(), task))
            .collect();
        let (persist, mut receiver) = watch::channel(initial);
        tauri::async_runtime::spawn(async move {
            while receiver.changed().await.is_ok() {
                let snapshot = receiver.borrow_and_update().clone();
                let path = path.clone();
                let result =
                    tauri::async_runtime::spawn_blocking(move || persist_history(&path, snapshot))
                        .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => log::error!("{}: {}", error.code, error.message),
                    Err(error) => log::error!("transfer history writer failed: {error}"),
                }
            }
        });
        Self {
            tasks: Mutex::new(tasks),
            persist,
        }
    }

    pub fn record(&self, task: TransferTask, persist: bool) -> Result<(), AppError> {
        let snapshot = {
            let mut tasks = self.lock()?;
            tasks.insert(task.id.clone(), task);
            trim_history(&mut tasks);
            tasks.values().cloned().collect::<Vec<_>>()
        };
        if persist {
            self.persist.send_replace(snapshot);
        }
        Ok(())
    }

    pub fn list(&self, session_id: &str) -> Result<Vec<TransferTask>, AppError> {
        let mut tasks = self
            .lock()?
            .values()
            .filter(|task| task.session_id == session_id)
            .cloned()
            .collect::<Vec<_>>();
        tasks.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(tasks)
    }

    pub fn clear_finished(&self, session_id: &str) -> Result<(), AppError> {
        let snapshot = {
            let mut tasks = self.lock()?;
            tasks.retain(|_, task| {
                task.session_id != session_id
                    || matches!(
                        task.status,
                        TransferStatus::Queued | TransferStatus::Scanning | TransferStatus::Running
                    )
            });
            tasks.values().cloned().collect::<Vec<_>>()
        };
        self.persist.send_replace(snapshot);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, TransferTask>>, AppError> {
        self.tasks.lock().map_err(|_| {
            AppError::sftp(
                "TRANSFER-REGISTRY-UNAVAILABLE",
                "传输队列暂时不可用",
                "transfer registry lock was poisoned",
            )
        })
    }
}

fn load_history(path: &Path) -> Vec<TransferTask> {
    let Ok(metadata) = fs::metadata(path) else {
        return Vec::new();
    };
    if metadata.len() > MAX_DOCUMENT_BYTES {
        log::warn!("transfer history exceeds size limit and was ignored");
        return Vec::new();
    }
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    let Ok(mut document) = serde_json::from_slice::<TransferDocument>(&bytes) else {
        log::warn!("transfer history is invalid and was ignored");
        return Vec::new();
    };
    if document.schema_version != TRANSFER_SCHEMA {
        log::warn!("unsupported transfer history schema was ignored");
        return Vec::new();
    }
    for task in &mut document.tasks {
        if matches!(
            task.status,
            TransferStatus::Queued | TransferStatus::Scanning | TransferStatus::Running
        ) {
            task.status = TransferStatus::Failed;
            task.error = Some("应用已退出，请重新连接后重试".to_owned());
        }
    }
    document.tasks.truncate(MAX_HISTORY);
    document.tasks
}

fn persist_history(path: &Path, mut tasks: Vec<TransferTask>) -> Result<(), AppError> {
    tasks.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    tasks.truncate(MAX_HISTORY);
    let bytes = serde_json::to_vec_pretty(&TransferDocument {
        schema_version: TRANSFER_SCHEMA,
        tasks,
    })
    .map_err(|error| AppError::storage("无法序列化传输历史", error.to_string()))?;
    atomic_write(path, &bytes)
}

fn trim_history(tasks: &mut HashMap<String, TransferTask>) {
    if tasks.len() <= MAX_HISTORY {
        return;
    }
    let mut oldest = tasks
        .values()
        .map(|task| (task.created_at.clone(), task.id.clone()))
        .collect::<Vec<_>>();
    oldest.sort();
    for (_, id) in oldest.into_iter().take(tasks.len() - MAX_HISTORY) {
        tasks.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::{load_history, persist_history};
    use crate::models::{TransferConflictPolicy, TransferDirection, TransferStatus, TransferTask};

    fn task(status: TransferStatus) -> TransferTask {
        TransferTask {
            id: "00000000-0000-4000-8000-000000000001".to_owned(),
            created_at: "2026-08-21T00:00:00Z".to_owned(),
            session_id: "session".to_owned(),
            file_name: "folder".to_owned(),
            direction: TransferDirection::Upload,
            source: "C:/folder".to_owned(),
            target: "/tmp/folder".to_owned(),
            sources: vec!["C:/folder".to_owned()],
            target_directory: "/tmp".to_owned(),
            conflict_policy: TransferConflictPolicy::Ask,
            transferred_bytes: 0,
            total_bytes: Some(0),
            total_files: 0,
            total_directories: 1,
            completed_files: 0,
            completed_directories: 0,
            skipped_files: 0,
            bytes_per_second: 0,
            current_path: None,
            elapsed_seconds: 0,
            status,
            error: None,
            errors: Vec::new(),
        }
    }

    #[test]
    fn active_jobs_load_as_retryable_failures() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transfers.json");
        persist_history(&path, vec![task(TransferStatus::Running)]).unwrap();
        let loaded = load_history(&path);
        assert_eq!(loaded.len(), 1);
        assert!(matches!(loaded[0].status, TransferStatus::Failed));
        assert!(loaded[0].error.as_deref().unwrap().contains("重试"));
    }
}
