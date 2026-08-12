use std::{collections::HashMap, sync::Mutex};

use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Duration};

use crate::error::AppError;
use crate::models::{RemoteDirectoryListing, TransferDirection, TransferTask};

#[derive(Debug)]
pub enum SessionCommand {
    Data(Vec<u8>),
    Resize {
        columns: u16,
        rows: u16,
    },
    ListRemoteDirectory {
        path: String,
        response: oneshot::Sender<Result<RemoteDirectoryListing, AppError>>,
    },
    CreateRemoteDirectory {
        parent_path: String,
        name: String,
        response: oneshot::Sender<Result<(), AppError>>,
    },
    RenameRemoteEntry {
        path: String,
        new_name: String,
        response: oneshot::Sender<Result<(), AppError>>,
    },
    DeleteRemoteEntry {
        path: String,
        response: oneshot::Sender<Result<(), AppError>>,
    },
    StartTransfer {
        direction: TransferDirection,
        source: String,
        target: String,
        overwrite: bool,
        response: oneshot::Sender<Result<TransferTask, AppError>>,
    },
    CancelTransfer {
        task_id: String,
    },
    Close,
}

enum SessionEntry {
    Mock {
        cancellation: oneshot::Sender<()>,
        completion: oneshot::Receiver<()>,
    },
    Ssh {
        commands: mpsc::Sender<SessionCommand>,
        completion: oneshot::Receiver<()>,
    },
}

#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionRegistry {
    pub fn insert_mock(
        &self,
        session_id: String,
        cancellation: oneshot::Sender<()>,
        completion: oneshot::Receiver<()>,
    ) -> Result<(), AppError> {
        self.insert(
            session_id,
            SessionEntry::Mock {
                cancellation,
                completion,
            },
        )
    }

    pub fn insert_ssh(
        &self,
        session_id: String,
        commands: mpsc::Sender<SessionCommand>,
        completion: oneshot::Receiver<()>,
    ) -> Result<(), AppError> {
        self.insert(
            session_id,
            SessionEntry::Ssh {
                commands,
                completion,
            },
        )
    }

    fn insert(&self, session_id: String, entry: SessionEntry) -> Result<(), AppError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        if sessions.contains_key(&session_id) {
            return Err(AppError::session_already_active(&session_id));
        }
        sessions.insert(session_id, entry);
        Ok(())
    }

    pub fn contains(&self, session_id: &str) -> Result<bool, AppError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        Ok(sessions.contains_key(session_id))
    }

    pub fn send(&self, session_id: &str, command: SessionCommand) -> Result<(), AppError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        let entry = sessions
            .get(session_id)
            .ok_or_else(|| AppError::session_not_found(session_id))?;
        match entry {
            SessionEntry::Ssh { commands, .. } => commands
                .try_send(command)
                .map_err(|error| AppError::session_command_failed(error.to_string())),
            SessionEntry::Mock { .. } => Err(AppError::invalid_session_operation()),
        }
    }

    pub fn resize(&self, session_id: &str, columns: u16, rows: u16) -> Result<(), AppError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        let entry = sessions
            .get(session_id)
            .ok_or_else(|| AppError::session_not_found(session_id))?;
        if let SessionEntry::Ssh { commands, .. } = entry {
            commands
                .try_send(SessionCommand::Resize { columns, rows })
                .map_err(|error| AppError::session_command_failed(error.to_string()))?;
        }
        Ok(())
    }

    pub async fn list_remote_directory(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<RemoteDirectoryListing, AppError> {
        let commands = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| AppError::session_registry_unavailable())?;
            match sessions
                .get(session_id)
                .ok_or_else(|| AppError::session_not_found(session_id))?
            {
                SessionEntry::Ssh { commands, .. } => commands.clone(),
                SessionEntry::Mock { .. } => return Err(AppError::invalid_session_operation()),
            }
        };
        let (response, receiver) = oneshot::channel();
        commands
            .send(SessionCommand::ListRemoteDirectory { path, response })
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?;
        receiver
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?
    }

    pub async fn create_remote_directory(
        &self,
        session_id: &str,
        parent_path: String,
        name: String,
    ) -> Result<(), AppError> {
        let commands = self.ssh_commands(session_id)?;
        let (response, receiver) = oneshot::channel();
        commands
            .send(SessionCommand::CreateRemoteDirectory {
                parent_path,
                name,
                response,
            })
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?;
        receiver
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?
    }

    pub async fn rename_remote_entry(
        &self,
        session_id: &str,
        path: String,
        new_name: String,
    ) -> Result<(), AppError> {
        let commands = self.ssh_commands(session_id)?;
        let (response, receiver) = oneshot::channel();
        commands
            .send(SessionCommand::RenameRemoteEntry {
                path,
                new_name,
                response,
            })
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?;
        receiver
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?
    }

    pub async fn delete_remote_entry(
        &self,
        session_id: &str,
        path: String,
    ) -> Result<(), AppError> {
        let commands = self.ssh_commands(session_id)?;
        let (response, receiver) = oneshot::channel();
        commands
            .send(SessionCommand::DeleteRemoteEntry { path, response })
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?;
        receiver
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?
    }

    pub async fn start_transfer(
        &self,
        session_id: &str,
        direction: TransferDirection,
        source: String,
        target: String,
        overwrite: bool,
    ) -> Result<TransferTask, AppError> {
        let commands = self.ssh_commands(session_id)?;
        let (response, receiver) = oneshot::channel();
        commands
            .send(SessionCommand::StartTransfer {
                direction,
                source,
                target,
                overwrite,
                response,
            })
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?;
        receiver
            .await
            .map_err(|error| AppError::session_command_failed(error.to_string()))?
    }

    pub fn cancel_transfer(&self, session_id: &str, task_id: String) -> Result<(), AppError> {
        self.send(session_id, SessionCommand::CancelTransfer { task_id })
    }

    fn ssh_commands(&self, session_id: &str) -> Result<mpsc::Sender<SessionCommand>, AppError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        match sessions
            .get(session_id)
            .ok_or_else(|| AppError::session_not_found(session_id))?
        {
            SessionEntry::Ssh { commands, .. } => Ok(commands.clone()),
            SessionEntry::Mock { .. } => Err(AppError::invalid_session_operation()),
        }
    }

    pub fn close(&self, session_id: &str) -> Result<(), AppError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        let session = sessions
            .remove(session_id)
            .ok_or_else(|| AppError::session_not_found(session_id))?;
        match session {
            SessionEntry::Mock { cancellation, .. } => {
                let _ = cancellation.send(());
            }
            SessionEntry::Ssh { commands, .. } => {
                let _ = commands.try_send(SessionCommand::Close);
            }
        }
        Ok(())
    }

    pub fn remove_finished(&self, session_id: &str) -> Result<(), AppError> {
        self.sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?
            .remove(session_id);
        Ok(())
    }

    pub async fn close_all_bounded(&self, timeout: Duration) -> Result<bool, AppError> {
        let completions = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| AppError::session_registry_unavailable())?;
            let mut completions = Vec::with_capacity(sessions.len());
            for (_, session) in sessions.drain() {
                match session {
                    SessionEntry::Mock {
                        cancellation,
                        completion,
                    } => {
                        let _ = cancellation.send(());
                        completions.push(completion);
                    }
                    SessionEntry::Ssh {
                        commands,
                        completion,
                    } => {
                        let _ = commands.try_send(SessionCommand::Close);
                        completions.push(completion);
                    }
                }
            }
            completions
        };
        Ok(time::timeout(timeout, async move {
            for completion in completions {
                let _ = completion.await;
            }
        })
        .await
        .is_ok())
    }

    #[cfg(test)]
    fn size(&self) -> Result<usize, AppError> {
        self.sessions
            .lock()
            .map(|sessions| sessions.len())
            .map_err(|_| AppError::session_registry_unavailable())
    }
}

#[derive(Default)]
pub struct OperationRegistry {
    operations: Mutex<HashMap<String, oneshot::Sender<()>>>,
}

impl OperationRegistry {
    pub fn register(&self, operation_id: String) -> Result<oneshot::Receiver<()>, AppError> {
        let (sender, receiver) = oneshot::channel();
        self.operations
            .lock()
            .map_err(|_| AppError::operation_registry_unavailable())?
            .insert(operation_id, sender);
        Ok(receiver)
    }

    pub fn finish(&self, operation_id: &str) -> Result<(), AppError> {
        self.operations
            .lock()
            .map_err(|_| AppError::operation_registry_unavailable())?
            .remove(operation_id);
        Ok(())
    }

    pub fn cancel(&self, operation_id: &str) -> Result<(), AppError> {
        if let Some(sender) = self
            .operations
            .lock()
            .map_err(|_| AppError::operation_registry_unavailable())?
            .remove(operation_id)
        {
            let _ = sender.send(());
        }
        Ok(())
    }

    pub fn cancel_all(&self) -> Result<(), AppError> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| AppError::operation_registry_unavailable())?;
        for (_, sender) in operations.drain() {
            let _ = sender.send(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, OperationRegistry, SessionRegistry};

    #[test]
    fn mock_session_lifecycle_removes_entries() {
        let registry = SessionRegistry::default();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let (_completion, completion_receiver) = tokio::sync::oneshot::channel();
        registry
            .insert_mock("session-1".to_owned(), sender, completion_receiver)
            .unwrap();
        assert!(registry.contains("session-1").unwrap());

        registry.close("session-1").unwrap();
        assert_eq!(registry.size().unwrap(), 0);
    }

    #[tokio::test]
    async fn close_all_clears_every_session() {
        let registry = SessionRegistry::default();
        let mut completions = Vec::new();
        for index in 0..3 {
            let (sender, _receiver) = tokio::sync::oneshot::channel();
            let (completion, completion_receiver) = tokio::sync::oneshot::channel();
            registry
                .insert_mock(format!("session-{index}"), sender, completion_receiver)
                .unwrap();
            completions.push(completion);
        }

        for completion in completions {
            completion.send(()).unwrap();
        }
        assert!(registry
            .close_all_bounded(Duration::from_secs(1))
            .await
            .unwrap());
        assert_eq!(registry.size().unwrap(), 0);
    }

    #[tokio::test]
    async fn close_all_stops_waiting_at_the_deadline() {
        let registry = SessionRegistry::default();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let (_completion, completion_receiver) = tokio::sync::oneshot::channel::<()>();
        registry
            .insert_mock("session-1".to_owned(), sender, completion_receiver)
            .unwrap();

        assert!(!registry
            .close_all_bounded(Duration::from_millis(10))
            .await
            .unwrap());
        assert_eq!(registry.size().unwrap(), 0);
    }

    #[test]
    fn duplicate_session_id_is_rejected() {
        let registry = SessionRegistry::default();
        let (first, _receiver) = tokio::sync::oneshot::channel();
        let (second, _receiver) = tokio::sync::oneshot::channel();
        let (_first_completion, first_receiver) = tokio::sync::oneshot::channel();
        let (_second_completion, second_receiver) = tokio::sync::oneshot::channel();
        registry
            .insert_mock("session-1".to_owned(), first, first_receiver)
            .unwrap();

        let error = registry
            .insert_mock("session-1".to_owned(), second, second_receiver)
            .unwrap_err();

        assert_eq!(error.code, "SESSION-ALREADY-ACTIVE");
        assert_eq!(registry.size().unwrap(), 1);
    }

    #[test]
    fn operation_can_be_cancelled() {
        let registry = OperationRegistry::default();
        let receiver = registry.register("operation-1".to_owned()).unwrap();
        registry.cancel("operation-1").unwrap();
        assert!(receiver.blocking_recv().is_ok());
    }
}
