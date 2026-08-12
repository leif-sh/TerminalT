use std::{collections::HashMap, sync::Mutex};

use tokio::sync::{mpsc, oneshot};

use crate::error::AppError;

#[derive(Debug)]
pub enum SessionCommand {
    Data(Vec<u8>),
    Resize { columns: u16, rows: u16 },
    Close,
}

enum SessionEntry {
    Mock {
        cancellation: oneshot::Sender<()>,
    },
    Ssh {
        commands: mpsc::Sender<SessionCommand>,
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
    ) -> Result<(), AppError> {
        self.insert(session_id, SessionEntry::Mock { cancellation })
    }

    pub fn insert_ssh(
        &self,
        session_id: String,
        commands: mpsc::Sender<SessionCommand>,
    ) -> Result<(), AppError> {
        self.insert(session_id, SessionEntry::Ssh { commands })
    }

    fn insert(&self, session_id: String, entry: SessionEntry) -> Result<(), AppError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
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
            SessionEntry::Ssh { commands } => commands
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
        if let SessionEntry::Ssh { commands } = entry {
            commands
                .try_send(SessionCommand::Resize { columns, rows })
                .map_err(|error| AppError::session_command_failed(error.to_string()))?;
        }
        Ok(())
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
            SessionEntry::Mock { cancellation } => {
                let _ = cancellation.send(());
            }
            SessionEntry::Ssh { commands } => {
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

    pub fn close_all(&self) -> Result<(), AppError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        for (_, session) in sessions.drain() {
            match session {
                SessionEntry::Mock { cancellation } => {
                    let _ = cancellation.send(());
                }
                SessionEntry::Ssh { commands } => {
                    let _ = commands.try_send(SessionCommand::Close);
                }
            }
        }
        Ok(())
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
    use super::{OperationRegistry, SessionRegistry};

    #[test]
    fn mock_session_lifecycle_removes_entries() {
        let registry = SessionRegistry::default();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        registry
            .insert_mock("session-1".to_owned(), sender)
            .unwrap();
        assert!(registry.contains("session-1").unwrap());

        registry.close("session-1").unwrap();
        assert_eq!(registry.size().unwrap(), 0);
    }

    #[test]
    fn close_all_clears_every_session() {
        let registry = SessionRegistry::default();
        for index in 0..3 {
            let (sender, _receiver) = tokio::sync::oneshot::channel();
            registry
                .insert_mock(format!("session-{index}"), sender)
                .unwrap();
        }

        registry.close_all().unwrap();
        assert_eq!(registry.size().unwrap(), 0);
    }

    #[test]
    fn operation_can_be_cancelled() {
        let registry = OperationRegistry::default();
        let receiver = registry.register("operation-1".to_owned()).unwrap();
        registry.cancel("operation-1").unwrap();
        assert!(receiver.blocking_recv().is_ok());
    }
}
