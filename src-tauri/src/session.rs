use std::{collections::HashMap, sync::Mutex};

use tokio::sync::oneshot;

use crate::error::AppError;

struct SessionEntry {
    cancellation: oneshot::Sender<()>,
    columns: u16,
    rows: u16,
}

#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionRegistry {
    pub fn insert(
        &self,
        session_id: String,
        cancellation: oneshot::Sender<()>,
    ) -> Result<(), AppError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        sessions.insert(
            session_id,
            SessionEntry {
                cancellation,
                columns: 80,
                rows: 24,
            },
        );
        Ok(())
    }

    pub fn contains(&self, session_id: &str) -> Result<bool, AppError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        Ok(sessions.contains_key(session_id))
    }

    pub fn resize(&self, session_id: &str, columns: u16, rows: u16) -> Result<(), AppError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| AppError::session_not_found(session_id))?;
        session.columns = columns;
        session.rows = rows;
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
        let _ = session.cancellation.send(());
        Ok(())
    }

    pub fn close_all(&self) -> Result<(), AppError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| AppError::session_registry_unavailable())?;
        for (_, session) in sessions.drain() {
            let _ = session.cancellation.send(());
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

#[cfg(test)]
mod tests {
    use super::SessionRegistry;

    #[test]
    fn session_lifecycle_removes_entries() {
        let registry = SessionRegistry::default();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        registry.insert("session-1".to_owned(), sender).unwrap();
        assert!(registry.contains("session-1").unwrap());

        registry.resize("session-1", 120, 40).unwrap();
        registry.close("session-1").unwrap();

        assert_eq!(registry.size().unwrap(), 0);
    }

    #[test]
    fn close_all_clears_every_session() {
        let registry = SessionRegistry::default();
        for index in 0..3 {
            let (sender, _receiver) = tokio::sync::oneshot::channel();
            registry.insert(format!("session-{index}"), sender).unwrap();
        }

        registry.close_all().unwrap();
        assert_eq!(registry.size().unwrap(), 0);
    }
}
