use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

use russh::{client, Disconnect};

use crate::{error::AppError, ssh_client::VerifiedHandler, tunnel::RemoteForwardTable};

pub(crate) struct PooledConnection {
    handle: Arc<client::Handle<VerifiedHandler>>,
    remote_forwards: RemoteForwardTable,
    upstream: Mutex<Vec<client::Handle<VerifiedHandler>>>,
    closing: AtomicBool,
    lease_count: AtomicUsize,
}

impl PooledConnection {
    pub fn new(
        handle: client::Handle<VerifiedHandler>,
        remote_forwards: RemoteForwardTable,
        upstream: Vec<client::Handle<VerifiedHandler>>,
    ) -> Self {
        Self {
            handle: Arc::new(handle),
            remote_forwards,
            upstream: Mutex::new(upstream),
            closing: AtomicBool::new(false),
            lease_count: AtomicUsize::new(0),
        }
    }

    async fn shutdown(&self, reason: &'static str) {
        if self.closing.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, reason, "")
            .await;
        let mut upstream = match self.upstream.lock() {
            Ok(mut upstream) => std::mem::take(&mut *upstream),
            Err(_) => Vec::new(),
        };
        while let Some(handle) = upstream.pop() {
            let _ = handle
                .disconnect(Disconnect::ByApplication, reason, "")
                .await;
        }
    }
}

pub(crate) struct ConnectionLease {
    connection: Arc<PooledConnection>,
}

impl Clone for ConnectionLease {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.connection))
    }
}

impl ConnectionLease {
    fn new(connection: Arc<PooledConnection>) -> Self {
        connection.lease_count.fetch_add(1, Ordering::Relaxed);
        Self { connection }
    }

    pub fn handle(&self) -> Arc<client::Handle<VerifiedHandler>> {
        Arc::clone(&self.connection.handle)
    }

    pub fn remote_forwards(&self) -> RemoteForwardTable {
        Arc::clone(&self.connection.remote_forwards)
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if self.connection.lease_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            let connection = Arc::clone(&self.connection);
            tauri::async_runtime::spawn(async move {
                connection.shutdown("last connection lease released").await;
            });
        }
    }
}

#[derive(Default)]
pub(crate) struct ConnectionPool {
    connections: Mutex<HashMap<String, Weak<PooledConnection>>>,
}

impl ConnectionPool {
    pub fn acquire(&self, key: &str) -> Result<Option<ConnectionLease>, AppError> {
        let mut connections = self.lock()?;
        let connection = connections.get(key).and_then(Weak::upgrade);
        if connection.is_none() {
            connections.remove(key);
        }
        Ok(connection.map(ConnectionLease::new))
    }

    pub fn adopt(
        &self,
        key: String,
        connection: PooledConnection,
    ) -> Result<ConnectionLease, AppError> {
        let candidate = Arc::new(connection);
        let existing = {
            let mut connections = self.lock()?;
            if let Some(existing) = connections.get(&key).and_then(Weak::upgrade) {
                Some(existing)
            } else {
                connections.insert(key, Arc::downgrade(&candidate));
                None
            }
        };
        if let Some(existing) = existing {
            tauri::async_runtime::spawn(async move {
                candidate
                    .shutdown("duplicate pooled connection discarded")
                    .await;
            });
            Ok(ConnectionLease::new(existing))
        } else {
            Ok(ConnectionLease::new(candidate))
        }
    }

    pub fn standalone(&self, connection: PooledConnection) -> ConnectionLease {
        ConnectionLease::new(Arc::new(connection))
    }

    pub fn invalidate(&self, key: &str) -> Result<(), AppError> {
        self.lock()?.remove(key);
        Ok(())
    }

    pub async fn shutdown_all_bounded(&self, timeout: Duration) -> Result<bool, AppError> {
        let connections = {
            let mut entries = self.lock()?;
            let connections = entries
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            entries.clear();
            connections
        };
        Ok(tokio::time::timeout(timeout, async move {
            for connection in connections {
                connection.shutdown("application exit").await;
            }
        })
        .await
        .is_ok())
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Weak<PooledConnection>>>, AppError> {
        self.connections.lock().map_err(|_| {
            AppError::ssh(
                "CONNECTION-POOL-UNAVAILABLE",
                "SSH 连接池暂时不可用",
                "connection pool lock was poisoned",
                true,
            )
        })
    }
}
