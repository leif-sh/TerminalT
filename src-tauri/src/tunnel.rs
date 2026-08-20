use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use russh::{client, Channel};
use tauri::{AppHandle, Emitter};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Semaphore},
    task::JoinSet,
};

use crate::{
    error::AppError,
    models::{TunnelKind, TunnelProfile, TunnelRuntimeState, TunnelStatus, TunnelStatusPayload},
    ssh_client::VerifiedHandler,
};

const TUNNEL_STATUS_EVENT: &str = "tunnel-status";
const MAX_TUNNEL_CONNECTIONS: usize = 100;
const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(crate) struct TunnelMetrics {
    active_connections: AtomicU32,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct RemoteForwardTarget {
    pub target_host: String,
    pub target_port: u16,
    pub metrics: Arc<TunnelMetrics>,
}

pub(crate) type RemoteForwardTable = Arc<Mutex<HashMap<(String, u32), RemoteForwardTarget>>>;

struct RemoteForwardRuntime {
    handle: Arc<client::Handle<VerifiedHandler>>,
    forwards: RemoteForwardTable,
    metrics: Arc<TunnelMetrics>,
}

struct TunnelEntry {
    state: TunnelRuntimeState,
    metrics: Arc<TunnelMetrics>,
    cancellation: Option<oneshot::Sender<()>>,
    completion: Option<oneshot::Receiver<()>>,
}

#[derive(Clone, Default)]
pub struct TunnelRegistry {
    entries: Arc<Mutex<HashMap<String, TunnelEntry>>>,
}

impl TunnelRegistry {
    pub async fn start(
        &self,
        app: AppHandle,
        session_id: String,
        profile: TunnelProfile,
        handle: Arc<client::Handle<VerifiedHandler>>,
        remote_forwards: RemoteForwardTable,
    ) -> Result<TunnelRuntimeState, AppError> {
        if let Some(state) = self.by_profile(&profile.id)? {
            if matches!(state.status, TunnelStatus::Starting | TunnelStatus::Running) {
                return Ok(state);
            }
        }
        let runtime_id = uuid::Uuid::new_v4().to_string();
        let metrics = Arc::new(TunnelMetrics::default());
        let (cancellation, cancellation_receiver) = oneshot::channel();
        let (completion, completion_receiver) = oneshot::channel();
        let state = TunnelRuntimeState {
            runtime_id: runtime_id.clone(),
            profile_id: profile.id.clone(),
            session_id,
            status: TunnelStatus::Starting,
            bound_port: profile.bind_port,
            active_connections: 0,
            bytes_up: 0,
            bytes_down: 0,
            last_error: None,
        };
        self.entries
            .lock()
            .map_err(|_| registry_unavailable())?
            .insert(
                runtime_id.clone(),
                TunnelEntry {
                    state: state.clone(),
                    metrics: Arc::clone(&metrics),
                    cancellation: Some(cancellation),
                    completion: Some(completion_receiver),
                },
            );
        emit_state(&app, &state);

        let registry = self.clone();
        let task_runtime_id = runtime_id.clone();
        tauri::async_runtime::spawn(async move {
            let result = match profile.kind {
                TunnelKind::Local | TunnelKind::Dynamic => {
                    run_local_listener(
                        &app,
                        &registry,
                        &task_runtime_id,
                        profile,
                        handle,
                        metrics,
                        cancellation_receiver,
                    )
                    .await
                }
                TunnelKind::Remote => {
                    run_remote_forward(
                        &app,
                        &registry,
                        &task_runtime_id,
                        profile,
                        RemoteForwardRuntime {
                            handle,
                            forwards: remote_forwards,
                            metrics,
                        },
                        cancellation_receiver,
                    )
                    .await
                }
            };
            registry.finish(&app, &task_runtime_id, result);
            let _ = completion.send(());
        });
        Ok(state)
    }

    pub fn list(&self) -> Result<Vec<TunnelRuntimeState>, AppError> {
        let entries = self.entries.lock().map_err(|_| registry_unavailable())?;
        Ok(entries.values().map(snapshot).collect())
    }

    pub fn by_profile(&self, profile_id: &str) -> Result<Option<TunnelRuntimeState>, AppError> {
        let entries = self.entries.lock().map_err(|_| registry_unavailable())?;
        Ok(entries
            .values()
            .find(|entry| entry.state.profile_id == profile_id)
            .map(snapshot))
    }

    pub fn has_active_session(&self, session_id: &str) -> Result<bool, AppError> {
        let entries = self.entries.lock().map_err(|_| registry_unavailable())?;
        Ok(entries.values().any(|entry| {
            entry.state.session_id == session_id
                && matches!(
                    entry.state.status,
                    TunnelStatus::Starting | TunnelStatus::Running | TunnelStatus::Stopping
                )
        }))
    }

    pub fn stop(&self, runtime_id: &str) -> Result<TunnelRuntimeState, AppError> {
        let mut entries = self.entries.lock().map_err(|_| registry_unavailable())?;
        let entry = entries.get_mut(runtime_id).ok_or_else(|| {
            AppError::ssh(
                "TUNNEL-NOT-FOUND",
                "运行中的隧道不存在",
                format!("tunnel runtime {runtime_id} was not found"),
                false,
            )
        })?;
        if let Some(cancellation) = entry.cancellation.take() {
            entry.state.status = TunnelStatus::Stopping;
            let _ = cancellation.send(());
        }
        Ok(snapshot(entry))
    }

    pub async fn stop_all_bounded(&self, timeout: Duration) -> Result<bool, AppError> {
        let completions = {
            let mut entries = self.entries.lock().map_err(|_| registry_unavailable())?;
            entries
                .values_mut()
                .filter_map(|entry| {
                    if let Some(cancellation) = entry.cancellation.take() {
                        entry.state.status = TunnelStatus::Stopping;
                        let _ = cancellation.send(());
                    }
                    entry.completion.take()
                })
                .collect::<Vec<_>>()
        };
        Ok(tokio::time::timeout(timeout, async move {
            for completion in completions {
                let _ = completion.await;
            }
        })
        .await
        .is_ok())
    }

    fn set_running(&self, app: &AppHandle, runtime_id: &str, port: u16) -> Result<(), AppError> {
        let mut entries = self.entries.lock().map_err(|_| registry_unavailable())?;
        let entry = entries
            .get_mut(runtime_id)
            .ok_or_else(registry_unavailable)?;
        entry.state.status = TunnelStatus::Running;
        entry.state.bound_port = port;
        emit_state(app, &snapshot(entry));
        Ok(())
    }

    fn finish(&self, app: &AppHandle, runtime_id: &str, result: Result<(), AppError>) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries.get_mut(runtime_id) {
                entry.cancellation = None;
                match result {
                    Ok(()) => entry.state.status = TunnelStatus::Stopped,
                    Err(error) => {
                        entry.state.status = TunnelStatus::Failed;
                        entry.state.last_error = Some(format!("{}: {}", error.code, error.message));
                    }
                }
                emit_state(app, &snapshot(entry));
            }
        }
    }
}

async fn run_local_listener(
    app: &AppHandle,
    registry: &TunnelRegistry,
    runtime_id: &str,
    profile: TunnelProfile,
    handle: Arc<client::Handle<VerifiedHandler>>,
    metrics: Arc<TunnelMetrics>,
    mut cancellation: oneshot::Receiver<()>,
) -> Result<(), AppError> {
    let listener = TcpListener::bind((profile.bind_host.as_str(), profile.bind_port))
        .await
        .map_err(|error| {
            AppError::ssh(
                "TUNNEL-BIND-FAILED",
                "无法监听指定地址或端口",
                error.to_string(),
                true,
            )
        })?;
    let bound_port = listener
        .local_addr()
        .map_err(|error| {
            AppError::ssh(
                "TUNNEL-BIND-FAILED",
                "无法读取隧道监听端口",
                error.to_string(),
                true,
            )
        })?
        .port();
    registry.set_running(app, runtime_id, bound_port)?;
    let slots = Arc::new(Semaphore::new(MAX_TUNNEL_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut cancellation => break,
            accepted = listener.accept() => {
                let (stream, origin) = accepted.map_err(|error| AppError::ssh(
                    "TUNNEL-BIND-FAILED", "隧道监听器无法接受连接", error.to_string(), true,
                ))?;
                let permit = match Arc::clone(&slots).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let handle = Arc::clone(&handle);
                let metrics = Arc::clone(&metrics);
                let kind = profile.kind;
                let target_host = profile.target_host.clone();
                let target_port = profile.target_port;
                connections.spawn(async move {
                    let _permit = permit;
                    metrics.active_connections.fetch_add(1, Ordering::Relaxed);
                    let result = match kind {
                        TunnelKind::Local => bridge_local_forward(
                            stream,
                            handle,
                            target_host.unwrap_or_default(),
                            target_port.unwrap_or_default(),
                            origin.ip().to_string(),
                            origin.port(),
                            Arc::clone(&metrics),
                        ).await,
                        TunnelKind::Dynamic => run_socks_client(stream, handle, origin, Arc::clone(&metrics)).await,
                        TunnelKind::Remote => Ok(()),
                    };
                    metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                    result
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn bridge_local_forward(
    mut stream: TcpStream,
    handle: Arc<client::Handle<VerifiedHandler>>,
    target_host: String,
    target_port: u16,
    origin_host: String,
    origin_port: u16,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), AppError> {
    let channel = handle
        .channel_open_direct_tcpip(
            target_host,
            u32::from(target_port),
            origin_host,
            u32::from(origin_port),
        )
        .await
        .map_err(|error| {
            AppError::ssh(
                "TUNNEL-TARGET-FAILED",
                "SSH 服务器无法连接隧道目标",
                error.to_string(),
                true,
            )
        })?;
    let mut remote = channel.into_stream();
    let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut remote)
        .await
        .map_err(|error| {
            AppError::ssh(
                "TUNNEL-TARGET-FAILED",
                "隧道数据转发中断",
                error.to_string(),
                true,
            )
        })?;
    metrics.bytes_up.fetch_add(up, Ordering::Relaxed);
    metrics.bytes_down.fetch_add(down, Ordering::Relaxed);
    Ok(())
}

async fn run_socks_client(
    mut stream: TcpStream,
    handle: Arc<client::Handle<VerifiedHandler>>,
    origin: std::net::SocketAddr,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), AppError> {
    tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, async {
        let version = stream.read_u8().await.map_err(tunnel_io_error)?;
        let method_count = stream.read_u8().await.map_err(tunnel_io_error)? as usize;
        if version != 5 || method_count == 0 || method_count > 16 {
            return Err(tunnel_protocol_error("invalid SOCKS5 greeting"));
        }
        let mut methods = vec![0_u8; method_count];
        stream
            .read_exact(&mut methods)
            .await
            .map_err(tunnel_io_error)?;
        if !methods.contains(&0) {
            stream
                .write_all(&[5, 0xff])
                .await
                .map_err(tunnel_io_error)?;
            return Err(tunnel_protocol_error("SOCKS5 client did not offer no-auth"));
        }
        stream.write_all(&[5, 0]).await.map_err(tunnel_io_error)?;
        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(tunnel_io_error)?;
        if header[0] != 5 || header[2] != 0 || header[1] != 1 {
            stream
                .write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(tunnel_io_error)?;
            return Err(tunnel_protocol_error(
                "only SOCKS5 TCP CONNECT is supported",
            ));
        }
        let target_host = read_socks_host(&mut stream, header[3]).await?;
        let target_port = stream.read_u16().await.map_err(tunnel_io_error)?;
        let channel = match handle
            .channel_open_direct_tcpip(
                target_host,
                u32::from(target_port),
                origin.ip().to_string(),
                u32::from(origin.port()),
            )
            .await
        {
            Ok(channel) => channel,
            Err(error) => {
                stream
                    .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .map_err(tunnel_io_error)?;
                return Err(AppError::ssh(
                    "TUNNEL-TARGET-FAILED",
                    "SSH 服务器无法连接动态转发目标",
                    error.to_string(),
                    true,
                ));
            }
        };
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(tunnel_io_error)?;
        let mut remote = channel.into_stream();
        let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut remote)
            .await
            .map_err(tunnel_io_error)?;
        metrics.bytes_up.fetch_add(up, Ordering::Relaxed);
        metrics.bytes_down.fetch_add(down, Ordering::Relaxed);
        Ok(())
    })
    .await
    .map_err(|_| tunnel_protocol_error("SOCKS5 handshake timed out"))?
}

async fn read_socks_host(stream: &mut TcpStream, address_type: u8) -> Result<String, AppError> {
    match address_type {
        1 => {
            let mut octets = [0_u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(tunnel_io_error)?;
            Ok(IpAddr::from(octets).to_string())
        }
        4 => {
            let mut octets = [0_u8; 16];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(tunnel_io_error)?;
            Ok(IpAddr::from(octets).to_string())
        }
        3 => {
            let length = stream.read_u8().await.map_err(tunnel_io_error)? as usize;
            if length == 0 {
                return Err(tunnel_protocol_error("SOCKS5 domain was empty"));
            }
            let mut domain = vec![0_u8; length];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(tunnel_io_error)?;
            String::from_utf8(domain)
                .map_err(|_| tunnel_protocol_error("SOCKS5 domain was not UTF-8"))
        }
        _ => Err(tunnel_protocol_error("SOCKS5 address type was unsupported")),
    }
}

async fn run_remote_forward(
    app: &AppHandle,
    registry: &TunnelRegistry,
    runtime_id: &str,
    profile: TunnelProfile,
    runtime: RemoteForwardRuntime,
    cancellation: oneshot::Receiver<()>,
) -> Result<(), AppError> {
    let requested_port = u32::from(profile.bind_port);
    let returned_port = runtime
        .handle
        .tcpip_forward(profile.bind_host.clone(), requested_port)
        .await
        .map_err(|error| {
            AppError::ssh(
                "TUNNEL-REMOTE-LISTEN-FAILED",
                "服务器拒绝了远程监听请求",
                error.to_string(),
                true,
            )
        })?;
    let bound_port = if profile.bind_port == 0 {
        u16::try_from(returned_port).map_err(|_| {
            AppError::ssh(
                "TUNNEL-REMOTE-LISTEN-FAILED",
                "服务器返回了无效的远程监听端口",
                format!("remote forwarding returned port {returned_port}"),
                false,
            )
        })?
    } else {
        profile.bind_port
    };
    runtime
        .forwards
        .lock()
        .map_err(|_| registry_unavailable())?
        .insert(
            (profile.bind_host.clone(), u32::from(bound_port)),
            RemoteForwardTarget {
                target_host: profile.target_host.clone().unwrap_or_default(),
                target_port: profile.target_port.unwrap_or_default(),
                metrics: runtime.metrics,
            },
        );
    registry.set_running(app, runtime_id, bound_port)?;
    let _ = cancellation.await;
    runtime
        .forwards
        .lock()
        .map_err(|_| registry_unavailable())?
        .remove(&(profile.bind_host.clone(), u32::from(bound_port)));
    runtime
        .handle
        .cancel_tcpip_forward(profile.bind_host, u32::from(bound_port))
        .await
        .map_err(|error| {
            AppError::ssh(
                "TUNNEL-STOP-FAILED",
                "无法撤销服务器远程监听",
                error.to_string(),
                true,
            )
        })
}

pub(crate) async fn bridge_remote_channel(
    channel: Channel<client::Msg>,
    target: RemoteForwardTarget,
) {
    target
        .metrics
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    let result = async {
        let mut local =
            TcpStream::connect((target.target_host.as_str(), target.target_port)).await?;
        let mut remote = channel.into_stream();
        tokio::io::copy_bidirectional(&mut remote, &mut local).await
    }
    .await;
    if let Ok((down, up)) = result {
        target.metrics.bytes_up.fetch_add(up, Ordering::Relaxed);
        target.metrics.bytes_down.fetch_add(down, Ordering::Relaxed);
    }
    target
        .metrics
        .active_connections
        .fetch_sub(1, Ordering::Relaxed);
}

fn snapshot(entry: &TunnelEntry) -> TunnelRuntimeState {
    TunnelRuntimeState {
        active_connections: entry.metrics.active_connections.load(Ordering::Relaxed),
        bytes_up: entry.metrics.bytes_up.load(Ordering::Relaxed),
        bytes_down: entry.metrics.bytes_down.load(Ordering::Relaxed),
        ..entry.state.clone()
    }
}

fn emit_state(app: &AppHandle, state: &TunnelRuntimeState) {
    let _ = app.emit(
        TUNNEL_STATUS_EVENT,
        TunnelStatusPayload {
            tunnel: state.clone(),
        },
    );
}

fn registry_unavailable() -> AppError {
    AppError::ssh(
        "TUNNEL-REGISTRY-UNAVAILABLE",
        "隧道服务暂时不可用",
        "tunnel registry lock was poisoned or runtime disappeared",
        true,
    )
}

fn tunnel_io_error(error: std::io::Error) -> AppError {
    AppError::ssh(
        "TUNNEL-TARGET-FAILED",
        "隧道网络连接中断",
        error.to_string(),
        true,
    )
}

fn tunnel_protocol_error(details: impl Into<String>) -> AppError {
    AppError::ssh(
        "PROXY-PROTOCOL-FAILED",
        "动态转发收到无效 SOCKS5 请求",
        details,
        false,
    )
}
