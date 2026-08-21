use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use russh::{
    client::{self, ChannelOpenHandle, KeyboardInteractiveAuthResponse},
    keys::{agent::AgentIdentity, load_secret_key, ssh_key, PrivateKeyWithHashAlg},
    ChannelMsg, ChannelOpenFailure, Disconnect,
};
use russh_sftp::{client::SftpSession, protocol::FileType};
use tauri::{AppHandle, Emitter, Manager};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, Semaphore},
    task::JoinSet,
};
use zeroize::Zeroizing;

use crate::{
    connection_pool::{ConnectionLease, ConnectionPool, PooledConnection},
    error::AppError,
    known_hosts::{HostKeyIdentity, KnownHostsStore},
    models::{
        AgentIdentityInfo, AuthType, AuthenticationPromptField, AuthenticationPromptPayload,
        ConnectionProgressPayload, ConnectionRequest, ConnectionTestResult, HostKeyApproval,
        HostKeyInspection, JumpHostRequest, RemoteDirectoryEntry, RemoteDirectoryListing,
        RemoteEntryKind, SessionOutputPayload, SessionState, SessionStatus, SessionStatusPayload,
        TransferConflictPolicy, TransferDirection, TransferProgressPayload, TransferStatus,
        TransferTask,
    },
    network,
    session::{SessionCommand, SessionRegistry},
    tunnel::{self, RemoteForwardTable},
};

const SESSION_OUTPUT_EVENT: &str = "session-output";
const SESSION_STATUS_EVENT: &str = "session-status";
const TRANSFER_PROGRESS_EVENT: &str = "transfer-progress";
const AUTHENTICATION_PROMPT_EVENT: &str = "authentication-prompt";
const CONNECTION_PROGRESS_EVENT: &str = "connection-progress";
const INTERACTIVE_AUTH_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_INTERACTIVE_ROUNDS: usize = 16;
const MAX_INTERACTIVE_PROMPTS: usize = 16;

#[derive(Clone, Copy)]
struct AuthenticationContext<'a> {
    app: &'a AppHandle,
    operation_id: &'a str,
}

#[derive(Clone)]
struct ProbeHandler {
    captured_key: Arc<Mutex<Option<ssh_key::PublicKey>>>,
}

impl client::Handler for ProbeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        if let Ok(mut captured_key) = self.captured_key.lock() {
            *captured_key = Some(server_public_key.clone());
        }
        Ok(true)
    }
}

#[derive(Clone)]
pub(crate) struct VerifiedHandler {
    expected_fingerprint: String,
    captured_key: Arc<Mutex<Option<ssh_key::PublicKey>>>,
    remote_forwards: RemoteForwardTable,
}

impl client::Handler for VerifiedHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        if let Ok(mut captured_key) = self.captured_key.lock() {
            *captured_key = Some(server_public_key.clone());
        }
        Ok(fingerprint == self.expected_fingerprint)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let target = self.remote_forwards.lock().ok().and_then(|forwards| {
            forwards
                .get(&(connected_address.to_owned(), connected_port))
                .or_else(|| {
                    forwards
                        .iter()
                        .find(|((_, port), _)| *port == connected_port)
                        .map(|(_, target)| target)
                })
                .cloned()
        });
        if let Some(target) = target {
            reply.accept().await;
            tauri::async_runtime::spawn(tunnel::bridge_remote_channel(channel, target));
        } else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        }
        Ok(())
    }
}

pub async fn inspect_host_key(
    host: &str,
    port: u16,
    timeout: Duration,
    known_hosts_path: PathBuf,
    proxy: Option<&crate::models::ProxyRequest>,
) -> Result<HostKeyInspection, AppError> {
    let captured_key = Arc::new(Mutex::new(None));
    let handler = ProbeHandler {
        captured_key: Arc::clone(&captured_key),
    };
    let config = Arc::new(client_config(None));
    let connection = if let Some(proxy) = proxy {
        let stream = network::connect_target(host, port, Some(proxy), timeout).await?;
        tokio::time::timeout(timeout, client::connect_stream(config, stream, handler))
            .await
            .map_err(|_| connection_timeout())?
            .map_err(map_connect_error)?
    } else {
        tokio::time::timeout(
            timeout,
            client::connect(config, (host.to_owned(), port), handler),
        )
        .await
        .map_err(|_| connection_timeout())?
        .map_err(map_connect_error)?
    };
    let _ = connection
        .disconnect(Disconnect::ByApplication, "host key inspected", "")
        .await;

    let key = captured_key
        .lock()
        .map_err(|_| {
            AppError::ssh(
                "HOST-KEY-READ-FAILED",
                "无法读取服务器指纹",
                "host key capture lock was poisoned",
                true,
            )
        })?
        .clone()
        .ok_or_else(|| {
            AppError::ssh(
                "HOST-KEY-MISSING",
                "服务器未提供可验证的主机密钥",
                "SSH handshake completed without a captured server key",
                false,
            )
        })?;
    let identity = HostKeyIdentity::from_public_key(&key).map_err(map_russh_error)?;
    KnownHostsStore::new(known_hosts_path).inspect(host, port, &identity)
}

pub async fn inspect_route_host_key(
    app: AppHandle,
    operation_id: String,
    mut request: ConnectionRequest,
    known_hosts_path: PathBuf,
) -> Result<HostKeyInspection, AppError> {
    request.validate().map_err(AppError::validation)?;
    let authentication_context = AuthenticationContext {
        app: &app,
        operation_id: &operation_id,
    };
    let jumps = std::mem::take(&mut request.jump_hosts);
    let mut upstream = connect_jump_chain(jumps, Some(authentication_context)).await?;
    emit_route_progress(
        &app,
        &operation_id,
        SessionStatus::HostKeyCheck,
        "正在获取目标服务器指纹",
    );
    let result = inspect_host_key_over_route(&request, upstream.last(), &known_hosts_path).await;
    disconnect_upstream(&mut upstream, "route inspection complete").await;
    result
}

pub async fn test_connection(
    app: AppHandle,
    operation_id: String,
    mut request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
) -> Result<ConnectionTestResult, AppError> {
    request.validate().map_err(AppError::validation)?;
    let started_at = Instant::now();
    let host = request.host.clone();
    let port = request.port;
    let timeout = authentication_timeout(&request);
    let (handle, identity, _, mut upstream) = tokio::time::timeout(
        timeout,
        connect_route_authenticated(
            &mut request,
            &approval.fingerprint_sha256,
            Some(AuthenticationContext {
                app: &app,
                operation_id: &operation_id,
            }),
        ),
    )
    .await
    .map_err(|_| connection_timeout())??;

    KnownHostsStore::new(known_hosts_path.clone()).approve(
        &host,
        port,
        &identity,
        approval.action,
    )?;
    let inspection = KnownHostsStore::new(known_hosts_path).inspect(&host, port, &identity)?;
    let _ = handle
        .disconnect(Disconnect::ByApplication, "connection test complete", "")
        .await;
    disconnect_upstream(&mut upstream, "connection test complete").await;

    Ok(ConnectionTestResult {
        elapsed_millis: started_at.elapsed().as_millis(),
        host_key: inspection,
    })
}

pub async fn start_session(
    app: AppHandle,
    operation_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
) -> Result<SessionState, AppError> {
    start_session_with_id(
        app,
        operation_id,
        request,
        approval,
        known_hosts_path,
        None,
        None,
    )
    .await
}

pub async fn start_pooled_session(
    app: AppHandle,
    operation_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
    pool_key: String,
) -> Result<SessionState, AppError> {
    start_session_with_id(
        app,
        operation_id,
        request,
        approval,
        known_hosts_path,
        None,
        Some(pool_key),
    )
    .await
}

pub async fn reconnect_session(
    app: AppHandle,
    operation_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
    session_id: String,
) -> Result<SessionState, AppError> {
    start_session_with_id(
        app,
        operation_id,
        request,
        approval,
        known_hosts_path,
        Some(session_id),
        None,
    )
    .await
}

pub async fn reconnect_pooled_session(
    app: AppHandle,
    operation_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
    session_id: String,
    pool_key: String,
) -> Result<SessionState, AppError> {
    start_session_with_id(
        app,
        operation_id,
        request,
        approval,
        known_hosts_path,
        Some(session_id),
        Some(pool_key),
    )
    .await
}

async fn start_session_with_id(
    app: AppHandle,
    operation_id: String,
    mut request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
    session_id: Option<String>,
    pool_key: Option<String>,
) -> Result<SessionState, AppError> {
    request.validate().map_err(AppError::validation)?;
    let timeout = authentication_timeout(&request);
    let title = request.name.clone();
    let host = request.host.clone();
    let port = request.port;
    let columns = request.columns;
    let rows = request.rows;
    let pool = app.state::<ConnectionPool>();
    let mut lease = if let Some(key) = pool_key.as_deref() {
        pool.acquire(key)?
    } else {
        None
    };
    let mut channel = match lease.as_ref() {
        Some(existing_lease) => match existing_lease.handle().channel_open_session().await {
            Ok(channel) => Some(channel),
            Err(_) => {
                if let Some(key) = pool_key.as_deref() {
                    pool.invalidate(key)?;
                }
                lease = None;
                None
            }
        },
        None => None,
    };
    if lease.is_none() {
        let (handle, identity, remote_forwards, upstream) = tokio::time::timeout(
            timeout,
            connect_route_authenticated(
                &mut request,
                &approval.fingerprint_sha256,
                Some(AuthenticationContext {
                    app: &app,
                    operation_id: &operation_id,
                }),
            ),
        )
        .await
        .map_err(|_| connection_timeout())??;
        KnownHostsStore::new(known_hosts_path).approve(&host, port, &identity, approval.action)?;
        let connection = PooledConnection::new(handle, remote_forwards, upstream);
        let acquired = if let Some(key) = pool_key {
            pool.adopt(key, connection)?
        } else {
            pool.standalone(connection)
        };
        channel = Some(
            acquired
                .handle()
                .channel_open_session()
                .await
                .map_err(map_russh_error)?,
        );
        lease = Some(acquired);
    }
    let lease = lease.ok_or_else(|| {
        AppError::ssh(
            "CONNECTION-POOL-UNAVAILABLE",
            "无法取得 SSH 连接租约",
            "connection lease was absent after acquisition",
            true,
        )
    })?;
    let channel = channel.ok_or_else(|| {
        AppError::ssh(
            "SSH-CHANNEL-FAILED",
            "无法打开远程终端通道",
            "session channel was absent after connection acquisition",
            true,
        )
    })?;
    channel
        .request_pty(
            true,
            "xterm-256color",
            u32::from(columns),
            u32::from(rows),
            0,
            0,
            &[],
        )
        .await
        .map_err(map_russh_error)?;
    channel.request_shell(true).await.map_err(map_russh_error)?;

    let session_id = session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let (commands_tx, commands_rx) = mpsc::channel(128);
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    app.state::<SessionRegistry>()
        .insert_ssh(session_id.clone(), commands_tx, completion_rx)?;

    let task_app = app.clone();
    let task_session_id = session_id.clone();
    tauri::async_runtime::spawn(async move {
        run_session(task_app, task_session_id, channel, commands_rx, lease).await;
        let _ = completion_tx.send(());
    });

    Ok(SessionState {
        id: session_id,
        title,
        status: SessionStatus::Connected,
        started_at: chrono::Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
async fn connect_authenticated(
    request: &mut ConnectionRequest,
    expected_fingerprint: &str,
    authentication_context: Option<AuthenticationContext<'_>>,
) -> Result<
    (
        client::Handle<VerifiedHandler>,
        HostKeyIdentity,
        RemoteForwardTable,
    ),
    AppError,
> {
    connect_authenticated_over_stream(request, expected_fingerprint, authentication_context, None)
        .await
}

async fn connect_route_authenticated(
    request: &mut ConnectionRequest,
    expected_fingerprint: &str,
    authentication_context: Option<AuthenticationContext<'_>>,
) -> Result<
    (
        client::Handle<VerifiedHandler>,
        HostKeyIdentity,
        RemoteForwardTable,
        Vec<client::Handle<VerifiedHandler>>,
    ),
    AppError,
> {
    let jumps = std::mem::take(&mut request.jump_hosts);
    let mut upstream = connect_jump_chain(jumps, authentication_context).await?;
    let stream = match upstream.last() {
        Some(handle) => match stream_from_upstream(handle, request).await {
            Ok(stream) => Some(stream),
            Err(error) => {
                disconnect_upstream(&mut upstream, "target route failed").await;
                return Err(error);
            }
        },
        None => None,
    };
    match connect_authenticated_over_stream(
        request,
        expected_fingerprint,
        authentication_context,
        stream,
    )
    .await
    {
        Ok((handle, identity, forwards)) => Ok((handle, identity, forwards, upstream)),
        Err(error) => {
            disconnect_upstream(&mut upstream, "target connection failed").await;
            Err(error)
        }
    }
}

async fn connect_authenticated_over_stream(
    request: &mut ConnectionRequest,
    expected_fingerprint: &str,
    authentication_context: Option<AuthenticationContext<'_>>,
    stream: Option<network::BoxedNetworkStream>,
) -> Result<
    (
        client::Handle<VerifiedHandler>,
        HostKeyIdentity,
        RemoteForwardTable,
    ),
    AppError,
> {
    let captured_key = Arc::new(Mutex::new(None));
    let remote_forwards = RemoteForwardTable::default();
    let handler = VerifiedHandler {
        expected_fingerprint: expected_fingerprint.to_owned(),
        captured_key: Arc::clone(&captured_key),
        remote_forwards: Arc::clone(&remote_forwards),
    };
    let keepalive = request
        .keepalive_enabled
        .then(|| Duration::from_secs(request.keepalive_seconds));
    let config = Arc::new(client_config(keepalive));
    let connection = async {
        if let Some(stream) = stream {
            client::connect_stream(config, stream, handler)
                .await
                .map_err(map_connect_error)
        } else if let Some(proxy) = request.proxy.as_ref() {
            let stream = network::connect_target(
                &request.host,
                request.port,
                Some(proxy),
                Duration::from_secs(request.timeout_seconds),
            )
            .await?;
            client::connect_stream(config, stream, handler)
                .await
                .map_err(map_connect_error)
        } else {
            client::connect(config, (request.host.clone(), request.port), handler)
                .await
                .map_err(map_connect_error)
        }
    };
    let mut handle = connection.await.map_err(|error| {
        let actual = captured_key
            .lock()
            .ok()
            .and_then(|key| key.clone())
            .map(|key| key.fingerprint(russh::keys::HashAlg::Sha256).to_string());
        if actual
            .as_deref()
            .is_some_and(|value| value != expected_fingerprint)
        {
            AppError::ssh(
                "HOST-KEY-CHANGED",
                "服务器身份与确认时不一致，连接已阻止",
                "server host key changed between inspection and connection",
                false,
            )
        } else {
            error
        }
    })?;

    let key = captured_key
        .lock()
        .map_err(|_| {
            AppError::ssh(
                "HOST-KEY-READ-FAILED",
                "无法读取服务器指纹",
                "host key capture lock was poisoned",
                true,
            )
        })?
        .clone()
        .ok_or_else(|| {
            AppError::ssh(
                "HOST-KEY-MISSING",
                "服务器未提供可验证的主机密钥",
                "SSH handshake completed without a captured server key",
                false,
            )
        })?;
    let identity = HostKeyIdentity::from_public_key(&key).map_err(map_russh_error)?;

    let authentication = match request.auth_type {
        AuthType::Password => {
            let password = Zeroizing::new(request.password.take().unwrap_or_default());
            handle
                .authenticate_password(request.username.clone(), password.as_str())
                .await
                .map_err(map_russh_error)?
        }
        AuthType::PrivateKey => {
            let path = request.private_key_path.take().unwrap_or_default();
            let passphrase = request.private_key_passphrase.take().map(Zeroizing::new);
            let key = tokio::task::spawn_blocking(move || {
                load_secret_key(path, passphrase.as_ref().map(|value| value.as_str()))
            })
            .await
            .map_err(|error| {
                AppError::ssh(
                    "PRIVATE-KEY-READ-FAILED",
                    "无法读取所选私钥",
                    error.to_string(),
                    true,
                )
            })?
            .map_err(map_private_key_error)?;
            let hash_algorithm = handle
                .best_supported_rsa_hash()
                .await
                .map_err(map_russh_error)?
                .flatten();
            handle
                .authenticate_publickey(
                    request.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash_algorithm),
                )
                .await
                .map_err(map_russh_error)?
        }
        AuthType::KeyboardInteractive => {
            authenticate_keyboard_interactive(&mut handle, request, authentication_context).await?
        }
        AuthType::Agent => {
            authenticate_with_agent(
                &mut handle,
                &request.username,
                request.agent_key_fingerprint.as_deref(),
            )
            .await?
        }
    };

    if !authentication.success() {
        let remaining = format!("authentication rejected: {authentication:?}");
        return Err(AppError::ssh(
            "AUTHENTICATION-FAILED",
            "认证失败，请检查用户名和凭据",
            remaining,
            true,
        ));
    }

    Ok((handle, identity, remote_forwards))
}

async fn connect_jump_chain(
    jumps: Vec<JumpHostRequest>,
    authentication_context: Option<AuthenticationContext<'_>>,
) -> Result<Vec<client::Handle<VerifiedHandler>>, AppError> {
    let total = jumps.len();
    let mut upstream = Vec::with_capacity(total);
    for (index, mut jump) in jumps.into_iter().enumerate() {
        if let Some(context) = authentication_context {
            emit_route_progress(
                context.app,
                context.operation_id,
                SessionStatus::Connecting,
                &format!(
                    "正在连接第 {}/{} 跳：{}",
                    index + 1,
                    total,
                    jump.connection.name
                ),
            );
        }
        let stream = match upstream.last() {
            Some(handle) => match stream_from_upstream(handle, &jump.connection).await {
                Ok(stream) => Some(stream),
                Err(error) => {
                    disconnect_upstream(&mut upstream, "jump route failed").await;
                    return Err(map_jump_error(index, total, &jump.connection, error));
                }
            },
            None => None,
        };
        match connect_authenticated_over_stream(
            &mut jump.connection,
            &jump.expected_fingerprint,
            authentication_context,
            stream,
        )
        .await
        {
            Ok((handle, _, _)) => upstream.push(handle),
            Err(error) => {
                disconnect_upstream(&mut upstream, "jump authentication failed").await;
                return Err(map_jump_error(index, total, &jump.connection, error));
            }
        }
    }
    Ok(upstream)
}

async fn stream_from_upstream(
    upstream: &client::Handle<VerifiedHandler>,
    request: &ConnectionRequest,
) -> Result<network::BoxedNetworkStream, AppError> {
    let (connect_host, connect_port) = request
        .proxy
        .as_ref()
        .map(|proxy| (proxy.host.as_str(), proxy.port))
        .unwrap_or((request.host.as_str(), request.port));
    let channel = upstream
        .channel_open_direct_tcpip(connect_host, u32::from(connect_port), "127.0.0.1", 0)
        .await
        .map_err(|error| {
            AppError::ssh(
                "JUMP-HOST-FAILED",
                "跳板服务器无法连接下一节点",
                error.to_string(),
                true,
            )
        })?;
    network::connect_over_stream(
        Box::pin(channel.into_stream()),
        &request.host,
        request.port,
        request.proxy.as_ref(),
        Duration::from_secs(request.timeout_seconds),
    )
    .await
}

async fn inspect_host_key_over_route(
    request: &ConnectionRequest,
    upstream: Option<&client::Handle<VerifiedHandler>>,
    known_hosts_path: &std::path::Path,
) -> Result<HostKeyInspection, AppError> {
    let upstream = match upstream {
        Some(upstream) => upstream,
        None => {
            return inspect_host_key(
                &request.host,
                request.port,
                Duration::from_secs(request.timeout_seconds),
                known_hosts_path.to_path_buf(),
                request.proxy.as_ref(),
            )
            .await
        }
    };
    let captured_key = Arc::new(Mutex::new(None));
    let stream = stream_from_upstream(upstream, request).await?;
    let handle = tokio::time::timeout(
        Duration::from_secs(request.timeout_seconds),
        client::connect_stream(
            Arc::new(client_config(None)),
            stream,
            ProbeHandler {
                captured_key: Arc::clone(&captured_key),
            },
        ),
    )
    .await
    .map_err(|_| connection_timeout())?
    .map_err(map_connect_error)?;
    let _ = handle
        .disconnect(Disconnect::ByApplication, "host key inspected", "")
        .await;
    let key = captured_key
        .lock()
        .map_err(|_| {
            AppError::ssh(
                "HOST-KEY-READ-FAILED",
                "无法读取服务器指纹",
                "host key capture lock was poisoned",
                true,
            )
        })?
        .clone()
        .ok_or_else(|| {
            AppError::ssh(
                "HOST-KEY-MISSING",
                "服务器未提供可验证的主机密钥",
                "SSH handshake completed without a captured server key",
                false,
            )
        })?;
    let identity = HostKeyIdentity::from_public_key(&key).map_err(map_russh_error)?;
    KnownHostsStore::new(known_hosts_path.to_path_buf()).inspect(
        &request.host,
        request.port,
        &identity,
    )
}

async fn disconnect_upstream(upstream: &mut Vec<client::Handle<VerifiedHandler>>, reason: &str) {
    while let Some(handle) = upstream.pop() {
        let _ = handle
            .disconnect(Disconnect::ByApplication, reason, "")
            .await;
    }
}

fn map_jump_error(
    index: usize,
    total: usize,
    request: &ConnectionRequest,
    error: AppError,
) -> AppError {
    AppError::ssh(
        "JUMP-HOST-FAILED",
        format!("第 {}/{} 跳“{}”连接失败", index + 1, total, request.name),
        format!(
            "jump {}/{} target={}:{} cause={} details={}",
            index + 1,
            total,
            request.host,
            request.port,
            error.code,
            error.technical_details.as_deref().unwrap_or("none")
        ),
        error.retryable,
    )
}

fn emit_route_progress(app: &AppHandle, operation_id: &str, status: SessionStatus, message: &str) {
    let _ = app.emit(
        CONNECTION_PROGRESS_EVENT,
        ConnectionProgressPayload {
            operation_id: operation_id.to_owned(),
            status,
            message: message.to_owned(),
        },
    );
}

fn authentication_timeout(request: &ConnectionRequest) -> Duration {
    std::iter::once(request)
        .chain(request.jump_hosts.iter().map(|jump| &jump.connection))
        .map(|connection| match connection.auth_type {
            AuthType::KeyboardInteractive => INTERACTIVE_AUTH_TIMEOUT + Duration::from_secs(30),
            _ => Duration::from_secs(connection.timeout_seconds),
        })
        .sum()
}

async fn authenticate_keyboard_interactive(
    handle: &mut client::Handle<VerifiedHandler>,
    request: &ConnectionRequest,
    context: Option<AuthenticationContext<'_>>,
) -> Result<russh::client::AuthResult, AppError> {
    let context = context.ok_or_else(|| {
        AppError::ssh(
            "AUTH-INTERACTIVE-UNAVAILABLE",
            "当前环境无法显示服务器认证请求",
            "keyboard-interactive authentication requires an application event context",
            false,
        )
    })?;
    let mut response = handle
        .authenticate_keyboard_interactive_start(request.username.clone(), None)
        .await
        .map_err(map_russh_error)?;

    for _ in 0..MAX_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(russh::client::AuthResult::Success)
            }
            KeyboardInteractiveAuthResponse::Failure { .. } => {
                return Err(AppError::ssh(
                    "AUTH-INTERACTIVE-REJECTED",
                    "服务器拒绝了交互式认证",
                    "keyboard-interactive authentication was rejected",
                    true,
                ))
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                if prompts.len() > MAX_INTERACTIVE_PROMPTS {
                    return Err(AppError::ssh(
                        "AUTH-INTERACTIVE-LIMIT",
                        "服务器返回的认证问题过多",
                        format!("received {} prompts in one round", prompts.len()),
                        false,
                    ));
                }
                let answer_ids = (0..prompts.len())
                    .map(|index| format!("answer-{index}"))
                    .collect::<Vec<_>>();
                let broker = context
                    .app
                    .state::<crate::authentication::AuthenticationBroker>();
                let pending = broker.register(context.operation_id, answer_ids.clone())?;
                let payload = AuthenticationPromptPayload {
                    operation_id: context.operation_id.to_owned(),
                    prompt_id: pending.prompt_id().to_owned(),
                    connection_title: request.name.clone(),
                    target: format!("{}@{}:{}", request.username, request.host, request.port),
                    name,
                    instructions,
                    prompts: prompts
                        .into_iter()
                        .zip(answer_ids)
                        .map(|(prompt, id)| AuthenticationPromptField {
                            id,
                            text: prompt.prompt,
                            echo: prompt.echo,
                        })
                        .collect(),
                };
                context
                    .app
                    .emit(AUTHENTICATION_PROMPT_EVENT, payload)
                    .map_err(|error| {
                        AppError::event_delivery_failed(AUTHENTICATION_PROMPT_EVENT, error)
                    })?;
                let answers = tokio::time::timeout(INTERACTIVE_AUTH_TIMEOUT, pending.wait())
                    .await
                    .map_err(|_| {
                        AppError::ssh(
                            "AUTH-INTERACTIVE-TIMEOUT",
                            "等待认证输入超时，请重新连接",
                            "keyboard-interactive prompt timed out",
                            true,
                        )
                    })??;
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(map_russh_error)?;
            }
        }
    }
    Err(AppError::ssh(
        "AUTH-INTERACTIVE-LIMIT",
        "服务器认证轮次过多，连接已停止",
        "keyboard-interactive authentication exceeded the round limit",
        false,
    ))
}

async fn authenticate_with_agent(
    handle: &mut client::Handle<VerifiedHandler>,
    username: &str,
    preferred_fingerprint: Option<&str>,
) -> Result<russh::client::AuthResult, AppError> {
    let mut agent = connect_system_agent().await?;
    let identities = agent.request_identities().await.map_err(map_agent_error)?;
    let mut identities = identities
        .into_iter()
        .filter_map(|identity| match identity {
            AgentIdentity::PublicKey { key, comment } => Some((key, comment)),
            AgentIdentity::Certificate { .. } => None,
        })
        .collect::<Vec<_>>();
    if let Some(preferred) = preferred_fingerprint {
        identities.sort_by_key(|(key, _)| {
            key.fingerprint(russh::keys::HashAlg::Sha256).to_string() != preferred
        });
    }
    let hash_algorithm = handle
        .best_supported_rsa_hash()
        .await
        .map_err(map_russh_error)?
        .flatten();
    let mut attempted = false;
    for (key, _) in identities {
        attempted = true;
        let result = handle
            .authenticate_publickey_with(username.to_owned(), key, hash_algorithm, &mut agent)
            .await
            .map_err(|error| {
                AppError::ssh(
                    "AUTH-AGENT-SIGN-FAILED",
                    "SSH Agent 未能完成签名",
                    error.to_string(),
                    true,
                )
            })?;
        if result.success() {
            return Ok(result);
        }
    }
    Err(AppError::ssh(
        if attempted {
            "AUTH-AGENT-REJECTED"
        } else {
            "AUTH-AGENT-NO-KEYS"
        },
        if attempted {
            "服务器未接受 SSH Agent 中的密钥"
        } else {
            "SSH Agent 中没有可用密钥"
        },
        "no plain SSH agent identity authenticated successfully",
        true,
    ))
}

pub async fn list_agent_identities() -> Result<Vec<AgentIdentityInfo>, AppError> {
    let mut agent = connect_system_agent().await?;
    let identities = agent.request_identities().await.map_err(map_agent_error)?;
    Ok(identities
        .into_iter()
        .filter_map(|identity| match identity {
            AgentIdentity::PublicKey { key, comment } => Some(AgentIdentityInfo {
                fingerprint_sha256: key.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
                algorithm: key.algorithm().to_string(),
                comment,
            }),
            AgentIdentity::Certificate { .. } => None,
        })
        .collect())
}

#[cfg(windows)]
async fn connect_system_agent() -> Result<
    russh::keys::agent::client::AgentClient<
        Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>,
    >,
    AppError,
> {
    tokio::time::timeout(
        Duration::from_secs(3),
        russh::keys::agent::client::AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent"),
    )
    .await
    .map_err(|_| agent_unavailable("SSH agent named-pipe connection timed out".to_owned()))?
    .map(|agent| agent.dynamic())
    .map_err(map_agent_error)
}

#[cfg(unix)]
async fn connect_system_agent() -> Result<
    russh::keys::agent::client::AgentClient<
        Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>,
    >,
    AppError,
> {
    russh::keys::agent::client::AgentClient::connect_env()
        .await
        .map(|agent| agent.dynamic())
        .map_err(map_agent_error)
}

fn map_agent_error(error: russh::keys::Error) -> AppError {
    agent_unavailable(error.to_string())
}

fn agent_unavailable(details: String) -> AppError {
    AppError::ssh(
        "AUTH-AGENT-UNAVAILABLE",
        "无法连接系统 SSH Agent，请确认 OpenSSH Authentication Agent 服务已启动",
        details,
        true,
    )
}

async fn run_session(
    app: AppHandle,
    session_id: String,
    channel: russh::Channel<client::Msg>,
    mut commands: mpsc::Receiver<SessionCommand>,
    lease: ConnectionLease,
) {
    app.state::<crate::diagnostics::DiagnosticLog>().record(
        "ssh-session-start",
        None,
        &format!("session={session_id}"),
    );
    let handle = lease.handle();
    let (sftp_commands, sftp_receiver) = mpsc::channel(8);
    let sftp_worker =
        tauri::async_runtime::spawn(run_sftp_worker(Arc::clone(&handle), sftp_receiver));
    let transfer_slots = Arc::new(Semaphore::new(3));
    let mut transfer_cancellations =
        std::collections::HashMap::<String, oneshot::Sender<()>>::new();
    let mut transfer_handles = JoinSet::new();
    let (mut reader, writer) = channel.split();
    let mut output_buffer = Vec::with_capacity(64 * 1024);
    let mut output_flush = tokio::time::interval(Duration::from_millis(16));
    output_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    output_flush.tick().await;
    let final_message = loop {
        tokio::select! {
            _ = output_flush.tick(), if !output_buffer.is_empty() => {
                if let Err(error) = emit_terminal_output(&app, &session_id, std::mem::take(&mut output_buffer)) {
                    break format!("终端数据发送失败：{}", error.message);
                }
            }
            command = commands.recv() => match command {
                Some(SessionCommand::Data(data)) => {
                    if let Err(error) = writer.data_bytes(data).await {
                        break format!("网络写入失败：{error}");
                    }
                }
                Some(SessionCommand::Resize { columns, rows }) => {
                    if let Err(error) = writer.window_change(u32::from(columns), u32::from(rows), 0, 0).await {
                        log::warn!("PTY resize failed for session {session_id}: {error}");
                    }
                }
                Some(SessionCommand::ListRemoteDirectory { path, cursor, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::Browse { path, cursor, response });
                }
                Some(SessionCommand::CreateRemoteDirectory { parent_path, name, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::CreateDirectory { parent_path, name, response });
                }
                Some(SessionCommand::RenameRemoteEntry { path, new_name, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::Rename { path, new_name, response });
                }
                Some(SessionCommand::DeleteRemoteEntry { paths, recursive, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::Delete { paths, recursive, response });
                }
                Some(SessionCommand::ChangeRemotePermissions { paths, mode, recursive, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::ChangePermissions { paths, mode, recursive, response });
                }
                Some(SessionCommand::StartTransfer { direction, sources, target_directory, conflict_policy, response }) => {
                    let task = new_transfer_task(&session_id, direction, sources, target_directory, conflict_policy);
                    let (cancel, cancellation) = oneshot::channel();
                    transfer_cancellations.insert(task.id.clone(), cancel);
                    let _ = response.send(Ok(task.clone()));
                    emit_transfer(&app, task.clone());
                    let transfer_app = app.clone();
                    let transfer_handle = Arc::clone(&handle);
                    let transfer_slots = Arc::clone(&transfer_slots);
                    let task_id = task.id.clone();
                    transfer_handles.spawn(async move {
                        run_transfer(transfer_app, transfer_handle, transfer_slots, task, cancellation).await;
                        task_id
                    });
                }
                Some(SessionCommand::CancelTransfer { task_id }) => {
                    if let Some(cancellation) = transfer_cancellations.remove(&task_id) {
                        let _ = cancellation.send(());
                    }
                }
                Some(SessionCommand::StartTunnel { profile, response }) => {
                    let result = app
                        .state::<crate::tunnel::TunnelRegistry>()
                        .start(
                            app.clone(),
                            session_id.clone(),
                            profile,
                            lease.clone(),
                        )
                        .await;
                    let _ = response.send(result);
                }
                Some(SessionCommand::Close) | None => {
                    let _ = writer.close().await;
                    break "会话已关闭".to_owned();
                }
            },
            completed = transfer_handles.join_next(), if !transfer_handles.is_empty() => {
                if let Some(Ok(task_id)) = completed {
                    transfer_cancellations.remove(&task_id);
                }
            }
            message = reader.wait() => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    output_buffer.extend_from_slice(&data);
                    if output_buffer.len() >= 64 * 1024 {
                        if let Err(error) = emit_terminal_output(&app, &session_id, std::mem::take(&mut output_buffer)) {
                            break format!("终端数据发送失败：{}", error.message);
                        }
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    break format!("远端 Shell 已退出，状态码 {exit_status}");
                }
                Some(ChannelMsg::Eof) => {
                    break "远端 Shell 已结束输出".to_owned();
                }
                Some(ChannelMsg::Close) => {
                    break "服务器已关闭当前会话".to_owned();
                }
                None => {
                    break "网络连接已中断或服务器已关闭会话".to_owned();
                }
                _ => {}
            }
        }
    };

    if !output_buffer.is_empty() {
        let _ = emit_terminal_output(&app, &session_id, output_buffer);
    }
    drop(sftp_commands);
    sftp_worker.abort();
    let _ = sftp_worker.await;
    for (_, cancellation) in transfer_cancellations.drain() {
        let _ = cancellation.send(());
    }
    let _ = tokio::time::timeout(Duration::from_millis(1200), async {
        while transfer_handles.join_next().await.is_some() {}
    })
    .await;
    drop(handle);
    drop(lease);
    let _ = app.state::<SessionRegistry>().remove_finished(&session_id);
    let _ = app.emit(
        SESSION_STATUS_EVENT,
        SessionStatusPayload {
            session_id: session_id.clone(),
            status: SessionStatus::Disconnected,
            message: Some(final_message.clone()),
        },
    );
    app.state::<crate::diagnostics::DiagnosticLog>().record(
        "ssh-session-end",
        None,
        &format!("session={session_id} result={final_message}"),
    );
}

enum SftpRequest {
    Browse {
        path: String,
        cursor: Option<String>,
        response: tokio::sync::oneshot::Sender<Result<RemoteDirectoryListing, AppError>>,
    },
    CreateDirectory {
        parent_path: String,
        name: String,
        response: tokio::sync::oneshot::Sender<Result<(), AppError>>,
    },
    Rename {
        path: String,
        new_name: String,
        response: tokio::sync::oneshot::Sender<Result<(), AppError>>,
    },
    Delete {
        paths: Vec<String>,
        recursive: bool,
        response: tokio::sync::oneshot::Sender<Result<(), AppError>>,
    },
    ChangePermissions {
        paths: Vec<String>,
        mode: u32,
        recursive: bool,
        response: tokio::sync::oneshot::Sender<Result<(), AppError>>,
    },
}

fn enqueue_sftp_request(sender: &mpsc::Sender<SftpRequest>, request: SftpRequest) {
    if let Err(error) = sender.try_send(request) {
        let failure = || {
            AppError::sftp(
                "SFTP-BUSY",
                "文件操作请求过多，请稍后重试",
                "SFTP request queue is full or closed",
            )
        };
        match error.into_inner() {
            SftpRequest::Browse { response, .. } => {
                let _ = response.send(Err(failure()));
            }
            SftpRequest::CreateDirectory { response, .. }
            | SftpRequest::Rename { response, .. }
            | SftpRequest::Delete { response, .. }
            | SftpRequest::ChangePermissions { response, .. } => {
                let _ = response.send(Err(failure()));
            }
        }
    }
}

async fn run_sftp_worker(
    handle: Arc<client::Handle<VerifiedHandler>>,
    mut requests: mpsc::Receiver<SftpRequest>,
) {
    let mut sftp = None;
    while let Some(request) = requests.recv().await {
        match request {
            SftpRequest::Browse {
                path,
                cursor,
                response,
            } => {
                let _ =
                    response.send(browse_remote_directory(&handle, &mut sftp, path, cursor).await);
            }
            SftpRequest::CreateDirectory {
                parent_path,
                name,
                response,
            } => {
                let _ = response
                    .send(create_remote_directory(&handle, &mut sftp, parent_path, name).await);
            }
            SftpRequest::Rename {
                path,
                new_name,
                response,
            } => {
                let _ =
                    response.send(rename_remote_entry(&handle, &mut sftp, path, new_name).await);
            }
            SftpRequest::Delete {
                paths,
                recursive,
                response,
            } => {
                let _ = response
                    .send(delete_remote_entries(&handle, &mut sftp, paths, recursive).await);
            }
            SftpRequest::ChangePermissions {
                paths,
                mode,
                recursive,
                response,
            } => {
                let _ = response.send(
                    change_remote_permissions(&handle, &mut sftp, paths, mode, recursive).await,
                );
            }
        }
    }
    if let Some(session) = sftp {
        let _ = session.close().await;
    }
}

async fn ensure_sftp_session<'a>(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &'a mut Option<SftpSession>,
) -> Result<&'a SftpSession, AppError> {
    if sftp.is_none() {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(map_sftp_ssh_error)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(map_sftp_ssh_error)?;
        let session = SftpSession::new(channel.into_stream())
            .await
            .map_err(map_sftp_error)?;
        session.set_timeout(1);
        *sftp = Some(session);
    }
    Ok(sftp.as_ref().expect("SFTP session initialized above"))
}

async fn browse_remote_directory(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &mut Option<SftpSession>,
    requested_path: String,
    cursor: Option<String>,
) -> Result<RemoteDirectoryListing, AppError> {
    let session = ensure_sftp_session(handle, sftp).await?;
    let result = async {
        let path = session
            .canonicalize(requested_path)
            .await
            .map_err(map_sftp_error)?;
        let raw_entries = session
            .read_dir(path.clone())
            .await
            .map_err(map_sftp_error)?
            .collect::<Vec<_>>();
        if raw_entries.len() > 100_000 {
            return Err(AppError::sftp(
                "SFTP-RECURSIVE-LIMIT",
                "远端目录条目超过安全上限",
                "directory contains more than 100000 entries",
            ));
        }
        let mut entries = Vec::with_capacity(raw_entries.len());
        for entry in raw_entries {
            let metadata = entry.metadata();
            let file_type = entry.file_type();
            let entry_path = entry.path();
            entries.push(RemoteDirectoryEntry {
                name: entry.file_name(),
                path: entry_path.clone(),
                kind: match file_type {
                    FileType::Dir => RemoteEntryKind::Directory,
                    FileType::File => RemoteEntryKind::File,
                    FileType::Symlink => RemoteEntryKind::Symlink,
                    FileType::Other => RemoteEntryKind::Other,
                },
                size: metadata.size.unwrap_or(0),
                modified_at: metadata
                    .modified()
                    .ok()
                    .map(|value| chrono::DateTime::<chrono::Utc>::from(value).to_rfc3339()),
                permissions: format!(
                    "{}{}",
                    match file_type {
                        FileType::Dir => "d",
                        FileType::File => "-",
                        FileType::Symlink => "l",
                        FileType::Other => "?",
                    },
                    metadata.permissions()
                ),
                permission_mode: metadata.permissions.map(|mode| mode & 0o7777),
                uid: metadata.uid,
                gid: metadata.gid,
                symlink_target: if file_type == FileType::Symlink {
                    session.read_link(entry_path).await.ok()
                } else {
                    None
                },
            });
        }
        entries.sort_by(|left, right| {
            let left_directory = left.kind == RemoteEntryKind::Directory;
            let right_directory = right.kind == RemoteEntryKind::Directory;
            right_directory
                .cmp(&left_directory)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        let offset = cursor
            .as_deref()
            .unwrap_or("0")
            .parse::<usize>()
            .map_err(|_| AppError::validation("目录加载游标无效"))?;
        let total = entries.len();
        let page = entries
            .into_iter()
            .skip(offset)
            .take(1000)
            .collect::<Vec<_>>();
        let next_offset = offset.saturating_add(page.len());
        let next_cursor = (next_offset < total).then(|| next_offset.to_string());
        Ok(RemoteDirectoryListing {
            parent_path: parent_remote_path(&path),
            path,
            entries: page,
            truncated: next_cursor.is_some(),
            next_cursor,
        })
    }
    .await;

    if result.is_err() {
        *sftp = None;
    }
    result
}

async fn create_remote_directory(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &mut Option<SftpSession>,
    parent_path: String,
    name: String,
) -> Result<(), AppError> {
    let session = ensure_sftp_session(handle, sftp).await?;
    let parent = session
        .canonicalize(parent_path)
        .await
        .map_err(map_sftp_error)?;
    let target = join_remote_path(&parent, &name);
    if session
        .try_exists(target.clone())
        .await
        .map_err(map_sftp_error)?
    {
        return Err(AppError::sftp(
            "SFTP-TARGET-EXISTS",
            "同名文件或目录已存在",
            target,
        ));
    }
    session.create_dir(target).await.map_err(map_sftp_error)
}

async fn rename_remote_entry(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &mut Option<SftpSession>,
    path: String,
    new_name: String,
) -> Result<(), AppError> {
    let session = ensure_sftp_session(handle, sftp).await?;
    session
        .symlink_metadata(path.clone())
        .await
        .map_err(map_sftp_error)?;
    let parent =
        parent_remote_path(&path).ok_or_else(|| AppError::validation("不能重命名远端根目录"))?;
    let target = join_remote_path(&parent, &new_name);
    if session
        .try_exists(target.clone())
        .await
        .map_err(map_sftp_error)?
    {
        return Err(AppError::sftp(
            "SFTP-TARGET-EXISTS",
            "同名文件或目录已存在",
            target,
        ));
    }
    session.rename(path, target).await.map_err(map_sftp_error)
}

async fn delete_remote_entries(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &mut Option<SftpSession>,
    paths: Vec<String>,
    recursive: bool,
) -> Result<(), AppError> {
    let session = ensure_sftp_session(handle, sftp).await?;
    let mut plan = Vec::new();
    for path in paths {
        let metadata = session
            .symlink_metadata(path.clone())
            .await
            .map_err(map_sftp_error)?;
        if metadata.file_type() == FileType::Dir && recursive {
            plan.extend(scan_remote_tree(session, path, true).await?);
        } else {
            plan.push((path, metadata.file_type(), 0));
        }
    }
    plan.sort_by(|left, right| right.2.cmp(&left.2));
    for (path, kind, _) in plan {
        match kind {
            FileType::Dir => session.remove_dir(path).await.map_err(map_sftp_error)?,
            FileType::File | FileType::Symlink => {
                session.remove_file(path).await.map_err(map_sftp_error)?
            }
            FileType::Other => {
                return Err(AppError::sftp(
                    "SFTP-UNSUPPORTED-ENTRY",
                    "不支持删除此类型的远端对象",
                    path,
                ));
            }
        }
    }
    Ok(())
}

async fn change_remote_permissions(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &mut Option<SftpSession>,
    paths: Vec<String>,
    mode: u32,
    recursive: bool,
) -> Result<(), AppError> {
    let session = ensure_sftp_session(handle, sftp).await?;
    let mut targets = Vec::new();
    for path in paths {
        let metadata = session
            .symlink_metadata(path.clone())
            .await
            .map_err(map_sftp_error)?;
        if recursive && metadata.file_type() == FileType::Dir {
            targets.extend(scan_remote_tree(session, path, false).await?);
        } else {
            targets.push((path, metadata.file_type(), 0));
        }
    }
    for (path, kind, _) in targets {
        if kind == FileType::Symlink {
            continue;
        }
        let attributes = russh_sftp::protocol::FileAttributes {
            permissions: Some(mode),
            ..Default::default()
        };
        session
            .set_metadata(path.clone(), attributes)
            .await
            .map_err(|error| {
                AppError::sftp(
                    "SFTP-PERMISSION-CHANGE-FAILED",
                    "无法修改远端权限",
                    format!("path={path}: {error}"),
                )
            })?;
    }
    Ok(())
}

async fn scan_remote_tree(
    session: &SftpSession,
    root: String,
    include_symlinks: bool,
) -> Result<Vec<(String, FileType, usize)>, AppError> {
    const MAX_DEPTH: usize = 64;
    const MAX_ENTRIES: usize = 100_000;
    const MAX_PENDING: usize = 10_000;
    let root_prefix = format!("{}/", root.trim_end_matches('/'));
    let mut pending = vec![(root.clone(), 0_usize)];
    let mut result = Vec::new();
    while let Some((path, depth)) = pending.pop() {
        if depth > MAX_DEPTH || result.len() >= MAX_ENTRIES || pending.len() > MAX_PENDING {
            return Err(AppError::sftp(
                "SFTP-RECURSIVE-LIMIT",
                "递归操作超过安全上限",
                format!("root={root} depth={depth} entries={}", result.len()),
            ));
        }
        let metadata = session
            .symlink_metadata(path.clone())
            .await
            .map_err(map_sftp_error)?;
        let kind = metadata.file_type();
        if path != root && !path.starts_with(&root_prefix) {
            return Err(AppError::sftp(
                "SFTP-PATH-ESCAPE",
                "远端路径越过所选根目录",
                format!("root={root} path={path}"),
            ));
        }
        result.push((path.clone(), kind, depth));
        if kind == FileType::Dir {
            let entries = session.read_dir(path).await.map_err(map_sftp_error)?;
            for entry in entries {
                let entry_kind = entry.file_type();
                if entry_kind == FileType::Symlink && !include_symlinks {
                    continue;
                }
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(result)
}

fn join_remote_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

fn new_transfer_task(
    session_id: &str,
    direction: TransferDirection,
    sources: Vec<String>,
    target_directory: String,
    conflict_policy: TransferConflictPolicy,
) -> TransferTask {
    let file_name = if sources.len() == 1 {
        transfer_source_name(&sources[0], direction).unwrap_or_else(|| "未命名对象".to_owned())
    } else {
        format!("{} 个对象", sources.len())
    };
    TransferTask {
        id: uuid::Uuid::new_v4().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_owned(),
        file_name,
        direction,
        source: sources.first().cloned().unwrap_or_default(),
        target: target_directory.clone(),
        sources,
        target_directory,
        conflict_policy,
        transferred_bytes: 0,
        total_bytes: None,
        total_files: 0,
        total_directories: 0,
        completed_files: 0,
        completed_directories: 0,
        skipped_files: 0,
        bytes_per_second: 0,
        current_path: None,
        elapsed_seconds: 0,
        status: TransferStatus::Queued,
        error: None,
        errors: Vec::new(),
    }
}

fn emit_transfer(app: &AppHandle, task: TransferTask) {
    let persist = matches!(
        task.status,
        TransferStatus::Queued
            | TransferStatus::Completed
            | TransferStatus::Failed
            | TransferStatus::Cancelled
    );
    if let Err(error) = app
        .state::<crate::transfer_registry::TransferRegistry>()
        .record(task.clone(), persist)
    {
        log::error!("{}: {}", error.code, error.message);
    }
    let _ = app.emit(TRANSFER_PROGRESS_EVENT, TransferProgressPayload { task });
}

async fn run_transfer(
    app: AppHandle,
    handle: Arc<client::Handle<VerifiedHandler>>,
    slots: Arc<Semaphore>,
    mut task: TransferTask,
    mut cancellation: oneshot::Receiver<()>,
) {
    let permit = tokio::select! {
        permit = slots.acquire_owned() => match permit { Ok(value) => value, Err(_) => return },
        _ = &mut cancellation => {
            task.status = TransferStatus::Cancelled;
            emit_transfer(&app, task);
            return;
        }
    };
    task.status = TransferStatus::Scanning;
    emit_transfer(&app, task.clone());
    let started = Instant::now();
    let result = execute_transfer_job(&app, &handle, &mut task, &mut cancellation, started).await;
    drop(permit);
    match result {
        Ok(()) if task.errors.is_empty() => task.status = TransferStatus::Completed,
        Ok(()) => {
            task.status = TransferStatus::Failed;
            task.error = Some(format!("{} 个项目失败", task.errors.len()));
        }
        Err(error) if error.code == "TRANSFER-CANCELLED" => task.status = TransferStatus::Cancelled,
        Err(error) => {
            task.status = TransferStatus::Failed;
            task.error = Some(error.message);
        }
    }
    task.current_path = None;
    task.elapsed_seconds = started.elapsed().as_secs();
    app.state::<crate::diagnostics::DiagnosticLog>().record(
        "sftp-transfer",
        task.error.as_deref(),
        &format!(
            "session={} direction={:?} status={:?} bytes={}",
            task.session_id, task.direction, task.status, task.transferred_bytes
        ),
    );
    emit_transfer(&app, task);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransferItemKind {
    Directory,
    File,
}

struct TransferItem {
    source: String,
    target: String,
    kind: TransferItemKind,
    modified_at: Option<u32>,
}

struct TransferPlan {
    items: Vec<TransferItem>,
    files: u64,
    directories: u64,
    bytes: u64,
    skipped: u64,
}

async fn execute_transfer_job(
    app: &AppHandle,
    handle: &client::Handle<VerifiedHandler>,
    task: &mut TransferTask,
    cancellation: &mut oneshot::Receiver<()>,
    started: Instant,
) -> Result<(), AppError> {
    let plan = match task.direction {
        TransferDirection::Upload => scan_local_sources(task, cancellation).await?,
        TransferDirection::Download => scan_remote_sources(handle, task, cancellation).await?,
    };
    task.total_files = plan.files;
    task.total_directories = plan.directories;
    task.total_bytes = Some(plan.bytes);
    task.skipped_files = plan.skipped;
    task.status = TransferStatus::Running;
    emit_transfer(app, task.clone());

    for item in plan.items {
        if cancellation.try_recv().is_ok() {
            return Err(cancelled_error());
        }
        task.current_path = Some(item.source.clone());
        task.source = item.source.clone();
        task.target = item.target.clone();
        let result = match (task.direction, item.kind) {
            (TransferDirection::Upload, TransferItemKind::Directory) => {
                ensure_remote_directory(handle, &item.target).await
            }
            (TransferDirection::Download, TransferItemKind::Directory) => {
                tokio::fs::create_dir_all(&item.target)
                    .await
                    .map_err(|error| {
                        AppError::sftp("LOCAL-WRITE-FAILED", "无法创建本地目录", error.to_string())
                    })
            }
            (TransferDirection::Upload, TransferItemKind::File) => {
                let target =
                    resolve_remote_conflict(handle, &item.target, task.conflict_policy).await?;
                if let Some(target) = target {
                    task.target = target;
                    let result = upload_file(app, handle, task, true, cancellation, started).await;
                    if result.is_ok() {
                        set_remote_modified_time(handle, &task.target, item.modified_at).await
                    } else {
                        result
                    }
                } else {
                    task.skipped_files += 1;
                    continue;
                }
            }
            (TransferDirection::Download, TransferItemKind::File) => {
                let target = resolve_local_conflict(&item.target, task.conflict_policy).await?;
                if let Some(target) = target {
                    task.target = target;
                    let result =
                        download_file(app, handle, task, true, cancellation, started).await;
                    if result.is_ok() {
                        set_local_modified_time(task.target.clone(), item.modified_at).await
                    } else {
                        result
                    }
                } else {
                    task.skipped_files += 1;
                    continue;
                }
            }
        };
        match result {
            Ok(()) if item.kind == TransferItemKind::Directory => task.completed_directories += 1,
            Ok(()) => task.completed_files += 1,
            Err(error) if error.code == "TRANSFER-CANCELLED" => return Err(error),
            Err(error) => {
                if task.errors.len() < 20 {
                    task.errors.push(format!(
                        "{} [{}]: {}",
                        item.source, error.code, error.message
                    ));
                }
            }
        }
        task.elapsed_seconds = started.elapsed().as_secs();
        update_transfer_progress(app, task, started);
    }
    Ok(())
}

fn transfer_source_name(source: &str, direction: TransferDirection) -> Option<String> {
    match direction {
        TransferDirection::Upload => std::path::Path::new(source)
            .file_name()
            .map(|value| value.to_string_lossy().into_owned()),
        TransferDirection::Download => source
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    }
}

async fn scan_local_sources(
    task: &TransferTask,
    cancellation: &mut oneshot::Receiver<()>,
) -> Result<TransferPlan, AppError> {
    const MAX_DEPTH: usize = 64;
    const MAX_ENTRIES: usize = 100_000;
    let mut pending = Vec::new();
    for source in &task.sources {
        let name = transfer_source_name(source, TransferDirection::Upload).ok_or_else(|| {
            AppError::sftp("TRANSFER-SCAN-FAILED", "无法确定本地对象名称", source)
        })?;
        pending.push((
            std::path::PathBuf::from(source),
            join_remote_path(&task.target_directory, &name),
            0_usize,
        ));
    }
    let mut plan = TransferPlan {
        items: Vec::new(),
        files: 0,
        directories: 0,
        bytes: 0,
        skipped: 0,
    };
    while let Some((source, target, depth)) = pending.pop() {
        if cancellation.try_recv().is_ok() {
            return Err(cancelled_error());
        }
        if depth > MAX_DEPTH || plan.items.len() >= MAX_ENTRIES || pending.len() > 10_000 {
            return Err(recursive_limit_error(depth, plan.items.len()));
        }
        if target.len() > 4096 {
            return Err(AppError::sftp(
                "TRANSFER-SCAN-FAILED",
                "远端目标路径超过长度限制",
                target,
            ));
        }
        let metadata = tokio::fs::symlink_metadata(&source)
            .await
            .map_err(|error| {
                AppError::sftp(
                    "TRANSFER-SCAN-FAILED",
                    "无法扫描本地对象",
                    format!("{}: {error}", source.display()),
                )
            })?;
        if metadata.file_type().is_symlink() {
            plan.skipped += 1;
            continue;
        }
        if metadata.is_dir() {
            plan.directories += 1;
            plan.items.push(TransferItem {
                source: source.display().to_string(),
                target: target.clone(),
                kind: TransferItemKind::Directory,
                modified_at: modified_timestamp(&metadata),
            });
            let mut entries = tokio::fs::read_dir(&source).await.map_err(|error| {
                AppError::sftp(
                    "TRANSFER-SCAN-FAILED",
                    "无法读取本地目录",
                    format!("{}: {error}", source.display()),
                )
            })?;
            while let Some(entry) = entries.next_entry().await.map_err(|error| {
                AppError::sftp(
                    "TRANSFER-SCAN-FAILED",
                    "无法扫描本地目录",
                    error.to_string(),
                )
            })? {
                let name = entry.file_name().to_string_lossy().into_owned();
                pending.push((entry.path(), join_remote_path(&target, &name), depth + 1));
            }
        } else if metadata.is_file() {
            plan.files += 1;
            plan.bytes = plan.bytes.saturating_add(metadata.len());
            plan.items.push(TransferItem {
                source: source.display().to_string(),
                target,
                kind: TransferItemKind::File,
                modified_at: modified_timestamp(&metadata),
            });
        } else {
            plan.skipped += 1;
        }
    }
    plan.items
        .sort_by_key(|item| item.kind != TransferItemKind::Directory);
    Ok(plan)
}

async fn scan_remote_sources(
    handle: &client::Handle<VerifiedHandler>,
    task: &TransferTask,
    cancellation: &mut oneshot::Receiver<()>,
) -> Result<TransferPlan, AppError> {
    const MAX_DEPTH: usize = 64;
    const MAX_ENTRIES: usize = 100_000;
    let sftp = open_transfer_sftp(handle).await?;
    let mut pending = Vec::new();
    for source in &task.sources {
        let name = transfer_source_name(source, TransferDirection::Download).ok_or_else(|| {
            AppError::sftp("TRANSFER-SCAN-FAILED", "无法确定远端对象名称", source)
        })?;
        pending.push((
            source.clone(),
            std::path::PathBuf::from(&task.target_directory).join(name),
            0_usize,
        ));
    }
    let mut plan = TransferPlan {
        items: Vec::new(),
        files: 0,
        directories: 0,
        bytes: 0,
        skipped: 0,
    };
    while let Some((source, target, depth)) = pending.pop() {
        if cancellation.try_recv().is_ok() {
            let _ = sftp.close().await;
            return Err(cancelled_error());
        }
        if depth > MAX_DEPTH || plan.items.len() >= MAX_ENTRIES || pending.len() > 10_000 {
            let _ = sftp.close().await;
            return Err(recursive_limit_error(depth, plan.items.len()));
        }
        if source.len() > 4096 || target.as_os_str().len() > 4096 {
            let _ = sftp.close().await;
            return Err(AppError::sftp(
                "TRANSFER-SCAN-FAILED",
                "传输路径超过长度限制",
                source,
            ));
        }
        let metadata = sftp
            .symlink_metadata(source.clone())
            .await
            .map_err(map_sftp_error)?;
        match metadata.file_type() {
            FileType::Symlink => plan.skipped += 1,
            FileType::Dir => {
                plan.directories += 1;
                plan.items.push(TransferItem {
                    source: source.clone(),
                    target: target.display().to_string(),
                    kind: TransferItemKind::Directory,
                    modified_at: metadata.mtime,
                });
                let child_prefix = format!("{}/", source.trim_end_matches('/'));
                let entries = sftp
                    .read_dir(source.clone())
                    .await
                    .map_err(map_sftp_error)?;
                for entry in entries {
                    let entry_path = entry.path();
                    if !entry_path.starts_with(&child_prefix) {
                        let _ = sftp.close().await;
                        return Err(AppError::sftp(
                            "SFTP-PATH-ESCAPE",
                            "远端目录返回了根路径以外的对象",
                            entry_path,
                        ));
                    }
                    pending.push((entry_path, target.join(entry.file_name()), depth + 1));
                }
            }
            FileType::File => {
                let size = metadata.size.unwrap_or(0);
                plan.files += 1;
                plan.bytes = plan.bytes.saturating_add(size);
                plan.items.push(TransferItem {
                    source,
                    target: target.display().to_string(),
                    kind: TransferItemKind::File,
                    modified_at: metadata.mtime,
                });
            }
            FileType::Other => plan.skipped += 1,
        }
    }
    let _ = sftp.close().await;
    plan.items
        .sort_by_key(|item| item.kind != TransferItemKind::Directory);
    Ok(plan)
}

fn recursive_limit_error(depth: usize, entries: usize) -> AppError {
    AppError::sftp(
        "SFTP-RECURSIVE-LIMIT",
        "递归传输超过安全上限",
        format!("depth={depth} entries={entries}"),
    )
}

fn modified_timestamp(metadata: &std::fs::Metadata) -> Option<u32> {
    metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        .try_into()
        .ok()
}

async fn set_remote_modified_time(
    handle: &client::Handle<VerifiedHandler>,
    path: &str,
    modified_at: Option<u32>,
) -> Result<(), AppError> {
    let Some(modified_at) = modified_at else {
        return Ok(());
    };
    let sftp = open_transfer_sftp(handle).await?;
    let attributes = russh_sftp::protocol::FileAttributes {
        mtime: Some(modified_at),
        ..Default::default()
    };
    let result = sftp
        .set_metadata(path.to_owned(), attributes)
        .await
        .map_err(map_sftp_error);
    let _ = sftp.close().await;
    result
}

async fn set_local_modified_time(path: String, modified_at: Option<u32>) -> Result<(), AppError> {
    let Some(modified_at) = modified_at else {
        return Ok(());
    };
    tauri::async_runtime::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|error| {
                AppError::sftp(
                    "LOCAL-WRITE-FAILED",
                    "无法恢复本地文件修改时间",
                    error.to_string(),
                )
            })?;
        let times = std::fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(u64::from(modified_at)));
        file.set_times(times).map_err(|error| {
            AppError::sftp(
                "LOCAL-WRITE-FAILED",
                "无法恢复本地文件修改时间",
                error.to_string(),
            )
        })
    })
    .await
    .map_err(|error| {
        AppError::sftp(
            "LOCAL-WRITE-FAILED",
            "本地文件时间恢复任务失败",
            error.to_string(),
        )
    })?
}

async fn ensure_remote_directory(
    handle: &client::Handle<VerifiedHandler>,
    path: &str,
) -> Result<(), AppError> {
    let sftp = open_transfer_sftp(handle).await?;
    let result = if sftp
        .try_exists(path.to_owned())
        .await
        .map_err(map_sftp_error)?
    {
        let metadata = sftp
            .symlink_metadata(path.to_owned())
            .await
            .map_err(map_sftp_error)?;
        if metadata.file_type() == FileType::Dir {
            Ok(())
        } else {
            Err(AppError::sftp(
                "TRANSFER-CONFLICT",
                "远端目录路径已被文件占用",
                path,
            ))
        }
    } else {
        sftp.create_dir(path.to_owned())
            .await
            .map_err(map_sftp_error)
    };
    let _ = sftp.close().await;
    result
}

async fn resolve_remote_conflict(
    handle: &client::Handle<VerifiedHandler>,
    target: &str,
    policy: TransferConflictPolicy,
) -> Result<Option<String>, AppError> {
    let sftp = open_transfer_sftp(handle).await?;
    let exists = sftp
        .try_exists(target.to_owned())
        .await
        .map_err(map_sftp_error)?;
    let result = if !exists || matches!(policy, TransferConflictPolicy::Overwrite) {
        Some(target.to_owned())
    } else if matches!(policy, TransferConflictPolicy::Skip) {
        None
    } else if matches!(policy, TransferConflictPolicy::Rename) {
        let mut selected = None;
        for index in 1..=999 {
            let candidate = conflict_name(target, index);
            if !sftp
                .try_exists(candidate.clone())
                .await
                .map_err(map_sftp_error)?
            {
                selected = Some(candidate);
                break;
            }
        }
        Some(
            selected
                .ok_or_else(|| AppError::sftp("TRANSFER-CONFLICT", "无法生成无冲突名称", target))?,
        )
    } else {
        let _ = sftp.close().await;
        return Err(AppError::sftp(
            "TRANSFER-CONFLICT",
            "目标已存在，请选择覆盖、跳过或自动重命名",
            target,
        ));
    };
    let _ = sftp.close().await;
    Ok(result)
}

async fn resolve_local_conflict(
    target: &str,
    policy: TransferConflictPolicy,
) -> Result<Option<String>, AppError> {
    if !tokio::fs::try_exists(target).await.map_err(|error| {
        AppError::sftp("LOCAL-WRITE-FAILED", "无法检查本地目标", error.to_string())
    })? || matches!(policy, TransferConflictPolicy::Overwrite)
    {
        return Ok(Some(target.to_owned()));
    }
    if matches!(policy, TransferConflictPolicy::Skip) {
        return Ok(None);
    }
    if matches!(policy, TransferConflictPolicy::Rename) {
        for index in 1..=999 {
            let candidate = conflict_name(target, index);
            if !tokio::fs::try_exists(&candidate).await.map_err(|error| {
                AppError::sftp("LOCAL-WRITE-FAILED", "无法检查本地目标", error.to_string())
            })? {
                return Ok(Some(candidate));
            }
        }
    }
    Err(AppError::sftp(
        "TRANSFER-CONFLICT",
        "目标已存在，请选择覆盖、跳过或自动重命名",
        target,
    ))
}

fn conflict_name(path: &str, index: usize) -> String {
    let path = std::path::Path::new(path);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = path.extension().and_then(|value| value.to_str());
    let name = match extension {
        Some(extension) => format!("{stem} ({index}).{extension}"),
        None => format!("{stem} ({index})"),
    };
    path.with_file_name(name)
        .display()
        .to_string()
        .replace('\\', "/")
}

async fn open_transfer_sftp(
    handle: &client::Handle<VerifiedHandler>,
) -> Result<SftpSession, AppError> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(map_sftp_ssh_error)?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(map_sftp_ssh_error)?;
    let session = SftpSession::new(channel.into_stream())
        .await
        .map_err(map_sftp_error)?;
    session.set_timeout(1);
    Ok(session)
}

fn cancelled_error() -> AppError {
    AppError::sftp("TRANSFER-CANCELLED", "传输已取消", "cancelled by user")
}

fn temporary_remote_path(target: &str, task_id: &str) -> String {
    format!("{target}.terminalt-{task_id}.part")
}

fn backup_remote_path(target: &str, task_id: &str) -> String {
    format!("{target}.terminalt-{task_id}.backup")
}

fn temporary_local_path(target: &std::path::Path, task_id: &str) -> std::path::PathBuf {
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("download");
    target.with_file_name(format!(".{name}.terminalt-{task_id}.part"))
}

fn backup_local_path(target: &std::path::Path, task_id: &str) -> std::path::PathBuf {
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("download");
    target.with_file_name(format!(".{name}.terminalt-{task_id}.backup"))
}

fn update_transfer_progress(app: &AppHandle, task: &mut TransferTask, started: Instant) {
    let elapsed = started.elapsed().as_secs_f64();
    task.bytes_per_second = if elapsed > 0.0 {
        (task.transferred_bytes as f64 / elapsed) as u64
    } else {
        0
    };
    emit_transfer(app, task.clone());
}

async fn upload_file(
    app: &AppHandle,
    handle: &client::Handle<VerifiedHandler>,
    task: &mut TransferTask,
    overwrite: bool,
    cancellation: &mut oneshot::Receiver<()>,
    started: Instant,
) -> Result<(), AppError> {
    let mut local = tokio::fs::File::open(&task.source).await.map_err(|error| {
        AppError::sftp("LOCAL-READ-FAILED", "无法读取本地文件", error.to_string())
    })?;
    let _ = local.metadata().await.map_err(|error| {
        AppError::sftp(
            "LOCAL-READ-FAILED",
            "无法读取本地文件信息",
            error.to_string(),
        )
    })?;
    let sftp = open_transfer_sftp(handle).await?;
    if !overwrite
        && sftp
            .try_exists(task.target.clone())
            .await
            .map_err(map_sftp_error)?
    {
        return Err(AppError::sftp(
            "TRANSFER-TARGET-EXISTS",
            "远端已存在同名文件，请确认覆盖",
            task.target.clone(),
        ));
    }
    let temporary = temporary_remote_path(&task.target, &task.id);
    let mut remote = sftp
        .create(temporary.clone())
        .await
        .map_err(map_sftp_error)?;
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut last_progress = Instant::now();
    let result: Result<(), AppError> = async {
        loop {
            let read = tokio::select! {
                value = local.read(&mut buffer) => value.map_err(|error| AppError::sftp("LOCAL-READ-FAILED", "读取本地文件失败", error.to_string()))?,
                _ = &mut *cancellation => return Err(cancelled_error()),
            };
            if read == 0 { return Ok(()); }
            tokio::select! {
                value = remote.write_all(&buffer[..read]) => value.map_err(|error| AppError::sftp("SFTP-WRITE-FAILED", "写入远端文件失败", error.to_string()))?,
                _ = &mut *cancellation => return Err(cancelled_error()),
            }
            task.transferred_bytes += read as u64;
            if last_progress.elapsed() >= Duration::from_millis(100) {
                update_transfer_progress(app, task, started);
                last_progress = Instant::now();
            }
        }
    }.await;
    let _ = remote.shutdown().await;
    if result.is_ok() {
        if let Err(error) =
            replace_remote_file(&sftp, &temporary, &task.target, &task.id, overwrite).await
        {
            if let Err(cleanup) = sftp.remove_file(temporary).await {
                log::warn!("remote transfer cleanup failed: {cleanup}");
            }
            let _ = sftp.close().await;
            return Err(error);
        }
    } else if let Err(error) = sftp.remove_file(temporary).await {
        let _ = sftp.close().await;
        return Err(AppError::sftp(
            "TRANSFER-TEMP-CLEANUP-FAILED",
            "传输失败且无法清理远端临时文件",
            error.to_string(),
        ));
    }
    let _ = sftp.close().await;
    result
}

async fn download_file(
    app: &AppHandle,
    handle: &client::Handle<VerifiedHandler>,
    task: &mut TransferTask,
    overwrite: bool,
    cancellation: &mut oneshot::Receiver<()>,
    started: Instant,
) -> Result<(), AppError> {
    let target = std::path::PathBuf::from(&task.target);
    if !overwrite
        && tokio::fs::try_exists(&target).await.map_err(|error| {
            AppError::sftp("LOCAL-WRITE-FAILED", "无法检查本地目标", error.to_string())
        })?
    {
        return Err(AppError::sftp(
            "TRANSFER-TARGET-EXISTS",
            "本地已存在同名文件，请确认覆盖",
            task.target.clone(),
        ));
    }
    let temporary = temporary_local_path(&target, &task.id);
    let sftp = open_transfer_sftp(handle).await?;
    sftp.metadata(task.source.clone())
        .await
        .map_err(map_sftp_error)?;
    let mut remote = sftp
        .open(task.source.clone())
        .await
        .map_err(map_sftp_error)?;
    let mut local = tokio::fs::File::create(&temporary).await.map_err(|error| {
        AppError::sftp(
            "LOCAL-WRITE-FAILED",
            "无法创建本地临时文件",
            error.to_string(),
        )
    })?;
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut last_progress = Instant::now();
    let result: Result<(), AppError> = async {
        loop {
            let read = tokio::select! {
                value = remote.read(&mut buffer) => value.map_err(|error| AppError::sftp("SFTP-READ-FAILED", "读取远端文件失败", error.to_string()))?,
                _ = &mut *cancellation => return Err(cancelled_error()),
            };
            if read == 0 { return Ok(()); }
            tokio::select! {
                value = local.write_all(&buffer[..read]) => value.map_err(|error| AppError::sftp("LOCAL-WRITE-FAILED", "写入本地文件失败", error.to_string()))?,
                _ = &mut *cancellation => return Err(cancelled_error()),
            }
            task.transferred_bytes += read as u64;
            if last_progress.elapsed() >= Duration::from_millis(100) {
                update_transfer_progress(app, task, started);
                last_progress = Instant::now();
            }
        }
    }.await;
    let _ = local.shutdown().await;
    if result.is_ok() {
        if let Err(error) = replace_local_file(&temporary, &target, &task.id, overwrite).await {
            if let Err(cleanup) = tokio::fs::remove_file(&temporary).await {
                log::warn!("local transfer cleanup failed: {cleanup}");
            }
            let _ = sftp.close().await;
            return Err(error);
        }
    } else if let Err(error) = tokio::fs::remove_file(&temporary).await {
        let _ = sftp.close().await;
        return Err(AppError::sftp(
            "TRANSFER-TEMP-CLEANUP-FAILED",
            "传输失败且无法清理本地临时文件",
            error.to_string(),
        ));
    }
    let _ = sftp.close().await;
    result
}

async fn replace_remote_file(
    sftp: &SftpSession,
    temporary: &str,
    target: &str,
    task_id: &str,
    overwrite: bool,
) -> Result<(), AppError> {
    let exists = sftp
        .try_exists(target.to_owned())
        .await
        .map_err(map_sftp_error)?;
    if exists && !overwrite {
        return Err(AppError::sftp(
            "TRANSFER-TARGET-EXISTS",
            "远端已存在同名文件，请确认覆盖",
            target,
        ));
    }
    let backup = backup_remote_path(target, task_id);
    if exists {
        sftp.rename(target.to_owned(), backup.clone())
            .await
            .map_err(map_sftp_error)?;
    }
    if let Err(error) = sftp.rename(temporary.to_owned(), target.to_owned()).await {
        if exists {
            let _ = sftp.rename(backup, target.to_owned()).await;
        }
        return Err(AppError::sftp(
            "TRANSFER-ATOMIC-REPLACE-FAILED",
            "无法原子替换远端目标文件",
            error.to_string(),
        ));
    }
    if exists {
        sftp.remove_file(backup).await.map_err(|error| {
            AppError::sftp(
                "TRANSFER-TEMP-CLEANUP-FAILED",
                "无法清理远端备份文件",
                error.to_string(),
            )
        })?;
    }
    Ok(())
}

async fn replace_local_file(
    temporary: &std::path::Path,
    target: &std::path::Path,
    task_id: &str,
    overwrite: bool,
) -> Result<(), AppError> {
    let exists = tokio::fs::try_exists(target).await.map_err(|error| {
        AppError::sftp("LOCAL-WRITE-FAILED", "无法检查本地目标", error.to_string())
    })?;
    if exists && !overwrite {
        return Err(AppError::sftp(
            "TRANSFER-TARGET-EXISTS",
            "本地已存在同名文件，请确认覆盖",
            target.display().to_string(),
        ));
    }
    let backup = backup_local_path(target, task_id);
    if exists {
        tokio::fs::rename(target, &backup).await.map_err(|error| {
            AppError::sftp(
                "LOCAL-WRITE-FAILED",
                "无法备份本地目标文件",
                error.to_string(),
            )
        })?;
    }
    if let Err(error) = tokio::fs::rename(temporary, target).await {
        if exists {
            let _ = tokio::fs::rename(&backup, target).await;
        }
        return Err(AppError::sftp(
            "TRANSFER-ATOMIC-REPLACE-FAILED",
            "无法原子替换本地目标文件",
            error.to_string(),
        ));
    }
    if exists {
        tokio::fs::remove_file(backup).await.map_err(|error| {
            AppError::sftp(
                "TRANSFER-TEMP-CLEANUP-FAILED",
                "无法清理本地备份文件",
                error.to_string(),
            )
        })?;
    }
    Ok(())
}

fn parent_remote_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let index = trimmed.rfind('/')?;
    Some(if index == 0 { "/" } else { &trimmed[..index] }.to_owned())
}

fn map_sftp_ssh_error(error: russh::Error) -> AppError {
    AppError::sftp(
        "SFTP-CHANNEL-FAILED",
        "无法打开 SFTP 文件通道",
        error.to_string(),
    )
}

fn map_sftp_error(error: russh_sftp::client::error::Error) -> AppError {
    AppError::sftp("SFTP-BROWSE-FAILED", "无法读取远端目录", error.to_string())
}

#[cfg(test)]
mod sftp_tests {
    use super::{
        backup_local_path, conflict_name, join_remote_path, new_transfer_task, parent_remote_path,
        replace_local_file, resolve_local_conflict, scan_local_sources, set_local_modified_time,
        temporary_local_path,
    };
    use crate::models::{TransferConflictPolicy, TransferDirection};

    #[test]
    fn derives_remote_parent_paths_without_escaping_root() {
        assert_eq!(parent_remote_path("/"), None);
        assert_eq!(parent_remote_path("/home"), Some("/".to_owned()));
        assert_eq!(parent_remote_path("/home/user/"), Some("/home".to_owned()));
        assert_eq!(parent_remote_path("relative"), None);
    }

    #[test]
    fn joins_remote_paths_with_one_separator() {
        assert_eq!(join_remote_path("/", "日志"), "/日志");
        assert_eq!(join_remote_path("/home/user/", "a b"), "/home/user/a b");
    }

    #[test]
    fn local_transfer_artifacts_stay_next_to_target() {
        let target = std::path::Path::new("C:\\downloads\\report.txt");
        assert_eq!(
            temporary_local_path(target, "task").file_name().unwrap(),
            ".report.txt.terminalt-task.part"
        );
        assert_eq!(
            backup_local_path(target, "task").file_name().unwrap(),
            ".report.txt.terminalt-task.backup"
        );
    }

    #[test]
    fn conflict_names_preserve_extensions_and_remote_separators() {
        assert_eq!(conflict_name("/tmp/report.txt", 2), "/tmp/report (2).txt");
        assert_eq!(conflict_name("/tmp/archive", 1), "/tmp/archive (1)");
    }

    #[tokio::test]
    async fn local_recursive_scan_handles_large_unicode_tree() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("部署 目录");
        std::fs::create_dir_all(&root).unwrap();
        for directory_index in 0..100 {
            let child = root.join(format!("目录-{directory_index:03}"));
            std::fs::create_dir_all(&child).unwrap();
            for file_index in 0..10 {
                let name = if directory_index == 0 && file_index == 0 {
                    ".隐藏文件".to_owned()
                } else {
                    format!("文件-{file_index:02}.txt")
                };
                std::fs::write(child.join(name), [file_index as u8]).unwrap();
            }
        }
        let mut nested = root.join("十层");
        for depth in 0..10 {
            nested = nested.join(format!("d{depth}"));
            std::fs::create_dir_all(&nested).unwrap();
        }
        std::fs::write(nested.join("zero"), []).unwrap();
        let task = new_transfer_task(
            "session",
            TransferDirection::Upload,
            vec![root.display().to_string()],
            "/deploy".to_owned(),
            TransferConflictPolicy::Rename,
        );
        let (_cancel, mut cancellation) = tokio::sync::oneshot::channel();
        let plan = scan_local_sources(&task, &mut cancellation).await.unwrap();
        assert_eq!(plan.files, 1001);
        assert_eq!(plan.directories, 112);
        assert!(plan
            .items
            .iter()
            .any(|item| item.target.contains("隐藏文件")));
        assert!(plan.items.iter().any(|item| item.target.ends_with("/zero")));
    }

    #[tokio::test]
    async fn failed_local_atomic_replace_restores_existing_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("report.txt");
        std::fs::write(&target, b"original").unwrap();
        let missing = directory.path().join("missing.part");
        assert!(replace_local_file(&missing, &target, "task", true)
            .await
            .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"original");
    }

    #[tokio::test]
    async fn local_conflict_policies_are_deterministic() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("report.txt");
        std::fs::write(&target, b"existing").unwrap();
        let target = target.display().to_string();
        assert!(resolve_local_conflict(&target, TransferConflictPolicy::Ask)
            .await
            .is_err());
        assert_eq!(
            resolve_local_conflict(&target, TransferConflictPolicy::Skip)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            resolve_local_conflict(&target, TransferConflictPolicy::Overwrite)
                .await
                .unwrap(),
            Some(target.clone())
        );
        assert!(
            resolve_local_conflict(&target, TransferConflictPolicy::Rename)
                .await
                .unwrap()
                .unwrap()
                .ends_with("report (1).txt")
        );
    }

    #[tokio::test]
    async fn downloaded_file_modified_time_is_restored() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("time.txt");
        std::fs::write(&target, b"content").unwrap();
        let timestamp = 1_700_000_000_u32;
        set_local_modified_time(target.display().to_string(), Some(timestamp))
            .await
            .unwrap();
        let actual = std::fs::metadata(target)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(actual, u64::from(timestamp));
    }

    #[tokio::test]
    async fn local_scan_rejects_excessive_depth() {
        let directory = tempfile::tempdir().unwrap();
        let mut root = directory.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.display().to_string();
        for _ in 0..65 {
            root = root.join("d");
            std::fs::create_dir_all(&root).unwrap();
        }
        let task = new_transfer_task(
            "session",
            TransferDirection::Upload,
            vec![source],
            "/deploy".to_owned(),
            TransferConflictPolicy::Ask,
        );
        let (_cancel, mut cancellation) = tokio::sync::oneshot::channel();
        let error = match scan_local_sources(&task, &mut cancellation).await {
            Ok(_) => panic!("deep tree should be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, "SFTP-RECURSIVE-LIMIT");
    }

    #[tokio::test]
    async fn transfer_scheduler_limits_concurrency_and_preserves_wait_order() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(3));
        let mut active = Vec::new();
        for _ in 0..3 {
            active.push(slots.clone().acquire_owned().await.unwrap());
        }
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        for index in 0..2 {
            let slots = slots.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                let _permit = slots.acquire_owned().await.unwrap();
                sender.send(index).await.unwrap();
            });
        }
        assert!(receiver.try_recv().is_err());
        drop(active.pop());
        assert_eq!(receiver.recv().await, Some(0));
        drop(active.pop());
        assert_eq!(receiver.recv().await, Some(1));
    }
}

fn emit_terminal_output(app: &AppHandle, session_id: &str, data: Vec<u8>) -> Result<(), AppError> {
    app.emit(
        SESSION_OUTPUT_EVENT,
        SessionOutputPayload {
            session_id: session_id.to_owned(),
            data,
        },
    )
    .map_err(|error| AppError::event_delivery_failed(SESSION_OUTPUT_EVENT, error))
}

fn client_config(keepalive_interval: Option<Duration>) -> client::Config {
    client::Config {
        nodelay: true,
        keepalive_interval,
        keepalive_max: 3,
        ..Default::default()
    }
}

fn connection_timeout() -> AppError {
    AppError::ssh(
        "CONNECTION-TIMEOUT",
        "连接超时，请检查主机、端口和防火墙",
        "SSH setup exceeded the configured timeout",
        true,
    )
}

fn map_connect_error(error: russh::Error) -> AppError {
    if let russh::Error::IO(io_error) = &error {
        return match io_error.kind() {
            std::io::ErrorKind::NotFound => AppError::ssh(
                "DNS-RESOLUTION-FAILED",
                "无法解析主机名，请检查地址或网络设置",
                io_error.to_string(),
                true,
            ),
            std::io::ErrorKind::ConnectionRefused => AppError::ssh(
                "CONNECTION-REFUSED",
                "目标主机拒绝连接，请确认 SSH 服务和端口",
                io_error.to_string(),
                true,
            ),
            std::io::ErrorKind::TimedOut => connection_timeout(),
            _ => AppError::ssh(
                "NETWORK-ERROR",
                "无法连接服务器，请检查网络设置",
                io_error.to_string(),
                true,
            ),
        };
    }
    map_russh_error(error)
}

fn map_russh_error(error: russh::Error) -> AppError {
    let details = error.to_string();
    match error {
        russh::Error::NoCommonAlgo { .. } => AppError::ssh(
            "SSH-NO-COMMON-ALGORITHM",
            "无法与服务器协商安全算法",
            details,
            false,
        ),
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => AppError::ssh(
            "HOST-KEY-REJECTED",
            "服务器身份校验失败，连接已阻止",
            details,
            false,
        ),
        russh::Error::ConnectionTimeout | russh::Error::InactivityTimeout => connection_timeout(),
        russh::Error::HUP | russh::Error::Disconnect => {
            AppError::ssh("REMOTE-CLOSED", "服务器已关闭当前连接", details, true)
        }
        _ => AppError::ssh(
            "SSH-PROTOCOL-ERROR",
            "SSH 握手或会话建立失败",
            details,
            true,
        ),
    }
}

fn map_private_key_error(error: russh::keys::Error) -> AppError {
    let details = error.to_string();
    match error {
        russh::keys::Error::IO(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
            AppError::ssh(
                "PRIVATE-KEY-NOT-FOUND",
                "所选私钥文件不存在",
                io_error.to_string(),
                false,
            )
        }
        russh::keys::Error::IO(io_error)
            if io_error.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            AppError::ssh(
                "PRIVATE-KEY-PERMISSION-DENIED",
                "没有权限读取所选私钥",
                io_error.to_string(),
                false,
            )
        }
        russh::keys::Error::KeyIsEncrypted => AppError::ssh(
            "PRIVATE-KEY-PASSPHRASE-REQUIRED",
            "该私钥需要口令",
            details,
            true,
        ),
        _ if details.to_ascii_lowercase().contains("decrypt")
            || details.to_ascii_lowercase().contains("password") =>
        {
            AppError::ssh(
                "PRIVATE-KEY-PASSPHRASE-INVALID",
                "私钥口令不正确",
                details,
                true,
            )
        }
        _ => AppError::ssh(
            "PRIVATE-KEY-INVALID",
            "无法读取或解析所选私钥",
            details,
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, collections::HashMap, sync::Arc, time::Duration};

    use russh::{
        client::{self, KeyboardInteractiveAuthResponse},
        keys::{ssh_key, Algorithm, EcdsaCurve, HashAlg, PrivateKey},
        server::{self, Auth, Msg, Response, Server as _, Session},
        Channel, ChannelId,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{oneshot, Mutex},
        task::JoinSet,
    };

    use super::{
        client_config, connect_authenticated, connect_route_authenticated, inspect_host_key,
        ProbeHandler,
    };
    use crate::{
        connection_pool::{ConnectionPool, PooledConnection},
        known_hosts::KnownHostsStore,
        models::{AuthType, ConnectionRequest, HostKeyStatus, JumpHostRequest},
    };

    type RemoteForwardCancellations = Arc<Mutex<HashMap<(String, u32), oneshot::Sender<()>>>>;

    #[derive(Clone)]
    struct TestServer {
        channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
        startup_output: Arc<Vec<u8>>,
        remote_forwards: RemoteForwardCancellations,
    }

    impl Default for TestServer {
        fn default() -> Self {
            Self {
                channels: Arc::default(),
                startup_output: Arc::new(b"terminal-ready\r\n".to_vec()),
                remote_forwards: Arc::default(),
            }
        }
    }

    impl server::Server for TestServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            self.clone()
        }
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            Ok(if user == "terminalt" && password == "test-secret" {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            _: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(if user == "terminalt" {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }

        async fn auth_keyboard_interactive<'a>(
            &'a mut self,
            user: &str,
            _: &str,
            response: Option<Response<'a>>,
        ) -> Result<Auth, Self::Error> {
            if user != "terminalt" {
                return Ok(Auth::reject());
            }
            match response {
                None => Ok(Auth::Partial {
                    name: Cow::Borrowed("Two-factor authentication"),
                    instructions: Cow::Borrowed("Enter the current one-time code"),
                    prompts: Cow::Owned(vec![(Cow::Borrowed("Verification code:"), false)]),
                }),
                Some(mut responses) => Ok(if responses.next().as_deref() == Some(b"654321") {
                    Auth::Accept
                } else {
                    Auth::reject()
                }),
            }
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            self.channels.lock().await.insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _: &str,
            _: u32,
            reply: server::ChannelOpenHandle,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            let port = match u16::try_from(port_to_connect) {
                Ok(port) => port,
                Err(_) => {
                    reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                    return Ok(());
                }
            };
            match tokio::net::TcpStream::connect((host_to_connect, port)).await {
                Ok(mut target) => {
                    reply.accept().await;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
                    });
                }
                Err(_) => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
            }
            Ok(())
        }

        async fn tcpip_forward(
            &mut self,
            address: &str,
            port: &mut u32,
            session: &mut Session,
        ) -> Result<bool, Self::Error> {
            let requested = u16::try_from(*port).map_err(|_| russh::Error::RequestDenied)?;
            let listener = TcpListener::bind((address, requested))
                .await
                .map_err(russh::Error::IO)?;
            *port = u32::from(listener.local_addr().map_err(russh::Error::IO)?.port());
            let key = (address.to_owned(), *port);
            let (cancel, mut cancellation) = oneshot::channel();
            self.remote_forwards
                .lock()
                .await
                .insert(key.clone(), cancel);
            let handle = session.handle();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut cancellation => break,
                        accepted = listener.accept() => {
                            let Ok((mut stream, origin)) = accepted else { break };
                            let handle = handle.clone();
                            let connected_address = key.0.clone();
                            let connected_port = key.1;
                            tokio::spawn(async move {
                                if let Ok(channel) = handle.channel_open_forwarded_tcpip(
                                    connected_address,
                                    connected_port,
                                    origin.ip().to_string(),
                                    u32::from(origin.port()),
                                ).await {
                                    let mut remote = channel.into_stream();
                                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
                                }
                            });
                        }
                    }
                }
            });
            Ok(true)
        }

        async fn cancel_tcpip_forward(
            &mut self,
            address: &str,
            port: u32,
            _: &mut Session,
        ) -> Result<bool, Self::Error> {
            if let Some(cancel) = self
                .remote_forwards
                .lock()
                .await
                .remove(&(address.to_owned(), port))
            {
                let _ = cancel.send(());
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _: &str,
            _: u32,
            _: u32,
            _: u32,
            _: u32,
            _: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            for chunk in self.startup_output.chunks(64 * 1024) {
                session.data(channel, chunk.to_vec())?;
            }
            Ok(())
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if self.channels.lock().await.contains_key(&channel) {
                session.data(channel, data.to_vec())?;
            }
            Ok(())
        }
    }

    async fn start_server() -> (std::net::SocketAddr, String, tokio::task::JoinHandle<()>) {
        start_server_with_output(b"terminal-ready\r\n".to_vec()).await
    }

    async fn start_server_with_output(
        startup_output: Vec<u8>,
    ) -> (std::net::SocketAddr, String, tokio::task::JoinHandle<()>) {
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let config = Arc::new(server::Config {
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            ..Default::default()
        });
        let socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let task = tokio::spawn(async move {
            let mut server = TestServer {
                startup_output: Arc::new(startup_output),
                ..TestServer::default()
            };
            let _ = server.run_on_address(config, address).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        (address, fingerprint, task)
    }

    async fn start_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        (address, task)
    }

    fn request(address: std::net::SocketAddr, auth_type: AuthType) -> ConnectionRequest {
        ConnectionRequest {
            name: "integration".to_owned(),
            host: address.ip().to_string(),
            port: address.port(),
            username: "terminalt".to_owned(),
            auth_type,
            password: Some("test-secret".to_owned()),
            private_key_path: None,
            private_key_passphrase: None,
            agent_key_fingerprint: None,
            proxy: None,
            jump_hosts: Vec::new(),
            columns: 100,
            rows: 30,
            timeout_seconds: 5,
            keepalive_enabled: true,
            keepalive_seconds: 30,
        }
    }

    #[tokio::test]
    async fn password_authentication_opens_pty_shell() {
        let (address, fingerprint, server) = start_server().await;
        let mut connection = request(address, AuthType::Password);
        let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let mut channel = handle.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        let output = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(russh::ChannelMsg::Data { data }) = channel.wait().await {
                    break data;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(output.as_ref(), b"terminal-ready\r\n");
        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn two_jump_route_opens_target_shell_over_direct_tcpip_channels() {
        let (target_address, target_fingerprint, target_server) = start_server().await;
        let (second_address, second_fingerprint, second_server) = start_server().await;
        let (first_address, first_fingerprint, first_server) = start_server().await;
        let mut target = request(target_address, AuthType::Password);
        target.jump_hosts = vec![
            JumpHostRequest {
                connection: request(first_address, AuthType::Password),
                expected_fingerprint: first_fingerprint,
            },
            JumpHostRequest {
                connection: request(second_address, AuthType::Password),
                expected_fingerprint: second_fingerprint,
            },
        ];

        let (handle, _, _, mut upstream) =
            connect_route_authenticated(&mut target, &target_fingerprint, None)
                .await
                .unwrap();
        assert_eq!(upstream.len(), 2);
        let mut channel = handle.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        let output = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(russh::ChannelMsg::Data { data }) = channel.wait().await {
                    break data;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(output.as_ref(), b"terminal-ready\r\n");
        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        super::disconnect_upstream(&mut upstream, "test complete").await;
        first_server.abort();
        second_server.abort();
        target_server.abort();
    }

    #[tokio::test]
    async fn changed_second_jump_fingerprint_blocks_the_route() {
        let (target_address, target_fingerprint, target_server) = start_server().await;
        let (second_address, _, second_server) = start_server().await;
        let (first_address, first_fingerprint, first_server) = start_server().await;
        let mut target = request(target_address, AuthType::Password);
        target.jump_hosts = vec![
            JumpHostRequest {
                connection: request(first_address, AuthType::Password),
                expected_fingerprint: first_fingerprint,
            },
            JumpHostRequest {
                connection: request(second_address, AuthType::Password),
                expected_fingerprint: "SHA256:changed-second-hop".to_owned(),
            },
        ];

        let error = match connect_route_authenticated(&mut target, &target_fingerprint, None).await
        {
            Ok(_) => panic!("route accepted a changed second-hop host key"),
            Err(error) => error,
        };
        assert_eq!(error.code, "JUMP-HOST-FAILED");
        assert!(error.message.contains("2/2"));
        first_server.abort();
        second_server.abort();
        target_server.abort();
    }

    #[tokio::test]
    async fn connection_pool_reuses_transport_until_the_last_lease_is_released() {
        let (address, fingerprint, server) = start_server().await;
        let mut connection = request(address, AuthType::Password);
        let (handle, _, forwards) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let pool = ConnectionPool::default();
        let first = pool
            .adopt(
                "saved-route".to_owned(),
                PooledConnection::new(handle, forwards, Vec::new()),
            )
            .unwrap();
        let second = pool.acquire("saved-route").unwrap().unwrap();
        assert!(Arc::ptr_eq(&first.handle(), &second.handle()));
        drop(first);

        let channel = second.handle().channel_open_session().await.unwrap();
        channel.close().await.unwrap();
        drop(second);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(pool.acquire("saved-route").unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn local_and_dynamic_tunnels_forward_real_tcp_payloads() {
        let (ssh_address, fingerprint, ssh_server) = start_server().await;
        let (echo_address, echo_server) = start_echo_server().await;
        let mut connection = request(ssh_address, AuthType::Password);
        let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let handle = Arc::new(handle);

        let ingress = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let mut local_client = TcpStream::connect(ingress_address).await.unwrap();
        let (local_server, _) = ingress.accept().await.unwrap();
        let local_handle = Arc::clone(&handle);
        let local = tokio::spawn(async move {
            crate::tunnel::test_local_forward(
                local_server,
                local_handle,
                echo_address.ip().to_string(),
                echo_address.port(),
            )
            .await
        });
        local_client.write_all(b"local-forward").await.unwrap();
        let mut local_echo = [0_u8; 13];
        local_client.read_exact(&mut local_echo).await.unwrap();
        assert_eq!(&local_echo, b"local-forward");
        drop(local_client);
        local.await.unwrap().unwrap();

        let ingress = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let mut socks_client = TcpStream::connect(ingress_address).await.unwrap();
        let (socks_server, _) = ingress.accept().await.unwrap();
        let dynamic_handle = Arc::clone(&handle);
        let dynamic = tokio::spawn(async move {
            crate::tunnel::test_dynamic_forward(socks_server, dynamic_handle).await
        });
        socks_client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        socks_client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let octets = match echo_address.ip() {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => panic!("echo listener was unexpectedly IPv6"),
        };
        let mut connect = vec![5, 1, 0, 1];
        connect.extend_from_slice(&octets);
        connect.extend_from_slice(&echo_address.port().to_be_bytes());
        socks_client.write_all(&connect).await.unwrap();
        let mut response = [0_u8; 10];
        socks_client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..2], &[5, 0]);
        socks_client.write_all(b"dynamic-forward").await.unwrap();
        let mut dynamic_echo = [0_u8; 15];
        socks_client.read_exact(&mut dynamic_echo).await.unwrap();
        assert_eq!(&dynamic_echo, b"dynamic-forward");
        drop(socks_client);
        dynamic.await.unwrap().unwrap();

        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        ssh_server.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn remote_tunnel_forwards_to_local_target_and_can_be_cancelled() {
        let (ssh_address, fingerprint, ssh_server) = start_server().await;
        let (echo_address, echo_server) = start_echo_server().await;
        let mut connection = request(ssh_address, AuthType::Password);
        let (handle, _, forwards) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let handle = Arc::new(handle);
        let bind_host = "127.0.0.1".to_owned();
        let port = crate::tunnel::test_start_remote_forward(
            Arc::clone(&handle),
            Arc::clone(&forwards),
            bind_host.clone(),
            echo_address.ip().to_string(),
            echo_address.port(),
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect((bind_host.as_str(), port))
            .await
            .unwrap();
        client.write_all(b"remote-forward").await.unwrap();
        let mut echoed = [0_u8; 14];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"remote-forward");
        drop(client);

        crate::tunnel::test_stop_remote_forward(
            Arc::clone(&handle),
            forwards,
            bind_host.clone(),
            port,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(TcpStream::connect((bind_host.as_str(), port))
            .await
            .is_err());
        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        ssh_server.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn one_ssh_transport_handles_one_hundred_concurrent_local_forwards() {
        let (ssh_address, fingerprint, ssh_server) = start_server().await;
        let (echo_address, echo_server) = start_echo_server().await;
        let mut connection = request(ssh_address, AuthType::Password);
        let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let handle = Arc::new(handle);
        let ingress = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let accept_handle = Arc::clone(&handle);
        let accept = tokio::spawn(async move {
            let mut forwards = JoinSet::new();
            for _ in 0..100 {
                let (stream, _) = ingress.accept().await.unwrap();
                let handle = Arc::clone(&accept_handle);
                forwards.spawn(crate::tunnel::test_local_forward(
                    stream,
                    handle,
                    echo_address.ip().to_string(),
                    echo_address.port(),
                ));
            }
            while let Some(result) = forwards.join_next().await {
                result.unwrap().unwrap();
            }
        });
        let mut clients = JoinSet::new();
        for index in 0_u32..100 {
            clients.spawn(async move {
                let mut stream = TcpStream::connect(ingress_address).await.unwrap();
                let payload = index.to_be_bytes();
                stream.write_all(&payload).await.unwrap();
                let mut echoed = [0_u8; 4];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
            });
        }
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
        accept.await.unwrap();
        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        ssh_server.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn local_forward_can_be_started_and_stopped_one_hundred_times() {
        let (ssh_address, fingerprint, ssh_server) = start_server().await;
        let (echo_address, echo_server) = start_echo_server().await;
        let mut connection = request(ssh_address, AuthType::Password);
        let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let handle = Arc::new(handle);

        for index in 0_u32..100 {
            let ingress = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let ingress_address = ingress.local_addr().unwrap();
            let mut client = TcpStream::connect(ingress_address).await.unwrap();
            let (server, _) = ingress.accept().await.unwrap();
            let forward_handle = Arc::clone(&handle);
            let forward = tokio::spawn(crate::tunnel::test_local_forward(
                server,
                forward_handle,
                echo_address.ip().to_string(),
                echo_address.port(),
            ));
            let payload = index.to_be_bytes();
            client.write_all(&payload).await.unwrap();
            let mut echoed = [0_u8; 4];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
            drop(client);
            forward.await.unwrap().unwrap();
        }

        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        ssh_server.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn keyboard_interactive_loopback_supports_hidden_one_time_code() {
        let (address, _, server) = start_server().await;
        let captured_key = Arc::new(std::sync::Mutex::new(None));
        let mut handle = client::connect(
            Arc::new(client_config(None)),
            address,
            ProbeHandler { captured_key },
        )
        .await
        .unwrap();
        let response = handle
            .authenticate_keyboard_interactive_start("terminalt", None)
            .await
            .unwrap();
        match response {
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                assert_eq!(prompts.len(), 1);
                assert!(!prompts[0].echo);
            }
            other => panic!("expected info request, got {other:?}"),
        }
        let response = handle
            .authenticate_keyboard_interactive_respond(vec!["654321".to_owned()])
            .await
            .unwrap();
        assert!(matches!(response, KeyboardInteractiveAuthResponse::Success));
        server.abort();
    }

    #[tokio::test]
    async fn ten_sessions_remain_isolated_when_another_authentication_fails() {
        let (address, fingerprint, server) = start_server().await;
        let mut handles = Vec::new();
        for index in 0..10 {
            let mut connection = request(address, AuthType::Password);
            connection.name = format!("session-{index}");
            let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
                .await
                .unwrap();
            handles.push(handle);
        }

        let mut rejected = request(address, AuthType::Password);
        rejected.password = Some("incorrect".to_owned());
        let error = match connect_authenticated(&mut rejected, &fingerprint, None).await {
            Ok(_) => panic!("incorrect password unexpectedly authenticated"),
            Err(error) => error,
        };
        assert_eq!(error.code, "AUTHENTICATION-FAILED");

        for (index, handle) in handles.into_iter().enumerate() {
            let channel = handle.channel_open_session().await.unwrap();
            channel
                .request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
                .await
                .unwrap();
            channel.request_shell(true).await.unwrap();
            let (mut reader, writer) = channel.split();
            let ready = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(russh::ChannelMsg::Data { data }) = reader.wait().await {
                        break data;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(ready.as_ref(), b"terminal-ready\r\n");

            let probe = format!("probe-{index}").into_bytes();
            writer.data_bytes(probe.clone()).await.unwrap();
            let echoed = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(russh::ChannelMsg::Data { data }) = reader.wait().await {
                        break data;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(echoed.as_ref(), probe);
            drop(reader);
            drop(writer);
            handle
                .disconnect(russh::Disconnect::ByApplication, "test complete", "")
                .await
                .unwrap();
        }
        server.abort();
    }

    #[tokio::test]
    async fn five_megabytes_of_output_preserve_follow_up_interaction() {
        const OUTPUT_SIZE: usize = 5 * 1024 * 1024;
        let startup_output = vec![b'L'; OUTPUT_SIZE];
        let (address, fingerprint, server) = start_server_with_output(startup_output).await;
        let mut connection = request(address, AuthType::Password);
        let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let channel = handle.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        let (mut reader, writer) = channel.split();

        let received = tokio::time::timeout(Duration::from_secs(15), async {
            let mut received = Vec::with_capacity(OUTPUT_SIZE);
            while received.len() < OUTPUT_SIZE {
                match reader.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => received.extend_from_slice(&data),
                    Some(_) => {}
                    None => panic!("server closed before the output completed"),
                }
            }
            received
        })
        .await
        .unwrap();
        assert_eq!(received.len(), OUTPUT_SIZE);
        assert!(received.iter().all(|byte| *byte == b'L'));

        writer
            .data_bytes(b"still-interactive".to_vec())
            .await
            .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(russh::ChannelMsg::Data { data }) = reader.wait().await {
                    break data;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(echoed.as_ref(), b"still-interactive");
        drop(reader);
        drop(writer);
        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn terminal_output_preserves_utf8_wide_combining_and_ansi_bytes() {
        let expected = concat!(
            "\u{1b}[38;2;50;215;168m真彩色\u{1b}[0m\r\n",
            "中文 / 🚀 / ＡＢ / e\u{301}\r\n",
            "\u{1b}[2J\u{1b}[H"
        )
        .as_bytes()
        .to_vec();
        let (address, fingerprint, server) = start_server_with_output(expected.clone()).await;
        let mut connection = request(address, AuthType::Password);
        let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        let mut channel = handle.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), async {
            let mut received = Vec::with_capacity(expected.len());
            while received.len() < expected.len() {
                if let Some(russh::ChannelMsg::Data { data }) = channel.wait().await {
                    received.extend_from_slice(&data);
                }
            }
            received
        })
        .await
        .unwrap();
        assert_eq!(received, expected);
        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn private_key_authentication_succeeds() {
        let (address, fingerprint, server) = start_server().await;
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("id_ed25519");
        let private_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        std::fs::write(
            &key_path,
            private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let mut connection = request(address, AuthType::PrivateKey);
        connection.password = None;
        connection.private_key_path = Some(key_path.to_string_lossy().into_owned());

        let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
            .await
            .unwrap();
        handle
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn common_openssh_key_algorithms_and_passphrase_are_supported() {
        let (address, fingerprint, server) = start_server().await;
        let directory = tempfile::tempdir().unwrap();
        let algorithms = [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Rsa { hash: None },
        ];

        for (index, algorithm) in algorithms.into_iter().enumerate() {
            let path = directory.path().join(format!("id_test_{index}"));
            let key = PrivateKey::random(&mut rand::rng(), algorithm).unwrap();
            let (key, passphrase) = if index == 0 {
                (
                    key.encrypt(&mut rand::rng(), "key-passphrase").unwrap(),
                    Some("key-passphrase".to_owned()),
                )
            } else {
                (key, None)
            };
            std::fs::write(
                &path,
                key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
            )
            .unwrap();

            let mut connection = request(address, AuthType::PrivateKey);
            connection.password = None;
            connection.private_key_path = Some(path.to_string_lossy().into_owned());
            connection.private_key_passphrase = passphrase;
            let (handle, _, _) = connect_authenticated(&mut connection, &fingerprint, None)
                .await
                .unwrap();
            handle
                .disconnect(russh::Disconnect::ByApplication, "test complete", "")
                .await
                .unwrap();
        }
        server.abort();
    }

    #[tokio::test]
    async fn incorrect_password_is_rejected_without_echoing_the_secret() {
        let (address, fingerprint, server) = start_server().await;
        let mut connection = request(address, AuthType::Password);
        connection.password = Some("must-not-appear".to_owned());
        let error = match connect_authenticated(&mut connection, &fingerprint, None).await {
            Ok(_) => panic!("incorrect password unexpectedly authenticated"),
            Err(error) => error,
        };

        assert_eq!(error.code, "AUTHENTICATION-FAILED");
        assert!(!error
            .technical_details
            .as_deref()
            .unwrap_or_default()
            .contains("must-not-appear"));
        server.abort();
    }

    #[tokio::test]
    async fn host_key_inspection_detects_unknown_then_trusted_key() {
        let (address, _, server) = start_server().await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts.json");
        let first = inspect_host_key(
            &address.ip().to_string(),
            address.port(),
            Duration::from_secs(5),
            path.clone(),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(first.status, HostKeyStatus::Unknown));

        let identity = super::HostKeyIdentity {
            algorithm: first.algorithm.clone(),
            fingerprint_sha256: first.fingerprint_sha256.clone(),
            public_key: "test-public-key".to_owned(),
        };
        KnownHostsStore::new(path.clone())
            .approve(
                &first.host,
                first.port,
                &identity,
                crate::models::HostKeyAction::TrustNew,
            )
            .unwrap();
        let second = inspect_host_key(
            &address.ip().to_string(),
            address.port(),
            Duration::from_secs(5),
            path,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(second.status, HostKeyStatus::Trusted));
        server.abort();
    }
}
