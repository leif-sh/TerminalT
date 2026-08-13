use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use russh::{
    client::{self},
    keys::{load_secret_key, ssh_key, PrivateKeyWithHashAlg},
    ChannelMsg, Disconnect,
};
use russh_sftp::{client::SftpSession, protocol::FileType};
use tauri::{AppHandle, Emitter, Manager};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, Semaphore},
};
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    known_hosts::{HostKeyIdentity, KnownHostsStore},
    models::{
        AuthType, ConnectionRequest, ConnectionTestResult, HostKeyApproval, HostKeyInspection,
        RemoteDirectoryEntry, RemoteDirectoryListing, RemoteEntryKind, SessionOutputPayload,
        SessionState, SessionStatus, SessionStatusPayload, TransferDirection,
        TransferProgressPayload, TransferStatus, TransferTask,
    },
    session::{SessionCommand, SessionRegistry},
};

const SESSION_OUTPUT_EVENT: &str = "session-output";
const SESSION_STATUS_EVENT: &str = "session-status";
const TRANSFER_PROGRESS_EVENT: &str = "transfer-progress";

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
struct VerifiedHandler {
    expected_fingerprint: String,
    captured_key: Arc<Mutex<Option<ssh_key::PublicKey>>>,
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
}

pub async fn inspect_host_key(
    host: &str,
    port: u16,
    timeout: Duration,
    known_hosts_path: PathBuf,
) -> Result<HostKeyInspection, AppError> {
    let captured_key = Arc::new(Mutex::new(None));
    let handler = ProbeHandler {
        captured_key: Arc::clone(&captured_key),
    };
    let config = Arc::new(client_config(None));
    let connection = tokio::time::timeout(
        timeout,
        client::connect(config, (host.to_owned(), port), handler),
    )
    .await
    .map_err(|_| connection_timeout())?
    .map_err(map_connect_error)?;
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

pub async fn test_connection(
    mut request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
) -> Result<ConnectionTestResult, AppError> {
    request.validate().map_err(AppError::validation)?;
    let started_at = Instant::now();
    let host = request.host.clone();
    let port = request.port;
    let timeout = Duration::from_secs(request.timeout_seconds);
    let (handle, identity) = tokio::time::timeout(
        timeout,
        connect_authenticated(&mut request, &approval.fingerprint_sha256),
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

    Ok(ConnectionTestResult {
        elapsed_millis: started_at.elapsed().as_millis(),
        host_key: inspection,
    })
}

pub async fn start_session(
    app: AppHandle,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
) -> Result<SessionState, AppError> {
    start_session_with_id(app, request, approval, known_hosts_path, None).await
}

pub async fn reconnect_session(
    app: AppHandle,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
    session_id: String,
) -> Result<SessionState, AppError> {
    start_session_with_id(app, request, approval, known_hosts_path, Some(session_id)).await
}

async fn start_session_with_id(
    app: AppHandle,
    mut request: ConnectionRequest,
    approval: HostKeyApproval,
    known_hosts_path: PathBuf,
    session_id: Option<String>,
) -> Result<SessionState, AppError> {
    request.validate().map_err(AppError::validation)?;
    let timeout = Duration::from_secs(request.timeout_seconds);
    let title = request.name.clone();
    let host = request.host.clone();
    let port = request.port;
    let columns = request.columns;
    let rows = request.rows;
    let (handle, identity) = tokio::time::timeout(
        timeout,
        connect_authenticated(&mut request, &approval.fingerprint_sha256),
    )
    .await
    .map_err(|_| connection_timeout())??;

    KnownHostsStore::new(known_hosts_path).approve(&host, port, &identity, approval.action)?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(map_russh_error)?;
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
        run_session(task_app, task_session_id, handle, channel, commands_rx).await;
        let _ = completion_tx.send(());
    });

    Ok(SessionState {
        id: session_id,
        title,
        status: SessionStatus::Connected,
        started_at: chrono::Utc::now().to_rfc3339(),
    })
}

async fn connect_authenticated(
    request: &mut ConnectionRequest,
    expected_fingerprint: &str,
) -> Result<(client::Handle<VerifiedHandler>, HostKeyIdentity), AppError> {
    let captured_key = Arc::new(Mutex::new(None));
    let handler = VerifiedHandler {
        expected_fingerprint: expected_fingerprint.to_owned(),
        captured_key: Arc::clone(&captured_key),
    };
    let keepalive = request
        .keepalive_enabled
        .then(|| Duration::from_secs(request.keepalive_seconds));
    let config = Arc::new(client_config(keepalive));
    let mut handle = client::connect(config, (request.host.clone(), request.port), handler)
        .await
        .map_err(|error| {
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
                map_connect_error(error)
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

    Ok((handle, identity))
}

async fn run_session(
    app: AppHandle,
    session_id: String,
    handle: client::Handle<VerifiedHandler>,
    channel: russh::Channel<client::Msg>,
    mut commands: mpsc::Receiver<SessionCommand>,
) {
    app.state::<crate::diagnostics::DiagnosticLog>().record(
        "ssh-session-start",
        None,
        &format!("session={session_id}"),
    );
    let handle = Arc::new(handle);
    let (sftp_commands, sftp_receiver) = mpsc::channel(8);
    let sftp_worker =
        tauri::async_runtime::spawn(run_sftp_worker(Arc::clone(&handle), sftp_receiver));
    let transfer_slots = Arc::new(Semaphore::new(3));
    let mut transfer_cancellations =
        std::collections::HashMap::<String, oneshot::Sender<()>>::new();
    let mut transfer_handles = Vec::new();
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
                Some(SessionCommand::ListRemoteDirectory { path, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::Browse { path, response });
                }
                Some(SessionCommand::CreateRemoteDirectory { parent_path, name, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::CreateDirectory { parent_path, name, response });
                }
                Some(SessionCommand::RenameRemoteEntry { path, new_name, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::Rename { path, new_name, response });
                }
                Some(SessionCommand::DeleteRemoteEntry { path, response }) => {
                    enqueue_sftp_request(&sftp_commands, SftpRequest::Delete { path, response });
                }
                Some(SessionCommand::StartTransfer { direction, source, target, overwrite, response }) => {
                    let task = new_transfer_task(&session_id, direction, source, target);
                    let (cancel, cancellation) = oneshot::channel();
                    transfer_cancellations.insert(task.id.clone(), cancel);
                    let _ = response.send(Ok(task.clone()));
                    emit_transfer(&app, task.clone());
                    let transfer_app = app.clone();
                    let transfer_handle = Arc::clone(&handle);
                    let transfer_slots = Arc::clone(&transfer_slots);
                    transfer_handles.push(tauri::async_runtime::spawn(async move {
                        run_transfer(transfer_app, transfer_handle, transfer_slots, task, overwrite, cancellation).await;
                    }));
                }
                Some(SessionCommand::CancelTransfer { task_id }) => {
                    if let Some(cancellation) = transfer_cancellations.remove(&task_id) {
                        let _ = cancellation.send(());
                    }
                }
                Some(SessionCommand::Close) | None => {
                    let _ = writer.close().await;
                    break "会话已关闭".to_owned();
                }
            },
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
        for transfer in transfer_handles {
            let _ = transfer.await;
        }
    })
    .await;
    let _ = handle
        .disconnect(Disconnect::ByApplication, "session closed", "")
        .await;
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
        path: String,
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
            | SftpRequest::Delete { response, .. } => {
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
            SftpRequest::Browse { path, response } => {
                let _ = response.send(browse_remote_directory(&handle, &mut sftp, path).await);
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
            SftpRequest::Delete { path, response } => {
                let _ = response.send(delete_remote_entry(&handle, &mut sftp, path).await);
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
        *sftp = Some(
            SftpSession::new(channel.into_stream())
                .await
                .map_err(map_sftp_error)?,
        );
    }
    Ok(sftp.as_ref().expect("SFTP session initialized above"))
}

async fn browse_remote_directory(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &mut Option<SftpSession>,
    requested_path: String,
) -> Result<RemoteDirectoryListing, AppError> {
    let session = ensure_sftp_session(handle, sftp).await?;
    let result = async {
        let path = session
            .canonicalize(requested_path)
            .await
            .map_err(map_sftp_error)?;
        let mut entries = session
            .read_dir(path.clone())
            .await
            .map_err(map_sftp_error)?
            .map(|entry| {
                let metadata = entry.metadata();
                let file_type = entry.file_type();
                RemoteDirectoryEntry {
                    name: entry.file_name(),
                    path: entry.path(),
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
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            let left_directory = left.kind == RemoteEntryKind::Directory;
            let right_directory = right.kind == RemoteEntryKind::Directory;
            right_directory
                .cmp(&left_directory)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        let truncated = entries.len() > 5000;
        entries.truncate(5000);
        Ok(RemoteDirectoryListing {
            parent_path: parent_remote_path(&path),
            path,
            entries,
            truncated,
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

async fn delete_remote_entry(
    handle: &client::Handle<VerifiedHandler>,
    sftp: &mut Option<SftpSession>,
    path: String,
) -> Result<(), AppError> {
    let session = ensure_sftp_session(handle, sftp).await?;
    let metadata = session
        .symlink_metadata(path.clone())
        .await
        .map_err(map_sftp_error)?;
    match metadata.file_type() {
        FileType::Dir => {
            let mut entries = session
                .read_dir(path.clone())
                .await
                .map_err(map_sftp_error)?;
            if entries.next().is_some() {
                return Err(AppError::sftp(
                    "SFTP-DIRECTORY-NOT-EMPTY",
                    "基础版不支持删除非空目录",
                    path,
                ));
            }
            session.remove_dir(path).await.map_err(map_sftp_error)
        }
        FileType::File | FileType::Symlink => {
            session.remove_file(path).await.map_err(map_sftp_error)
        }
        FileType::Other => Err(AppError::sftp(
            "SFTP-UNSUPPORTED-ENTRY",
            "不支持删除此类型的远端对象",
            path,
        )),
    }
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
    source: String,
    target: String,
) -> TransferTask {
    let file_name = match direction {
        TransferDirection::Upload => std::path::Path::new(&source).file_name(),
        TransferDirection::Download => std::path::Path::new(&target).file_name(),
    }
    .and_then(|value| value.to_str())
    .unwrap_or("未命名文件")
    .to_owned();
    TransferTask {
        id: uuid::Uuid::new_v4().to_string(),
        session_id: session_id.to_owned(),
        file_name,
        direction,
        source,
        target,
        transferred_bytes: 0,
        total_bytes: None,
        bytes_per_second: 0,
        status: TransferStatus::Queued,
        error: None,
    }
}

fn emit_transfer(app: &AppHandle, task: TransferTask) {
    let _ = app.emit(TRANSFER_PROGRESS_EVENT, TransferProgressPayload { task });
}

async fn run_transfer(
    app: AppHandle,
    handle: Arc<client::Handle<VerifiedHandler>>,
    slots: Arc<Semaphore>,
    mut task: TransferTask,
    overwrite: bool,
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
    task.status = TransferStatus::Running;
    emit_transfer(&app, task.clone());
    let started = Instant::now();
    let result = match task.direction {
        TransferDirection::Upload => {
            upload_file(
                &app,
                &handle,
                &mut task,
                overwrite,
                &mut cancellation,
                started,
            )
            .await
        }
        TransferDirection::Download => {
            download_file(
                &app,
                &handle,
                &mut task,
                overwrite,
                &mut cancellation,
                started,
            )
            .await
        }
    };
    drop(permit);
    match result {
        Ok(()) => task.status = TransferStatus::Succeeded,
        Err(error) if error.code == "TRANSFER-CANCELLED" => task.status = TransferStatus::Cancelled,
        Err(error) => {
            task.status = TransferStatus::Failed;
            task.error = Some(error.message);
        }
    }
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
    task.total_bytes = Some(
        local
            .metadata()
            .await
            .map_err(|error| {
                AppError::sftp(
                    "LOCAL-READ-FAILED",
                    "无法读取本地文件信息",
                    error.to_string(),
                )
            })?
            .len(),
    );
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
            let _ = sftp.remove_file(temporary).await;
            let _ = sftp.close().await;
            return Err(error);
        }
    } else {
        let _ = sftp.remove_file(temporary).await;
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
    task.total_bytes = Some(
        sftp.metadata(task.source.clone())
            .await
            .map_err(map_sftp_error)?
            .size
            .unwrap_or(0),
    );
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
            let _ = tokio::fs::remove_file(&temporary).await;
            let _ = sftp.close().await;
            return Err(error);
        }
    } else {
        let _ = tokio::fs::remove_file(&temporary).await;
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
        return Err(map_sftp_error(error));
    }
    if exists {
        let _ = sftp.remove_file(backup).await;
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
            "LOCAL-WRITE-FAILED",
            "无法完成本地文件替换",
            error.to_string(),
        ));
    }
    if exists {
        let _ = tokio::fs::remove_file(backup).await;
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
    use super::{backup_local_path, join_remote_path, parent_remote_path, temporary_local_path};

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
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use russh::{
        keys::{ssh_key, Algorithm, EcdsaCurve, HashAlg, PrivateKey},
        server::{self, Auth, Msg, Server as _, Session},
        Channel, ChannelId,
    };
    use tokio::sync::Mutex;

    use super::{connect_authenticated, inspect_host_key};
    use crate::{
        known_hosts::KnownHostsStore,
        models::{AuthType, ConnectionRequest, HostKeyStatus},
    };

    #[derive(Clone)]
    struct TestServer {
        channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
        startup_output: Arc<Vec<u8>>,
    }

    impl Default for TestServer {
        fn default() -> Self {
            Self {
                channels: Arc::default(),
                startup_output: Arc::new(b"terminal-ready\r\n".to_vec()),
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
            session.data(channel, data.to_vec())?;
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
        let (handle, _) = connect_authenticated(&mut connection, &fingerprint)
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
    async fn ten_sessions_remain_isolated_when_another_authentication_fails() {
        let (address, fingerprint, server) = start_server().await;
        let mut handles = Vec::new();
        for index in 0..10 {
            let mut connection = request(address, AuthType::Password);
            connection.name = format!("session-{index}");
            let (handle, _) = connect_authenticated(&mut connection, &fingerprint)
                .await
                .unwrap();
            handles.push(handle);
        }

        let mut rejected = request(address, AuthType::Password);
        rejected.password = Some("incorrect".to_owned());
        let error = match connect_authenticated(&mut rejected, &fingerprint).await {
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
        let (handle, _) = connect_authenticated(&mut connection, &fingerprint)
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
        let (handle, _) = connect_authenticated(&mut connection, &fingerprint)
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

        let (handle, _) = connect_authenticated(&mut connection, &fingerprint)
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
            let (handle, _) = connect_authenticated(&mut connection, &fingerprint)
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
        let error = match connect_authenticated(&mut connection, &fingerprint).await {
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
        )
        .await
        .unwrap();
        assert!(matches!(second.status, HostKeyStatus::Trusted));
        server.abort();
    }
}
