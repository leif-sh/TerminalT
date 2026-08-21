mod assets;
mod authentication;
mod connection_pool;
mod credentials;
mod diagnostics;
mod error;
mod known_hosts;
mod models;
mod network;
mod session;
mod settings;
mod ssh_client;
mod tunnel;

use chrono::Utc;
use error::AppError;
use models::{
    AgentIdentityInfo, AssetTransferSummary, AuthenticationPromptResponse, ConnectionAssetSnapshot,
    ConnectionGroup, ConnectionProfile, ConnectionProgressPayload, ConnectionRequest,
    ConnectionTestResult, GroupNameRequest, HealthResponse, HostKeyApproval, HostKeyInspection,
    JumpHostRequest, KeepaliveSettings, ReconnectSavedSessionRequest, RemoteDirectoryListing,
    SaveConnectionRequest, SaveTunnelRequest, SavedSessionRequest, SessionOutputPayload,
    SessionState, SessionStatus, SessionStatusPayload, TransferDirection, TransferTask,
    TunnelProfile, TunnelRuntimeState, WindowState,
};
use session::{OperationRegistry, SessionCommand, SessionRegistry};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::{sync::oneshot, time};
use uuid::Uuid;

#[tauri::command]
fn load_settings(
    app: AppHandle,
    store: State<'_, settings::SettingsStore>,
) -> Result<settings::AppSettings, AppError> {
    let download = app
        .path()
        .download_dir()
        .map_err(|error| AppError::asset_storage("无法确定系统下载目录", error.to_string()))?;
    store.load(&download)
}

#[tauri::command]
fn save_settings(
    store: State<'_, settings::SettingsStore>,
    settings: settings::AppSettings,
) -> Result<(), AppError> {
    store.save(&settings)
}

#[tauri::command]
fn save_window_state(
    store: State<'_, settings::SettingsStore>,
    state: WindowState,
) -> Result<(), AppError> {
    store.save_window(&state)
}

#[tauri::command]
fn diagnostics_path(store: State<'_, diagnostics::DiagnosticLog>) -> String {
    store.directory()
}

#[tauri::command]
fn clear_diagnostics(store: State<'_, diagnostics::DiagnosticLog>) -> Result<(), AppError> {
    store.clear()
}

#[tauri::command]
fn export_diagnostics(
    store: State<'_, diagnostics::DiagnosticLog>,
    path: String,
) -> Result<diagnostics::LogExportSummary, AppError> {
    store.export_filtered(std::path::Path::new(&path))
}

const IPC_PROTOCOL_VERSION: u16 = 1;
const SESSION_OUTPUT_EVENT: &str = "session-output";
const SESSION_STATUS_EVENT: &str = "session-status";
const CONNECTION_PROGRESS_EVENT: &str = "connection-progress";

#[tauri::command]
fn health_check() -> HealthResponse {
    HealthResponse {
        status: "ok",
        protocol_version: IPC_PROTOCOL_VERSION,
        app_version: env!("CARGO_PKG_VERSION"),
    }
}

#[tauri::command]
fn list_connection_assets(
    store: State<'_, assets::AssetStore>,
) -> Result<ConnectionAssetSnapshot, AppError> {
    store.snapshot()
}

#[tauri::command]
fn save_connection_profile(
    store: State<'_, assets::AssetStore>,
    request: SaveConnectionRequest,
) -> Result<ConnectionProfile, AppError> {
    store.save_connection(request)
}

#[tauri::command]
fn copy_connection_profile(
    store: State<'_, assets::AssetStore>,
    connection_id: String,
) -> Result<ConnectionProfile, AppError> {
    store.copy_connection(&connection_id)
}

#[tauri::command]
fn delete_connection_profile(
    store: State<'_, assets::AssetStore>,
    connection_id: String,
) -> Result<(), AppError> {
    store.delete_connection(&connection_id)
}

#[tauri::command]
fn save_tunnel_profile(
    store: State<'_, assets::AssetStore>,
    request: SaveTunnelRequest,
) -> Result<TunnelProfile, AppError> {
    store.save_tunnel(request)
}

#[tauri::command]
fn copy_tunnel_profile(
    store: State<'_, assets::AssetStore>,
    tunnel_id: String,
) -> Result<TunnelProfile, AppError> {
    store.copy_tunnel(&tunnel_id)
}

#[tauri::command]
fn delete_tunnel_profile(
    store: State<'_, assets::AssetStore>,
    tunnel_id: String,
) -> Result<(), AppError> {
    store.delete_tunnel(&tunnel_id)
}

#[tauri::command]
fn list_runtime_tunnels(
    registry: State<'_, tunnel::TunnelRegistry>,
) -> Result<Vec<TunnelRuntimeState>, AppError> {
    registry.list()
}

#[tauri::command]
async fn start_tunnel(
    sessions: State<'_, SessionRegistry>,
    store: State<'_, assets::AssetStore>,
    session_id: String,
    tunnel_id: String,
) -> Result<TunnelRuntimeState, AppError> {
    let profile = store.tunnel(&tunnel_id)?;
    sessions.start_tunnel(&session_id, profile).await
}

#[tauri::command]
fn stop_tunnel(
    registry: State<'_, tunnel::TunnelRegistry>,
    runtime_id: String,
) -> Result<TunnelRuntimeState, AppError> {
    registry.stop(&runtime_id)
}

#[tauri::command]
fn save_connection_group(
    store: State<'_, assets::AssetStore>,
    request: GroupNameRequest,
) -> Result<ConnectionGroup, AppError> {
    store.save_group(request)
}

#[tauri::command]
fn delete_connection_group(
    store: State<'_, assets::AssetStore>,
    group_id: String,
) -> Result<(), AppError> {
    store.delete_group(&group_id)
}

#[tauri::command]
fn record_recent_target(
    store: State<'_, assets::AssetStore>,
    target: String,
) -> Result<(), AppError> {
    store.record_recent_target(&target)
}

#[tauri::command]
fn clear_recent_targets(store: State<'_, assets::AssetStore>) -> Result<(), AppError> {
    store.clear_recent_targets()
}

#[tauri::command]
fn export_connection_assets(
    store: State<'_, assets::AssetStore>,
    path: String,
) -> Result<AssetTransferSummary, AppError> {
    store.export_to(std::path::Path::new(&path))
}

#[tauri::command]
fn import_connection_assets(
    store: State<'_, assets::AssetStore>,
    path: String,
) -> Result<AssetTransferSummary, AppError> {
    store.import_from(std::path::Path::new(&path))
}

#[tauri::command]
fn list_host_keys(app: AppHandle) -> Result<Vec<known_hosts::HostKeyRecord>, AppError> {
    known_hosts::KnownHostsStore::new(known_hosts_path(&app)?).list()
}

#[tauri::command]
fn delete_host_key(app: AppHandle, host: String, port: u16) -> Result<(), AppError> {
    known_hosts::KnownHostsStore::new(known_hosts_path(&app)?).delete(&host, port)
}

#[tauri::command]
fn clear_host_keys(app: AppHandle) -> Result<(), AppError> {
    known_hosts::KnownHostsStore::new(known_hosts_path(&app)?).clear()
}

#[tauri::command]
fn create_mock_session(
    app: AppHandle,
    registry: State<'_, SessionRegistry>,
) -> Result<SessionState, AppError> {
    let session_id = Uuid::new_v4().to_string();
    let started_at = Utc::now().to_rfc3339();
    let (cancellation, cancellation_receiver) = oneshot::channel();
    let (completion, completion_receiver) = oneshot::channel();
    registry.insert_mock(session_id.clone(), cancellation, completion_receiver)?;

    let task_session_id = session_id.clone();
    let task_app = app.clone();
    tauri::async_runtime::spawn(async move {
        run_mock_session(task_app, task_session_id, cancellation_receiver).await;
        let _ = completion.send(());
    });

    Ok(SessionState {
        id: session_id,
        title: "架构验证会话".to_owned(),
        status: SessionStatus::Connected,
        started_at,
    })
}

async fn run_mock_session(app: AppHandle, session_id: String, cancellation: oneshot::Receiver<()>) {
    time::sleep(time::Duration::from_millis(100)).await;
    let status = SessionStatusPayload {
        session_id: session_id.clone(),
        status: SessionStatus::Connected,
        message: None,
    };
    if let Err(error) = app.emit(SESSION_STATUS_EVENT, status) {
        log::warn!("failed to emit mock session status: {error}");
        return;
    }

    let welcome = concat!(
        "\u{1b}[38;2;50;215;168mTerminalT mock session ready.\u{1b}[0m\r\n",
        "IPC protocol v1 · UTF-8: 中文 / 🚀\r\n",
        "\u{1b}[36mterminalt\u{1b}[0m $ "
    );
    if let Err(error) = emit_output(&app, &session_id, welcome.as_bytes().to_vec()) {
        log::warn!("{}: {}", error.code, error.message);
        return;
    }

    let _ = cancellation.await;
}

#[tauri::command]
fn write_mock_session(
    app: AppHandle,
    registry: State<'_, SessionRegistry>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), AppError> {
    if !registry.contains(&session_id)? {
        return Err(AppError::session_not_found(&session_id));
    }

    emit_output(&app, &session_id, data.clone())?;
    if data.as_slice() == b"\r" {
        emit_output(&app, &session_id, b"\n\x1b[36mterminalt\x1b[0m $ ".to_vec())?;
    }
    Ok(())
}

#[tauri::command]
fn write_session(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), AppError> {
    registry.send(&session_id, SessionCommand::Data(data))
}

#[tauri::command]
fn resize_mock_session(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    columns: u16,
    rows: u16,
) -> Result<(), AppError> {
    registry.resize(&session_id, columns, rows)
}

#[tauri::command]
fn resize_session(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    columns: u16,
    rows: u16,
) -> Result<(), AppError> {
    registry.resize(&session_id, columns, rows)
}

#[tauri::command]
fn close_mock_session(
    app: AppHandle,
    registry: State<'_, SessionRegistry>,
    session_id: String,
) -> Result<(), AppError> {
    registry.close(&session_id)?;
    let payload = SessionStatusPayload {
        session_id,
        status: SessionStatus::Disconnected,
        message: Some("会话已关闭".to_owned()),
    };
    app.emit(SESSION_STATUS_EVENT, payload)
        .map_err(|error| AppError::event_delivery_failed(SESSION_STATUS_EVENT, error))
}

#[tauri::command]
fn close_session(registry: State<'_, SessionRegistry>, session_id: String) -> Result<(), AppError> {
    registry.close(&session_id)
}

#[tauri::command]
async fn list_remote_directory(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    path: Option<String>,
) -> Result<RemoteDirectoryListing, AppError> {
    let path = path.unwrap_or_else(|| ".".to_owned());
    if path.len() > 4096 || path.contains('\0') {
        return Err(AppError::validation("远端路径无效"));
    }
    registry.list_remote_directory(&session_id, path).await
}

fn validate_remote_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
        || name.len() > 255
    {
        return Err(AppError::validation(
            "名称不能为空、包含路径分隔符或超过 255 个字符",
        ));
    }
    Ok(name.to_owned())
}

fn validate_remote_path(path: &str) -> Result<String, AppError> {
    let path = path.trim();
    if !path.starts_with('/') || path.len() > 4096 || path.contains('\0') {
        return Err(AppError::validation("远端路径无效"));
    }
    Ok(path.to_owned())
}

#[tauri::command]
async fn create_remote_directory(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    parent_path: String,
    name: String,
) -> Result<(), AppError> {
    let name = validate_remote_name(&name)?;
    let parent_path = validate_remote_path(&parent_path)?;
    registry
        .create_remote_directory(&session_id, parent_path, name)
        .await
}

#[tauri::command]
async fn rename_remote_entry(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    path: String,
    new_name: String,
) -> Result<(), AppError> {
    let new_name = validate_remote_name(&new_name)?;
    let path = validate_remote_path(&path)?;
    registry
        .rename_remote_entry(&session_id, path, new_name)
        .await
}

#[tauri::command]
async fn delete_remote_entry(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    path: String,
) -> Result<(), AppError> {
    let path = validate_remote_path(&path)?;
    registry.delete_remote_entry(&session_id, path).await
}

#[tauri::command]
async fn start_transfer(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    direction: TransferDirection,
    source: String,
    target: String,
    overwrite: bool,
) -> Result<TransferTask, AppError> {
    if source.trim().is_empty() || target.trim().is_empty() {
        return Err(AppError::validation("传输源和目标不能为空"));
    }
    registry
        .start_transfer(&session_id, direction, source, target, overwrite)
        .await
}

#[tauri::command]
fn cancel_transfer(
    registry: State<'_, SessionRegistry>,
    session_id: String,
    task_id: String,
) -> Result<(), AppError> {
    registry.cancel_transfer(&session_id, task_id)
}

#[tauri::command]
async fn inspect_ssh_host_key(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    operation_id: String,
    host: String,
    port: u16,
    timeout_seconds: u64,
    proxy: Option<models::ProxyRequest>,
) -> Result<HostKeyInspection, AppError> {
    let host = host.trim().to_owned();
    if host.is_empty() {
        return Err(AppError::validation("请输入主机地址"));
    }
    if !(5..=60).contains(&timeout_seconds) {
        return Err(AppError::validation("连接超时必须为 5～60 秒"));
    }
    emit_progress(
        &app,
        &operation_id,
        SessionStatus::HostKeyCheck,
        "正在获取服务器指纹",
    );
    let cancellation = operations.register(operation_id.clone())?;
    let known_hosts_path = known_hosts_path(&app)?;
    let result = tokio::select! {
        result = ssh_client::inspect_host_key(
            &host,
            port,
            time::Duration::from_secs(timeout_seconds),
            known_hosts_path,
            proxy.as_ref(),
        ) => result,
        _ = cancellation => Err(AppError::cancelled()),
    };
    operations.finish(&operation_id)?;
    result
}

#[tauri::command]
async fn inspect_saved_ssh_host_key(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    store: State<'_, assets::AssetStore>,
    operation_id: String,
    connection_id: String,
    temporary_secret: Option<String>,
    keepalive: Option<KeepaliveSettings>,
) -> Result<HostKeyInspection, AppError> {
    let request =
        prepare_saved_connection(&app, &store, &connection_id, temporary_secret, keepalive)?;
    emit_progress(
        &app,
        &operation_id,
        SessionStatus::HostKeyCheck,
        "正在验证网络路径并获取目标指纹",
    );
    let cancellation = operations.register(operation_id.clone())?;
    let result = tokio::select! {
        result = ssh_client::inspect_route_host_key(
            app.clone(), operation_id.clone(), request, known_hosts_path(&app)?,
        ) => result,
        _ = cancellation => Err(AppError::cancelled()),
    };
    operations.finish(&operation_id)?;
    result
}

#[tauri::command]
async fn test_ssh_connection(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    operation_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
) -> Result<ConnectionTestResult, AppError> {
    emit_progress(
        &app,
        &operation_id,
        SessionStatus::Connecting,
        "正在建立 SSH 连接",
    );
    emit_progress(
        &app,
        &operation_id,
        SessionStatus::Authenticating,
        "正在验证认证信息",
    );
    let cancellation = operations.register(operation_id.clone())?;
    let known_hosts_path = known_hosts_path(&app)?;
    let result = tokio::select! {
        result = ssh_client::test_connection(
            app.clone(),
            operation_id.clone(),
            request,
            approval,
            known_hosts_path,
        ) => result,
        _ = cancellation => Err(AppError::cancelled()),
    };
    operations.finish(&operation_id)?;
    if result.is_err() {
        emit_progress(&app, &operation_id, SessionStatus::Failed, "连接测试失败");
    }
    result
}

#[tauri::command]
async fn connect_ssh(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    operation_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
) -> Result<SessionState, AppError> {
    connect_ssh_with_pool_key(app, operations, operation_id, request, approval, None).await
}

async fn connect_ssh_with_pool_key(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    operation_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    pool_key: Option<String>,
) -> Result<SessionState, AppError> {
    let setup_timeout = connection_setup_timeout(&request);
    emit_progress(
        &app,
        &operation_id,
        SessionStatus::Connecting,
        "正在建立 SSH 连接",
    );
    emit_progress(
        &app,
        &operation_id,
        SessionStatus::Authenticating,
        "正在认证并创建远程 Shell",
    );
    let cancellation = operations.register(operation_id.clone())?;
    let known_hosts_path = known_hosts_path(&app)?;
    let result = tokio::select! {
        result = time::timeout(
            setup_timeout,
            async {
                match pool_key {
                    Some(pool_key) => ssh_client::start_pooled_session(
                        app.clone(), operation_id.clone(), request, approval, known_hosts_path, pool_key,
                    ).await,
                    None => ssh_client::start_session(
                        app.clone(), operation_id.clone(), request, approval, known_hosts_path,
                    ).await,
                }
            },
        ) => result.map_err(|_| AppError::ssh(
            "CONNECTION-TIMEOUT",
            "连接超时，请检查主机、端口和防火墙",
            "SSH session setup exceeded the configured timeout",
            true,
        ))?,
        _ = cancellation => Err(AppError::cancelled()),
    };
    operations.finish(&operation_id)?;
    if result.is_err() {
        emit_progress(
            &app,
            &operation_id,
            SessionStatus::Failed,
            "SSH 会话建立失败",
        );
    }
    result
}

#[tauri::command]
async fn test_saved_connection(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    store: State<'_, assets::AssetStore>,
    operation_id: String,
    request: SavedSessionRequest,
) -> Result<ConnectionTestResult, AppError> {
    let connection = prepare_saved_connection(
        &app,
        &store,
        &request.connection_id,
        request.temporary_secret,
        request.keepalive,
    )?;
    test_ssh_connection(app, operations, operation_id, connection, request.approval).await
}

#[tauri::command]
async fn connect_saved_connection(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    store: State<'_, assets::AssetStore>,
    operation_id: String,
    request: SavedSessionRequest,
) -> Result<SessionState, AppError> {
    let connection = prepare_saved_connection(
        &app,
        &store,
        &request.connection_id,
        request.temporary_secret,
        request.keepalive,
    )?;
    let pool_key = saved_pool_key(
        &request.connection_id,
        &connection,
        &request.approval.fingerprint_sha256,
    );
    let session = connect_ssh_with_pool_key(
        app.clone(),
        operations,
        operation_id,
        connection,
        request.approval,
        Some(pool_key),
    )
    .await?;
    for tunnel in store.automatic_tunnels(&request.connection_id)? {
        if let Err(error) = app
            .state::<SessionRegistry>()
            .start_tunnel(&session.id, tunnel)
            .await
        {
            log::warn!(
                "automatic tunnel start failed: {}: {}",
                error.code,
                error.message
            );
        }
    }
    if let Err(error) = store.mark_connected(&request.connection_id) {
        log::warn!("failed to update last-connected timestamp: {}", error.code);
    }
    Ok(session)
}

#[tauri::command]
async fn reconnect_ssh(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    operation_id: String,
    session_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
) -> Result<SessionState, AppError> {
    reconnect_ssh_with_pool_key(
        app,
        operations,
        operation_id,
        session_id,
        request,
        approval,
        None,
    )
    .await
}

async fn reconnect_ssh_with_pool_key(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    operation_id: String,
    session_id: String,
    request: ConnectionRequest,
    approval: HostKeyApproval,
    pool_key: Option<String>,
) -> Result<SessionState, AppError> {
    let setup_timeout = connection_setup_timeout(&request);
    emit_progress(
        &app,
        &operation_id,
        SessionStatus::Connecting,
        "正在建立新的 SSH 会话",
    );
    let cancellation = operations.register(operation_id.clone())?;
    let known_hosts_path = known_hosts_path(&app)?;
    let result = tokio::select! {
        result = time::timeout(
            setup_timeout,
            async {
                match pool_key {
                    Some(pool_key) => ssh_client::reconnect_pooled_session(
                        app.clone(), operation_id.clone(), request, approval, known_hosts_path,
                        session_id, pool_key,
                    ).await,
                    None => ssh_client::reconnect_session(
                        app.clone(), operation_id.clone(), request, approval, known_hosts_path,
                        session_id,
                    ).await,
                }
            },
        ) => result.map_err(|_| AppError::ssh(
            "CONNECTION-TIMEOUT",
            "重新连接超时，请检查网络和服务器状态",
            "SSH reconnect setup exceeded the configured timeout",
            true,
        ))?,
        _ = cancellation => Err(AppError::cancelled()),
    };
    operations.finish(&operation_id)?;
    if result.is_err() {
        emit_progress(&app, &operation_id, SessionStatus::Failed, "重新连接失败");
    }
    result
}

#[tauri::command]
async fn reconnect_saved_connection(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    store: State<'_, assets::AssetStore>,
    operation_id: String,
    request: ReconnectSavedSessionRequest,
) -> Result<SessionState, AppError> {
    let connection = prepare_saved_connection(
        &app,
        &store,
        &request.connection_id,
        request.temporary_secret,
        request.keepalive,
    )?;
    let pool_key = saved_pool_key(
        &request.connection_id,
        &connection,
        &request.approval.fingerprint_sha256,
    );
    let session = reconnect_ssh_with_pool_key(
        app,
        operations,
        operation_id,
        request.session_id,
        connection,
        request.approval,
        Some(pool_key),
    )
    .await?;
    if let Err(error) = store.mark_connected(&request.connection_id) {
        log::warn!("failed to update last-connected timestamp: {}", error.code);
    }
    Ok(session)
}

fn apply_keepalive(request: &mut ConnectionRequest, settings: Option<KeepaliveSettings>) {
    if let Some(settings) = settings {
        request.keepalive_enabled = settings.enabled;
        request.keepalive_seconds = settings.seconds;
    }
}

fn prepare_saved_connection(
    app: &AppHandle,
    store: &assets::AssetStore,
    connection_id: &str,
    temporary_secret: Option<String>,
    keepalive: Option<KeepaliveSettings>,
) -> Result<ConnectionRequest, AppError> {
    let mut route = store.connection_route_requests(connection_id, temporary_secret)?;
    let mut target = route
        .pop()
        .ok_or_else(|| AppError::asset_not_found("connection", connection_id))?;
    let trusted = known_hosts::KnownHostsStore::new(known_hosts_path(app)?)
        .list()?
        .into_iter()
        .map(|record| ((record.host, record.port), record.fingerprint_sha256))
        .collect::<std::collections::HashMap<_, _>>();
    let mut jump_hosts = Vec::with_capacity(route.len());
    for mut connection in route {
        apply_keepalive(&mut connection, keepalive);
        let expected_fingerprint = trusted
            .get(&(connection.host.clone(), connection.port))
            .cloned()
            .ok_or_else(|| {
                AppError::ssh(
                    "JUMP-HOST-FAILED",
                    format!("请先单独连接并信任跳板“{}”的服务器指纹", connection.name),
                    format!(
                        "jump host {}:{} has no trusted host key",
                        connection.host, connection.port
                    ),
                    false,
                )
            })?;
        jump_hosts.push(JumpHostRequest {
            connection,
            expected_fingerprint,
        });
    }
    apply_keepalive(&mut target, keepalive);
    target.jump_hosts = jump_hosts;
    Ok(target)
}

fn saved_pool_key(
    connection_id: &str,
    request: &ConnectionRequest,
    target_fingerprint: &str,
) -> String {
    use std::fmt::Write as _;

    let mut key = format!("saved:{connection_id}:target-key={target_fingerprint}");
    for jump in &request.jump_hosts {
        append_connection_pool_key(&mut key, &jump.connection);
        let _ = write!(key, ":host-key={}", jump.expected_fingerprint);
    }
    append_connection_pool_key(&mut key, request);
    key
}

fn append_connection_pool_key(key: &mut String, request: &ConnectionRequest) {
    use std::fmt::Write as _;

    let _ = write!(
        key,
        ":{}:{}:{}:{:?}:{:?}:{}:{}",
        request.host,
        request.port,
        request.username,
        request.auth_type,
        request.proxy.as_ref().map(|proxy| (
            proxy.proxy_type,
            proxy.host.as_str(),
            proxy.port,
            proxy.username.as_deref()
        )),
        request.keepalive_enabled,
        request.keepalive_seconds,
    );
}

fn connection_setup_timeout(request: &ConnectionRequest) -> time::Duration {
    std::iter::once(request)
        .chain(request.jump_hosts.iter().map(|jump| &jump.connection))
        .map(|connection| match connection.auth_type {
            models::AuthType::KeyboardInteractive => time::Duration::from_secs(150),
            _ => time::Duration::from_secs(connection.timeout_seconds),
        })
        .sum()
}

#[tauri::command]
fn respond_authentication_prompt(
    broker: State<'_, authentication::AuthenticationBroker>,
    response: AuthenticationPromptResponse,
) -> Result<(), AppError> {
    broker.respond(response)
}

#[tauri::command]
async fn list_ssh_agent_identities() -> Result<Vec<AgentIdentityInfo>, AppError> {
    ssh_client::list_agent_identities().await
}

#[tauri::command]
fn cancel_operation(
    operations: State<'_, OperationRegistry>,
    authentication: State<'_, authentication::AuthenticationBroker>,
    operation_id: String,
) -> Result<(), AppError> {
    authentication.cancel_operation(&operation_id)?;
    operations.cancel(&operation_id)
}

fn known_hosts_path(app: &AppHandle) -> Result<std::path::PathBuf, AppError> {
    app.path()
        .app_data_dir()
        .map(|path| path.join("known_hosts.json"))
        .map_err(|error| AppError::storage("无法确定服务器指纹存储位置", error.to_string()))
}

fn emit_progress(app: &AppHandle, operation_id: &str, status: SessionStatus, message: &str) {
    let _ = app.emit(
        CONNECTION_PROGRESS_EVENT,
        ConnectionProgressPayload {
            operation_id: operation_id.to_owned(),
            status,
            message: message.to_owned(),
        },
    );
}

fn emit_output(app: &AppHandle, session_id: &str, data: Vec<u8>) -> Result<(), AppError> {
    app.emit(
        SESSION_OUTPUT_EVENT,
        SessionOutputPayload {
            session_id: session_id.to_owned(),
            data,
        },
    )
    .map_err(|error| AppError::event_delivery_failed(SESSION_OUTPUT_EVENT, error))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(SessionRegistry::default())
        .manage(connection_pool::ConnectionPool::default())
        .manage(tunnel::TunnelRegistry::default())
        .manage(OperationRegistry::default())
        .manage(authentication::AuthenticationBroker::default())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let asset_path = data_dir.join("connections.json");
            app.manage(assets::AssetStore::new(
                asset_path,
                credentials::system_vault(),
            ));
            app.manage(settings::SettingsStore::new(data_dir.join("settings.json")));
            let diagnostics = diagnostics::DiagnosticLog::new(data_dir.join("logs"));
            diagnostics.record(
                "application-start",
                None,
                &format!(
                    "version={} platform={}",
                    env!("CARGO_PKG_VERSION"),
                    std::env::consts::OS
                ),
            );
            app.manage(diagnostics);
            if let Some(state) = app.state::<settings::SettingsStore>().load_window() {
                if let Some(window) = app.get_webview_window("main") {
                    let visible = window.available_monitors()?.iter().any(|monitor| {
                        let position = monitor.position();
                        let size = monitor.size();
                        state.x < position.x + size.width as i32
                            && state.y < position.y + size.height as i32
                            && state.x + state.width as i32 > position.x
                            && state.y + state.height as i32 > position.y
                    });
                    if visible {
                        let _ = window.set_position(tauri::PhysicalPosition::new(state.x, state.y));
                        let _ =
                            window.set_size(tauri::PhysicalSize::new(state.width, state.height));
                        if state.maximized {
                            let _ = window.maximize();
                        }
                    }
                }
            }
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            load_settings,
            save_settings,
            save_window_state,
            diagnostics_path,
            clear_diagnostics,
            export_diagnostics,
            list_connection_assets,
            save_connection_profile,
            copy_connection_profile,
            delete_connection_profile,
            save_tunnel_profile,
            copy_tunnel_profile,
            delete_tunnel_profile,
            list_runtime_tunnels,
            start_tunnel,
            stop_tunnel,
            save_connection_group,
            delete_connection_group,
            record_recent_target,
            clear_recent_targets,
            export_connection_assets,
            import_connection_assets,
            list_host_keys,
            delete_host_key,
            clear_host_keys,
            create_mock_session,
            write_mock_session,
            resize_mock_session,
            close_mock_session,
            write_session,
            resize_session,
            close_session,
            list_remote_directory,
            create_remote_directory,
            rename_remote_entry,
            delete_remote_entry,
            start_transfer,
            cancel_transfer,
            inspect_ssh_host_key,
            inspect_saved_ssh_host_key,
            test_ssh_connection,
            connect_ssh,
            test_saved_connection,
            connect_saved_connection,
            reconnect_ssh,
            reconnect_saved_connection,
            respond_authentication_prompt,
            list_ssh_agent_identities,
            cancel_operation,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build TerminalT application");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            match tauri::async_runtime::block_on(
                app_handle
                    .state::<tunnel::TunnelRegistry>()
                    .stop_all_bounded(time::Duration::from_secs(2)),
            ) {
                Ok(true) => {}
                Ok(false) => log::warn!("tunnel shutdown exceeded the 2 second deadline"),
                Err(error) => log::error!("{}: {}", error.code, error.message),
            }
            match tauri::async_runtime::block_on(
                app_handle
                    .state::<SessionRegistry>()
                    .close_all_bounded(time::Duration::from_secs(2)),
            ) {
                Ok(true) => {}
                Ok(false) => log::warn!("session shutdown exceeded the 2 second deadline"),
                Err(error) => log::error!("{}: {}", error.code, error.message),
            }
            if let Err(error) = app_handle.state::<OperationRegistry>().cancel_all() {
                log::error!("{}: {}", error.code, error.message);
            }
            match tauri::async_runtime::block_on(
                app_handle
                    .state::<connection_pool::ConnectionPool>()
                    .shutdown_all_bounded(time::Duration::from_secs(2)),
            ) {
                Ok(true) => {}
                Ok(false) => log::warn!("connection pool shutdown exceeded the 2 second deadline"),
                Err(error) => log::error!("{}: {}", error.code, error.message),
            }
        }
    });
}

#[cfg(test)]
mod sftp_validation_tests {
    use super::{validate_remote_name, validate_remote_path};

    #[test]
    fn remote_names_reject_path_components() {
        assert!(validate_remote_name("日志 2026").is_ok());
        assert!(validate_remote_name("../secret").is_err());
        assert!(validate_remote_name("a\\b").is_err());
        assert!(validate_remote_name("..").is_err());
    }

    #[test]
    fn mutating_operations_require_absolute_remote_paths() {
        assert!(validate_remote_path("/home/user").is_ok());
        assert!(validate_remote_path("relative/path").is_err());
        assert!(validate_remote_path("/bad\0path").is_err());
    }
}
