mod assets;
mod credentials;
mod error;
mod known_hosts;
mod models;
mod session;
mod ssh_client;

use chrono::Utc;
use error::AppError;
use models::{
    ConnectionAssetSnapshot, ConnectionGroup, ConnectionProfile, ConnectionProgressPayload,
    ConnectionRequest, ConnectionTestResult, GroupNameRequest, HealthResponse, HostKeyApproval,
    HostKeyInspection, KeepaliveSettings, ReconnectSavedSessionRequest, SaveConnectionRequest,
    SavedSessionRequest, SessionOutputPayload, SessionState, SessionStatus, SessionStatusPayload,
};
use session::{OperationRegistry, SessionCommand, SessionRegistry};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::{sync::oneshot, time};
use uuid::Uuid;

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
fn list_host_keys(app: AppHandle) -> Result<Vec<known_hosts::HostKeyRecord>, AppError> {
    known_hosts::KnownHostsStore::new(known_hosts_path(&app)?).list()
}

#[tauri::command]
fn delete_host_key(app: AppHandle, host: String, port: u16) -> Result<(), AppError> {
    known_hosts::KnownHostsStore::new(known_hosts_path(&app)?).delete(&host, port)
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
async fn inspect_ssh_host_key(
    app: AppHandle,
    operations: State<'_, OperationRegistry>,
    operation_id: String,
    host: String,
    port: u16,
    timeout_seconds: u64,
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
        result = ssh_client::test_connection(request, approval, known_hosts_path) => result,
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
    let setup_timeout = time::Duration::from_secs(request.timeout_seconds);
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
            ssh_client::start_session(app.clone(), request, approval, known_hosts_path),
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
    let mut connection =
        store.connection_request(&request.connection_id, request.temporary_secret)?;
    apply_keepalive(&mut connection, request.keepalive);
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
    let mut connection =
        store.connection_request(&request.connection_id, request.temporary_secret)?;
    apply_keepalive(&mut connection, request.keepalive);
    let session = connect_ssh(app, operations, operation_id, connection, request.approval).await?;
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
    let setup_timeout = time::Duration::from_secs(request.timeout_seconds);
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
            ssh_client::reconnect_session(
                app.clone(),
                request,
                approval,
                known_hosts_path,
                session_id,
            ),
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
    let mut connection =
        store.connection_request(&request.connection_id, request.temporary_secret)?;
    apply_keepalive(&mut connection, request.keepalive);
    let session = reconnect_ssh(
        app,
        operations,
        operation_id,
        request.session_id,
        connection,
        request.approval,
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

#[tauri::command]
fn cancel_operation(
    operations: State<'_, OperationRegistry>,
    operation_id: String,
) -> Result<(), AppError> {
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
        .manage(OperationRegistry::default())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let asset_path = app.path().app_data_dir()?.join("connections.json");
            app.manage(assets::AssetStore::new(
                asset_path,
                credentials::system_vault(),
            ));
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
            list_connection_assets,
            save_connection_profile,
            copy_connection_profile,
            delete_connection_profile,
            save_connection_group,
            delete_connection_group,
            record_recent_target,
            clear_recent_targets,
            list_host_keys,
            delete_host_key,
            create_mock_session,
            write_mock_session,
            resize_mock_session,
            close_mock_session,
            write_session,
            resize_session,
            close_session,
            inspect_ssh_host_key,
            test_ssh_connection,
            connect_ssh,
            test_saved_connection,
            connect_saved_connection,
            reconnect_ssh,
            reconnect_saved_connection,
            cancel_operation,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build TerminalT application");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
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
        }
    });
}
