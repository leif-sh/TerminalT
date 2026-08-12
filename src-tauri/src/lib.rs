mod error;
mod models;
mod session;

use chrono::Utc;
use error::AppError;
use models::{
    HealthResponse, SessionOutputPayload, SessionState, SessionStatus, SessionStatusPayload,
};
use session::SessionRegistry;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::{sync::oneshot, time};
use uuid::Uuid;

const IPC_PROTOCOL_VERSION: u16 = 1;
const SESSION_OUTPUT_EVENT: &str = "session-output";
const SESSION_STATUS_EVENT: &str = "session-status";

#[tauri::command]
fn health_check() -> HealthResponse {
    HealthResponse {
        status: "ok",
        protocol_version: IPC_PROTOCOL_VERSION,
        app_version: env!("CARGO_PKG_VERSION"),
    }
}

#[tauri::command]
fn create_mock_session(
    app: AppHandle,
    registry: State<'_, SessionRegistry>,
) -> Result<SessionState, AppError> {
    let session_id = Uuid::new_v4().to_string();
    let started_at = Utc::now().to_rfc3339();
    let (cancellation, cancellation_receiver) = oneshot::channel();
    registry.insert(session_id.clone(), cancellation)?;

    let task_session_id = session_id.clone();
    let task_app = app.clone();
    tauri::async_runtime::spawn(async move {
        run_mock_session(task_app, task_session_id, cancellation_receiver).await;
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
fn resize_mock_session(
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
        .setup(|app| {
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
            create_mock_session,
            write_mock_session,
            resize_mock_session,
            close_mock_session,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build TerminalT application");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            if let Err(error) = app_handle.state::<SessionRegistry>().close_all() {
                log::error!("{}: {}", error.code, error.message);
            }
        }
    });
}
