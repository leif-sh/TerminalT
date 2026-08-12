use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub code: &'static str,
    pub category: &'static str,
    pub message: String,
    pub technical_details: Option<String>,
    pub retryable: bool,
}

impl AppError {
    pub fn session_not_found(session_id: &str) -> Self {
        Self {
            code: "SESSION-NOT-FOUND",
            category: "session",
            message: "会话不存在或已经关闭".to_owned(),
            technical_details: Some(format!("session id {session_id} is not registered")),
            retryable: false,
        }
    }

    pub fn session_registry_unavailable() -> Self {
        Self {
            code: "SESSION-REGISTRY-UNAVAILABLE",
            category: "internal",
            message: "会话服务暂时不可用".to_owned(),
            technical_details: Some("session registry lock was poisoned".to_owned()),
            retryable: true,
        }
    }

    pub fn event_delivery_failed(event: &'static str, details: impl ToString) -> Self {
        Self {
            code: "IPC-EVENT-DELIVERY-FAILED",
            category: "ipc",
            message: "终端数据未能发送到界面".to_owned(),
            technical_details: Some(format!("failed to emit {event}: {}", details.to_string())),
            retryable: true,
        }
    }
}
