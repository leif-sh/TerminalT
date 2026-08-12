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

    pub fn invalid_session_operation() -> Self {
        Self::new(
            "SESSION-INVALID-OPERATION",
            "session",
            "当前会话不支持该操作",
            None,
            false,
        )
    }

    pub fn session_command_failed(details: String) -> Self {
        Self::new(
            "SESSION-COMMAND-FAILED",
            "session",
            "无法向远端会话发送数据",
            Some(details),
            true,
        )
    }

    pub fn operation_registry_unavailable() -> Self {
        Self::new(
            "OPERATION-REGISTRY-UNAVAILABLE",
            "internal",
            "连接任务服务暂时不可用",
            None,
            true,
        )
    }

    pub fn cancelled() -> Self {
        Self::new("OPERATION-CANCELLED", "cancelled", "操作已取消", None, true)
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::new("CONNECTION-INVALID", "validation", message, None, false)
    }

    pub fn ssh(
        code: &'static str,
        message: impl Into<String>,
        details: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::new(code, "ssh", message, Some(details.into()), retryable)
    }

    pub fn storage(message: impl Into<String>, details: impl Into<String>) -> Self {
        Self::new(
            "HOST-KEY-STORAGE-FAILED",
            "storage",
            message,
            Some(details.into()),
            true,
        )
    }

    pub fn asset_storage(message: impl Into<String>, details: impl Into<String>) -> Self {
        Self::new(
            "ASSET-STORAGE-FAILED",
            "storage",
            message,
            Some(details.into()),
            true,
        )
    }

    pub fn credential(
        code: &'static str,
        message: impl Into<String>,
        details: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::new(code, "credential", message, Some(details.into()), retryable)
    }

    pub fn asset_not_found(kind: &'static str, id: &str) -> Self {
        Self::new(
            "ASSET-NOT-FOUND",
            "storage",
            "连接或分组不存在",
            Some(format!("{kind} id {id} was not found")),
            false,
        )
    }

    fn new(
        code: &'static str,
        category: &'static str,
        message: impl Into<String>,
        technical_details: Option<String>,
        retryable: bool,
    ) -> Self {
        Self {
            code,
            category,
            message: message.into(),
            technical_details,
            retryable,
        }
    }
}
