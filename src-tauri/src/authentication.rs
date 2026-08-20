use std::{collections::HashMap, sync::Mutex};

use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::{AuthenticationPromptAnswer, AuthenticationPromptResponse},
};

struct PendingAuthentication {
    operation_id: String,
    answer_ids: Vec<String>,
    sender: oneshot::Sender<Vec<String>>,
}

#[derive(Default)]
pub struct AuthenticationBroker {
    pending: Mutex<HashMap<String, PendingAuthentication>>,
}

pub struct PendingPrompt<'a> {
    broker: &'a AuthenticationBroker,
    prompt_id: String,
    receiver: oneshot::Receiver<Vec<String>>,
}

impl AuthenticationBroker {
    pub fn register(
        &self,
        operation_id: &str,
        answer_ids: Vec<String>,
    ) -> Result<PendingPrompt<'_>, AppError> {
        let prompt_id = Uuid::new_v4().to_string();
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| broker_unavailable())?
            .insert(
                prompt_id.clone(),
                PendingAuthentication {
                    operation_id: operation_id.to_owned(),
                    answer_ids,
                    sender,
                },
            );
        Ok(PendingPrompt {
            broker: self,
            prompt_id,
            receiver,
        })
    }

    pub fn respond(&self, response: AuthenticationPromptResponse) -> Result<(), AppError> {
        let mut pending = self.pending.lock().map_err(|_| broker_unavailable())?;
        let entry = pending.get(&response.prompt_id).ok_or_else(stale_prompt)?;
        if entry.operation_id != response.operation_id
            || !answers_match(&entry.answer_ids, &response.answers)
        {
            return Err(stale_prompt());
        }
        let entry = pending
            .remove(&response.prompt_id)
            .ok_or_else(stale_prompt)?;
        let answers = response
            .answers
            .into_iter()
            .map(|answer| answer.value)
            .collect();
        entry.sender.send(answers).map_err(|_| stale_prompt())
    }

    pub fn cancel_operation(&self, operation_id: &str) -> Result<(), AppError> {
        self.pending
            .lock()
            .map_err(|_| broker_unavailable())?
            .retain(|_, entry| entry.operation_id != operation_id);
        Ok(())
    }

    fn remove(&self, prompt_id: &str) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(prompt_id);
        }
    }
}

impl PendingPrompt<'_> {
    pub fn prompt_id(&self) -> &str {
        &self.prompt_id
    }

    pub async fn wait(mut self) -> Result<Vec<String>, AppError> {
        let result = (&mut self.receiver)
            .await
            .map_err(|_| AppError::cancelled());
        self.broker.remove(&self.prompt_id);
        result
    }
}

impl Drop for PendingPrompt<'_> {
    fn drop(&mut self) {
        self.broker.remove(&self.prompt_id);
    }
}

fn answers_match(expected: &[String], answers: &[AuthenticationPromptAnswer]) -> bool {
    expected.len() == answers.len()
        && expected
            .iter()
            .zip(answers)
            .all(|(expected, answer)| expected == &answer.id)
}

fn stale_prompt() -> AppError {
    AppError::ssh(
        "AUTH-PROMPT-STALE",
        "认证请求已失效，请重新连接",
        "authentication prompt is missing, expired, or does not match the operation",
        true,
    )
}

fn broker_unavailable() -> AppError {
    AppError::ssh(
        "AUTH-BROKER-UNAVAILABLE",
        "认证服务暂时不可用",
        "authentication broker lock was poisoned",
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::AuthenticationBroker;
    use crate::models::{AuthenticationPromptAnswer, AuthenticationPromptResponse};

    #[tokio::test]
    async fn response_is_bound_to_operation_and_ordered_prompt_ids() {
        let broker = AuthenticationBroker::default();
        let pending = broker
            .register("operation-a", vec!["answer-0".to_owned()])
            .unwrap();
        let prompt_id = pending.prompt_id().to_owned();
        broker
            .respond(AuthenticationPromptResponse {
                operation_id: "operation-a".to_owned(),
                prompt_id,
                answers: vec![AuthenticationPromptAnswer {
                    id: "answer-0".to_owned(),
                    value: "one-time-secret".to_owned(),
                }],
            })
            .unwrap();
        assert_eq!(pending.wait().await.unwrap(), vec!["one-time-secret"]);
    }

    #[tokio::test]
    async fn cancellation_drops_pending_prompt() {
        let broker = AuthenticationBroker::default();
        let pending = broker.register("operation-a", Vec::new()).unwrap();
        let prompt_id = pending.prompt_id().to_owned();
        broker.cancel_operation("operation-a").unwrap();
        assert!(pending.wait().await.is_err());
        assert!(broker
            .respond(AuthenticationPromptResponse {
                operation_id: "operation-a".to_owned(),
                prompt_id,
                answers: Vec::new(),
            })
            .is_err());
    }

    #[tokio::test]
    async fn mismatched_response_cannot_invalidate_the_real_prompt() {
        let broker = AuthenticationBroker::default();
        let pending = broker
            .register("operation-a", vec!["answer-0".to_owned()])
            .unwrap();
        let prompt_id = pending.prompt_id().to_owned();
        assert!(broker
            .respond(AuthenticationPromptResponse {
                operation_id: "operation-b".to_owned(),
                prompt_id: prompt_id.clone(),
                answers: vec![AuthenticationPromptAnswer {
                    id: "answer-0".to_owned(),
                    value: "malicious".to_owned(),
                }],
            })
            .is_err());
        broker
            .respond(AuthenticationPromptResponse {
                operation_id: "operation-a".to_owned(),
                prompt_id,
                answers: vec![AuthenticationPromptAnswer {
                    id: "answer-0".to_owned(),
                    value: "valid".to_owned(),
                }],
            })
            .unwrap();
        assert_eq!(pending.wait().await.unwrap(), vec!["valid"]);
    }
}
