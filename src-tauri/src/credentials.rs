use std::sync::Arc;

use zeroize::Zeroizing;

use crate::error::AppError;

pub trait CredentialVault: Send + Sync {
    fn set(&self, reference: &str, secret: &str) -> Result<(), AppError>;
    fn get(&self, reference: &str) -> Result<Option<Zeroizing<String>>, AppError>;
    fn delete(&self, reference: &str) -> Result<(), AppError>;
}

pub fn system_vault() -> Arc<dyn CredentialVault> {
    Arc::new(SystemCredentialVault)
}

struct SystemCredentialVault;

#[cfg(windows)]
impl CredentialVault for SystemCredentialVault {
    fn set(&self, reference: &str, secret: &str) -> Result<(), AppError> {
        use std::ptr::null_mut;
        use windows_sys::Win32::Security::Credentials::{
            CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
        };

        let mut target = wide(reference);
        let mut username = wide("TerminalT");
        let secret_bytes = secret.as_bytes();
        let blob_size = u32::try_from(secret_bytes.len()).map_err(|_| {
            credential_error(
                "CREDENTIAL-TOO-LARGE",
                "凭据长度超出系统限制",
                "secret exceeds u32",
            )
        })?;
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: blob_size,
            CredentialBlob: secret_bytes.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: username.as_mut_ptr(),
            Attributes: null_mut(),
            ..Default::default()
        };
        let success = unsafe { CredWriteW(&credential, 0) };
        if success == 0 {
            return Err(last_error(
                "CREDENTIAL-WRITE-FAILED",
                "无法写入 Windows 凭据库",
            ));
        }
        Ok(())
    }

    fn get(&self, reference: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        use std::{ptr::null_mut, slice};
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_NOT_FOUND},
            Security::Credentials::{CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC},
        };

        let target = wide(reference);
        let mut pointer: *mut CREDENTIALW = null_mut();
        let success = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer) };
        if success == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NOT_FOUND {
                return Ok(None);
            }
            return Err(credential_error(
                "CREDENTIAL-READ-FAILED",
                "无法读取 Windows 凭据库",
                format!("CredReadW failed with Win32 error {code}"),
            ));
        }

        struct CredentialGuard(*mut CREDENTIALW);
        impl Drop for CredentialGuard {
            fn drop(&mut self) {
                unsafe { CredFree(self.0.cast()) };
            }
        }
        let guard = CredentialGuard(pointer);
        let credential = unsafe { &*guard.0 };
        let bytes = unsafe {
            slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            )
        };
        let secret = String::from_utf8(bytes.to_vec()).map_err(|error| {
            credential_error(
                "CREDENTIAL-DECODE-FAILED",
                "已保存的凭据无法读取，请重新输入",
                error.to_string(),
            )
        })?;
        Ok(Some(Zeroizing::new(secret)))
    }

    fn delete(&self, reference: &str) -> Result<(), AppError> {
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_NOT_FOUND},
            Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC},
        };
        let target = wide(reference);
        let success = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if success == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND {
                return Err(credential_error(
                    "CREDENTIAL-DELETE-FAILED",
                    "无法删除 Windows 凭据",
                    format!("CredDeleteW failed with Win32 error {code}"),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl CredentialVault for SystemCredentialVault {
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        Err(unavailable())
    }
    fn get(&self, _: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        Err(unavailable())
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        Err(unavailable())
    }
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn last_error(code: &'static str, message: &'static str) -> AppError {
    use windows_sys::Win32::Foundation::GetLastError;
    let error = unsafe { GetLastError() };
    credential_error(
        code,
        message,
        format!("Windows credential API error {error}"),
    )
}

fn credential_error(
    code: &'static str,
    message: &'static str,
    details: impl Into<String>,
) -> AppError {
    AppError::credential(code, message, details, true)
}

#[cfg(all(test, windows))]
mod tests {
    use super::{CredentialVault, SystemCredentialVault};

    #[test]
    #[ignore = "requires an interactive Windows logon session"]
    fn windows_credential_round_trip() {
        let vault = SystemCredentialVault;
        let reference = format!("TerminalT/test/{}", uuid::Uuid::new_v4());
        vault.set(&reference, "临时测试秘密").unwrap();
        let result = vault.get(&reference).unwrap();
        vault.delete(&reference).unwrap();
        assert_eq!(
            result.as_ref().map(|value| value.as_str()),
            Some("临时测试秘密")
        );
        assert!(vault.get(&reference).unwrap().is_none());
    }
}

#[cfg(not(windows))]
fn unavailable() -> AppError {
    credential_error(
        "CREDENTIAL-STORE-UNAVAILABLE",
        "当前系统不支持安全凭据存储，请仅本次输入",
        "Windows Credential Manager is unavailable on this platform",
    )
}
