use std::{net::IpAddr, pin::Pin, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    models::{ProxyRequest, ProxyType},
};

const MAX_HTTP_RESPONSE_HEADER: usize = 16 * 1024;

pub trait NetworkStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> NetworkStream for T {}
pub type BoxedNetworkStream = Pin<Box<dyn NetworkStream + Send>>;

pub async fn connect_target(
    host: &str,
    port: u16,
    proxy: Option<&ProxyRequest>,
    timeout: Duration,
) -> Result<BoxedNetworkStream, AppError> {
    validate_target(host)?;
    let connection = async {
        match proxy {
            None => TcpStream::connect((host, port))
                .await
                .map(|stream| Box::pin(stream) as BoxedNetworkStream)
                .map_err(|error| proxy_connect_error("direct TCP connection failed", error)),
            Some(proxy) => {
                validate_proxy(proxy)?;
                let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
                    .await
                    .map_err(|error| proxy_connect_error("proxy TCP connection failed", error))?;
                match proxy.proxy_type {
                    ProxyType::Http => http_connect(&mut stream, host, port, proxy).await?,
                    ProxyType::Socks5 => socks5_connect(&mut stream, host, port, proxy).await?,
                }
                Ok(Box::pin(stream) as BoxedNetworkStream)
            }
        }
    };
    tokio::time::timeout(timeout, connection)
        .await
        .map_err(|_| {
            AppError::ssh(
                "PROXY-CONNECT-FAILED",
                "连接代理服务器超时",
                "proxy connection or handshake timed out",
                true,
            )
        })?
}

fn validate_target(host: &str) -> Result<(), AppError> {
    if host.trim().is_empty() || host.len() > 255 || host.contains(['\r', '\n', '\0']) {
        return Err(AppError::validation("目标主机地址无效"));
    }
    Ok(())
}

fn validate_proxy(proxy: &ProxyRequest) -> Result<(), AppError> {
    if proxy.host.trim().is_empty()
        || proxy.host.len() > 255
        || proxy.host.contains(['\r', '\n', '\0'])
    {
        return Err(AppError::validation("代理主机地址无效"));
    }
    if proxy.username.as_deref().is_some_and(|value| {
        value.is_empty() || value.len() > 255 || value.contains(['\r', '\n', '\0'])
    }) {
        return Err(AppError::validation("代理用户名无效"));
    }
    if proxy
        .password
        .as_deref()
        .is_some_and(|value| value.len() > 255 || value.contains(['\r', '\n', '\0']))
    {
        return Err(AppError::validation("代理密码无效"));
    }
    Ok(())
}

async fn http_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    proxy: &ProxyRequest,
) -> Result<(), AppError> {
    let authority = format_authority(host, port);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(username) = proxy.username.as_deref() {
        let password = Zeroizing::new(proxy.password.clone().unwrap_or_default());
        let credentials = Zeroizing::new(format!("{username}:{}", password.as_str()));
        let encoded = Zeroizing::new(base64_encode(credentials.as_bytes()));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(encoded.as_str());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| proxy_connect_error("failed to write HTTP CONNECT request", error))?;
    stream
        .flush()
        .await
        .map_err(|error| proxy_connect_error("failed to flush HTTP CONNECT request", error))?;

    let mut header = Vec::with_capacity(512);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HTTP_RESPONSE_HEADER {
            return Err(proxy_protocol_error(
                "HTTP CONNECT response header exceeded 16 KiB",
            ));
        }
        let byte = stream
            .read_u8()
            .await
            .map_err(|error| proxy_connect_error("failed to read HTTP CONNECT response", error))?;
        header.push(byte);
    }
    let status_line = std::str::from_utf8(&header)
        .ok()
        .and_then(|value| value.lines().next())
        .ok_or_else(|| proxy_protocol_error("HTTP CONNECT response was not valid UTF-8"))?;
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| proxy_protocol_error("HTTP CONNECT response had no valid status"))?;
    match status {
        200..=299 => Ok(()),
        407 => Err(AppError::ssh(
            "PROXY-AUTH-FAILED",
            "代理服务器拒绝了认证信息",
            "HTTP CONNECT returned status 407",
            true,
        )),
        _ => Err(AppError::ssh(
            "PROXY-CONNECT-FAILED",
            "代理服务器拒绝了目标连接",
            format!("HTTP CONNECT returned status {status}"),
            true,
        )),
    }
}

async fn socks5_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    proxy: &ProxyRequest,
) -> Result<(), AppError> {
    let authenticated = proxy.username.is_some();
    let methods: &[u8] = if authenticated {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    stream
        .write_all(methods)
        .await
        .map_err(|error| proxy_connect_error("failed to write SOCKS5 method negotiation", error))?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|error| proxy_connect_error("failed to read SOCKS5 method negotiation", error))?;
    if method[0] != 5 {
        return Err(proxy_protocol_error(
            "SOCKS5 server returned an invalid version",
        ));
    }
    match method[1] {
        0 => {}
        2 if authenticated => socks5_authenticate(stream, proxy).await?,
        0xff => {
            return Err(AppError::ssh(
                "PROXY-AUTH-FAILED",
                "代理服务器不接受当前认证方式",
                "SOCKS5 server rejected all authentication methods",
                true,
            ))
        }
        value => {
            return Err(proxy_protocol_error(format!(
                "SOCKS5 server selected unsupported method {value}"
            )))
        }
    }

    let mut request = vec![5, 1, 0];
    encode_socks_address(&mut request, host)?;
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| proxy_connect_error("failed to write SOCKS5 CONNECT request", error))?;
    let mut response = [0_u8; 4];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|error| proxy_connect_error("failed to read SOCKS5 CONNECT response", error))?;
    if response[0] != 5 || response[2] != 0 {
        return Err(proxy_protocol_error(
            "SOCKS5 CONNECT response header was invalid",
        ));
    }
    if response[1] != 0 {
        return Err(AppError::ssh(
            "PROXY-CONNECT-FAILED",
            "SOCKS5 代理无法连接目标服务器",
            format!("SOCKS5 CONNECT returned reply code {}", response[1]),
            true,
        ));
    }
    discard_socks_address(stream, response[3]).await
}

async fn socks5_authenticate(stream: &mut TcpStream, proxy: &ProxyRequest) -> Result<(), AppError> {
    let username = proxy.username.as_deref().unwrap_or_default().as_bytes();
    let password = Zeroizing::new(proxy.password.clone().unwrap_or_default());
    let password_bytes = password.as_bytes();
    let mut request = Vec::with_capacity(3 + username.len() + password_bytes.len());
    request.extend_from_slice(&[1, username.len() as u8]);
    request.extend_from_slice(username);
    request.push(password_bytes.len() as u8);
    request.extend_from_slice(password_bytes);
    stream.write_all(&request).await.map_err(|error| {
        proxy_connect_error("failed to write SOCKS5 authentication request", error)
    })?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await.map_err(|error| {
        proxy_connect_error("failed to read SOCKS5 authentication response", error)
    })?;
    if response == [1, 0] {
        Ok(())
    } else {
        Err(AppError::ssh(
            "PROXY-AUTH-FAILED",
            "SOCKS5 代理拒绝了认证信息",
            "SOCKS5 username/password authentication failed",
            true,
        ))
    }
}

fn encode_socks_address(buffer: &mut Vec<u8>, host: &str) -> Result<(), AppError> {
    if let Ok(address) = host.parse::<IpAddr>() {
        match address {
            IpAddr::V4(address) => {
                buffer.push(1);
                buffer.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                buffer.push(4);
                buffer.extend_from_slice(&address.octets());
            }
        }
    } else {
        if host.is_empty() || host.len() > 255 || host.contains('\0') {
            return Err(AppError::validation("代理目标主机地址无效"));
        }
        buffer.extend_from_slice(&[3, host.len() as u8]);
        buffer.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

async fn discard_socks_address(stream: &mut TcpStream, address_type: u8) -> Result<(), AppError> {
    let length = match address_type {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await.map_err(|error| {
            proxy_connect_error("failed to read SOCKS5 bound domain length", error)
        })? as usize,
        _ => {
            return Err(proxy_protocol_error(
                "SOCKS5 response used an invalid address type",
            ))
        }
    };
    let mut remaining = vec![0_u8; length + 2];
    stream
        .read_exact(&mut remaining)
        .await
        .map_err(|error| proxy_connect_error("failed to read SOCKS5 bound address", error))?;
    Ok(())
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn proxy_connect_error(context: &str, error: impl ToString) -> AppError {
    AppError::ssh(
        "PROXY-CONNECT-FAILED",
        "无法通过代理建立连接",
        format!("{context}: {}", error.to_string()),
        true,
    )
}

fn proxy_protocol_error(details: impl Into<String>) -> AppError {
    AppError::ssh(
        "PROXY-PROTOCOL-FAILED",
        "代理服务器返回了无效响应",
        details,
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{base64_encode, connect_target};
    use crate::models::{ProxyRequest, ProxyType};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn proxy(proxy_type: ProxyType, address: std::net::SocketAddr) -> ProxyRequest {
        ProxyRequest {
            proxy_type,
            host: address.ip().to_string(),
            port: address.port(),
            username: None,
            password: None,
        }
    }

    #[test]
    fn basic_credentials_use_rfc_4648_encoding() {
        assert_eq!(base64_encode(b"user:secret"), "dXNlcjpzZWNyZXQ=");
        assert_eq!(base64_encode(b"a:b"), "YTpi");
    }

    #[tokio::test]
    async fn target_rejects_http_header_injection_before_connecting() {
        let error = match connect_target(
            "example.test\r\nInjected: true",
            22,
            None,
            std::time::Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => panic!("header injection target was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "CONNECTION-INVALID");
    }

    #[tokio::test]
    async fn http_connect_accepts_success_and_sends_basic_auth() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                request.push(stream.read_u8().await.unwrap());
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT example.test:443 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        let mut config = proxy(ProxyType::Http, address);
        config.username = Some("user".to_owned());
        config.password = Some("secret".to_owned());
        connect_target(
            "example.test",
            443,
            Some(&config),
            std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_maps_authentication_rejection() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut byte = [0_u8; 1];
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let error = connect_target(
            "example.test",
            443,
            Some(&proxy(ProxyType::Http, address)),
            std::time::Duration::from_secs(2),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.code, "PROXY-AUTH-FAILED");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_supports_authenticated_domain_connect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut methods = [0_u8; 4];
            stream.read_exact(&mut methods).await.unwrap();
            assert_eq!(methods, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0_u8; 13];
            stream.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x04user\x06secret");
            stream.write_all(&[1, 0]).await.unwrap();
            let mut request = [0_u8; 19];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..5], b"\x05\x01\x00\x03\x0c");
            assert_eq!(&request[5..17], b"example.test");
            assert_eq!(&request[17..], &443_u16.to_be_bytes());
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        let mut config = proxy(ProxyType::Socks5, address);
        config.username = Some("user".to_owned());
        config.password = Some("secret".to_owned());
        connect_target(
            "example.test",
            443,
            Some(&config),
            std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_rejects_invalid_protocol_version() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut methods = [0_u8; 3];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[4, 0]).await.unwrap();
        });
        let error = connect_target(
            "example.test",
            22,
            Some(&proxy(ProxyType::Socks5, address)),
            std::time::Duration::from_secs(2),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.code, "PROXY-PROTOCOL-FAILED");
    }
}
