//! Credential isolation at the CLI process boundary, including proxy settings.

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[test]
fn invalid_api_urls_never_echo_credentials() {
    for url in [
        "postgres://alice:very-secret-password@host",
        "http://alice:very-secret-password@[invalid-ipv6",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dataglot"))
            .args(["ops", "--api", url, "status"])
            .env_remove("DATAGLOT_PROFILE")
            .output()
            .expect("run CLI");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).expect("UTF-8 error");
        assert!(error.contains("invalid API URL"), "{error}");
        assert!(!error.contains("very-secret-password"), "{error}");
        assert!(!error.contains("alice"), "{error}");
    }
}

/// Record one request and answer it without forwarding anything elsewhere.
fn answer_once(
    listener: TcpListener,
    label: &'static str,
    seen: mpsc::Sender<(&'static str, String)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept request");
        let mut request = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let len = socket.read(&mut chunk).await.expect("read request");
            if len == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..len]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 8192, "unexpectedly large request headers");
        }
        seen.send((label, String::from_utf8_lossy(&request).into_owned()))
            .await
            .expect("record request");
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .expect("answer request");
    })
}

#[tokio::test]
async fn loopback_bearer_requests_bypass_environment_proxies() {
    let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
    let proxy = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
    let api = format!("http://{}", origin.local_addr().expect("origin address"));
    let proxy_url = format!("http://{}", proxy.local_addr().expect("proxy address"));
    let (seen, mut requests) = mpsc::channel(2);
    let origin_task = answer_once(origin, "origin", seen.clone());
    let proxy_task = answer_once(proxy, "proxy", seen);

    // Isolate proxy/token environment changes in the child process so parallel
    // tests cannot affect the result or accidentally receive the test token.
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_dataglot"));
    command
        .args(["ops", "--api", &api, "status", "--format", "json"])
        .env_remove("DATAGLOT_PROFILE")
        .env_remove("REQUEST_METHOD")
        .env("DATAGLOT_API_TOKEN", "proxy-regression-token")
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .kill_on_drop(true);
    for key in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        command.env(key, &proxy_url);
    }
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .expect("CLI finished")
        .expect("run CLI");
    let (destination, request) = tokio::time::timeout(Duration::from_secs(1), requests.recv())
        .await
        .expect("received request")
        .expect("request recorded");
    origin_task.abort();
    proxy_task.abort();

    assert_eq!(
        destination, "origin",
        "the bearer request reached the proxy"
    );
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer proxy-regression-token"));
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 output"),
        "{}\n"
    );
}
