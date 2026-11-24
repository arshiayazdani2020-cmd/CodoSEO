//! Cloudflare Turnstile on the audit form (cloud only, and only when keys are configured).
//! The page loads Cloudflare's script, which adds a `cf-turnstile-response` field to the form;
//! the server checks that token with Cloudflare before starting any crawl.

use std::net::IpAddr;

use serde::Deserialize;

use crate::config::TurnstileConfig;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Turnstile isn't configured, or Cloudflare confirmed the token.
    Passed,
    /// No token, or Cloudflare rejected it.
    Failed,
    /// Cloudflare couldn't be asked. The form fails closed rather than let bots through.
    Unavailable,
}

#[derive(Deserialize)]
struct SiteVerify {
    success: bool,
}

pub async fn verify(state: &AppState, token: Option<&str>, ip: Option<IpAddr>) -> Verdict {
    verify_with(state.config.turnstile.as_ref(), &state.http, token, ip).await
}

async fn verify_with(
    config: Option<&TurnstileConfig>,
    http: &reqwest::Client,
    token: Option<&str>,
    ip: Option<IpAddr>,
) -> Verdict {
    let Some(cfg) = config else {
        return Verdict::Passed;
    };
    // Tokens are a few hundred bytes; refuse anything absurd without a round trip.
    let Some(token) = token
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= 2048)
    else {
        return Verdict::Failed;
    };
    let mut form = vec![
        ("secret", cfg.secret.clone()),
        ("response", token.to_owned()),
    ];
    if let Some(ip) = ip {
        form.push(("remoteip", ip.to_string()));
    }
    let response = http
        .post(cfg.verify_url.clone())
        .form(&form)
        .send()
        .await
        .and_then(|r| r.error_for_status());
    let body = match response {
        Ok(r) => r.json::<SiteVerify>().await,
        Err(e) => {
            tracing::warn!(error = %e, "turnstile verification unavailable");
            return Verdict::Unavailable;
        }
    };
    match body {
        Ok(v) if v.success => Verdict::Passed,
        Ok(_) => Verdict::Failed,
        Err(e) => {
            tracing::warn!(error = %e, "turnstile verification returned an unreadable answer");
            Verdict::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use url::Url;

    fn config(url: Url) -> TurnstileConfig {
        TurnstileConfig {
            site_key: "site-key".to_owned(),
            secret: "secret-key".to_owned(),
            verify_url: url,
        }
    }

    async fn fake_siteverify(
        status: &'static str,
        body: &'static str,
    ) -> (Url, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let expected_len = loop {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "client closed before sending the request");
                request.extend_from_slice(&chunk[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    break end + 4 + length;
                }
            };
            while request.len() < expected_len {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "client closed before sending the request body");
                request.extend_from_slice(&chunk[..n]);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        (
            Url::parse(&format!("http://{address}/siteverify")).unwrap(),
            task,
        )
    }

    #[tokio::test]
    async fn missing_turnstile_configuration_allows_without_a_token() {
        let http = reqwest::Client::new();
        assert_eq!(verify_with(None, &http, None, None).await, Verdict::Passed);
    }

    #[tokio::test]
    async fn missing_blank_and_oversized_tokens_are_rejected_before_network_access() {
        let http = reqwest::Client::new();
        let cfg = config(Url::parse("http://127.0.0.1:1/siteverify").unwrap());
        assert_eq!(
            verify_with(Some(&cfg), &http, None, None).await,
            Verdict::Failed
        );
        assert_eq!(
            verify_with(Some(&cfg), &http, Some("  "), None).await,
            Verdict::Failed
        );
        assert_eq!(
            verify_with(Some(&cfg), &http, Some(&"x".repeat(2049)), None).await,
            Verdict::Failed
        );
    }

    #[tokio::test]
    async fn successful_verification_sends_secret_token_and_optional_remote_ip() {
        let (url, server) = fake_siteverify("200 OK", r#"{"success":true}"#).await;
        let cfg = config(url);
        let http = reqwest::Client::new();
        let ip = "203.0.113.8".parse().unwrap();
        assert_eq!(
            verify_with(Some(&cfg), &http, Some("valid-token"), Some(ip)).await,
            Verdict::Passed
        );
        let request = server.await.unwrap();
        let body = request.split_once("\r\n\r\n").unwrap().1;
        assert!(body.contains("secret=secret-key"), "{body}");
        assert!(body.contains("response=valid-token"), "{body}");
        assert!(body.contains("remoteip=203.0.113.8"), "{body}");
    }

    #[tokio::test]
    async fn cloudflare_rejection_returns_failed() {
        let (url, server) = fake_siteverify("200 OK", r#"{"success":false}"#).await;
        let cfg = config(url);
        assert_eq!(
            verify_with(Some(&cfg), &reqwest::Client::new(), Some("bad-token"), None).await,
            Verdict::Failed
        );
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn http_errors_and_unreadable_responses_fail_closed_as_unavailable() {
        let (url, server) =
            fake_siteverify("503 Service Unavailable", r#"{"success":false}"#).await;
        let cfg = config(url);
        assert_eq!(
            verify_with(
                Some(&cfg),
                &reqwest::Client::new(),
                Some("valid-token"),
                None
            )
            .await,
            Verdict::Unavailable
        );
        let _ = server.await.unwrap();

        let (url, server) = fake_siteverify("200 OK", "not-json").await;
        let cfg = config(url);
        assert_eq!(
            verify_with(
                Some(&cfg),
                &reqwest::Client::new(),
                Some("valid-token"),
                None
            )
            .await,
            Verdict::Unavailable
        );
        let _ = server.await.unwrap();
    }
}
