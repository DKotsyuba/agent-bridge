//! Outbound-only owner channel: one Telegram `sendMessage` call.
//!
//! The only request this module can build is `POST
//! https://api.telegram.org/bot<token>/sendMessage` with `{"chat_id",
//! "text"}` for the one configured chat: plain text (no `parse_mode`), no
//! reply targeting, no harness delivery mode. The origin is the fixed
//! [`crate::config::TELEGRAM_API`]; [`send`] re-checks the whole
//! configuration ([`TelegramConfig::check`]) before reading the token, so a
//! hand-built configuration cannot forward the token elsewhere. There is no
//! incoming path — no `getUpdates`, webhook, command, reply or approval code
//! exists.
//!
//! Credentials: the bot token is read from a protected file
//! ([`crate::config::read_secret`]) and handed to `curl` only through its
//! standard input as a config file, never in argv (visible to other
//! processes). Every transport observation is redacted against the token
//! (verbatim, with `:` percent-encoded, and its secret part after `:`)
//! *before* any classification, truncation or detail is built — and, for a
//! JSON answer, again on every decoded string, so a token hidden behind JSON
//! escapes still cannot reach an outcome, ledger or log.
//!
//! Outcome classes are kept strictly apart ([`SendOutcome`]): provider
//! acceptance (not proof that anyone read it), known refusal (an HTTP 4xx
//! answer), known-unsent (provably no request left this host) and possible
//! send (anything after the request may have started). Only the two known
//! non-acceptance classes may ever be retried, and only by
//! [`crate::notify`]'s bounded policy; this module itself never retries.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{TELEGRAM_API, TelegramConfig, read_secret};

/// Largest accepted provider answer, in bytes.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Largest kept transport diagnostic (curl stderr), in bytes.
const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;

/// Largest accepted bot token, in bytes.
const MAX_TOKEN_BYTES: usize = 128;

/// Largest notification text Telegram accepts, in characters.
pub const MAX_TEXT_CHARS: usize = 4096;

/// Replacement text for a redacted credential.
const REDACTED: &str = "<redacted>";

/// The classified result of one send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SendOutcome {
    /// The provider accepted the message. Not proof of reading.
    ProviderAccepted {
        /// Provider message id when present.
        message_id: Option<i64>,
    },
    /// The provider answered with a definitive refusal (HTTP 4xx).
    KnownRefusal {
        /// Redacted detail (status and provider description).
        detail: String,
        /// Provider rate-limit hint, in milliseconds.
        retry_after_ms: Option<u64>,
    },
    /// Provably nothing was sent (pre-effect failure).
    KnownUnsent {
        /// Redacted detail.
        detail: String,
    },
    /// The request may have reached the provider; outcome unknown. Never
    /// retried automatically.
    PossibleSend {
        /// Redacted detail.
        detail: String,
    },
}

/// What the transport observed, before redaction and classification.
///
/// Untrusted: every text may contain anything the provider or transport
/// echoed, including the token. [`send`] redacts it before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportReply {
    /// An HTTP answer arrived.
    Responded {
        /// HTTP status (0 when unreadable).
        status: u16,
        /// Bounded answer body.
        body: String,
    },
    /// The request provably never left this host.
    NotSent(String),
    /// The request may have been sent; no usable answer.
    Uncertain(String),
}

/// One outbound HTTPS POST, at most once per call.
pub trait Transport {
    /// Posts `body` (JSON) to `url` within `timeout`; never retries.
    ///
    /// `url` contains the token: implementations must not log it. A reply
    /// may only be `NotSent` when the implementation positively knows that
    /// no byte of the request could have reached the network.
    fn post(&self, url: &str, body: &str, timeout: Duration) -> TransportReply;
}

/// The production transport: the system `curl`, configured through stdin.
#[derive(Debug, Clone)]
pub struct CurlTransport {
    /// The curl executable.
    curl: PathBuf,
    /// Test-only fault and stub hooks; absent from production builds.
    #[cfg(test)]
    hooks: TestHooks,
}

/// Test-only behaviour of [`CurlTransport`].
#[cfg(test)]
#[derive(Debug, Clone, Default)]
struct TestHooks {
    /// Rewrites the fixed origin to a local plain-HTTP stub origin.
    stub_origin: Option<String>,
    /// Makes the config writer fail after writing all but this many bytes.
    withhold_tail: Option<usize>,
}

impl Default for CurlTransport {
    /// `/usr/bin/curl`.
    fn default() -> Self {
        CurlTransport {
            curl: PathBuf::from("/usr/bin/curl"),
            #[cfg(test)]
            hooks: TestHooks::default(),
        }
    }
}

impl CurlTransport {
    /// The argv (without the executable) for one request: no URL, no token,
    /// no body — those travel on stdin.
    ///
    /// `--disable` ignores `~/.curlrc`; `--noproxy *` (with a cleared
    /// environment) forbids proxies; only `https`; no redirects; bounded
    /// total time and reply size.
    pub fn args(&self, timeout: Duration) -> Vec<String> {
        #[cfg(test)]
        let proto = if self.hooks.stub_origin.is_some() {
            "=https,http"
        } else {
            "=https"
        };
        #[cfg(not(test))]
        let proto = "=https";
        [
            "--disable",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--proto",
            proto,
            "--max-redirs",
            "0",
            "--max-time",
            &format!("{:.3}", timeout.as_secs_f64()),
            "--max-filesize",
            &MAX_REPLY_BYTES.to_string(),
            "--request",
            "POST",
            "--write-out",
            "\n%{http_code}",
            "--config",
            "-",
        ]
        .iter()
        .map(ToString::to_string)
        .collect()
    }

    /// Writes the request config to curl's stdin (test builds may inject a
    /// failure after a partial write).
    fn write_config(&self, stdin: &mut dyn Write, config: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(tail) = self.hooks.withhold_tail {
            stdin.write_all(&config[..config.len().saturating_sub(tail)])?;
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        stdin.write_all(config)
    }
}

/// Quotes a value for a curl config file (`\` and `"` escaped).
fn curl_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

impl Transport for CurlTransport {
    /// Runs curl once with header, body and — last — the URL in a stdin
    /// config, then waits for it.
    ///
    /// Classification: failure to start curl → `NotSent`. Once curl runs,
    /// any failure to deliver the whole config → `Uncertain` (curl may act
    /// on a partial config). With the whole config delivered: exit 0 parses
    /// the status trailer; exits 1, 2, 3, 6, 7, 35 and 60 (unsupported
    /// protocol, init/config, bad URL, DNS, TCP connect, TLS handshake,
    /// certificate) are failures before any request byte was sent for this
    /// single request with no proxy and no redirect → `NotSent`; every
    /// other exit (timeout 28, empty reply 52, send/receive 55/56, …) →
    /// `Uncertain`. curl's stderr (bounded) is kept as diagnostic text.
    fn post(&self, url: &str, body: &str, timeout: Duration) -> TransportReply {
        #[cfg(test)]
        let rewritten = match &self.hooks.stub_origin {
            Some(origin) => url.replacen(TELEGRAM_API, origin, 1),
            None => url.to_string(),
        };
        #[cfg(test)]
        let url = rewritten.as_str();
        let config = format!(
            "header = \"content-type: application/json\"\ndata-binary = {}\nurl = {}\n",
            curl_quote(body),
            curl_quote(url)
        );
        let child = Command::new(&self.curl)
            .args(self.args(timeout))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => return TransportReply::NotSent(format!("curl did not start: {error}")),
        };
        let delivered = match child.stdin.take() {
            Some(mut stdin) => self.write_config(&mut stdin, config.as_bytes()),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        };
        let mut stdout = Vec::new();
        if let Some(out) = child.stdout.take() {
            let _ = out
                .take(MAX_REPLY_BYTES as u64 + 16)
                .read_to_end(&mut stdout);
        }
        let mut stderr = Vec::new();
        if let Some(err) = child.stderr.take() {
            let _ = err
                .take(MAX_DIAGNOSTIC_BYTES as u64)
                .read_to_end(&mut stderr);
        }
        let status = child.wait();
        let diagnostic = String::from_utf8_lossy(&stderr).trim().to_string();
        if let Err(error) = delivered {
            return TransportReply::Uncertain(format!(
                "request config delivery failed after curl started ({error}); curl may have acted on part of it: {diagnostic}"
            ));
        }
        let status = match status {
            Ok(status) => status,
            Err(error) => return TransportReply::Uncertain(format!("curl wait failed: {error}")),
        };
        match status.code() {
            Some(0) => {
                let text = String::from_utf8_lossy(&stdout);
                let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
                TransportReply::Responded {
                    status: code.trim().parse().unwrap_or(0),
                    body: body.to_string(),
                }
            }
            Some(code @ (1 | 2 | 3 | 6 | 7 | 35 | 60)) => TransportReply::NotSent(format!(
                "curl exit {code} before any request was sent: {diagnostic}"
            )),
            other => TransportReply::Uncertain(format!(
                "curl exit {other:?} after the request may have been sent: {diagnostic}"
            )),
        }
    }
}

/// Replaces every form of `token` in `text`: verbatim, with `:` percent-
/// encoded (either case), and its secret part after the first `:`.
///
/// Full forms are replaced before the secret part, so no fragment of a
/// whole token survives; callers must redact before truncating.
pub fn redact(text: &str, token: &str) -> String {
    let mut forms = vec![
        token.to_string(),
        token.replace(':', "%3A"),
        token.replace(':', "%3a"),
    ];
    if let Some((_, secret)) = token.split_once(':')
        && !secret.is_empty()
    {
        forms.push(secret.to_string());
    }
    forms
        .iter()
        .fold(text.to_string(), |text, form| text.replace(form, REDACTED))
}

/// Redacts every string (and object key) of a decoded JSON value in place.
fn redact_json(value: &mut Value, token: &str) {
    match value {
        Value::String(text) => *text = redact(text, token),
        Value::Array(items) => items.iter_mut().for_each(|item| redact_json(item, token)),
        Value::Object(map) => {
            *map = std::mem::take(map)
                .into_iter()
                .map(|(key, mut item)| {
                    redact_json(&mut item, token);
                    (redact(&key, token), item)
                })
                .collect();
        }
        _ => {}
    }
}

/// Redacts every untrusted text of a transport reply.
///
/// An answer body is redacted as raw text and, when it is JSON, again after
/// decoding: a JSON string escape (`:`, `T`, …) can hide a token
/// from the raw text yet decode to it in a provider description.
fn redact_reply(reply: TransportReply, token: &str) -> TransportReply {
    match reply {
        TransportReply::Responded { status, body } => {
            let body = redact(&body, token);
            let body = match serde_json::from_str::<Value>(&body) {
                Ok(mut parsed) => {
                    redact_json(&mut parsed, token);
                    parsed.to_string()
                }
                Err(_) => body,
            };
            TransportReply::Responded { status, body }
        }
        TransportReply::NotSent(detail) => TransportReply::NotSent(redact(&detail, token)),
        TransportReply::Uncertain(detail) => TransportReply::Uncertain(redact(&detail, token)),
    }
}

/// Classifies an (already redacted) transport observation.
///
/// HTTP 2xx with `"ok": true` is provider acceptance; any other 2xx, a
/// 5xx or an unreadable status is a possible send; 4xx is a known refusal
/// (429 carries `parameters.retry_after`). Descriptions and diagnostics
/// are cut to 200 characters.
pub fn classify(reply: TransportReply) -> SendOutcome {
    let cut = |text: &str| text.chars().take(200).collect::<String>();
    match reply {
        TransportReply::NotSent(detail) => SendOutcome::KnownUnsent {
            detail: cut(&detail),
        },
        TransportReply::Uncertain(detail) => SendOutcome::PossibleSend {
            detail: cut(&detail),
        },
        TransportReply::Responded { status, body } => {
            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let description = cut(parsed
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("no description"));
            match status {
                200..=299 if parsed.get("ok") == Some(&Value::Bool(true)) => {
                    SendOutcome::ProviderAccepted {
                        message_id: parsed.pointer("/result/message_id").and_then(Value::as_i64),
                    }
                }
                400..=499 => SendOutcome::KnownRefusal {
                    detail: format!("http {status}: {description}"),
                    retry_after_ms: parsed
                        .pointer("/parameters/retry_after")
                        .and_then(Value::as_u64)
                        .map(|seconds| seconds.saturating_mul(1000)),
                },
                _ => SendOutcome::PossibleSend {
                    detail: format!("http {status} without a definitive answer: {description}"),
                },
            }
        }
    }
}

/// Sends one plain-text message to the configured owner chat.
///
/// Known-unsent, with no request, when: `config` is absent
/// ("unconfigured"); it fails [`TelegramConfig::check`] (checked before
/// the token is read); the token file is not protected or empty; or the
/// token is longer than 128 bytes or holds characters outside
/// `[A-Za-z0-9:_-]`. Otherwise exactly one transport call; its reply is
/// redacted against the token before classification. `text` is cut to
/// [`MAX_TEXT_CHARS`] characters.
pub fn send(config: Option<&TelegramConfig>, transport: &dyn Transport, text: &str) -> SendOutcome {
    let Some(config) = config else {
        return SendOutcome::KnownUnsent {
            detail: "owner channel unconfigured".into(),
        };
    };
    if let Err(detail) = config.check() {
        return SendOutcome::KnownUnsent { detail };
    }
    let token = match read_secret(&config.token_file) {
        Ok(token) => token,
        Err(detail) => return SendOutcome::KnownUnsent { detail },
    };
    if token.len() > MAX_TOKEN_BYTES
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_-".contains(&byte))
    {
        return SendOutcome::KnownUnsent {
            detail: "bot token file holds an unexpected value".into(),
        };
    }
    let text: String = text.chars().take(MAX_TEXT_CHARS).collect();
    let url = format!("{TELEGRAM_API}/bot{token}/sendMessage");
    let body = json!({"chat_id": config.chat_id, "text": text}).to_string();
    let reply = transport.post(&url, &body, Duration::from_millis(config.timeout_ms));
    classify(redact_reply(reply, &token))
}

#[cfg(test)]
mod tests {
    //! Classification over a real curl process against a local HTTP stub.
    //! The stub origin is substituted only inside the test transport; the
    //! production configuration contract (fixed official origin) is
    //! unchanged. No network, no real bot, no real token.

    use super::*;
    use crate::testdir::TestDir;
    use std::io::BufRead;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

    /// Fake token used only against the local stub.
    const TOKEN: &str = "123456:TEST-token_value";

    /// A test transport aimed at the stub on `port`.
    fn transport(port: u16) -> CurlTransport {
        CurlTransport {
            hooks: TestHooks {
                stub_origin: Some(format!("http://127.0.0.1:{port}")),
                withhold_tail: None,
            },
            ..CurlTransport::default()
        }
    }

    /// What the stub does with one request.
    enum Stub {
        /// Answer this status and body.
        Answer(u16, String),
        /// Read the request, then close without answering.
        Close,
        /// Read the request, then stay silent past the client deadline.
        Silent,
    }

    /// Serves at most one request on a fresh port for up to 5 s; returns
    /// the port and a handle yielding the request line and body (`None`
    /// when no request arrived).
    fn stub(mode: Stub) -> (u16, std::thread::JoinHandle<Option<(String, String)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return None,
                }
            };
            stream.set_nonblocking(false).unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).ok()?;
            let mut length = 0;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).ok()? == 0 {
                    return Some((request_line, String::new()));
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                if header == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).ok()?;
            let mut stream = stream;
            match mode {
                Stub::Answer(status, text) => {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                        text.len()
                    );
                }
                Stub::Close => drop(stream),
                Stub::Silent => std::thread::sleep(Duration::from_millis(2500)),
            }
            Some((request_line, String::from_utf8(body).unwrap()))
        });
        (port, handle)
    }

    /// A valid configuration with a protected token file in `dir`.
    fn config(dir: &TestDir) -> TelegramConfig {
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, TOKEN).unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        TelegramConfig {
            token_file,
            chat_id: "4242".into(),
            api_base: TELEGRAM_API.into(),
            timeout_ms: 1000,
        }
    }

    /// Sends through a stub and returns the outcome and the observed request.
    fn exchange(mode: Stub) -> (SendOutcome, Option<(String, String)>) {
        let dir = TestDir::new("tg");
        let (port, handle) = stub(mode);
        let outcome = send(Some(&config(&dir)), &transport(port), "incident #1");
        (outcome, handle.join().unwrap())
    }

    /// A successful provider answer is reported only as acceptance, with the
    /// message id, over the fixed request shape.
    #[test]
    fn provider_acceptance_is_only_acceptance() {
        let (outcome, request) = exchange(Stub::Answer(
            200,
            r#"{"ok":true,"result":{"message_id":7}}"#.into(),
        ));
        assert_eq!(
            outcome,
            SendOutcome::ProviderAccepted {
                message_id: Some(7)
            }
        );
        let (line, body) = request.unwrap();
        assert!(line.starts_with(&format!("POST /bot{TOKEN}/sendMessage ")));
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body, json!({"chat_id": "4242", "text": "incident #1"}));
    }

    /// Client errors are known refusals (with the rate-limit delay), while server
    /// errors and `ok:false` on success are possible sends.
    #[test]
    fn refusals_rate_limits_and_server_errors_are_classified() {
        let (refused, _) = exchange(Stub::Answer(
            400,
            r#"{"ok":false,"description":"chat not found"}"#.into(),
        ));
        assert!(matches!(
            refused,
            SendOutcome::KnownRefusal {
                retry_after_ms: None,
                ..
            }
        ));
        let (limited, _) = exchange(Stub::Answer(
            429,
            r#"{"ok":false,"description":"slow down","parameters":{"retry_after":3}}"#.into(),
        ));
        assert!(matches!(
            limited,
            SendOutcome::KnownRefusal {
                retry_after_ms: Some(3000),
                ..
            }
        ));
        let (server, _) = exchange(Stub::Answer(502, "bad gateway".into()));
        assert!(matches!(server, SendOutcome::PossibleSend { .. }));
        let (odd, _) = exchange(Stub::Answer(200, r#"{"ok":false}"#.into()));
        assert!(matches!(odd, SendOutcome::PossibleSend { .. }));
    }

    /// Provider text echoing the token in any form is redacted from the outcome
    /// detail.
    #[test]
    fn provider_echo_of_the_token_never_reaches_the_outcome() {
        let secret = TOKEN.split_once(':').unwrap().1;
        // The verbatim token straddles the 200-character cut; the encoded
        // form and the bare secret part follow.
        let description = format!(
            "{}{TOKEN} url=/bot{} secret={secret}",
            "x".repeat(190),
            TOKEN.replace(':', "%3A")
        );
        let (outcome, _) = exchange(Stub::Answer(
            400,
            json!({"ok": false, "description": description}).to_string(),
        ));
        let SendOutcome::KnownRefusal { detail, .. } = outcome else {
            panic!("unexpected {outcome:?}");
        };
        for fragment in [&TOKEN[..9], &secret[..6], "%3ATEST"] {
            assert!(!detail.contains(fragment), "{fragment:?} leaked: {detail}");
        }
        let short = format!(
            "bad {TOKEN} or %3a form {} or {secret}",
            TOKEN.replace(':', "%3a")
        );
        let (outcome, _) = exchange(Stub::Answer(
            401,
            json!({"ok": false, "description": short}).to_string(),
        ));
        let rendered = serde_json::to_string(&outcome).unwrap();
        assert!(!rendered.contains(secret), "{rendered}");
        assert!(rendered.contains(REDACTED), "{rendered}");
    }

    /// A transport that echoes the token through its non-HTTP replies.
    struct Echo(bool);

    impl Transport for Echo {
        /// Echoes the URL (which holds the token) as a diagnostic.
        fn post(&self, url: &str, _body: &str, _timeout: Duration) -> TransportReply {
            if self.0 {
                TransportReply::NotSent(format!("refused {url}"))
            } else {
                TransportReply::Uncertain(format!("lost {url}"))
            }
        }
    }

    /// Transport diagnostics never expose the token.
    #[test]
    fn transport_diagnostics_are_redacted() {
        let dir = TestDir::new("tgecho");
        for not_sent in [true, false] {
            let outcome = send(Some(&config(&dir)), &Echo(not_sent), "x");
            let rendered = serde_json::to_string(&outcome).unwrap();
            assert!(!rendered.contains("TEST-token"), "{rendered}");
        }
    }

    /// A closed connection or no answer after the request is a possible send.
    #[test]
    fn lost_and_silent_answers_are_possible_sends() {
        let (lost, _) = exchange(Stub::Close);
        assert!(matches!(lost, SendOutcome::PossibleSend { .. }), "{lost:?}");
        let (silent, _) = exchange(Stub::Silent);
        assert!(
            matches!(silent, SendOutcome::PossibleSend { .. }),
            "{silent:?}"
        );
    }

    /// If the request configuration is only partly delivered to curl, the request
    /// may still go out, so the outcome is a possible send.
    #[test]
    fn partial_config_delivery_is_a_possible_send() {
        let dir = TestDir::new("tgpart");
        let (port, handle) = stub(Stub::Answer(
            200,
            r#"{"ok":true,"result":{"message_id":9}}"#.into(),
        ));
        let mut transport = transport(port);
        // Everything but the final newline reaches the real curl process,
        // which may still act on it: the request can go out.
        transport.hooks.withhold_tail = Some(1);
        let outcome = send(Some(&config(&dir)), &transport, "x");
        let received = handle.join().unwrap();
        assert!(
            matches!(outcome, SendOutcome::PossibleSend { .. }),
            "{outcome:?} (stub received a request: {})",
            received.is_some()
        );
    }

    /// A refused connection is known-unsent, and invalid configuration never
    /// reaches the transport.
    #[test]
    fn refused_connection_and_invalid_config_are_known_unsent_before_effect() {
        let dir = TestDir::new("tgunsent");
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let config = config(&dir);
        let outcome = send(Some(&config), &transport(port), "x");
        assert!(
            matches!(outcome, SendOutcome::KnownUnsent { .. }),
            "{outcome:?}"
        );
        /// Counts calls; must never be reached.
        struct Never(std::cell::Cell<u32>);
        impl Transport for Never {
            /// Records an unexpected call.
            fn post(&self, _: &str, _: &str, _: Duration) -> TransportReply {
                self.0.set(self.0.get() + 1);
                TransportReply::Uncertain(String::new())
            }
        }
        let never = Never(std::cell::Cell::new(0));
        for bad in [
            TelegramConfig {
                api_base: "https://evil.example".into(),
                ..config.clone()
            },
            TelegramConfig {
                timeout_ms: 0,
                ..config.clone()
            },
            TelegramConfig {
                chat_id: "1\"\nurl = \"x".into(),
                ..config.clone()
            },
        ] {
            assert!(matches!(
                send(Some(&bad), &never, "x"),
                SendOutcome::KnownUnsent { .. }
            ));
        }
        std::fs::set_permissions(&config.token_file, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(matches!(
            send(Some(&config), &never, "x"),
            SendOutcome::KnownUnsent { .. }
        ));
        assert!(matches!(
            send(None, &never, "x"),
            SendOutcome::KnownUnsent { .. }
        ));
        assert_eq!(never.0.get(), 0, "no request for invalid configuration");
    }

    /// The curl arguments carry neither the token nor the bot path, and pin the
    /// https-only protocol with default config disabled.
    #[test]
    fn the_token_never_reaches_argv() {
        let args = CurlTransport::default().args(Duration::from_secs(5));
        assert!(
            args.iter()
                .all(|arg| !arg.contains("bot") && !arg.contains(':'))
        );
        assert!(args.contains(&"=https".to_string()));
        assert_eq!(args.first().map(String::as_str), Some("--disable"));
    }

    /// A transport answering one fixed raw HTTP body.
    struct Fixed(u16, String);

    impl Transport for Fixed {
        /// Answers the fixed status and body.
        fn post(&self, _url: &str, _body: &str, _timeout: Duration) -> TransportReply {
            TransportReply::Responded {
                status: self.0,
                body: self.1.clone(),
            }
        }
    }

    /// `text` with every character written as a JSON `\uXXXX` escape, so the
    /// raw body never holds any run of it verbatim.
    fn escape_all(text: &str) -> String {
        text.chars()
            .map(|character| format!("\\u{:04x}", character as u32))
            .collect()
    }

    /// A token echoed through JSON string escapes (so the raw body never holds
    /// it verbatim) is redacted from the decoded outcome detail too.
    #[test]
    fn json_escaped_token_echoes_are_redacted_after_decoding() {
        let dir = TestDir::new("tgjson");
        let secret = TOKEN.split_once(':').unwrap().1;
        for (status, echoed) in [
            (400, escape_all(TOKEN)),
            (
                401,
                format!("{} and {}", escape_all(secret), escape_all(TOKEN)),
            ),
            (200, escape_all(&TOKEN.replace(":", "%3A"))),
        ] {
            let body = format!(r#"{{"ok":false,"description":"bad {echoed} here"}}"#);
            let outcome = send(Some(&config(&dir)), &Fixed(status, body), "x");
            let rendered = serde_json::to_string(&outcome).unwrap();
            assert!(!rendered.contains(secret), "{status}: {rendered}");
            assert!(!rendered.contains("123456:"), "{status}: {rendered}");
        }
    }
}
