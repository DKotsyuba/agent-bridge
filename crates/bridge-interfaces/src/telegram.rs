//! Outbound-only owner notification channel (Telegram).
//!
//! Sends plain-text `sendMessage` requests to the one configured owner
//! destination and nothing else. There is no incoming path in this module:
//! no getUpdates, no webhook, no commands, no replies, no approval
//! handling — none of that code exists.
//!
//! Failure classification is the point of this file:
//! - [`SendOutcome::Sent`] means the provider accepted the message. That is
//!   provider acceptance, explicitly not proof that the owner read it.
//! - [`SendOutcome::KnownRefusal`] is a positively established
//!   non-acceptance (definitive 4xx, including rate limits). Only this
//!   class may ever feed a bounded automatic retry policy elsewhere.
//! - [`SendOutcome::PossibleSend`] covers timeouts and connection failures
//!   after the request may have been written: the message may have been
//!   delivered. This class never authorizes an automatic retry and never
//!   hardens into "unsent" without new positive evidence.
//! - An unconfigured channel reports [`SendOutcome::Unconfigured`] and any
//!   dependent incident stays open: "no configured channel" must never
//!   imply the owner was notified.
//!
//! Credentials live in a protected file outside this code's control and are
//! never logged, never copied into incidents and never echoed in errors.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::operator::{IncidentInput, IncidentStore};

/// Configuration for the outbound owner channel, usually from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    /// Whether the channel is configured and may be used at all.
    ///
    /// `false` (or a missing/unreadable token file) makes every send
    /// report [`SendOutcome::Unconfigured`]/[`SendOutcome::Misconfigured`]
    /// without any network attempt.
    #[serde(default)]
    pub enabled: bool,
    /// Path of the protected file holding the bot token (0600).
    pub bot_token_file: PathBuf,
    /// The one fixed destination chat id; never caller-supplied.
    pub chat_id: String,
    /// API host base, default `api.telegram.org`.
    #[serde(default = "default_api_base")]
    pub api_base: String,
    /// Per-request timeout in seconds; elapsed time past this is a
    /// possible-send, not a known refusal.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

/// Default Telegram API host.
fn default_api_base() -> String {
    "api.telegram.org".to_string()
}

/// Default per-request timeout in seconds.
const fn default_timeout_secs() -> u64 {
    15
}

/// The classified outcome of one outbound send attempt.
///
/// The distinction between `KnownRefusal` and `PossibleSend` is a contract
/// obligation: collapsing them (treating ambiguity as refusal, or refusal
/// as ambiguity) is a boundary violation, not a formatting choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SendOutcome {
    /// Provider accepted the message (not proof of reading).
    Sent {
        /// Provider-assigned message id, when parsed from the response.
        message_id: Option<i64>,
    },
    /// Positively known non-acceptance; the only retry-eligible class.
    KnownRefusal {
        /// Safe-for-logging refusal detail (no token, no URL).
        detail: String,
        /// Rate-limit retry hint from the provider, in milliseconds.
        retry_after_ms: Option<u64>,
    },
    /// The request may have been written; delivery is unknown.
    PossibleSend {
        /// Safe-for-logging ambiguity detail.
        detail: String,
    },
    /// The channel is not configured; nothing was attempted.
    Unconfigured,
    /// Configured but unusable (for example a missing token file).
    Misconfigured {
        /// Safe-for-logging configuration problem.
        detail: String,
    },
}

impl SendOutcome {
    /// Whether this outcome positively establishes non-acceptance.
    ///
    /// Only `KnownRefusal` does; `PossibleSend` and `Sent` never claim it.
    pub fn is_known_refusal(&self) -> bool {
        matches!(self, SendOutcome::KnownRefusal { .. })
    }

    /// Whether this outcome is a failure that must stay visible.
    ///
    /// Everything except `Sent` keeps any dependent incident open.
    pub fn is_failure(&self) -> bool {
        !matches!(self, SendOutcome::Sent { .. })
    }
}

/// One raw transport reply, before classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportReply {
    /// The server answered with this HTTP status and body.
    Responded {
        /// HTTP status code.
        status: u16,
        /// Response body text, bounded by the transport.
        body: String,
    },
    /// The request timed out after the request may have been written.
    TimedOut,
    /// The connection failed; treated conservatively as possible-send.
    ConnectFailed {
        /// Safe-for-logging connection failure detail.
        detail: String,
    },
}

/// The outbound transport used for `sendMessage`.
///
/// Implementations must send exactly the request they are given and report
/// honestly; tests use scripted fixtures, the real deployment uses
/// [`CurlTransport`].
pub trait Transport {
    /// Posts one JSON body to an HTTPS URL and reports the raw reply.
    ///
    /// Never retries: one call, one honest reply.
    fn post_json(&self, url: &str, body: &str, timeout: Duration) -> TransportReply;
}

/// Real transport: one `curl` invocation per send, no retries.
///
/// Uses the system `curl` binary so the workspace needs no HTTP client
/// dependency. The URL contains the bot token, so callers must log the
/// method and chat id only, never the URL. Live qualification requires
/// owner-provided configuration and an explicitly authorized test delivery;
/// none has occurred.
#[derive(Debug, Clone)]
pub struct CurlTransport;

impl Transport for CurlTransport {
    /// Runs `curl -sS --max-time <t> -X POST` with the JSON body on stdin
    /// and `-w` to append the HTTP status as the final output line.
    ///
    /// Exit 0 maps to [`TransportReply::Responded`] with the parsed
    /// status; a timeout exit (28) maps to [`TransportReply::TimedOut`];
    /// anything else is a conservative
    /// [`TransportReply::ConnectFailed`].
    fn post_json(&self, url: &str, body: &str, timeout: Duration) -> TransportReply {
        let output = std::process::Command::new("curl")
            .arg("-sS")
            .arg("--max-time")
            .arg(timeout.as_secs().to_string())
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("content-type: application/json")
            .arg("--data-binary")
            .arg("@-")
            .arg("-w")
            .arg("\n%{http_code}")
            .arg(url)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(body.as_bytes())?;
                }
                child.wait_with_output()
            });
        match output {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout).into_owned();
                let (body, status) = match text.rfind('\n') {
                    Some(index) => (
                        text[..index].to_string(),
                        text[index + 1..].trim().parse::<u16>().unwrap_or(0),
                    ),
                    None => (text.clone(), 0),
                };
                TransportReply::Responded { status, body }
            }
            Ok(output) if output.status.code() == Some(28) => TransportReply::TimedOut,
            Ok(output) => TransportReply::ConnectFailed {
                detail: format!(
                    "curl exited {:?}: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            },
            Err(error) => TransportReply::ConnectFailed {
                detail: format!("curl spawn failed: {error}"),
            },
        }
    }
}

/// A scripted transport for isolated tests and fixtures.
///
/// Replies are consumed in order; an exhausted script answers
/// [`TransportReply::TimedOut`] (the conservative class). Recorded requests
/// are visible for assertions. Not thread-safe by design: test fixtures
/// drive it strictly sequentially.
#[derive(Debug)]
pub struct FixtureTransport {
    replies: std::cell::RefCell<std::collections::VecDeque<TransportReply>>,
    /// URLs of every request seen, for assertions (tests use fake tokens).
    pub seen_urls: std::cell::RefCell<Vec<String>>,
    /// Bodies of every request seen, for assertions.
    pub seen_bodies: std::cell::RefCell<Vec<String>>,
}

impl FixtureTransport {
    /// Builds a fixture with the given scripted replies.
    pub fn new(replies: Vec<TransportReply>) -> Self {
        FixtureTransport {
            replies: std::cell::RefCell::new(replies.into()),
            seen_urls: std::cell::RefCell::new(Vec::new()),
            seen_bodies: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// How many sends this fixture performed.
    pub fn send_count(&self) -> usize {
        self.seen_urls.borrow().len()
    }
}

impl Transport for FixtureTransport {
    /// Records the request and returns the next scripted reply.
    fn post_json(&self, url: &str, body: &str, _timeout: Duration) -> TransportReply {
        self.seen_urls.borrow_mut().push(url.to_string());
        self.seen_bodies.borrow_mut().push(body.to_string());
        self.replies
            .borrow_mut()
            .pop_front()
            .unwrap_or(TransportReply::TimedOut)
    }
}

/// Reads the bot token from its protected file.
///
/// Trims trailing whitespace/newlines. Errors name the file path without
/// ever including file content.
fn read_token(config: &TelegramConfig) -> Result<String, SendOutcome> {
    match std::fs::read_to_string(&config.bot_token_file) {
        Ok(token) => Ok(token.trim().to_string()),
        Err(error) => Err(SendOutcome::Misconfigured {
            detail: format!(
                "cannot read bot token file {}: {error}",
                config.bot_token_file.display()
            ),
        }),
    }
}

/// Builds the exact `sendMessage` request URL for a token.
///
/// The only URL this module can produce: the fixed API host, the token
/// path segment and `sendMessage`. No other Telegram method exists here.
pub fn send_message_url(config: &TelegramConfig, token: &str) -> String {
    format!("https://{}/bot{}/sendMessage", config.api_base, token)
}

/// Builds the exact plain-text `sendMessage` JSON body.
///
/// Only `chat_id` and `text`: no `parse_mode`, no reply targeting, no
/// harness delivery mode — Telegram inputs carry none.
pub fn send_message_body(config: &TelegramConfig, text: &str) -> String {
    serde_json::json!({"chat_id": config.chat_id, "text": text}).to_string()
}

/// Classifies one raw transport reply into a send outcome.
///
/// Mapping rules:
/// - HTTP 200 with `ok: true` and a `result.message_id` → `Sent`.
/// - HTTP 200 with `ok: true` but no message id → `Sent` with `None`
///   (acceptance parsed, id absent — still acceptance, still not reading).
/// - Any response with `ok: false` and a definitive 4xx status →
///   `KnownRefusal` (429 extracts `parameters.retry_after`).
/// - HTTP 5xx → `PossibleSend`: the server errored after possibly
///   processing the request; that is ambiguity, not refusal.
/// - Timeout/connection failure → `PossibleSend`.
pub fn classify(reply: TransportReply) -> SendOutcome {
    match reply {
        TransportReply::TimedOut => SendOutcome::PossibleSend {
            detail: "request timed out after the request may have been written".to_string(),
        },
        TransportReply::ConnectFailed { detail } => SendOutcome::PossibleSend {
            detail: format!("connection failed (possible send): {detail}"),
        },
        TransportReply::Responded { status, body } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(
                serde_json::Value::Object(Default::default()),
            );
            let ok = parsed.get("ok").and_then(|ok| ok.as_bool());
            if ok == Some(true) {
                let message_id = parsed
                    .pointer("/result/message_id")
                    .and_then(|id| id.as_i64());
                return SendOutcome::Sent { message_id };
            }
            let description = parsed
                .get("description")
                .and_then(|value| value.as_str())
                .unwrap_or("provider refused without description")
                .to_string();
            if (400..500).contains(&status) {
                let retry_after_ms = parsed
                    .pointer("/parameters/retry_after")
                    .and_then(|value| value.as_u64())
                    .map(|seconds| seconds * 1000);
                return SendOutcome::KnownRefusal {
                    detail: format!("http {status}: {description}"),
                    retry_after_ms,
                };
            }
            SendOutcome::PossibleSend {
                detail: format!("http {status} after possible processing: {description}"),
            }
        }
    }
}

/// Sends one owner notification and classifies the result.
///
/// Exactly one transport attempt; no retry, no fallback channel. The
/// caller is responsible for what the outcome means for its incident.
pub fn send_once(
    config: &TelegramConfig,
    transport: &dyn Transport,
    text: &str,
) -> SendOutcome {
    if !config.enabled {
        return SendOutcome::Unconfigured;
    }
    let token = match read_token(config) {
        Ok(token) => token,
        Err(outcome) => return outcome,
    };
    if config.chat_id.is_empty() {
        return SendOutcome::Misconfigured {
            detail: "configured chat id is empty".to_string(),
        };
    }
    let url = send_message_url(config, &token);
    let body = send_message_body(config, text);
    // Log method and destination only; the URL carries the token.
    bridge_core::service::log_event(
        "info",
        "telegram_send",
        &[("method", "sendMessage"), ("chat_id", &config.chat_id)],
    );
    classify(transport.post_json(&url, &body, Duration::from_secs(config.timeout_secs)))
}

/// The full owner-notification flow: send once, then keep the truth durable.
///
/// On any failure class, an incident is recorded (or idempotently
/// refreshed) in the operator store so the failure stays visible even
/// though the owner channel is the thing that failed; an unconfigured
/// channel records nothing new here but also never claims notification.
/// This function never resends the original uncertain event and never
/// retries: one report text, one attempt, one honest record.
pub fn notify_owner(
    store: &mut IncidentStore,
    config: &TelegramConfig,
    transport: &dyn Transport,
    report_text: &str,
    incident_ref: Option<(&str, &str, &str)>,
) -> (SendOutcome, Option<i64>) {
    let outcome = send_once(config, transport, report_text);
    let incident_id = match (&outcome, incident_ref) {
        // Channel fine: no incident about the channel itself.
        (SendOutcome::Sent { .. }, _) => None,
        // Unconfigured: nothing new to record about a channel that is
        // absent; callers keep their own incident visible regardless.
        (SendOutcome::Unconfigured, _) => None,
        // Real channel failure: retain a visible, classified incident.
        (outcome, Some((publisher, event_id, envelope_hash))) => {
            let reason = match outcome {
                SendOutcome::KnownRefusal { .. } => "owner_channel_known_refusal",
                SendOutcome::PossibleSend { .. } => "owner_channel_possible_send",
                SendOutcome::Misconfigured { .. } => "owner_channel_misconfigured",
                SendOutcome::Sent { .. } | SendOutcome::Unconfigured => unreachable!(),
            };
            let detail = match outcome {
                SendOutcome::KnownRefusal { detail, .. }
                | SendOutcome::PossibleSend { detail }
                | SendOutcome::Misconfigured { detail } => detail.clone(),
                _ => String::new(),
            };
            let input = IncidentInput {
                publisher: publisher.to_string(),
                event_id: event_id.to_string(),
                envelope_hash: envelope_hash.to_string(),
                source: "telegram".to_string(),
                reason: reason.to_string(),
                detail,
                next_action: "review the owner channel incident; no automatic retry exists"
                    .to_string(),
                review_deadline_ms: None,
                blocked_dependents: Vec::new(),
            };
            match store.record(&input, current_unix_millis()) {
                Ok(incident) => Some(incident.id),
                Err(error) => {
                    bridge_core::service::log_event(
                        "error",
                        "owner_channel_incident_record_failed",
                        &[("error", &error)],
                    );
                    None
                }
            }
        }
        (outcome, None) => {
            bridge_core::service::log_event(
                "warn",
                "owner_channel_failed_without_ref",
                &[("outcome", &serde_json::to_string(outcome).unwrap_or_default())],
            );
            None
        }
    };
    (outcome, incident_id)
}

/// Current wall clock in Unix epoch milliseconds.
fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}
