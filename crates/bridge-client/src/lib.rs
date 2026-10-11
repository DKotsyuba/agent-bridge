//! Shared typed client for Agent Bridge family producers and operators.
//!
//! Agent Run, Agent IDE and Agent Worktree depend on this crate — not on
//! `bridge-core` internals — so the envelope model they build against stays
//! stable while the service evolves. The [`PublishRequest`] builder
//! validates and freezes an event; [`BridgeClient`] speaks the local
//! protocol: newline-delimited JSON over the daemon's Unix stream socket,
//! one response per request, with bounded reads and writes.
//!
//! Retries after a lost response resend the exact same event (same event id
//! and content): custody deduplication returns the original receipt, so a
//! retry never duplicates an event or restarts business work. A changed
//! body under the same event id is refused as a conflict by the service.
//! The client reconnects once on its own when an idle connection was closed
//! by the service, but only for requests that are safe to repeat.

pub use bridge_core::recovery::{EvidenceTier, HoldView, IncidentView};
pub use bridge_core::service::DeliveryEvidence;
pub use bridge_core::{
    CoreError, CustodyReceipt, Envelope, EnvelopeHash, EventId, ExpiresAt, Harness, Kind, Metadata,
    Mode, NativeAddress, Payload, Policy, PublisherId, SCHEMA_VERSION, StreamId,
};

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bridge_core::service::{PublishBody, Request, Response, Token};
use bridge_core::wire::{MAX_RESPONSE_BYTES, read_bounded_line, write_line};

/// How long a request write may block.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the first byte of a response (the service may wait
/// for a busy database before answering).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// A client's typed view of one protocol refusal or transport failure.
///
/// `class` mirrors the service's machine-readable classes: `auth`,
/// `forbidden`, `unsupported`, `invalid`, `conflict`, `capacity`, `held`,
/// `fence`, `busy`, `internal`; the client adds `transport` when the
/// connection failed before a response arrived (the request may or may not
/// have been processed — retry publish and status with the same body).
/// `detail` is safe-for-logging text without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    /// Machine-readable refusal class.
    pub class: String,
    /// Human-readable detail.
    pub detail: String,
}

impl ProtocolError {
    /// Builds a transport-class error.
    fn transport(detail: impl Into<String>) -> Self {
        ProtocolError {
            class: "transport".into(),
            detail: detail.into(),
        }
    }

    /// Builds an internal-class error for a response of the wrong shape.
    fn unexpected(operation: &str, response: &Response) -> Self {
        ProtocolError {
            class: "internal".into(),
            detail: format!("unexpected response to {operation}: {response:?}"),
        }
    }
}

impl std::fmt::Display for ProtocolError {
    /// Renders class and detail on one line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.class, self.detail)
    }
}

impl std::error::Error for ProtocolError {}

/// One open connection to the daemon.
#[derive(Debug)]
struct Connection {
    /// Write half.
    stream: UnixStream,
    /// Buffered read half.
    reader: BufReader<UnixStream>,
}

/// A connected client for one daemon socket.
///
/// One connection at a time, sequential requests; safe to reuse across
/// retries and idle periods (a closed idle connection is re-established
/// once per request when that is safe). Not `Sync`.
#[derive(Debug)]
pub struct BridgeClient {
    /// The daemon socket path, kept for reconnection.
    socket: PathBuf,
    /// The current connection, if any.
    connection: Option<Connection>,
}

impl BridgeClient {
    /// Connects to the daemon's socket.
    ///
    /// Fails with the underlying I/O error when no daemon is listening.
    pub fn connect(socket: impl AsRef<Path>) -> std::io::Result<Self> {
        let socket = socket.as_ref().to_path_buf();
        let connection = open(&socket)?;
        Ok(BridgeClient {
            socket,
            connection: Some(connection),
        })
    }

    /// Publishes (or idempotently replays) one event under the given grant.
    ///
    /// The grant token authenticates the publisher identity the service
    /// stamps; `body` must not (and cannot) carry a publisher. A lost
    /// response is retried by calling this again with the identical body.
    pub fn publish(
        &mut self,
        token: &str,
        body: &PublishBody,
    ) -> Result<CustodyReceipt, ProtocolError> {
        let request = Request::Publish {
            token: Token::new(token),
            event: Box::new(body.clone()),
        };
        match self.round_trip(&request, true)? {
            Response::Published { receipt } => Ok(receipt),
            other => Err(ProtocolError::unexpected("publish", &other)),
        }
    }

    /// Looks up the caller's own event status: custody receipt plus the
    /// delivery evidence tiers (never another publisher's).
    ///
    /// `delivery` is `None` when the event was never accepted; callers must
    /// treat a missing tier as not_available, never as delivered.
    pub fn status(
        &mut self,
        token: &str,
        event_id: &str,
    ) -> Result<(Option<CustodyReceipt>, Option<DeliveryEvidence>), ProtocolError> {
        let request = Request::Status {
            token: Token::new(token),
            event_id: event_id.to_string(),
        };
        match self.round_trip(&request, true)? {
            Response::Status { receipt, delivery } => Ok((receipt, delivery.map(|boxed| *boxed))),
            other => Err(ProtocolError::unexpected("status", &other)),
        }
    }

    /// Requests a drained daemon shutdown (operator grants only).
    pub fn shutdown(&mut self, token: &str) -> Result<(), ProtocolError> {
        let request = Request::Shutdown {
            token: Token::new(token),
        };
        match self.round_trip(&request, false)? {
            Response::ShuttingDown => Ok(()),
            other => Err(ProtocolError::unexpected("shutdown", &other)),
        }
    }

    /// Lists retained incidents with age, deadlines and blocked dependents
    /// (operator grants only; `limit` is capped by the service).
    pub fn incidents(
        &mut self,
        token: &str,
        include_closed: bool,
        limit: Option<usize>,
    ) -> Result<Vec<IncidentView>, ProtocolError> {
        let request = Request::Incidents {
            token: Token::new(token),
            include_closed,
            limit,
        };
        match self.round_trip(&request, true)? {
            Response::Incidents { incidents } => Ok(incidents),
            other => Err(ProtocolError::unexpected("incidents", &other)),
        }
    }

    /// Lists visible recipient holds (operator grants only).
    pub fn holds(
        &mut self,
        token: &str,
        limit: Option<usize>,
    ) -> Result<Vec<HoldView>, ProtocolError> {
        let request = Request::Holds {
            token: Token::new(token),
            limit,
        };
        match self.round_trip(&request, true)? {
            Response::Holds { holds } => Ok(holds),
            other => Err(ProtocolError::unexpected("holds", &other)),
        }
    }

    /// Authorizes one more attempt of the same event after an unresolved
    /// possible hand-off; the duplicate risk is recorded permanently.
    pub fn authorize_retry(
        &mut self,
        token: &str,
        publisher: &str,
        event_id: &str,
        note: &str,
    ) -> Result<(), ProtocolError> {
        self.operator_action(Request::AuthorizeRetry {
            token: Token::new(token),
            publisher: publisher.to_string(),
            event_id: event_id.to_string(),
            note: note.to_string(),
        })
    }

    /// Closes an event with an audited disposition (never claims delivery).
    pub fn dispose(
        &mut self,
        token: &str,
        publisher: &str,
        event_id: &str,
        note: &str,
    ) -> Result<(), ProtocolError> {
        self.operator_action(Request::Dispose {
            token: Token::new(token),
            publisher: publisher.to_string(),
            event_id: event_id.to_string(),
            note: note.to_string(),
        })
    }

    /// Waives a missing or expired predecessor of a dependent event.
    pub fn waive_predecessor(
        &mut self,
        token: &str,
        publisher: &str,
        event_id: &str,
        note: &str,
    ) -> Result<(), ProtocolError> {
        self.operator_action(Request::WaivePredecessor {
            token: Token::new(token),
            publisher: publisher.to_string(),
            event_id: event_id.to_string(),
            note: note.to_string(),
        })
    }

    /// Records positive late evidence that settles an uncertain attempt
    /// without another send.
    pub fn record_evidence(
        &mut self,
        token: &str,
        publisher: &str,
        event_id: &str,
        attempt_seq: u64,
        tier: EvidenceTier,
        detail: &str,
    ) -> Result<(), ProtocolError> {
        self.operator_action(Request::Evidence {
            token: Token::new(token),
            publisher: publisher.to_string(),
            event_id: event_id.to_string(),
            attempt_seq,
            tier,
            detail: detail.to_string(),
        })
    }

    /// Sets the durable no-wake policy for a recipient.
    pub fn pause(
        &mut self,
        token: &str,
        recipient: &NativeAddress,
        reason: &str,
    ) -> Result<(), ProtocolError> {
        self.operator_action(Request::Pause {
            token: Token::new(token),
            recipient: recipient.clone(),
            reason: reason.to_string(),
        })
    }

    /// Clears the durable no-wake policy for a recipient.
    pub fn resume(&mut self, token: &str, recipient: &NativeAddress) -> Result<(), ProtocolError> {
        self.operator_action(Request::Resume {
            token: Token::new(token),
            recipient: recipient.clone(),
        })
    }

    /// Sends an operator mutation and expects the `Done` acknowledgement.
    ///
    /// Never resent after a lost response: an audited decision is applied
    /// once, and the caller inspects the incident list to see the outcome.
    fn operator_action(&mut self, request: Request) -> Result<(), ProtocolError> {
        match self.round_trip(&request, false)? {
            Response::Done => Ok(()),
            other => Err(ProtocolError::unexpected("operator action", &other)),
        }
    }

    /// Sends one request line and reads one bounded response line.
    ///
    /// A write failure on a stale connection is always safe to repeat (the
    /// service acts only on complete lines). A missing response is repeated
    /// once only when `repeatable`; otherwise it is reported as a transport
    /// error because the request may have been processed.
    fn round_trip(
        &mut self,
        request: &Request,
        repeatable: bool,
    ) -> Result<Response, ProtocolError> {
        let bytes = serde_json::to_vec(request)
            .map_err(|error| ProtocolError::transport(format!("cannot encode request: {error}")))?;
        let mut last = ProtocolError::transport("no attempt was made");
        for _ in 0..2 {
            if self.connection.is_none() {
                self.connection = Some(open(&self.socket).map_err(|error| {
                    ProtocolError::transport(format!("cannot connect: {error}"))
                })?);
            }
            let Some(connection) = self.connection.as_mut() else {
                continue;
            };
            if let Err(error) = write_line(&mut connection.stream, &bytes, WRITE_TIMEOUT) {
                self.connection = None;
                last = ProtocolError::transport(format!("write failed: {error}"));
                continue;
            }
            match read_bounded_line(
                &mut connection.reader,
                MAX_RESPONSE_BYTES,
                RESPONSE_TIMEOUT,
                RESPONSE_TIMEOUT,
            ) {
                Ok(Some(line)) => {
                    return match serde_json::from_str::<Response>(&line) {
                        Ok(Response::Error { class, detail }) => {
                            Err(ProtocolError { class, detail })
                        }
                        Ok(response) => match response.validate() {
                            Ok(()) => Ok(response),
                            Err(error) => {
                                self.connection = None;
                                Err(ProtocolError::transport(format!(
                                    "invalid response: {error}"
                                )))
                            }
                        },
                        Err(error) => {
                            self.connection = None;
                            Err(ProtocolError::transport(format!(
                                "unparseable or invalid response: {error}"
                            )))
                        }
                    };
                }
                Ok(None) => {
                    self.connection = None;
                    last = ProtocolError::transport(
                        "connection closed before a response; the request may have been processed",
                    );
                }
                Err(error) => {
                    self.connection = None;
                    last = ProtocolError::transport(format!("read failed: {error}"));
                }
            }
            if !repeatable {
                break;
            }
        }
        Err(last)
    }
}

/// Opens a connection and its buffered read half.
fn open(socket: &Path) -> std::io::Result<Connection> {
    let stream = UnixStream::connect(socket)?;
    let reader = BufReader::new(stream.try_clone()?);
    Ok(Connection { stream, reader })
}

/// A publisher-side builder for one event's publication intent.
///
/// Validates every component as it is added, so a completed request always
/// yields a canonical [`Envelope`] acceptable to Bridge custody. The
/// request is checked once by [`PublishRequest::validate`] exactly as the
/// service checks it, including renderability.
#[derive(Debug, Clone)]
pub struct PublishRequest {
    /// Stable per-producer event id for idempotent retry.
    event: EventId,
    /// Exact native logical recipient.
    recipient: NativeAddress,
    /// Opaque event kind from the publisher's contract.
    kind: Kind,
    /// Requested delivery mode.
    mode: Mode,
    /// Coalescing policy.
    policy: Policy,
    /// Bounded payload.
    payload: Payload,
    /// Bounded metadata (sorted map).
    metadata: Metadata,
    /// Absolute expiry, if any.
    expires_at: Option<ExpiresAt>,
}

impl PublishRequest {
    /// Starts a request from already-validated components.
    ///
    /// Component-level validation happened in their constructors; the final
    /// cross-field validation still runs in [`PublishRequest::validate`]. The
    /// publisher identity is deliberately absent: the service stamps it
    /// from the authenticated grant.
    pub fn new(
        event: EventId,
        recipient: NativeAddress,
        kind: Kind,
        mode: Mode,
        policy: Policy,
        payload: Payload,
    ) -> Self {
        PublishRequest {
            event,
            recipient,
            kind,
            mode,
            policy,
            payload,
            metadata: Metadata::new(),
            expires_at: None,
        }
    }

    /// Attaches one metadata entry, replacing any earlier value for the key.
    ///
    /// Keys and values are validated by [`PublishRequest::validate`] against
    /// the metadata bounds; a map insert here is unchecked and cheap. The
    /// `project` and `task` keys scope coalescing; `predecessor` names an
    /// earlier event of the same publisher that this event must wait for.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Attaches an absolute expiry (already normalized by the producer).
    ///
    /// Producers deriving expiry from a relative TTL must normalize once
    /// with [`ExpiresAt::relative`] before calling this; the request never
    /// stores a relative value, so a retry cannot extend expiry.
    pub fn with_expires_at(mut self, expires_at: ExpiresAt) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Validates the whole request exactly as the service will.
    ///
    /// Runs every component's rules (address, kind, stream/group, revision
    /// and expiry ranges, payload and metadata bounds, predecessor shape)
    /// by assembling a probe envelope with a placeholder publisher — the
    /// real one is stamped server-side from the authenticated grant — and
    /// checks that the event can always be rendered (no forbidden control
    /// characters, escaped size within the manifest bound).
    pub fn validate(&self) -> Result<(), CoreError> {
        let probe = Envelope::new(
            PublisherId::new("client-validation")?,
            self.event.clone(),
            self.recipient.clone(),
            self.kind.clone(),
            self.mode,
            self.policy.clone(),
            self.payload.clone(),
            self.metadata.clone(),
            self.expires_at,
        )?;
        if let Some(predecessor) = self.metadata.get("predecessor") {
            EventId::new(predecessor.clone())?;
        }
        bridge_core::framing::check_renderable(&probe)
    }

    /// Converts this request into the wire body the service expects.
    ///
    /// Validates first ([`PublishRequest::validate`]); a failed conversion
    /// writes nothing anywhere and reports [`CoreError::InvalidEnvelope`].
    /// The body deliberately carries no publisher identity.
    pub fn into_body(self) -> Result<PublishBody, CoreError> {
        self.validate()?;
        Ok(PublishBody {
            event_id: self.event.as_str().to_string(),
            recipient: self.recipient,
            kind: self.kind.as_str().to_string(),
            mode: self.mode,
            policy: self.policy,
            payload: self.payload.as_str().to_string(),
            metadata: self.metadata,
            expires_at: self.expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Builder checks: validation surfaced at build time.

    use super::*;

    /// A minimal request for builder tests.
    fn request(id: &str, payload: &str) -> PublishRequest {
        PublishRequest::new(
            EventId::new(id).unwrap(),
            NativeAddress::new("host", Harness::Codex, "default", "thread-1").unwrap(),
            Kind::new("worker.completed").unwrap(),
            Mode::Auto,
            Policy::KeepAll,
            Payload::new(payload).unwrap(),
        )
    }

    #[test]
    fn builder_produces_validated_body() {
        let body = request("evt-42", "done")
            .with_metadata("project", "agent-bridge")
            .with_expires_at(ExpiresAt::from_unix_millis(4_102_444_800_000).unwrap())
            .into_body()
            .unwrap();

        assert_eq!(body.event_id, "evt-42");
        assert_eq!(body.recipient.native_session_id, "thread-1");
        assert_eq!(body.kind, "worker.completed");
        assert_eq!(
            body.metadata
                .get("project")
                .map(std::string::String::as_str),
            Some("agent-bridge")
        );
        assert_eq!(
            body.expires_at.map(ExpiresAt::unix_millis),
            Some(4_102_444_800_000)
        );
    }

    #[test]
    fn builder_surfaces_metadata_violations() {
        let mut oversized = request("evt-43", "x");
        for index in 0..17 {
            oversized = oversized.with_metadata(format!("key{index}"), "v");
        }
        match oversized.into_body() {
            Err(CoreError::InvalidEnvelope(detail)) => {
                assert!(detail.contains("metadata"), "unexpected detail: {detail}")
            }
            other => panic!("expected metadata rejection, got {other:?}"),
        }
    }

    #[test]
    fn builder_refuses_events_that_could_never_be_rendered() {
        assert!(request("evt-44", "bad\u{1}control").into_body().is_err());
        assert!(
            request("evt-45", &"&".repeat(60 * 1024))
                .into_body()
                .is_err()
        );
        assert!(
            request("evt-46", "ok")
                .with_metadata("predecessor", "")
                .into_body()
                .is_err()
        );
    }
}
