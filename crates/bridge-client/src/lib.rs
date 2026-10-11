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

pub use bridge_core::recovery::{
    EvidenceTier, HoldView, IncidentPage, IncidentView, LineageScope, RetentionView,
};
pub use bridge_core::service::{DeliveryCounts, DeliveryEvidence};
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

    /// Reads one operator-only finite incident page without changing state.
    ///
    /// `include_closed` controls the live state filter; `limit` defaults to
    /// 100 and clamps to 1..200. Start with `after_seq=0, through_seq=None`,
    /// then carry the fixed returned high-water and optional next cursor.
    /// Final pages have no next cursor; restart to see new/reopened rows.
    /// Invalid cursors, wrong grants or malformed/misbound replies fail;
    /// repeating this read after transport loss never repeats a report.
    pub fn incidents_page(
        &mut self,
        token: &str,
        include_closed: bool,
        limit: Option<usize>,
        after_seq: u64,
        through_seq: Option<u64>,
    ) -> Result<IncidentPage, ProtocolError> {
        let request = Request::IncidentsPage {
            token: Token::new(token),
            include_closed,
            limit,
            after_seq,
            through_seq,
        };
        match self.round_trip(&request, true)? {
            Response::IncidentsPage { page } => Ok(page),
            other => Err(ProtocolError::unexpected("incidents_page", &other)),
        }
    }

    /// Reads exact operator-only retention facts for validated event identity.
    ///
    /// An unaccepted `publisher/event_id` returns `None`; stored expiry,
    /// tombstone/GC and scoped watermark facts never establish native recall.
    /// No payload bytes, credentials or mutation are returned/performed.
    /// Refused grants, invalid identifiers and malformed/misbound responses
    /// fail; a lost read may reconnect/repeat safely.
    pub fn retention(
        &mut self,
        token: &str,
        publisher: &str,
        event_id: &str,
    ) -> Result<Option<RetentionView>, ProtocolError> {
        let request = Request::Retention {
            token: Token::new(token),
            publisher: publisher.to_string(),
            event_id: event_id.to_string(),
        };
        match self.round_trip(&request, true)? {
            Response::Retention { retention } => Ok(retention.map(|view| *view)),
            other => Err(ProtocolError::unexpected("retention", &other)),
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

    /// Reads bounded delivery counts (events per tier plus open
    /// incidents); operator grants only.
    pub fn counts(&mut self, token: &str) -> Result<DeliveryCounts, ProtocolError> {
        match self.round_trip(
            &Request::Counts {
                token: Token::new(token),
            },
            false,
        )? {
            Response::Counts { counts } => Ok(counts),
            Response::Error { class, detail } => Err(ProtocolError { class, detail }),
            other => Err(ProtocolError {
                class: "internal".into(),
                detail: format!("unexpected response to counts: {other:?}"),
            }),
        }
    }

    /// Transfers a stream lineage's authoritative producer (audited,
    /// operator grants only).
    ///
    /// The lineage is the coalescing scope without the publisher (exact
    /// recipient, kind, mode, declared project/task, stream). After the
    /// transfer the previous owner's further `latest` publications into
    /// the lineage are declined before acceptance; event ids, watermarks,
    /// attempts and evidence are never rewritten. The core refuses the handover
    /// while another producer's event in the lineage has a possible or
    /// unknown native effect (invoking, in review or natively held): resolve
    /// it with an audited disposition first. Never resent after a
    /// lost response: re-read the incident/audit surface instead.
    pub fn transfer_lineage(
        &mut self,
        token: &str,
        scope: &LineageScope,
        new_publisher: &str,
        note: &str,
    ) -> Result<(), ProtocolError> {
        let recipient = NativeAddress::parse(&scope.recipient).map_err(|error| ProtocolError {
            class: "invalid".into(),
            detail: error.to_string(),
        })?;
        self.operator_action(Request::TransferLineage {
            token: Token::new(token),
            recipient,
            kind: scope.kind.clone(),
            mode: scope.mode.clone(),
            project: scope.project.clone(),
            task: scope.task.clone(),
            stream: scope.stream.clone(),
            new_publisher: new_publisher.to_string(),
            note: note.to_string(),
        })
    }

    /// Sets the durable no-wake policy for a recipient.
    ///
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
                        Ok(response) => match response
                            .validate()
                            .and_then(|()| validate_request_binding(request, &response))
                        {
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

/// Checks that a structurally valid response matches the exact requested scope.
///
/// Publish receipts must name the requested event and hash its exact immutable
/// body under the server-stamped publisher. Status receipts must name the queried
/// event; delivery without custody is invalid. Operator pages must match the
/// requested cursor/filter/limit; retention must name the exact requested
/// identity. Other operations have no custody binding. Tokens are never inspected
/// or included in refusal text. A mismatch returns an invalid-envelope error and
/// must not release the caller's intent.
fn validate_request_binding(request: &Request, response: &Response) -> Result<(), CoreError> {
    match (request, response) {
        (Request::Publish { event, .. }, Response::Published { receipt }) => {
            let expected = Envelope::new(
                PublisherId::new(receipt.publisher.clone())?,
                EventId::new(event.event_id.clone())?,
                event.recipient.clone(),
                Kind::new(event.kind.clone())?,
                event.mode,
                event.policy.clone(),
                Payload::new(event.payload.clone())?,
                event.metadata.clone(),
                event.expires_at,
            )?;
            if receipt.event_id != event.event_id
                || receipt.envelope_hash != expected.envelope_hash()
            {
                return Err(CoreError::InvalidEnvelope(
                    "publication receipt does not acknowledge the requested immutable event".into(),
                ));
            }
        }
        (Request::Status { event_id, .. }, Response::Status { receipt, delivery })
            if receipt
                .as_ref()
                .is_some_and(|item| item.event_id != *event_id)
                || (receipt.is_none() && delivery.is_some()) =>
        {
            return Err(CoreError::InvalidEnvelope(
                "status response does not match the queried custody event".into(),
            ));
        }
        (
            Request::IncidentsPage {
                include_closed,
                limit,
                after_seq,
                through_seq,
                ..
            },
            Response::IncidentsPage { page },
        ) => {
            if page.incidents.len() > limit.unwrap_or(100).clamp(1, 200)
                || page.through_seq < *after_seq
                || through_seq.is_some_and(|through| through != page.through_seq)
                || page.incidents.iter().any(|row| {
                    row.incident_seq <= *after_seq
                        || (!include_closed
                            && row.state != bridge_core::recovery::IncidentState::Open)
                })
            {
                return Err(CoreError::InvalidEnvelope(
                    "incident page does not match the requested scan".into(),
                ));
            }
        }
        (
            Request::Retention {
                publisher,
                event_id,
                ..
            },
            Response::Retention {
                retention: Some(view),
            },
        ) if view.receipt.publisher != PublisherId::new(publisher.clone())?.as_str()
            || view.receipt.event_id != EventId::new(event_id.clone())?.as_str() =>
        {
            return Err(CoreError::InvalidEnvelope(
                "retention response does not match the queried event".into(),
            ));
        }
        _ => {}
    }
    Ok(())
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

    /// The builder produces a fully validated publisher-less body with the
    /// attached metadata and expiry.
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
    /// The builder surfaces metadata bound violations as invalid-envelope
    /// errors.
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
    /// The builder refuses events whose framing could never render (bad
    /// tag or unbounded content) before they reach the wire.
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
