//! Shared typed publisher client for Agent Bridge family producers.
//!
//! Agent Run, Agent IDE and Agent Worktree depend on this crate — not on
//! `bridge-core` internals — so the envelope model they build against stays
//! stable while the service evolves. The [`PublishRequest`] builder
//! validates and freezes an event; [`BridgeClient`] speaks the local
//! publisher protocol: newline-delimited JSON over the daemon's Unix
//! stream socket, one response per request.
//!
//! Retries after a lost response resend the exact same event (same event id
//! and content): custody deduplication returns the original receipt, so a
//! retry never duplicates an event or restarts business work. A changed
//! body under the same event id is refused as a conflict by the service.

pub use bridge_core::{
    CoreError, CustodyReceipt, Envelope, EnvelopeHash, EventId, ExpiresAt, Harness, Kind, Metadata,
    Mode, NativeAddress, Payload, Policy, PublisherId, SCHEMA_VERSION, StreamId,
};

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use bridge_core::service::{PublishBody, Request, Response};

/// A client's typed view of one protocol refusal.
///
/// `class` mirrors the service's machine-readable classes: `auth`,
/// `forbidden`, `unsupported`, `invalid`, `conflict`, `capacity`,
/// `internal`; `detail` is safe-for-logging text without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    /// Machine-readable refusal class from the service.
    pub class: String,
    /// Human-readable detail.
    pub detail: String,
}

impl std::fmt::Display for ProtocolError {
    /// Renders class and detail on one line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.class, self.detail)
    }
}

impl std::error::Error for ProtocolError {}

/// A connected publisher client for one daemon socket.
///
/// One connection, sequential requests; safe to reuse across retries.
/// Not `Sync` (shares one stream); clone per thread if ever needed.
#[derive(Debug)]
pub struct BridgeClient {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl BridgeClient {
    /// Connects to the daemon's socket.
    ///
    /// Fails with the underlying I/O error when no daemon is listening.
    pub fn connect(socket: impl AsRef<Path>) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(BridgeClient { stream, reader })
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
            token: token.to_string(),
            event: body.clone(),
        };
        match self.round_trip(&request) {
            Response::Published { receipt } => Ok(receipt),
            Response::Error { class, detail } => Err(ProtocolError {
                class: class.to_string(),
                detail,
            }),
            other => Err(ProtocolError {
                class: "internal".into(),
                detail: format!("unexpected response to publish: {other:?}"),
            }),
        }
    }

    /// Looks up the caller's own event status (custody only, never another
    /// publisher's).
    pub fn status(
        &mut self,
        token: &str,
        event_id: &str,
    ) -> Result<Option<CustodyReceipt>, ProtocolError> {
        let request = Request::Status {
            token: token.to_string(),
            event_id: event_id.to_string(),
        };
        match self.round_trip(&request) {
            Response::Status { receipt } => Ok(receipt),
            Response::Error { class, detail } => Err(ProtocolError {
                class: class.to_string(),
                detail,
            }),
            other => Err(ProtocolError {
                class: "internal".into(),
                detail: format!("unexpected response to status: {other:?}"),
            }),
        }
    }

    /// Requests a drained daemon shutdown (admin grants only).
    pub fn shutdown(&mut self, token: &str) -> Result<(), ProtocolError> {
        let request = Request::Shutdown {
            token: token.to_string(),
        };
        match self.round_trip(&request) {
            Response::ShuttingDown => Ok(()),
            Response::Error { class, detail } => Err(ProtocolError {
                class: class.to_string(),
                detail,
            }),
            other => Err(ProtocolError {
                class: "internal".into(),
                detail: format!("unexpected response to shutdown: {other:?}"),
            }),
        }
    }

    /// Sends one request line and reads one response line.
    fn round_trip(&mut self, request: &Request) -> Response {
        let mut line = serde_json::to_vec(request).unwrap_or_else(|_| b"{}".to_vec());
        line.push(b'\n');
        if self.stream.write_all(&line).is_err() || self.stream.flush().is_err() {
            return io_error_response("write failed");
        }
        let mut response_line = String::new();
        match self.reader.read_line(&mut response_line) {
            Ok(0) | Err(_) => io_error_response("connection closed"),
            Ok(_) => serde_json::from_str(&response_line).unwrap_or_else(|error| {
                io_error_response(&format!("unparseable response: {error}"))
            }),
        }
    }
}

/// Builds the internal-class error response for transport failures.
fn io_error_response(detail: &str) -> Response {
    Response::Error {
        class: "internal".into(),
        detail: detail.to_string(),
    }
}

/// A publisher-side builder for one event's publication intent.
///
/// Validates every component as it is added, so a completed request always
/// yields a canonical [`Envelope`] acceptable to Bridge custody. The
/// envelope is frozen (hash included) exactly once by
/// [`PublishRequest::validate`].
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
    /// the metadata bounds; a map insert here is unchecked and cheap.
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
    /// Runs every component's rules (address, kind, stream/group, payload
    /// bounds, metadata bounds, expiry bounds) without constructing an
    /// envelope, since the publisher identity is stamped server-side from
    /// the authenticated grant.
    pub fn validate(&self) -> Result<(), CoreError> {
        self.event.validate()?;
        self.recipient.validate()?;
        self.kind.validate()?;
        self.policy.validate()?;
        self.payload.validate()?;
        bridge_core::validate_metadata(&self.metadata)?;
        if let Some(expiry) = self.expires_at {
            expiry.validate()?;
        }
        Ok(())
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

    #[test]
    fn builder_produces_validated_body() {
        let body = PublishRequest::new(
            EventId::new("evt-42").unwrap(),
            NativeAddress::new("host", Harness::Codex, "default", "thread-1").unwrap(),
            Kind::new("worker.completed").unwrap(),
            Mode::Auto,
            Policy::KeepAll,
            Payload::new("done").unwrap(),
        )
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
        let mut oversized = PublishRequest::new(
            EventId::new("evt-43").unwrap(),
            NativeAddress::new("host", Harness::ClaudeCode, "default", "s-1").unwrap(),
            Kind::new("note").unwrap(),
            Mode::Message,
            Policy::KeepAll,
            Payload::new("x").unwrap(),
        );
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
}
