//! Shared typed publisher client for Agent Bridge family producers.
//!
//! Agent Run, Agent IDE and Agent Worktree depend on this crate — not on
//! `bridge-core` internals — so the envelope model they build against stays
//! stable while the service evolves. This first slice provides the canonical
//! types (re-exported) and a validating [`PublishRequest`] builder that
//! producers use to construct exactly the envelopes the custody store
//! accepts.
//!
//! The transport (local IPC to the Bridge service) arrives with the
//! publisher-protocol task and is deliberately absent here: no fake or
//! speculative wire protocol is shipped. Until then, producers can already
//! validate and freeze the events they intend to publish.

pub use bridge_core::{
    CoreError, Envelope, EnvelopeHash, EventId, ExpiresAt, Harness, Kind, Metadata, Mode,
    NativeAddress, Payload, Policy, PublisherId, SCHEMA_VERSION, StreamId,
};

/// A publisher-side builder for one event's publication intent.
///
/// Validates every component as it is added, so a completed request always
/// yields a canonical [`Envelope`] acceptable to Bridge custody. The
/// envelope is frozen (hash included) exactly once by [`PublishRequest::build`].
#[derive(Debug, Clone)]
pub struct PublishRequest {
    /// Authenticated publisher identity, supplied by the producer's
    /// integration grant — never guessed from a task label.
    publisher: PublisherId,
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
    /// cross-field validation still runs in [`PublishRequest::build`].
    pub fn new(
        publisher: PublisherId,
        event: EventId,
        recipient: NativeAddress,
        kind: Kind,
        mode: Mode,
        policy: Policy,
        payload: Payload,
    ) -> Self {
        PublishRequest {
            publisher,
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
    /// Keys and values are validated by [`PublishRequest::build`] against
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

    /// Freezes the request into its canonical envelope.
    ///
    /// Runs full validation (including metadata bounds) and computes the
    /// identity-content hash. A failed build writes nothing anywhere and
    /// reports [`CoreError::InvalidEnvelope`].
    pub fn build(self) -> Result<Envelope, CoreError> {
        Envelope::new(
            self.publisher,
            self.event,
            self.recipient,
            self.kind,
            self.mode,
            self.policy,
            self.payload,
            self.metadata,
            self.expires_at,
        )
    }
}

#[cfg(test)]
mod tests {
    //! Builder checks: validation surfaced at build time.

    use super::*;

    #[test]
    fn builder_produces_canonical_envelope() {
        let envelope = PublishRequest::new(
            PublisherId::new("agent-run").unwrap(),
            EventId::new("evt-42").unwrap(),
            NativeAddress::new("host", Harness::Codex, "default", "thread-1").unwrap(),
            Kind::new("worker.completed").unwrap(),
            Mode::Auto,
            Policy::KeepAll,
            Payload::new("done").unwrap(),
        )
        .with_metadata("project", "agent-bridge")
        .with_expires_at(ExpiresAt::from_unix_millis(4_102_444_800_000).unwrap())
        .build()
        .unwrap();

        assert_eq!(envelope.schema_version, SCHEMA_VERSION);
        assert_eq!(
            envelope.metadata.get("project").map(String::as_str),
            Some("agent-bridge")
        );
        assert_eq!(
            envelope.expires_at.map(ExpiresAt::unix_millis),
            Some(4_102_444_800_000)
        );
        assert_eq!(envelope.envelope_hash().as_str().len(), 64);
    }

    #[test]
    fn builder_surfaces_metadata_violations() {
        let mut oversized = PublishRequest::new(
            PublisherId::new("agent-run").unwrap(),
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
        match oversized.build() {
            Err(CoreError::InvalidEnvelope(detail)) => {
                assert!(detail.contains("metadata"), "unexpected detail: {detail}")
            }
            other => panic!("expected metadata rejection, got {other:?}"),
        }
    }
}
