//! Canonical event identity, envelope and hashing for Agent Bridge.
//!
//! These types define the immutable identity of a published event: who sent
//! it, the exact native recipient, what it is, how it may be coalesced and
//! when it expires. The canonical serialization and [`EnvelopeHash`] freeze
//! that identity so an accepted event can never silently change, and so an
//! identical retry after a lost acknowledgement can be recognized as the same
//! event rather than a duplicate.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{MAX_FIELD_BYTES, MAX_METADATA_ENTRIES, MAX_PAYLOAD_BYTES};

/// Envelope schema version understood by this build.
///
/// Events carry their own [`Envelope::schema_version`]; a future incompatible
/// change to the canonical form must bump this and refuse older envelopes
/// explicitly instead of reinterpreting them.
pub const SCHEMA_VERSION: u16 = 1;

/// Validates a bounded identifier-like UTF-8 string field.
///
/// Accepts any non-empty string up to `max` bytes that contains no Unicode
/// control characters (C0, DEL, or C1 ranges). Rejects anything else with
/// [`CoreError::InvalidEnvelope`], naming the field. Identifiers appear in
/// addresses, kinds, stream and group ids; hostile content is rejected at the
/// trust boundary rather than escaped here (rendering owns escaping).
fn validate_field(field: &'static str, value: &str, max: usize) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(CoreError::InvalidEnvelope(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > max {
        return Err(CoreError::InvalidEnvelope(format!(
            "{field} exceeds {max} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(CoreError::InvalidEnvelope(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

/// Harness (native host product) a recipient session lives in.
///
/// The harness decides which native store namespace and session identifier
/// kinds are meaningful; it is part of the recipient's canonical logical
/// address and never implied by a transport or a display name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Harness {
    /// A Codex installation; sessions are identified by thread id.
    Codex,
    /// A Claude Code installation; sessions are identified by session id.
    ClaudeCode,
}

impl Harness {
    /// Canonical wire name of this harness, stable across schema revisions.
    ///
    /// Never display-derived: the names are part of the canonical address.
    pub const fn as_str(self) -> &'static str {
        match self {
            Harness::Codex => "codex",
            Harness::ClaudeCode => "claude-code",
        }
    }

    /// Parses a harness from its canonical wire name.
    ///
    /// Returns [`CoreError::InvalidEnvelope`] for any other spelling; there
    /// is no fuzzy matching and no default harness.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "codex" => Ok(Harness::Codex),
            "claude-code" => Ok(Harness::ClaudeCode),
            other => Err(CoreError::InvalidEnvelope(format!(
                "unknown harness {other:?}"
            ))),
        }
    }
}

/// Canonical logical address of one native recipient session.
///
/// Composed of host id, harness, native store namespace and native session
/// id, exactly as defined by the technical plan: the namespace identifies the
/// actual native home/store/profile under the OS owner — never a cwd or
/// project name. Fork, `/clear` or a new native id produces a different
/// recipient; display names never participate in routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NativeAddress {
    /// Identifier of the OS host owning the native store.
    pub host_id: String,
    /// Native harness product of the session.
    pub harness: Harness,
    /// Native home/store/profile namespace under the OS owner.
    pub native_store_namespace: String,
    /// Native session identifier (Codex thread id or Claude session id).
    pub native_session_id: String,
}

impl NativeAddress {
    /// Builds and validates a recipient address.
    ///
    /// Every component must be non-empty, at most [`MAX_FIELD_BYTES`]
    /// bytes, and free of control
    /// characters; violations return [`CoreError::InvalidEnvelope`].
    pub fn new(
        host_id: impl Into<String>,
        harness: Harness,
        native_store_namespace: impl Into<String>,
        native_session_id: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let address = NativeAddress {
            host_id: host_id.into(),
            harness,
            native_store_namespace: native_store_namespace.into(),
            native_session_id: native_session_id.into(),
        };
        address.validate()?;
        Ok(address)
    }

    /// Checks every component against the field rules.
    ///
    /// Pure function; no effects. Errors name the offending field.
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_field("host_id", &self.host_id, MAX_FIELD_BYTES)?;
        validate_field(
            "native_store_namespace",
            &self.native_store_namespace,
            MAX_FIELD_BYTES,
        )?;
        validate_field(
            "native_session_id",
            &self.native_session_id,
            MAX_FIELD_BYTES,
        )?;
        Ok(())
    }

    /// Canonical text form used in logs and status output.
    ///
    /// Slash-separated, harness as its canonical wire name. Round-trips
    /// through [`NativeAddress::parse`]; not used for hashing (the envelope
    /// serialization is).
    pub fn to_canonical_string(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.host_id,
            self.harness.as_str(),
            self.native_store_namespace,
            self.native_session_id
        )
    }

    /// Parses the canonical text form produced by
    /// [`NativeAddress::to_canonical_string`].
    ///
    /// Refuses extra segments, empty components and unknown harness names.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() != 4 {
            return Err(CoreError::InvalidEnvelope(
                "address must have four slash-separated components".into(),
            ));
        }
        NativeAddress::new(parts[0], Harness::parse(parts[1])?, parts[2], parts[3])
    }
}

/// A validated, bounded producer-side event identifier.
///
/// Stable across retries of the same publication and unique per publisher:
/// custody deduplication keys on `(publisher, event id)`. Not a UUID
/// freshness signal and not a recipient-visible delivery correlation id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(String);

impl EventId {
    /// Validates and wraps an event id (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("event_id", &value, MAX_FIELD_BYTES)?;
        Ok(EventId(value))
    }

    /// The id text, validated at construction.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated publisher identity (already authenticated upstream).
///
/// The storage layer trusts this value; the publisher protocol task owns how
/// it is authenticated and which grants it carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublisherId(String);

impl PublisherId {
    /// Validates and wraps a publisher id (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("publisher_id", &value, MAX_FIELD_BYTES)?;
        Ok(PublisherId(value))
    }

    /// The id text, validated at construction.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated event kind (for example a completion or a diagnostic view).
///
/// Kinds are agreed per publisher contract; the core treats them as bounded
/// opaque labels and never interprets their meaning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Kind(String);

impl Kind {
    /// Validates and wraps a kind (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("kind", &value, 64)?;
        Ok(Kind(value))
    }

    /// The kind text, validated at construction.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An authoritative replaceable snapshot stream identifier for `latest`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamId(String);

impl StreamId {
    /// Validates and wraps a stream id (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("stream_id", &value, MAX_FIELD_BYTES)?;
        Ok(StreamId(value))
    }

    /// The stream id text, validated at construction.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Requested delivery mode, exactly as chosen by the publisher.
///
/// `Auto` is a selector, not a third transport: the effective mode is decided
/// at dispatch time (active recipient -> inject, inactive -> message) and is
/// recorded on the attempt, never on this immutable field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mode {
    /// Deliver through a qualified native hook at a natural context point.
    Inject,
    /// Deliver through the native queue/message carrier.
    Message,
    /// Select inject or message from the recipient's current state.
    Auto,
}

/// Coalescing policy attached to an event.
///
/// `KeepAll` preserves every independently meaningful event. `Latest`
/// identifies one authoritative replaceable snapshot at a durable monotonic
/// source revision. `Batch` marks the event as packagable with siblings of
/// the same group without losing ids, order or per-member source wrappers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    /// Never compact this event with any other.
    KeepAll,
    /// Replaceable snapshot state on `stream` at monotonic `revision`.
    Latest {
        /// Authoritative stream this snapshot belongs to.
        stream: StreamId,
        /// Durable monotonic source revision; arrival order is not freshness.
        revision: u64,
    },
    /// Losslessly packagable with other events naming the same group.
    Batch {
        /// Group entity shared by batchable siblings.
        group: String,
    },
}

impl Policy {
    /// Validates the policy's own fields (stream/group shape and bounds).
    ///
    /// Struct constructors already validate [`StreamId`]; this checks the
    /// batch group text. Returns [`CoreError::InvalidEnvelope`] on failure.
    pub fn validate(&self) -> Result<(), CoreError> {
        match self {
            Policy::KeepAll => Ok(()),
            Policy::Latest { stream, .. } => {
                validate_field("stream_id", stream.as_str(), MAX_FIELD_BYTES)
            }
            Policy::Batch { group } => validate_field("group", group, MAX_FIELD_BYTES),
        }
    }
}

/// Absolute expiry of an event, in Unix epoch milliseconds.
///
/// Relative TTLs are normalized exactly once, at the edge where a request is
/// turned into an envelope ([`ExpiresAt::relative`]); the envelope stores
/// only the absolute value, so a later retry cannot extend expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExpiresAt(u64);

impl ExpiresAt {
    /// Wraps an absolute Unix-epoch-milliseconds expiry.
    ///
    /// Refuses zero (an unset expiry is represented by `None` on the
    /// envelope, not by a sentinel value).
    pub fn from_unix_millis(millis: u64) -> Result<Self, CoreError> {
        if millis == 0 {
            return Err(CoreError::InvalidEnvelope(
                "expires_at must be a non-zero absolute timestamp".into(),
            ));
        }
        Ok(ExpiresAt(millis))
    }

    /// Normalizes a relative TTL once: `now_ms + ttl_ms`.
    ///
    /// `ttl_ms` may be zero (expire immediately); the result is the absolute
    /// value the envelope will freeze.
    pub fn relative(ttl_ms: u64, now_ms: u64) -> Result<Self, CoreError> {
        let millis = now_ms
            .checked_add(ttl_ms)
            .ok_or_else(|| CoreError::InvalidEnvelope("expires_at overflow".into()))?;
        ExpiresAt::from_unix_millis(millis)
    }

    /// The absolute expiry in Unix epoch milliseconds.
    pub const fn unix_millis(self) -> u64 {
        self.0
    }
}

/// A bounded, valid UTF-8 notification payload.
///
/// Size is checked against [`MAX_PAYLOAD_BYTES`] at construction; escaping,
/// source wrappers and render budgets are applied later at framing time and
/// are not this type's concern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload(String);

impl Payload {
    /// Validates and wraps a payload.
    ///
    /// Rejects payloads over [`MAX_PAYLOAD_BYTES`] bytes of UTF-8. Control
    /// characters are accepted here — payloads are producer content; the
    /// framing layer rejects forbidden controls at render time.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.len() > MAX_PAYLOAD_BYTES {
            return Err(CoreError::InvalidEnvelope(format!(
                "payload exceeds {MAX_PAYLOAD_BYTES} bytes"
            )));
        }
        Ok(Payload(value))
    }

    /// The payload text, bounded at construction.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded project/task metadata attached to an envelope.
///
/// Sorted map (deterministic serialization order regardless of insertion
/// order). Keys and values are validated for length and control characters;
/// at most [`MAX_METADATA_ENTRIES`] pairs are kept.
pub type Metadata = BTreeMap<String, String>;

/// Validates a metadata map against the entry, key and value bounds.
///
/// Returns [`CoreError::InvalidEnvelope`] naming the violated rule.
pub fn validate_metadata(metadata: &Metadata) -> Result<(), CoreError> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(CoreError::InvalidEnvelope(format!(
            "metadata exceeds {MAX_METADATA_ENTRIES} entries"
        )));
    }
    for (key, value) in metadata {
        validate_field("metadata key", key, 64)?;
        validate_field("metadata value", value, MAX_FIELD_BYTES)?;
    }
    Ok(())
}

/// The immutable publisher envelope: one event's complete identity.
///
/// Field order in this struct defines the canonical serialization order;
/// together with sorted [`Metadata`] this makes [`Envelope::canonical_bytes`]
/// deterministic, so the same logical envelope always produces the same
/// [`EnvelopeHash`] no matter how or in which order it was constructed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope schema version ([`SCHEMA_VERSION`] for this build).
    pub schema_version: u16,
    /// Authenticated publisher identity stamped by Bridge at acceptance.
    pub publisher: PublisherId,
    /// Producer-stable event id, unique per publisher.
    pub event_id: EventId,
    /// Exact native logical recipient address.
    pub recipient: NativeAddress,
    /// Opaque event kind agreed in the publisher's contract.
    pub kind: Kind,
    /// Requested delivery mode (the effective mode is recorded per attempt).
    pub mode: Mode,
    /// Coalescing policy and its group/revision fields.
    pub policy: Policy,
    /// Bounded UTF-8 payload.
    pub payload: Payload,
    /// Bounded project/task metadata (sorted, deterministic).
    pub metadata: Metadata,
    /// Absolute expiry in Unix epoch milliseconds, if any.
    pub expires_at: Option<ExpiresAt>,
}

impl Envelope {
    /// Assembles and fully validates an envelope.
    ///
    /// Every component is re-validated here, so an [`Envelope`] value is
    /// always safe to hash, store and dispatch. Field-level failures return
    /// [`CoreError::InvalidEnvelope`]; nothing is written anywhere by this
    /// pure constructor. The argument count mirrors the envelope's own
    /// fields; publishers preferring incremental construction use the
    /// client crate's builder.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher: PublisherId,
        event_id: EventId,
        recipient: NativeAddress,
        kind: Kind,
        mode: Mode,
        policy: Policy,
        payload: Payload,
        metadata: Metadata,
        expires_at: Option<ExpiresAt>,
    ) -> Result<Self, CoreError> {
        recipient.validate()?;
        policy.validate()?;
        validate_metadata(&metadata)?;
        Ok(Envelope {
            schema_version: SCHEMA_VERSION,
            publisher,
            event_id,
            recipient,
            kind,
            mode,
            policy,
            payload,
            metadata,
            expires_at,
        })
    }

    /// Validates an envelope received through storage or IPC.
    ///
    /// Same rules as [`Envelope::new`]; use for deserialized values whose
    /// construction path is not trusted.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CoreError::InvalidEnvelope(format!(
                "unsupported schema_version {}",
                self.schema_version
            )));
        }
        self.recipient.validate()?;
        self.policy.validate()?;
        validate_metadata(&self.metadata)?;
        Ok(())
    }

    /// Deterministic canonical serialization of the whole envelope.
    ///
    /// Compact JSON with struct fields in declaration order and sorted
    /// metadata keys. Two envelopes that are logically equal always produce
    /// identical bytes; any difference in identity-content produces
    /// different bytes. No timestamps or server state are included.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .expect("envelope serialization is infallible for validated UTF-8 fields")
    }

    /// Parses canonical bytes back into an envelope and validates them.
    ///
    /// Errors: [`CoreError::InvalidEnvelope`] for malformed JSON, schema
    /// mismatch or any rule violation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        let envelope: Envelope = serde_json::from_slice(bytes)
            .map_err(|error| CoreError::InvalidEnvelope(format!("malformed envelope: {error}")))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// SHA-256 over [`Envelope::canonical_bytes`], lowercase hex encoded.
    ///
    /// This is the frozen identity-content hash used for custody receipts,
    /// replay recognition and conflict detection.
    pub fn envelope_hash(&self) -> EnvelopeHash {
        EnvelopeHash::from_canonical_bytes(&self.canonical_bytes())
    }
}

/// The frozen SHA-256 identity-content hash of an envelope.
///
/// Lowercase hexadecimal, 64 characters. Equality of hashes is the storage
/// layer's replay test; a mismatch under the same `(publisher, event id)`
/// key is a conflict, never an overwrite.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvelopeHash(
    /// Lowercase hex text; visible crate-wide for storage round-trips only.
    pub(crate) String,
);

impl EnvelopeHash {
    /// Wrips raw canonical bytes through SHA-256 into a hex hash.
    fn from_canonical_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        EnvelopeHash(hex_encode(&digest))
    }

    /// The 64-character lowercase hex text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lowercase-hex encodes a byte slice without external dependencies.
///
/// Used only for hash digests; not a general formatting utility.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Structured non-success for the core crate.
///
/// Every failure names its class; callers never need to parse strings.
/// Storage layer failures wrap [`rusqlite::Error`] via `From`.
#[derive(Debug)]
pub enum CoreError {
    /// An envelope or field violated a validation rule; nothing was written.
    InvalidEnvelope(String),
    /// The same `(publisher, event id)` key arrived with different
    /// identity-content; the original event is untouched.
    Conflict {
        /// The stable event id whose content changed.
        event_id: String,
        /// Hash of the stored (original) envelope.
        stored_hash: String,
        /// Hash of the submitted (conflicting) envelope.
        submitted_hash: String,
    },
    /// Admission was refused because a configured hard cap is reached.
    Capacity {
        /// Human description of the exhausted limit.
        limit: String,
    },
    /// A SQLite-level failure; transaction state is reported by SQLite.
    Storage(rusqlite::Error),
}

impl fmt::Display for CoreError {
    /// Compact one-line rendering naming the class and details.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidEnvelope(detail) => write!(f, "invalid envelope: {detail}"),
            CoreError::Conflict {
                event_id,
                stored_hash,
                submitted_hash,
            } => write!(
                f,
                "conflict on event {event_id}: stored {stored_hash} != submitted {submitted_hash}"
            ),
            CoreError::Capacity { limit } => write!(f, "capacity limit reached: {limit}"),
            CoreError::Storage(error) => write!(f, "storage failure: {error}"),
        }
    }
}

impl std::error::Error for CoreError {
    /// Chains the underlying SQLite error when present.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CoreError::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for CoreError {
    /// Converts a raw SQLite error into [`CoreError::Storage`].
    fn from(error: rusqlite::Error) -> Self {
        CoreError::Storage(error)
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for the canonical identity model.

    use super::*;

    /// A minimal valid address for tests.
    fn address() -> NativeAddress {
        NativeAddress::new("host-1", Harness::ClaudeCode, "default", "session-9").unwrap()
    }

    /// A minimal valid envelope for tests.
    fn envelope(payload: &str) -> Envelope {
        let mut metadata = Metadata::new();
        metadata.insert("project".to_string(), "agent-bridge".to_string());
        metadata.insert("task".to_string(), "t-1".to_string());
        Envelope::new(
            PublisherId::new("agent-run").unwrap(),
            EventId::new("evt-1").unwrap(),
            address(),
            Kind::new("worker.completed").unwrap(),
            Mode::Auto,
            Policy::KeepAll,
            Payload::new(payload).unwrap(),
            metadata,
            Some(ExpiresAt::from_unix_millis(4_102_444_800_000).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn hash_is_stable_across_construction_order() {
        // Same logical content, metadata inserted in opposite order.
        let mut a = Metadata::new();
        a.insert("alpha".into(), "1".into());
        a.insert("beta".into(), "2".into());
        let mut b = Metadata::new();
        b.insert("beta".into(), "2".into());
        b.insert("alpha".into(), "1".into());

        let mut left = envelope("body");
        let mut right = envelope("body");
        left.metadata = a;
        right.metadata = b;

        assert_eq!(left.envelope_hash(), right.envelope_hash());
        assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    }

    #[test]
    fn hash_changes_with_identity_content() {
        let left = envelope("body");
        let mut right = envelope("different body");
        right.event_id = left.event_id.clone();
        assert_ne!(left.envelope_hash(), right.envelope_hash());
    }

    #[test]
    fn envelope_roundtrips_through_canonical_bytes() {
        let original = envelope("round trip");
        let bytes = original.canonical_bytes();
        let parsed = Envelope::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.envelope_hash(), original.envelope_hash());
    }

    #[test]
    fn policy_validation_refuses_invalid_input() {
        assert!(
            Policy::Batch {
                group: String::new()
            }
            .validate()
            .is_err()
        );
        assert!(StreamId::new("").is_err());
        assert!(StreamId::new("ok").is_ok());
    }

    #[test]
    fn field_validation_refuses_control_chars_and_oversize() {
        assert!(EventId::new("bad\u{1}id").is_err());
        assert!(EventId::new("").is_err());
        assert!(Kind::new("x".repeat(65)).is_err());
        assert!(Payload::new("x".repeat(MAX_PAYLOAD_BYTES + 1)).is_err());
        assert!(NativeAddress::new("h", Harness::Codex, "ns", "").is_err());
    }

    #[test]
    fn relative_ttl_is_normalized_exactly_once() {
        let baked = ExpiresAt::relative(5_000, 1_000_000).unwrap();
        assert_eq!(baked.unix_millis(), 1_005_000);
        // The envelope stores only the absolute value; re-submitting the
        // same absolute expiry later cannot extend it.
        let mut envelope = envelope("ttl");
        envelope.expires_at = Some(baked);
        assert_eq!(
            Envelope::from_canonical_bytes(&envelope.canonical_bytes())
                .unwrap()
                .expires_at
                .map(|expiry| expiry.unix_millis()),
            Some(1_005_000)
        );
        assert!(ExpiresAt::from_unix_millis(0).is_err());
    }

    #[test]
    fn harness_and_address_roundtrip_canonically() {
        let address = address();
        let parsed = NativeAddress::parse(&address.to_canonical_string()).unwrap();
        assert_eq!(address, parsed);
        assert!(NativeAddress::parse("host/codex").is_err());
        assert!(Harness::parse("Codex").is_err());
    }
}
