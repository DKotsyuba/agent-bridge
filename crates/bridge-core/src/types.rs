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

/// Largest unsigned value safely representable in SQLite's signed INTEGER.
///
/// `latest` revisions, absolute expiry milliseconds and any other u64 that
/// reaches durable storage must not exceed this bound; values above it are
/// rejected explicitly at validation (never silently wrapped by a signed
/// cast, which would turn a newer revision into an apparently stale one).
pub const MAX_SQLITE_INT: u64 = i64::MAX as u64;

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

/// Largest canonical harness identifier, in bytes.
pub const MAX_HARNESS_BYTES: usize = 32;

/// Harness (native host product) a recipient session lives in.
///
/// The harness decides which native store namespace and session identifier
/// kinds are meaningful; it is part of the recipient's canonical logical
/// address and never implied by a transport or a display name.
///
/// The set is open: any canonical identifier (1 to [`MAX_HARNESS_BYTES`] bytes
/// of `[a-z0-9-]`, starting with a letter) names a harness, and whether a
/// harness is served is decided by the adapter's harness profiles, never here.
/// The built-in harnesses keep their canonical names ([`Harness::CODEX`],
/// [`Harness::CLAUDE_CODE`], [`Harness::OPENCODE`]) and, in serde form, their
/// historical spellings (`Codex`, `ClaudeCode`, `OpenCode`): those spellings are
/// part of every stored canonical envelope and its frozen hash, so they never
/// change. Any other harness serializes as its canonical identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Harness {
    /// Identifier length in bytes; at least one.
    len: u8,
    /// ASCII identifier bytes, zero-padded after `len`.
    bytes: [u8; MAX_HARNESS_BYTES],
}

impl Harness {
    /// A Codex installation; sessions are identified by thread id.
    pub const CODEX: Harness = Harness::from_static("codex");
    /// A Claude Code installation; sessions are identified by session id.
    pub const CLAUDE_CODE: Harness = Harness::from_static("claude-code");
    /// An OpenCode installation; sessions are identified by native session id.
    pub const OPENCODE: Harness = Harness::from_static("opencode");

    /// The built-in harnesses with their historical serde spellings.
    const BUILT_IN: [(Harness, &'static str); 3] = [
        (Harness::CODEX, "Codex"),
        (Harness::CLAUDE_CODE, "ClaudeCode"),
        (Harness::OPENCODE, "OpenCode"),
    ];

    /// Builds a harness from a compile-time identifier.
    ///
    /// # Panics
    ///
    /// When `name` is not a canonical identifier; in a constant this is a
    /// compile-time error.
    pub const fn from_static(name: &str) -> Harness {
        match Harness::from_bytes(name.as_bytes()) {
            Some(harness) => harness,
            None => panic!("invalid harness identifier"),
        }
    }

    /// Validates the canonical grammar and copies the identifier.
    const fn from_bytes(name: &[u8]) -> Option<Harness> {
        if name.is_empty() || name.len() > MAX_HARNESS_BYTES || !name[0].is_ascii_lowercase() {
            return None;
        }
        let mut bytes = [0u8; MAX_HARNESS_BYTES];
        let mut index = 0;
        while index < name.len() {
            let byte = name[index];
            if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
                return None;
            }
            bytes[index] = byte;
            index += 1;
        }
        Some(Harness {
            len: name.len() as u8,
            bytes,
        })
    }

    /// Canonical wire name of this harness, stable across schema revisions.
    ///
    /// Never display-derived: the names are part of the canonical address.
    pub fn as_str(&self) -> &str {
        // Only validated ASCII is ever stored, so this never falls back.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or_default()
    }

    /// Whether this is one of the harnesses Bridge ships code for.
    pub fn is_built_in(&self) -> bool {
        Harness::BUILT_IN.iter().any(|(harness, _)| harness == self)
    }

    /// Parses a harness from its canonical wire name.
    ///
    /// Returns [`CoreError::InvalidEnvelope`] for anything that is not a
    /// canonical identifier; there is no fuzzy matching and no default harness.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        Harness::from_bytes(value.as_bytes()).ok_or_else(|| {
            CoreError::InvalidEnvelope(format!("invalid harness identifier {value:?}"))
        })
    }

    /// The serde spelling: the historical name of a built-in harness, else the
    /// canonical identifier.
    fn serde_name(&self) -> &str {
        Harness::BUILT_IN
            .iter()
            .find(|(harness, _)| harness == self)
            .map_or_else(|| self.as_str(), |(_, legacy)| legacy)
    }

    /// Parses exactly the serde spelling written by [`Harness::serde_name`]: a
    /// built-in harness only by its historical name, any other harness by its
    /// canonical identifier. A built-in's canonical name is refused here so that
    /// one harness never has two serialized forms inside canonical envelopes.
    fn from_serde_name(value: &str) -> Result<Self, CoreError> {
        if let Some((harness, _)) = Harness::BUILT_IN
            .iter()
            .find(|(_, legacy)| *legacy == value)
        {
            return Ok(*harness);
        }
        let harness = Harness::parse(value)?;
        if harness.is_built_in() {
            return Err(CoreError::InvalidEnvelope(format!(
                "harness {value:?} must use its historical serialized name"
            )));
        }
        Ok(harness)
    }
}

impl fmt::Debug for Harness {
    /// Prints `Harness("<canonical id>")`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Harness").field(&self.as_str()).finish()
    }
}

impl fmt::Display for Harness {
    /// Prints the canonical identifier.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Harness {
    /// Writes the historical name of a built-in harness, else the canonical id.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.serde_name())
    }
}

impl<'de> Deserialize<'de> for Harness {
    /// Reads exactly the spelling [`Serialize`] writes; anything else refuses.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Harness::from_serde_name(&value).map_err(serde::de::Error::custom)
    }
}

/// Canonical logical address of one native recipient session.
///
/// Composed of host id, harness, native store namespace and native session
/// id, exactly as defined by the technical plan: the namespace identifies the
/// actual native store under the OS owner — never a cwd or
/// project name. Fork, `/clear` or a new native id produces a different
/// recipient; display names never participate in routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawNativeAddress")]
pub struct NativeAddress {
    /// Identifier of the OS host owning the native store.
    pub host_id: String,
    /// Native harness product of the session.
    pub harness: Harness,
    /// Native store namespace under the OS owner (one per harness product in a
    /// native daemon's harness policy).
    pub native_store_namespace: String,
    /// Native session identifier (Codex thread id or Claude session id).
    pub native_session_id: String,
}

/// Unvalidated wire shape of [`NativeAddress`]; deserialization converts it
/// through [`NativeAddress::validate`] so no address skips the field rules.
#[derive(Deserialize)]
struct RawNativeAddress {
    /// Host identifier as received.
    host_id: String,
    /// Harness as received.
    harness: Harness,
    /// Native store namespace as received.
    native_store_namespace: String,
    /// Native session id as received.
    native_session_id: String,
}

impl TryFrom<RawNativeAddress> for NativeAddress {
    type Error = CoreError;

    /// Validates every component of a deserialized address.
    fn try_from(raw: RawNativeAddress) -> Result<Self, CoreError> {
        NativeAddress::new(
            raw.host_id,
            raw.harness,
            raw.native_store_namespace,
            raw.native_session_id,
        )
    }
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

    /// Canonical text form used in logs, status output and storage keys.
    ///
    /// Four slash-separated components, harness as its canonical wire name.
    /// Component text may itself contain slashes (path namespaces, slash-
    /// bearing native session ids), so each component is percent-encoded
    /// (`/` as `%2F`, `%` as `%25`) first: the encoding is injective and
    /// lossless, and distinct component tuples always produce distinct text.
    /// Round-trips through [`NativeAddress::parse`]; not used for hashing
    /// (the envelope serialization is).
    pub fn to_canonical_string(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            encode_component(&self.host_id),
            self.harness.as_str(),
            encode_component(&self.native_store_namespace),
            encode_component(&self.native_session_id),
        )
    }

    /// Parses the canonical text form produced by
    /// [`NativeAddress::to_canonical_string`].
    ///
    /// Refuses anything that is not exactly four encoded components with a
    /// known harness name, malformed percent escapes, and components that
    /// fail validation.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() != 4 {
            return Err(CoreError::InvalidEnvelope(
                "address must have four slash-separated components".into(),
            ));
        }
        NativeAddress::new(
            decode_component(parts[0])?,
            Harness::parse(parts[1])?,
            decode_component(parts[2])?,
            decode_component(parts[3])?,
        )
    }
}

/// Percent-encodes one address component losslessly.
///
/// Only the two bytes that would break the four-separator structure are
/// escaped (`%` and `/`); everything else (already validated free of
/// control characters) passes through unchanged.
fn encode_component(component: &str) -> String {
    component.replace('%', "%25").replace('/', "%2F")
}

/// Strictly percent-decodes one address component.
///
/// Every `%` must be followed by exactly two uppercase or lowercase hex
/// digits; anything else is [`CoreError::InvalidEnvelope`]. Decoding works
/// on raw bytes so multi-byte UTF-8 passes through unchanged, and the
/// result must be valid UTF-8; the decoded text is re-validated by
/// [`NativeAddress::new`].
fn decode_component(component: &str) -> Result<String, CoreError> {
    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(component.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = bytes
                    .get(index + 1..index + 3)
                    .and_then(|slice| std::str::from_utf8(slice).ok())
                    .and_then(|text| u8::from_str_radix(text, 16).ok());
                let byte = hex.ok_or_else(|| {
                    CoreError::InvalidEnvelope(format!(
                        "malformed percent escape in address component at byte {index}"
                    ))
                })?;
                decoded.push(byte);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| {
        CoreError::InvalidEnvelope("address component is not valid UTF-8 after decoding".into())
    })
}

/// A validated, bounded producer-side event identifier.
///
/// Stable across retries of the same publication and unique per publisher:
/// custody deduplication keys on `(publisher, event id)`. Not a UUID
/// freshness signal and not a recipient-visible delivery correlation id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct EventId(String);

impl TryFrom<String> for EventId {
    type Error = CoreError;

    /// Validates a deserialized EventId through its constructor rules.
    fn try_from(value: String) -> Result<Self, CoreError> {
        EventId::new(value)
    }
}

impl EventId {
    /// Validates and wraps an event id (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("event_id", &value, MAX_FIELD_BYTES)?;
        Ok(EventId(value))
    }

    /// Re-checks the id rules on a value that did not pass through
    /// [`EventId::new`] (for example one produced by deserialization).
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_field("event_id", &self.0, MAX_FIELD_BYTES)
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
#[serde(try_from = "String")]
pub struct PublisherId(String);

impl TryFrom<String> for PublisherId {
    type Error = CoreError;

    /// Validates a deserialized PublisherId through its constructor rules.
    fn try_from(value: String) -> Result<Self, CoreError> {
        PublisherId::new(value)
    }
}

impl PublisherId {
    /// Validates and wraps a publisher id (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("publisher_id", &value, MAX_FIELD_BYTES)?;
        Ok(PublisherId(value))
    }

    /// Re-checks the id rules on a value that did not pass through
    /// [`PublisherId::new`] (for example one produced by deserialization).
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_field("publisher_id", &self.0, MAX_FIELD_BYTES)
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
#[serde(try_from = "String")]
pub struct Kind(String);

impl TryFrom<String> for Kind {
    type Error = CoreError;

    /// Validates a deserialized Kind through its constructor rules.
    fn try_from(value: String) -> Result<Self, CoreError> {
        Kind::new(value)
    }
}

impl Kind {
    /// Validates and wraps a kind (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("kind", &value, 64)?;
        Ok(Kind(value))
    }

    /// Re-checks the kind rules on a value that did not pass through
    /// [`Kind::new`] (for example one produced by deserialization).
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_field("kind", &self.0, 64)
    }

    /// The kind text, validated at construction.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An authoritative replaceable snapshot stream identifier for `latest`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct StreamId(String);

impl TryFrom<String> for StreamId {
    type Error = CoreError;

    /// Validates a deserialized StreamId through its constructor rules.
    fn try_from(value: String) -> Result<Self, CoreError> {
        StreamId::new(value)
    }
}

impl StreamId {
    /// Validates and wraps a stream id (non-empty, bounded, no controls).
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_field("stream_id", &value, MAX_FIELD_BYTES)?;
        Ok(StreamId(value))
    }

    /// Re-checks the stream rules on a value that did not pass through
    /// [`StreamId::new`] (for example one produced by deserialization).
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_field("stream_id", &self.0, MAX_FIELD_BYTES)
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

impl Mode {
    /// Canonical storage/wire name of this requested mode.
    ///
    /// Part of the coalescing scope key and of grant allowlists; never
    /// display-derived.
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::Inject => "inject",
            Mode::Message => "message",
            Mode::Auto => "auto",
        }
    }

    /// Parses a mode from its canonical wire name.
    ///
    /// Refuses any other spelling; there is no default mode.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "inject" => Ok(Mode::Inject),
            "message" => Ok(Mode::Message),
            "auto" => Ok(Mode::Auto),
            other => Err(CoreError::InvalidEnvelope(format!(
                "unknown mode {other:?}"
            ))),
        }
    }
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
    /// For `Latest` this re-checks the stream id (covering deserialized
    /// values) and refuses a revision above [`MAX_SQLITE_INT`], which
    /// could not be stored without wrapping into an apparently stale
    /// value. For `Batch` the group text is checked. Returns
    /// [`CoreError::InvalidEnvelope`] on failure.
    pub fn validate(&self) -> Result<(), CoreError> {
        match self {
            Policy::KeepAll => Ok(()),
            Policy::Latest { stream, revision } => {
                stream.validate()?;
                if *revision > MAX_SQLITE_INT {
                    return Err(CoreError::InvalidEnvelope(format!(
                        "latest revision {revision} exceeds the supported bound {MAX_SQLITE_INT}"
                    )));
                }
                Ok(())
            }
            Policy::Batch { group } => validate_field("group", group, MAX_FIELD_BYTES),
        }
    }

    /// The policy's canonical name for grant allowlists.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Policy::KeepAll => "keep_all",
            Policy::Latest { .. } => "latest",
            Policy::Batch { .. } => "batch",
        }
    }
}

/// Absolute expiry of an event, in Unix epoch milliseconds.
///
/// Relative TTLs are normalized exactly once, at the edge where a request is
/// turned into an envelope ([`ExpiresAt::relative`]); the envelope stores
/// only the absolute value, so a later retry cannot extend expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u64")]
pub struct ExpiresAt(u64);

impl TryFrom<u64> for ExpiresAt {
    type Error = CoreError;

    /// Validates a deserialized expiry through the constructor rules.
    fn try_from(millis: u64) -> Result<Self, CoreError> {
        ExpiresAt::from_unix_millis(millis)
    }
}

impl ExpiresAt {
    /// Wraps an absolute Unix-epoch-milliseconds expiry.
    ///
    /// Refuses zero (an unset expiry is represented by `None` on the
    /// envelope, not by a sentinel value) and values above
    /// [`MAX_SQLITE_INT`], which could not be stored without a wrapping
    /// signed cast.
    pub fn from_unix_millis(millis: u64) -> Result<Self, CoreError> {
        if millis == 0 {
            return Err(CoreError::InvalidEnvelope(
                "expires_at must be a non-zero absolute timestamp".into(),
            ));
        }
        if millis > MAX_SQLITE_INT {
            return Err(CoreError::InvalidEnvelope(format!(
                "expires_at {millis} exceeds the supported bound {MAX_SQLITE_INT}"
            )));
        }
        Ok(ExpiresAt(millis))
    }

    /// Re-checks the expiry rules on a value that did not pass through
    /// [`ExpiresAt::from_unix_millis`] (for example one produced by
    /// deserialization).
    pub fn validate(self) -> Result<(), CoreError> {
        ExpiresAt::from_unix_millis(self.0).map(|_| ())
    }

    /// Normalizes a relative TTL once: `now_ms + ttl_ms`.
    ///
    /// `ttl_ms` may be zero (expire immediately); the result is the absolute
    /// value the envelope will freeze, bounded as above.
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
#[serde(try_from = "String")]
pub struct Payload(String);

impl TryFrom<String> for Payload {
    type Error = CoreError;

    /// Validates a deserialized payload through the constructor rules.
    fn try_from(value: String) -> Result<Self, CoreError> {
        Payload::new(value)
    }
}

impl Payload {
    /// Validates and wraps a payload.
    ///
    /// Rejects payloads over [`MAX_PAYLOAD_BYTES`] bytes of UTF-8. Control
    /// characters are accepted here — payloads are producer content; the
    /// framing layer rejects forbidden controls at render time.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let payload = Payload(value.into());
        payload.validate()?;
        Ok(payload)
    }

    /// Re-checks the payload bounds on a value that did not pass through
    /// [`Payload::new`] (for example one produced by deserialization).
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.0.len() > MAX_PAYLOAD_BYTES {
            return Err(CoreError::InvalidEnvelope(format!(
                "payload exceeds {MAX_PAYLOAD_BYTES} bytes"
            )));
        }
        Ok(())
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
#[serde(try_from = "RawEnvelope")]
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

/// Unvalidated wire shape of [`Envelope`]; deserialization converts it
/// through [`Envelope::validate`], so a value built by `Deserialize` has
/// passed exactly the constructor rules (schema version, bounds, ranges).
#[derive(Deserialize)]
struct RawEnvelope {
    /// Schema version as received.
    schema_version: u16,
    /// Publisher as received.
    publisher: PublisherId,
    /// Event id as received.
    event_id: EventId,
    /// Recipient as received.
    recipient: NativeAddress,
    /// Kind as received.
    kind: Kind,
    /// Mode as received.
    mode: Mode,
    /// Policy as received.
    policy: Policy,
    /// Payload as received.
    payload: Payload,
    /// Metadata as received.
    metadata: Metadata,
    /// Expiry as received.
    expires_at: Option<ExpiresAt>,
}

impl TryFrom<RawEnvelope> for Envelope {
    type Error = CoreError;

    /// Validates a deserialized envelope as a whole.
    fn try_from(raw: RawEnvelope) -> Result<Self, CoreError> {
        let envelope = Envelope {
            schema_version: raw.schema_version,
            publisher: raw.publisher,
            event_id: raw.event_id,
            recipient: raw.recipient,
            kind: raw.kind,
            mode: raw.mode,
            policy: raw.policy,
            payload: raw.payload,
            metadata: raw.metadata,
            expires_at: raw.expires_at,
        };
        envelope.validate()?;
        Ok(envelope)
    }
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
        let envelope = Envelope {
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
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates an envelope received through storage or IPC.
    ///
    /// This is the one shared trust-boundary check: it applies exactly the
    /// constructor rules to every component — including values that reached
    /// this struct through `Deserialize`, which bypasses the newtype
    /// constructors. Malformed publisher, event id, kind, stream, payload,
    /// expiry, address, policy or metadata makes the whole envelope invalid
    /// before it can be hashed, stored, acknowledged or disclosed.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CoreError::InvalidEnvelope(format!(
                "unsupported schema_version {}",
                self.schema_version
            )));
        }
        self.publisher.validate()?;
        self.event_id.validate()?;
        self.kind.validate()?;
        self.payload.validate()?;
        if let Some(expiry) = self.expires_at {
            expiry.validate()?;
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
#[serde(try_from = "String")]
pub struct EnvelopeHash(
    /// Lowercase hex text; private so every value passed a hex check.
    String,
);

impl TryFrom<String> for EnvelopeHash {
    type Error = CoreError;

    /// Accepts exactly 64 lowercase hexadecimal characters.
    fn try_from(value: String) -> Result<Self, CoreError> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(EnvelopeHash(value))
        } else {
            Err(CoreError::InvalidEnvelope(
                "envelope hash must be 64 lowercase hex characters".into(),
            ))
        }
    }
}

impl EnvelopeHash {
    /// Hashes raw canonical bytes through SHA-256 into a hex hash.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Self {
        EnvelopeHash(sha256_hex(bytes))
    }

    /// The 64-character lowercase hex text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SHA-256 of `bytes` as 64 lowercase hex characters.
///
/// Shared by envelope identity hashing and frozen manifest hashing.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

/// Lowercase-hex encodes a byte slice without external dependencies.
///
/// Used only for hash digests; not a general formatting utility.
fn hex_encode(bytes: &[u8]) -> String {
    /// Lowercase hexadecimal digit alphabet indexed by nibble value.
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
    /// Dispatch was refused by a durable recipient policy (no-wake/pause).
    PolicyHold {
        /// Canonical recipient address text.
        recipient: String,
        /// Why the recipient is held.
        reason: String,
    },
    /// A fenced dispatch transition was refused (stale fence, foreign
    /// state, unresolved uncertainty or missing event); nothing was invoked.
    Fence(String),
    /// The recipient is known not to support the requested mode (its
    /// attested capabilities lack the needed path). Permanent, unlike a
    /// transient hold: the producer keeps its intent and its own compatible
    /// route, and nothing was accepted.
    Unsupported(String),
    /// The database was busy, locked or out of space; the transaction was
    /// rolled back and changed nothing, so the operation may be retried with
    /// the same key. An I/O failure during COMMIT is reported as
    /// [`CoreError::Storage`] instead: its outcome is uncertain and the
    /// caller reconciles through the idempotent key.
    Busy(String),
    /// Stored data violated an invariant this build wrote (foreign or
    /// corrupted rows, a hash that no longer matches its bytes, a counter
    /// out of range). The affected record is never used; nothing was
    /// changed by the failing call.
    Integrity(String),
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
            CoreError::PolicyHold { recipient, reason } => {
                write!(f, "recipient {recipient} is held: {reason}")
            }
            CoreError::Fence(detail) => write!(f, "dispatch fence refused: {detail}"),
            CoreError::Unsupported(detail) => write!(f, "unsupported: {detail}"),
            CoreError::Busy(detail) => write!(f, "storage busy: {detail}"),
            CoreError::Integrity(detail) => write!(f, "storage integrity violation: {detail}"),
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
    /// Converts a raw SQLite error: lock contention and a full disk become
    /// retryable [`CoreError::Busy`], everything else [`CoreError::Storage`].
    fn from(error: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(failure, _) = &error
            && matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy
                    | rusqlite::ErrorCode::DatabaseLocked
                    | rusqlite::ErrorCode::DiskFull
            )
        {
            return CoreError::Busy(error.to_string());
        }
        CoreError::Storage(error)
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for the canonical identity model.

    use super::*;

    /// A minimal valid address for tests.
    fn address() -> NativeAddress {
        NativeAddress::new("host-1", Harness::CLAUDE_CODE, "default", "session-9").unwrap()
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

    /// The envelope hash is stable regardless of construction order of the
    /// sorted metadata.
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

    /// Any identity-content change produces a different envelope hash.
    #[test]
    fn hash_changes_with_identity_content() {
        let left = envelope("body");
        let mut right = envelope("different body");
        right.event_id = left.event_id.clone();
        assert_ne!(left.envelope_hash(), right.envelope_hash());
    }

    /// An envelope round-trips exactly through its canonical bytes with the
    /// same hash.
    #[test]
    fn envelope_roundtrips_through_canonical_bytes() {
        let original = envelope("round trip");
        let bytes = original.canonical_bytes();
        let parsed = Envelope::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.envelope_hash(), original.envelope_hash());
    }

    /// Policy validation refuses invalid stream and group shapes.
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

    /// Field validation refuses empty, oversized and control-bearing
    /// identifiers, addresses and payloads.
    #[test]
    fn field_validation_refuses_control_chars_and_oversize() {
        assert!(EventId::new("bad\u{1}id").is_err());
        assert!(EventId::new("").is_err());
        assert!(Kind::new("x".repeat(65)).is_err());
        assert!(Payload::new("x".repeat(MAX_PAYLOAD_BYTES + 1)).is_err());
        assert!(NativeAddress::new("h", Harness::CODEX, "ns", "").is_err());
    }

    /// A relative TTL is normalized to an absolute expiry exactly once; the
    /// envelope never stores a relative value.
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

    /// Harness names and percent-encoded addresses round-trip through the
    /// canonical text form and refuse malformed input.
    #[test]
    fn harness_and_address_roundtrip_canonically() {
        let address = address();
        let parsed = NativeAddress::parse(&address.to_canonical_string()).unwrap();
        assert_eq!(address, parsed);
        assert!(NativeAddress::parse("host/codex").is_err());
        assert!(Harness::parse("Codex").is_err());
    }

    #[test]
    /// The harness set is open: any canonical identifier parses and
    /// round-trips through the canonical address, everything else refuses.
    fn open_harness_identifiers_follow_the_canonical_grammar() {
        for valid in [
            "zcode",
            "a",
            "cursor-agent-2",
            &"x".repeat(MAX_HARNESS_BYTES),
        ] {
            let harness = Harness::parse(valid).unwrap();
            assert_eq!(harness.as_str(), valid);
            assert!(!harness.is_built_in());
            let address = NativeAddress::new("h", harness, "ns", "s/1").unwrap();
            assert_eq!(
                NativeAddress::parse(&address.to_canonical_string()).unwrap(),
                address
            );
        }
        for invalid in [
            "",
            "Zcode",
            "1code",
            "-code",
            "z_code",
            "z code",
            "zcode/x",
            "zcödе",
            &"x".repeat(MAX_HARNESS_BYTES + 1),
        ] {
            assert!(Harness::parse(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(Harness::parse("claude-code").unwrap(), Harness::CLAUDE_CODE);
        assert!(Harness::CODEX.is_built_in() && Harness::OPENCODE.is_built_in());
    }

    #[test]
    /// Built-in harnesses keep their historical serde spellings, which are part
    /// of every stored canonical envelope and its frozen hash; any other harness
    /// serializes as its canonical identifier, and no harness has two forms.
    fn harness_serde_form_is_frozen_for_built_ins_and_canonical_otherwise() {
        for (harness, serialized) in [
            (Harness::CODEX, "\"Codex\""),
            (Harness::CLAUDE_CODE, "\"ClaudeCode\""),
            (Harness::OPENCODE, "\"OpenCode\""),
            (Harness::from_static("zcode"), "\"zcode\""),
        ] {
            assert_eq!(serde_json::to_string(&harness).unwrap(), serialized);
            assert_eq!(
                serde_json::from_str::<Harness>(serialized).unwrap(),
                harness
            );
        }
        for refused in [
            "\"codex\"",
            "\"claude-code\"",
            "\"opencode\"",
            "\"Zcode\"",
            "\"\"",
        ] {
            assert!(
                serde_json::from_str::<Harness>(refused).is_err(),
                "{refused}"
            );
        }
        let address = NativeAddress::new("h", Harness::CLAUDE_CODE, "ns", "s").unwrap();
        assert_eq!(
            serde_json::to_string(&address).unwrap(),
            r#"{"host_id":"h","harness":"ClaudeCode","native_store_namespace":"ns","native_session_id":"s"}"#
        );
    }

    #[test]
    /// Busy, locked and full storage conditions map to the single retryable
    /// busy class; integrity failures never do.
    fn busy_locked_and_full_storage_map_to_retryable_busy_only() {
        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_LOCKED,
            rusqlite::ffi::SQLITE_FULL,
        ] {
            let error = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert!(
                matches!(CoreError::from(error), CoreError::Busy(_)),
                "{code}"
            );
        }
        let io = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
            None,
        );
        assert!(
            matches!(CoreError::from(io), CoreError::Storage(_)),
            "an I/O failure is not a retryable busy condition"
        );
    }

    #[test]
    /// Deserialized newtype values pass the same validation as constructed
    /// ones.
    fn deserialized_values_are_validated() {
        assert!(serde_json::from_str::<EventId>("\"\"").is_err());
        assert!(serde_json::from_str::<Payload>(&format!("\"{}\"", "x".repeat(70_000))).is_err());
        assert!(serde_json::from_str::<EnvelopeHash>("\"abc\"").is_err());
        assert!(serde_json::from_str::<ExpiresAt>("0").is_err());
        assert!(serde_json::from_str::<ExpiresAt>("1700000000000").is_ok());
    }
}
