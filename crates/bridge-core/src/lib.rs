//! Agent Bridge core crate: the durable communication service's domain types
//! and local storage foundation.
//!
//! This crate owns the canonical event identity model shared by every family
//! publisher (Agent Run, Agent IDE, Agent Worktree) and by the restricted
//! orchestrator surface: the publisher envelope, its canonical serialization
//! and hash, and the SQLite-backed custody store that makes an accepted event
//! immutable and durably recoverable.
//!
//! Module layout:
//! - [`types`]: canonical address, envelope, policy and expiry types with
//!   validation and canonical hashing.
//!
//! Boundary note: authentication and authorization of publishers, the IPC
//! protocol and dispatch state machinery live in later tasks of this Module
//! and are intentionally absent here.

pub mod types;

pub use types::{
    CoreError, Envelope, EnvelopeHash, EventId, ExpiresAt, Harness, Kind, Metadata, Mode,
    NativeAddress, Payload, Policy, PublisherId, SCHEMA_VERSION, StreamId,
};

/// Byte bound applied to every bounded UTF-8 string field in the envelope.
///
/// The value is deliberately conservative for the first delivery scope; it is
/// a validation constant, not an owner-required cap, and may be tuned by a
/// later task without changing the canonical form of existing envelopes.
pub const MAX_FIELD_BYTES: usize = 256;

/// Maximum payload size accepted in one envelope, in bytes of UTF-8.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum number of metadata entries in one envelope.
pub const MAX_METADATA_ENTRIES: usize = 16;
