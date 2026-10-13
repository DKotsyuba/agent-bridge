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
//! - [`storage`] and [`schema`]: transactional custody storage with
//!   idempotent publication, conflict detection, stream watermarks,
//!   admission caps and forward-only schema migration.
//! - [`framing`]: source-wrapped, escaped, bounded manifests.
//! - [`dispatch`]: fenced attempts over a frozen manifest and the carrier
//!   contract.
//! - [`recovery`]: evidence tiers, retained incidents, audited operator
//!   recovery and reconciliation.
//! - [`service`]: the authenticated local socket service and its lifecycle.
//!
//! Boundary note: storage callers pass an already-authenticated publisher
//! identity; the service authenticates every ingress. Native adapters are
//! consumers of the [`dispatch`] contract and are not part of this crate.

pub mod dispatch;
pub mod framing;
pub mod producer;
pub mod recovery;
pub mod schema;
pub mod service;
pub mod storage;
pub mod types;
pub mod universal;
pub mod wire;

pub use producer::{ProducerAuthorizer, ProducerPolicy, ProducerPolicyGrant, UniversalLimits};
pub use universal::{RegistrationClaimState, RegistrationReconciliation, VerifiedRegistration};

pub use recovery::DeliveryEvidence;
pub use service::{
    Config, GrantConfig, PublishBody, Request, Response, Running, start as start_service,
    start_with_carriers,
};
pub use storage::{CustodyReceipt, EventState, Limits, PublishOutcome, Storage};
pub use types::{
    CoreError, Envelope, EnvelopeHash, EventId, ExpiresAt, Harness, Kind, MAX_SQLITE_INT, Metadata,
    Mode, NativeAddress, Payload, Policy, PublisherId, SCHEMA_VERSION, StreamId, validate_metadata,
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
