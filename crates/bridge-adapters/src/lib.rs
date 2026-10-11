//! Agent Bridge native adapters: attestation, lifecycle, carriers and hooks.
//!
//! This crate owns the M-002 boundary of Agent Bridge: everything that turns
//! a frozen core attempt into an interaction with one native harness session
//! (Codex or Claude Code), and every observation about that session that the
//! core's `auto` selector and no-wake guards are allowed to rely on.
//!
//! Module layout:
//! - [`attest`]: attested bindings — exact native address, actual actor,
//!   fenced endpoint epochs, loaded capabilities and fail-closed
//!   root/child correlation (the `bridge-root-caller` obligations).
//! - [`lifecycle`]: loaded lifecycle observation and the explicit no-wake
//!   policy; unknown, disconnected and `notLoaded` are never inactive.
//! - [`dispatch`]: the adapter side of the consumed `bridge-dispatch`
//!   contract — fenced attempt validation and the one-automatic-attempt
//!   gate that keeps unknown outcomes retained without replay.
//! - [`codex`]: the queue-only Codex message carrier and its confined
//!   helper specification (no load, resume or start exists on its surface).
//! - [`claude`]: the Claude `later` carrier, held receipts with a stable
//!   daemon callback, `written_no_receipt` tracking and uncertainty tiers.
//! - [`hook`]: the quiet root hook drain — manifest committed before any
//!   payload reply, with the full hook fault envelope.
//! - [`auto`]: dispatch-time selection between the two existing paths.
//! - [`evidence`]: the distinct native evidence tiers as immutable records.
//! - [`qualify`]: loaded-version attestation and baseline alignment records.
//!
//! Boundary note: real native transports (GUI front ends, desktop daemons,
//! working Claude sessions) are qualification-gated and intentionally absent.
//! Every operation here is a deterministic library operation over injected
//! clocks and owned fixture state; tests use isolated synthetic publishers
//! and owned fixture processes only. Nothing in this crate wakes a peer,
//! answers a permission request, loads/resumes/starts a native target, or
//! retries a possibly accepted handoff.

pub mod attest;
pub mod auto;
pub mod claude;
pub mod codex;
pub mod dispatch;
pub mod evidence;
pub mod hook;
pub mod lifecycle;
pub mod qualify;

/// Structured non-success for the adapter crate.
///
/// Every failure names its class and the boundary rule it protects; callers
/// never need to parse strings, and no variant implies delivery happened.
#[derive(Debug)]
pub enum AdapterError {
    /// Correlation evidence was missing, duplicated, stale or conflicting;
    /// the caller is refused (fail closed) and nothing was invoked.
    Correlation(attest::CorrelationError),
    /// A fenced attempt was refused before any invocation: stale epoch,
    /// actor mismatch, deadline exceeded or missing permission.
    FenceRefused(&'static str),
    /// The requested carrier or capability is unsupported on the loaded
    /// host; refused before production acceptance, never silently routed
    /// to another recipient or mode.
    Unsupported(&'static str),
    /// A no-wake guard or hold applied (pause, permission/input wait,
    /// disconnected, archived, unknown); no invocation was made.
    Hold(&'static str),
    /// A child actor attempted an operation reserved for the verified root
    /// (drain, emission or acknowledgement); refused.
    ChildRefused(&'static str),
    /// Invalid input at this crate's trust boundary (malformed spec,
    /// unallowlisted helper path, bad fixture argument). Nothing ran.
    Invalid(String),
}

impl std::fmt::Display for AdapterError {
    /// Compact one-line rendering naming the class and details.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::Correlation(error) => write!(f, "correlation refused: {error}"),
            AdapterError::FenceRefused(rule) => write!(f, "fence refused: {rule}"),
            AdapterError::Unsupported(rule) => write!(f, "unsupported capability: {rule}"),
            AdapterError::Hold(reason) => write!(f, "hold: {reason}"),
            AdapterError::ChildRefused(rule) => write!(f, "child refused: {rule}"),
            AdapterError::Invalid(detail) => write!(f, "invalid adapter input: {detail}"),
        }
    }
}

impl std::error::Error for AdapterError {
    /// Chains the correlation error when present.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AdapterError::Correlation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<attest::CorrelationError> for AdapterError {
    /// Converts a fail-closed correlation outcome into [`AdapterError`].
    fn from(error: attest::CorrelationError) -> Self {
        AdapterError::Correlation(error)
    }
}
