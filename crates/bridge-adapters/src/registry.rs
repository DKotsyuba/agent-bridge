//! Protected registry: harness incarnations, endpoint epochs, lifecycle and
//! fail-closed actor correlation.
//!
//! The registry lives in the Bridge daemon and is fed only by connections
//! on the adapter channel ([`crate::server`]) whose peer the kernel
//! identifies. A peer counts as a *hook of a harness* only when its parent
//! chain reaches a qualified harness executable through allowlisted
//! intermediates (shells), as the same user, and that harness's own store
//! is a configured profile. That harness process incarnation (PID plus
//! start time) is the protected channel: every record below is scoped to
//! it.
//!
//! - **Bindings.** The first hook of an address from a harness incarnation,
//!   the owner's own non-`compact` `SessionStart` (never a Claude child's,
//!   never a `compact` restart, which keep the binding, its epoch and its
//!   records), or a different live incarnation renews the binding
//!   with a strictly larger endpoint epoch; every older record becomes
//!   stale. A binding held by another live incarnation refuses the
//!   newcomer as conflicting.
//! - **Lifecycle.** Hook events are the owner session's own lifecycle feed:
//!   prompt/tool events are active, the owner's `Stop` is idle, permission
//!   and question prompts are awaiting input, `SessionEnd` and a dead
//!   incarnation are unknown. A new or renewed binding starts unknown and
//!   leaves it only on such a positive owner event (a first `SubagentStop`,
//!   a child's event or an unrelated notification never makes it idle).
//!   Unknown is never inactive.
//! - **Call records.** Each `PreToolUse` records its per-call id
//!   (`tool_use_id`, the same value the harness later presents as Claude
//!   `claudecode/toolUseId` or Codex `callId`) with the actual actor. A
//!   caller is attested only by joining exactly one fresh, unconsumed
//!   record of the current epoch from the *same* harness incarnation;
//!   a join consumes it, so a replay is a duplicate.
//!
//! What this does not prove: same-user code running inside the harness's
//! own tool sandbox (for example a model shell command) shares the
//! harness's process ancestry and could replay the hook client with forged
//! native JSON. That is the plan's excluded "hostile same-UID code" case;
//! deployments restrict it by denying the channel socket to the harness's
//! tool sandbox. Model arguments, display names, cwd, inherited foreign
//! environment and PIDs alone are never evidence here.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use bridge_core::dispatch::{Attestation, Capabilities, Lifecycle};
use bridge_core::{Harness, NativeAddress};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::os::{self, PeerIdentity, ProcessFacts};

mod assertions;
mod claims;
pub(crate) use claims::EvidenceClaim;

/// Largest accepted native identifier (session, agent, call id), in bytes.
pub const MAX_NATIVE_ID_BYTES: usize = 256;

/// Default bound of retained call records; the oldest are evicted first,
/// which can only turn a later join into a refusal.
pub const DEFAULT_MAX_CALL_RECORDS: usize = 8_192;

/// Default bound of retained bindings.
pub const DEFAULT_MAX_BINDINGS: usize = 4_096;

/// Default largest age of a call record a caller may join, in milliseconds.
pub const DEFAULT_MAX_CALL_AGE_MS: u64 = 10 * 60_000;

/// One executable build qualified for a profile, and what it supports.
///
/// Capabilities are qualified support of this exact loaded build (matched
/// by resolved path *and* SHA-256 of the file the process was started
/// from), not network liveness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualifiedExecutable {
    /// Absolute resolved path of the harness executable.
    pub path: PathBuf,
    /// Lowercase hex SHA-256 of the qualified file.
    pub sha256: String,
    /// Human version label recorded in proof references.
    pub version: String,
    /// Root hook context injection is qualified on this build.
    pub inject: bool,
    /// The harness's message carrier is qualified on this build.
    pub message: bool,
}

/// One native store (home/profile) of one harness under this OS user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The `native_store_namespace` component of addresses in this store.
    pub namespace: String,
    /// Harness product of the store.
    pub harness: Harness,
    /// Absolute store directory (`CODEX_HOME`, Claude config directory).
    pub store: PathBuf,
    /// Qualified harness builds that may own sessions in this store.
    pub executables: Vec<QualifiedExecutable>,
}

/// Registry configuration, normally the `[adapters]` table of the daemon
/// configuration (operator-owned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// `host_id` component of every address this daemon attests.
    pub host_id: String,
    /// Configured stores.
    pub profiles: Vec<Profile>,
    /// Executables allowed between a peer and its harness (shells that
    /// launch hook commands). The peer's own executable is not checked.
    #[serde(default = "default_intermediates")]
    pub intermediates: Vec<PathBuf>,
    /// Largest age of a joinable call record, in milliseconds.
    #[serde(default = "default_call_age")]
    pub max_call_age_ms: u64,
    /// Bridge-owned relay builds (for example the restricted MCP's root
    /// daemon) that may redeem sealed caller proofs. Empty: redemption
    /// always refuses.
    #[serde(default)]
    pub relays: Vec<RelayExecutable>,
    /// Optional generic backend audiences; absent preserves legacy deployments.
    #[serde(default)]
    pub audiences: Vec<BackendAudience>,
}

/// One relay build allowed to redeem sealed caller proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayExecutable {
    /// Absolute resolved executable path of the relay process.
    pub path: PathBuf,
    /// Lowercase hex SHA-256 of the qualified relay build.
    pub sha256: String,
}

/// One generic detached backend audience, scoped to an authenticated producer.
/// Names have no product meaning. Kernel peer ownership and this exact warmed
/// executable build must match before invocation facts are consumed/disclosed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendAudience {
    /// Opaque configured audience name, nonempty and bounded to native ID limits.
    pub name: String,
    /// Stable authenticated core producer identity, independent of token rotation.
    pub producer: String,
    /// Exact backend executable path and qualified loaded-build digest.
    pub executable: RelayExecutable,
}

/// Lifetime of a sealed caller proof, in milliseconds.
pub const SEALED_PROOF_TTL_MS: u64 = 30_000;

/// Most sealed proofs outstanding at once; sealing refuses beyond it.
const MAX_SEALED: usize = 1_024;

/// One outstanding sealed proof.
#[derive(Debug, Clone)]
struct Sealed {
    /// The caller facts fixed at issue time.
    caller: VerifiedCaller,
    /// Canonical address of the caller's binding.
    binding: String,
    /// Harness incarnation of the issuing frontend.
    harness: (u32, u64),
    /// Expiry (Unix epoch ms).
    expires_ms: u64,
    /// Original source-use identity, unchanged through sealing.
    source_use_key: String,
    /// Original protected native per-call identifier.
    native_call_id: String,
    /// Positive native host-call classification retained through sealing.
    tool_name: Option<String>,
}

impl Sealed {
    /// Bounds v1 use to both the original protected observation lifetime and
    /// the legacy transfer proof lifetime. Sealing never renews native evidence;
    /// legacy redemption independently retains its established proof expiry.
    fn source_expires_at_ms(&self, max_call_age_ms: u64) -> u64 {
        self.expires_ms
            .min(self.caller.observed_at_ms().saturating_add(max_call_age_ms))
    }
}

/// Shells that may sit between a harness and its hook command.
fn default_intermediates() -> Vec<PathBuf> {
    [
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/bin/dash",
        "/usr/bin/env",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// Serde default for [`RegistryConfig::max_call_age_ms`].
fn default_call_age() -> u64 {
    DEFAULT_MAX_CALL_AGE_MS
}

/// Why caller or hook correlation refused. Every variant fails closed:
/// nothing is attested, drained, routed or redirected to a parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationError {
    /// No attestation provider is configured (the root ingress default).
    Unattested,
    /// No trusted record or binding exists for the presented identifier.
    Missing(String),
    /// The identifier was already consumed or matches several identical
    /// records; a replay or an ambiguous join refuses.
    Duplicate(String),
    /// The record predates the current epoch or is too old.
    Stale(String),
    /// Records, binding or presented fields disagree.
    Conflicting(String),
    /// The presented material is not caller evidence (not a hook of a
    /// qualified harness, wrong user, model arguments, foreign fields).
    NotEvidence(String),
    /// The registry could not be reached or answered malformed data.
    Unavailable(String),
}

impl CorrelationError {
    /// Stable machine-readable class name, also used on the wire.
    pub fn class(&self) -> &'static str {
        match self {
            CorrelationError::Unattested => "caller_unattested",
            CorrelationError::Missing(_) => "missing",
            CorrelationError::Duplicate(_) => "duplicate",
            CorrelationError::Stale(_) => "stale",
            CorrelationError::Conflicting(_) => "conflicting",
            CorrelationError::NotEvidence(_) => "not_evidence",
            CorrelationError::Unavailable(_) => "unavailable",
        }
    }

    /// The detail text (empty for [`CorrelationError::Unattested`]).
    pub fn detail(&self) -> &str {
        match self {
            CorrelationError::Unattested => "",
            CorrelationError::Missing(detail)
            | CorrelationError::Duplicate(detail)
            | CorrelationError::Stale(detail)
            | CorrelationError::Conflicting(detail)
            | CorrelationError::NotEvidence(detail)
            | CorrelationError::Unavailable(detail) => detail,
        }
    }

    /// Rebuilds an error from its wire class and detail; an unknown class
    /// becomes [`CorrelationError::Unavailable`].
    pub(crate) fn from_wire(class: &str, detail: String) -> Self {
        match class {
            "caller_unattested" => CorrelationError::Unattested,
            "missing" => CorrelationError::Missing(detail),
            "duplicate" => CorrelationError::Duplicate(detail),
            "stale" => CorrelationError::Stale(detail),
            "conflicting" => CorrelationError::Conflicting(detail),
            "not_evidence" => CorrelationError::NotEvidence(detail),
            _ => CorrelationError::Unavailable(format!("{class}: {detail}")),
        }
    }
}

impl std::fmt::Display for CorrelationError {
    /// Renders `class: detail`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.class(), self.detail())
    }
}

impl std::error::Error for CorrelationError {}

/// Role of an actor within its native session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRole {
    /// The addressed session's own context (Claude root, Codex thread).
    Root,
    /// A child context: a Claude subagent sharing the root session id, or
    /// a Codex child thread (which has its own address).
    Child,
}

/// Which protected correlation produced a [`VerifiedCaller`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerChannel {
    /// Claude `claudecode/toolUseId` joined to one `PreToolUse` hook record.
    ClaudeToolUse,
    /// Codex `_meta.threadId` + `_meta.callId` joined to one `PreToolUse`
    /// hook record of the same thread.
    CodexCall,
}

/// Protected native MCP request metadata presented for caller attestation.
///
/// Only the harness-owned `_meta` fields of the actual MCP `tools/call`
/// request: Claude's `claudecode/toolUseId`, or Codex's `threadId` and
/// `callId` together with its `x-codex-turn-metadata` object. Model
/// arguments, display names, cwd, environment and caller-asserted actors
/// have no field here. Build the native variants only with
/// [`PresentedMeta::from_mcp_meta`] on the `_meta` object the MCP framework
/// separated from arguments.
///
/// Field provenance: Claude `claudecode/toolUseId` and the Codex keys
/// `threadId`, `callId` and `x-codex-turn-metadata` (with `thread_id`
/// inside) are the top-level `_meta` keys captured from real Claude Code
/// 2.1.294 and Codex 0.162.0-alpha.17.2 MCP `tools/call` requests during
/// reconnaissance. That the Codex `callId` equals the same call's
/// `PreToolUse` hook `tool_use_id` was observed only on the build the
/// Root's native Q3 run exercised; it is not a general guarantee, and on a
/// build where it does not hold the join finds no record and refuses.
///
/// [`PresentedMeta::Sealed`] is not native metadata: it is Bridge-owned
/// enrichment, a registry-issued single-use proof forwarded by a
/// harness-launched frontend to a relay process (see
/// [`crate::client::RegistryAttestor::attest_sealed`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "host", rename_all = "snake_case")]
pub enum PresentedMeta {
    /// Claude Code request metadata.
    Claude {
        /// `_meta["claudecode/toolUseId"]`.
        tool_use_id: String,
    },
    /// Codex request metadata.
    Codex {
        /// `_meta.threadId`: the calling thread (root or child).
        thread_id: String,
        /// `_meta.callId`: the per-call identifier.
        call_id: String,
    },
    /// A sealed proof issued by the registry for an already attested
    /// caller; redeemable once, only by a configured relay executable.
    Sealed {
        /// The opaque proof text.
        proof: SealedProof,
    },
}

/// An opaque, unguessable, single-use caller proof issued by the registry.
///
/// It carries no caller facts: redeeming it returns exactly the facts the
/// registry stored at issue time, once, to a configured relay process
/// within a short lifetime. `Debug` never prints the value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SealedProof(String);

impl SealedProof {
    /// Wraps proof text received from a frontend over a relay's own
    /// transport; validity is decided only by redemption.
    pub fn from_wire(text: impl Into<String>) -> Self {
        SealedProof(text.into())
    }

    /// The proof text to forward (treat as a secret; never log).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SealedProof {
    /// Prints a placeholder instead of the proof.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedProof(<redacted>)")
    }
}

impl PresentedMeta {
    /// Parses exactly one complete supported host contract from an MCP
    /// request `_meta` object.
    ///
    /// Codex needs `threadId`, `callId` and an `x-codex-turn-metadata`
    /// object; Claude needs `claudecode/toolUseId`. Fields of both hosts at
    /// once, a lone partial contract, or an invalid identifier refuse as
    /// [`CorrelationError::NotEvidence`]. Other `_meta` keys are ignored.
    pub fn from_mcp_meta(
        meta: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, CorrelationError> {
        let codex = ["x-codex-turn-metadata", "threadId", "callId"]
            .iter()
            .any(|field| meta.contains_key(*field));
        let claude = meta.contains_key("claudecode/toolUseId");
        let field = |name: &str| -> Result<String, CorrelationError> {
            let value = meta
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CorrelationError::NotEvidence(format!("_meta {name} missing")))?;
            checked_id(value, name).map_err(CorrelationError::NotEvidence)
        };
        match (codex, claude) {
            (true, false) => {
                let Some(turn) = meta
                    .get("x-codex-turn-metadata")
                    .and_then(serde_json::Value::as_object)
                else {
                    return Err(CorrelationError::NotEvidence(
                        "_meta x-codex-turn-metadata object missing".into(),
                    ));
                };
                let thread_id = field("threadId")?;
                // The turn metadata names the same thread when it names one.
                if turn
                    .get("thread_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|turn_thread| turn_thread != thread_id)
                {
                    return Err(CorrelationError::Conflicting(
                        "_meta threadId differs from the turn metadata thread".into(),
                    ));
                }
                Ok(PresentedMeta::Codex {
                    thread_id,
                    call_id: field("callId")?,
                })
            }
            (false, true) => Ok(PresentedMeta::Claude {
                tool_use_id: field("claudecode/toolUseId")?,
            }),
            _ => Err(CorrelationError::NotEvidence(
                "_meta does not carry exactly one supported host contract".into(),
            )),
        }
    }

    /// Presents a sealed proof received from a frontend.
    pub fn sealed(proof: SealedProof) -> Self {
        PresentedMeta::Sealed { proof }
    }

    /// The per-call identifier and harness of native metadata; `None` for
    /// a sealed proof.
    fn native(&self) -> Option<(&str, Harness)> {
        match self {
            PresentedMeta::Claude { tool_use_id } => Some((tool_use_id, Harness::ClaudeCode)),
            PresentedMeta::Codex { call_id, .. } => Some((call_id, Harness::Codex)),
            PresentedMeta::Sealed { .. } => None,
        }
    }
}

/// The verified actual caller of one native MCP request.
///
/// The `bridge-root-caller` provider ABI: `(address, role, native_id)` is
/// the full scope — two Claude subagents sharing a session id have the same
/// address but different `native_id`, and only a `Root` caller whose
/// native id is the address's own session may act on that address's
/// root-context data. Fields are private; production values come only from
/// the registry (through [`crate::client::RegistryAttestor`]). There is no
/// `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCaller {
    /// Exact native address of the session the caller acts in.
    address: NativeAddress,
    /// Root or child.
    role: ActorRole,
    /// Native actor id: Claude session id (root) or agent id (child);
    /// Codex thread id.
    native_id: String,
    /// Endpoint epoch of the binding the join was made under.
    epoch: u64,
    /// When the joined hook record was observed (Unix epoch ms).
    observed_at_ms: u64,
    /// Which correlation produced it.
    channel: CallerChannel,
    /// Whether it was obtained by redeeming a sealed proof in a relay
    /// process rather than directly by the harness-launched frontend.
    relayed: bool,
}

impl VerifiedCaller {
    /// Crate-internal constructor used by the registry and its client.
    pub(crate) fn new(
        address: NativeAddress,
        role: ActorRole,
        native_id: String,
        epoch: u64,
        observed_at_ms: u64,
        channel: CallerChannel,
    ) -> Self {
        VerifiedCaller {
            address,
            role,
            native_id,
            epoch,
            observed_at_ms,
            channel,
            relayed: false,
        }
    }

    /// The same caller marked as obtained through a relay redemption.
    pub(crate) fn into_relayed(mut self) -> Self {
        self.relayed = true;
        self
    }

    /// Whether this caller was obtained by redeeming a sealed proof.
    pub fn relayed(&self) -> bool {
        self.relayed
    }

    /// Explicit fixture constructor for consumer tests only; never
    /// compiled into production builds (feature `test-fixtures`).
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn fixture(
        address: NativeAddress,
        role: ActorRole,
        native_id: impl Into<String>,
        epoch: u64,
        observed_at_ms: u64,
        channel: CallerChannel,
    ) -> Self {
        VerifiedCaller::new(
            address,
            role,
            native_id.into(),
            epoch,
            observed_at_ms,
            channel,
        )
    }

    /// The exact native address the caller acts in.
    pub fn address(&self) -> &NativeAddress {
        &self.address
    }

    /// Root or child.
    pub fn role(&self) -> ActorRole {
        self.role
    }

    /// The caller's native actor id.
    pub fn native_id(&self) -> &str {
        &self.native_id
    }

    /// Endpoint epoch of the binding at join time.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Observation time of the joined hook record (Unix epoch ms).
    pub fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    /// Which correlation produced this caller.
    pub fn channel(&self) -> CallerChannel {
        self.channel
    }

    /// Whether the caller is the addressed actor itself (its native id is
    /// the address's own session id) and may read, drain or acknowledge
    /// that address's data. A Claude subagent sharing the root session id
    /// never may; a Codex child thread may act on its own thread address.
    pub fn may_act_as_address(&self) -> bool {
        self.native_id == self.address.native_session_id
    }
}

/// The root-caller attestation provider consumed by the restricted MCP.
///
/// Implementations must authenticate the actual calling actor from the
/// presented protected metadata *and* the provider's own protected
/// evidence; `now_ms` is the consumer's clock for its own freshness bound.
pub trait CallerAttestor: Send + Sync {
    /// Attests the caller of one MCP request, or refuses.
    fn attest(&self, meta: &PresentedMeta, now_ms: u64)
    -> Result<VerifiedCaller, CorrelationError>;
}

/// The fail-closed default provider: every call refuses as
/// [`CorrelationError::Unattested`]. Root ingress without a configured
/// provider uses this; no configured-address fallback exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unattested;

impl CallerAttestor for Unattested {
    /// Always refuses with `caller_unattested`.
    fn attest(
        &self,
        _meta: &PresentedMeta,
        _now_ms: u64,
    ) -> Result<VerifiedCaller, CorrelationError> {
        Err(CorrelationError::Unattested)
    }
}

/// Native hook event names this registry understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    /// Session started, resumed, cleared or compacted.
    SessionStart,
    /// A user prompt was submitted (natural context point).
    UserPromptSubmit,
    /// A tool call is about to run.
    PreToolUse,
    /// A tool call finished (natural context point).
    PostToolUse,
    /// A tool call failed.
    PostToolUseFailure,
    /// The harness asks the user for a permission decision.
    PermissionRequest,
    /// A harness notification (permission or idle prompts).
    Notification,
    /// The root turn ended; the session is idle.
    Stop,
    /// A child context ended.
    SubagentStop,
    /// The session ended.
    SessionEnd,
}

impl HookKind {
    /// Parses the native `hook_event_name`.
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "SessionStart" => HookKind::SessionStart,
            "UserPromptSubmit" => HookKind::UserPromptSubmit,
            "PreToolUse" => HookKind::PreToolUse,
            "PostToolUse" => HookKind::PostToolUse,
            "PostToolUseFailure" => HookKind::PostToolUseFailure,
            "PermissionRequest" => HookKind::PermissionRequest,
            "Notification" => HookKind::Notification,
            "Stop" => HookKind::Stop,
            "SubagentStop" => HookKind::SubagentStop,
            "SessionEnd" => HookKind::SessionEnd,
            _ => return None,
        })
    }

    /// The native name, for hook output and proof references.
    pub fn as_str(self) -> &'static str {
        match self {
            HookKind::SessionStart => "SessionStart",
            HookKind::UserPromptSubmit => "UserPromptSubmit",
            HookKind::PreToolUse => "PreToolUse",
            HookKind::PostToolUse => "PostToolUse",
            HookKind::PostToolUseFailure => "PostToolUseFailure",
            HookKind::PermissionRequest => "PermissionRequest",
            HookKind::Notification => "Notification",
            HookKind::Stop => "Stop",
            HookKind::SubagentStop => "SubagentStop",
            HookKind::SessionEnd => "SessionEnd",
        }
    }

    /// Whether this event is a natural context point where queued inject
    /// events may be handed to the model.
    pub fn is_context_point(self) -> bool {
        matches!(self, HookKind::PostToolUse | HookKind::UserPromptSubmit)
    }
}

/// The parsed, bounded fields of one native hook payload.
///
/// Unknown fields (tool input/output, prompts, cwd) are ignored and never
/// retained; duplicate known keys refuse.
#[derive(Debug, Clone, Deserialize)]
pub struct HookPayload {
    /// Native event name.
    pub hook_event_name: String,
    /// Root session id (Claude) or root thread id (Codex).
    pub session_id: String,
    /// Child actor id when the event comes from a child context.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Per-call id of tool events.
    #[serde(default)]
    pub tool_use_id: Option<String>,
    /// Tool name of tool events.
    #[serde(default)]
    pub tool_name: Option<String>,
    /// Claude notification type (`permission_prompt`, `idle_prompt`, ...).
    #[serde(default)]
    pub notification_type: Option<String>,
    /// Native transcript file of the session.
    #[serde(default)]
    pub transcript_path: Option<String>,
    /// Claude `SessionStart` source (`startup`, `resume`, `clear`,
    /// `compact`); `compact` can fire in the middle of a turn, so it is not
    /// evidence that the root is idle.
    #[serde(default)]
    pub source: Option<String>,
}

/// What the registry decided about one admitted hook event.
#[derive(Debug, Clone)]
pub struct HookAdmission {
    /// The parsed event kind.
    pub kind: HookKind,
    /// The address whose binding the event belongs to.
    pub address: NativeAddress,
    /// The actor that fired the hook.
    pub role: ActorRole,
    /// Its native id.
    pub native_id: String,
    /// Binding attestation for core when it changed (new epoch, new
    /// capabilities); the server forwards it to `observe_binding`.
    pub renewed: Option<Attestation>,
    /// At a context point of the addressed root actor with qualified
    /// inject: the attestation under which the hook may drain.
    pub drain: Option<Attestation>,
}

/// One binding of an address to a harness incarnation. Only daemon-verified
/// facts are persisted privately; fresh OS/build validation is required on load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    /// The bound address.
    address: NativeAddress,
    /// Harness incarnation `(pid, start_time)`.
    harness: (u32, u64),
    /// Monotonic endpoint epoch.
    epoch: u64,
    /// Current capabilities of this binding (a carrier may withdraw message
    /// on positive runtime disablement, and restore it only up to
    /// `qualified`).
    capabilities: Capabilities,
    /// The capabilities the loaded build is qualified for at renewal (the
    /// profile's, minus host-level unsupported paths); never exceeded.
    qualified: Capabilities,
    /// Qualified build label for proof references.
    version: String,
    /// Owner-session lifecycle from the latest hook; a new or renewed
    /// binding starts [`Lifecycle::Unknown`] and leaves it only on a
    /// positive owner-actor observation ([`next_lifecycle`]).
    lifecycle: Lifecycle,
    /// Session transcript inside the profile store, when reported.
    transcript: Option<PathBuf>,
    /// Profile store of the binding.
    store: PathBuf,
    /// Qualified harness executable of the binding.
    executable: PathBuf,
    /// Set by root `SessionEnd`; normal recipient and caller authority stays refused.
    retired: bool,
    /// Positive pre-end Desktop owner idleness, granting only native MESSAGE
    /// candidate eligibility. Missing legacy facts keep tombstones held. Old
    /// binaries reject this field when true rather than restore authority;
    /// false is omitted so ineligible rows retain their prior journal shape.
    #[serde(default, skip_serializing_if = "is_false")]
    desktop_idle_message: bool,
    /// Retained transcript device/inode at the positive end observation;
    /// replacement or movement out of sessions revokes message eligibility.
    /// Missing values read as None and are omitted when writing old-shaped rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    desktop_idle_transcript: Option<(u64, u64)>,
}

/// Serde omission predicate for the private idle fact: false carries no new
/// authority and need not change legacy journal rows; true must persist.
fn is_false(value: &bool) -> bool {
    !*value
}

/// A verified native observation tuple: caller, actual harness incarnation,
/// protected native call ID and optional bounded host tool classification.
type NativeInspection = (VerifiedCaller, (u32, u64), String, Option<String>);

/// One `PreToolUse` call record.
#[derive(Debug, Clone)]
struct CallRecord {
    /// Harness incarnation that fired the hook.
    harness: (u32, u64),
    /// Canonical address of the actor's binding.
    address: String,
    /// Actor role.
    role: ActorRole,
    /// Actor native id.
    native_id: String,
    /// Binding epoch at observation.
    epoch: u64,
    /// Observation time (Unix epoch ms).
    observed_ms: u64,
    /// Whether a caller join already consumed it.
    consumed: bool,
    /// An exclusive registration claim is unresolved.
    claimed: bool,
    /// Bounded protected native tool classification, never producer meaning.
    tool_name: Option<String>,
}

/// The harness a peer belongs to.
#[derive(Debug, Clone)]
struct HarnessMatch {
    /// Harness incarnation.
    incarnation: (u32, u64),
    /// Index of the matched profile.
    profile: usize,
    /// Index of the matched executable in the profile.
    executable: usize,
}

/// Identity of one exact executable file, the key of its hashed digest.
///
/// Besides the path it holds the device and inode (a replacement by
/// rename gets another inode), the length, the modification time and the
/// status-change time (ctime), both with nanoseconds. The kernel sets the
/// status-change time on every write, rename-into-place, chmod or link
/// change and a program cannot set it back (unlike mtime, which `cp -p`,
/// `install -p` and `touch` restore), so a same-size or timestamp-preserving
/// replacement still gets another key and can never reuse a digest hashed
/// from the previous file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileKey {
    /// Path as configured.
    path: PathBuf,
    /// Device and inode.
    inode: (u64, u64),
    /// Length in bytes.
    len: u64,
    /// Modification time: whole seconds and nanoseconds since the Unix epoch.
    mtime: (i64, i64),
    /// Status-change time: whole seconds and nanoseconds since the Unix epoch.
    ctime: (i64, i64),
}

/// The identity of the file at `path` (following symlinks, as the kernel
/// resolves a started executable), or `None` when it is unreadable.
fn file_key(path: &Path) -> Option<FileKey> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileKey {
        path: path.to_path_buf(),
        inode: (metadata.dev(), metadata.ino()),
        len: metadata.len(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

/// Recipient view for the message carriers.
#[derive(Debug, Clone)]
pub struct RecipientBinding {
    /// Harness incarnation `(pid, start_time)` owning the session.
    pub harness: (u32, u64),
    /// Endpoint epoch.
    pub epoch: u64,
    /// Profile store directory.
    pub store: PathBuf,
    /// Qualified harness executable (the loaded build).
    pub executable: PathBuf,
    /// Session transcript inside the store, when reported by hooks.
    pub transcript: Option<PathBuf>,
    /// This MESSAGE snapshot requires the native Desktop route even if its
    /// capability disappears after validation; never fall back to a CLI helper.
    pub(crate) desktop_message_only: bool,
}

/// Owned Codex MESSAGE validation snapshot; performs OS/file validation after
/// releasing the registry lock. Ordinary bindings retain their capabilities;
/// retired Desktop exceptions supply no inject, caller or call authority.
pub(crate) struct CodexMessageCandidate {
    /// Exact private binding, including its unchanged tombstone epoch.
    binding: Binding,
    /// Current configured executable qualification, never journal authority.
    qualified: QualifiedExecutable,
    /// Owner required for both process and retained transcript.
    owner_uid: u32,
    /// Startup-warmed identities of this qualified executable; no runtime hashing.
    keys: Vec<FileKey>,
}

impl CodexMessageCandidate {
    /// Revalidates exact PID/start, owner, executable, current profile/store and
    /// startup-warmed loaded bytes. Retired candidates additionally require the
    /// app capability and the same owned regular transcript under sessions,
    /// with no symlink/path traversal. Returns Inactive only for that private
    /// positive fact; all missing or changed evidence refuses before sending.
    /// Ordinary live bindings retain their owner lifecycle and capabilities.
    /// Current store aliases use the same canonical equivalence as admission;
    /// retired transcript checks still require the literal configured sessions
    /// prefix and a canonical path without symlink components, plus exact inode.
    /// The caller must perform the final locked stamp check after frontend I/O.
    pub(crate) fn validate(&self) -> Result<(Attestation, RecipientBinding), String> {
        let binding = &self.binding;
        let facts = os::process_facts(binding.harness.0).ok_or("harness is gone")?;
        let key = file_key(&binding.executable).ok_or("executable unreadable")?;
        if facts.uid != Some(self.owner_uid)
            || facts.start_time != binding.harness.1
            || facts.exe.as_ref() != Some(&binding.executable)
            || !harness_store(&facts, Harness::Codex)
                .is_some_and(|store| same_path(&store, &binding.store))
            || !self.keys.contains(&key)
            || i128::from(key.mtime.0.max(key.ctime.0)) >= i128::from(facts.start_time)
        {
            return Err("Codex message harness/store/loaded build changed".into());
        }
        let lifecycle = if binding.retired {
            if !binding.desktop_idle_message
                || binding.address.harness != Harness::Codex
                || os::process_env(facts.pid, "CODEX_APP_TOOLS_PIPE_PATH").is_none()
                || retained_transcript(binding, self.owner_uid) != binding.desktop_idle_transcript
                || binding.desktop_idle_transcript.is_none()
            {
                return Err("retired Desktop message evidence unavailable".into());
            }
            Lifecycle::Inactive
        } else {
            binding.lifecycle
        };
        let attestation = Attestation::verified(
            binding.address.clone(),
            binding.address.native_session_id.clone(),
            binding.epoch,
            lifecycle,
            Capabilities {
                inject: !binding.retired && binding.capabilities.inject,
                message: binding.capabilities.message && self.qualified.message,
            },
            proof(format!(
                "codex-message:{}@{}:epoch{}",
                binding.harness.0, binding.harness.1, binding.epoch
            )),
        )
        .map_err(|error| error.to_string())?;
        Ok((
            attestation,
            RecipientBinding {
                harness: binding.harness,
                epoch: binding.epoch,
                store: binding.store.clone(),
                executable: binding.executable.clone(),
                transcript: binding.transcript.clone(),
                desktop_message_only: binding.retired,
            },
        ))
    }
}

/// Returns device/inode only for the exact owned regular transcript inside the
/// configured store/sessions. Canonical equality rejects symlink components,
/// traversal and moved/archive/foreign files; absence is never positive evidence.
fn retained_transcript(binding: &Binding, owner_uid: u32) -> Option<(u64, u64)> {
    let path = binding.transcript.as_ref()?;
    if !path.is_absolute()
        || !path.starts_with(binding.store.join("sessions"))
        || path.canonicalize().ok()?.as_path() != path.as_path()
    {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    (meta.is_file() && meta.uid() == owner_uid && meta.nlink() == 1)
        .then_some((meta.dev(), meta.ino()))
}

/// Versioned bounded route snapshot. It contains no publisher tokens, native
/// inbox keys, message bodies, caller records or single-use proofs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSnapshot {
    /// Snapshot format version; only version 1 is accepted.
    schema: u32,
    /// Last verified bindings, including retired tombstones and input-wait states.
    bindings: Vec<Binding>,
}

/// Largest private route snapshot accepted before allocation/JSON parsing.
const MAX_ROUTE_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

/// Protected native registry. Verified recipient routes can be journaled in the
/// private channel directory and recovered only for the same live, qualified
/// harness/store. Call records, exclusive claims, sealed proofs and detached
/// assertions remain strictly memory-only; route history is never fresh authority.
#[derive(Debug)]
pub struct Registry {
    /// Configuration.
    config: RegistryConfig,
    /// The only user id accepted on the channel.
    owner_uid: u32,
    /// Bindings by canonical address.
    bindings: HashMap<String, Binding>,
    /// Optional private atomic snapshot of verified recipient routes, never calls or secrets.
    journal: Option<PathBuf>,
    /// Call records by call id.
    calls: HashMap<String, Vec<CallRecord>>,
    /// Call ids in insertion order, for bounded eviction.
    call_order: VecDeque<String>,
    /// Executable digests hashed by [`Registry::warm_digests`], keyed by the
    /// exact file identity; never filled while serving.
    digests: HashMap<FileKey, String>,
    /// Outstanding sealed proofs by SHA-256 of the proof text.
    sealed: HashMap<String, Sealed>,
    /// Ephemeral issuer identity for globally unique native source-use keys.
    issuer_boot: String,
    /// Exclusive unresolved registration reservations by original source key.
    claims: HashMap<String, claims::ClaimRecord>,
    /// Bounded per-boot detached assertions and immutable consumption receipts.
    assertions: HashMap<String, assertions::AssertionRecord>,
    /// Precommit capacity reservations, never credentials or native authority.
    assertion_slots: std::collections::HashSet<(String, String)>,
    /// Bound of retained call records.
    max_calls: usize,
    /// Harnesses whose message carrier is unavailable on this host (for
    /// example no OS confinement launcher): never granted, so publication
    /// refuses before acceptance.
    message_disabled: Vec<Harness>,
}

/// Checks that `binding` is live and is still the binding `expected` was
/// taken from: same endpoint epoch and same harness incarnation.
///
/// # Errors
///
/// The binding is retired, or was renewed since the snapshot.
fn same_binding(binding: &Binding, expected: &RecipientBinding) -> Result<(), String> {
    if binding.retired {
        return Err("the recipient session ended (unknown, not inactive)".into());
    }
    if binding.epoch != expected.epoch || binding.harness != expected.harness {
        return Err(
            "the recipient binding was renewed since this observation (holding; re-attest)".into(),
        );
    }
    Ok(())
}

/// Validates one native identifier: non-empty, bounded, no controls.
fn checked_id(value: &str, field: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > MAX_NATIVE_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(format!("{field} is not a valid native identifier"));
    }
    Ok(value.to_string())
}

/// The longest prefix of `text` that is at most `max_bytes` bytes long and
/// ends on a UTF-8 character boundary.
///
/// Never splits a multi-byte character and never panics, whatever the
/// input (configured labels, native error text, stored hashes); a shorter
/// text is returned whole.
pub(crate) fn prefix_within(text: &str, max_bytes: usize) -> &str {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Bounded single-line proof reference text: control characters removed,
/// then at most 256 bytes cut on a character boundary (the input includes
/// the operator-configured version label, which may be any UTF-8), so the
/// result always satisfies core's proof reference bound and never panics.
fn proof(text: String) -> String {
    let text: String = text.chars().filter(|c| !c.is_control()).collect();
    prefix_within(&text, 256).to_string()
}

impl Registry {
    /// Builds an empty registry for `owner_uid` (the daemon's own user).
    ///
    /// Refuses a configuration with relative paths, an empty namespace or
    /// host id, or a malformed digest.
    ///
    /// Before returning, hashes every configured harness and relay
    /// executable once ([`Registry::warm_digests`]), so a registry that is
    /// shared and served afterwards never reads an executable while
    /// handling a request and no caller has to remember a separate warm-up
    /// step. The call therefore blocks for about one streamed read of those
    /// files (about 1.6 s per 246 MB optimized, tens of seconds
    /// unoptimized); a missing or unreadable file does not fail the
    /// constructor, it just stays unqualified.
    pub fn new(config: RegistryConfig, owner_uid: u32) -> Result<Self, String> {
        checked_id(&config.host_id, "host_id")?;
        for profile in &config.profiles {
            checked_id(&profile.namespace, "namespace")?;
            if !profile.store.is_absolute() {
                return Err("profile store must be absolute".into());
            }
            for executable in &profile.executables {
                if !executable.path.is_absolute() {
                    return Err("qualified executable path must be absolute".into());
                }
                if executable.sha256.len() != 64
                    || !executable.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("qualified executable sha256 must be 64 hex digits".into());
                }
            }
        }
        let mut audience_names = Vec::new();
        for audience in &config.audiences {
            checked_id(&audience.name, "audience")?;
            checked_id(&audience.producer, "producer")?;
            if !audience.executable.path.is_absolute()
                || audience.executable.sha256.len() != 64
                || !audience
                    .executable
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("audience executable requires absolute path and 64-hex digest".into());
            }
            if audience_names.contains(&(&audience.producer, &audience.name)) {
                return Err("duplicate producer audience".into());
            }
            audience_names.push((&audience.producer, &audience.name));
        }
        let mut registry = Registry {
            config,
            owner_uid,
            bindings: HashMap::new(),
            journal: None,
            calls: HashMap::new(),
            call_order: VecDeque::new(),
            digests: HashMap::new(),
            sealed: HashMap::new(),
            issuer_boot: crate::os::random_bytes()
                .map_err(|error| error.to_string())?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            claims: HashMap::new(),
            assertions: HashMap::new(),
            assertion_slots: std::collections::HashSet::new(),
            max_calls: DEFAULT_MAX_CALL_RECORDS,
            message_disabled: Vec::new(),
        };
        registry.warm_digests();
        Ok(registry)
    }

    /// Attaches the private route journal and revalidates every saved route before
    /// publishing a new endpoint epoch. `path` must lie in an existing owner-only
    /// channel directory. Missing snapshots are initial setup; malformed, symlinked,
    /// foreign, shared, oversized or unsupported files refuse startup. Dead/reused
    /// processes and changed stores/builds/profiles are omitted. Retired
    /// tombstones retain their exact epoch and refusal fences; their optional
    /// Desktop MESSAGE fact is revalidated on every carrier use, never promoted
    /// into normal live authority by recovery. Missing new fields default false/
    /// None and false/None values are omitted, preserving old row shape. Older
    /// binaries reject eligible rows with new fields (`deny_unknown_fields`),
    /// so rollback with those rows requires a compatible journal or fresh setup.
    /// Current profile capabilities bound recovery; unknown/input-wait lifecycle
    /// stays such. No hook is manufactured and no caller/proof record is restored.
    /// Returns fresh recipient attestations for core to fence before serving.
    pub fn attach_journal(&mut self, path: &Path, now_ms: u64) -> Result<Vec<Attestation>, String> {
        if self.journal.as_deref() == Some(path) {
            return Ok(Vec::new());
        }
        crate::server::private_directory(path.parent().ok_or("route journal lacks parent")?)
            .map_err(|_| "route journal directory refused".to_string())?;
        let snapshot = match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("route journal unreadable".into()),
            Ok(meta) => {
                if !meta.is_file()
                    || meta.uid() != self.owner_uid
                    || meta.mode() & 0o077 != 0
                    || meta.nlink() != 1
                    || meta.len() > MAX_ROUTE_SNAPSHOT_BYTES
                {
                    return Err("route journal is not a bounded private regular file".into());
                }
                let file = std::fs::File::open(path).map_err(|_| "route journal unreadable")?;
                let opened = file
                    .metadata()
                    .map_err(|_| "route journal metadata unreadable")?;
                if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
                    return Err("route journal changed while opening".into());
                }
                let mut bytes = Vec::new();
                file.take(MAX_ROUTE_SNAPSHOT_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "route journal unreadable")?;
                if bytes.len() as u64 > MAX_ROUTE_SNAPSHOT_BYTES {
                    return Err("route journal oversized".into());
                }
                let snapshot: RouteSnapshot =
                    serde_json::from_slice(&bytes).map_err(|_| "route journal malformed")?;
                if snapshot.schema != 1 || snapshot.bindings.len() > DEFAULT_MAX_BINDINGS {
                    return Err("route journal version or count refused".into());
                }
                Some(snapshot)
            }
        };
        if let Some(snapshot) = snapshot {
            for mut binding in snapshot.bindings {
                if binding.address.host_id != self.config.host_id
                    || binding.epoch == 0
                    || binding.epoch == u64::MAX
                    || NativeAddress::parse(&binding.address.to_canonical_string()).is_err()
                {
                    continue;
                }
                if binding.retired {
                    self.bindings
                        .entry(binding.address.to_canonical_string())
                        .or_insert(binding);
                    continue;
                }
                let Some(facts) = os::process_facts(binding.harness.0) else {
                    continue;
                };
                if facts.uid != Some(self.owner_uid)
                    || facts.start_time != binding.harness.1
                    || facts.exe.as_ref() != Some(&binding.executable)
                    || harness_store(&facts, binding.address.harness).as_ref()
                        != Some(&binding.store)
                {
                    continue;
                }
                let qualified = self
                    .config
                    .profiles
                    .iter()
                    .find(|p| {
                        p.harness == binding.address.harness
                            && p.namespace == binding.address.native_store_namespace
                            && p.store == binding.store
                    })
                    .and_then(|p| p.executables.iter().find(|e| e.path == binding.executable))
                    .cloned();
                let Some(qualified) = qualified else {
                    continue;
                };
                if self
                    .verify_loaded(&qualified.path, facts.start_time, &qualified.sha256)
                    .is_err()
                {
                    continue;
                }
                binding.epoch = now_ms.max(binding.epoch + 1);
                binding.qualified = Capabilities {
                    inject: qualified.inject,
                    message: qualified.message
                        && !self.message_disabled.contains(&binding.address.harness),
                };
                binding.capabilities.inject &= binding.qualified.inject;
                binding.capabilities.message &= binding.qualified.message;
                binding.version = qualified.version;
                if binding
                    .transcript
                    .as_ref()
                    .is_some_and(|p| !p.starts_with(&binding.store))
                {
                    binding.transcript = None;
                }
                self.bindings
                    .entry(binding.address.to_canonical_string())
                    .or_insert(binding);
            }
        }
        self.journal = Some(path.to_path_buf());
        self.persist_routes()?;
        Ok(self
            .bindings
            .values()
            .filter(|b| !b.retired)
            .filter_map(|b| self.attest_recipient(&b.address).ok().map(|(a, _)| a))
            .collect())
    }

    /// Atomically fsyncs the bounded verified-route snapshot with mode 0600 and
    /// an owner-only parent directory. Failure is reported without payload/path
    /// diagnostics; a failed write leaves the previous snapshot intact. No-op
    /// when persistence is disabled for an isolated registry.
    fn persist_routes(&self) -> Result<(), String> {
        let Some(path) = &self.journal else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(&RouteSnapshot {
            schema: 1,
            bindings: self.bindings.values().cloned().collect(),
        })
        .map_err(|_| "route snapshot encoding failed")?;
        if bytes.len() as u64 > MAX_ROUTE_SNAPSHOT_BYTES {
            return Err("route snapshot oversized".into());
        }
        let random = os::random_bytes().map_err(|_| "route snapshot entropy unavailable")?;
        let temp = path.with_extension(format!(
            "new-{:x}",
            u64::from_le_bytes(random[..8].try_into().expect("eight entropy bytes"))
        ));
        // ponytail: one bounded snapshot per hook; use journaled rows if hook throughput warrants it.
        let result = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, path)?;
            std::fs::File::open(path.parent().expect("validated journal parent"))?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
            return Err("route snapshot could not be committed".into());
        }
        Ok(())
    }

    /// Bootstraps a missing interactive Claude recipient from fresh native session
    /// metadata, including clients opened before route journals existed. Addresses
    /// already known (including ended/held tombstones) are never overwritten. A
    /// descriptor supplies only session/PID/status; current OS UID/start/executable,
    /// process-owned store, descriptor age and qualified loaded bytes are rechecked.
    /// Persistence precedes delivery and caller records remain absent. Returns
    /// no-op on absent/unknown native evidence; normal attestation then holds it.
    pub(crate) fn discover_claude_recipient(
        &mut self,
        address: &NativeAddress,
        now_ms: u64,
    ) -> Result<(), String> {
        let key = address.to_canonical_string();
        if self.bindings.contains_key(&key)
            || address.host_id != self.config.host_id
            || address.harness != Harness::ClaudeCode
        {
            return Ok(());
        }
        let Some(profile) = self
            .config
            .profiles
            .iter()
            .find(|p| p.harness == address.harness && p.namespace == address.native_store_namespace)
            .cloned()
        else {
            return Ok(());
        };
        let Some(hint) =
            crate::claude::session_hint(&profile.store, &address.native_session_id, self.owner_uid)
        else {
            return Ok(());
        };
        let Some(facts) = os::process_facts(hint.pid) else {
            return Ok(());
        };
        if facts.uid != Some(self.owner_uid)
            || i128::from(hint.written_at) < i128::from(facts.start_time)
            || harness_store(&facts, Harness::ClaudeCode).as_ref() != Some(&profile.store)
        {
            return Ok(());
        }
        let Some(exe) = profile
            .executables
            .iter()
            .find(|e| facts.exe.as_ref() == Some(&e.path))
            .cloned()
        else {
            return Ok(());
        };
        if self
            .verify_loaded(&exe.path, facts.start_time, &exe.sha256)
            .is_err()
        {
            return Ok(());
        }
        self.evict_bindings();
        if self.bindings.len() >= DEFAULT_MAX_BINDINGS {
            return Err("verified route capacity exhausted".into());
        }
        let qualified = Capabilities {
            inject: exe.inject,
            message: exe.message && !self.message_disabled.contains(&Harness::ClaudeCode),
        };
        self.bindings.insert(
            key.clone(),
            Binding {
                address: address.clone(),
                harness: (facts.pid, facts.start_time),
                epoch: now_ms.max(1),
                capabilities: qualified,
                qualified,
                version: exe.version,
                lifecycle: hint.lifecycle,
                transcript: None,
                store: profile.store,
                executable: exe.path,
                retired: false,
                desktop_idle_message: false,
                desktop_idle_transcript: None,
            },
        );
        if let Err(error) = self.persist_routes() {
            self.bindings.remove(&key);
            return Err(error);
        }
        Ok(())
    }

    /// Never grants the message capability for `harness` (the host cannot
    /// run its carrier safely). Applies to bindings renewed afterwards; the
    /// daemon calls it before serving.
    pub fn disable_message(&mut self, harness: Harness) {
        if !self.message_disabled.contains(&harness) {
            self.message_disabled.push(harness);
        }
    }

    /// Whether the file at `exe` is still a qualified build of some
    /// profile (same path and digest) — checked before a carrier launches
    /// it, so a replaced file is never started as the qualified build.
    /// Reads no file: a file replaced since the startup hash is refused.
    pub fn executable_qualified(&mut self, exe: &Path) -> bool {
        let qualified: Vec<String> = self
            .config
            .profiles
            .iter()
            .flat_map(|profile| profile.executables.iter())
            .filter(|candidate| candidate.path == exe)
            .map(|candidate| candidate.sha256.clone())
            .collect();
        qualified
            .iter()
            .any(|digest| self.verify_loaded(exe, u64::MAX, digest).is_ok())
    }

    /// The configured host id.
    pub fn host_id(&self) -> &str {
        &self.config.host_id
    }

    /// Resolves the qualified harness a channel peer belongs to.
    ///
    /// The peer must run as the owner; its nearest ancestor that is not an
    /// allowlisted intermediate must be a configured executable of
    /// `harness`, unmodified since that process started, with the
    /// qualified digest, and its own store must be a configured profile.
    fn harness_of(
        &mut self,
        peer: PeerIdentity,
        harness: Harness,
    ) -> Result<HarnessMatch, CorrelationError> {
        if peer.uid != self.owner_uid {
            return Err(CorrelationError::NotEvidence(
                "peer runs as another user".into(),
            ));
        }
        let chain = os::ancestry(peer.pid);
        let Some((_, ancestors)) = chain.split_first() else {
            return Err(CorrelationError::NotEvidence("peer process is gone".into()));
        };
        let candidate = ancestors.iter().find(|facts| {
            !facts
                .exe
                .as_ref()
                .is_some_and(|exe| self.config.intermediates.contains(exe))
        });
        let Some(facts) = candidate else {
            return Err(CorrelationError::NotEvidence("no harness ancestor".into()));
        };
        if facts.uid != Some(self.owner_uid) {
            return Err(CorrelationError::NotEvidence(
                "harness runs as another user".into(),
            ));
        }
        let exe = facts
            .exe
            .clone()
            .ok_or_else(|| CorrelationError::NotEvidence("harness executable unreadable".into()))?;
        let store = harness_store(facts, harness)
            .ok_or_else(|| CorrelationError::NotEvidence("harness store unresolvable".into()))?;
        let mut found = None;
        for (index, profile) in self.config.profiles.iter().enumerate() {
            if profile.harness != harness || !same_path(&profile.store, &store) {
                continue;
            }
            if let Some(position) = profile.executables.iter().position(|e| e.path == exe) {
                found = Some((index, position));
                break;
            }
        }
        let (profile, executable) = found.ok_or_else(|| {
            CorrelationError::NotEvidence(
                "harness build or store is not a qualified profile".into(),
            )
        })?;
        let qualified = self.config.profiles[profile].executables[executable]
            .sha256
            .clone();
        self.verify_loaded(&exe, facts.start_time, &qualified)?;
        Ok(HarnessMatch {
            incarnation: (facts.pid, facts.start_time),
            profile,
            executable,
        })
    }

    /// Hashes every configured harness, relay and backend executable into the digest
    /// cache. This is the only place an executable is ever hashed: serving
    /// never reads one, so no hook or relay request can stall the registry
    /// lock on a whole (possibly hundreds of MB) file.
    ///
    /// [`Registry::new`] already runs this, so consumers need not. Calling
    /// it again is idempotent: a file whose identity is already cached is
    /// not read again (it only reports the counts, as the daemon does for
    /// its log), and only a file that changed since is re-hashed. Never call
    /// it on a registry that is shared and serving, since that would hash
    /// under the lock. The work is one streamed read per distinct
    /// configured path, bounded by
    /// the file sizes (about 1.6 s for 246 MB in an optimized build, tens
    /// of seconds unoptimized). Each file is hashed for real, never trusted
    /// from its configured digest, and cached only when its file identity
    /// (path, device and inode, length, nanosecond mtime) is the same
    /// before and after the read.
    ///
    /// Qualified afterwards: exactly those files, unchanged since. Not
    /// qualified, with a `NotEvidence` refusal from every route that needs
    /// the file: a configured file that was missing, unreadable or changing
    /// at this call, and any file installed, replaced or modified later
    /// (even by a same-size rewrite within the same second); other cached
    /// executables keep attesting. The operator's next action is to restart
    /// the daemon, which re-hashes the then-current files. Returns
    /// `(cached, skipped)` path counts.
    pub fn warm_digests(&mut self) -> (usize, usize) {
        let mut paths: Vec<&Path> = self
            .config
            .profiles
            .iter()
            .flat_map(|profile| profile.executables.iter().map(|e| e.path.as_path()))
            .chain(self.config.relays.iter().map(|relay| relay.path.as_path()))
            .chain(
                self.config
                    .audiences
                    .iter()
                    .map(|audience| audience.executable.path.as_path()),
            )
            .collect();
        paths.sort();
        paths.dedup();
        let paths: Vec<PathBuf> = paths.into_iter().map(Path::to_path_buf).collect();
        let (mut cached, mut skipped) = (0, 0);
        for path in paths {
            let Some(key) = file_key(&path) else {
                skipped += 1;
                continue;
            };
            if self.digests.contains_key(&key) {
                cached += 1;
                continue;
            }
            match file_sha256(&path) {
                Ok(digest) if file_key(&path).as_ref() == Some(&key) => {
                    self.digests.insert(key, digest);
                    cached += 1;
                }
                _ => skipped += 1,
            }
        }
        (cached, skipped)
    }

    /// How many configured harness and relay executable entries cannot
    /// attest right now: the file is missing, unreadable, changed since it
    /// was hashed or not hashed, or its real hashed digest differs from the
    /// configured one. One entry counts once, so the number is bounded by
    /// the configuration.
    ///
    /// It only stats files and compares the cached real digests with the
    /// configured ones (never trusting the configured value, never reading
    /// a file), so it is cheap and safe at startup, after
    /// [`Registry::new`], to tell the operator that a route is
    /// unqualified. It does not look at process start times.
    pub fn unqualified_executables(&self) -> usize {
        let profiles = self
            .config
            .profiles
            .iter()
            .flat_map(|profile| profile.executables.iter().map(|e| (&e.path, &e.sha256)));
        let relays = self
            .config
            .relays
            .iter()
            .map(|relay| (&relay.path, &relay.sha256));
        profiles
            .chain(relays)
            .filter(|(path, configured)| {
                !file_key(path)
                    .and_then(|key| self.digests.get(&key))
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(configured))
            })
            .count()
    }

    /// Proves the loaded build: both the modification second and the
    /// status-change (ctime) second of the file are strictly before the
    /// process start (`started` is the process start in Unix seconds, or
    /// `u64::MAX` when no process is involved) and its digest, hashed by
    /// [`Registry::warm_digests`] for this exact file identity (which
    /// includes the nanosecond ctime), equals `qualified`.
    ///
    /// What this proves: since before the process was born, the file at the
    /// path has not been written, replaced, renamed into place or chmod-ed,
    /// so the bytes on disk, hashed at startup, are the bytes the process
    /// started from. mtime alone is not enough: an installer that restores
    /// timestamps (`cp -p`, `install -p`, `touch`) keeps an old mtime, but
    /// the kernel sets ctime on every such change and a program cannot set
    /// it back, and the OS keeps reporting the same executable path for the
    /// live process after a replacement (probed on macOS), so the path
    /// alone shows nothing. Times are whole seconds, so a change in the very
    /// second the process was born is ambiguous and refused; restarting the
    /// harness a second or more after the last change to the file resolves
    /// the birth-second ambiguity. A benign chmod or link change also moves
    /// the nanosecond ctime, which is part of the daemon-start digest cache
    /// identity too, so any change after the daemon warmed needs BOTH a
    /// daemon restart (to hash the current file again, never under this
    /// lock) and a harness restart (a new birth second). A run that wants
    /// to show the stock binary was not touched should record its
    /// inode, mtime and ctime before and after; nothing here claims the
    /// operating system can never write it. It does not defend against code
    /// that already runs as the user with the ability to move the system
    /// clock backwards.
    ///
    /// Never reads the file: a file without a warmed digest (installed,
    /// replaced or changed since startup, or missing at startup) is refused
    /// as unqualified until the daemon restarts, so this is safe under the
    /// registry lock.
    fn verify_loaded(
        &mut self,
        exe: &Path,
        started: u64,
        qualified: &str,
    ) -> Result<(), CorrelationError> {
        let key = file_key(exe)
            .ok_or_else(|| CorrelationError::NotEvidence("harness executable unreadable".into()))?;
        if i128::from(key.mtime.0.max(key.ctime.0)) >= i128::from(started) {
            return Err(CorrelationError::NotEvidence(
                "harness executable written or changed on disk at or after the process start second; loaded build unproven"
                    .into(),
            ));
        }
        let Some(digest) = self.digests.get(&key) else {
            return Err(CorrelationError::NotEvidence(
                "harness executable was not hashed unchanged at daemon startup (new, replaced or modified since); unqualified until the daemon restarts"
                    .into(),
            ));
        };
        if !digest.eq_ignore_ascii_case(qualified) {
            return Err(CorrelationError::NotEvidence(
                "harness build digest is not the qualified build".into(),
            ));
        }
        Ok(())
    }

    /// Admits one hook event from a channel peer.
    ///
    /// Verifies the peer's harness, parses the payload, renews the binding
    /// when needed (new incarnation, the owner's own non-`compact`
    /// `SessionStart`, first sight), applies
    /// the lifecycle transition, records `PreToolUse` calls and decides
    /// whether this event may drain inject. Refuses (and changes nothing)
    /// on a non-harness peer, a malformed payload, or an address held by
    /// another live incarnation. A route-journal failure restores the previous
    /// binding and records no caller/context evidence for the refused event.
    /// Root Desktop SessionEnd can retain only prior positive owner Inactive
    /// message eligibility and the exact owned regular sessions transcript inode;
    /// retirement and Unknown lifecycle remain, and renewal clears both facts.
    pub fn admit_hook(
        &mut self,
        peer: PeerIdentity,
        harness: Harness,
        payload: &HookPayload,
        now_ms: u64,
    ) -> Result<HookAdmission, CorrelationError> {
        let kind = HookKind::parse(&payload.hook_event_name)
            .ok_or_else(|| CorrelationError::NotEvidence("unsupported hook event".into()))?;
        let session =
            checked_id(&payload.session_id, "session_id").map_err(CorrelationError::NotEvidence)?;
        let agent = payload
            .agent_id
            .as_deref()
            .map(|agent| checked_id(agent, "agent_id"))
            .transpose()
            .map_err(CorrelationError::NotEvidence)?;
        if kind == HookKind::PreToolUse && payload.tool_use_id.is_some() {
            self.ensure_call_capacity()?;
        }
        let matched = self.harness_of(peer, harness)?;
        let profile = self.config.profiles[matched.profile].clone();
        let qualified = profile.executables[matched.executable].clone();
        // Claude children share the root session's address; Codex children
        // are their own threads with their own addresses.
        let (role, native_id, address_session) = match (&agent, harness) {
            (None, _) => (ActorRole::Root, session.clone(), session.clone()),
            (Some(agent), Harness::ClaudeCode) => {
                (ActorRole::Child, agent.clone(), session.clone())
            }
            (Some(agent), Harness::Codex) => (ActorRole::Child, agent.clone(), agent.clone()),
        };
        let address = NativeAddress::new(
            self.config.host_id.clone(),
            harness,
            profile.namespace.clone(),
            address_session,
        )
        .map_err(|error| CorrelationError::NotEvidence(error.to_string()))?;
        let key = address.to_canonical_string();
        let capabilities = Capabilities {
            inject: qualified.inject,
            message: qualified.message && !self.message_disabled.contains(&harness),
        };
        let transcript = payload
            .transcript_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.starts_with(&profile.store));

        let previous_binding = self.bindings.get(&key).cloned();
        let (renewed, previous_epoch) = match self.bindings.get(&key) {
            Some(binding) if binding.harness != matched.incarnation => {
                if !binding.retired && os::incarnation_alive(binding.harness.0, binding.harness.1) {
                    return Err(CorrelationError::Conflicting(
                        "address is bound to another live harness incarnation".into(),
                    ));
                }
                (true, Some(binding.epoch))
            }
            Some(binding) => (
                starts_own_session(kind, role, harness, payload) || binding.retired,
                Some(binding.epoch),
            ),
            None => (true, None),
        };
        if renewed {
            let epoch =
                previous_epoch.map_or(now_ms.max(1), |old| now_ms.max(old.saturating_add(1)));
            self.evict_bindings();
            if !self.bindings.contains_key(&key) && self.bindings.len() >= DEFAULT_MAX_BINDINGS {
                return Err(CorrelationError::Unavailable(
                    "verified route capacity exhausted".into(),
                ));
            }
            self.bindings.insert(
                key.clone(),
                Binding {
                    address: address.clone(),
                    harness: matched.incarnation,
                    epoch,
                    capabilities,
                    qualified: capabilities,
                    version: qualified.version.clone(),
                    lifecycle: Lifecycle::Unknown,
                    transcript: None,
                    store: profile.store.clone(),
                    executable: qualified.path.clone(),
                    retired: false,
                    desktop_idle_message: false,
                    desktop_idle_transcript: None,
                },
            );
        }
        let binding = self.bindings.get_mut(&key).expect("binding inserted above");
        let retained_path = transcript
            .as_ref()
            .is_none_or(|path| binding.transcript.as_ref() == Some(path));
        if transcript.is_some() {
            binding.transcript = transcript;
        }
        if kind == HookKind::SessionEnd && role == ActorRole::Root {
            binding.desktop_idle_transcript = if harness == Harness::Codex
                && binding.lifecycle == Lifecycle::Inactive
                && retained_path
                && os::process_env(binding.harness.0, "CODEX_APP_TOOLS_PIPE_PATH").is_some()
            {
                retained_transcript(binding, self.owner_uid)
            } else {
                None
            };
            binding.desktop_idle_message = binding.desktop_idle_transcript.is_some();
            binding.retired = true;
        }
        binding.lifecycle = next_lifecycle(binding.lifecycle, kind, role, harness, payload);
        let binding = binding.clone();
        if let Err(error) = self.persist_routes() {
            match previous_binding {
                Some(old) => {
                    self.bindings.insert(key.clone(), old);
                }
                None => {
                    self.bindings.remove(&key);
                }
            }
            return Err(CorrelationError::Unavailable(error));
        }

        if kind == HookKind::PreToolUse
            && let Some(call) = payload.tool_use_id.as_deref()
        {
            let call = checked_id(call, "tool_use_id").map_err(CorrelationError::NotEvidence)?;
            self.record_call(
                call,
                CallRecord {
                    harness: matched.incarnation,
                    address: key.clone(),
                    role,
                    native_id: native_id.clone(),
                    epoch: binding.epoch,
                    observed_ms: now_ms,
                    consumed: false,
                    claimed: false,
                    tool_name: payload
                        .tool_name
                        .as_deref()
                        .and_then(|name| checked_id(name, "tool_name").ok()),
                },
            );
        }

        let proof_ref = |label: &str| {
            proof(format!(
                "{label}:{}@{}:{}:epoch{}",
                binding.harness.0, binding.harness.1, binding.version, binding.epoch
            ))
        };
        let renewed = if renewed {
            Some(
                Attestation::verified(
                    address.clone(),
                    address.native_session_id.clone(),
                    binding.epoch,
                    binding.lifecycle,
                    binding.capabilities,
                    proof_ref("binding"),
                )
                .map_err(|error| CorrelationError::NotEvidence(error.to_string()))?,
            )
        } else {
            None
        };
        // Only the addressed actor itself, at a natural context point, with
        // qualified inject, may drain; a Claude child sharing the root
        // address never may.
        let drain = if kind.is_context_point()
            && native_id == address.native_session_id
            && binding.capabilities.inject
            && !binding.retired
        {
            Some(
                Attestation::verified(
                    address.clone(),
                    native_id.clone(),
                    binding.epoch,
                    Lifecycle::Active,
                    binding.capabilities,
                    proof_ref(kind.as_str()),
                )
                .map_err(|error| CorrelationError::NotEvidence(error.to_string()))?,
            )
        } else {
            None
        };
        Ok(HookAdmission {
            kind,
            address,
            role,
            native_id,
            renewed,
            drain,
        })
    }

    /// Stores one call record, evicting the oldest beyond the bound.
    fn record_call(&mut self, call: String, record: CallRecord) {
        self.calls.entry(call.clone()).or_default().push(record);
        self.call_order.push_back(call);
        while self.call_order.len() > self.max_calls {
            // ponytail: bounded linear scan (8192 records); index if measured hot.
            let Some(index) = self.call_order.iter().position(|call| {
                self.calls
                    .get(call)
                    .and_then(|records| records.first())
                    .is_some_and(|record| !record.claimed)
            }) else {
                break;
            };
            let oldest = self.call_order.remove(index).expect("known index");
            if let Some(records) = self.calls.get_mut(&oldest) {
                records.remove(0);
                if records.is_empty() {
                    self.calls.remove(&oldest);
                }
            }
        }
    }

    /// Refuses new observations before changing a binding when every available
    /// eviction candidate is reserved. Unresolved claims cannot be evicted.
    fn ensure_call_capacity(&self) -> Result<(), CorrelationError> {
        if self.call_order.len() < self.max_calls
            || self.call_order.iter().any(|call| {
                self.calls
                    .get(call)
                    .and_then(|records| records.first())
                    .is_some_and(|record| !record.claimed)
            })
        {
            return Ok(());
        }
        Err(CorrelationError::Unavailable(
            "native claim capacity exhausted".into(),
        ))
    }

    /// Drops only dead process bindings at capacity; live retired tombstones must
    /// remain refusal fences against automatic native descriptor rediscovery.
    fn evict_bindings(&mut self) {
        if self.bindings.len() < DEFAULT_MAX_BINDINGS {
            return;
        }
        self.bindings
            .retain(|_, binding| os::incarnation_alive(binding.harness.0, binding.harness.1));
    }

    /// Attests the actual caller of one MCP request.
    ///
    /// `peer` is the kernel identity of the process presenting the request
    /// (the harness-launched MCP server). It must belong to a qualified
    /// harness of the metadata's host; the per-call id must join exactly
    /// one unconsumed record from that same harness incarnation, of the
    /// binding's current epoch, younger than the configured age; Codex's
    /// thread id must be the record's actor. A successful join consumes the
    /// record.
    pub fn attest_caller(
        &mut self,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
    ) -> Result<VerifiedCaller, CorrelationError> {
        if let PresentedMeta::Sealed { proof } = meta {
            return self.redeem(peer, proof, now_ms);
        }
        let (caller, harness, call, _) = self.inspect_native(peer, meta, now_ms, false)?;
        let records = self.calls.get_mut(&call).expect("verified record");
        records
            .iter_mut()
            .find(|record| record.harness == harness)
            .expect("verified incarnation")
            .consumed = true;
        Ok(caller)
    }

    /// Validates a native source without spending it. `allow_spent` is only
    /// historical replay origin inspection; it never returns fresh permission.
    /// Result fixes caller, actual incarnation, native call and host tool name.
    fn inspect_native(
        &mut self,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
        allow_spent: bool,
    ) -> Result<NativeInspection, CorrelationError> {
        let (call, harness) = match meta {
            PresentedMeta::Sealed { .. } => {
                return Err(CorrelationError::NotEvidence(
                    "native metadata required".into(),
                ));
            }
            native => native.native().expect("native metadata"),
        };
        let call = call.to_string();
        checked_id(&call, "call id").map_err(CorrelationError::NotEvidence)?;
        let matched = self.harness_of(peer, harness)?;
        let max_age = self.config.max_call_age_ms;
        let records = self
            .calls
            .get(&call)
            .ok_or_else(|| CorrelationError::Missing(call.clone()))?;
        let same: Vec<&CallRecord> = records
            .iter()
            .filter(|record| record.harness == matched.incarnation)
            .collect();
        if same.is_empty() {
            return Err(CorrelationError::Missing(call));
        }
        if !allow_spent && same.iter().any(|record| record.claimed) {
            return Err(CorrelationError::Unavailable(
                "native evidence reserved".into(),
            ));
        }
        if !allow_spent && same.iter().any(|record| record.consumed) {
            return Err(CorrelationError::Duplicate(call));
        }
        if same.len() > 1 {
            let first = (&same[0].address, &same[0].native_id);
            return Err(
                if same.iter().all(|r| (&r.address, &r.native_id) == first) {
                    CorrelationError::Duplicate(call)
                } else {
                    CorrelationError::Conflicting(call)
                },
            );
        }
        let record = same[0];
        let binding = self
            .bindings
            .get(&record.address)
            .ok_or_else(|| CorrelationError::Missing(call.clone()))?;
        if binding.retired
            || binding.harness != matched.incarnation
            || binding.epoch != record.epoch
        {
            return Err(CorrelationError::Stale(call));
        }
        if now_ms.saturating_sub(record.observed_ms) > max_age || record.observed_ms > now_ms {
            return Err(CorrelationError::Stale(call));
        }
        if let PresentedMeta::Codex { thread_id, .. } = meta
            && *thread_id != record.native_id
        {
            return Err(CorrelationError::Conflicting(call));
        }
        Ok((
            VerifiedCaller::new(
                binding.address.clone(),
                record.role,
                record.native_id.clone(),
                binding.epoch,
                record.observed_ms,
                match harness {
                    Harness::ClaudeCode => CallerChannel::ClaudeToolUse,
                    Harness::Codex => CallerChannel::CodexCall,
                },
            ),
            matched.incarnation,
            call,
            record.tool_name.clone(),
        ))
    }

    /// Attests a caller like [`Registry::attest_caller`] (native metadata
    /// only) and issues a sealed single-use proof of exactly that result
    /// for the frontend to forward to a configured relay.
    pub fn attest_and_seal(
        &mut self,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
    ) -> Result<(VerifiedCaller, SealedProof), CorrelationError> {
        if matches!(meta, PresentedMeta::Sealed { .. }) {
            return Err(CorrelationError::NotEvidence(
                "a sealed proof cannot be resealed".into(),
            ));
        }
        let (source_caller, source_harness, native_call_id, tool_name) =
            self.inspect_native(peer, meta, now_ms, false)?;
        let source_use_key = self.source_use_key(
            &native_call_id,
            source_harness,
            source_caller.epoch(),
            source_caller.observed_at_ms(),
        );
        let caller = self.attest_caller(peer, meta, now_ms)?;
        let claims = &self.claims;
        self.sealed.retain(|_, sealed| {
            sealed.expires_ms > now_ms || claims.contains_key(&sealed.source_use_key)
        });
        if self.sealed.len() >= MAX_SEALED {
            return Err(CorrelationError::Unavailable(
                "too many outstanding sealed proofs".into(),
            ));
        }
        let random = crate::os::random_bytes()
            .map_err(|error| CorrelationError::Unavailable(error.to_string()))?;
        let proof: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let binding = caller.address.to_canonical_string();
        let harness = self
            .bindings
            .get(&binding)
            .map(|binding| binding.harness)
            .ok_or_else(|| CorrelationError::Missing("binding vanished".into()))?;
        self.sealed.insert(
            crate::server::sha256_hex(proof.as_bytes()),
            Sealed {
                caller: caller.clone(),
                binding,
                harness,
                expires_ms: now_ms.saturating_add(SEALED_PROOF_TTL_MS),
                source_use_key,
                native_call_id,
                tool_name,
            },
        );
        Ok((caller, SealedProof(proof)))
    }

    /// Redeems a sealed proof for a configured relay process, once.
    ///
    /// The peer must run as the owner from a configured relay executable,
    /// unmodified since it started and with the configured digest. The
    /// proof is consumed by any redemption attempt that finds it; an
    /// expired proof, or one whose binding was renewed, retired or lost its
    /// harness since issue, is stale.
    fn redeem(
        &mut self,
        peer: PeerIdentity,
        proof: &SealedProof,
        now_ms: u64,
    ) -> Result<VerifiedCaller, CorrelationError> {
        self.verify_relay(peer)?;
        let digest = crate::server::sha256_hex(proof.as_str().as_bytes());
        if self
            .sealed
            .get(&digest)
            .is_some_and(|sealed| self.claims.contains_key(&sealed.source_use_key))
        {
            return Err(CorrelationError::Unavailable(
                "sealed evidence reserved".into(),
            ));
        }
        let sealed = self
            .sealed
            .remove(&digest)
            .ok_or_else(|| CorrelationError::Missing("sealed proof".into()))?;
        if sealed.expires_ms <= now_ms {
            return Err(CorrelationError::Stale("sealed proof expired".into()));
        }
        let current = self.bindings.get(&sealed.binding).is_some_and(|binding| {
            !binding.retired
                && binding.harness == sealed.harness
                && binding.epoch == sealed.caller.epoch
                && os::incarnation_alive(binding.harness.0, binding.harness.1)
        });
        if !current {
            return Err(CorrelationError::Stale(
                "binding changed since sealing".into(),
            ));
        }
        Ok(sealed.caller.into_relayed())
    }

    /// Computes the attestation that records a change of the message
    /// capability of `address` to `message`, without applying it.
    ///
    /// A carrier calls this after observing the native inbox under the
    /// snapshot `expected` (from [`Registry::attest_recipient`]): `true`
    /// when the same session and incarnation advertises its inbox (a late
    /// binding), `false` when it positively runs with the inbox disabled.
    /// An absent or not-yet-advertised inbox is transient and must not call
    /// this. The carrier records the returned attestation in core first and
    /// only then applies it with [`Registry::commit_message`], so the
    /// registry never grants message while core still refuses it, and a
    /// failed core write leaves the binding unchanged for the next check.
    /// A withdrawal lasts until the binding is renewed (a new
    /// `SessionStart` or incarnation takes capabilities from the profile
    /// again) or the same incarnation later advertises its inbox.
    ///
    /// Returns `Ok(None)` when nothing would change: the capability already
    /// has that value, or `message` is `true` but the loaded build is not
    /// qualified for it (a late inbox never promotes beyond `qualified`).
    /// The endpoint epoch, lifecycle and actor are the binding's own.
    ///
    /// # Errors
    ///
    /// The binding is gone, retired, or was renewed since `expected` was
    /// taken (another endpoint epoch or harness incarnation): an
    /// observation of an old incarnation never changes a renewed binding;
    /// the caller holds and re-attests.
    pub fn message_change(
        &self,
        address: &NativeAddress,
        expected: &RecipientBinding,
        message: bool,
    ) -> Result<Option<Attestation>, String> {
        let binding = self
            .bindings
            .get(&address.to_canonical_string())
            .ok_or_else(|| {
                "no attested binding for this recipient (unknown, not inactive)".to_string()
            })?;
        same_binding(binding, expected)?;
        if binding.capabilities.message == message || (message && !binding.qualified.message) {
            return Ok(None);
        }
        let label = if message {
            "message-restored"
        } else {
            "message-disabled"
        };
        Attestation::verified(
            binding.address.clone(),
            binding.address.native_session_id.clone(),
            binding.epoch,
            binding.lifecycle,
            Capabilities {
                message,
                ..binding.capabilities
            },
            proof(format!(
                "{label}:{}@{}:{}:epoch{}",
                binding.harness.0, binding.harness.1, binding.version, binding.epoch
            )),
        )
        .map(Some)
        .map_err(|error| error.to_string())
    }

    /// Applies a message capability change that core has already recorded
    /// (see [`Registry::message_change`]) to the binding `expected` was
    /// taken from. Never grants message beyond `qualified`.
    ///
    /// # Errors
    ///
    /// The same as [`Registry::message_change`]: gone, retired or renewed
    /// since `expected`; nothing is changed then.
    pub fn commit_message(
        &mut self,
        address: &NativeAddress,
        expected: &RecipientBinding,
        message: bool,
    ) -> Result<(), String> {
        let binding = self
            .bindings
            .get_mut(&address.to_canonical_string())
            .ok_or_else(|| {
                "no attested binding for this recipient (unknown, not inactive)".to_string()
            })?;
        same_binding(binding, expected)?;
        binding.capabilities.message = message && binding.qualified.message;
        self.persist_routes()
    }

    /// Addresses of live `harness` bindings whose message capability was
    /// withdrawn at runtime although the loaded build is qualified for it.
    ///
    /// A carrier re-checks these periodically, independent of pending
    /// work, so a late inbox restores message even when no event waits
    /// (publications are refused while it is withdrawn, so no work would
    /// otherwise trigger the check). Retired bindings and builds not
    /// qualified for message are never listed. The list is bounded by the
    /// registry's own binding bound.
    pub fn message_withdrawn(&self, harness: Harness) -> Vec<NativeAddress> {
        self.bindings
            .values()
            .filter(|binding| {
                binding.address.harness == harness
                    && !binding.retired
                    && binding.qualified.message
                    && !binding.capabilities.message
            })
            .map(|binding| binding.address.clone())
            .collect()
    }

    /// Copies current Codex MESSAGE qualification and private binding under the
    /// lock, without OS/file/native I/O. The owned candidate MUST be validated
    /// outside the lock on every attest/send, and app frontends separately checked.
    /// Missing profiles, disabled message capability and legacy tombstones refuse.
    pub(crate) fn codex_message_candidate(
        &self,
        address: &NativeAddress,
    ) -> Result<CodexMessageCandidate, String> {
        let binding = self
            .bindings
            .get(&address.to_canonical_string())
            .ok_or("no Codex message binding")?;
        if address.harness != Harness::Codex
            || self.message_disabled.contains(&Harness::Codex)
            || (binding.retired && !binding.desktop_idle_message)
        {
            return Err("Codex message binding unavailable".into());
        }
        let qualified = self
            .config
            .profiles
            .iter()
            .find(|p| {
                p.harness == Harness::Codex
                    && p.namespace == address.native_store_namespace
                    && p.store == binding.store
            })
            .and_then(|p| p.executables.iter().find(|e| e.path == binding.executable))
            .ok_or("Codex message profile changed")?
            .clone();
        let keys = self
            .digests
            .iter()
            .filter(|(key, digest)| {
                key.path == qualified.path && digest.eq_ignore_ascii_case(&qualified.sha256)
            })
            .map(|(key, _)| key.clone())
            .collect();
        Ok(CodexMessageCandidate {
            binding: binding.clone(),
            qualified,
            owner_uid: self.owner_uid,
            keys,
        })
    }

    /// Refuses a MESSAGE snapshot changed during unlocked OS/frontend validation.
    /// Compares the entire binding including same-epoch lifecycle/capabilities,
    /// retirement and private transcript evidence, and current host disablement.
    /// Pure in-memory check; callers run it under the registry lock last, on both
    /// attest and send. It grants no caller or ordinary recipient authority.
    pub(crate) fn codex_message_current(
        &self,
        candidate: &CodexMessageCandidate,
    ) -> Result<(), String> {
        if self.message_disabled.contains(&Harness::Codex)
            || self
                .bindings
                .get(&candidate.binding.address.to_canonical_string())
                != Some(&candidate.binding)
        {
            return Err("Codex message binding changed during validation".into());
        }
        Ok(())
    }

    /// Attests a recipient endpoint for ordinary recipient authority right now.
    ///
    /// Errors (core holds visibly, never treats as inactive) when no
    /// binding exists, it is retired, or its harness incarnation is gone.
    /// The actor is the addressed session itself; lifecycle is the latest
    /// owner-session observation.
    pub fn attest_recipient(
        &self,
        address: &NativeAddress,
    ) -> Result<(Attestation, RecipientBinding), String> {
        let binding = self
            .bindings
            .get(&address.to_canonical_string())
            .ok_or_else(|| {
                "no attested binding for this recipient (unknown, not inactive)".to_string()
            })?;
        if binding.retired {
            return Err("the recipient session ended (unknown, not inactive)".into());
        }
        if !os::incarnation_alive(binding.harness.0, binding.harness.1) {
            return Err(
                "the recipient's harness process is gone (disconnected, not inactive)".into(),
            );
        }
        let attestation = Attestation::verified(
            binding.address.clone(),
            binding.address.native_session_id.clone(),
            binding.epoch,
            binding.lifecycle,
            binding.capabilities,
            proof(format!(
                "carrier:{}@{}:{}:epoch{}",
                binding.harness.0, binding.harness.1, binding.version, binding.epoch
            )),
        )
        .map_err(|error| error.to_string())?;
        Ok((
            attestation,
            RecipientBinding {
                harness: binding.harness,
                epoch: binding.epoch,
                store: binding.store.clone(),
                executable: binding.executable.clone(),
                transcript: binding.transcript.clone(),
                desktop_message_only: false,
            },
        ))
    }
}

/// Whether the actor is the owner of the address its event belongs to: the
/// root, or a Codex child thread (which has its own address). A Claude
/// child shares the root's address and is not its owner.
fn owns_address(role: ActorRole, harness: Harness) -> bool {
    role == ActorRole::Root || (harness == Harness::Codex && role == ActorRole::Child)
}

/// Whether one hook event is the address owner's own real session start
/// (`startup`, `resume`, `clear` or an unlabeled `SessionStart`): the only
/// event that renews the binding and establishes idleness on its own. A
/// Claude child's `SessionStart` and a `compact` restart (which can fire
/// mid-turn) are not.
fn starts_own_session(
    kind: HookKind,
    role: ActorRole,
    harness: Harness,
    payload: &HookPayload,
) -> bool {
    kind == HookKind::SessionStart
        && owns_address(role, harness)
        && payload.source.as_deref() != Some("compact")
}

/// The next owner-session lifecycle after one hook event.
///
/// Prompt and tool events are active (a child's tool event means the root
/// awaits its subagent); `AskUserQuestion`, permission requests and
/// permission notifications await input; the owner's own `Stop`, idle-prompt
/// notification and non-`compact` `SessionStart` are idle; the owner's
/// `SessionEnd` is unknown. Every other event (`SubagentStop`, a Claude
/// child's `Stop`, `SessionStart`, `SessionEnd` or idle notification, other
/// notification types, a `compact` restart) keeps `current`, which for a new or renewed
/// binding is unknown: only the owner's own events may establish idle.
fn next_lifecycle(
    current: Lifecycle,
    kind: HookKind,
    role: ActorRole,
    harness: Harness,
    payload: &HookPayload,
) -> Lifecycle {
    let owner = owns_address(role, harness);
    match kind {
        HookKind::SessionStart if starts_own_session(kind, role, harness, payload) => {
            Lifecycle::Inactive
        }
        HookKind::SessionStart => current,
        HookKind::UserPromptSubmit | HookKind::PostToolUse | HookKind::PostToolUseFailure => {
            Lifecycle::Active
        }
        HookKind::PreToolUse => {
            if payload.tool_name.as_deref() == Some("AskUserQuestion") {
                Lifecycle::AwaitingInput
            } else {
                Lifecycle::Active
            }
        }
        HookKind::PermissionRequest => Lifecycle::AwaitingInput,
        HookKind::Notification => match payload.notification_type.as_deref() {
            Some("permission_prompt" | "elicitation_dialog") => Lifecycle::AwaitingInput,
            Some("idle_prompt") if owner => Lifecycle::Inactive,
            _ => current,
        },
        HookKind::Stop if owner => Lifecycle::Inactive,
        HookKind::Stop | HookKind::SubagentStop => current,
        HookKind::SessionEnd if owner => Lifecycle::Unknown,
        HookKind::SessionEnd => current,
    }
}

/// Resolves a harness process's own store directory from its own
/// environment: `CODEX_HOME` or `CLAUDE_CONFIG_DIR`, else `$HOME/.codex`
/// or `$HOME/.claude`.
fn harness_store(facts: &ProcessFacts, harness: Harness) -> Option<PathBuf> {
    let (variable, default) = match harness {
        Harness::Codex => ("CODEX_HOME", ".codex"),
        Harness::ClaudeCode => ("CLAUDE_CONFIG_DIR", ".claude"),
    };
    if let Some(value) = os::process_env(facts.pid, variable) {
        return Some(PathBuf::from(value));
    }
    os::process_env(facts.pid, "HOME").map(|home| PathBuf::from(home).join(default))
}

/// Whether two paths name the same directory (canonicalized when both
/// exist, otherwise compared literally).
fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// Lowercase hex SHA-256 of a file's bytes, streamed.
pub fn file_sha256(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    //! The executable digest cache: warmed before serving, never trusted.

    use super::*;

    /// Controlled permission/renewal during the production frontend picker
    /// refuses before returning a route. Same-epoch changes invalidate the entire
    /// snapshot, including permission/input state, capabilities and idle inode;
    /// default-reading old journal rows cannot mint the private Desktop fact.
    #[test]
    fn codex_message_stamp_rejects_same_epoch_changes_and_legacy_facts() {
        let mut registry = registry_with(&[]);
        let address = NativeAddress::new("h", Harness::Codex, "ns", "idle").unwrap();
        let binding = Binding {
            address: address.clone(),
            harness: (1, 2),
            epoch: 3,
            capabilities: Capabilities {
                inject: true,
                message: true,
            },
            qualified: Capabilities {
                inject: true,
                message: true,
            },
            version: "qualified".into(),
            lifecycle: Lifecycle::Unknown,
            transcript: Some("/tmp/store/sessions/idle.jsonl".into()),
            store: "/tmp/store".into(),
            executable: "/tmp/executable".into(),
            retired: true,
            desktop_idle_message: true,
            desktop_idle_transcript: Some((4, 5)),
        };
        let candidate = CodexMessageCandidate {
            binding: binding.clone(),
            owner_uid: 0,
            keys: Vec::new(),
            qualified: QualifiedExecutable {
                path: binding.executable.clone(),
                sha256: "0".repeat(64),
                version: "qualified".into(),
                inject: true,
                message: true,
            },
        };
        let key = address.to_canonical_string();
        registry.bindings.insert(key.clone(), binding.clone());
        assert!(registry.codex_message_current(&candidate).is_ok());
        {
            let shared = std::cell::RefCell::new(&mut registry);
            let selected = PathBuf::from("/owned/frontend.sock");
            assert_eq!(
                crate::codex::checked_frontend(
                    || Ok(Some(selected.clone())),
                    || shared.borrow().codex_message_current(&candidate),
                )
                .unwrap(),
                Some(selected.clone())
            );
            for renewed in [false, true] {
                shared
                    .borrow_mut()
                    .bindings
                    .insert(key.clone(), binding.clone());
                let result = crate::codex::checked_frontend(
                    || {
                        let mut registry = shared.borrow_mut();
                        let current = registry.bindings.get_mut(&key).unwrap();
                        if renewed {
                            current.epoch += 1;
                        } else {
                            current.lifecycle = Lifecycle::AwaitingInput;
                        }
                        Ok(Some(selected.clone()))
                    },
                    || shared.borrow().codex_message_current(&candidate),
                );
                assert!(
                    result.is_err(),
                    "frontend chosen during permission/renewal must not escape final fence"
                );
            }
        }
        for change in 0..8 {
            let mut changed = binding.clone();
            match change {
                0 => changed.lifecycle = Lifecycle::AwaitingInput,
                1 => changed.capabilities.message = false,
                2 => changed.retired = false,
                3 => changed.desktop_idle_message = false,
                4 => changed.desktop_idle_transcript = Some((4, 6)),
                5 => changed.harness.0 = 7,
                6 => changed.epoch += 1,
                _ => changed.capabilities.inject = false,
            }
            registry.bindings.insert(key.clone(), changed);
            assert!(registry.codex_message_current(&candidate).is_err());
        }
        registry.bindings.insert(key, binding.clone());
        registry.message_disabled.push(Harness::Codex);
        assert!(registry.codex_message_current(&candidate).is_err());
        let mut legacy = serde_json::to_value(binding).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("desktop_idle_message");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("desktop_idle_transcript");
        let restored: Binding = serde_json::from_value(legacy).unwrap();
        assert!(restored.retired);
        assert!(!restored.desktop_idle_message);
        assert!(restored.desktop_idle_transcript.is_none());
        let old_shape = serde_json::to_value(restored).unwrap();
        assert!(old_shape.get("desktop_idle_message").is_none());
        assert!(old_shape.get("desktop_idle_transcript").is_none());
    }

    /// A registry whose one Claude profile qualifies `executables` (path,
    /// configured digest) and whose relays are empty.
    fn registry_with(executables: &[(&Path, &str)]) -> Registry {
        let config = RegistryConfig {
            host_id: "h".into(),
            profiles: vec![Profile {
                namespace: "ns".into(),
                harness: Harness::ClaudeCode,
                store: PathBuf::from("/tmp/store"),
                executables: executables
                    .iter()
                    .map(|(path, sha256)| QualifiedExecutable {
                        path: path.to_path_buf(),
                        sha256: (*sha256).into(),
                        version: "t".into(),
                        inject: true,
                        message: true,
                    })
                    .collect(),
            }],
            intermediates: Vec::new(),
            max_call_age_ms: 600_000,
            relays: Vec::new(),
            audiences: Vec::new(),
        };
        Registry::new(config, 0).unwrap()
    }

    /// A fresh temporary directory for one test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("m2{tag}{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Construction alone (no manual warm) caches the real digest of every
    /// readable configured file; a wrong configured digest is never trusted
    /// over the hashed file, a missing file is skipped without affecting the
    /// others, and warming again reads nothing (proved by a sentinel digest
    /// planted under the unchanged file's identity, which a re-read would
    /// overwrite).
    #[test]
    fn warming_hashes_real_files_and_never_trusts_the_configured_digest() {
        let dir = scratch("warm");
        let good = dir.join("good");
        let wrong = dir.join("wrong");
        let missing = dir.join("missing");
        std::fs::write(&good, vec![7u8; 1 << 20]).unwrap();
        std::fs::write(&wrong, vec![9u8; 1 << 20]).unwrap();
        let good_digest = file_sha256(&good).unwrap();
        let bad_config = "0".repeat(64);
        let mut registry = registry_with(&[
            (&good, &good_digest),
            (&wrong, &bad_config),
            (&missing, &good_digest),
        ]);
        registry
            .verify_loaded(&good, u64::MAX, &good_digest)
            .expect("the warmed, unchanged file attests");
        let sentinel = "5".repeat(64);
        registry
            .digests
            .insert(file_key(&good).unwrap(), sentinel.clone());
        assert_eq!(registry.warm_digests(), (2, 1));
        registry
            .verify_loaded(&good, u64::MAX, &sentinel)
            .expect("an unchanged file's cached digest is not re-read");
        assert!(
            registry
                .verify_loaded(&wrong, u64::MAX, &bad_config)
                .is_err()
        );
        assert!(
            registry
                .verify_loaded(&missing, u64::MAX, &good_digest)
                .is_err()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Serving never hashes: a file without a startup digest is unqualified even
    /// when its contents match the configured digest, and a file replaced
    /// after startup (by rename or in place, with the same size and within
    /// the same second) or removed is refused too, while an unaffected
    /// warmed path keeps attesting.
    #[test]
    fn changed_new_or_missing_files_fail_closed_without_hashing() {
        let dir = scratch("chg");
        let kept = dir.join("kept");
        let renamed = dir.join("renamed");
        let rewritten = dir.join("rewritten");
        let removed = dir.join("removed");
        let late = dir.join("late");
        for path in [&kept, &renamed, &rewritten, &removed] {
            std::fs::write(path, vec![1u8; 4096]).unwrap();
        }
        let digest = file_sha256(&kept).unwrap();
        let all = [&kept, &renamed, &rewritten, &removed, &late];
        let config: Vec<(&Path, &str)> =
            all.iter().map(|p| (p.as_path(), digest.as_str())).collect();

        // An unwarmed (cleared) cache: the digest would match, so only a
        // refusal proves the request path did not hash.
        let mut cold = registry_with(&config);
        cold.digests.clear();
        assert!(cold.verify_loaded(&kept, u64::MAX, &digest).is_err());

        let mut registry = registry_with(&config);
        assert_eq!(registry.warm_digests(), (4, 1), "late does not exist yet");
        for path in [&kept, &renamed, &rewritten, &removed] {
            registry.verify_loaded(path, u64::MAX, &digest).unwrap();
        }
        // Installed after startup, with the configured contents.
        std::fs::write(&late, vec![1u8; 4096]).unwrap();
        // Same size, same second, other content (so a reused digest would
        // be wrong, and only the identity check can refuse it).
        let other = dir.join("other");
        std::fs::write(&other, vec![2u8; 4096]).unwrap();
        std::fs::rename(&other, &renamed).unwrap();
        std::fs::write(&rewritten, vec![2u8; 4096]).unwrap();
        std::fs::remove_file(&removed).unwrap();
        for path in [&renamed, &rewritten, &removed, &late] {
            let error = registry.verify_loaded(path, u64::MAX, &digest);
            assert!(error.is_err(), "{path:?} must be unqualified");
        }
        registry
            .verify_loaded(&kept, u64::MAX, &digest)
            .expect("an untouched warmed file still attests");
        // A file modified after the process started is refused before any
        // digest question.
        assert!(registry.verify_loaded(&kept, 0, &digest).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The process start time and the file mtime are both whole seconds, so
    /// a file written in the very second a process was born may be the bytes
    /// that process loaded or newer ones written right after it loaded the
    /// old ones; that second is unknown and refused. Only a file strictly
    /// older than the process start (or no process at all, `u64::MAX`)
    /// attests.
    #[test]
    fn a_file_written_in_the_process_birth_second_is_not_proven_loaded() {
        let dir = scratch("birth");
        let exe = dir.join("exe");
        std::fs::write(&exe, vec![5u8; 4096]).unwrap();
        let digest = file_sha256(&exe).unwrap();
        let mut registry = registry_with(&[(&exe, &digest)]);
        let second = u64::try_from(file_key(&exe).unwrap().mtime.0).unwrap();
        assert!(
            registry.verify_loaded(&exe, second, &digest).is_err(),
            "same second as the process birth is ambiguous"
        );
        assert!(registry.verify_loaded(&exe, second - 1, &digest).is_err());
        registry
            .verify_loaded(&exe, second + 1, &digest)
            .expect("strictly older than the process start attests");
        registry
            .verify_loaded(&exe, u64::MAX, &digest)
            .expect("no process involved");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The startup diagnostic count covers every way a configured entry
    /// cannot attest: a missing file, a real hashed digest that differs
    /// from the configured one (the configured value is never trusted), and
    /// a file changed after it was hashed; matching files are not counted.
    #[test]
    fn unqualified_count_covers_missing_mismatched_and_changed_entries() {
        let dir = scratch("unq");
        let good = dir.join("good");
        let wrong = dir.join("wrong");
        let changed = dir.join("changed");
        let missing = dir.join("missing");
        for path in [&good, &wrong, &changed] {
            std::fs::write(path, vec![3u8; 4096]).unwrap();
        }
        let digest = file_sha256(&good).unwrap();
        let other = "1".repeat(64);
        let mut registry = registry_with(&[
            (&good, &digest),
            (&wrong, &other),
            (&changed, &digest),
            (&missing, &digest),
        ]);
        // wrong: hashed digest differs from the configured one; missing:
        // no file; good and changed qualify so far.
        assert_eq!(registry.warm_digests(), (3, 1));
        assert_eq!(registry.unqualified_executables(), 2);
        std::fs::write(&changed, vec![4u8; 4096]).unwrap();
        assert_eq!(
            registry.unqualified_executables(),
            3,
            "changed since hashed"
        );
        // A second configured entry for the same good path with a wrong
        // digest counts separately.
        let again = registry_with(&[(&good, &digest), (&good, &other)]);
        assert_eq!(again.unqualified_executables(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Sets the modification time of `path` to a fixed time long ago, as an
    /// installer that preserves timestamps (`cp -p`, `install -p`) would.
    fn backdate(path: &Path) {
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_577_833_200);
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }

    /// Whole second of the last status change (ctime) of `path`.
    fn status_change_second(path: &Path) -> i64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().ctime()
    }

    /// Blocks until the wall clock is in whole second `second`.
    fn wait_until_second(second: u64) {
        while std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            < second
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// An ordinary update that keeps an old mtime (installer-style: new bytes
    /// written, mtime backdated, renamed over the path) after the process
    /// started is still refused, because the kernel status-change time of
    /// the new file is not before the process birth second, even though the
    /// configured digest matches the new bytes and the mtime looks old. The
    /// process's own reported executable path does not change in this case
    /// (probed on this platform), so the file times are the only evidence.
    #[test]
    fn backdated_replacement_after_process_start_is_not_proven_loaded() {
        let dir = scratch("upd");
        let exe = dir.join("exe");
        std::fs::write(&exe, vec![1u8; 4096]).unwrap();
        backdate(&exe);
        let installed = u64::try_from(status_change_second(&exe)).unwrap();
        let born = installed + 1;
        let digest_old = file_sha256(&exe).unwrap();
        let mut before = registry_with(&[(&exe, &digest_old)]);
        before
            .verify_loaded(&exe, born, &digest_old)
            .expect("installed before the process was born");

        // The update happens after the process birth second.
        wait_until_second(born);
        let staged = dir.join("staged");
        std::fs::write(&staged, vec![2u8; 4096]).unwrap();
        backdate(&staged);
        std::fs::rename(&staged, &exe).unwrap();
        let digest_new = file_sha256(&exe).unwrap();
        assert_ne!(digest_old, digest_new);
        // A daemon constructed after the update warms and is configured
        // with the new digest.
        let mut after = registry_with(&[(&exe, &digest_new)]);
        assert!(
            after.verify_loaded(&exe, born, &digest_new).is_err(),
            "the old process cannot have loaded the new bytes"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An in-place same-size rewrite whose mtime is restored after startup
    /// cannot reuse the digest hashed before it: the status-change time is
    /// part of the file identity.
    #[test]
    fn restored_mtime_after_an_in_place_rewrite_does_not_reuse_the_warmed_digest() {
        let dir = scratch("inp");
        let exe = dir.join("exe");
        std::fs::write(&exe, vec![1u8; 4096]).unwrap();
        backdate(&exe);
        let digest = file_sha256(&exe).unwrap();
        let mut registry = registry_with(&[(&exe, &digest)]);
        registry
            .verify_loaded(&exe, u64::MAX, &digest)
            .expect("warmed and unchanged");
        // Same size, other bytes, original mtime put back.
        wait_until_second(u64::try_from(status_change_second(&exe)).unwrap() + 1);
        std::fs::write(&exe, vec![2u8; 4096]).unwrap();
        backdate(&exe);
        assert!(
            registry.verify_loaded(&exe, u64::MAX, &digest).is_err(),
            "the stale digest must not vouch for the rewritten file"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
