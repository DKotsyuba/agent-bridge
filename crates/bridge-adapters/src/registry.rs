//! Protected registry: harness incarnations, endpoint epochs, lifecycle and
//! fail-closed actor correlation.
//!
//! The registry lives in the Bridge daemon and is fed only by connections
//! on the adapter channel ([`crate::server`]) whose peer the kernel
//! identifies. A peer counts as a *hook of a harness* only when its parent
//! chain reaches the harness process through allowlisted intermediates
//! (shells), as the same user, for a harness kind enabled by the configured
//! harness policy. That process must be a marked harness (its resolved
//! executable path carries the product marker), run an executable that is
//! unchanged since it started, and have its own store (derived from its
//! environment) be a canonical directory owned by this user that no group or
//! other user can write. No store path or harness executable is predeclared.
//! That harness process incarnation (PID plus start time) is the protected
//! channel: every record below is scoped to it.
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
//! - **Component evidence.** Bridge's own privileged components (relays, owner
//!   relays, backend audiences) are qualified by the real SHA-256 of their exact
//!   file identity, hashed outside this registry's lock (at startup and by a
//!   background refresh after an update), never by reading a file while serving.
//!   Native recipient binaries are not predeclared: capabilities come from the
//!   harness-level policy.
//! - **Idle gateway.** A Codex Desktop address whose harness incarnation ended
//!   while positively idle can still receive one MESSAGE through a unique live
//!   Desktop frontend, from a transcript-bound proof and with no caller or inject
//!   authority (the `gateway` module).
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bridge_core::dispatch::{Attestation, Capabilities, Lifecycle};
use bridge_core::{Harness, NativeAddress};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::os::{self, PeerIdentity, ProcessFacts};
use crate::server::lock_registry;

mod assertions;
mod claims;
mod executables;
mod gateway;
mod observations;
pub(crate) use claims::EvidenceClaim;
pub use executables::VendorSignature;
#[cfg(test)]
use executables::wait_refresh;
pub(crate) use executables::{refresh_stale, stop_refresh};
pub(crate) use gateway::WakeProof;

/// Largest accepted native identifier (session, agent, call id), in bytes.
pub const MAX_NATIVE_ID_BYTES: usize = 256;

/// Default bound of retained call records; the oldest are evicted first,
/// which can only turn a later join into a refusal.
pub const DEFAULT_MAX_CALL_RECORDS: usize = 8_192;

/// Default bound of retained bindings.
pub const DEFAULT_MAX_BINDINGS: usize = 4_096;

/// Default largest age of a call record a caller may join, in milliseconds.
pub const DEFAULT_MAX_CALL_AGE_MS: u64 = 10 * 60_000;

/// Legacy migration input: one executable build of a retired profile entry.
///
/// It still parses so that a configuration written for the removed executable
/// trust loads, and only its `inject` and `message` flags are read (to derive
/// the harness-level policy when no `[[adapters.harnesses]]` entry exists). The
/// path, digest and signature never authorize, qualify or restrict a harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualifiedExecutable {
    /// Absolute resolved path of the harness executable.
    pub path: PathBuf,
    /// Lowercase hex SHA-256 recorded for the legacy file; never checked.
    pub sha256: String,
    /// Human version label recorded in legacy configuration.
    pub version: String,
    /// Legacy: root hook context injection declared for this build; read only to
    /// derive the harness policy when no `harnesses` entry exists.
    pub inject: bool,
    /// Legacy: the harness's message carrier declared for this build; read only
    /// to derive the harness policy when no `harnesses` entry exists.
    pub message: bool,
    /// Optional legacy vendor signing identity, ignored (see [`VendorSignature`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<VendorSignature>,
}

/// Legacy migration input: one native store entry of the retired static trust.
///
/// A configuration written for it still loads. It authorizes nothing: no store
/// is allowed or refused because of it. Its only effects are the harness policy
/// derived from it when no `[[adapters.harnesses]]` entry exists, and the
/// namespace label an address of exactly this store keeps, so addresses of
/// existing journals and consumers stay stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The `native_store_namespace` component of addresses in this store.
    pub namespace: String,
    /// Harness product of the store.
    pub harness: Harness,
    /// Absolute store directory (`CODEX_HOME`, Claude config directory); only a
    /// namespace label, never an allowlist entry.
    pub store: PathBuf,
    /// Legacy executable entries; only their capability flags are read.
    pub executables: Vec<QualifiedExecutable>,
}

/// Harness-level policy: which native harness product this daemon serves, the
/// default `native_store_namespace` of its addresses and the capabilities its
/// bindings carry. It names no store path and no executable: a fresh session of
/// the harness in any canonical owner-only store registers from its genuine
/// lifecycle hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessPolicy {
    /// The harness product (`Codex`, `ClaudeCode` or `OpenCode`).
    pub harness: Harness,
    /// Default `native_store_namespace` component of this harness's addresses.
    pub namespace: String,
    /// Root hook context injection is supported for this harness.
    pub inject: bool,
    /// The harness's message carrier is supported.
    pub message: bool,
    /// Case-insensitive substrings of the harness process's resolved executable
    /// path that positively mark it as this product. Empty means the product name
    /// (`codex`, `claude` or `opencode`). An unrelated ancestor (a terminal, a build tool, a
    /// generic wrapper) matches none and is never a harness. Best-effort
    /// identification, not authentication.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executable_markers: Vec<String>,
}

/// Registry configuration, normally the `[adapters]` table of the daemon
/// configuration (operator-owned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// `host_id` component of every address this daemon attests.
    pub host_id: String,
    /// Harness-level policies; empty together with empty `profiles` serves no
    /// native harness.
    #[serde(default)]
    pub harnesses: Vec<HarnessPolicy>,
    /// Legacy migration input (see [`Profile`]); authorizes nothing.
    #[serde(default)]
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
    /// Parse-only legacy input: how many `[[adapters.owner_relays]]` entries a
    /// configuration written for the removed owner path and SHA-256 allowlist
    /// carries. The entries themselves are discarded unread: they authorize
    /// nothing, join no digest cache and play no part in owner admission; the
    /// count only lets [`Registry::migration_notes`] report them as
    /// `legacy_owner_relays_ignored`. Never serialized and not a current setting.
    #[doc(hidden)]
    #[serde(
        default,
        rename = "owner_relays",
        deserialize_with = "count_legacy_entries",
        skip_serializing
    )]
    pub legacy_owner_relays: usize,
}

/// Prefix of the migration note that reports an ignored legacy `owner_relays`
/// table: the daemon log event and the `bridge doctor` check
/// `legacy_owner_relays_ignored` are derived from it. Profile notes carry no
/// prefix and keep their established event and check names.
pub const LEGACY_OWNER_RELAYS_PREFIX: &str = "legacy_owner_relays_ignored: ";

/// Deserializes a legacy list setting into its entry count, discarding every
/// entry unread (whatever its shape): the parse-only half of a retired setting.
fn count_legacy_entries<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<usize, D::Error> {
    Vec::<serde::de::IgnoredAny>::deserialize(deserializer).map(|entries| entries.len())
}

impl RegistryConfig {
    /// The effective harness-level policies and the notes of what was migrated
    /// or ignored from legacy `profiles` and `owner_relays`, exactly as
    /// [`Registry::new`] derives them, without building a registry (no file is
    /// read). Used by the operator checks.
    ///
    /// # Errors
    ///
    /// An invalid namespace, two policies for one harness, `harnesses` together
    /// with legacy `profiles`, or legacy profiles of one harness naming more than
    /// one distinct namespace.
    pub fn harness_policies(&self) -> Result<(Vec<HarnessPolicy>, Vec<String>), String> {
        Registry::derive_policies(self)
    }
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
    /// marked harness process of a served policy, wrong user, model arguments,
    /// foreign fields).
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
    /// Trusted OpenCode Bridge plugin context joined to its exact native hook call.
    #[serde(rename = "opencode_call")]
    OpenCodeCall,
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
    /// Native context carried by the first-party OpenCode Bridge plugin only.
    /// Ordinary OpenCode MCP session metadata alone is not a complete contract.
    #[serde(rename = "opencode")]
    OpenCode {
        /// Native ToolContext.sessionID, independent of model arguments.
        session_id: String,
        /// Native ToolContext.id joined to the plugin's protected PreToolUse record.
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
        let opencode = ["ai.opencode/sessionID", "ai.agent_bridge/toolCallID"]
            .iter()
            .any(|key| meta.contains_key(*key));
        let field = |name: &str| -> Result<String, CorrelationError> {
            let value = meta
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CorrelationError::NotEvidence(format!("_meta {name} missing")))?;
            checked_id(value, name).map_err(CorrelationError::NotEvidence)
        };
        match (codex, claude, opencode) {
            (true, false, false) => {
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
            (false, true, false) => Ok(PresentedMeta::Claude {
                tool_use_id: field("claudecode/toolUseId")?,
            }),
            (false, false, true) => Ok(PresentedMeta::OpenCode {
                session_id: field("ai.opencode/sessionID")?,
                call_id: field("ai.agent_bridge/toolCallID")?,
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
            PresentedMeta::OpenCode { call_id, .. } => Some((call_id, Harness::OpenCode)),
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
    /// OpenCode observed activity; never a context drain or caller record.
    OpenCodeActivity,
    /// OpenCode lost its lifecycle feed; readiness is explicitly unknown.
    OpenCodeUnknown,
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
            "OpenCodeActivity" => HookKind::OpenCodeActivity,
            "OpenCodeUnknown" => HookKind::OpenCodeUnknown,
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
            HookKind::OpenCodeActivity => "OpenCodeActivity",
            HookKind::OpenCodeUnknown => "OpenCodeUnknown",
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
    /// The capabilities the harness policy grants at renewal (minus host-level
    /// unsupported paths); never exceeded.
    qualified: Capabilities,
    /// Label of the policy the binding was made under, for proof references.
    version: String,
    /// Owner-session lifecycle from the latest hook; a new or renewed
    /// binding starts [`Lifecycle::Unknown`] and leaves it only on a
    /// positive owner-actor observation ([`next_lifecycle`]).
    lifecycle: Lifecycle,
    /// Session transcript inside the harness store, when reported.
    transcript: Option<PathBuf>,
    /// Harness store of the binding (the harness process's own, a process fact).
    store: PathBuf,
    /// Harness executable of the binding, as the verified process runs it (a
    /// process fact, never an allowlist entry).
    executable: PathBuf,
    /// Set by the root's `SessionEnd`, and by an OpenCode child's own
    /// `SessionEnd` (its own address ended); normal recipient and caller
    /// authority stays refused until a renewal.
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
    /// Positive-idle proof of a live Codex Desktop owner, bound to its exact
    /// stable transcript, enabling the MESSAGE-only gateway route after the
    /// harness incarnation ends (see the `gateway` module). Stamped only by an
    /// owner hook that leaves the lifecycle `Inactive` and cleared by every other
    /// lifecycle, renewal, retirement and a spent hand-off; absent in journals of
    /// older builds (such rows are never gateway-eligible) and omitted when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wake: Option<WakeProof>,
    /// Journal compatibility only: a row written by the removed vendor-signature
    /// verification of a route whose build was not yet proven. It is never
    /// written (always false) and a row carrying `true` is dropped on restore,
    /// because it was never proven; the harness's own next hook registers the
    /// address afresh. Absent in journals of other builds; omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pending: bool,
    /// OpenCode only: the actor whose own hooks feed this address (`Root`, or
    /// `Child` for a subagent session, which is never a MESSAGE recipient),
    /// recorded at binding. `None` for every other harness (their rows keep
    /// their shape) and in OpenCode rows written by earlier builds: such a row
    /// is ambiguous, restored without MESSAGE until the address's own next hook
    /// renews it with the actor recorded. An earlier build refuses a journal
    /// carrying this field (rows deny unknown fields), like `wake`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<ActorRole>,
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
    /// The harness's own store, derived from its process environment and proven
    /// canonical, owned by this user and not writable by group or other.
    store: PathBuf,
    /// The resolved executable of the harness process (a process fact recorded
    /// for incarnation consistency, never an allowlist entry).
    executable: PathBuf,
    /// The harness-level policy of the matched harness kind.
    policy: HarnessPolicy,
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
    Some(key_of(path, &std::fs::metadata(path).ok()?))
}

/// The identity of `path` from already read `metadata`, which may come from an
/// opened descriptor so the identity is that of the exact file being read.
fn key_of(path: &Path, metadata: &std::fs::Metadata) -> FileKey {
    FileKey {
        path: path.to_path_buf(),
        inode: (metadata.dev(), metadata.ino()),
        len: metadata.len(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

/// Recipient view for the message carriers.
#[derive(Debug, Clone)]
pub struct RecipientBinding {
    /// Harness incarnation `(pid, start_time)` owning the session.
    pub harness: (u32, u64),
    /// Endpoint epoch.
    pub epoch: u64,
    /// Harness store directory, the harness process's own (a process fact).
    pub store: PathBuf,
    /// Harness executable the verified process runs (a process fact).
    pub executable: PathBuf,
    /// Session transcript inside the store, when reported by hooks.
    pub transcript: Option<PathBuf>,
    /// This MESSAGE snapshot requires the native Desktop route even if its
    /// capability disappears after validation; never fall back to a CLI helper.
    pub(crate) desktop_message_only: bool,
    /// This snapshot is the MESSAGE-only physical gateway of an idle address
    /// whose harness incarnation ended; `harness` is then the gateway, and a
    /// hand-off through it spends the one-shot wake proof.
    pub(crate) gateway: bool,
}

/// Owned MESSAGE validation snapshot of a Codex or Claude Code recipient;
/// performs OS/file validation after releasing the registry lock. Ordinary
/// bindings retain their capabilities; retired Codex Desktop exceptions supply no
/// inject, caller or call authority. Both the carrier routes and the native owner
/// route start from this snapshot and then separately prove their own route.
pub(crate) struct MessageCandidate {
    /// Exact private binding, including its unchanged tombstone epoch.
    binding: Binding,
    /// Current harness-level policy, never journal authority: it can only narrow
    /// the binding's capabilities.
    policy: HarnessPolicy,
    /// Owner required for both process and retained transcript.
    owner_uid: u32,
}

impl MessageCandidate {
    /// Revalidates exact PID/start, owner, recorded executable and the harness's
    /// own canonical owner-only store. Retired candidates additionally require the
    /// app capability and the same owned regular transcript under sessions,
    /// with no symlink/path traversal. Returns Inactive only for that private
    /// positive fact; all missing or changed evidence refuses before sending.
    /// Ordinary live bindings retain their owner lifecycle and capabilities.
    /// Current store aliases use the same canonical equivalence as admission;
    /// retired transcript checks still require the literal configured sessions
    /// prefix and a canonical path without symlink components, plus exact inode.
    /// The caller must perform the final locked stamp check after frontend I/O.
    ///
    /// A live, non-retired Codex Desktop binding whose lifecycle is `Unknown` but
    /// that carries an unspent idle proof is
    /// attested `Inactive`, message-only and flagged as a proof route (its send
    /// spends the proof) only while that exact transcript proof reads back
    /// unchanged; otherwise it stays `Unknown`, which core holds.
    pub(crate) fn validate(&self) -> Result<(Attestation, RecipientBinding), String> {
        let binding = &self.binding;
        let facts = self.live_check()?;
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
        } else if self.needs_idle_proof() && self.proves_idle().is_ok() {
            Lifecycle::Inactive
        } else {
            binding.lifecycle
        };
        let proven = !binding.retired && lifecycle != binding.lifecycle;
        let attestation = Attestation::verified(
            binding.address.clone(),
            binding.address.native_session_id.clone(),
            binding.epoch,
            lifecycle,
            Capabilities {
                inject: !binding.retired
                    && !proven
                    && binding.capabilities.inject
                    && self.policy.inject,
                message: binding.capabilities.message && self.policy.message,
            },
            proof(format!(
                "{}-message:{}@{}:epoch{}",
                match binding.address.harness {
                    Harness::Codex => "codex",
                    Harness::ClaudeCode => "claude",
                    Harness::OpenCode => "opencode",
                },
                binding.harness.0,
                binding.harness.1,
                binding.epoch
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
                gateway: proven,
            },
        ))
    }

    /// Re-reads the live harness of the snapshot and proves it still is the
    /// recorded incarnation (exact PID and start time), the same user, executable
    /// and store, an executable that is still owner/root-owned, non-writable and
    /// unchanged since process birth, and a store that is still a canonical
    /// directory owned by this user and not writable by group or other. Returns
    /// its facts.
    ///
    /// # Errors
    ///
    /// The harness is gone or anything above changed.
    fn live_check(&self) -> Result<ProcessFacts, String> {
        live_binding(&self.binding, self.owner_uid)
    }
}

/// Revalidates one existing binding's exact live PID/start, UID, executable and
/// process-selected canonical private store without modifying registry state.
/// Returns current process facts; any absent or changed fact fails closed.
fn live_binding(binding: &Binding, owner_uid: u32) -> Result<ProcessFacts, String> {
    let facts = os::process_facts(binding.harness.0).ok_or("harness is gone")?;
    if facts.uid != Some(owner_uid)
        || facts.start_time != binding.harness.1
        || facts.exe.as_ref() != Some(&binding.executable)
        || harness_store(&facts, binding.address.harness).is_none_or(|store| store != binding.store)
        || private_store(&binding.store, owner_uid).is_err()
        || executable_current(&binding.executable, &facts, owner_uid).is_err()
    {
        return Err("message harness/store changed".into());
    }
    Ok(facts)
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
/// private channel directory and recovered only for the same live harness
/// incarnation in its own store (or as a gateway candidate of a gone Codex
/// incarnation). Call records, exclusive claims, sealed proofs and detached
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
    /// Digests of the configured relay and audience executables
    /// hashed by [`Registry::warm_digests`] or [`refresh_stale`], keyed by the
    /// exact file identity; the newest identity per path only. Serving never
    /// hashes: the cache is filled only outside the registry lock.
    digests: HashMap<FileKey, String>,
    /// Single-flight flag of [`refresh_stale`]: set while a background pass runs.
    refreshing: Arc<AtomicBool>,
    /// Join handle of the running refresh pass, for [`stop_refresh`].
    pass: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    /// Set by [`stop_refresh`] when the daemon stops: no pass starts or commits.
    stopping: Arc<AtomicBool>,
    /// Effective harness-level policies, at most one per harness kind: the
    /// configured `harnesses`, or the single policy migrated from legacy profiles.
    policies: Vec<HarnessPolicy>,
    /// Plain-text notes of what was migrated or ignored from the legacy
    /// configuration, for the operator log; never silently dropped.
    migration_notes: Vec<String>,
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
    /// host id, a malformed digest, more than one policy for a harness, both
    /// `harnesses` and legacy `profiles`, or legacy profiles of one harness that
    /// name more than one distinct namespace.
    ///
    /// Native recipients are not predeclared by store or executable: the harness
    /// policy (or the single policy migrated from legacy profiles, whose paths,
    /// digests and signatures are dropped and reported by
    /// [`Registry::migration_notes`]) is all a fresh session needs.
    ///
    /// Before returning, hashes every configured relay and audience
    /// executable once ([`Registry::warm_digests`]), so a registry that is
    /// shared and served afterwards never reads an executable while
    /// handling a request and no caller has to remember a separate warm-up
    /// step. The call therefore blocks for about one streamed read of those
    /// files (about 1.6 s per 246 MB optimized, tens of seconds
    /// unoptimized); a missing or unreadable file does not fail the
    /// constructor, it just stays unqualified.
    pub fn new(config: RegistryConfig, owner_uid: u32) -> Result<Self, String> {
        Self::build(config, owner_uid)
    }

    /// Derives the effective harness policies and the migration notes from
    /// `config`: `harnesses` as written, or one policy per harness of the legacy
    /// `profiles` (union of their capability flags, their single namespace).
    ///
    /// # Errors
    ///
    /// A namespace is invalid, a harness has two policies, `harnesses` and
    /// `profiles` are both present, or legacy profiles of one harness name more
    /// than one distinct namespace (ambiguous: the operator must choose).
    pub(crate) fn derive_policies(
        config: &RegistryConfig,
    ) -> Result<(Vec<HarnessPolicy>, Vec<String>), String> {
        for policy in &config.harnesses {
            checked_id(&policy.namespace, "namespace")?;
        }
        if !config.harnesses.is_empty() && !config.profiles.is_empty() {
            return Err(
                "configure either [[adapters.harnesses]] or the legacy [[adapters.profiles]], not both"
                    .into(),
            );
        }
        let mut policies: Vec<HarnessPolicy> = Vec::new();
        let mut notes = Vec::new();
        if config.legacy_owner_relays > 0 {
            notes.push(format!(
                "{LEGACY_OWNER_RELAYS_PREFIX}{} [[adapters.owner_relays]] entr{} ignored; the native owner route no longer uses an owner path or digest and trusts only the same-user direct-parent owner running a trusted, unchanged executable, so nothing here authorizes or restricts anything",
                config.legacy_owner_relays,
                if config.legacy_owner_relays == 1 { "y" } else { "ies" }
            ));
        }
        for policy in &config.harnesses {
            if policies.iter().any(|known| known.harness == policy.harness) {
                return Err("one harness cannot carry two policies".into());
            }
            policies.push(policy.clone());
        }
        for profile in &config.profiles {
            checked_id(&profile.namespace, "namespace")?;
            let capability =
                |select: fn(&QualifiedExecutable) -> bool| profile.executables.iter().any(select);
            match policies
                .iter_mut()
                .find(|known| known.harness == profile.harness)
            {
                Some(known) if known.namespace != profile.namespace => {
                    return Err(format!(
                        "legacy profiles of one harness name more than one namespace ({} and {}); configure [[adapters.harnesses]] explicitly",
                        known.namespace, profile.namespace
                    ));
                }
                Some(known) => {
                    known.inject |= capability(|e| e.inject);
                    known.message |= capability(|e| e.message);
                }
                None => policies.push(HarnessPolicy {
                    harness: profile.harness,
                    namespace: profile.namespace.clone(),
                    inject: capability(|e| e.inject),
                    message: capability(|e| e.message),
                    executable_markers: Vec::new(),
                }),
            }
            notes.push(format!(
                "legacy profile {} migrated to the {:?} harness policy: its store path, {} executable path(s), digests and vendor signatures no longer authorize anything",
                profile.namespace,
                profile.harness,
                profile.executables.len()
            ));
        }
        if policies
            .iter()
            .any(|policy| policy.harness == Harness::OpenCode && policy.inject)
        {
            return Err("OpenCode hook context injection is not qualified".into());
        }
        Ok((policies, notes))
    }

    /// Validates `config`, derives the harness policies and warms the digest
    /// cache of the privileged components once.
    fn build(config: RegistryConfig, owner_uid: u32) -> Result<Self, String> {
        checked_id(&config.host_id, "host_id")?;
        let (policies, migration_notes) = Self::derive_policies(&config)?;
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
            refreshing: Arc::new(AtomicBool::new(false)),
            pass: Arc::new(Mutex::new(None)),
            stopping: Arc::new(AtomicBool::new(false)),
            policies,
            migration_notes,
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
    /// foreign, shared, oversized or unsupported files refuse startup. A recorded
    /// PID is the same incarnation only with its exact recorded start time (a reused
    /// PID is gone), and a live row whose process store, executable or owner no
    /// longer matches the recorded facts is omitted. A row carrying the removed
    /// `pending` flag is dropped, never restored: it was never proven. A gone
    /// Codex incarnation is retained, inert, only while it carries an *unspent*
    /// idle proof and its address still has a harness policy and an owned private
    /// store (its committed gateway is forgotten; a spent or absent proof drops the
    /// row). Retired tombstones retain their exact epoch and refusal fences; their
    /// optional Desktop MESSAGE fact is revalidated on every carrier use, never
    /// promoted into normal live authority by recovery. Missing new fields default
    /// false/None and false/None values are omitted, preserving old row shape.
    /// Rollback boundary: `Binding.wake` (written on every Desktop idle owner hook)
    /// and `Binding.pending` are journal fields and the row type denies unknown
    /// fields, so a daemon of an earlier build refuses to start on a journal that
    /// contains them; rolling back
    /// needs a compatible (earlier) journal or a fresh one, and no migration rewrites
    /// rows. A live OpenCode row keeps MESSAGE only when it records its actor as
    /// the root (`Binding.role`): a recorded child, or an earlier build's row
    /// with no actor fact, is restored with MESSAGE withheld, so core refuses a
    /// message to it before acceptance until its own next hook renews it. Current harness policy capabilities bound recovery; unknown/input-wait
    /// lifecycle stays such. No hook is manufactured and no caller/proof record is
    /// restored.
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
                // A row of the removed vendor verification was never proven; it
                // is inert history and is not restored.
                if binding.pending {
                    continue;
                }
                // The recorded incarnation is alive only if its PID is held by a
                // process with exactly the recorded start time: a reused PID is a
                // different process, gone for every purpose and never authority.
                let live = os::process_facts(binding.harness.0)
                    .filter(|facts| facts.start_time == binding.harness.1);
                let Some(facts) = live else {
                    // A gone incarnation survives only as an *unspent* gateway
                    // candidate (the spend is journaled before any native write, so
                    // a spent proof is already absent) of a still-configured exact
                    // thread, store and executable: it keeps its epoch and proof, no
                    // ordinary route attests it, and every gateway fact is proven
                    // again at use against the live gateway.
                    if self.policy(binding.address.harness).is_some()
                        && binding.address.harness == Harness::Codex
                        && private_store(&binding.store, self.owner_uid).is_ok()
                        && let Some(wake) = binding.wake.as_mut()
                    {
                        // A committed gateway was bound to a process of the
                        // previous daemon life: it is forgotten and re-committed
                        // with a fresh epoch at first use.
                        wake.forget_gateway();
                        self.bindings
                            .entry(binding.address.to_canonical_string())
                            .or_insert(binding);
                    }
                    continue;
                };
                if facts.uid != Some(self.owner_uid)
                    || facts.exe.as_ref() != Some(&binding.executable)
                    || harness_store(&facts, binding.address.harness).as_ref()
                        != Some(&binding.store)
                    || private_store(&binding.store, self.owner_uid).is_err()
                    || executable_current(&binding.executable, &facts, self.owner_uid).is_err()
                {
                    continue;
                }
                let Some(policy) = self.policy(binding.address.harness).cloned() else {
                    continue;
                };
                binding.epoch = now_ms.max(binding.epoch + 1);
                self.apply_policy(&mut binding, &policy);
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
            .filter(|b| !b.retired && !b.pending)
            .filter_map(|b| self.attest_recipient(&b.address).ok().map(|(a, _)| a))
            .collect())
    }

    /// The effective harness-level policy of `harness`, or `None` when this
    /// daemon serves no such harness.
    pub(crate) fn policy(&self, harness: Harness) -> Option<&HarnessPolicy> {
        self.policies
            .iter()
            .find(|policy| policy.harness == harness)
    }

    /// What was migrated or ignored from the legacy configuration, for the
    /// operator log and `bridge doctor`: one note per legacy profile, plus one
    /// `legacy_owner_relays_ignored` note (prefixed
    /// [`LEGACY_OWNER_RELAYS_PREFIX`]) when an `owner_relays` table was present;
    /// empty when none was configured.
    pub fn migration_notes(&self) -> &[String] {
        &self.migration_notes
    }

    /// Sets a restored binding's capabilities from the current harness policy:
    /// the saved capabilities are only ever narrowed, message is not granted on a
    /// host that disabled it, and the policy label replaces the saved one.
    /// An OpenCode row recorded as a child is never qualified for MESSAGE, and
    /// one without a recorded actor (an earlier build's row) is restored with
    /// MESSAGE withheld, so core refuses messages to it before acceptance until
    /// its own next hook records the actor (see [`Registry::admit_hook`]).
    fn apply_policy(&self, binding: &mut Binding, policy: &HarnessPolicy) {
        let opencode = binding.address.harness == Harness::OpenCode;
        binding.qualified = Capabilities {
            inject: policy.inject,
            message: policy.message
                && !self.message_disabled.contains(&binding.address.harness)
                && !(opencode && binding.role == Some(ActorRole::Child)),
        };
        binding.capabilities.inject &= binding.qualified.inject;
        binding.capabilities.message &= binding.qualified.message;
        if opencode && binding.role.is_none() {
            binding.capabilities.message = false;
        }
        binding.version = POLICY_LABEL.to_string();
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

    /// Re-observes the lifecycle of a known live interactive Claude route stuck at
    /// `Unknown` from fresh native session metadata. No address is ever created
    /// here (registration comes only from the harness's own hook), and every other
    /// known address (ended or held tombstones, input-waiting or already-observed
    /// routes) is left alone.
    ///
    /// Only a fresh owned descriptor in the route's own store that positively
    /// reports `idle` or `busy` for exactly the recorded session, PID and start
    /// time, executable and store, written at or after the process start, sets the
    /// lifecycle (same epoch, no capability or caller change, journaled with
    /// rollback on failure). The store must still be a canonical owner-only
    /// directory, the process a marked harness running a trusted executable
    /// unchanged since it started. An unreadable, unknown-status, stale,
    /// foreign-store or reused-PID descriptor changes nothing; nothing is inferred
    /// from the earlier saved state.
    pub(crate) fn discover_claude_recipient(
        &mut self,
        address: &NativeAddress,
    ) -> Result<(), String> {
        let key = address.to_canonical_string();
        let Some(known) = self.bindings.get(&key).cloned() else {
            return Ok(());
        };
        if known.retired
            || known.pending
            || known.lifecycle != Lifecycle::Unknown
            || address.host_id != self.config.host_id
            || address.harness != Harness::ClaudeCode
        {
            return Ok(());
        }
        let Some(policy) = self.policy(Harness::ClaudeCode).cloned() else {
            return Ok(());
        };
        let Some(hint) =
            crate::claude::session_hint(&known.store, &address.native_session_id, self.owner_uid)
        else {
            return Ok(());
        };
        let Some(facts) = os::process_facts(hint.pid) else {
            return Ok(());
        };
        if facts.uid != Some(self.owner_uid)
            || (facts.pid, facts.start_time) != known.harness
            || i128::from(hint.written_at) < i128::from(facts.start_time)
            || facts.exe.as_ref() != Some(&known.executable)
            || harness_store(&facts, Harness::ClaudeCode).as_ref() != Some(&known.store)
            || private_store(&known.store, self.owner_uid).is_err()
            || !product_marked(&facts, &policy)
            || executable_current(&known.executable, &facts, self.owner_uid).is_err()
        {
            return Ok(());
        }
        let mut observed = known.clone();
        observed.lifecycle = hint.lifecycle;
        self.bindings.insert(key.clone(), observed);
        if let Err(error) = self.persist_routes() {
            self.bindings.insert(key, known);
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

    /// The only user id this registry accepts (the daemon's own user).
    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// The configured host id.
    pub fn host_id(&self) -> &str {
        &self.config.host_id
    }

    /// Resolves the harness a channel peer belongs to.
    ///
    /// The peer must run as the owner, and `harness` must be enabled by the
    /// harness policy. Its nearest ancestor that is not an allowlisted
    /// intermediate is the harness process: it must run as the owner, carry the
    /// positive product marker ([`product_marked`]: the product name or a
    /// configured marker in its resolved executable path; an inherited
    /// environment variable never counts), have an executable that is a regular file owned by the owner or
    /// root, not writable by group or other and unchanged since that process
    /// started ([`executable_current`]), and a store, derived from its own
    /// environment, that is a canonical directory owned by the owner and not
    /// writable by group or other ([`private_store`]). No store path and no
    /// executable is predeclared.
    ///
    /// `frontend` is true only for a Codex MCP caller attestation: then the
    /// peer's direct parent alone may be the signed Node frontend hop (see
    /// [`signed_node_hop`]) and is skipped before the walk; hooks never get it.
    fn harness_of(
        &mut self,
        peer: PeerIdentity,
        harness: Harness,
        frontend: bool,
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
        let hop = frontend
            && harness == Harness::Codex
            && ancestors
                .first()
                .is_some_and(|parent| signed_node_hop(peer.pid, parent, self.owner_uid));
        let candidate = ancestors[usize::from(hop)..].iter().find(|facts| {
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
        let policy = self.policy(harness).cloned().ok_or_else(|| {
            CorrelationError::NotEvidence("this harness is not enabled by the policy".into())
        })?;
        if !product_marked(facts, &policy) {
            return Err(CorrelationError::NotEvidence(
                "the ancestor is not a marked harness process".into(),
            ));
        }
        let exe = facts
            .exe
            .clone()
            .ok_or_else(|| CorrelationError::NotEvidence("harness executable unreadable".into()))?;
        executable_current(&exe, facts, self.owner_uid).map_err(CorrelationError::NotEvidence)?;
        let store = harness_store(facts, harness)
            .ok_or_else(|| CorrelationError::NotEvidence("harness store unresolvable".into()))?;
        private_store(&store, self.owner_uid).map_err(CorrelationError::NotEvidence)?;
        Ok(HarnessMatch {
            incarnation: (facts.pid, facts.start_time),
            store,
            executable: exe,
            policy,
        })
    }

    /// Hashes every configured relay and backend executable into the digest
    /// cache, blocking the caller for the whole read. It is the startup warm-up
    /// ([`Registry::new`] already runs it, so consumers need not): never call it on
    /// a registry that is shared and serving, since that would hash under the
    /// lock. A serving daemon refreshes the cache with `refresh_stale` instead,
    /// which hashes outside the lock. Calling it again is idempotent: a file whose
    /// identity is already cached is not read again (it only reports the counts,
    /// as the daemon does for its log), and only a file that changed since is
    /// re-hashed, replacing the superseded identities of that path. The work is
    /// one streamed read per distinct configured path, bounded by the file sizes
    /// (about 1.6 s for 246 MB in an optimized build, tens of seconds
    /// unoptimized). Each file is hashed for real, never trusted from its
    /// configured digest, and cached only when its file identity (path, device
    /// and inode, length, nanosecond mtime and ctime) is the same before and
    /// after the read.
    ///
    /// Qualified afterwards: exactly the files whose cached digest equals the
    /// configured one, unchanged since. Not qualified, with a `NotEvidence`
    /// refusal from every route that needs the file: a configured file that was
    /// missing, unreadable or changing at this call, one whose real digest is not
    /// the configured one (a new build is never accepted by hashing it), and any
    /// file installed, replaced or modified later until `refresh_stale` has
    /// hashed its new identity (even a same-size rewrite within the same second);
    /// other cached executables keep attesting. Returns `(cached, skipped)` path
    /// counts.
    pub fn warm_digests(&mut self) -> (usize, usize) {
        self.refresh_blocking();
        let paths = self.configured_paths();
        let cached = paths
            .iter()
            .filter(|path| file_key(path).is_some_and(|key| self.digests.contains_key(&key)))
            .count();
        (cached, paths.len() - cached)
    }

    /// How many configured relay and audience executable entries
    /// cannot attest right now: the file is missing, unreadable, changed since it
    /// was hashed or not hashed, or its real hashed digest differs from the
    /// configured one. One entry counts once, so the number is bounded by the
    /// configuration.
    ///
    /// It only stats files and compares the cached real digests with the
    /// configured ones (never trusting the configured value, never reading
    /// a file), so it is cheap and safe at startup, after
    /// [`Registry::new`], to tell the operator that a route is
    /// unqualified. It does not look at process start times.
    pub fn unqualified_executables(&self) -> usize {
        self.config
            .relays
            .iter()
            .filter(|relay| {
                !file_key(&relay.path)
                    .and_then(|key| self.digests.get(&key))
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(&relay.sha256))
            })
            .count()
    }

    /// Proves the loaded build of a configured relay, audience or other Bridge
    /// executable (never a native recipient's binary): both the modification second and the
    /// status-change (ctime) second of the file are strictly before the
    /// process start (`started` is the process start in Unix seconds, or
    /// `u64::MAX` when no process is involved) and its digest, hashed by
    /// [`Registry::warm_digests`] or [`refresh_stale`] for this exact file
    /// identity (which includes the nanosecond ctime), equals `qualified`.
    ///
    /// What this proves: since before the process was born, the file at the
    /// path has not been written, replaced, renamed into place or chmod-ed,
    /// so the bytes on disk, hashed at any later time under the same identity,
    /// are the bytes the process started from. mtime alone is not enough: an
    /// installer that restores timestamps (`cp -p`, `install -p`, `touch`)
    /// keeps an old mtime, but the kernel sets ctime on every such change and
    /// a program cannot set it back, and the OS keeps reporting the same
    /// executable path for the live process after a replacement (probed on
    /// macOS), so the path alone shows nothing. Times are whole seconds, so a
    /// change in the very second the process was born is ambiguous and
    /// refused; restarting the harness a second or more after the last change
    /// to the file resolves the birth-second ambiguity. A benign chmod or link
    /// change moves the nanosecond ctime and so needs a new digest identity
    /// ([`refresh_stale`], automatic and outside this lock) and a harness
    /// started after it. A process that started before the change is never
    /// proven loaded, whatever the digest. A run that wants to show the stock
    /// binary was not touched should record its inode, mtime and ctime before
    /// and after; nothing here claims the operating system can never write it.
    /// It does not defend against code that already runs as the user with the
    /// ability to move the system clock backwards.
    ///
    /// Never reads the file: a file without a cached digest for its current
    /// identity (missing, or installed, replaced or changed since the last
    /// refresh) is refused as unqualified until [`refresh_stale`] has hashed
    /// it, so this is safe under the registry lock. A different real digest is
    /// refused as "not the configured build" however it got there.
    fn verify_loaded(
        &self,
        exe: &Path,
        started: u64,
        qualified: &str,
    ) -> Result<(), CorrelationError> {
        let key = self.stable_identity(exe, started)?;
        let Some(digest) = self.digests.get(&key) else {
            return Err(CorrelationError::NotEvidence(
                "configured executable has no hashed digest for its current file identity (new, replaced or modified since the last hash); unqualified until it is hashed again"
                    .into(),
            ));
        };
        if !digest.eq_ignore_ascii_case(qualified) {
            return Err(CorrelationError::NotEvidence(
                "executable digest is not the configured build".into(),
            ));
        }
        Ok(())
    }

    /// The current identity of `exe` when it was neither written nor changed
    /// (mtime and ctime) at or after the process start second `started`, the
    /// file-time gate of [`Registry::verify_loaded`].
    ///
    /// # Errors
    ///
    /// The file is unreadable, or its mtime or ctime second is not strictly
    /// before `started` (the loaded build is then unproven).
    fn stable_identity(&self, exe: &Path, started: u64) -> Result<FileKey, CorrelationError> {
        let key = file_key(exe).ok_or_else(|| {
            CorrelationError::NotEvidence("configured executable unreadable".into())
        })?;
        if i128::from(key.mtime.0.max(key.ctime.0)) >= i128::from(started) {
            return Err(CorrelationError::NotEvidence(
                "configured executable written or changed on disk at or after the process start second; loaded build unproven"
                    .into(),
            ));
        }
        Ok(key)
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
    /// OpenCode bindings record their actor (`Binding.role`, from the hook:
    /// root without `agent_id`, child with it). A child (its own address, never
    /// positively idle) is bound without the MESSAGE capability, so core refuses
    /// a message to it before acceptance; its `Stop` never makes it idle; its
    /// own `SessionEnd` retires its binding with Unknown lifecycle. An OpenCode
    /// binding whose recorded actor differs from, or lacks, this hook's actor
    /// (an earlier build's row, restored with MESSAGE withheld) is renewed with
    /// a new epoch, so a root regains MESSAGE and a child keeps it withdrawn.
    /// Caller attestation is unchanged.
    ///
    /// The binding's namespace and capabilities come from the harness-level policy
    /// of the matched harness, its store from the harness process's own
    /// environment (proven canonical and owner-only), and it records the
    /// executable the verified process actually runs. A fresh session in any such
    /// store registers from its genuine hook with no pre-enrollment. After the
    /// lifecycle transition a
    /// Codex Desktop owner's **positive** idle event (the owner's own session
    /// start, `Stop` or idle-prompt notification, never an event that merely
    /// leaves an earlier `Inactive` in place) re-stamps the idle proof: the
    /// retained transcript must be the owned regular file inside the store's
    /// sessions directory whose first line (up to 1 MiB) is the `session_meta`
    /// record of exactly this thread, read with its length, nanosecond times and
    /// last 64 KiB from one stable descriptor; any other lifecycle, a retirement
    /// or an unreadable transcript leaves no proof, and a `SessionEnd` keeps only
    /// the proof stamped before it under the narrow retired-Desktop idle
    /// exception. Every refusal above (another live incarnation, route-journal
    /// failure with rollback, a peer that is not a marked harness) keeps the private endpoint
    /// epoch, lifecycle and permission fences: labels, PIDs and model text never
    /// become evidence.
    pub fn admit_hook(
        &mut self,
        peer: PeerIdentity,
        harness: Harness,
        payload: &HookPayload,
        now_ms: u64,
    ) -> Result<HookAdmission, CorrelationError> {
        let kind = HookKind::parse(&payload.hook_event_name)
            .ok_or_else(|| CorrelationError::NotEvidence("unsupported hook event".into()))?;
        if harness != Harness::OpenCode
            && matches!(kind, HookKind::OpenCodeActivity | HookKind::OpenCodeUnknown)
        {
            return Err(CorrelationError::NotEvidence(
                "hook event belongs to another harness".into(),
            ));
        }
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
        let matched = self.harness_of(peer, harness, false)?;
        // Claude children share the root session's address; Codex children
        // are their own threads with their own addresses.
        let (role, native_id, address_session) = match (&agent, harness) {
            (None, _) => (ActorRole::Root, session.clone(), session.clone()),
            (Some(agent), Harness::ClaudeCode) => {
                (ActorRole::Child, agent.clone(), session.clone())
            }
            (Some(agent), Harness::Codex | Harness::OpenCode) => {
                (ActorRole::Child, agent.clone(), agent.clone())
            }
        };
        let address = NativeAddress::new(
            self.config.host_id.clone(),
            harness,
            matched.policy.namespace.clone(),
            address_session,
        )
        .map_err(|error| CorrelationError::NotEvidence(error.to_string()))?;
        let key = address.to_canonical_string();
        // An OpenCode child never becomes positively idle (it does not own a
        // wakeable session), so no MESSAGE to it could ever be delivered: its
        // binding never advertises the capability and core refuses such a
        // publication before acceptance instead of holding it forever.
        let opencode_child = harness == Harness::OpenCode && role == ActorRole::Child;
        let capabilities = Capabilities {
            inject: matched.policy.inject,
            message: matched.policy.message
                && !self.message_disabled.contains(&harness)
                && !opencode_child,
        };
        let transcript = payload
            .transcript_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.starts_with(&matched.store));

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
            // An OpenCode binding without this actor recorded (an earlier
            // build's row, restored with MESSAGE withheld) is renewed from the
            // address's own hook, so core records the actor's true capability.
            Some(binding) => (
                starts_own_session(kind, role, harness, payload)
                    || binding.retired
                    || binding.pending
                    || (harness == Harness::OpenCode && binding.role != Some(role)),
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
                    version: POLICY_LABEL.to_string(),
                    lifecycle: Lifecycle::Unknown,
                    transcript: None,
                    store: matched.store.clone(),
                    executable: matched.executable.clone(),
                    retired: false,
                    desktop_idle_message: false,
                    desktop_idle_transcript: None,
                    wake: None,
                    pending: false,
                    role: (harness == Harness::OpenCode).then_some(role),
                },
            );
        }
        let owner_uid = self.owner_uid;
        let binding = self.bindings.get_mut(&key).expect("binding inserted above");
        let prior_wake = binding.wake.take();
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
        } else if kind == HookKind::SessionEnd && opencode_child {
            // The child's own address ended (its native session was deleted):
            // retire it truthfully; there is no idle exception for a child.
            binding.retired = true;
        }
        binding.lifecycle = next_lifecycle(binding.lifecycle, kind, role, harness, payload);
        // ponytail: one bounded transcript read per idle hook under the lock (head line up to 1 MiB, last 64 KiB); stamp from a worker if hook rates ever matter.
        // The proof is re-stamped only by a positive owner idle event, never by an
        // event that merely leaves an earlier `Inactive` in place (a subagent stop,
        // a Claude child's stop, an unrelated notification): those keep the proof
        // stamped at the real idle, and any non-idle lifecycle clears it.
        binding.wake = if harness != Harness::Codex
            || binding.retired
            || binding.lifecycle != Lifecycle::Inactive
        {
            None
        } else if is_positive_idle_event(kind, role, harness, payload) {
            os::process_env(binding.harness.0, "CODEX_APP_TOOLS_PIPE_PATH")
                .and_then(|_| gateway::read_stamp(binding, owner_uid))
        } else {
            prior_wake.clone()
        };
        if kind == HookKind::SessionEnd && role == ActorRole::Root && binding.desktop_idle_message {
            // The narrow retired-Desktop idle exception keeps the proof stamped at
            // the positive idle before the end; every other end clears it.
            binding.wake = prior_wake;
        }
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
        // the inject capability of its binding, may drain; a Claude child sharing the root
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
    /// (the harness-launched MCP server). It must belong to a marked harness
    /// that the harness policy enables, on the metadata's host; the per-call id must join exactly
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
        let matched = self.harness_of(peer, harness, true)?;
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
        if let PresentedMeta::OpenCode { session_id, .. } = meta
            && *session_id != record.native_id
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
                    Harness::OpenCode => CallerChannel::OpenCodeCall,
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
    /// `SessionStart` or incarnation takes capabilities from the harness
    /// policy again) or the same incarnation later advertises its inbox.
    ///
    /// Returns `Ok(None)` when nothing would change: the capability already
    /// has that value, or `message` is `true` but the harness policy does not
    /// grant it to this binding (a late inbox never promotes beyond `qualified`).
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
    /// withdrawn at runtime although the harness policy grants it to them.
    ///
    /// A carrier re-checks these periodically, independent of pending
    /// work, so a late inbox restores message even when no event waits
    /// (publications are refused while it is withdrawn, so no work would
    /// otherwise trigger the check). Retired bindings and bindings whose
    /// policy does not grant message are never listed. The list is bounded by the
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

    /// Copies current MESSAGE qualification and private binding of a Codex or
    /// Claude recipient under the lock, without OS/file/native I/O. The owned
    /// candidate MUST be validated outside the lock on every attest/send, and
    /// app frontends or owner routes separately checked. A harness without a
    /// policy, disabled message capability and legacy tombstones refuse.
    pub(crate) fn message_candidate(
        &self,
        address: &NativeAddress,
    ) -> Result<MessageCandidate, String> {
        let binding = self
            .bindings
            .get(&address.to_canonical_string())
            .ok_or("no message binding")?;
        if self.message_disabled.contains(&address.harness)
            || binding.pending
            || (binding.retired && !binding.desktop_idle_message)
        {
            return Err("message binding unavailable".into());
        }
        let policy = self
            .policy(address.harness)
            .ok_or("message policy changed")?
            .clone();
        Ok(MessageCandidate {
            binding: binding.clone(),
            policy,
            owner_uid: self.owner_uid,
        })
    }

    /// Refuses a MESSAGE snapshot changed during unlocked OS/frontend validation.
    /// Compares the entire binding including same-epoch lifecycle/capabilities,
    /// retirement and private transcript evidence, and current host disablement.
    /// Pure in-memory check; callers run it under the registry lock last, on both
    /// attest and send. It grants no caller or ordinary recipient authority.
    pub(crate) fn message_current(&self, candidate: &MessageCandidate) -> Result<(), String> {
        if self
            .message_disabled
            .contains(&candidate.binding.address.harness)
            || self
                .bindings
                .get(&candidate.binding.address.to_canonical_string())
                != Some(&candidate.binding)
        {
            return Err("message binding changed during validation".into());
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
                gateway: false,
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

/// Whether one hook event is a *positive* owner idle observation: exactly the
/// events [`next_lifecycle`] turns into `Inactive` by themselves (the owner's own
/// session start, the owner's `Stop` and its idle-prompt notification). An event
/// that merely leaves an earlier `Inactive` in place is not one.
fn is_positive_idle_event(
    kind: HookKind,
    role: ActorRole,
    harness: Harness,
    payload: &HookPayload,
) -> bool {
    match kind {
        HookKind::SessionStart => {
            harness != Harness::OpenCode && starts_own_session(kind, role, harness, payload)
        }
        HookKind::Stop => owns_address(role, harness),
        HookKind::Notification => {
            owns_address(role, harness)
                && payload.notification_type.as_deref() == Some("idle_prompt")
        }
        _ => false,
    }
}

/// The next owner-session lifecycle after one hook event.
///
/// Prompt and tool events are active (a child's tool event means the root
/// awaits its subagent); `AskUserQuestion`, permission requests and
/// permission notifications await input; the owner's own `Stop`, idle-prompt
/// notification and non-`compact` `SessionStart` are idle; the owner's
/// `SessionEnd`, and an OpenCode child's own `SessionEnd`, is unknown. Every other event (`SubagentStop`, a Claude
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
        HookKind::OpenCodeActivity => Lifecycle::Active,
        HookKind::OpenCodeUnknown => Lifecycle::Unknown,
        HookKind::SessionStart if harness == Harness::OpenCode => Lifecycle::Unknown,
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
        // An OpenCode child's end is its own address ending (it is retired).
        HookKind::SessionEnd if owner || harness == Harness::OpenCode => Lifecycle::Unknown,
        HookKind::SessionEnd => current,
    }
}

/// Resolves the harness's store from its OS environment, never hook arguments.
/// Codex/Claude retain their existing home defaults. Supported owned OpenCode
/// launches explicitly name OPENCODE_DB; its absolute parent is the store, with
/// no guessed fallback for arbitrary unowned installations.
fn harness_store(facts: &ProcessFacts, harness: Harness) -> Option<PathBuf> {
    let (variable, default) = match harness {
        Harness::Codex => ("CODEX_HOME", ".codex"),
        Harness::ClaudeCode => ("CLAUDE_CONFIG_DIR", ".claude"),
        Harness::OpenCode => {
            let database = PathBuf::from(os::process_env(facts.pid, "OPENCODE_DB")?);
            return if database.is_absolute() {
                database.parent().map(Path::to_path_buf)
            } else {
                None
            };
        }
    };
    if let Some(value) = os::process_env(facts.pid, variable) {
        return Some(PathBuf::from(value));
    }
    os::process_env(facts.pid, "HOME").map(|home| PathBuf::from(home).join(default))
}

/// Whether the native owner process `owner` runs from a trusted executable:
/// the resolved path exists and [`executable_current`] holds for it (a regular
/// file owned by `owner_uid` or root, not writable by group or other, unchanged
/// since the owner process started). No path or digest is predeclared and
/// nothing else is granted; used only by the native owner route.
///
/// # Errors
///
/// The reason the owner executable is refused (a static text, never the path).
pub(crate) fn owner_executable_current(owner: &ProcessFacts, owner_uid: u32) -> Result<(), String> {
    let exe = owner
        .exe
        .as_ref()
        .ok_or("native owner executable is unreadable")?;
    executable_current(exe, owner, owner_uid)
}

/// Version label recorded on every binding made under the harness-level policy.
const POLICY_LABEL: &str = "harness-policy";

/// Whether `facts` is positively a process of the product `policy` serves: its
/// resolved executable path contains, case-insensitively, one of the policy's
/// `executable_markers`, or the product name (`codex` or `claude`) when none is
/// configured. An environment variable never counts: every descendant of a
/// harness inherits the harness's store variables. An unrelated ancestor such as
/// a terminal, a build tool or a generic wrapper that is not an allowlisted
/// intermediate matches none and is never a harness. This is a best-effort
/// marker, not authentication: same-user code can fake it (the documented
/// excluded hostile same-user case).
fn product_marked(facts: &ProcessFacts, policy: &HarnessPolicy) -> bool {
    let default = match policy.harness {
        Harness::Codex => "codex",
        Harness::ClaudeCode => "claude",
        Harness::OpenCode => "opencode",
    };
    let Some(exe) = facts.exe.as_ref() else {
        return false;
    };
    let path = exe.to_string_lossy().to_lowercase();
    if policy.executable_markers.is_empty() {
        path.contains(default)
    } else {
        policy
            .executable_markers
            .iter()
            .any(|marker| !marker.is_empty() && path.contains(&marker.to_lowercase()))
    }
}

/// Proves `store` is a runtime store Bridge may bind: an absolute path that is
/// already canonical (no symlink component, no `.`/`..`), a directory (read with
/// `lstat`, never through a final link) owned by `owner_uid` that no group or
/// other user can write. Re-read on every use, never cached.
///
/// # Errors
///
/// The reason the store is refused (a static text, never the path).
fn private_store(store: &Path, owner_uid: u32) -> Result<(), String> {
    if !store.is_absolute() || store.canonicalize().ok().as_deref() != Some(store) {
        return Err("harness store is not an absolute canonical path".into());
    }
    let meta = std::fs::symlink_metadata(store).map_err(|_| "harness store is unreadable")?;
    if !meta.is_dir() || meta.uid() != owner_uid || meta.mode() & 0o022 != 0 {
        return Err(
            "harness store is not an owner-owned directory closed to group and other writers"
                .into(),
        );
    }
    Ok(())
}

/// Proves the executable `exe` of the process `facts` may be run by Bridge: a
/// regular file owned by `owner_uid` or root that no group or other user can
/// write, whose modification and status-change seconds are strictly before the
/// process start second (so it is unchanged since the process began). No digest
/// or path is allowlisted.
///
/// # Errors
///
/// The reason the executable is refused (a static text, never the path).
fn executable_current(exe: &Path, facts: &ProcessFacts, owner_uid: u32) -> Result<(), String> {
    let meta = std::fs::metadata(exe).map_err(|_| "executable is unreadable")?;
    if !meta.is_file() || !(meta.uid() == owner_uid || meta.uid() == 0) || meta.mode() & 0o022 != 0
    {
        return Err("executable is not a regular, trusted-owner, non-writable file".into());
    }
    if i128::from(meta.mtime().max(meta.ctime())) >= i128::from(facts.start_time) {
        return Err("executable was written or changed at or after the process start".into());
    }
    Ok(())
}

/// Whether `parent`, the kernel parent of the MCP peer `peer_pid`, is the
/// signed Node frontend hop of a Codex application MCP server: the launched
/// Bridge MCP process replaced itself (same PID, `exec`) with the
/// host-supplied Node runtime, which runs the Rust MCP child (the peer).
///
/// All of these must hold, so neither an environment value nor a PID alone
/// is authority: the hop runs as `owner_uid`; its kernel-resolved executable
/// is current ([`executable_current`]) and is exactly the runtime that the
/// host named in the hop's own preserved exec-time environment
/// (`CODEX_MCP_NODE_PATH`, both paths canonical); that environment also holds
/// the application pipe capability (`CODEX_APP_TOOLS_PIPE_PATH`); and the
/// peer's environment carries `BRIDGE_DESKTOP_PARENT_PID` naming the hop's
/// kernel PID (the frontend stamps it when it spawns its child, after removing
/// both capability variables from the child). Unreadable facts refuse. The
/// harness above the hop is still proven by every ordinary check.
fn signed_node_hop(peer_pid: u32, parent: &ProcessFacts, owner_uid: u32) -> bool {
    let Some(exe) = parent.exe.as_deref() else {
        return false;
    };
    let declared = os::process_env(parent.pid, "CODEX_MCP_NODE_PATH")
        .and_then(|path| Path::new(&path).canonicalize().ok());
    parent.uid == Some(owner_uid)
        && executable_current(exe, parent, owner_uid).is_ok()
        && declared.is_some()
        && declared == exe.canonicalize().ok()
        && os::process_env(parent.pid, "CODEX_APP_TOOLS_PIPE_PATH").is_some()
        && os::process_env(peer_pid, "BRIDGE_DESKTOP_PARENT_PID")
            .is_some_and(|pid| pid.to_str() == Some(parent.pid.to_string().as_str()))
}

/// Starts a background evidence refresh of a serving registry when a configured
/// executable has a new file identity; never blocks and never hashes on the
/// caller's thread (see `refresh_stale`). The daemon calls it periodically
/// from its main loop, so an application update is covered within about a
/// second plus one hash pass, with no request and no restart involved.
pub fn refresh_executables(registry: &Arc<Mutex<Registry>>) {
    refresh_stale(registry);
}

/// Ends the background evidence refresh at daemon shutdown: no later call starts a
/// pass, a running pass abandons its hash and commits nothing more, and this
/// returns only after the pass thread has been joined.
/// Call it after the service has stopped and before the process exits.
pub fn stop_executable_refresh(registry: &Arc<Mutex<Registry>>) {
    stop_refresh(registry);
}

/// Lowercase hex SHA-256 of a file's bytes, streamed.
pub fn file_sha256(path: &Path) -> std::io::Result<String> {
    sha256_reader(&mut std::fs::File::open(path)?)
}

/// Lowercase hex SHA-256 of everything `reader` yields, streamed in 64 KiB chunks.
fn sha256_reader(reader: &mut impl Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = reader.read(&mut buffer)?;
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
            wake: None,
            pending: false,
            role: None,
        };
        let candidate = MessageCandidate {
            binding: binding.clone(),
            owner_uid: 0,
            policy: HarnessPolicy {
                harness: Harness::Codex,
                namespace: "ns".into(),
                inject: true,
                message: true,
                executable_markers: Vec::new(),
            },
        };
        let key = address.to_canonical_string();
        registry.bindings.insert(key.clone(), binding.clone());
        assert!(registry.message_current(&candidate).is_ok());
        {
            let shared = std::cell::RefCell::new(&mut registry);
            let selected = PathBuf::from("/owned/frontend.sock");
            assert_eq!(
                crate::codex::checked_frontend(
                    || Ok(Some(selected.clone())),
                    || shared.borrow().message_current(&candidate),
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
                    || shared.borrow().message_current(&candidate),
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
            assert!(registry.message_current(&candidate).is_err());
        }
        registry.bindings.insert(key, binding.clone());
        registry.message_disabled.push(Harness::Codex);
        assert!(registry.message_current(&candidate).is_err());
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

    /// A registry whose Claude harness policy serves any store and whose relay
    /// entries are `executables` (path, configured digest): the only executables
    /// whose digests the cache covers.
    fn registry_with(executables: &[(&Path, &str)]) -> Registry {
        let config = RegistryConfig {
            host_id: "h".into(),
            harnesses: vec![HarnessPolicy {
                harness: Harness::ClaudeCode,
                namespace: "ns".into(),
                inject: true,
                message: true,
                executable_markers: Vec::new(),
            }],
            profiles: Vec::new(),
            intermediates: Vec::new(),
            max_call_age_ms: 600_000,
            relays: executables
                .iter()
                .map(|(path, sha256)| RelayExecutable {
                    path: path.to_path_buf(),
                    sha256: (*sha256).into(),
                })
                .collect(),
            audiences: Vec::new(),
            legacy_owner_relays: 0,
        };
        Registry::new(config, 0).unwrap()
    }

    /// A fresh temporary directory for one test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("m2{tag}{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
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
        let registry = registry_with(&[(&exe, &digest)]);
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
        let before = registry_with(&[(&exe, &digest_old)]);
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
        let after = registry_with(&[(&exe, &digest_new)]);
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
        let registry = registry_with(&[(&exe, &digest)]);
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
    /// Runs one background refresh pass to completion (the production call only
    /// starts it and returns).
    fn refresh(registry: &Arc<Mutex<Registry>>) {
        if refresh_stale(registry) {
            wait_refresh(registry);
        }
    }

    /// Replaces `exe` by a renamed file holding `bytes` with the original mtime
    /// restored (an installer-style update), after the status-change second moved on.
    fn update_in_place(exe: &Path, bytes: Vec<u8>) {
        wait_until_second(u64::try_from(status_change_second(exe)).unwrap() + 1);
        let staged = exe.with_extension("staged");
        std::fs::write(&staged, bytes).unwrap();
        backdate(&staged);
        std::fs::rename(&staged, exe).unwrap();
    }

    /// An application update that leaves the approved bytes identical (a new
    /// inode and ctime) is refused until the cache is refreshed and then attests
    /// again without a daemon restart; the daemon-held registry is only locked
    /// to stage and commit. The process-birth gate still refuses a process that
    /// started before the update, whatever the digest, and repeated updates keep
    /// exactly one cached identity per path.
    #[test]
    fn refresh_requalifies_identical_bytes_but_never_an_old_process() {
        let dir = scratch("rfs");
        let exe = dir.join("exe");
        std::fs::write(&exe, vec![3u8; 4096]).unwrap();
        backdate(&exe);
        let digest = file_sha256(&exe).unwrap();
        let registry = Arc::new(Mutex::new(registry_with(&[(&exe, &digest)])));
        let first = u64::try_from(status_change_second(&exe)).unwrap();
        for round in 0..3 {
            update_in_place(&exe, vec![3u8; 4096]);
            let updated = u64::try_from(status_change_second(&exe)).unwrap();
            assert!(first <= updated);
            assert!(
                registry
                    .lock()
                    .unwrap()
                    .verify_loaded(&exe, u64::MAX, &digest)
                    .is_err(),
                "round {round}: a new identity has no digest until refreshed"
            );
            refresh(&registry);
            let registry = registry.lock().unwrap();
            registry
                .verify_loaded(&exe, updated + 1, &digest)
                .expect("identical approved bytes qualify a process born after the update");
            assert!(
                registry.verify_loaded(&exe, updated, &digest).is_err(),
                "a process born in the update second is unproven"
            );
            assert!(
                registry.verify_loaded(&exe, first, &digest).is_err(),
                "a process that predates the update is never proven loaded"
            );
            assert_eq!(
                registry.digests.len(),
                1,
                "superseded identities are pruned"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A refresh never accepts a new build: other bytes at the approved path are
    /// hashed for real and refused as "not the configured build", while an
    /// unrelated approved path keeps attesting.
    #[test]
    fn refresh_never_accepts_a_changed_digest() {
        let dir = scratch("rfc");
        let exe = dir.join("exe");
        let other = dir.join("other");
        std::fs::write(&exe, vec![3u8; 4096]).unwrap();
        std::fs::write(&other, vec![4u8; 4096]).unwrap();
        backdate(&exe);
        let digest = file_sha256(&exe).unwrap();
        let other_digest = file_sha256(&other).unwrap();
        let registry = Arc::new(Mutex::new(registry_with(&[
            (&exe, &digest),
            (&other, &other_digest),
        ])));
        update_in_place(&exe, vec![5u8; 4096]);
        refresh(&registry);
        let registry = registry.lock().unwrap();
        let refused = registry.verify_loaded(&exe, u64::MAX, &digest).unwrap_err();
        assert!(
            refused.detail().contains("not the configured build"),
            "{}",
            refused.detail()
        );
        registry
            .verify_loaded(&other, u64::MAX, &other_digest)
            .expect("an unaffected approved path keeps attesting");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The whole-file read happens with the registry lock released, and a file
    /// whose metadata changes during the read is not cached. A FIFO at the
    /// configured path blocks the hash until a writer connects, which holds the
    /// refresh mid-read deterministically: the registry must stay lockable, and
    /// a `chmod` (ctime) during the read makes the digest unstable, so nothing
    /// is committed and the path stays unqualified.
    #[test]
    fn refresh_hashes_outside_the_registry_lock_and_drops_an_unstable_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("rfl");
        let exe = dir.join("exe");
        std::fs::write(&exe, vec![3u8; 4096]).unwrap();
        let digest = file_sha256(&exe).unwrap();
        let registry = Arc::new(Mutex::new(registry_with(&[(&exe, &digest)])));
        std::fs::remove_file(&exe).unwrap();
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&exe)
                .status()
                .unwrap()
                .success()
        );
        assert!(refresh_stale(&registry), "a stale identity starts a pass");
        assert!(
            !refresh_stale(&registry),
            "a pass already in flight is shared, not duplicated"
        );
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert!(
            registry.lock().unwrap().refreshing.load(Ordering::SeqCst),
            "the hash is blocked on the FIFO"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let fifo_key = file_key(&exe).unwrap();
        let lockable = loop {
            if let Ok(guard) = registry.try_lock() {
                break guard.digests.contains_key(&fifo_key);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "refresh holds the registry lock while hashing"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert!(!lockable, "the FIFO identity has no digest yet");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(std::fs::OpenOptions::new().write(true).open(&exe).unwrap());
        wait_refresh(&registry);
        assert!(
            registry
                .lock()
                .unwrap()
                .verify_loaded(&exe, u64::MAX, &digest)
                .is_err(),
            "an identity that changed during the read is not cached"
        );
        assert!(
            registry
                .lock()
                .unwrap()
                .digests
                .keys()
                .all(|key| key.inode != fifo_key.inode),
            "nothing was cached for the unstable identity"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// A result computed for a file identity that changed before the commit is
    /// dropped under the final lock: nothing is pruned or cached for it, the new
    /// identity stays unqualified and is staged again.
    #[test]
    fn commit_skips_a_result_for_a_file_changed_after_the_check() {
        let dir = scratch("cmt");
        let exe = dir.join("exe");
        std::fs::write(&exe, vec![1u8; 4096]).unwrap();
        backdate(&exe);
        let digest = file_sha256(&exe).unwrap();
        let mut registry = registry_with(&[(&exe, &digest)]);
        update_in_place(&exe, vec![1u8; 4096]);
        let checked: Vec<_> = registry
            .stale_files()
            .into_iter()
            .filter_map(executables::check_file)
            .collect();
        assert_eq!(checked.len(), 1);
        update_in_place(&exe, vec![1u8; 4096]);
        let before = registry.digests.clone();
        for item in checked {
            registry.commit_checked(item);
        }
        assert_eq!(registry.digests, before, "nothing pruned or inserted");
        assert!(registry.verify_loaded(&exe, u64::MAX, &digest).is_err());
        assert_eq!(
            registry.stale_files().len(),
            1,
            "staged again for its new identity"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Stopping the refresh ends it for good: no pass starts, and a running pass
    /// is abandoned and joined (a blocked hash is interrupted only by its reader
    /// closing here, so this checks the flag path with an idle registry).
    #[test]
    fn stopped_refresh_starts_nothing_and_commits_nothing() {
        let dir = scratch("stp");
        let exe = dir.join("exe");
        std::fs::write(&exe, vec![1u8; 4096]).unwrap();
        backdate(&exe);
        let digest = file_sha256(&exe).unwrap();
        let registry = Arc::new(Mutex::new(registry_with(&[(&exe, &digest)])));
        update_in_place(&exe, vec![1u8; 4096]);
        stop_refresh(&registry);
        assert!(!refresh_stale(&registry));
        assert!(
            registry
                .lock()
                .unwrap()
                .verify_loaded(&exe, u64::MAX, &digest)
                .is_err()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The child side of [`live_child`]: parks for a minute only when the process
    /// was started by it (the marker variable is set), and returns at once in every
    /// ordinary test run.
    #[test]
    fn park_for_live_child() {
        if std::env::var_os("BRIDGE_TEST_PARK").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    /// An owned fixture child: killed and reaped when dropped, so an assertion
    /// panic cannot leak a parked process.
    pub(super) struct LiveChild(std::process::Child);

    impl LiveChild {
        /// Takes ownership of an already started child.
        pub(super) fn own(child: std::process::Child) -> Self {
            LiveChild(child)
        }
    }

    impl std::ops::Deref for LiveChild {
        type Target = std::process::Child;

        /// The owned child, for its PID and status.
        fn deref(&self) -> &std::process::Child {
            &self.0
        }
    }

    impl std::ops::DerefMut for LiveChild {
        /// The owned child, mutably (status polling).
        fn deref_mut(&mut self) -> &mut std::process::Child {
            &mut self.0
        }
    }

    impl Drop for LiveChild {
        /// Kills and reaps the child, whatever the test's outcome.
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A copy of this test binary at `path` (the "harness" executable) and a live
    /// child started from it that parks, born in a later second than the copy so
    /// the loaded-build file-time gate can prove it. Only the child gets the
    /// marker variable `BRIDGE_TEST_PARK` and `store` as its store through the
    /// environment variable `variable`; it runs exactly the parking test. The
    /// fixture asserts the child is still alive after startup and that the OS
    /// reports exactly this executable path and store for it. (A copy of
    /// `/bin/sleep` did not stay alive in a manual probe, so it cannot serve.)
    pub(super) fn live_child(path: &Path, variable: &str, store: &Path) -> LiveChild {
        std::fs::copy(std::env::current_exe().unwrap(), path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let mut child = LiveChild(
            std::process::Command::new(path)
                .args([
                    "--exact",
                    "registry::tests::park_for_live_child",
                    "--nocapture",
                ])
                .env(variable, store)
                .env("BRIDGE_TEST_PARK", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            child.try_wait().unwrap().is_none(),
            "the fixture harness must stay alive"
        );
        let facts = os::process_facts(child.id()).expect("fixture process facts");
        assert_eq!(facts.exe.as_deref(), Some(path), "fixture executable");
        assert_eq!(
            os::process_env(child.id(), variable).as_deref(),
            Some(store.as_os_str()),
            "fixture store"
        );
        child
    }
    /// A Claude registry whose harness policy serves any store (inject and
    /// message supported) and whose configuration names no store or executable.
    fn claude_registry() -> Registry {
        Registry::new(
            RegistryConfig {
                host_id: "h".into(),
                harnesses: vec![HarnessPolicy {
                    harness: Harness::ClaudeCode,
                    namespace: "ns".into(),
                    inject: true,
                    message: true,
                    executable_markers: vec!["harness".into()],
                }],
                profiles: Vec::new(),
                intermediates: Vec::new(),
                max_call_age_ms: 600_000,
                relays: Vec::new(),
                audiences: Vec::new(),
                legacy_owner_relays: 0,
            },
            os::process_facts(std::process::id()).unwrap().uid.unwrap(),
        )
        .unwrap()
    }

    /// A live Claude binding of `child` under `store`/`exe`, lifecycle `Unknown`.
    fn unknown_binding(
        address: &NativeAddress,
        child: &std::process::Child,
        store: &Path,
        exe: &Path,
    ) -> Binding {
        let facts = os::process_facts(child.id()).unwrap();
        Binding {
            address: address.clone(),
            harness: (facts.pid, facts.start_time),
            epoch: 5,
            capabilities: Capabilities {
                inject: true,
                message: true,
            },
            qualified: Capabilities {
                inject: true,
                message: true,
            },
            version: "vendor".into(),
            lifecycle: Lifecycle::Unknown,
            transcript: None,
            store: store.to_path_buf(),
            executable: exe.to_path_buf(),
            retired: false,
            desktop_idle_message: false,
            desktop_idle_transcript: None,
            wake: None,
            pending: false,
            role: None,
        }
    }

    /// Observation reads preserve the whole registry and journal, and a final
    /// snapshot fence rejects epoch, lifecycle, retirement, store or policy races.
    /// Live process checks reject a mismatching expected tuple and a dead process.
    #[test]
    fn observation_snapshot_is_read_only_and_fenced() {
        use bridge_protocol::{Host, ResolveRecipientParams};
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("obs");
        let store = dir.join("store");
        std::fs::create_dir(&store).unwrap();
        let exe = dir.join("harness");
        let child = live_child(&exe, "CLAUDE_CONFIG_DIR", &store);
        let mut registry = claude_registry();
        let address = registry
            .observation_address(Host::ClaudeCode, "session")
            .unwrap();
        assert_eq!(address.to_canonical_string(), "h/claude-code/ns/session");
        assert!(
            registry
                .observation_address(Host::Codex, "session")
                .is_none()
        );
        let key = address.to_canonical_string();
        let binding = unknown_binding(&address, &child, &store, &exe);
        registry.bindings.insert(key.clone(), binding.clone());
        let journal = dir.join("untouched.json");
        registry.journal = Some(journal.clone());
        let expected = ResolveRecipientParams {
            host: Host::ClaudeCode,
            native_session_id: "session".into(),
            expected_store: store.to_str().unwrap().into(),
            expected_harness_pid: binding.harness.0,
            expected_harness_start_time_secs: binding.harness.1,
        };
        let candidate = registry.observation_candidate(&address).unwrap();
        assert!(candidate.live(Some(&expected)));
        assert!(registry.observation_current(&candidate));
        assert!(candidate.live(None));
        assert_eq!(registry.bindings[&key], binding);
        assert!(
            registry.calls.is_empty()
                && registry.sealed.is_empty()
                && registry.claims.is_empty()
                && registry.assertions.is_empty()
        );
        assert!(!journal.exists(), "read must not persist a journal");
        for case in 0..6 {
            let changed = registry.bindings.get_mut(&key).unwrap();
            match case {
                0 => changed.epoch += 1,
                1 => changed.lifecycle = Lifecycle::AwaitingInput,
                2 => changed.retired = true,
                3 => changed.store = dir.clone(),
                4 => changed.capabilities.message = false,
                _ => changed.pending = true,
            }
            assert!(
                !registry.observation_current(&candidate),
                "changed snapshot {case}"
            );
            if case == 2 || case == 5 {
                assert!(registry.observation_candidate(&address).is_none());
            }
            registry.bindings.insert(key.clone(), binding.clone());
        }
        registry.policies[0].message = false;
        assert!(!registry.observation_current(&candidate));
        registry.policies[0].message = true;
        registry.message_disabled.push(Harness::ClaudeCode);
        assert!(!registry.observation_current(&candidate));
        registry.message_disabled.clear();
        let mut wrong = expected.clone();
        wrong.expected_harness_start_time_secs += 1;
        assert!(!candidate.live(Some(&wrong)));
        wrong = expected.clone();
        wrong.expected_store.push_str("-other");
        assert!(!candidate.live(Some(&wrong)));
        // A private store changing permissions is not a valid current binding.
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!candidate.live(Some(&expected)));
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(candidate.live(Some(&expected)));
        drop(child);
        assert!(!candidate.live(Some(&expected)));
        assert!(!journal.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Writes a Claude session descriptor `<store>/sessions/<pid>.json` for
    /// `session` claiming `pid` with `status`, modified `age_secs` before now.
    fn descriptor(store: &Path, session: &str, pid: u32, status: &str, age_secs: u64) {
        std::fs::create_dir_all(store.join("sessions")).unwrap();
        let path = store.join("sessions").join(format!("{pid}.json"));
        std::fs::write(
            &path,
            format!(
                "{{\"sessionId\":\"{session}\",\"kind\":\"interactive\",\"pid\":{pid},\"status\":\"{status}\"}}"
            ),
        )
        .unwrap();
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    /// A known live Claude route stuck at `Unknown` (a promoted pending route) is
    /// re-observed from a fresh owned native descriptor, and only from one: idle
    /// and busy statuses set the lifecycle for exactly the recorded session, PID
    /// and start, executable and store with no capability change; an unknown
    /// status, a descriptor claiming another PID, one older than the process, one
    /// in another store, a reused PID, a retired tombstone, a pending route and an
    /// already observed lifecycle all change nothing. The address and its history
    /// survive throughout.
    #[test]
    fn unknown_claude_route_is_reobserved_only_from_an_exact_fresh_descriptor() {
        let dir = scratch("rob");
        let store = dir.join("store");
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&store).unwrap();
        let exe = dir.join("harness");
        let child = live_child(&exe, "CLAUDE_CONFIG_DIR", &store);
        let mut registry = claude_registry();
        let address = NativeAddress::new("h", Harness::ClaudeCode, "ns", "sess").unwrap();
        let key = address.to_canonical_string();
        let pid = child.id();
        let lifecycle = |registry: &Registry| registry.bindings[&key].lifecycle;
        let reset = |registry: &mut Registry, edit: &dyn Fn(&mut Binding)| {
            let mut binding = unknown_binding(&address, &child, &store, &exe);
            edit(&mut binding);
            registry.bindings.insert(key.clone(), binding);
        };
        let observe = |registry: &mut Registry| {
            registry.discover_claude_recipient(&address).unwrap();
        };

        descriptor(&store, "sess", pid, "idle", 0);
        reset(&mut registry, &|_| {});
        observe(&mut registry);
        assert_eq!(lifecycle(&registry), Lifecycle::Inactive, "fresh idle");
        assert_eq!(registry.bindings[&key].epoch, 5, "same epoch");
        let (attestation, _) = registry.attest_recipient(&address).unwrap();
        assert_eq!(attestation.lifecycle(), Lifecycle::Inactive);
        descriptor(&store, "sess", pid, "busy", 0);
        reset(&mut registry, &|_| {});
        observe(&mut registry);
        assert_eq!(lifecycle(&registry), Lifecycle::Active, "fresh busy");

        for (status, claimed, age, why) in [
            ("starting", pid, 0, "unknown status"),
            (
                "idle",
                std::process::id(),
                0,
                "descriptor claims another PID",
            ),
            ("idle", pid, 3_600, "descriptor older than the process"),
        ] {
            let _ = std::fs::remove_file(store.join("sessions").join(format!("{pid}.json")));
            descriptor(&store, "sess", claimed, status, age);
            reset(&mut registry, &|_| {});
            observe(&mut registry);
            assert_eq!(lifecycle(&registry), Lifecycle::Unknown, "{why}");
            let _ = std::fs::remove_file(store.join("sessions").join(format!("{claimed}.json")));
        }
        descriptor(&store, "other-session", pid, "idle", 0);
        reset(&mut registry, &|_| {});
        observe(&mut registry);
        assert_eq!(lifecycle(&registry), Lifecycle::Unknown, "another session");
        let _ = std::fs::remove_file(store.join("sessions").join(format!("{pid}.json")));

        descriptor(&store, "sess", pid, "idle", 0);
        reset(&mut registry, &|b| b.retired = true);
        observe(&mut registry);
        assert_eq!(lifecycle(&registry), Lifecycle::Unknown, "tombstone");
        reset(&mut registry, &|b| b.pending = true);
        observe(&mut registry);
        assert_eq!(lifecycle(&registry), Lifecycle::Unknown, "pending");
        reset(&mut registry, &|b| b.harness.1 += 7);
        observe(&mut registry);
        assert_eq!(lifecycle(&registry), Lifecycle::Unknown, "reused PID");
        reset(&mut registry, &|b| b.lifecycle = Lifecycle::AwaitingInput);
        observe(&mut registry);
        assert_eq!(
            lifecycle(&registry),
            Lifecycle::AwaitingInput,
            "input wait is never overwritten"
        );
        std::fs::remove_file(store.join("sessions").join(format!("{pid}.json"))).unwrap();
        descriptor(&elsewhere, "sess", pid, "idle", 0);
        reset(&mut registry, &|_| {});
        observe(&mut registry);
        assert_eq!(lifecycle(&registry), Lifecycle::Unknown, "other store");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Facts of this very test process for the marker and executable checks.
    fn own_facts() -> ProcessFacts {
        os::process_facts(std::process::id()).unwrap()
    }

    /// A store is bindable only when it is an absolute, already canonical
    /// directory owned by this user that no group or other user can write: a
    /// private store (mode 0700) and an ordinary 0755 home store pass, while a
    /// group-writable or world-writable one, a symlink to a good store, a
    /// non-canonical spelling, a relative path, a file and a missing path are
    /// each refused with a static reason that names no path.
    #[test]
    fn a_store_must_be_canonical_owner_owned_and_closed_to_writers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("pst");
        let uid = own_facts().uid.unwrap();
        let mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let store = dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        for good in [0o700, 0o755, 0o750] {
            mode(&store, good);
            assert!(private_store(&store, uid).is_ok(), "{good:o}");
        }
        for bad in [0o775, 0o777, 0o757, 0o770 | 0o020] {
            mode(&store, bad);
            let reason = private_store(&store, uid).unwrap_err();
            assert!(!reason.contains(store.to_str().unwrap()), "{reason}");
        }
        mode(&store, 0o700);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&store, &link).unwrap();
        assert!(private_store(&link, uid).is_err(), "symlink");
        assert!(
            private_store(&dir.join("store").join("..").join("store"), uid).is_err(),
            "non-canonical"
        );
        assert!(private_store(Path::new("relative/store"), uid).is_err());
        assert!(private_store(&dir.join("missing"), uid).is_err());
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(private_store(&file, uid).is_err(), "not a directory");
        assert!(
            private_store(&store, uid.wrapping_add(1)).is_err(),
            "foreign owner"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A process executable must be a regular file of this user or root that
    /// no group or other user can write and that is unchanged since the process
    /// started: a freshly written file, a group-writable one and a directory are
    /// refused, a backdated private file passes. No digest is involved.
    #[test]
    fn a_process_executable_must_be_trusted_and_unchanged_since_start() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("exc");
        let facts = own_facts();
        let uid = facts.uid.unwrap();
        let exe = dir.join("exe");
        std::fs::write(&exe, b"x").unwrap();
        assert!(
            executable_current(&exe, &facts, uid).is_err(),
            "written after the process started"
        );
        backdate(&exe);
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        // chmod moves the status-change time: the file counts as changed again.
        let mut older = facts.clone();
        older.start_time = u64::MAX / 2;
        assert!(executable_current(&exe, &older, uid).is_ok());
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            executable_current(&exe, &older, uid).is_err(),
            "group writable"
        );
        assert!(executable_current(&dir, &older, uid).is_err(), "directory");
        assert!(executable_current(&exe, &older, uid.wrapping_add(1)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Message delivery rechecks the executable after admission: changing the
    /// running harness file's permissions after the snapshot was created makes
    /// the candidate unusable before any native send.
    #[test]
    fn message_candidate_refuses_an_executable_changed_after_admission() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mex");
        let store = dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = dir.join("claude-harness");
        let mut child = live_child(&executable, "CLAUDE_CONFIG_DIR", &store);
        let facts = os::process_facts(child.id()).unwrap();
        let address = NativeAddress::new("h", Harness::ClaudeCode, "ns", "session").unwrap();
        let candidate = MessageCandidate {
            binding: Binding {
                address,
                harness: (facts.pid, facts.start_time),
                epoch: 1,
                capabilities: Capabilities {
                    inject: true,
                    message: true,
                },
                qualified: Capabilities {
                    inject: true,
                    message: true,
                },
                version: POLICY_LABEL.into(),
                lifecycle: Lifecycle::Inactive,
                transcript: None,
                store: store.clone(),
                executable: executable.clone(),
                retired: false,
                desktop_idle_message: false,
                desktop_idle_transcript: None,
                wake: None,
                pending: false,
                role: None,
            },
            policy: HarnessPolicy {
                harness: Harness::ClaudeCode,
                namespace: "ns".into(),
                inject: true,
                message: true,
                executable_markers: Vec::new(),
            },
            owner_uid: facts.uid.unwrap(),
        };
        candidate.live_check().expect("unchanged executable");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            candidate.live_check().is_err(),
            "changed executable must refuse"
        );
        let _ = child.kill();
        let _ = child.wait();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A process is positively a harness only by its resolved executable path:
    /// the product name by default or a configured marker. An inherited store
    /// variable never marks it (every descendant of a harness carries it), so an
    /// unrelated process, even one whose environment names the product store, is
    /// never a Codex or Claude harness.
    #[test]
    fn an_unmarked_ancestor_is_never_a_harness() {
        let policy = |harness, markers: &[&str]| HarnessPolicy {
            harness,
            namespace: "ns".into(),
            inject: true,
            message: true,
            executable_markers: markers.iter().map(|m| (*m).to_string()).collect(),
        };
        let codex = policy(Harness::Codex, &[]);
        let claude = policy(Harness::ClaudeCode, &[]);
        // An unrelated executable that inherited the product store variable.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .env("CLAUDE_CONFIG_DIR", "/tmp/anything")
            .env("CODEX_HOME", "/tmp/anything")
            .spawn()
            .unwrap();
        let facts = os::process_facts(child.id()).unwrap();
        assert!(!product_marked(&facts, &codex));
        assert!(!product_marked(&facts, &claude));
        let _ = child.kill();
        let _ = child.wait();
        let mut named = facts.clone();
        named.exe = Some(PathBuf::from("/opt/Claude/bin/Claude Code"));
        assert!(product_marked(&named, &claude));
        assert!(!product_marked(&named, &codex));
        named.exe = Some(PathBuf::from("/Applications/ChatGPT.app/codex-cli/codex"));
        assert!(product_marked(&named, &codex));
        // A configured marker replaces the product name; an empty marker matches nothing.
        let custom = policy(Harness::Codex, &["wrapper-x", ""]);
        named.exe = Some(PathBuf::from("/opt/Wrapper-X/run"));
        assert!(product_marked(&named, &custom));
        named.exe = Some(PathBuf::from("/opt/codex/run"));
        assert!(!product_marked(&named, &custom));
        named.exe = None;
        assert!(!product_marked(&named, &codex));
    }

    /// A channel peer of another user, a harness the policy does not serve, and a
    /// hook of an unmarked ancestor are all refused as not evidence before any
    /// state changes; no store path or executable is consulted.
    #[test]
    fn foreign_user_unserved_harness_and_unmarked_ancestor_are_refused() {
        let mut registry = registry_with(&[]);
        let uid = own_facts().uid.unwrap();
        registry.owner_uid = uid;
        let payload = HookPayload {
            hook_event_name: "SessionStart".into(),
            session_id: "s".into(),
            agent_id: None,
            tool_use_id: None,
            tool_name: None,
            notification_type: None,
            transcript_path: None,
            source: None,
        };
        let me = |uid| PeerIdentity {
            pid: std::process::id(),
            uid,
        };
        for (peer, harness, why, reason) in [
            (
                me(uid.wrapping_add(1)),
                Harness::ClaudeCode,
                "foreign user",
                "another user",
            ),
            (
                me(uid),
                Harness::Codex,
                "harness not served by the policy",
                "not enabled",
            ),
            (
                me(uid),
                Harness::ClaudeCode,
                "no marked harness ancestor",
                "no harness ancestor",
            ),
        ] {
            let error = registry
                .admit_hook(peer, harness, &payload, 1_000)
                .unwrap_err();
            assert_eq!(error.class(), "not_evidence", "{why}: {error}");
            // The exact refusal, so a skipped earlier fence cannot hide behind a later one.
            assert!(
                error.detail().contains(reason)
                    || (reason == "no harness ancestor" && error.detail().contains("marked")),
                "{why}: {error}"
            );
        }
        assert!(registry.bindings.is_empty(), "nothing was bound");
    }

    /// Legacy `profiles` are migration input only: one policy per harness (their
    /// single namespace, union of the capability flags) with an explicit note per
    /// profile and no path, digest or signature authorizing anything; both
    /// `harnesses` and `profiles`, two namespaces for one harness, two policies
    /// for one harness and a bad namespace fail loudly, and a configuration with
    /// neither serves no harness.
    #[test]
    fn legacy_profiles_migrate_explicitly_and_ambiguity_fails_loudly() {
        let entry = |inject, message| QualifiedExecutable {
            path: "/nowhere/harness".into(),
            sha256: "0".repeat(64),
            version: "legacy".into(),
            inject,
            message,
            signature: Some(VendorSignature {
                identifier: "vendor-tool".into(),
                team_id: "ABCDE12345".into(),
            }),
        };
        let profile = |namespace: &str, harness, store: &str, inject, message| Profile {
            namespace: namespace.into(),
            harness,
            store: store.into(),
            executables: vec![entry(inject, message)],
        };
        let base = || RegistryConfig {
            host_id: "h".into(),
            harnesses: Vec::new(),
            profiles: Vec::new(),
            intermediates: Vec::new(),
            max_call_age_ms: 1,
            relays: Vec::new(),
            audiences: Vec::new(),
            legacy_owner_relays: 0,
        };
        let none = base().harness_policies().unwrap();
        assert!(none.0.is_empty() && none.1.is_empty());

        let mut legacy = base();
        legacy.profiles = vec![
            profile("claude-main", Harness::ClaudeCode, "/s/one", true, false),
            profile("claude-main", Harness::ClaudeCode, "/s/two", false, true),
            profile("codex-main", Harness::Codex, "/s/x", false, true),
        ];
        let (policies, notes) = legacy.harness_policies().unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(
            policies[0],
            HarnessPolicy {
                harness: Harness::ClaudeCode,
                namespace: "claude-main".into(),
                inject: true,
                message: true,
                executable_markers: Vec::new()
            }
        );
        assert!(!policies[1].inject && policies[1].message);
        assert_eq!(notes.len(), 3, "one explicit note per legacy profile");
        assert!(notes.iter().all(|n| n.contains("no longer authorize")));
        let registry = Registry::new(legacy.clone(), 0).unwrap();
        assert_eq!(registry.migration_notes().len(), 3);
        assert!(registry.policy(Harness::Codex).is_some());

        let mut ambiguous = legacy.clone();
        ambiguous.profiles.push(profile(
            "claude-other",
            Harness::ClaudeCode,
            "/s/three",
            true,
            true,
        ));
        assert!(
            ambiguous
                .harness_policies()
                .unwrap_err()
                .contains("more than one namespace")
        );
        assert!(Registry::new(ambiguous, 0).is_err());

        let policy = HarnessPolicy {
            harness: Harness::Codex,
            namespace: "codex-main".into(),
            inject: false,
            message: true,
            executable_markers: Vec::new(),
        };
        let mut both = legacy.clone();
        both.harnesses = vec![policy.clone()];
        assert!(both.harness_policies().unwrap_err().contains("not both"));
        let mut twice = base();
        twice.harnesses = vec![policy.clone(), policy.clone()];
        assert!(
            twice
                .harness_policies()
                .unwrap_err()
                .contains("two policies")
        );
        let mut bad = base();
        bad.harnesses = vec![HarnessPolicy {
            namespace: String::new(),
            ..policy
        }];
        assert!(bad.harness_policies().is_err());
    }

    /// A configuration written for the removed store and build trust still parses
    /// from TOML, vendor signature included, and only migrates: the policy keeps
    /// its namespace and capability flags and nothing else survives.
    #[test]
    fn a_legacy_toml_profile_with_signature_parses_and_migrates() {
        let legacy = r#"
host_id = "h"
[[profiles]]
namespace = "codex-main"
harness = "Codex"
store = "/ABS/home/.codex"
[[profiles.executables]]
path = "/Applications/Codex.app/codex"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
version = "1"
inject = false
message = true
signature = { identifier = "codex", team_id = "ABCDE12345" }
"#;
        let config: RegistryConfig = toml::from_str(legacy).unwrap();
        assert!(config.harnesses.is_empty());
        let (policies, notes) = config.harness_policies().unwrap();
        assert_eq!(
            policies,
            vec![HarnessPolicy {
                harness: Harness::Codex,
                namespace: "codex-main".into(),
                inject: false,
                message: true,
                executable_markers: Vec::new(),
            }]
        );
        assert!(notes[0].contains("vendor signatures no longer authorize"));
        let current: RegistryConfig = toml::from_str(
            "host_id = \"h\"\n[[harnesses]]\nharness = \"Codex\"\nnamespace = \"codex-main\"\ninject = false\nmessage = true\nexecutable_markers = [\"codex\"]\n",
        )
        .unwrap();
        assert_eq!(
            current.harness_policies().unwrap().0[0].executable_markers,
            ["codex"]
        );
        assert!(
            toml::from_str::<RegistryConfig>(
                "host_id = \"h\"\n[[harnesses]]\nharness = \"Codex\"\nnamespace = \"c\"\ninject = false\nmessage = true\nstore = \"/x\"\n"
            )
            .is_err(),
            "a harness policy accepts no store or executable path"
        );
    }

    /// A configuration written for the removed owner-build allowlist still
    /// parses: its `owner_relays` input is an ignored unknown key that
    /// authorizes nothing and changes no policy, and an invalid entry in it is
    /// not even validated.
    #[test]
    fn legacy_owner_relays_input_is_ignored() {
        let with_legacy: RegistryConfig = toml::from_str(
            "host_id = \"h\"\n[[harnesses]]\nharness = \"Codex\"\nnamespace = \"codex-main\"\ninject = false\nmessage = true\n[[owner_relays]]\npath = \"relative/not-even-absolute\"\nsha256 = \"nothex\"\n",
        )
        .unwrap();
        let without: RegistryConfig = toml::from_str(
            "host_id = \"h\"\n[[harnesses]]\nharness = \"Codex\"\nnamespace = \"codex-main\"\ninject = false\nmessage = true\n",
        )
        .unwrap();
        assert_eq!(with_legacy.legacy_owner_relays, 1);
        assert_eq!(without.legacy_owner_relays, 0);
        assert_eq!(
            with_legacy.harness_policies().unwrap().0,
            without.harness_policies().unwrap().0,
            "the legacy input changes no policy"
        );
        assert!(
            without.harness_policies().unwrap().1.is_empty(),
            "a current configuration reports nothing"
        );
        let registry = Registry::new(with_legacy.clone(), 0).unwrap();
        assert_eq!(registry.unqualified_executables(), 0);
        assert!(
            registry.configured_paths().is_empty(),
            "no owner path joins the digest cache"
        );
        assert!(registry.policy(Harness::Codex).is_some());
        // The one explicit migration note, with its log/check code.
        assert_eq!(registry.migration_notes().len(), 1);
        assert!(
            registry.migration_notes()[0].starts_with(
                "legacy_owner_relays_ignored: 1 [[adapters.owner_relays]] entry ignored"
            ),
            "{:?}",
            registry.migration_notes()
        );
        // Never serialized back: the retired key does not reappear.
        assert!(
            !serde_json::to_string(&with_legacy)
                .unwrap()
                .contains("owner_relays")
        );
    }

    /// The registry advertises no native host/build fact: there is no configured
    /// build to disclose, and nothing fake is listed.
    #[test]
    fn no_native_build_contract_is_advertised() {
        let mut registry = registry_with(&[]);
        assert!(registry.native_contracts().is_empty());
    }
}
