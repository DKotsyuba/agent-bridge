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
//!   a `SessionStart`, or a different live incarnation renews the binding
//!   with a strictly larger endpoint epoch; every older record becomes
//!   stale. A binding held by another live incarnation refuses the
//!   newcomer as conflicting.
//! - **Lifecycle.** Hook events are the owner session's own lifecycle feed:
//!   prompt/tool events are active, `Stop` is idle, permission and
//!   question prompts are awaiting input, `SessionEnd` and a dead
//!   incarnation are unknown. Unknown is never inactive.
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
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use bridge_core::dispatch::{Attestation, Capabilities, Lifecycle};
use bridge_core::{Harness, NativeAddress};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::os::{self, PeerIdentity, ProcessFacts};

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
/// have no field here. Build it only with [`PresentedMeta::from_mcp_meta`]
/// on the `_meta` object the MCP framework separated from arguments.
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
                if !meta
                    .get("x-codex-turn-metadata")
                    .is_some_and(serde_json::Value::is_object)
                {
                    return Err(CorrelationError::NotEvidence(
                        "_meta x-codex-turn-metadata object missing".into(),
                    ));
                }
                Ok(PresentedMeta::Codex {
                    thread_id: field("threadId")?,
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

    /// The per-call identifier joined against hook records.
    fn call_id(&self) -> &str {
        match self {
            PresentedMeta::Claude { tool_use_id } => tool_use_id,
            PresentedMeta::Codex { call_id, .. } => call_id,
        }
    }

    /// The harness this metadata belongs to.
    fn harness(&self) -> Harness {
        match self {
            PresentedMeta::Claude { .. } => Harness::ClaudeCode,
            PresentedMeta::Codex { .. } => Harness::Codex,
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
        }
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

/// One binding of an address to a harness incarnation.
#[derive(Debug, Clone)]
struct Binding {
    /// The bound address.
    address: NativeAddress,
    /// Harness incarnation `(pid, start_time)`.
    harness: (u32, u64),
    /// Monotonic endpoint epoch.
    epoch: u64,
    /// Qualified capabilities of the harness build.
    capabilities: Capabilities,
    /// Qualified build label for proof references.
    version: String,
    /// Owner-session lifecycle from the latest hook.
    lifecycle: Lifecycle,
    /// Session transcript inside the profile store, when reported.
    transcript: Option<PathBuf>,
    /// Profile store of the binding.
    store: PathBuf,
    /// Qualified harness executable of the binding.
    executable: PathBuf,
    /// Set by `SessionEnd`; a retired binding never attests.
    retired: bool,
}

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

/// Cache key of a verified executable digest: path, length, mtime.
type FileKey = (PathBuf, u64, u64);

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
}

/// The in-memory protected registry. Not persisted: after a daemon restart
/// every session is unknown until its next hook, never inactive.
#[derive(Debug)]
pub struct Registry {
    /// Configuration.
    config: RegistryConfig,
    /// The only user id accepted on the channel.
    owner_uid: u32,
    /// Bindings by canonical address.
    bindings: HashMap<String, Binding>,
    /// Call records by call id.
    calls: HashMap<String, Vec<CallRecord>>,
    /// Call ids in insertion order, for bounded eviction.
    call_order: VecDeque<String>,
    /// Verified executable digests keyed by (path, length, mtime).
    digests: HashMap<FileKey, String>,
    /// Bound of retained call records.
    max_calls: usize,
    /// Harnesses whose message carrier is unavailable on this host (for
    /// example no OS confinement launcher): never granted, so publication
    /// refuses before acceptance.
    message_disabled: Vec<Harness>,
}

/// Validates one native identifier: non-empty, bounded, no controls.
fn checked_id(value: &str, field: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > MAX_NATIVE_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(format!("{field} is not a valid native identifier"));
    }
    Ok(value.to_string())
}

/// Bounded single-line proof reference text.
fn proof(text: String) -> String {
    let mut text: String = text.chars().filter(|c| !c.is_control()).collect();
    text.truncate(256);
    text
}

impl Registry {
    /// Builds an empty registry for `owner_uid` (the daemon's own user).
    ///
    /// Refuses a configuration with relative paths, an empty namespace or
    /// host id, or a malformed digest.
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
        Ok(Registry {
            config,
            owner_uid,
            bindings: HashMap::new(),
            calls: HashMap::new(),
            call_order: VecDeque::new(),
            digests: HashMap::new(),
            max_calls: DEFAULT_MAX_CALL_RECORDS,
            message_disabled: Vec::new(),
        })
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

    /// Proves the loaded build: the file was not modified after the process
    /// started (disk is still what was loaded) and hashes to the qualified
    /// digest. Digests are cached per (path, length, mtime).
    fn verify_loaded(
        &mut self,
        exe: &Path,
        started: u64,
        qualified: &str,
    ) -> Result<(), CorrelationError> {
        let metadata = std::fs::metadata(exe)
            .map_err(|_| CorrelationError::NotEvidence("harness executable unreadable".into()))?;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .ok_or_else(|| CorrelationError::NotEvidence("harness mtime unreadable".into()))?;
        if mtime > started {
            return Err(CorrelationError::NotEvidence(
                "harness executable changed on disk after the process started; loaded build unproven"
                    .into(),
            ));
        }
        let key = (exe.to_path_buf(), metadata.len(), mtime);
        let digest = match self.digests.get(&key) {
            Some(digest) => digest.clone(),
            None => {
                let digest = file_sha256(exe)
                    .map_err(|_| CorrelationError::NotEvidence("harness unreadable".into()))?;
                self.digests.insert(key, digest.clone());
                digest
            }
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
    /// when needed (new incarnation, `SessionStart`, first sight), applies
    /// the lifecycle transition, records `PreToolUse` calls and decides
    /// whether this event may drain inject. Refuses (and changes nothing)
    /// on a non-harness peer, a malformed payload, or an address held by
    /// another live incarnation.
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
                kind == HookKind::SessionStart || binding.retired,
                Some(binding.epoch),
            ),
            None => (true, None),
        };
        if renewed {
            let epoch =
                previous_epoch.map_or(now_ms.max(1), |old| now_ms.max(old.saturating_add(1)));
            self.evict_bindings();
            self.bindings.insert(
                key.clone(),
                Binding {
                    address: address.clone(),
                    harness: matched.incarnation,
                    epoch,
                    capabilities,
                    version: qualified.version.clone(),
                    lifecycle: Lifecycle::Inactive,
                    transcript: None,
                    store: profile.store.clone(),
                    executable: qualified.path.clone(),
                    retired: false,
                },
            );
        }
        let binding = self.bindings.get_mut(&key).expect("binding inserted above");
        if transcript.is_some() {
            binding.transcript = transcript;
        }
        binding.lifecycle = next_lifecycle(binding.lifecycle, kind, role, harness, payload);
        if kind == HookKind::SessionEnd && role == ActorRole::Root {
            binding.retired = true;
        }
        let binding = binding.clone();

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
            if let Some(oldest) = self.call_order.pop_front()
                && let Some(records) = self.calls.get_mut(&oldest)
            {
                records.remove(0);
                if records.is_empty() {
                    self.calls.remove(&oldest);
                }
            }
        }
    }

    /// Drops retired or dead bindings when the bound is reached.
    fn evict_bindings(&mut self) {
        if self.bindings.len() < DEFAULT_MAX_BINDINGS {
            return;
        }
        self.bindings.retain(|_, binding| {
            !binding.retired && os::incarnation_alive(binding.harness.0, binding.harness.1)
        });
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
        let call = meta.call_id().to_string();
        checked_id(&call, "call id").map_err(CorrelationError::NotEvidence)?;
        let matched = self.harness_of(peer, meta.harness())?;
        let max_age = self.config.max_call_age_ms;
        let records = self
            .calls
            .get_mut(&call)
            .ok_or_else(|| CorrelationError::Missing(call.clone()))?;
        let mut same: Vec<&mut CallRecord> = records
            .iter_mut()
            .filter(|record| record.harness == matched.incarnation)
            .collect();
        if same.is_empty() {
            return Err(CorrelationError::Missing(call));
        }
        if same.iter().any(|record| record.consumed) {
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
        let record = &mut same[0];
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
        record.consumed = true;
        Ok(VerifiedCaller::new(
            binding.address.clone(),
            record.role,
            record.native_id.clone(),
            binding.epoch,
            record.observed_ms,
            match meta {
                PresentedMeta::Claude { .. } => CallerChannel::ClaudeToolUse,
                PresentedMeta::Codex { .. } => CallerChannel::CodexCall,
            },
        ))
    }

    /// Attests a recipient endpoint for a message carrier right now.
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
            },
        ))
    }
}

/// The next owner-session lifecycle after one hook event.
///
/// Prompt and tool events are active (a child's tool event means the root
/// awaits its subagent); `AskUserQuestion`, permission requests and
/// permission notifications await input; `Stop` and an idle-prompt
/// notification are idle; `SessionEnd` is unknown. Other events keep the
/// current state.
fn next_lifecycle(
    current: Lifecycle,
    kind: HookKind,
    role: ActorRole,
    harness: Harness,
    payload: &HookPayload,
) -> Lifecycle {
    let codex_child = harness == Harness::Codex && role == ActorRole::Child;
    match kind {
        HookKind::SessionStart => Lifecycle::Inactive,
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
            Some("idle_prompt") => Lifecycle::Inactive,
            _ => current,
        },
        HookKind::Stop if role == ActorRole::Root || codex_child => Lifecycle::Inactive,
        HookKind::Stop | HookKind::SubagentStop => current,
        HookKind::SessionEnd if role == ActorRole::Root || codex_child => Lifecycle::Unknown,
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
