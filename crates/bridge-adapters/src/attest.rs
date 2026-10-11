//! Attested bindings and fail-closed actor correlation.
//!
//! An [`AttestedBinding`] is the adapter layer's answer to "who and where is
//! this recipient, really": the exact canonical [`NativeAddress`], the actual
//! calling actor (root or child), a monotonically fenced endpoint epoch with
//! real process evidence, and the capabilities the loaded adapter actually
//! supports. Nothing here is derived from display names, `/root/child`
//! display paths, inherited environment, cwd or a bare PID.
//!
//! The correlation half implements the `bridge-root-caller` obligations:
//! Codex children carry their own real MCP thread id while turn metadata
//! keeps the shared root session id; Claude children share the root
//! `session_id` and are distinguished only by joining the MCP request's
//! `claudecode/toolUseId` to exactly one trusted actor-bearing `PreToolUse`
//! record on the same protected channel. Missing, duplicate, stale or
//! conflicting evidence refuses.

use std::collections::BTreeMap;

use bridge_core::{CoreError, Harness, NativeAddress};

/// Maximum bytes of a native actor identifier (thread id, agent id).
pub const MAX_ACTOR_ID_BYTES: usize = 256;

/// Role of one native actor within its harness session.
///
/// Root and child are routing-distinct: root-targeted inject may be drained
/// only by a verified root hook, and a child may never drain, emit under, or
/// acknowledge the parent's data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActorRole {
    /// The session's root context (Codex turn root, Claude root session).
    Root,
    /// A distinct child context with its own real native actor identifier
    /// (Codex MCP thread id, Claude hook agent id).
    Child,
}

/// The actual native actor identity, independent of any display path.
///
/// `native_id` is the harness-owned identifier only (a Codex thread id or a
/// Claude agent id) — never a name, project, task or temporary label.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActorId {
    /// Whether this actor is the session root or a child context.
    pub role: ActorRole,
    /// The harness-native identifier of this actor.
    pub native_id: String,
}

impl ActorId {
    /// Builds a root actor with the session's own identifier.
    ///
    /// Errors with [`AdapterError::Invalid`] when the id is empty, over
    /// [`MAX_ACTOR_ID_BYTES`] bytes, or contains control characters.
    pub fn root(native_id: impl Into<String>) -> Result<Self, CoreError> {
        ActorId::new(ActorRole::Root, native_id)
    }

    /// Builds a child actor with its distinct real native identifier.
    ///
    /// Same validation rules as [`ActorId::root`].
    pub fn child(native_id: impl Into<String>) -> Result<Self, CoreError> {
        ActorId::new(ActorRole::Child, native_id)
    }

    /// Validates and wraps an actor identifier for either role.
    fn new(role: ActorRole, native_id: impl Into<String>) -> Result<Self, CoreError> {
        let native_id = native_id.into();
        if native_id.is_empty() || native_id.len() > MAX_ACTOR_ID_BYTES {
            return Err(CoreError::InvalidEnvelope("actor id out of bounds".into()));
        }
        if native_id.chars().any(char::is_control) {
            return Err(CoreError::InvalidEnvelope(
                "actor id must not contain control characters".into(),
            ));
        }
        Ok(ActorId { role, native_id })
    }
}

/// Monotonically fenced endpoint binding epoch.
///
/// Reconnecting the same verified logical session renews its epoch; a stale
/// endpoint can never receive a new invocation merely because its path or
/// PID resembles the old one. Epochs only increase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingEpoch(pub u64);

/// Real endpoint/process evidence for one transport binding.
///
/// Every field is observed from the OS, not asserted by a peer: the PID of
/// the endpoint process, the socket or path it was reached through, and the
/// wall-clock time the evidence was gathered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointEvidence {
    /// OS process id of the native endpoint.
    pub pid: u32,
    /// Socket path (or equivalent endpoint name) the binding used.
    pub endpoint_path: String,
    /// Unix epoch milliseconds at which this evidence was observed.
    pub observed_at_ms: u64,
}

/// Availability of one carrier capability on the actually loaded adapter.
///
/// `Unsupported` is a permanent, known limitation that must refuse before
/// production acceptance. `Hold` is a transient outage of a supported
/// capability with an explicit recheck deadline — never indefinite parking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// The capability is qualified and usable on this loaded adapter.
    Supported,
    /// The loaded adapter does not support this capability; refuse before
    /// production acceptance and keep the producer's durable intent on its
    /// still-owned compatible route.
    Unsupported(&'static str),
    /// A supported capability is transiently unavailable; recheck at the
    /// given absolute Unix epoch millisecond deadline.
    Hold { recheck_at_ms: u64 },
}

impl Capability {
    /// Whether an operation may proceed on this capability right now.
    pub fn usable(&self) -> bool {
        matches!(self, Capability::Supported)
    }
}

/// Capabilities of one loaded native adapter, keyed by carrier name.
///
/// Keys are the canonical mode names (`inject`, `message`) plus
/// `child_routing`; unknown keys simply do not appear.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadedCapabilities {
    /// Capability map; absent means never attested, which callers must
    /// treat as unsupported rather than supported.
    pub carriers: BTreeMap<&'static str, Capability>,
}

impl LoadedCapabilities {
    /// Looks up one carrier capability.
    ///
    /// An unattested carrier returns [`Capability::Unsupported`] — absence
    /// of evidence is never evidence of support.
    pub fn carrier(&self, name: &str) -> Capability {
        self.carriers
            .get(name)
            .cloned()
            .unwrap_or(Capability::Unsupported("carrier never attested"))
    }
}

/// A fully attested transport binding to one native recipient.
///
/// Bundles the canonical logical address, the actual actor the binding was
/// established for, the fenced epoch, real endpoint evidence and the loaded
/// capabilities observed at attestation time. Renewal of a verified session
/// produces a new, higher epoch; anything else is a different recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedBinding {
    /// Exact canonical logical address of the recipient session.
    pub address: NativeAddress,
    /// The actual actor this binding serves.
    pub actor: ActorId,
    /// Fenced epoch; attempts carrying a lower epoch are stale.
    pub epoch: BindingEpoch,
    /// Real process evidence backing the binding.
    pub evidence: EndpointEvidence,
    /// Capabilities of the loaded adapter at attestation time.
    pub capabilities: LoadedCapabilities,
}

impl AttestedBinding {
    /// Renews the binding after a verified reconnect of the same logical
    /// session and actor.
    ///
    /// Fails with [`AdapterError::Invalid`] if the address or actor changed
    /// (that is a different recipient, not a renewal) or the new epoch does
    /// not strictly exceed the current one. On success the epoch is the
    /// supplied newer one and the endpoint evidence is replaced.
    pub fn renew(
        &self,
        epoch: BindingEpoch,
        evidence: EndpointEvidence,
    ) -> Result<Self, crate::AdapterError> {
        if epoch <= self.epoch {
            return Err(crate::AdapterError::Invalid(
                "binding renewal must increase the epoch".into(),
            ));
        }
        Ok(AttestedBinding {
            address: self.address.clone(),
            actor: self.actor.clone(),
            epoch,
            evidence,
            capabilities: self.capabilities.clone(),
        })
    }

    /// Whether an attempt fenced to `epoch` is still current for this
    /// binding.
    ///
    /// An attempt epoch below the binding's is stale and must be refused
    /// without invocation (it may belong to a previous endpoint of the same
    /// logical session).
    pub fn accepts_epoch(&self, epoch: BindingEpoch) -> bool {
        epoch == self.epoch
    }
}

/// Why correlation evidence refused to identify exactly one actor.
///
/// Every variant fails closed: no invocation, no routing, no fallback to a
/// display path or the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationError {
    /// No trusted record exists for the presented identifier.
    Missing(String),
    /// More than one trusted record matched; ambiguous identity refuses.
    Duplicate(String),
    /// The matched record predates the current binding epoch.
    Stale(String),
    /// Matching records disagree on actor, session or channel.
    Conflicting(String),
    /// The presented evidence is of a kind that never authenticates
    /// (inherited environment, display path, cwd or model arguments).
    NotEvidence(&'static str),
}

impl std::fmt::Display for CorrelationError {
    /// Names the refusal class and the identifier involved.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorrelationError::Missing(id) => write!(f, "no trusted record for {id}"),
            CorrelationError::Duplicate(id) => write!(f, "ambiguous records for {id}"),
            CorrelationError::Stale(id) => write!(f, "record for {id} predates binding epoch"),
            CorrelationError::Conflicting(id) => write!(f, "conflicting records for {id}"),
            CorrelationError::NotEvidence(kind) => {
                write!(f, "{kind} is not caller identity evidence")
            }
        }
    }
}

impl std::error::Error for CorrelationError {}

/// One trusted, actor-bearing `PreToolUse` record on a protected channel.
///
/// Claude correlation material: the record a real MCP request's
/// `claudecode/toolUseId` must join to exactly one of. Records are inserted
/// only by the protected channel observer; model arguments, payload text and
/// inherited environment can never create one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreToolUseRecord {
    /// The tool-use identifier the MCP request will present.
    pub tool_use_id: String,
    /// The hook `agent_id` of the actual child actor.
    pub agent_id: String,
    /// The root `session_id` the channel belongs to.
    pub session_id: String,
    /// Binding epoch the record was observed under.
    pub epoch: BindingEpoch,
}

/// Fail-closed registry joining Claude tool-use ids to trusted records.
///
/// The join rule is exact: one tool-use id must match exactly one trusted
/// record under the current binding epoch and the same session; anything
/// else refuses with the matching [`CorrelationError`].
#[derive(Debug, Default)]
pub struct PreToolUseLog {
    records: BTreeMap<String, Vec<PreToolUseRecord>>,
}

impl PreToolUseLog {
    /// Records one trusted `PreToolUse` observation.
    ///
    /// Duplicate inserts are kept (they make later resolution ambiguous by
    /// construction); the registry never silently drops evidence.
    pub fn record(&mut self, entry: PreToolUseRecord) {
        self.records
            .entry(entry.tool_use_id.clone())
            .or_default()
            .push(entry);
    }

    /// Resolves the actual child actor for a presented tool-use id.
    ///
    /// Refuses when the id is unknown ([`CorrelationError::Missing`]),
    /// matches several records ([`Duplicate`]), all matching records are
    /// older than the current epoch ([`Stale`]), or matching records
    /// disagree on actor or session ([`Conflicting`]). On success returns
    /// the child [`ActorId`] and the session the channel belongs to.
    pub fn resolve(
        &self,
        tool_use_id: &str,
        current_epoch: BindingEpoch,
    ) -> Result<(ActorId, String), CorrelationError> {
        let matches = self
            .records
            .get(tool_use_id)
            .ok_or_else(|| CorrelationError::Missing(tool_use_id.to_string()))?;
        let fresh: Vec<&PreToolUseRecord> = matches
            .iter()
            .filter(|record| record.epoch == current_epoch)
            .collect();
        if fresh.is_empty() {
            return Err(CorrelationError::Stale(tool_use_id.to_string()));
        }
        let first = fresh[0];
        if fresh.iter().any(|record| {
            record.agent_id != first.agent_id || record.session_id != first.session_id
        }) {
            return Err(CorrelationError::Conflicting(tool_use_id.to_string()));
        }
        if fresh.len() > 1 {
            // Same actor repeated is still ambiguous evidence: an id must
            // join exactly one trusted record.
            return Err(CorrelationError::Duplicate(tool_use_id.to_string()));
        }
        Ok((
            ActorId::child(first.agent_id.clone())
                .expect("trusted records carry validated agent ids"),
            first.session_id.clone(),
        ))
    }
}

/// Native identity evidence kinds that never authenticate a caller.
///
/// Checking one of these is not merely unreliable — presenting it as
/// evidence is refused outright with [`CorrelationError::NotEvidence`], so a
/// hostile payload cannot launder itself through environment or paths.
pub const NON_EVIDENCE_KINDS: [&str; 4] = [
    "inherited harness environment (e.g. CODEX_* under Claude)",
    "display paths such as /root/child",
    "current working directory",
    "model arguments or payload text",
];

/// Refuses non-evidence presented as caller identity.
///
/// Takes the name of the evidence kind (one of [`NON_EVIDENCE_KINDS`] or any
/// descriptive label) and always returns
/// [`CorrelationError::NotEvidence`]; there is no input for which this
/// function succeeds, which lets call sites route every pseudo-evidence
/// attempt through one fail-closed gate.
pub fn refuse_non_evidence(kind: &'static str) -> CorrelationError {
    CorrelationError::NotEvidence(kind)
}

/// A caller attested from protected native correlation evidence.
///
/// This is the `bridge-root-caller` provider ABI consumed by the restricted
/// MCP surface (M-006): everything an authorized root operation needs to
/// know about who is actually calling, and nothing it can guess. Produced
/// exclusively by [`attest_caller`] from protected-channel evidence — an
/// operator-configured address is a substitute fixture on the consumer side
/// and can never construct one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCaller {
    /// Exact canonical native address of the calling session.
    pub address: NativeAddress,
    /// The actual calling actor (root or child), never a display label.
    pub actor: ActorId,
    /// Endpoint binding epoch the correlation was made under.
    pub epoch: BindingEpoch,
    /// Unix epoch milliseconds at which the protected evidence was joined.
    pub observed_at_ms: u64,
    /// Which protected correlation channel produced this attestation.
    pub channel: ProtectedChannel,
}

/// Which protected channel the caller attestation was derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedChannel {
    /// Claude: `claudecode/toolUseId` joined to exactly one trusted
    /// `PreToolUse` record on the same protected channel.
    ClaudePreToolUse,
    /// Codex: real MCP `threadId` correlation against the attested binding.
    CodexMcpThread,
}

impl AttestedCaller {
    /// Whether the attestation is still fresh enough to authorize a call at
    /// `now_ms`.
    ///
    /// Staleness degrades to `false` (refuse); it never relaxes into a
    /// weaker-but-usable state.
    pub fn is_fresh(&self, now_ms: u64, max_age_ms: u64) -> bool {
        now_ms.saturating_sub(self.observed_at_ms) <= max_age_ms
    }

    /// Whether this caller may perform root-only operations (drain, emit,
    /// acknowledge root-targeted data).
    ///
    /// Only a verified root actor may; children never drain, emit under or
    /// acknowledge the parent's data.
    pub fn may_operate_root(&self) -> bool {
        self.actor.role == ActorRole::Root
    }
}

/// Protected correlation evidence presented for caller attestation.
///
/// One variant per harness; both carry only harness-produced protected
/// metadata. Model arguments, payload text, display names, cwd, PIDs and
/// environment inherited from a foreign harness have no variant here and
/// can never produce an [`AttestedCaller`].
pub enum ProtectedEvidence<'a> {
    /// Claude evidence: the tool-use id from the real MCP request plus the
    /// trusted `PreToolUse` log and the binding to join against.
    ClaudeToolUse {
        /// `claudecode/toolUseId` supplied by the real MCP request.
        tool_use_id: &'a str,
        /// Trusted actor-bearing records from the protected channel.
        log: &'a PreToolUseLog,
        /// Current binding of the addressed root session.
        binding: &'a AttestedBinding,
        /// Host id component of the address under construction.
        host_id: &'a str,
        /// Native store namespace component of the address.
        store_namespace: &'a str,
    },
    /// Codex evidence: the real MCP thread identity plus the binding it
    /// must correlate with.
    CodexThread {
        /// The observed MCP thread/root identity split.
        identity: &'a CodexSessionIdentity,
        /// Current binding the thread must match.
        binding: &'a AttestedBinding,
        /// Host id component of the address under construction.
        host_id: &'a str,
        /// Native store namespace component of the address.
        store_namespace: &'a str,
    },
}

/// Attests the actual caller from protected evidence, fail-closed.
///
/// Claude: joins the tool-use id to exactly one fresh trusted record under
/// the binding epoch, and requires the record's session to be the bound
/// address's session id. Codex: requires the thread identity to be the
/// bound context (root thread or child thread) and derives the address from
/// the real thread id. Any miss — unknown id, duplicates, stale epoch,
/// session or channel disagreement — returns the matching
/// [`CorrelationError`] and authorizes nothing.
pub fn attest_caller(evidence: ProtectedEvidence<'_>) -> Result<AttestedCaller, CorrelationError> {
    match evidence {
        ProtectedEvidence::ClaudeToolUse {
            tool_use_id,
            log,
            binding,
            host_id,
            store_namespace,
        } => {
            let (actor, session_id) = log.resolve(tool_use_id, binding.epoch)?;
            let address =
                NativeAddress::new(host_id, Harness::ClaudeCode, store_namespace, &session_id)
                    .map_err(|_| CorrelationError::Conflicting(tool_use_id.to_string()))?;
            if address != binding.address {
                return Err(CorrelationError::Conflicting(tool_use_id.to_string()));
            }
            Ok(AttestedCaller {
                address,
                actor,
                epoch: binding.epoch,
                observed_at_ms: binding.evidence.observed_at_ms,
                channel: ProtectedChannel::ClaudePreToolUse,
            })
        }
        ProtectedEvidence::CodexThread {
            identity,
            binding,
            host_id,
            store_namespace,
        } => {
            let address = identity
                .address(host_id, store_namespace)
                .map_err(|_| CorrelationError::Conflicting(identity.mcp_thread_id.clone()))?;
            let actor = identity
                .actor()
                .map_err(|_| CorrelationError::Conflicting(identity.mcp_thread_id.clone()))?;
            // The presented thread must be the bound context itself; a
            // sibling thread under the same root is a different recipient.
            if binding.address != address || binding.actor != actor {
                return Err(CorrelationError::Conflicting(
                    identity.mcp_thread_id.clone(),
                ));
            }
            Ok(AttestedCaller {
                address,
                actor,
                epoch: binding.epoch,
                observed_at_ms: binding.evidence.observed_at_ms,
                channel: ProtectedChannel::CodexMcpThread,
            })
        }
    }
}

/// Codex session identity split: child MCP thread vs shared turn root.
///
/// Reconnaissance established that Codex children have distinct real MCP
/// `threadId` values while turn metadata keeps one shared root `session_id`.
/// Both parts are carried without conflating them: routing to the child uses
/// the thread id; the root session id is context, never the child address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexSessionIdentity {
    /// The real MCP thread id of this (child or root) context.
    pub mcp_thread_id: String,
    /// The shared root session id from turn metadata.
    pub root_session_id: String,
    /// Whether this context is the root itself.
    pub is_root: bool,
}

impl CodexSessionIdentity {
    /// The native address of this context inside `store_namespace`.
    ///
    /// The session id component is the MCP thread id — the real per-context
    /// identifier — never the shared root session id.
    pub fn address(
        &self,
        host_id: &str,
        store_namespace: &str,
    ) -> Result<NativeAddress, CoreError> {
        NativeAddress::new(
            host_id,
            Harness::Codex,
            store_namespace,
            &self.mcp_thread_id,
        )
    }

    /// The actor identity of this context.
    ///
    /// Root contexts use the root session id as their actor id; children use
    /// their own thread id. Errors on invalid ids (empty/oversized).
    pub fn actor(&self) -> Result<ActorId, CoreError> {
        if self.is_root {
            ActorId::root(&self.root_session_id)
        } else {
            ActorId::child(&self.mcp_thread_id)
        }
    }

    /// Whether routing to this context as a child is enabled.
    ///
    /// Enabled only when the actual child address is attested and the named
    /// carrier capability is supported; otherwise the caller must return
    /// unsupported and never redirect to the parent.
    pub fn child_routing_enabled(&self, capabilities: &LoadedCapabilities, carrier: &str) -> bool {
        !self.is_root && capabilities.carrier(carrier).usable()
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for attestation and correlation.

    use super::*;

    fn record(tool_use_id: &str, agent: &str, epoch: u64) -> PreToolUseRecord {
        PreToolUseRecord {
            tool_use_id: tool_use_id.into(),
            agent_id: agent.into(),
            session_id: "session-9".into(),
            epoch: BindingEpoch(epoch),
        }
    }

    #[test]
    fn claude_join_requires_exactly_one_fresh_matching_record() {
        let mut log = PreToolUseLog::default();
        assert!(matches!(
            log.resolve("tu-1", BindingEpoch(1)),
            Err(CorrelationError::Missing(_))
        ));
        log.record(record("tu-1", "agent-a", 1));
        let (actor, session) = log.resolve("tu-1", BindingEpoch(1)).unwrap();
        assert_eq!(actor.role, ActorRole::Child);
        assert_eq!(actor.native_id, "agent-a");
        assert_eq!(session, "session-9");
        // Duplicate insert (even identical) makes the join ambiguous.
        log.record(record("tu-1", "agent-a", 1));
        assert!(matches!(
            log.resolve("tu-1", BindingEpoch(1)),
            Err(CorrelationError::Duplicate(_))
        ));
        // Fresh id but stale epoch refuses.
        log.record(record("tu-2", "agent-b", 1));
        assert!(matches!(
            log.resolve("tu-2", BindingEpoch(2)),
            Err(CorrelationError::Stale(_))
        ));
        // Disagreeing records conflict.
        log.record(record("tu-3", "agent-b", 2));
        log.record(record("tu-3", "agent-c", 2));
        assert!(matches!(
            log.resolve("tu-3", BindingEpoch(2)),
            Err(CorrelationError::Conflicting(_))
        ));
    }

    #[test]
    fn non_evidence_always_refuses() {
        for kind in NON_EVIDENCE_KINDS {
            assert!(matches!(
                refuse_non_evidence(kind),
                CorrelationError::NotEvidence(_)
            ));
        }
    }

    #[test]
    fn codex_child_address_uses_thread_id_not_shared_root() {
        let identity = CodexSessionIdentity {
            mcp_thread_id: "thread-child-7".into(),
            root_session_id: "root-1".into(),
            is_root: false,
        };
        let address = identity.address("host-1", "store").unwrap();
        assert_eq!(address.native_session_id, "thread-child-7");
        assert_eq!(identity.actor().unwrap().role, ActorRole::Child);
        let root = CodexSessionIdentity {
            mcp_thread_id: "thread-child-7".into(),
            root_session_id: "root-1".into(),
            is_root: true,
        };
        assert_eq!(root.actor().unwrap().role, ActorRole::Root);
    }

    #[test]
    fn child_routing_needs_attested_capability() {
        let identity = CodexSessionIdentity {
            mcp_thread_id: "t-1".into(),
            root_session_id: "r-1".into(),
            is_root: false,
        };
        let mut capabilities = LoadedCapabilities::default();
        assert!(!identity.child_routing_enabled(&capabilities, "message"));
        capabilities
            .carriers
            .insert("message", Capability::Supported);
        assert!(identity.child_routing_enabled(&capabilities, "message"));
        capabilities
            .carriers
            .insert("message", Capability::Unsupported("not loaded"));
        assert!(!identity.child_routing_enabled(&capabilities, "message"));
    }

    #[test]
    fn binding_renewal_fences_epochs() {
        let binding = AttestedBinding {
            address: NativeAddress::new("h", Harness::ClaudeCode, "s", "sess").unwrap(),
            actor: ActorId::root("sess").unwrap(),
            epoch: BindingEpoch(3),
            evidence: EndpointEvidence {
                pid: 42,
                endpoint_path: "/tmp/x.sock".into(),
                observed_at_ms: 1_000,
            },
            capabilities: LoadedCapabilities::default(),
        };
        let renewed = binding
            .renew(
                BindingEpoch(4),
                EndpointEvidence {
                    pid: 43,
                    endpoint_path: "/tmp/x.sock".into(),
                    observed_at_ms: 2_000,
                },
            )
            .unwrap();
        assert!(binding.accepts_epoch(BindingEpoch(3)));
        assert!(!binding.accepts_epoch(BindingEpoch(4)));
        assert!(renewed.accepts_epoch(BindingEpoch(4)));
        assert!(
            binding
                .renew(BindingEpoch(3), renewed.evidence.clone())
                .is_err()
        );
    }

    #[test]
    fn unattested_carrier_is_unsupported() {
        let capabilities = LoadedCapabilities::default();
        assert!(!capabilities.carrier("inject").usable());
    }

    #[test]
    fn attested_caller_maps_protected_evidence_fail_closed() {
        let binding = AttestedBinding {
            address: NativeAddress::new("h", Harness::ClaudeCode, "store", "session-9").unwrap(),
            actor: ActorId::root("session-9").unwrap(),
            epoch: BindingEpoch(2),
            evidence: EndpointEvidence {
                pid: 7,
                endpoint_path: "/tmp/c.sock".into(),
                observed_at_ms: 5_000,
            },
            capabilities: LoadedCapabilities::default(),
        };
        let mut log = PreToolUseLog::default();
        // No record yet: refuse.
        assert!(
            attest_caller(ProtectedEvidence::ClaudeToolUse {
                tool_use_id: "tu-1",
                log: &log,
                binding: &binding,
                host_id: "h",
                store_namespace: "store",
            })
            .is_err()
        );
        log.record(record("tu-1", "agent-a", 2));
        let caller = attest_caller(ProtectedEvidence::ClaudeToolUse {
            tool_use_id: "tu-1",
            log: &log,
            binding: &binding,
            host_id: "h",
            store_namespace: "store",
        })
        .unwrap();
        assert_eq!(caller.actor.role, ActorRole::Child);
        assert!(!caller.may_operate_root());
        assert!(caller.is_fresh(6_000, 2_000));
        assert!(!caller.is_fresh(9_000, 2_000));
        // A binding to a different session refuses (channel disagreement).
        let mut other = binding.clone();
        other.address = NativeAddress::new("h", Harness::ClaudeCode, "store", "other").unwrap();
        assert!(
            attest_caller(ProtectedEvidence::ClaudeToolUse {
                tool_use_id: "tu-1",
                log: &log,
                binding: &other,
                host_id: "h",
                store_namespace: "store",
            })
            .is_err()
        );
        // Codex path: the bound root thread attests a root caller.
        let identity = CodexSessionIdentity {
            mcp_thread_id: "root-1".into(),
            root_session_id: "root-1".into(),
            is_root: true,
        };
        let codex_binding = AttestedBinding {
            address: identity.address("h", "store").unwrap(),
            actor: identity.actor().unwrap(),
            epoch: BindingEpoch(1),
            evidence: EndpointEvidence {
                pid: 9,
                endpoint_path: "/tmp/x.sock".into(),
                observed_at_ms: 1_000,
            },
            capabilities: LoadedCapabilities::default(),
        };
        let caller = attest_caller(ProtectedEvidence::CodexThread {
            identity: &identity,
            binding: &codex_binding,
            host_id: "h",
            store_namespace: "store",
        })
        .unwrap();
        assert!(caller.may_operate_root());
        // A different thread under the same root is a different recipient.
        let sibling = CodexSessionIdentity {
            mcp_thread_id: "thread-2".into(),
            root_session_id: "root-1".into(),
            is_root: false,
        };
        assert!(
            attest_caller(ProtectedEvidence::CodexThread {
                identity: &sibling,
                binding: &codex_binding,
                host_id: "h",
                store_namespace: "store",
            })
            .is_err()
        );
    }
}
