//! Durable managed invocation records. No legacy assertion is promoted.

use super::*;
use bridge_protocol::Secret;

/// A full observed process incarnation including the configured host namespace.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Incarnation {
    /// Operator-configured host namespace.
    host_id: String,
    /// Linux kernel boot UUID.
    boot_id: String,
    /// PID namespace inode.
    pid_namespace_inode: u64,
    /// Effective UID.
    uid: u32,
    /// PID within the observer's namespace.
    pid: u32,
    /// Start time in kernel clock ticks.
    start_ticks: u64,
}

impl Incarnation {
    /// Combines configured host identity with independently captured kernel facts.
    fn new(host_id: &str, kernel: &os::attempt::KernelIncarnation) -> Self {
        Self {
            host_id: host_id.into(),
            boot_id: kernel.boot_id.clone(),
            pid_namespace_inode: kernel.pid_namespace_inode,
            uid: kernel.uid,
            pid: kernel.pid,
            start_ticks: kernel.start_ticks,
        }
    }

    /// Compares all kernel fields; process read errors never mean current.
    fn live(&self, host_id: &str) -> bool {
        self.host_id == host_id
            && os::attempt::kernel_incarnation(self.pid, self.uid)
                .is_ok_and(|actual| Self::new(host_id, &actual) == *self)
    }
}

/// Root actor fixed by the original native hook and its endpoint epoch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Actor {
    /// Canonical actual native address.
    address: String,
    /// Actor role; B1 only accepts `root`.
    role: String,
    /// Exact native session/actor identifier.
    native_id: String,
    /// Binding epoch when the hook fired.
    epoch: u64,
}

/// Original protected observation; not independently a Run admission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    /// Kernel identity sampled around direct launch environment access.
    incarnation: Incarnation,
    /// Run-generated launch correlation UUID.
    launch_id: String,
    /// Protected native actor and binding epoch.
    actor: Actor,
    /// Original per-call native identifier.
    native_call_id: String,
    /// Exact original hook tool name.
    tool_name: String,
    /// Hook observation time.
    observed_at_ms: u64,
    /// Original unrenewable observation expiry.
    expires_at_ms: u64,
}

/// Immutable durable consume receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    /// Original authenticated producer.
    producer: String,
    /// Original consume request identity.
    consume_request_id: String,
    /// Original invocation key.
    invocation_key: String,
    /// Full frontend/backend command security digest.
    security_digest: String,
    /// Original kernel/native observation.
    observation: Observation,
    /// Issuer epoch that captured the observation.
    issuer_epoch: String,
    /// First durable consume time.
    consumed_at_ms: u64,
}

/// Registered assertion fixed to one original observation and command.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    /// Protected key retained only while the original assertion can be current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assertion_key: Option<Secret>,
    /// SHA-256 index of the key, never used as the credential itself.
    assertion_hash: String,
    /// Exact command security digest.
    security_digest: String,
    /// Configured consumer audience.
    audience: String,
    /// Exact invocation nonce.
    nonce: String,
    /// Committed receipt, absent until consumed.
    receipt: Option<Receipt>,
}

/// Durable reservation and possible assertion, with original evidence only.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    /// Original authenticated producer.
    producer: String,
    /// Original invocation key, unique per producer.
    invocation_key: String,
    /// Opaque reference retained only while the original context can be current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context_ref: Option<Secret>,
    /// SHA-256 lookup key for the context reference.
    context_hash: String,
    /// Native command name from explicit configuration.
    command_name: String,
    /// Protected actual call observation.
    observation: Observation,
    /// Issuer epoch at capture.
    issuer_epoch: String,
    /// In-memory native source claim identity, never recreated after restart.
    claim_key: String,
    /// Registration when completed.
    registration: Option<Registration>,
    /// Expiry, abort or restart seals this original invocation forever.
    sealed: bool,
    /// The consumed association was explicitly aborted; its receipt survives.
    #[serde(default)]
    aborted: bool,
}

/// Durable abort fence, including fences installed before a consume existed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    /// Original producer.
    producer: String,
    /// Original consume request ID; absent for an expired reservation.
    consume_request_id: Option<String>,
    /// Permanently fenced invocation key.
    invocation_key: String,
    /// Original security digest when known.
    security_digest: Option<String>,
    /// Authenticated consumer audience when known.
    audience: Option<String>,
}

/// Permanent compact invocation/consume fence after evidence is no longer needed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    /// Hash of the authenticated producer and invocation key.
    invocation_hash: String,
    /// Full original source-use hash, retained after call-record eviction.
    #[serde(default)]
    source_hash: Option<String>,
    /// Hash of producer and consume request ID when one existed.
    consume_hash: Option<String>,
    /// Hash of the exact aborted intention when one existed.
    intention_hash: Option<String>,
    /// Consumer audience for authenticating abort/consume replay.
    audience: Option<String>,
    /// Whether the original intention was explicitly aborted.
    aborted: bool,
}

/// Durable, idempotent Run-attested namespace retirement receipt.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    /// Original producer identity.
    producer: String,
    /// Retired original issuer epoch.
    issuer_epoch: String,
    /// Unique Run-supplied retirement intention key.
    retirement_key: String,
    /// Number of records compacted by the first retirement.
    retired_count: u64,
}

/// Numbered bounded assertion/consume journal embedded in the atomic snapshot.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    /// Journal version, refusing unknown future formats.
    schema: u32,
    /// Reserved and registered original invocations.
    contexts: Vec<Context>,
    /// Permanent abort and expired-reservation fences.
    tombstones: Vec<Tombstone>,
    /// Permanent compact rejecting keys, never released by TTL.
    #[serde(default)]
    fences: Vec<Fence>,
    /// Immutable authenticated namespace-retirement receipts.
    #[serde(default)]
    retirements: Vec<Retirement>,
}

/// Separate managed journal, tied to the durable route-store identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LedgerFile {
    /// Numbered file format, independent of the route snapshot.
    schema: u32,
    /// Durable store identity this ledger belongs to.
    pub(super) store_id: String,
    /// Managed invocation ledger.
    pub(super) ledger: Ledger,
}

impl LedgerFile {
    /// Encodes one store-bound managed snapshot.
    fn encode(store_id: &str, ledger: &Ledger) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&Self {
            schema: 1,
            store_id: store_id.into(),
            ledger: ledger.clone(),
        })
        .map_err(|_| "attempt journal encoding failed".into())
    }

    /// Decodes and validates one numbered store-bound snapshot.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, String> {
        let file: Self = serde_json::from_slice(bytes).map_err(|_| "attempt journal malformed")?;
        if file.schema != 1 || !os::attempt::canonical_uuid(&file.store_id) {
            return Err("attempt journal version or store refused".into());
        }
        file.ledger.validate()?;
        Ok(file)
    }
}

impl std::fmt::Debug for Ledger {
    /// No secret, native, or invocation data is printed by registry diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger")
            .field("schema", &self.schema)
            .field("contexts", &self.contexts.len())
            .field("tombstones", &self.tombstones.len())
            .field("fences", &self.fences.len())
            .finish()
    }
}

impl Default for Ledger {
    /// An empty first-version consume journal.
    fn default() -> Self {
        Self {
            schema: 2,
            contexts: Vec::new(),
            tombstones: Vec::new(),
            fences: Vec::new(),
            retirements: Vec::new(),
        }
    }
}

/// Hard bound; neither a consume receipt nor a tombstone is evicted for capacity.
const MAX_RECORDS: usize = 8192;
/// Permanent compact keys remain bounded separately from live reservations.
const MAX_FENCES: usize = 65_536;

/// Read-only snapshot of managed journal fence and byte capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttemptCapacity {
    /// Number of compact permanent key fences in the snapshot.
    pub fence_count: usize,
    /// Remaining record slots after reserving space for outstanding work.
    pub fence_slots_remaining: usize,
    /// Hard count limit; the byte limit can be reached sooner.
    pub fence_slot_limit: usize,
    /// Current serialized journal size in bytes.
    pub journal_bytes: u64,
    /// Bytes reserved for outstanding contexts and aborts.
    pub reserved_bytes: u64,
    /// Remaining bytes after outstanding reservations; not a promise of admissions.
    pub journal_bytes_remaining: u64,
    /// Hard maximum serialized journal size in bytes.
    pub journal_byte_limit: u64,
}

/// Reads one bounded private managed-journal snapshot without changing it.
///
/// `channel` is the configured channel socket path and `owner` is the caller's
/// kernel-observed effective UID. Absence returns `None`; all values are a
/// momentary observation and neither capacity nor availability is guaranteed.
/// No stored keys, observations, payloads or file contents are returned.
///
/// # Errors
///
/// The journal is inaccessible, not private, unsupported or malformed.
pub fn inspect_attempt_capacity(
    channel: &Path,
    owner: u32,
) -> Result<Option<AttemptCapacity>, String> {
    let path = channel.with_extension("attempts.json");
    let Some(bytes) = read_private_journal(&path, owner)? else {
        return Ok(None);
    };
    let file = LedgerFile::decode(&bytes)?;
    let ledger = file.ledger;
    let used_slots = ledger
        .fences
        .len()
        .saturating_add(ledger.contexts.len())
        .saturating_add(ledger.tombstones.len())
        .saturating_add(ledger.retirements.len());
    let journal_bytes = bytes.len() as u64;
    let reserved_bytes = ledger.reserved_bytes();
    Ok(Some(AttemptCapacity {
        fence_count: ledger.fences.len(),
        fence_slots_remaining: MAX_FENCES.saturating_sub(used_slots),
        fence_slot_limit: MAX_FENCES,
        journal_bytes,
        reserved_bytes,
        journal_bytes_remaining: MAX_ROUTE_SNAPSHOT_BYTES
            .saturating_sub(journal_bytes.saturating_add(reserved_bytes)),
        journal_byte_limit: MAX_ROUTE_SNAPSHOT_BYTES,
    }))
}

/// Hashes structured fence fields with an explicit domain separator.
fn fence_hash<T: Serialize>(domain: &str, fields: T) -> String {
    crate::server::sha256_hex(
        &serde_json::to_vec(&(domain, fields)).expect("bounded fence fields serialize"),
    )
}

/// Derives the permanent producer/invocation key fence.
fn invocation_fence(producer: &str, invocation: &str) -> String {
    fence_hash("invocation-v1", (producer, invocation))
}

/// Derives the permanent producer/consume-request key fence.
fn consume_fence(producer: &str, request: &str) -> String {
    fence_hash("consume-v1", (producer, request))
}

/// Derives a fixed-size permanent fence for the original source-use key.
fn source_fence(source: &str) -> String {
    fence_hash("source-v1", source)
}

/// Stable native source identity independent of issuer and binding epochs.
fn managed_source_key(observation: &Observation) -> String {
    fence_hash(
        "managed-source-v1",
        (
            &observation.incarnation,
            &observation.native_call_id,
            &observation.actor.address,
            &observation.actor.native_id,
        ),
    )
}

/// Derives the exact consumer abort intention for compact replay.
fn abort_fence(
    producer: &str,
    request: &str,
    invocation: &str,
    digest: &str,
    audience: &str,
) -> String {
    fence_hash(
        "abort-v1",
        (producer, request, invocation, digest, audience),
    )
}

impl Ledger {
    /// Finds a permanent key fence without trusting caller labels as authority.
    fn find_fence(
        &self,
        producer: &str,
        invocation: &str,
        request: Option<&str>,
    ) -> Option<&Fence> {
        let invocation_hash = invocation_fence(producer, invocation);
        let request_hash = request.map(|request| consume_fence(producer, request));
        self.fences.iter().find(|fence| {
            fence.invocation_hash == invocation_hash
                || request_hash
                    .as_ref()
                    .is_some_and(|hash| fence.consume_hash.as_ref() == Some(hash))
        })
    }

    /// Reserves one future permanent key fence for every outstanding context.
    fn fence_capacity(&self) -> bool {
        self.fences
            .len()
            .saturating_add(self.contexts.len())
            .saturating_add(self.tombstones.len())
            .saturating_add(self.retirements.len())
            < MAX_FENCES
    }
    /// Validates the numbered representation and all retained identity uniqueness.
    pub(super) fn validate(&self) -> Result<(), String> {
        if !(1..=2).contains(&self.schema)
            || self.reserved_slots() > MAX_RECORDS
            || self
                .fences
                .len()
                .saturating_add(self.retirements.len())
                .saturating_add(self.contexts.len())
                .saturating_add(self.tombstones.len())
                > MAX_FENCES
        {
            return Err("attempt journal version or count refused".into());
        }
        let valid_id = |value: &str| {
            bridge_protocol::validate_id("journal_id", value, bridge_protocol::MAX_ID_BYTES).is_ok()
        };
        let valid_hash = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        let mut invocations = std::collections::HashSet::new();
        let mut refs = std::collections::HashSet::new();
        let mut assertions = std::collections::HashSet::new();
        let mut consumes = std::collections::HashSet::new();
        let mut active_sources = std::collections::HashSet::new();
        for context in &self.contexts {
            let observation = &context.observation;
            let native = &observation.incarnation;
            let address = NativeAddress::parse(&observation.actor.address).ok();
            if ![
                context.producer.as_str(),
                context.invocation_key.as_str(),
                context.command_name.as_str(),
                context.issuer_epoch.as_str(),
                context.claim_key.as_str(),
                observation.native_call_id.as_str(),
                observation.tool_name.as_str(),
                native.host_id.as_str(),
                observation.actor.native_id.as_str(),
            ]
            .iter()
            .all(|value| valid_id(value))
                || context
                    .context_ref
                    .as_ref()
                    .is_some_and(|key| !valid_hash(key.expose()))
                || !valid_hash(&context.context_hash)
                || (!context.sealed && context.context_ref.is_none())
                || !os::attempt::canonical_uuid(&native.boot_id)
                || !os::attempt::canonical_uuid(&observation.launch_id)
                || native.pid == 0
                || native.start_ticks == 0
                || native.pid_namespace_inode == 0
                || observation.actor.role != "root"
                || observation.actor.epoch == 0
                || address.as_ref().is_none_or(|value| {
                    value.host_id != native.host_id
                        || value.native_session_id != observation.actor.native_id
                })
                || observation.observed_at_ms == 0
                || observation.expires_at_ms <= observation.observed_at_ms
                || (context.aborted
                    && (!context.sealed
                        || context
                            .registration
                            .as_ref()
                            .and_then(|registration| registration.receipt.as_ref())
                            .is_none()))
                || !invocations.insert((&context.producer, &context.invocation_key))
                || (self.schema >= 2 && context.claim_key != managed_source_key(observation))
                || !active_sources.insert(source_fence(&context.claim_key))
                || !refs.insert(&context.context_hash)
                || context.context_ref.as_ref().is_some_and(|key| {
                    context.context_hash != crate::server::sha256_hex(key.expose().as_bytes())
                })
            {
                return Err("attempt journal identity refused".into());
            }
            if let Some(registration) = &context.registration {
                if registration
                    .assertion_key
                    .as_ref()
                    .is_some_and(|key| !valid_hash(key.expose()))
                    || !valid_hash(&registration.assertion_hash)
                    || (!context.sealed && registration.assertion_key.is_none())
                    || !valid_hash(&registration.security_digest)
                    || !valid_id(&registration.audience)
                    || !valid_id(&registration.nonce)
                    || registration.assertion_key.as_ref().is_some_and(|key| {
                        registration.assertion_hash
                            != crate::server::sha256_hex(key.expose().as_bytes())
                    })
                    || !assertions.insert(&registration.assertion_hash)
                {
                    return Err("attempt journal assertion refused".into());
                }
                if let Some(receipt) = &registration.receipt
                    && (!valid_id(&receipt.consume_request_id)
                        || receipt.producer != context.producer
                        || receipt.invocation_key != context.invocation_key
                        || receipt.security_digest != registration.security_digest
                        || receipt.observation != *observation
                        || receipt.issuer_epoch != context.issuer_epoch
                        || receipt.consumed_at_ms < observation.observed_at_ms
                        || receipt.consumed_at_ms >= observation.expires_at_ms
                        || !consumes.insert((&receipt.producer, &receipt.consume_request_id)))
                {
                    return Err("attempt journal receipt refused".into());
                }
            }
        }
        let mut tombstone_ids = std::collections::HashSet::new();
        let mut tombstone_invocations = std::collections::HashSet::new();
        for tombstone in &self.tombstones {
            if !valid_id(&tombstone.producer)
                || !valid_id(&tombstone.invocation_key)
                || !tombstone_invocations.insert((&tombstone.producer, &tombstone.invocation_key))
                || tombstone.consume_request_id.as_ref().is_none_or(|id| {
                    !valid_id(id) || !tombstone_ids.insert((&tombstone.producer, id))
                })
                || tombstone
                    .security_digest
                    .as_ref()
                    .is_none_or(|digest| !valid_hash(digest))
                || tombstone
                    .audience
                    .as_ref()
                    .is_none_or(|audience| !valid_id(audience))
            {
                return Err("attempt journal tombstone refused".into());
            }
            if let Some(id) = &tombstone.consume_request_id
                && consumes.contains(&(&tombstone.producer, id))
                && !self.contexts.iter().any(|context| {
                    context.producer == tombstone.producer
                        && context.invocation_key == tombstone.invocation_key
                        && context
                            .registration
                            .as_ref()
                            .and_then(|registration| registration.receipt.as_ref())
                            .is_some_and(|receipt| &receipt.consume_request_id == id)
                })
            {
                return Err("attempt journal consume identity conflict".into());
            }
            if let Some(context) = self.contexts.iter().find(|context| {
                context.producer == tombstone.producer
                    && context.invocation_key == tombstone.invocation_key
            }) && (!context.sealed
                || context.registration.as_ref().is_some_and(|registration| {
                    Some(&registration.security_digest) != tombstone.security_digest.as_ref()
                        || Some(&registration.audience) != tombstone.audience.as_ref()
                        || registration.receipt.as_ref().is_some_and(|receipt| {
                            Some(&receipt.consume_request_id)
                                != tombstone.consume_request_id.as_ref()
                        })
                }))
            {
                return Err("attempt journal tombstone association refused".into());
            }
        }
        let mut fences = std::collections::HashSet::new();
        let mut consumed = std::collections::HashSet::new();
        let mut sources = std::collections::HashSet::new();
        let active_invocations: std::collections::HashSet<String> =
            self.contexts
                .iter()
                .map(|context| invocation_fence(&context.producer, &context.invocation_key))
                .chain(self.tombstones.iter().map(|tombstone| {
                    invocation_fence(&tombstone.producer, &tombstone.invocation_key)
                }))
                .collect();
        let active_consumes: std::collections::HashSet<String> = self
            .contexts
            .iter()
            .filter_map(|context| {
                context
                    .registration
                    .as_ref()
                    .and_then(|registration| registration.receipt.as_ref())
            })
            .map(|receipt| consume_fence(&receipt.producer, &receipt.consume_request_id))
            .chain(self.tombstones.iter().filter_map(|tombstone| {
                tombstone
                    .consume_request_id
                    .as_ref()
                    .map(|request| consume_fence(&tombstone.producer, request))
            }))
            .collect();
        for fence in &self.fences {
            if !valid_hash(&fence.invocation_hash)
                || !fences.insert(&fence.invocation_hash)
                || fence
                    .source_hash
                    .as_ref()
                    .is_some_and(|value| !valid_hash(value) || !sources.insert(value))
                || fence
                    .consume_hash
                    .as_ref()
                    .is_some_and(|value| !valid_hash(value) || !consumed.insert(value))
                || fence
                    .intention_hash
                    .as_ref()
                    .is_some_and(|value| !valid_hash(value))
                || fence
                    .audience
                    .as_ref()
                    .is_some_and(|value| !valid_id(value))
                || (fence.aborted
                    && (fence.consume_hash.is_none()
                        || fence.intention_hash.is_none()
                        || fence.audience.is_none()))
            {
                return Err("attempt journal fence refused".into());
            }
            if active_invocations.contains(&fence.invocation_hash) {
                return Err("attempt journal fence overlaps live state".into());
            }
            if fence
                .source_hash
                .as_ref()
                .is_some_and(|hash| active_sources.contains(hash))
            {
                return Err("attempt journal source fence overlaps live state".into());
            }
            if fence
                .consume_hash
                .as_ref()
                .is_some_and(|hash| active_consumes.contains(hash))
            {
                return Err("attempt journal consume fence overlaps live state".into());
            }
        }
        let mut retirement_keys = std::collections::HashSet::new();
        let mut retired_namespaces = std::collections::HashSet::new();
        for retirement in &self.retirements {
            if !valid_id(&retirement.producer)
                || !valid_id(&retirement.issuer_epoch)
                || !valid_id(&retirement.retirement_key)
                || !retirement_keys.insert(&retirement.retirement_key)
                || !retired_namespaces.insert((&retirement.producer, &retirement.issuer_epoch))
            {
                return Err("attempt journal retirement refused".into());
            }
        }
        Ok(())
    }

    /// Counts one context plus its reserved future abort slot; unrelated
    /// pre-consume tombstones consume their own permanent slots.
    fn reserved_slots(&self) -> usize {
        let contexts: std::collections::HashSet<_> = self
            .contexts
            .iter()
            .map(|context| (&context.producer, &context.invocation_key))
            .collect();
        let tombstones: std::collections::HashSet<_> = self
            .tombstones
            .iter()
            .map(|tombstone| (&tombstone.producer, &tombstone.invocation_key))
            .collect();
        let pending_abort = self
            .contexts
            .iter()
            .filter(|context| {
                !context.sealed
                    && !tombstones.contains(&(&context.producer, &context.invocation_key))
            })
            .count();
        self.contexts
            .len()
            .saturating_add(pending_abort)
            .saturating_add(
                self.tombstones
                    .iter()
                    .filter(|tombstone| {
                        !contexts.contains(&(&tombstone.producer, &tombstone.invocation_key))
                    })
                    .count(),
            )
    }

    /// Reserves bounded bytes for each context's remaining registration,
    /// consume receipt and abort before any unrelated route write can fill them.
    pub(super) fn reserved_bytes(&self) -> u64 {
        let aborted: std::collections::HashSet<_> = self
            .tombstones
            .iter()
            .map(|tombstone| (&tombstone.producer, &tombstone.invocation_key))
            .collect();
        self.contexts.iter().fold(0_u64, |total, context| {
            let mut reserved = 0_u64;
            if !context.sealed && context.registration.is_none() {
                reserved += 4096;
            }
            if !context.sealed
                && context
                    .registration
                    .as_ref()
                    .is_none_or(|registration| registration.receipt.is_none())
            {
                let observation_len = serde_json::to_vec(&context.observation)
                    .map_or(MAX_ROUTE_SNAPSHOT_BYTES, |bytes| bytes.len() as u64);
                reserved = reserved
                    .saturating_add(observation_len)
                    .saturating_add(4096);
            }
            if !context.sealed && !aborted.contains(&(&context.producer, &context.invocation_key)) {
                reserved += 4096;
            }
            total.saturating_add(reserved)
        })
    }

    /// Seals unregistered original calls whose bounded observation has expired.
    /// The retained context is itself a permanent invocation tombstone.
    fn expire(&mut self, now_ms: u64) -> (Vec<String>, bool) {
        let mut changed = false;
        let released = self
            .contexts
            .iter_mut()
            .filter_map(|c| {
                if !c.sealed && c.observation.expires_at_ms <= now_ms {
                    changed = true;
                    c.sealed = true;
                    c.context_ref = None;
                    if let Some(registration) = &mut c.registration {
                        registration.assertion_key = None;
                    }
                    c.registration.is_none().then(|| c.claim_key.clone())
                } else {
                    None
                }
            })
            .collect();
        (released, changed)
    }

    /// A previous issuer's original evidence cannot become fresh after restart.
    pub(super) fn seal_after_restart(&mut self, issuer: &str) {
        if self.schema == 1 {
            // Rebuild only from the already preserved full original observation.
            for context in &mut self.contexts {
                context.claim_key = managed_source_key(&context.observation);
            }
        }
        self.schema = 2;
        for context in &mut self.contexts {
            if context.issuer_epoch != issuer {
                context.sealed = true;
                context.context_ref = None;
                if let Some(registration) = &mut context.registration {
                    registration.assertion_key = None;
                }
            }
        }
        self.compact(issuer);
    }

    /// Compacts sealed unregistered, aborted-unconsumed and older unconsumed
    /// contexts; consumed receipts remain until authenticated retirement.
    fn compact(&mut self, issuer: &str) {
        let mut remove = std::collections::HashSet::new();
        let mut removed_sources = std::collections::HashMap::new();
        let aborted_keys: std::collections::HashSet<_> = self
            .tombstones
            .iter()
            .map(|tombstone| (&tombstone.producer, &tombstone.invocation_key))
            .collect();
        let mut existing: std::collections::HashSet<String> = self
            .fences
            .iter()
            .map(|fence| fence.invocation_hash.clone())
            .collect();
        for context in &self.contexts {
            let has_receipt = context
                .registration
                .as_ref()
                .is_some_and(|r| r.receipt.is_some());
            let aborted = aborted_keys.contains(&(&context.producer, &context.invocation_key));
            if context.sealed
                && !has_receipt
                && (context.registration.is_none() || context.issuer_epoch != issuer || aborted)
            {
                let invocation_hash = invocation_fence(&context.producer, &context.invocation_key);
                removed_sources.insert(invocation_hash.clone(), source_fence(&context.claim_key));
                if !aborted && existing.insert(invocation_hash.clone()) {
                    self.fences.push(Fence {
                        invocation_hash,
                        source_hash: Some(source_fence(&context.claim_key)),
                        consume_hash: None,
                        intention_hash: None,
                        audience: None,
                        aborted: false,
                    });
                }
                remove.insert((context.producer.clone(), context.invocation_key.clone()));
            }
        }
        self.contexts.retain(|context| {
            !remove.contains(&(context.producer.clone(), context.invocation_key.clone()))
        });
        let retained_receipts: std::collections::HashSet<_> = self
            .contexts
            .iter()
            .filter(|context| {
                context
                    .registration
                    .as_ref()
                    .is_some_and(|registration| registration.receipt.is_some())
            })
            .map(|context| (context.producer.clone(), context.invocation_key.clone()))
            .collect();
        let mut retain = Vec::new();
        for tombstone in self.tombstones.drain(..) {
            if retained_receipts
                .contains(&(tombstone.producer.clone(), tombstone.invocation_key.clone()))
            {
                retain.push(tombstone);
                continue;
            }
            if let (Some(request), Some(digest), Some(audience)) = (
                &tombstone.consume_request_id,
                &tombstone.security_digest,
                &tombstone.audience,
            ) {
                let invocation_hash =
                    invocation_fence(&tombstone.producer, &tombstone.invocation_key);
                if existing.contains(&invocation_hash) {
                    self.fences
                        .retain(|fence| fence.invocation_hash != invocation_hash);
                }
                existing.insert(invocation_hash.clone());
                let source_hash = removed_sources.remove(&invocation_hash);
                self.fences.push(Fence {
                    invocation_hash,
                    source_hash,
                    consume_hash: Some(consume_fence(&tombstone.producer, request)),
                    intention_hash: Some(abort_fence(
                        &tombstone.producer,
                        request,
                        &tombstone.invocation_key,
                        digest,
                        audience,
                    )),
                    audience: Some(audience.clone()),
                    aborted: true,
                });
            } else {
                retain.push(tombstone);
            }
        }
        self.tombstones = retain;
    }
}

/// Random secret for one protected local exchange.
fn random_secret() -> Result<Secret, CorrelationError> {
    Ok(Secret::new(
        os::random_bytes()
            .map_err(|_| CorrelationError::Unavailable("entropy unavailable".into()))?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    ))
}

/// Exact configured native host tool mapping, never prefix-only matching.
fn tool_matches(mapping: &ManagedTools, producer: &str, command: &str, tool: &str) -> bool {
    mapping.producer == producer
        && mapping.commands.iter().any(|allowed| allowed == command)
        && tool == format!("mcp__{}__{command}", mapping.server)
}

impl Registry {
    /// Periodic maintenance scrubs expired protected keys even while idle.
    pub(crate) fn maintain_attempts(&mut self, now_ms: u64) {
        let _ = self.expire_attempt_contexts(now_ms);
    }

    /// Fences all further B1 work after an uncertain commit while releasing
    /// legacy call capacity without making the observed calls reusable.
    fn poison_attempt_commit(&mut self) {
        self.attempt_journal_poisoned = true;
        self.attempt_journal_uncertain = true;
        #[cfg(target_os = "linux")]
        let claims: Vec<String> = self
            .claims
            .iter()
            .filter(|(_, claim)| matches!(claim.source, claims::ClaimSource::ManagedNative { .. }))
            .map(|(key, _)| key.clone())
            .collect();
        #[cfg(not(target_os = "linux"))]
        let claims: Vec<String> = Vec::new();
        for claim in claims {
            self.finalize_claim(&claim);
        }
    }

    /// Requires the complete managed configuration for the target producer.
    fn managed_configured(&self, producer: &str) -> ResultV1<()> {
        if self
            .config
            .managed_tools
            .iter()
            .any(|entry| entry.producer == producer)
            && self
                .config
                .run_readers
                .iter()
                .any(|entry| entry.producer == producer)
            && self
                .config
                .audiences
                .iter()
                .any(|entry| entry.producer == producer)
        {
            Ok(())
        } else {
            Err(AttemptError::new("capability_missing", "none"))
        }
    }
    /// Ensures expired unregistered claims become durable fences before eviction.
    pub(super) fn expire_attempt_contexts(&mut self, now_ms: u64) -> Result<(), CorrelationError> {
        if self.attempt_journal_poisoned {
            return Ok(());
        }
        let (released, changed) = self.attempt_ledger.expire(now_ms);
        if changed {
            self.attempt_ledger.compact(&self.issuer_boot);
            if self.persist_attempt().is_err() {
                self.poison_attempt_commit();
                return Ok(());
            }
            for claim in released {
                self.release_claim(&claim);
            }
        }
        Ok(())
    }
}

/// Bounded, content-free managed operation refusal.
#[derive(Clone, Copy)]
pub(crate) struct AttemptError {
    /// Stable protocol code, never an input value.
    pub(crate) code: &'static str,
    /// Required recovery class.
    pub(crate) recovery: &'static str,
}

impl AttemptError {
    /// Creates one static refusal.
    fn new(code: &'static str, recovery: &'static str) -> Self {
        Self { code, recovery }
    }
}

/// Managed operation outcome before response-envelope encoding.
pub(crate) type ResultV1<T> = Result<T, AttemptError>;

/// Converts original-source refusal to a bounded managed error.
fn source_error(_: CorrelationError) -> AttemptError {
    AttemptError::new("binding_unavailable", "fresh_invocation")
}

impl Registry {
    /// Authenticates a managed producer audience and resolves one pinned route.
    pub(crate) fn owner_v2_route(
        &mut self,
        expected_store: &str,
        peer: PeerIdentity,
        producer: &str,
        audience: &str,
        allowed: &[String],
        intent: &bridge_protocol::managed_owner::OutboxIntentV1,
    ) -> ResultV1<ManagedOwnerRoute> {
        self.owner_v2_access(
            expected_store,
            peer,
            producer,
            audience,
            allowed,
            &intent.producer_scope,
        )?;
        if intent.bridge_route.component_store_id != self.store_id
            || intent.bridge_route.worker_uid != self.owner_uid
        {
            return Err(AttemptError::new("route_mismatch", "none"));
        }
        let mut routes = self.config.owner_v2_routes.iter().filter(|route| {
            route.producer == producer
                && route.audience == audience
                && route.permits_scope(&intent.producer_scope)
                && route.run_route == intent.target_binding.run_route
                && route.pool_route.component_store_id == intent.target_binding.pool_store_id
                && route.bridge_route == intent.bridge_route
        });
        let Some(route) = routes.next() else {
            return Err(AttemptError::new("capability_missing", "none"));
        };
        if routes.next().is_some() {
            return Err(AttemptError::new("route_mismatch", "none"));
        }
        Ok(route.clone())
    }

    /// Authenticates the same producer audience for durable effect lookup.
    pub(crate) fn owner_v2_access(
        &mut self,
        expected_store: &str,
        peer: PeerIdentity,
        producer: &str,
        audience: &str,
        allowed: &[String],
        scope: &str,
    ) -> ResultV1<()> {
        // Managed-owner custody lives in the core store. A damaged B1 consume
        // ledger must not hide an already recorded owner outcome.
        if self.journal.is_none() || expected_store != self.store_id {
            return Err(AttemptError::new("recovery_required", "operator"));
        }
        self.managed_configured(producer)?;
        self.verify_attempt_consumer(peer, producer, audience, allowed)?;
        if !self.config.owner_v2_routes.iter().any(|route| {
            route.producer == producer && route.audience == audience && route.permits_scope(scope)
        }) {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        Ok(())
    }

    /// Proves the connected Run server's same-UID, loaded executable identity.
    pub(crate) fn verify_owner_v2_run_peer(
        &self,
        peer: PeerIdentity,
        route: &ManagedOwnerRoute,
    ) -> ResultV1<()> {
        let unavailable = || AttemptError::new("peer_not_authorized", "none");
        if peer.uid != self.owner_uid {
            return Err(unavailable());
        }
        let before =
            os::attempt::kernel_incarnation(peer.pid, peer.uid).map_err(|_| unavailable())?;
        let facts = os::process_facts(peer.pid).ok_or_else(unavailable)?;
        if facts.uid != Some(peer.uid)
            || facts.exe.as_ref() != Some(&route.run_executable.path)
            || self
                .verify_loaded(
                    &route.run_executable.path,
                    facts.start_time,
                    &route.run_executable.sha256,
                )
                .is_err()
            || os::attempt::kernel_incarnation(peer.pid, peer.uid)
                .ok()
                .as_ref()
                != Some(&before)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Rechecks one exact live root binding and its original launch capture.
    #[cfg(target_os = "linux")]
    pub(crate) fn owner_v2_target_current(
        &self,
        intent: &bridge_protocol::managed_owner::OutboxIntentV1,
    ) -> bool {
        let identity = &intent.expected_incarnation;
        if self.root_capture_poisoned
            || identity.host_id != self.config.host_id
            || identity.uid != self.owner_uid
        {
            return false;
        }
        let expected = os::attempt::KernelIncarnation {
            boot_id: identity.boot_id.clone(),
            pid_namespace_inode: identity.pid_namespace_inode,
            uid: identity.uid,
            pid: identity.pid,
            start_ticks: identity.start_ticks,
        };
        if !os::attempt::kernel_incarnation(expected.pid, expected.uid)
            .is_ok_and(|actual| actual == expected)
        {
            return false;
        }
        if self
            .root_launches
            .iter()
            .filter(|(address, root)| {
                root.incarnation == expected
                    && self
                        .bindings
                        .get(*address)
                        .is_none_or(|binding| !binding.retired)
            })
            .count()
            != 1
        {
            return false;
        }
        let roots: Vec<_> = self
            .root_launches
            .iter()
            .filter_map(|(address, capture)| {
                let binding = self.bindings.get(address)?;
                (capture.armed
                    && capture.incarnation == expected
                    && !binding.retired
                    && binding.epoch == capture.epoch
                    && binding.managed_incarnation.as_ref() == Some(&expected))
                .then_some((binding, capture))
            })
            .collect();
        let [(binding, capture)] = roots.as_slice() else {
            return false;
        };
        let actor = &intent.target_binding.actor;
        capture.observation.as_ref().is_some_and(|observation| {
            observation.launch_id == intent.target_binding.attempt.launch_id
        }) && binding.address.to_canonical_string() == actor.address
            && binding.address.native_session_id == actor.native_id
            && binding.epoch == actor.epoch
            && os::process_facts(expected.pid).is_some_and(|facts| {
                facts.uid == Some(expected.uid)
                    && facts.exe.as_ref() == Some(&binding.executable)
                    && executable_current(&binding.executable, &facts, expected.uid).is_ok()
            })
            && os::attempt::kernel_incarnation(expected.pid, expected.uid)
                .is_ok_and(|actual| actual == expected)
    }

    /// Unsupported hosts cannot establish a managed owner target.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn owner_v2_target_current(
        &self,
        _: &bridge_protocol::managed_owner::OutboxIntentV1,
    ) -> bool {
        false
    }

    /// Reads a Run reader's exact original root actor. Live authority requires a
    /// unique first-hook capture and equal full kernel reads around the binding.
    #[cfg(target_os = "linux")]
    pub(crate) fn run_actor_lookup(
        &mut self,
        peer: PeerIdentity,
        reader: &str,
        query: &bridge_protocol::managed_owner::RunActorLookupParamsV1,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(&query.expected_store_id)?;
        self.managed_configured(&query.producer)?;
        self.verify_run_reader(peer, reader, &query.producer)?;
        let requested = &query.incarnation;
        let result = |state: &str, actor: Option<Actor>, issuer: Option<&str>| {
            serde_json::json!({"version":1,"store_id":self.store_id,"producer":query.producer,
                "incarnation":requested,"launch_id":query.launch_id,"state":state,
                "actor":actor,"issuer_epoch":issuer})
        };
        if self.root_capture_poisoned
            || requested.host_id != self.config.host_id
            || requested.uid != self.owner_uid
        {
            return Ok(result("unavailable", None, None));
        }
        let expected = os::attempt::KernelIncarnation {
            boot_id: requested.boot_id.clone(),
            pid_namespace_inode: requested.pid_namespace_inode,
            uid: requested.uid,
            pid: requested.pid,
            start_ticks: requested.start_ticks,
        };
        let live_before = os::attempt::kernel_incarnation(expected.pid, expected.uid)
            .is_ok_and(|actual| actual == expected);
        if self
            .root_launches
            .iter()
            .filter(|(address, root)| {
                root.incarnation == expected
                    && self
                        .bindings
                        .get(*address)
                        .is_none_or(|binding| !binding.retired)
            })
            .count()
            > 1
        {
            return Ok(result("unavailable", None, None));
        }
        let roots: Vec<_> = self
            .root_launches
            .iter()
            .filter_map(|(address, capture)| {
                let binding = self.bindings.get(address)?;
                (capture.armed
                    && capture.incarnation == expected
                    && !binding.retired
                    && binding.managed_incarnation.as_ref() == Some(&expected)
                    && binding.epoch == capture.epoch)
                    .then_some((binding, capture))
            })
            .collect();
        if live_before && roots.len() == 1 {
            let (binding, capture) = roots[0];
            if capture
                .observation
                .as_ref()
                .is_some_and(|observed| observed.launch_id == query.launch_id)
                && os::process_facts(expected.pid).is_some_and(|facts| {
                    facts.uid == Some(expected.uid)
                        && facts.exe.as_ref() == Some(&binding.executable)
                        && executable_current(&binding.executable, &facts, expected.uid).is_ok()
                })
                && os::attempt::kernel_incarnation(expected.pid, expected.uid)
                    .is_ok_and(|actual| actual == expected)
            {
                let actor = Actor {
                    address: binding.address.to_canonical_string(),
                    role: "root".into(),
                    native_id: binding.address.native_session_id.clone(),
                    epoch: binding.epoch,
                };
                return Ok(result("current", Some(actor), Some(&self.issuer_boot)));
            }
            return Ok(result("unavailable", None, None));
        }
        if live_before && roots.len() > 1 {
            return Ok(result("unavailable", None, None));
        }
        let mut historical = self.attempt_ledger.contexts.iter().filter(|context| {
            context.producer == query.producer
                && context.observation.launch_id == query.launch_id
                && context.observation.incarnation
                    == Incarnation::new(&self.config.host_id, &expected)
        });
        if let Some(first) = historical.next()
            && historical.all(|other| {
                other.observation.actor == first.observation.actor
                    && other.issuer_epoch == first.issuer_epoch
            })
        {
            return Ok(result(
                "historical",
                Some(first.observation.actor.clone()),
                Some(&first.issuer_epoch),
            ));
        }
        Ok(result("unavailable", None, None))
    }

    /// Reports whether an exact captured root can re-arm or needs relaunch.
    #[cfg(target_os = "linux")]
    pub(crate) fn run_actor_recovery_status(
        &mut self,
        peer: PeerIdentity,
        reader: &str,
        query: &bridge_protocol::managed_owner::RunActorLookupParamsV1,
    ) -> ResultV1<serde_json::Value> {
        let observed = self.run_actor_lookup(peer, reader, query)?;
        let requested = &query.incarnation;
        let expected = os::attempt::KernelIncarnation {
            boot_id: requested.boot_id.clone(),
            pid_namespace_inode: requested.pid_namespace_inode,
            uid: requested.uid,
            pid: requested.pid,
            start_ticks: requested.start_ticks,
        };
        let state = if observed["state"] == "current" {
            "current"
        } else if self.root_capture_poisoned
            || requested.host_id != self.config.host_id
            || requested.uid != self.owner_uid
            || !os::attempt::kernel_incarnation(expected.pid, expected.uid)
                .is_ok_and(|actual| actual == expected)
        {
            "unavailable"
        } else {
            let matching: Vec<_> = self
                .root_launches
                .iter()
                .filter(|(address, root)| {
                    root.incarnation == expected
                        && self
                            .bindings
                            .get(*address)
                            .is_none_or(|binding| !binding.retired)
                })
                .collect();
            if matching.len() > 1 {
                "unavailable"
            } else if let Some((address, root)) = matching.first() {
                if root
                    .observation
                    .as_ref()
                    .is_some_and(|observation| observation.launch_id == query.launch_id)
                    && self.bindings.get(*address).is_some_and(|binding| {
                        !binding.retired
                            && binding.epoch == root.epoch
                            && binding.managed_incarnation.as_ref() == Some(&expected)
                    })
                {
                    "awaiting_root_hook"
                } else {
                    "relaunch_required"
                }
            } else if !self
                .bindings
                .values()
                .any(|binding| binding.managed_incarnation.as_ref() == Some(&expected))
                && root_started_after_issuer(self.issuer_process_incarnation.as_ref(), &expected)
            {
                "awaiting_root_hook"
            } else {
                "relaunch_required"
            }
        };
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"producer":query.producer,
            "incarnation":requested,"launch_id":query.launch_id,"state":state}),
        )
    }

    /// Unsupported hosts cannot establish managed actor recovery readiness.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn run_actor_recovery_status(
        &mut self,
        _: PeerIdentity,
        _: &str,
        _: &bridge_protocol::managed_owner::RunActorLookupParamsV1,
    ) -> ResultV1<serde_json::Value> {
        Err(AttemptError::new("transport_unsupported", "none"))
    }

    /// Unsupported platforms cannot prove a managed root launch.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn run_actor_lookup(
        &mut self,
        _: PeerIdentity,
        _: &str,
        _: &bridge_protocol::managed_owner::RunActorLookupParamsV1,
    ) -> ResultV1<serde_json::Value> {
        Err(AttemptError::new("transport_unsupported", "none"))
    }

    /// Returns the private route store identity for a bounded error envelope.
    pub(crate) fn attempt_store_id(&self) -> String {
        self.store_id.clone()
    }

    /// Advertises the durable store only on an initialized same-UID route.
    pub(crate) fn attempt_capabilities(
        &mut self,
        peer: PeerIdentity,
        principal: &str,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(&self.store_id)?;
        if peer.uid != self.owner_uid {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        let reader_source = self
            .config
            .run_readers
            .iter()
            .find(|reader| {
                reader.reader == principal
                    && self
                        .config
                        .managed_tools
                        .iter()
                        .any(|tool| tool.producer == reader.producer)
                    && self
                        .config
                        .audiences
                        .iter()
                        .any(|audience| audience.producer == reader.producer)
            })
            .map(|reader| reader.producer.clone());
        let source = if self
            .config
            .managed_tools
            .iter()
            .any(|tool| tool.producer == principal)
        {
            self.verify_discovery_principal(peer, principal)?;
            principal.to_string()
        } else if let Some(source) = reader_source {
            self.verify_run_reader(peer, principal, &source)?;
            source
        } else if let Some(source) = self
            .config
            .run_readers
            .iter()
            .find(|reader| reader.reader == principal)
            .map(|reader| reader.producer.clone())
        {
            self.verify_run_reader(peer, principal, &source)?;
            return Err(AttemptError::new("capability_missing", "none"));
        } else {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        };
        if !self
            .config
            .managed_tools
            .iter()
            .any(|tool| tool.producer == source)
            || !self
                .config
                .run_readers
                .iter()
                .any(|reader| reader.producer == source)
            || !self
                .config
                .audiences
                .iter()
                .any(|audience| audience.producer == source)
        {
            return Err(AttemptError::new("capability_missing", "none"));
        }
        #[cfg(target_os = "linux")]
        self.ensure_frontend_roles()?;
        let mut capabilities = vec![
            "attempt_launch_v1",
            "launch_assertion_v1",
            "namespace_retirement_v1",
        ];
        if cfg!(target_os = "linux") {
            capabilities.push("run_actor_lookup_v1");
            capabilities.push("run_actor_recovery_status_v1");
            if self.config.owner_v2_routes.iter().any(|route| {
                route.producer == source
                    && route.bridge_route.component_store_id == self.store_id
                    && file_key(&route.run_executable.path)
                        .and_then(|key| self.digests.get(&key))
                        .is_some_and(|digest| digest == &route.run_executable.sha256)
            }) {
                capabilities.push("managed_owner_v2");
            }
        }
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"capabilities":capabilities,"issuer_epoch":self.issuer_boot}),
        )
    }

    /// Refuses missing durable storage, poisoned state or a different store.
    fn attempt_store(&self, expected: &str) -> ResultV1<()> {
        if self.journal.is_none() || self.attempt_journal.is_none() || expected != self.store_id {
            Err(AttemptError::new("recovery_required", "operator"))
        } else if self.attempt_journal_poisoned {
            Err(AttemptError::new(
                "recovery_required",
                if self.attempt_journal_uncertain {
                    "same_key_lookup"
                } else {
                    "operator"
                },
            ))
        } else {
            Ok(())
        }
    }

    /// Checks journal capacity without I/O so a new reservation can refuse
    /// before claiming an unrecoverable amount of space.
    fn attempt_snapshot_fits(&self) -> bool {
        LedgerFile::encode(&self.store_id, &self.attempt_ledger).is_ok_and(|bytes| {
            (bytes.len() as u64).saturating_add(self.attempt_ledger.reserved_bytes())
                <= MAX_ROUTE_SNAPSHOT_BYTES
        })
    }

    /// Syncs the complete snapshot before acknowledgement; uncertain failure
    /// fences all later journal writes until a restart reloads durable bytes.
    fn commit_attempt(&mut self) -> ResultV1<()> {
        if self.persist_attempt().is_err() {
            self.poison_attempt_commit();
            Err(AttemptError::new("recovery_required", "same_key_lookup"))
        } else {
            Ok(())
        }
    }

    /// Commits only managed evidence; route writes remain independent.
    pub(super) fn persist_attempt(&self) -> Result<(), String> {
        let path = self
            .attempt_journal
            .as_ref()
            .ok_or("attempt journal unattached")?;
        self.attempt_ledger.validate()?;
        let bytes = LedgerFile::encode(&self.store_id, &self.attempt_ledger)?;
        if (bytes.len() as u64).saturating_add(self.attempt_ledger.reserved_bytes())
            > MAX_ROUTE_SNAPSHOT_BYTES
        {
            return Err("attempt journal capacity exhausted".into());
        }
        write_private_journal(path, &bytes)
    }

    /// Permanently scrubs an observation already found historical; an
    /// unregistered source is compacted and released only after commit.
    fn seal_historical_context(&mut self, index: usize) -> ResultV1<()> {
        if self.attempt_ledger.contexts[index].sealed {
            return Ok(());
        }
        let release = self.attempt_ledger.contexts[index].registration.is_none();
        let claim = self.attempt_ledger.contexts[index].claim_key.clone();
        let context = &mut self.attempt_ledger.contexts[index];
        context.sealed = true;
        context.context_ref = None;
        if let Some(registration) = &mut context.registration {
            registration.assertion_key = None;
        }
        self.attempt_ledger.compact(&self.issuer_boot);
        self.commit_attempt()?;
        if release {
            self.release_claim(&claim);
        }
        Ok(())
    }

    /// Currentness requires the original issuer, full live identity and exact
    /// actor/binding epoch. No later read can create a missing observation.
    fn attempt_current(&self, context: &Context) -> bool {
        let observation = &context.observation;
        if context.sealed
            || context.issuer_epoch != self.issuer_boot
            || !observation.incarnation.live(&self.config.host_id)
        {
            return false;
        }
        let binding_current =
            self.bindings
                .get(&observation.actor.address)
                .is_some_and(|binding| {
                    !binding.retired
                        && binding.epoch == observation.actor.epoch
                        && binding.address.native_session_id == observation.actor.native_id
                        && binding
                            .managed_incarnation
                            .as_ref()
                            .is_some_and(|identity| {
                                Incarnation::new(&self.config.host_id, identity)
                                    == observation.incarnation
                            })
                        && os::process_facts(observation.incarnation.pid).is_some_and(|facts| {
                            facts.exe.as_ref() == Some(&binding.executable)
                                && executable_current(&binding.executable, &facts, self.owner_uid)
                                    .is_ok()
                        })
                });
        let still_same = os::attempt::kernel_incarnation(
            observation.incarnation.pid,
            observation.incarnation.uid,
        )
        .is_ok_and(|identity| {
            Incarnation::new(&self.config.host_id, &identity) == observation.incarnation
        });
        let now_ms = bridge_core::service::current_unix_millis();
        binding_current
            && still_same
            && observation.observed_at_ms <= now_ms
            && now_ms < observation.expires_at_ms
    }

    /// Authenticates the exact configured frontend build and its stdio process.
    #[cfg(target_os = "linux")]
    fn verify_managed_frontend(
        &mut self,
        peer: PeerIdentity,
        frontend: &RelayExecutable,
    ) -> ResultV1<os::attempt::KernelIncarnation> {
        let frontend_before = os::attempt::kernel_incarnation(peer.pid, self.owner_uid)
            .map_err(|_| AttemptError::new("peer_not_authorized", "none"))?;
        let facts = os::process_facts(peer.pid)
            .ok_or_else(|| AttemptError::new("peer_not_authorized", "none"))?;
        if peer.uid != self.owner_uid
            || facts.uid != Some(self.owner_uid)
            || facts.exe.as_ref() != Some(&frontend.path)
        {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.verify_loaded(&frontend.path, facts.start_time, &frontend.sha256)
            .map_err(source_error)?;
        let stdio = [0, 1]
            .iter()
            .all(|fd| os::attempt::managed_stdio(peer.pid, *fd));
        if !stdio
            || os::attempt::kernel_incarnation(peer.pid, self.owner_uid)
                .ok()
                .as_ref()
                != Some(&frontend_before)
        {
            return Err(AttemptError::new("transport_unsupported", "none"));
        }
        Ok(frontend_before)
    }

    /// Authenticates a configured stdio frontend and its verified managed
    /// harness ancestry, then durably fences that exact frontend incarnation.
    #[cfg(target_os = "linux")]
    fn verify_producer_frontend(&mut self, peer: PeerIdentity, producer: &str) -> ResultV1<()> {
        let facts = os::process_facts(peer.pid)
            .ok_or_else(|| AttemptError::new("peer_not_authorized", "none"))?;
        let frontend = self
            .config
            .managed_tools
            .iter()
            .find(|tool| {
                tool.producer == producer && facts.exe.as_ref() == Some(&tool.frontend.path)
            })
            .map(|tool| tool.frontend.clone())
            .ok_or_else(|| AttemptError::new("peer_not_authorized", "none"))?;
        let before = self.verify_managed_frontend(peer, &frontend)?;
        let executable = os::attempt::live_executable(&before)
            .map_err(|_| AttemptError::new("peer_not_authorized", "none"))?;
        let qualifying = self.managed_frontend_harnesses(peer);
        if qualifying.is_empty()
            || os::attempt::kernel_incarnation(peer.pid, peer.uid)
                .ok()
                .as_ref()
                != Some(&before)
        {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.remember_frontend(&before)?;
        if self.managed_frontend_harnesses(peer) != qualifying
            || os::attempt::kernel_incarnation(peer.pid, peer.uid)
                .ok()
                .as_ref()
                != Some(&before)
            || os::attempt::live_executable(&before).ok().as_ref() != Some(&executable)
        {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        Ok(())
    }

    /// Authenticates a producer for capability discovery, which grants no
    /// authority: either the stdio frontend, or a configured resident whose
    /// executable and loaded build are pinned by `adapters.audiences`. Every
    /// later operation keeps its own role and transport checks. A resident
    /// refusal is reported only when the peer is not the frontend build.
    fn verify_discovery_principal(&mut self, peer: PeerIdentity, producer: &str) -> ResultV1<()> {
        let Err(refusal) = self.verify_producer_frontend(peer, producer) else {
            return Ok(());
        };
        let audiences: Vec<String> = self
            .config
            .audiences
            .iter()
            .filter(|entry| entry.producer == producer)
            .map(|entry| entry.name.clone())
            .collect();
        match self.verify_any_attempt_consumer(peer, producer, &audiences) {
            Ok(()) => Ok(()),
            Err(error) if refusal.code == "peer_not_authorized" => Err(error),
            Err(_) => Err(refusal),
        }
    }

    /// Samples all configured managed harness matches in stable policy order;
    /// each match already proves the full same-UID ancestry to that harness.
    #[cfg(target_os = "linux")]
    fn managed_frontend_harnesses(
        &mut self,
        peer: PeerIdentity,
    ) -> Vec<os::attempt::KernelIncarnation> {
        [Harness::CODEX, Harness::CLAUDE_CODE]
            .into_iter()
            .filter_map(|harness| {
                self.harness_of(peer, harness, true)
                    .ok()
                    .filter(|matched| matched.managed_ancestry)
                    .and_then(|matched| matched.kernel_incarnation)
            })
            .collect()
    }

    /// Unsupported platforms cannot qualify a managed producer frontend.
    #[cfg(not(target_os = "linux"))]
    fn verify_producer_frontend(&mut self, _: PeerIdentity, _: &str) -> ResultV1<()> {
        Err(AttemptError::new("transport_unsupported", "none"))
    }

    /// Unsupported platforms cannot qualify a managed stdio frontend.
    #[cfg(not(target_os = "linux"))]
    fn verify_managed_frontend(
        &mut self,
        _: PeerIdentity,
        _: &RelayExecutable,
    ) -> ResultV1<os::attempt::KernelIncarnation> {
        Err(AttemptError::new("transport_unsupported", "none"))
    }

    /// Resolves a real direct stdio peer to the immutable original hook capture.
    #[cfg(target_os = "linux")]
    fn attempt_source(
        &mut self,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
        producer: &str,
        command: &str,
        grant: &bridge_core::ProducerPolicyGrant,
    ) -> ResultV1<Observation> {
        let (call, harness, channel) = meta
            .native()
            .ok_or_else(|| AttemptError::new("transport_unsupported", "none"))?;
        if harness != Harness::CODEX && harness != Harness::CLAUDE_CODE {
            return Err(AttemptError::new("transport_unsupported", "none"));
        }
        let call = checked_id(call, "call id")
            .map_err(|_| AttemptError::new("binding_unavailable", "fresh_invocation"))?;
        let matched = self.harness_of(peer, harness, true).map_err(source_error)?;
        if !matched.managed_ancestry {
            return Err(AttemptError::new("attempt_mismatch", "fresh_invocation"));
        }
        let proof = match channel {
            CallerChannel::ClaudeToolUse => CallerProof::ClaudeMeta,
            CallerChannel::CodexCall => CallerProof::CodexMeta,
            _ => return Err(AttemptError::new("transport_unsupported", "none")),
        };
        if !matched.policy.accepts(proof) {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        let identity = matched
            .kernel_incarnation
            .as_ref()
            .ok_or_else(|| AttemptError::new("attempt_not_ready", "fresh_invocation"))?;
        let records = self
            .calls
            .get(&call)
            .ok_or_else(|| AttemptError::new("binding_unavailable", "fresh_invocation"))?;
        // A later hook with the same call ID must never repair an original
        // observation whose launch capture was absent or unreadable.
        if records
            .iter()
            .any(|record| record.launch_observation.is_none())
        {
            return Err(AttemptError::new("attempt_not_ready", "fresh_invocation"));
        }
        let mut matching = records.iter().filter(|record| {
            record
                .launch_observation
                .as_ref()
                .is_some_and(|launch| &launch.incarnation == identity)
        });
        let Some(record) = matching.next().cloned() else {
            return Err(AttemptError::new("attempt_mismatch", "fresh_invocation"));
        };
        if matching.next().is_some() {
            return Err(AttemptError::new("invocation_spent", "fresh_invocation"));
        }
        let binding = self
            .bindings
            .get(&record.address)
            .cloned()
            .ok_or_else(|| AttemptError::new("binding_unavailable", "fresh_invocation"))?;
        if !grant.policy().is_some_and(|policy| policy.registration)
            || !grant.allows_native_scope(&binding.address)
        {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        if record.role != ActorRole::Root
            || record.native_id != binding.address.native_session_id
            || matches!(meta, PresentedMeta::Codex { thread_id, .. } if thread_id != &record.native_id)
        {
            return Err(AttemptError::new("actor_mismatch", "none"));
        }
        if record.observed_ms > now_ms
            || now_ms.saturating_sub(record.observed_ms) >= self.config.max_call_age_ms
        {
            return Err(AttemptError::new("assertion_stale", "fresh_invocation"));
        }
        let tool = record
            .tool_name
            .clone()
            .ok_or_else(|| AttemptError::new("route_mismatch", "fresh_invocation"))?;
        let frontend = self
            .config
            .managed_tools
            .iter()
            .find(|mapping| tool_matches(mapping, producer, command, &tool))
            .map(|mapping| mapping.frontend.clone())
            .ok_or_else(|| AttemptError::new("route_mismatch", "none"))?;
        self.verify_managed_frontend(peer, &frontend)?;
        let launch = record
            .launch_observation
            .ok_or_else(|| AttemptError::new("attempt_not_ready", "fresh_invocation"))?;
        if binding.managed_incarnation.as_ref() != Some(&launch.incarnation)
            || binding.epoch != record.epoch
            || binding.retired
            || os::attempt::kernel_incarnation(launch.incarnation.pid, self.owner_uid)
                .ok()
                .as_ref()
                != Some(&launch.incarnation)
        {
            return Err(AttemptError::new("attempt_mismatch", "fresh_invocation"));
        }
        Ok(Observation {
            incarnation: Incarnation::new(&self.config.host_id, &launch.incarnation),
            launch_id: launch.launch_id,
            actor: Actor {
                address: record.address,
                role: "root".into(),
                native_id: record.native_id,
                epoch: record.epoch,
            },
            native_call_id: call,
            tool_name: tool,
            observed_at_ms: record.observed_ms,
            expires_at_ms: record
                .observed_ms
                .saturating_add(self.config.max_call_age_ms),
        })
    }

    /// Unsupported platforms never manufacture a managed launch observation.
    #[cfg(not(target_os = "linux"))]
    fn attempt_source(
        &mut self,
        _: PeerIdentity,
        _: &PresentedMeta,
        _: u64,
        _: &str,
        _: &str,
        _: &bridge_core::ProducerPolicyGrant,
    ) -> ResultV1<Observation> {
        Err(AttemptError::new("transport_unsupported", "none"))
    }

    /// Reserves the one original hook and persists its immutable context.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated protocol fields are kept separate"
    )]
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_attempt(
        &mut self,
        expected: &str,
        expected_issuer: &str,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
        producer: &str,
        invocation: &str,
        command: &str,
        grant: &bridge_core::ProducerPolicyGrant,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(expected)?;
        self.managed_configured(producer)?;
        if !grant.policy().is_some_and(|policy| policy.registration) {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.verify_producer_frontend(peer, producer)?;
        if expected_issuer != self.issuer_boot {
            return Err(AttemptError::new("assertion_stale", "fresh_invocation"));
        }
        if peer.uid != self.owner_uid {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.expire_attempt_contexts(now_ms).map_err(source_error)?;
        self.attempt_store(expected)?;
        if self
            .attempt_ledger
            .tombstones
            .iter()
            .any(|t| t.producer == producer && t.invocation_key == invocation)
        {
            return Err(AttemptError::new("aborted", "none"));
        }
        if let Some(fence) = self.attempt_ledger.find_fence(producer, invocation, None) {
            return Err(if fence.aborted {
                AttemptError::new("aborted", "none")
            } else {
                AttemptError::new("invocation_spent", "fresh_invocation")
            });
        }
        let observation = self.attempt_source(peer, meta, now_ms, producer, command, grant)?;
        if let Some(existing) = self
            .attempt_ledger
            .contexts
            .iter()
            .find(|c| c.producer == producer && c.invocation_key == invocation)
        {
            if existing.command_name != command || existing.observation != observation {
                return Err(AttemptError::new("intent_conflict", "none"));
            }
            if !self.attempt_current(existing) {
                return Err(AttemptError::new("assertion_stale", "fresh_invocation"));
            }
            return Ok(
                serde_json::json!({"version":1,"store_id":self.store_id,"bridge_context_ref":existing.context_ref,"invocation_key":invocation,"expires_at_ms":observation.expires_at_ms}),
            );
        }
        if self.attempt_ledger.reserved_slots().saturating_add(2) > MAX_RECORDS
            || !self.attempt_ledger.fence_capacity()
        {
            return Err(AttemptError::new("capacity_exhausted", "operator"));
        }
        let context_ref = random_secret().map_err(source_error)?;
        let source = os::attempt::KernelIncarnation {
            boot_id: observation.incarnation.boot_id.clone(),
            pid_namespace_inode: observation.incarnation.pid_namespace_inode,
            uid: observation.incarnation.uid,
            pid: observation.incarnation.pid,
            start_ticks: observation.incarnation.start_ticks,
        };
        let claim_key = managed_source_key(&observation);
        let source_hash = source_fence(&claim_key);
        if self
            .attempt_ledger
            .contexts
            .iter()
            .any(|context| context.claim_key == claim_key)
            || self
                .attempt_ledger
                .fences
                .iter()
                .any(|fence| fence.source_hash.as_ref() == Some(&source_hash))
        {
            return Err(AttemptError::new("invocation_spent", "fresh_invocation"));
        }
        if self.claims.contains_key(&claim_key) {
            return Err(AttemptError::new("invocation_spent", "fresh_invocation"));
        }
        if self.claims.len() >= self.max_calls {
            return Err(AttemptError::new("capacity_exhausted", "operator"));
        }
        let record = self
            .calls
            .get_mut(&observation.native_call_id)
            .and_then(|records| {
                records.iter_mut().find(|record| {
                    record
                        .launch_observation
                        .as_ref()
                        .is_some_and(|launch| launch.incarnation == source)
                })
            })
            .ok_or_else(|| AttemptError::new("binding_unavailable", "fresh_invocation"))?;
        if record.claimed || record.consumed {
            return Err(AttemptError::new("invocation_spent", "fresh_invocation"));
        }
        record.claimed = true;
        self.claims.insert(
            claim_key.clone(),
            claims::ClaimRecord {
                producer: producer.into(),
                request_id: invocation.into(),
                fingerprint: crate::server::sha256_hex(command.as_bytes()),
                source: claims::ClaimSource::ManagedNative {
                    call: observation.native_call_id.clone(),
                    incarnation: source,
                },
            },
        );
        // Recheck the same full original incarnation after reservation.
        if self
            .attempt_source(peer, meta, now_ms, producer, command, grant)
            .ok()
            .as_ref()
            != Some(&observation)
        {
            self.release_claim(&claim_key);
            return Err(AttemptError::new("attempt_mismatch", "fresh_invocation"));
        }
        let fresh_now = bridge_core::service::current_unix_millis();
        if fresh_now < observation.observed_at_ms || fresh_now >= observation.expires_at_ms {
            self.release_claim(&claim_key);
            return Err(AttemptError::new("assertion_stale", "fresh_invocation"));
        }
        let context = Context {
            producer: producer.into(),
            invocation_key: invocation.into(),
            context_hash: crate::server::sha256_hex(context_ref.expose().as_bytes()),
            context_ref: Some(context_ref.clone()),
            command_name: command.into(),
            observation: observation.clone(),
            issuer_epoch: self.issuer_boot.clone(),
            claim_key: claim_key.clone(),
            registration: None,
            sealed: false,
            aborted: false,
        };
        self.attempt_ledger.contexts.push(context);
        if !self.attempt_snapshot_fits() {
            self.attempt_ledger.contexts.pop();
            self.release_claim(&claim_key);
            return Err(AttemptError::new("capacity_exhausted", "operator"));
        }
        self.commit_attempt()?;
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"bridge_context_ref":context_ref,"invocation_key":invocation,"expires_at_ms":observation.expires_at_ms}),
        )
    }

    /// Unsupported platforms cannot create a managed reservation.
    #[cfg(not(target_os = "linux"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "matches the Linux private operation"
    )]
    pub(crate) fn prepare_attempt(
        &mut self,
        _: &str,
        _: &str,
        _: PeerIdentity,
        _: &PresentedMeta,
        _: u64,
        _: &str,
        _: &str,
        _: &str,
        _: &bridge_core::ProducerPolicyGrant,
    ) -> ResultV1<serde_json::Value> {
        Err(AttemptError::new("transport_unsupported", "none"))
    }

    /// Verifies a configured reader's credential identity, peer UID and loaded build.
    fn verify_run_reader(
        &mut self,
        peer: PeerIdentity,
        reader: &str,
        producer: &str,
    ) -> ResultV1<()> {
        if peer.uid != self.owner_uid {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        let executable = self
            .config
            .run_readers
            .iter()
            .find(|entry| entry.reader == reader && entry.producer == producer)
            .map(|entry| entry.executable.clone())
            .ok_or_else(|| AttemptError::new("peer_not_authorized", "none"))?;
        let before = os::attempt::kernel_incarnation(peer.pid, peer.uid)
            .map_err(|_| AttemptError::new("peer_not_authorized", "none"))?;
        let facts = os::process_facts(peer.pid)
            .ok_or_else(|| AttemptError::new("peer_not_authorized", "none"))?;
        if facts.uid != Some(self.owner_uid) || facts.exe.as_ref() != Some(&executable.path) {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.verify_loaded(&executable.path, facts.start_time, &executable.sha256)
            .map_err(source_error)?;
        if os::attempt::kernel_incarnation(peer.pid, peer.uid)
            .ok()
            .as_ref()
            != Some(&before)
        {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        Ok(())
    }

    /// Checks a consumer audience, detached role and exact live executable,
    /// bracketed by the full same-incarnation kernel identity.
    #[cfg(target_os = "linux")]
    fn verify_attempt_consumer(
        &mut self,
        peer: PeerIdentity,
        producer: &str,
        audience: &str,
        allowed: &[String],
    ) -> ResultV1<()> {
        if !allowed.iter().any(|entry| entry == audience) {
            return Err(AttemptError::new("audience_mismatch", "none"));
        }
        let before = os::attempt::kernel_incarnation(peer.pid, peer.uid)
            .map_err(|_| AttemptError::new("peer_not_authorized", "none"))?;
        let executable = os::attempt::live_executable(&before)
            .map_err(|_| AttemptError::new("peer_not_authorized", "none"))?;
        self.verify_audience(peer, producer, audience)
            .map_err(source_error)?;
        self.verify_detached_consumer(&before, producer, audience)?;
        if os::attempt::kernel_incarnation(peer.pid, peer.uid)
            .ok()
            .as_ref()
            != Some(&before)
            || os::attempt::live_executable(&before).ok().as_ref() != Some(&executable)
        {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.remember_consumer(&before)?;
        if self
            .verify_detached_consumer(&before, producer, audience)
            .is_err()
            || os::attempt::kernel_incarnation(peer.pid, peer.uid)
                .ok()
                .as_ref()
                != Some(&before)
            || os::attempt::live_executable(&before).ok().as_ref() != Some(&executable)
        {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        Ok(())
    }

    /// Unsupported platforms cannot establish a detached managed consumer.
    #[cfg(not(target_os = "linux"))]
    fn verify_attempt_consumer(
        &mut self,
        _: PeerIdentity,
        _: &str,
        _: &str,
        _: &[String],
    ) -> ResultV1<()> {
        Err(AttemptError::new("transport_unsupported", "none"))
    }

    /// Authenticates a configured consumer when an expired fence has no audience.
    fn verify_any_attempt_consumer(
        &mut self,
        peer: PeerIdentity,
        producer: &str,
        allowed: &[String],
    ) -> ResultV1<()> {
        let candidates: Vec<String> = self
            .config
            .audiences
            .iter()
            .filter(|entry| entry.producer == producer && allowed.contains(&entry.name))
            .map(|entry| entry.name.clone())
            .collect();
        let mut recovery = None;
        for audience in candidates {
            match self.verify_attempt_consumer(peer, producer, &audience, allowed) {
                Ok(()) => return Ok(()),
                Err(error)
                    if matches!(
                        error.code,
                        "relaunch_required" | "recovery_required" | "capacity_exhausted"
                    ) =>
                {
                    recovery = Some(error)
                }
                Err(_) => (),
            }
        }
        Err(recovery.unwrap_or_else(|| AttemptError::new("peer_not_authorized", "none")))
    }

    /// Gives a configured Run reader the unchanged bootstrap observation.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated protocol fields are kept separate"
    )]
    pub(crate) fn lookup_attempt_context(
        &mut self,
        expected: &str,
        peer: PeerIdentity,
        reader: &str,
        producer: &str,
        reference: &str,
        invocation: &str,
        now_ms: u64,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(expected)?;
        self.managed_configured(producer)?;
        self.verify_run_reader(peer, reader, producer)?;
        self.expire_attempt_contexts(now_ms).map_err(source_error)?;
        self.attempt_store(expected)?;
        if self
            .attempt_ledger
            .find_fence(producer, invocation, None)
            .is_some()
        {
            return Err(AttemptError::new(
                "assertion_historical",
                "fresh_invocation",
            ));
        }
        let digest = crate::server::sha256_hex(reference.as_bytes());
        let index = self
            .attempt_ledger
            .contexts
            .iter()
            .position(|c| {
                c.producer == producer && c.context_hash == digest && c.invocation_key == invocation
            })
            .ok_or_else(|| AttemptError::new("binding_unavailable", "same_key_lookup"))?;
        let context = self.attempt_ledger.contexts[index].clone();
        let validity = if self.attempt_current(&context) {
            "current"
        } else {
            self.seal_historical_context(index)?;
            "historical"
        };
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"bridge_context_ref":reference,"invocation_key":invocation,"observation":context.observation,"issuer_epoch":context.issuer_epoch,"validity":validity}),
        )
    }

    /// Registers a digest and configured audience against the same reserved call.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated protocol fields are kept separate"
    )]
    pub(crate) fn register_attempt(
        &mut self,
        expected: &str,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
        producer: &str,
        reference: &str,
        invocation: &str,
        command: &str,
        digest: &str,
        audience: &str,
        nonce: &str,
        allowed: &[String],
        grant: &bridge_core::ProducerPolicyGrant,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(expected)?;
        self.managed_configured(producer)?;
        if !grant.policy().is_some_and(|policy| policy.registration) {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.verify_producer_frontend(peer, producer)?;
        if peer.uid != self.owner_uid {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.expire_attempt_contexts(now_ms).map_err(source_error)?;
        self.attempt_store(expected)?;
        if !allowed.iter().any(|v| v == audience)
            || !self
                .config
                .audiences
                .iter()
                .any(|a| a.producer == producer && a.name == audience)
        {
            return Err(AttemptError::new("audience_mismatch", "none"));
        }
        if self
            .attempt_ledger
            .tombstones
            .iter()
            .any(|t| t.producer == producer && t.invocation_key == invocation)
        {
            return Err(AttemptError::new("aborted", "none"));
        }
        if let Some(fence) = self.attempt_ledger.find_fence(producer, invocation, None) {
            return Err(if fence.aborted {
                AttemptError::new("aborted", "none")
            } else {
                AttemptError::new("invocation_spent", "fresh_invocation")
            });
        }
        let observation = self.attempt_source(peer, meta, now_ms, producer, command, grant)?;
        let hash = crate::server::sha256_hex(reference.as_bytes());
        let index = self
            .attempt_ledger
            .contexts
            .iter()
            .position(|c| {
                c.producer == producer && c.invocation_key == invocation && c.context_hash == hash
            })
            .ok_or_else(|| AttemptError::new("binding_unavailable", "fresh_invocation"))?;
        let context = &self.attempt_ledger.contexts[index];
        if context.command_name != command || context.observation != observation {
            return Err(AttemptError::new("intent_conflict", "none"));
        }
        if !self.attempt_current(context) {
            self.seal_historical_context(index)?;
            return Err(AttemptError::new("assertion_stale", "fresh_invocation"));
        }
        if let Some(registered) = &context.registration {
            if registered.security_digest != digest
                || registered.audience != audience
                || registered.nonce != nonce
            {
                return Err(AttemptError::new("intent_conflict", "none"));
            }
            return Ok(
                serde_json::json!({"version":1,"store_id":self.store_id,"assertion_key":registered.assertion_key,"invocation_key":invocation,"issuer_epoch":context.issuer_epoch,"expires_at_ms":context.observation.expires_at_ms}),
            );
        }
        let key = random_secret().map_err(source_error)?;
        self.attempt_ledger.contexts[index].registration = Some(Registration {
            assertion_hash: crate::server::sha256_hex(key.expose().as_bytes()),
            assertion_key: Some(key.clone()),
            security_digest: digest.into(),
            audience: audience.into(),
            nonce: nonce.into(),
            receipt: None,
        });
        self.commit_attempt()?;
        let context = &self.attempt_ledger.contexts[index];
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"assertion_key":key,"invocation_key":invocation,"issuer_epoch":context.issuer_epoch,"expires_at_ms":context.observation.expires_at_ms}),
        )
    }
}

impl Registry {
    /// Consumes exactly one registered digest under its qualified audience.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated protocol fields are kept separate"
    )]
    pub(crate) fn consume_attempt(
        &mut self,
        expected: &str,
        peer: PeerIdentity,
        producer: &str,
        request_id: &str,
        key: &str,
        invocation: &str,
        digest: &str,
        allowed: &[String],
        _now_ms: u64,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(expected)?;
        self.managed_configured(producer)?;
        if let Some(fence) = self
            .attempt_ledger
            .find_fence(producer, invocation, Some(request_id))
            .cloned()
        {
            if let Some(audience) = &fence.audience {
                self.verify_attempt_consumer(peer, producer, audience, allowed)?;
            } else {
                self.verify_any_attempt_consumer(peer, producer, allowed)?;
            }
            if fence.aborted {
                let audience = fence.audience.as_deref().expect("validated aborted fence");
                if fence.invocation_hash != invocation_fence(producer, invocation)
                    || fence.consume_hash.as_deref()
                        != Some(consume_fence(producer, request_id).as_str())
                    || fence.intention_hash.as_deref()
                        != Some(
                            abort_fence(producer, request_id, invocation, digest, audience)
                                .as_str(),
                        )
                {
                    return Err(AttemptError::new("intent_conflict", "none"));
                }
                return Err(AttemptError::new("aborted", "none"));
            }
            return Err(AttemptError::new("invocation_spent", "fresh_invocation"));
        }
        if let Some(tombstone) = self
            .attempt_ledger
            .tombstones
            .iter()
            .find(|t| {
                t.producer == producer
                    && (t.invocation_key == invocation
                        || t.consume_request_id.as_deref() == Some(request_id))
            })
            .cloned()
        {
            let audience = tombstone
                .audience
                .as_deref()
                .ok_or_else(|| AttemptError::new("aborted", "none"))?;
            self.verify_attempt_consumer(peer, producer, audience, allowed)?;
            if tombstone.invocation_key != invocation
                || tombstone.consume_request_id.as_deref() != Some(request_id)
                || tombstone.security_digest.as_deref() != Some(digest)
            {
                return Err(AttemptError::new("intent_conflict", "none"));
            }
            let registered = self
                .attempt_ledger
                .contexts
                .iter()
                .find(|c| c.producer == producer && c.invocation_key == invocation)
                .and_then(|c| c.registration.as_ref());
            if registered.is_some_and(|registration| {
                registration.assertion_hash != crate::server::sha256_hex(key.as_bytes())
            }) {
                return Err(AttemptError::new("intent_conflict", "none"));
            }
            let receipt = registered.and_then(|r| r.receipt.as_ref());
            return match receipt {
                Some(receipt) => Ok(
                    serde_json::json!({"version":1,"store_id":self.store_id,"receipt":receipt,"validity":"historical","aborted":true}),
                ),
                None => Err(AttemptError::new("aborted", "none")),
            };
        }
        let hash = crate::server::sha256_hex(key.as_bytes());
        let index = self
            .attempt_ledger
            .contexts
            .iter()
            .position(|c| {
                c.producer == producer
                    && c.registration
                        .as_ref()
                        .is_some_and(|r| r.assertion_hash == hash)
            })
            .ok_or_else(|| AttemptError::new("binding_unavailable", "fresh_invocation"))?;
        let context = self.attempt_ledger.contexts[index].clone();
        let registration = context.registration.as_ref().expect("matched registration");
        self.verify_attempt_consumer(peer, producer, &registration.audience, allowed)?;
        if context.invocation_key != invocation || registration.security_digest != digest {
            return Err(AttemptError::new("intent_conflict", "none"));
        }
        if self
            .attempt_ledger
            .contexts
            .iter()
            .filter_map(|c| c.registration.as_ref().and_then(|r| r.receipt.as_ref()))
            .any(|receipt| {
                receipt.producer == producer
                    && receipt.consume_request_id == request_id
                    && (receipt.invocation_key != invocation || receipt.security_digest != digest)
            })
        {
            return Err(AttemptError::new("intent_conflict", "none"));
        }
        let abort = self.attempt_ledger.tombstones.iter().find(|t| {
            t.producer == producer
                && (t.invocation_key == invocation
                    || t.consume_request_id.as_deref() == Some(request_id))
        });
        if let Some(abort) = abort {
            if abort.invocation_key != invocation
                || abort
                    .consume_request_id
                    .as_deref()
                    .is_some_and(|id| id != request_id)
                || abort
                    .security_digest
                    .as_deref()
                    .is_some_and(|v| v != digest)
                || abort
                    .audience
                    .as_deref()
                    .is_some_and(|v| v != registration.audience)
            {
                return Err(AttemptError::new("intent_conflict", "none"));
            }
            if let Some(receipt) = &registration.receipt {
                return Ok(
                    serde_json::json!({"version":1,"store_id":self.store_id,"receipt":receipt,"validity":"historical","aborted":true}),
                );
            }
            return Err(AttemptError::new("aborted", "none"));
        }
        if let Some(receipt) = &registration.receipt {
            if receipt.consume_request_id != request_id {
                return Err(AttemptError::new("invocation_spent", "fresh_invocation"));
            }
            if context.aborted {
                return Ok(
                    serde_json::json!({"version":1,"store_id":self.store_id,"receipt":receipt,"validity":"historical","aborted":true}),
                );
            }
            let validity = if self.attempt_current(&context) {
                "current"
            } else {
                self.seal_historical_context(index)?;
                "historical"
            };
            return Ok(
                serde_json::json!({"version":1,"store_id":self.store_id,"receipt":receipt,"validity":validity,"aborted":false}),
            );
        }
        if !self.attempt_current(&context) {
            self.seal_historical_context(index)?;
            return Err(AttemptError::new(
                "assertion_historical",
                "fresh_invocation",
            ));
        }
        let consumed_at_ms = bridge_core::service::current_unix_millis();
        if consumed_at_ms < context.observation.observed_at_ms
            || consumed_at_ms >= context.observation.expires_at_ms
        {
            return Err(AttemptError::new("assertion_stale", "fresh_invocation"));
        }
        let claim_key = context.claim_key.clone();
        let receipt = Receipt {
            producer: producer.into(),
            consume_request_id: request_id.into(),
            invocation_key: invocation.into(),
            security_digest: digest.into(),
            observation: context.observation,
            issuer_epoch: context.issuer_epoch,
            consumed_at_ms,
        };
        self.attempt_ledger.contexts[index]
            .registration
            .as_mut()
            .expect("matched registration")
            .receipt = Some(receipt.clone());
        self.commit_attempt()?;
        self.finalize_claim(&claim_key);
        let validity = if self.attempt_current(&self.attempt_ledger.contexts[index]) {
            "current"
        } else {
            "historical"
        };
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"receipt":receipt,"validity":validity,"aborted":false}),
        )
    }

    /// Looks up only an exact committed association after reader or consumer authentication.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated protocol fields are kept separate"
    )]
    pub(crate) fn lookup_attempt(
        &mut self,
        expected: &str,
        peer: PeerIdentity,
        authenticated: &str,
        producer: &str,
        request_id: &str,
        invocation: &str,
        digest: &str,
        allowed: &[String],
        _now_ms: u64,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(expected)?;
        self.managed_configured(producer)?;
        let context_index = self.attempt_ledger.contexts.iter().position(|c| {
            c.producer == producer
                && c.invocation_key == invocation
                && c.registration
                    .as_ref()
                    .and_then(|r| r.receipt.as_ref())
                    .is_some_and(|r| r.consume_request_id == request_id)
        });
        let context = context_index.map(|index| self.attempt_ledger.contexts[index].clone());
        let retired_fence = self
            .attempt_ledger
            .find_fence(producer, invocation, Some(request_id))
            .cloned();
        if self
            .config
            .run_readers
            .iter()
            .any(|reader| reader.producer == producer && reader.reader == authenticated)
        {
            self.verify_run_reader(peer, authenticated, producer)?;
        } else if authenticated == producer {
            let audience = context
                .as_ref()
                .and_then(|c| c.registration.as_ref())
                .map(|r| r.audience.clone())
                .or_else(|| {
                    retired_fence
                        .as_ref()
                        .and_then(|fence| fence.audience.clone())
                })
                .ok_or_else(|| AttemptError::new("binding_unavailable", "same_key_lookup"))?;
            self.verify_attempt_consumer(peer, producer, &audience, allowed)?;
        } else {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        if retired_fence.is_some() {
            return Err(AttemptError::new(
                "assertion_historical",
                "fresh_invocation",
            ));
        }
        let context =
            context.ok_or_else(|| AttemptError::new("binding_unavailable", "same_key_lookup"))?;
        let receipt = context
            .registration
            .as_ref()
            .and_then(|r| r.receipt.as_ref())
            .expect("matched receipt");
        if receipt.security_digest != digest {
            return Err(AttemptError::new("intent_conflict", "none"));
        }
        let aborted = context.aborted
            || self
                .attempt_ledger
                .tombstones
                .iter()
                .any(|t| t.producer == producer && t.invocation_key == invocation);
        let validity = if !aborted && self.attempt_current(&context) {
            "current"
        } else {
            if let Some(index) = context_index {
                self.seal_historical_context(index)?;
            }
            "historical"
        };
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"receipt":receipt,"validity":validity,"aborted":aborted}),
        )
    }

    /// Durably aborts the original exact intention before a delayed consume can win.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated protocol fields are kept separate"
    )]
    pub(crate) fn abort_attempt(
        &mut self,
        expected: &str,
        peer: PeerIdentity,
        authenticated: &str,
        producer: &str,
        request_id: &str,
        invocation: &str,
        digest: &str,
        audience: &str,
        allowed: &[String],
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(expected)?;
        self.managed_configured(producer)?;
        if authenticated != producer {
            return Err(AttemptError::new("peer_not_authorized", "none"));
        }
        self.verify_attempt_consumer(peer, producer, audience, allowed)?;
        let invocation_hash = invocation_fence(producer, invocation);
        let request_hash = consume_fence(producer, request_id);
        let intention_hash = abort_fence(producer, request_id, invocation, digest, audience);
        let fence_index = self.attempt_ledger.fences.iter().position(|fence| {
            fence.invocation_hash == invocation_hash
                || fence.consume_hash.as_ref() == Some(&request_hash)
        });
        if let Some(index) = fence_index {
            let fence = &self.attempt_ledger.fences[index];
            if fence.aborted
                && fence.invocation_hash == invocation_hash
                && fence.consume_hash.as_ref() == Some(&request_hash)
                && fence.intention_hash.as_ref() == Some(&intention_hash)
            {
                return Ok(
                    serde_json::json!({"version":1,"store_id":self.store_id,"aborted":true,"receipt":null}),
                );
            }
            if !fence.aborted
                && fence.invocation_hash == invocation_hash
                && fence.consume_hash.is_none()
            {
                let occupied =
                    self.attempt_ledger
                        .fences
                        .iter()
                        .enumerate()
                        .any(|(other, fence)| {
                            other != index && fence.consume_hash.as_ref() == Some(&request_hash)
                        })
                        || self
                            .attempt_ledger
                            .contexts
                            .iter()
                            .filter_map(|context| {
                                context
                                    .registration
                                    .as_ref()
                                    .and_then(|registration| registration.receipt.as_ref())
                            })
                            .any(|receipt| {
                                receipt.producer == producer
                                    && receipt.consume_request_id == request_id
                            })
                        || self.attempt_ledger.tombstones.iter().any(|tombstone| {
                            tombstone.producer == producer
                                && tombstone.consume_request_id.as_deref() == Some(request_id)
                        });
                if occupied {
                    return Err(AttemptError::new("intent_conflict", "none"));
                }
                let before = self.attempt_ledger.fences[index].clone();
                let fence = &mut self.attempt_ledger.fences[index];
                fence.consume_hash = Some(request_hash);
                fence.intention_hash = Some(intention_hash);
                fence.audience = Some(audience.into());
                fence.aborted = true;
                if !self.attempt_snapshot_fits() {
                    self.attempt_ledger.fences[index] = before;
                    return Err(AttemptError::new("capacity_exhausted", "operator"));
                }
                self.commit_attempt()?;
                return Ok(
                    serde_json::json!({"version":1,"store_id":self.store_id,"aborted":true,"receipt":null}),
                );
            }
            return Err(AttemptError::new("invocation_spent", "fresh_invocation"));
        }
        if self
            .attempt_ledger
            .contexts
            .iter()
            .filter_map(|c| c.registration.as_ref().and_then(|r| r.receipt.as_ref()))
            .any(|receipt| {
                receipt.producer == producer
                    && receipt.consume_request_id == request_id
                    && (receipt.invocation_key != invocation || receipt.security_digest != digest)
            })
        {
            return Err(AttemptError::new("intent_conflict", "none"));
        }
        let context_index = self
            .attempt_ledger
            .contexts
            .iter()
            .position(|c| c.producer == producer && c.invocation_key == invocation);
        let context = context_index.map(|index| self.attempt_ledger.contexts[index].clone());
        let receipt = if let Some(context) = &context {
            if let Some(registration) = &context.registration {
                if registration.audience != audience
                    || registration.security_digest != digest
                    || registration
                        .receipt
                        .as_ref()
                        .is_some_and(|r| r.consume_request_id != request_id)
                {
                    return Err(AttemptError::new("intent_conflict", "none"));
                }
                registration.receipt.clone()
            } else {
                None
            }
        } else {
            None
        };
        if context.as_ref().is_some_and(|context| context.aborted) {
            return Ok(
                serde_json::json!({"version":1,"store_id":self.store_id,"aborted":true,"receipt":receipt}),
            );
        }
        if let Some(old) = self.attempt_ledger.tombstones.iter().find(|t| {
            t.producer == producer
                && (t.invocation_key == invocation
                    || t.consume_request_id.as_deref() == Some(request_id))
        }) {
            if old.invocation_key != invocation
                || old.consume_request_id.as_deref() != Some(request_id)
                || old.security_digest.as_deref() != Some(digest)
                || old.audience.as_deref() != Some(audience)
            {
                return Err(AttemptError::new("intent_conflict", "none"));
            }
            return Ok(
                serde_json::json!({"version":1,"store_id":self.store_id,"aborted":true,"receipt":receipt}),
            );
        }
        if context_index.is_none()
            && (self.attempt_ledger.reserved_slots().saturating_add(1) > MAX_RECORDS
                || !self.attempt_ledger.fence_capacity())
        {
            return Err(AttemptError::new("capacity_exhausted", "operator"));
        }
        let before = self.attempt_ledger.clone();
        if let Some(index) = context_index {
            self.attempt_ledger.contexts[index].sealed = true;
            self.attempt_ledger.contexts[index].context_ref = None;
            if let Some(registration) = &mut self.attempt_ledger.contexts[index].registration {
                registration.assertion_key = None;
            }
        }
        if receipt.is_some() {
            self.attempt_ledger.contexts[context_index.expect("receipt has context")].aborted =
                true;
            self.commit_attempt()?;
            if let Some(context) = context {
                self.finalize_claim(&context.claim_key);
            }
            return Ok(
                serde_json::json!({"version":1,"store_id":self.store_id,"aborted":true,"receipt":receipt}),
            );
        }
        self.attempt_ledger.tombstones.push(Tombstone {
            producer: producer.into(),
            consume_request_id: Some(request_id.into()),
            invocation_key: invocation.into(),
            security_digest: Some(digest.into()),
            audience: Some(audience.into()),
        });
        self.attempt_ledger.compact(&self.issuer_boot);
        if !self.attempt_snapshot_fits() {
            self.attempt_ledger = before;
            return Err(AttemptError::new("capacity_exhausted", "operator"));
        }
        self.commit_attempt()?;
        if let Some(context) = context {
            self.finalize_claim(&context.claim_key);
        }
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"aborted":true,"receipt":receipt}),
        )
    }

    /// Retires one old issuer namespace only after an authenticated Run reader
    /// attests that no admission or consume receipt needs further recovery.
    pub(crate) fn retire_attempt_namespace(
        &mut self,
        expected: &str,
        peer: PeerIdentity,
        reader: &str,
        producer: &str,
        issuer: &str,
        retirement_key: &str,
    ) -> ResultV1<serde_json::Value> {
        self.attempt_store(expected)?;
        self.managed_configured(producer)?;
        self.verify_run_reader(peer, reader, producer)?;
        if issuer == self.issuer_boot {
            return Err(AttemptError::new("intent_conflict", "none"));
        }
        if let Some(existing) = self.attempt_ledger.retirements.iter().find(|record| {
            record.retirement_key == retirement_key
                || (record.producer == producer && record.issuer_epoch == issuer)
        }) {
            if existing.producer != producer
                || existing.issuer_epoch != issuer
                || existing.retirement_key != retirement_key
            {
                return Err(AttemptError::new("intent_conflict", "none"));
            }
            return Ok(
                serde_json::json!({"version":1,"store_id":self.store_id,"producer":producer,"issuer_epoch":issuer,"retirement_key":retirement_key,"retired_count":existing.retired_count}),
            );
        }
        if !self.attempt_ledger.fence_capacity() {
            return Err(AttemptError::new("capacity_exhausted", "operator"));
        }
        let before = self.attempt_ledger.clone();
        let mut claims = Vec::new();
        let mut retired = Vec::new();
        for context in &self.attempt_ledger.contexts {
            if context.producer == producer && context.issuer_epoch == issuer {
                claims.push(context.claim_key.clone());
                let registration = context.registration.as_ref();
                let receipt = registration.and_then(|entry| entry.receipt.as_ref());
                retired.push(Fence {
                    invocation_hash: invocation_fence(producer, &context.invocation_key),
                    source_hash: Some(source_fence(&context.claim_key)),
                    consume_hash: receipt
                        .map(|receipt| consume_fence(producer, &receipt.consume_request_id)),
                    intention_hash: if context.aborted {
                        receipt.zip(registration).map(|(receipt, registration)| {
                            abort_fence(
                                producer,
                                &receipt.consume_request_id,
                                &context.invocation_key,
                                &receipt.security_digest,
                                &registration.audience,
                            )
                        })
                    } else {
                        None
                    },
                    audience: registration.map(|entry| entry.audience.clone()),
                    aborted: context.aborted,
                });
            }
        }
        let count = retired.len() as u64;
        if count == 0 {
            return Err(AttemptError::new("binding_unavailable", "none"));
        }
        let retired_invocations: std::collections::HashSet<_> = retired
            .iter()
            .map(|fence| fence.invocation_hash.clone())
            .collect();
        self.attempt_ledger
            .contexts
            .retain(|context| !(context.producer == producer && context.issuer_epoch == issuer));
        self.attempt_ledger.tombstones.retain(|tombstone| {
            !retired_invocations.contains(&invocation_fence(
                &tombstone.producer,
                &tombstone.invocation_key,
            ))
        });
        self.attempt_ledger
            .fences
            .retain(|fence| !retired_invocations.contains(&fence.invocation_hash));
        self.attempt_ledger.fences.extend(retired);
        self.attempt_ledger.retirements.push(Retirement {
            producer: producer.into(),
            issuer_epoch: issuer.into(),
            retirement_key: retirement_key.into(),
            retired_count: count,
        });
        if !self.attempt_snapshot_fits() {
            self.attempt_ledger = before;
            return Err(AttemptError::new("capacity_exhausted", "operator"));
        }
        self.commit_attempt()?;
        for claim in claims {
            self.finalize_claim(&claim);
        }
        Ok(
            serde_json::json!({"version":1,"store_id":self.store_id,"producer":producer,"issuer_epoch":issuer,"retirement_key":retirement_key,"retired_count":count}),
        )
    }
}

#[cfg(test)]
mod tests {
    //! Synthetic ledger records test expiry, provenance and exact mappings.
    use super::*;

    /// One synthetic original context, never a real process or session.
    fn context(invocation: &str) -> Context {
        let reference = Secret::new(crate::server::sha256_hex(invocation.as_bytes()));
        let mut context = Context {
            producer: "pool".into(),
            invocation_key: invocation.into(),
            context_hash: crate::server::sha256_hex(reference.expose().as_bytes()),
            context_ref: Some(reference),
            command_name: "vote".into(),
            issuer_epoch: "issuer".into(),
            claim_key: String::new(),
            sealed: false,
            observation: Observation {
                incarnation: Incarnation {
                    host_id: "lab".into(),
                    boot_id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
                    pid_namespace_inode: 1,
                    uid: 1000,
                    pid: 42,
                    start_ticks: 77,
                },
                launch_id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
                actor: Actor {
                    address: "lab/claude-code/store/session".into(),
                    role: "root".into(),
                    native_id: "session".into(),
                    epoch: 1,
                },
                native_call_id: format!("call-{invocation}"),
                tool_name: "mcp__pool__vote".into(),
                observed_at_ms: 1,
                expires_at_ms: 10,
            },
            registration: None,
            aborted: false,
        };
        context.claim_key = managed_source_key(&context.observation);
        context
    }

    /// A pre-existing or same-tick process cannot be re-observed as a new
    /// issuer's original root launch, including after a dropped journal row.
    #[cfg(target_os = "linux")]
    #[test]
    fn root_capture_requires_process_after_issuer() {
        let mut issuer = os::attempt::KernelIncarnation {
            boot_id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
            pid_namespace_inode: 7,
            uid: 1000,
            pid: 20,
            start_ticks: 100,
        };
        let mut process = issuer.clone();
        process.pid = 21;
        assert!(!root_started_after_issuer(Some(&issuer), &process));
        process.start_ticks = 101;
        assert!(root_started_after_issuer(Some(&issuer), &process));
        issuer.pid_namespace_inode = 8;
        assert!(!root_started_after_issuer(Some(&issuer), &process));
        assert!(!root_started_after_issuer(None, &process));
    }

    /// Expiry frees only abandoned call claims; registered/consumed work is retained.
    #[test]
    fn context_expiry_capacity() {
        let abandoned = context("abandoned");
        let mut registered = context("registered");
        let key = Secret::new("2".repeat(64));
        registered.registration = Some(Registration {
            assertion_hash: crate::server::sha256_hex(key.expose().as_bytes()),
            assertion_key: Some(key),
            security_digest: "a".repeat(64),
            audience: "consumer".into(),
            nonce: "nonce".into(),
            receipt: None,
        });
        let released_key = abandoned.claim_key.clone();
        let mut ledger = Ledger {
            schema: 2,
            contexts: vec![abandoned, registered],
            tombstones: Vec::new(),
            fences: Vec::new(),
            retirements: Vec::new(),
        };
        assert!(ledger.validate().is_ok());
        assert_eq!(ledger.expire(10), (vec![released_key], true));
        assert!(ledger.contexts[0].sealed);
        assert!(ledger.contexts[1].sealed);
        assert!(ledger.contexts[1].registration.is_some());
        assert!(ledger.expire(u64::MAX).0.is_empty());
        assert!(ledger.validate().is_ok());
        ledger.schema = 3;
        assert!(ledger.validate().is_err());
    }

    /// A full live reservation table compacts to bounded permanent keys and
    /// regains active capacity without forgetting any invocation.
    #[test]
    fn expired_reservations_compact_and_restore_capacity() {
        let mut ledger = Ledger {
            contexts: (0..(MAX_RECORDS / 2))
                .map(|index| {
                    let mut entry = context(&format!("inv-{index}"));
                    entry.observation.native_call_id = format!("call-{index}");
                    entry.claim_key = managed_source_key(&entry.observation);
                    entry
                })
                .collect(),
            ..Ledger::default()
        };
        assert_eq!(ledger.reserved_slots(), MAX_RECORDS);
        let (claims, changed) = ledger.expire(10);
        assert!(changed);
        assert_eq!(claims.len(), MAX_RECORDS / 2);
        ledger.compact("issuer");
        assert!(ledger.contexts.is_empty());
        assert_eq!(ledger.reserved_slots(), 0);
        assert_eq!(ledger.fences.len(), MAX_RECORDS / 2);
        assert!(ledger.validate().is_ok());
        assert!(ledger.find_fence("pool", "inv-42", None).is_some());
        assert!(
            ledger
                .find_fence("pool", "inv-42", None)
                .unwrap()
                .source_hash
                .is_some()
        );
    }

    /// Every admitted context retains space for a consume receipt and abort;
    /// orphan tombstones cannot consume those reserved slots.
    #[test]
    fn abort_capacity_is_reserved_before_context_admission() {
        let entry = context("reserved");
        let mut ledger = Ledger {
            schema: 2,
            contexts: vec![entry.clone()],
            tombstones: Vec::new(),
            fences: Vec::new(),
            retirements: Vec::new(),
        };
        let before = ledger.reserved_bytes();
        assert_eq!(ledger.reserved_slots(), 2);
        let key = Secret::new("2".repeat(64));
        ledger.contexts[0].registration = Some(Registration {
            assertion_hash: crate::server::sha256_hex(key.expose().as_bytes()),
            assertion_key: Some(key),
            security_digest: "a".repeat(64),
            audience: "consumer".into(),
            nonce: "nonce".into(),
            receipt: None,
        });
        assert!(ledger.reserved_bytes() < before);
        ledger.contexts[0].sealed = true;
        ledger.tombstones.push(Tombstone {
            producer: "pool".into(),
            consume_request_id: Some("request".into()),
            invocation_key: "reserved".into(),
            security_digest: Some("a".repeat(64)),
            audience: Some("consumer".into()),
        });
        assert_eq!(ledger.reserved_slots(), 1);
        assert_eq!(ledger.reserved_bytes(), 0);
        ledger.tombstones.push(Tombstone {
            producer: "pool".into(),
            consume_request_id: Some("other-request".into()),
            invocation_key: "other".into(),
            security_digest: Some("a".repeat(64)),
            audience: Some("consumer".into()),
        });
        assert_eq!(ledger.reserved_slots(), 2);
        assert!(ledger.validate().is_ok());
    }

    /// An exact live managed identity survives arbitrary legacy-second skew;
    /// a different start tick for that same live PID cannot replace the route.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_managed_binding_ignores_seconds_and_refuses_tick_reuse() {
        let pid = std::process::id();
        let uid = os::process_facts(pid).unwrap().uid.unwrap();
        let identity = os::attempt::kernel_incarnation(pid, uid).unwrap();
        let binding = Binding {
            address: NativeAddress::new("lab", Harness::CLAUDE_CODE, "store", "session").unwrap(),
            harness: (pid, 1),
            managed_incarnation: Some(identity.clone()),
            epoch: 9,
            capabilities: Capabilities {
                inject: false,
                message: false,
            },
            qualified: Capabilities {
                inject: false,
                message: false,
            },
            version: "fixture".into(),
            lifecycle: Lifecycle::Unknown,
            transcript: None,
            store: PathBuf::new(),
            executable: PathBuf::new(),
            retired: false,
            desktop_idle_message: false,
            desktop_idle_transcript: None,
            wake: None,
            pending: false,
            role: None,
        };
        assert_eq!(
            managed_binding_decision(Some(&binding), &identity).unwrap(),
            (false, Some(9))
        );
        let mut reused = identity;
        reused.start_ticks += 1;
        assert!(matches!(
            managed_binding_decision(Some(&binding), &reused),
            Err(CorrelationError::Conflicting(_))
        ));
    }

    /// The writer commits an expired reservation before freeing its call slot.
    #[cfg(target_os = "linux")]
    #[test]
    fn context_expiry_releases_actual_call_capacity() {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("b1-cap-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let owner = os::process_facts(std::process::id()).unwrap().uid.unwrap();
        let config = RegistryConfig {
            host_id: "lab".into(),
            harnesses: Vec::new(),
            profiles: Vec::new(),
            intermediates: Vec::new(),
            max_call_age_ms: 10,
            relays: Vec::new(),
            audiences: Vec::new(),
            run_readers: Vec::new(),
            managed_tools: Vec::new(),
            owner_v2_routes: Vec::new(),
            legacy_owner_relays: 0,
        };
        let mut registry = Registry::new(config, owner).unwrap();
        let journal = dir.join("routes.json");
        registry.attach_journal(&journal, 1).unwrap();
        registry.max_calls = 1;
        let abandoned = context("abandoned");
        let claim_key = abandoned.claim_key.clone();
        let call_id = abandoned.observation.native_call_id.clone();
        registry.record_call(
            call_id.clone(),
            CallRecord {
                harness: (42, 77),
                launch_observation: None,
                address: "lab/claude-code/store/session".into(),
                role: ActorRole::Root,
                native_id: "session".into(),
                epoch: 1,
                observed_ms: 1,
                consumed: false,
                claimed: true,
                tool_name: Some("mcp__pool__vote".into()),
                token_digest: None,
            },
        );
        registry.claims.insert(
            claim_key,
            claims::ClaimRecord {
                producer: "pool".into(),
                request_id: "abandoned".into(),
                fingerprint: "f".into(),
                source: claims::ClaimSource::Native {
                    call: call_id.clone(),
                    harness: (42, 77),
                },
            },
        );
        registry.attempt_ledger.contexts.push(abandoned);
        assert!(registry.ensure_call_capacity().is_err());
        registry.expire_attempt_contexts(10).unwrap();
        assert!(registry.ensure_call_capacity().is_ok());
        assert!(!registry.calls[&call_id][0].claimed);
        let ledger =
            LedgerFile::decode(&std::fs::read(journal.with_extension("attempts.json")).unwrap())
                .unwrap();
        assert_eq!(ledger.ledger.fences.len(), 1);
        let capacity = inspect_attempt_capacity(&dir.join("routes.sock"), owner)
            .unwrap()
            .unwrap();
        assert_eq!(capacity.fence_count, 1);
        assert_eq!(capacity.fence_slots_remaining, MAX_FENCES - 1);
        assert_eq!(
            capacity.journal_bytes_remaining,
            MAX_ROUTE_SNAPSHOT_BYTES - capacity.journal_bytes
        );
        assert!(
            inspect_attempt_capacity(&dir.join("missing.sock"), owner)
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A full or failed managed ledger never consumes route-journal capacity
    /// or poisons unrelated legacy persistence.
    #[cfg(target_os = "linux")]
    #[test]
    fn managed_capacity_and_uncertain_commit_do_not_poison_legacy_routes() {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("b1-isolate-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let owner = os::process_facts(std::process::id()).unwrap().uid.unwrap();
        let config = RegistryConfig {
            host_id: "lab".into(),
            harnesses: Vec::new(),
            profiles: Vec::new(),
            intermediates: Vec::new(),
            max_call_age_ms: 10,
            relays: Vec::new(),
            audiences: Vec::new(),
            run_readers: Vec::new(),
            managed_tools: Vec::new(),
            owner_v2_routes: Vec::new(),
            legacy_owner_relays: 0,
        };
        let mut registry = Registry::new(config, owner).unwrap();
        let journal = dir.join("routes.json");
        registry.attach_journal(&journal, 1).unwrap();
        registry.attempt_ledger.fences = (0..MAX_FENCES)
            .map(|index| Fence {
                invocation_hash: format!("{index:064x}"),
                source_hash: None,
                consume_hash: None,
                intention_hash: None,
                audience: None,
                aborted: false,
            })
            .collect();
        assert!(!registry.attempt_ledger.fence_capacity());
        registry.persist_routes().unwrap();
        let snapshot: RouteSnapshot =
            serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
        assert!(snapshot.attempts.is_none());
        assert!(std::fs::metadata(&journal).unwrap().len() < 4096);
        registry.attempt_ledger.fences.clear();
        let identity = os::attempt::KernelIncarnation {
            boot_id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
            pid_namespace_inode: 1,
            uid: owner,
            pid: 42,
            start_ticks: 7,
        };
        registry.max_calls = 1;
        registry.record_call(
            "poison-call".into(),
            CallRecord {
                harness: (42, 1),
                launch_observation: Some(os::attempt::LaunchObservation {
                    incarnation: identity.clone(),
                    launch_id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
                }),
                address: "lab/claude-code/store/session".into(),
                role: ActorRole::Root,
                native_id: "session".into(),
                epoch: 1,
                observed_ms: 1,
                consumed: false,
                claimed: true,
                tool_name: None,
                token_digest: None,
            },
        );
        registry.claims.insert(
            "poison-claim".into(),
            claims::ClaimRecord {
                producer: "pool".into(),
                request_id: "request".into(),
                fingerprint: "fingerprint".into(),
                source: claims::ClaimSource::ManagedNative {
                    call: "poison-call".into(),
                    incarnation: identity,
                },
            },
        );
        assert!(registry.ensure_call_capacity().is_err());
        registry.attempt_journal = Some(dir.join("missing-parent/attempts.json"));
        let error = registry
            .commit_attempt()
            .expect_err("uncertain managed commit");
        assert_eq!(error.recovery, "same_key_lookup");
        assert!(registry.attempt_journal_poisoned);
        assert!(registry.ensure_call_capacity().is_ok());
        assert!(registry.calls["poison-call"][0].consumed);
        registry.expire_attempt_contexts(u64::MAX).unwrap();
        registry.persist_routes().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Schema-2 embedded consumed receipts migrate atomically to the separate
    /// journal; restart removes plaintext keys but preserves historical facts.
    #[cfg(target_os = "linux")]
    #[test]
    fn schema2_consumed_receipt_migrates_and_scrubs_secrets() {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let dir = std::env::temp_dir().join(format!("b1-schema2-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let owner = os::process_facts(std::process::id()).unwrap().uid.unwrap();
        let config = RegistryConfig {
            host_id: "lab".into(),
            harnesses: Vec::new(),
            profiles: Vec::new(),
            intermediates: Vec::new(),
            max_call_age_ms: 10,
            relays: Vec::new(),
            audiences: Vec::new(),
            run_readers: Vec::new(),
            managed_tools: Vec::new(),
            owner_v2_routes: Vec::new(),
            legacy_owner_relays: 0,
        };
        let mut old_context = context("old-inv");
        let key = Secret::new("2".repeat(64));
        let receipt = Receipt {
            producer: "pool".into(),
            consume_request_id: "old-consume".into(),
            invocation_key: "old-inv".into(),
            security_digest: "a".repeat(64),
            observation: old_context.observation.clone(),
            issuer_epoch: old_context.issuer_epoch.clone(),
            consumed_at_ms: 2,
        };
        old_context.registration = Some(Registration {
            assertion_hash: crate::server::sha256_hex(key.expose().as_bytes()),
            assertion_key: Some(key),
            security_digest: "a".repeat(64),
            audience: "consumer".into(),
            nonce: "nonce".into(),
            receipt: Some(receipt.clone()),
        });
        let mut ledger = Ledger {
            schema: 1,
            ..Ledger::default()
        };
        ledger.contexts.push(old_context);
        let replay_ledger = ledger.clone();
        let path = dir.join("routes.json");
        let snapshot = RouteSnapshot {
            schema: 2,
            store_id: Some("01234567-89ab-4cde-8fab-0123456789ab".into()),
            bindings: Vec::new(),
            attempts: Some(ledger),
            #[cfg(target_os = "linux")]
            root_launches: Vec::new(),
        };
        let mut historical = serde_json::to_value(&snapshot).unwrap();
        historical["attempts"]
            .as_object_mut()
            .unwrap()
            .remove("fences");
        historical["attempts"]
            .as_object_mut()
            .unwrap()
            .remove("retirements");
        historical["attempts"]["contexts"][0]
            .as_object_mut()
            .unwrap()
            .remove("aborted");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(&serde_json::to_vec(&historical).unwrap())
            .unwrap();
        let old_route = std::fs::read(&path).unwrap();
        let separate = path.with_extension("attempts.json");
        let bad =
            LedgerFile::encode("11234567-89ab-4cde-8fab-0123456789ab", &replay_ledger).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&separate)
            .unwrap()
            .write_all(&bad)
            .unwrap();
        let mut refused = Registry::new(config.clone(), owner).unwrap();
        assert!(refused.attach_journal(&path, 3).is_ok());
        assert!(refused.attempt_journal_poisoned);
        let retained: RouteSnapshot =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(retained.schema, 2);
        let retained_ledger = retained.attempts.unwrap();
        assert!(!old_route.is_empty());
        std::fs::write(
            &separate,
            LedgerFile::encode("01234567-89ab-4cde-8fab-0123456789ab", &retained_ledger).unwrap(),
        )
        .unwrap();
        let stale = path.with_extension("new-dead");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stale)
            .unwrap()
            .write_all(b"secret")
            .unwrap();
        let stale_attempt = path
            .with_extension("attempts.json")
            .with_extension("new-dead");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stale_attempt)
            .unwrap()
            .write_all(b"secret")
            .unwrap();
        let mut registry = Registry::new(config, owner).unwrap();
        registry.attach_journal(&path, 3).unwrap();
        assert!(!stale.exists());
        assert!(!stale_attempt.exists());
        let route: RouteSnapshot = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(route.schema, 4);
        assert!(route.attempts.is_none());
        let bytes = std::fs::read(path.with_extension("attempts.json")).unwrap();
        assert!(
            !bytes.windows(64).any(|window| window
                == b"2222222222222222222222222222222222222222222222222222222222222222")
        );
        let migrated = LedgerFile::decode(&bytes).unwrap();
        assert!(migrated.ledger.contexts[0].sealed);
        assert!(migrated.ledger.contexts[0].context_ref.is_none());
        assert!(
            migrated.ledger.contexts[0]
                .registration
                .as_ref()
                .unwrap()
                .receipt
                .as_ref()
                == Some(&receipt)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The configured server and exact command both participate in matching.
    #[test]
    fn exact_tool_command_mapping() {
        let mapping = ManagedTools {
            producer: "pool".into(),
            server: "pool".into(),
            commands: vec!["vote".into()],
            frontend: RelayExecutable {
                path: "/fixture".into(),
                sha256: "a".repeat(64),
            },
        };
        assert!(tool_matches(&mapping, "pool", "vote", "mcp__pool__vote"));
        for (producer, command, tool) in [
            ("other", "vote", "mcp__pool__vote"),
            ("pool", "ready", "mcp__pool__vote"),
            ("pool", "vote", "mcp__other__vote"),
            ("pool", "vote", "mcp__pool__vote_extra"),
        ] {
            assert!(!tool_matches(&mapping, producer, command, tool));
        }
    }
}
