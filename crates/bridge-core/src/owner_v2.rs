//! Durable one-effect owner v2 custody, independent of legacy event batching.
//!
//! The authenticated adapter supplies the exact frozen intent and route. A
//! committed invoking row is never retried after a crash or uncertain write.

use crate::{CoreError, Storage};
use bridge_protocol::managed_owner::{ManagedOwnerStateV1, OutboxIntentV1, egress_intent_digest};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

/// Hard per-store retained effect bound; rows are never TTL-evicted.
pub const MAX_OWNER_EFFECTS: u64 = 65_536;
/// Maximum active and retained effects occupied by any one producer.
pub const MAX_OWNER_EFFECTS_PER_PRODUCER: u64 = 4_096;

/// Read-only managed-owner ledger headroom for one producer.
#[derive(Serialize)]
pub struct OwnerProducerCapacity {
    /// Authenticated producer identity, never a message or credential.
    pub producer: String,
    /// Retained effect rows occupying this producer's quota.
    pub used: u64,
    /// Remaining rows under the per-producer quota.
    pub remaining: u64,
}

/// Point-in-time read-only managed-owner capacity report.
#[derive(Serialize)]
pub struct OwnerCapacity {
    /// Effective per-store limit.
    pub store_limit: u64,
    /// Retained effects in the store.
    pub store_used: u64,
    /// Available rows before the store limit.
    pub store_remaining: u64,
    /// Maximum rows available to one producer.
    pub producer_limit: u64,
    /// Occupied quotas, without effect IDs or message text.
    pub producers: Vec<OwnerProducerCapacity>,
}

/// Inspects an already existing private owner ledger without migrating it or
/// creating a database. This is a point-in-time operator diagnostic only.
///
/// # Errors
///
/// The database is not a private owned file, has an unsupported schema, or
/// cannot be read without mutation.
#[cfg(unix)]
pub fn inspect_owner_capacity(
    path: &std::path::Path,
    owner_uid: u32,
    retained_limit: usize,
) -> Result<OwnerCapacity, CoreError> {
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::symlink_metadata(path)
        .map_err(|_| CoreError::Integrity("owner capacity unavailable".into()))?;
    if !before.is_file()
        || before.uid() != owner_uid
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
    {
        return Err(CoreError::Integrity("owner capacity unavailable".into()));
    }
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(std::time::Duration::from_millis(100))?;
    let after = std::fs::symlink_metadata(path)
        .map_err(|_| CoreError::Integrity("owner capacity unavailable".into()))?;
    if (
        before.dev(),
        before.ino(),
        before.uid(),
        before.mode(),
        before.nlink(),
    ) != (
        after.dev(),
        after.ino(),
        after.uid(),
        after.mode(),
        after.nlink(),
    ) {
        return Err(CoreError::Integrity("owner capacity unavailable".into()));
    }
    let schema: String = connection.query_row(
        "SELECT value FROM schema_meta WHERE key='schema_version'",
        [],
        |row| row.get(0),
    )?;
    if schema != crate::schema::SCHEMA_VERSION.to_string() {
        return Err(CoreError::Integrity("owner capacity unavailable".into()));
    }
    let mut statement = connection.prepare(
        "SELECT producer,COUNT(*) FROM managed_owner_effects GROUP BY producer ORDER BY producer",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
    })?;
    let store_limit = (retained_limit as u64).min(MAX_OWNER_EFFECTS);
    let producer_limit = MAX_OWNER_EFFECTS_PER_PRODUCER.min(store_limit);
    let mut producers = Vec::new();
    let mut total = 0_u64;
    for row in rows {
        let (producer, used) = row?;
        total = total.saturating_add(used);
        producers.push(OwnerProducerCapacity {
            producer,
            used,
            remaining: producer_limit.saturating_sub(used),
        });
    }
    let store_remaining = store_limit.saturating_sub(total);
    for producer in &mut producers {
        producer.remaining = producer.remaining.min(store_remaining);
    }
    Ok(OwnerCapacity {
        store_limit,
        store_used: total,
        store_remaining,
        producer_limit,
        producers,
    })
}

/// Frozen authenticated input for a single managed effect reservation.
pub struct OwnerEffect<'a> {
    /// Authenticated producer identity.
    pub producer: &'a str,
    /// Authenticated configured consumer audience.
    pub audience: &'a str,
    /// Original immutable outbox intent.
    pub intent: &'a OutboxIntentV1,
    /// Canonical effect digest.
    pub digest: &'a str,
    /// Original opaque Run current-receipt identity.
    pub run_receipt_id: &'a str,
    /// Hash of the immutable configured target route, excluding build pins.
    pub route_fingerprint: &'a str,
    /// Per-dispatch correlation; excluded from effect identity.
    pub call_id: &'a str,
    /// Exact message bytes; never included in diagnostics.
    pub text: &'a str,
}

/// A retained effect state; an invoking row projects to unknown on lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerEffectResult {
    /// Accepted, positively unsent, or unknown native outcome.
    pub state: ManagedOwnerStateV1,
    /// Actual native protocol for an acceptance, otherwise absent.
    pub protocol: Option<String>,
    /// Exact native receipt for an acceptance, otherwise absent.
    pub native_id: Option<String>,
    /// Finite refusal or uncertainty reason, otherwise absent.
    pub reason: Option<String>,
}

/// Immutable identity and original route needed for later authenticated
/// reconciliation. This contains no message text or producer credential.
pub struct OwnerRecoveryIdentity {
    /// Exact original outbox target and effect.
    pub intent: OutboxIntentV1,
    /// Original Run current-receipt selector.
    pub run_receipt_id: String,
    /// Hash of the originally configured Run, Pool and Bridge route.
    pub route_fingerprint: String,
}

/// One settled row eligible for scoped compaction after further verification.
pub struct OwnerCompactionCandidate {
    /// Original immutable target for authenticated Run lookup.
    pub identity: OwnerRecoveryIdentity,
    /// Frozen canonical effect digest.
    pub digest: String,
    /// Exact settled Bridge result to compare with Run and before deletion.
    pub result: OwnerEffectResult,
}

/// Reservation result: exactly one caller is allowed to start owner I/O.
pub enum OwnerReservation {
    /// A durable invoking fence was committed for this dispatch.
    Invoke,
    /// Existing accepted, invoking or unknown state; never invoke again.
    Existing(OwnerEffectResult),
}

/// Bounds a static-provenance identifier without echoing any rejected bytes.
fn identifier(value: &str) -> bool {
    bridge_protocol::validate_id("owner_effect", value, bridge_protocol::MAX_ID_BYTES).is_ok()
}

/// Validates canonical SHA-256 spelling.
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Decodes a stored terminal or invoking state, refusing malformed rows.
fn outcome(
    state: &str,
    protocol: Option<String>,
    native_id: Option<String>,
    reason: Option<String>,
) -> Result<OwnerEffectResult, CoreError> {
    let corrupt = || CoreError::Integrity("managed owner outcome malformed".into());
    let state = match state {
        "invoking" | "abort_pending" => {
            return Ok(OwnerEffectResult {
                state: ManagedOwnerStateV1::Unknown,
                protocol: None,
                native_id: None,
                reason: Some(
                    match reason.as_deref() {
                        Some("channel_failed") => "channel_failed",
                        _ => "native_uncertain",
                    }
                    .into(),
                ),
            });
        }
        "accepted" => ManagedOwnerStateV1::Accepted,
        "known_unsent" => ManagedOwnerStateV1::KnownUnsent,
        "unknown" => ManagedOwnerStateV1::Unknown,
        "aborted" => ManagedOwnerStateV1::Aborted,
        _ => return Err(corrupt()),
    };
    let valid = match (
        state,
        protocol.as_deref(),
        native_id.as_deref(),
        reason.as_deref(),
    ) {
        (
            ManagedOwnerStateV1::Accepted,
            Some("codex_turn" | "claude_input"),
            Some(native),
            None,
        ) => identifier(native),
        (
            ManagedOwnerStateV1::KnownUnsent,
            None,
            None,
            Some(
                "capability_missing"
                | "actor_mismatch"
                | "not_idle"
                | "awaiting_input"
                | "finished"
                | "budget"
                | "cancelled"
                | "unavailable"
                | "invalid_request"
                | "capacity"
                | "conflict"
                | "attempt_not_ready"
                | "attempt_mismatch"
                | "qualification_pending",
            ),
        ) => true,
        (ManagedOwnerStateV1::Unknown, None, None, Some("native_uncertain" | "channel_failed")) => {
            true
        }
        (ManagedOwnerStateV1::Aborted, None, None, None) => true,
        _ => false,
    };
    if !valid {
        return Err(corrupt());
    }
    Ok(OwnerEffectResult {
        state,
        protocol,
        native_id,
        reason,
    })
}

/// Raw selected state and immutable association from one SQLite row.
type Row = (
    String,
    String,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Reads one effect by its global scope/key uniqueness fence.
fn row(
    connection: &rusqlite::Connection,
    scope: &str,
    effect: &str,
) -> Result<Option<Row>, CoreError> {
    connection.query_row(
        "SELECT producer,audience,effect_digest,run_receipt_id,route_fingerprint,intent_json,payload,state,protocol,native_id,reason FROM managed_owner_effects WHERE producer_scope=?1 AND effect_id=?2",
        params![scope, effect],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
    ).optional().map_err(Into::into)
}

/// Refuses any new dispatch in a durably retired producer scope.
fn require_open_scope(
    connection: &rusqlite::Connection,
    producer: &str,
    scope: &str,
) -> Result<(), CoreError> {
    let closed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM delivery_scopes WHERE producer=?1 AND scope_key=?2 AND closed_ms IS NOT NULL)",
        params![producer, scope], |row| row.get(0),
    )?;
    if closed {
        return Err(CoreError::Fence("managed owner scope retired".into()));
    }
    Ok(())
}

/// Validates and serializes the exact frozen effect for durable comparison.
fn checked_effect(effect: &OwnerEffect<'_>) -> Result<Vec<u8>, CoreError> {
    effect
        .intent
        .validate(effect.text)
        .map_err(|_| CoreError::InvalidEnvelope("managed effect invalid".into()))?;
    if ![
        effect.producer,
        effect.audience,
        effect.run_receipt_id,
        effect.call_id,
    ]
    .iter()
    .all(|value| identifier(value))
        || !hash(effect.route_fingerprint)
        || !hash(effect.digest)
        || egress_intent_digest(effect.intent)
            .map_err(|_| CoreError::InvalidEnvelope("managed effect invalid".into()))?
            != effect.digest
    {
        return Err(CoreError::InvalidEnvelope("managed effect invalid".into()));
    }
    serde_json::to_vec(effect.intent)
        .map_err(|_| CoreError::InvalidEnvelope("managed effect encoding failed".into()))
}

/// Checks an existing row against the exact original effect and route.
fn same_effect(row: &Row, effect: &OwnerEffect<'_>, intent: &[u8]) -> bool {
    row.0 == effect.producer
        && row.1 == effect.audience
        && row.2 == effect.digest
        && row.3 == effect.run_receipt_id
        && row.4 == effect.route_fingerprint
        && row.5 == intent
        && row.6.is_empty()
}

impl Storage {
    /// Whether the producer scope is durably closed to new dispatches.
    ///
    /// # Errors
    ///
    /// The database cannot be read.
    pub fn owner_v2_scope_retired(&self, producer: &str, scope: &str) -> Result<bool, CoreError> {
        self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM delivery_scopes WHERE producer=?1 AND scope_key=?2 AND closed_ms IS NOT NULL)",
            params![producer, scope], |row| row.get(0),
        ).map_err(Into::into)
    }

    /// Selects only terminal candidates in a retired scope. Unknown,
    /// invoking and abort-pending rows are never candidates.
    ///
    /// # Errors
    ///
    /// The scope is not retired or a stored row is invalid or unreadable.
    pub fn owner_v2_compaction_candidates(
        &self,
        producer: &str,
        audience: &str,
        scope: &str,
    ) -> Result<Vec<OwnerCompactionCandidate>, CoreError> {
        if !self.owner_v2_scope_retired(producer, scope)? {
            return Err(CoreError::Fence("managed owner scope not retired".into()));
        }
        let keys = {
            let mut statement = self.connection.prepare(
                "SELECT effect_id,effect_digest FROM managed_owner_effects WHERE producer=?1 AND audience=?2 AND producer_scope=?3 AND state IN ('accepted','aborted','known_unsent') ORDER BY effect_id",
            )?;
            let rows = statement.query_map(params![producer, audience, scope], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        keys.into_iter()
            .map(|(effect, digest)| {
                let identity = self
                    .owner_v2_recovery_identity(producer, audience, scope, &effect, &digest)?
                    .ok_or_else(|| CoreError::Integrity("managed effect missing".into()))?;
                let result = self
                    .owner_v2_lookup(producer, audience, scope, &effect, &digest)?
                    .ok_or_else(|| CoreError::Integrity("managed effect missing".into()))?;
                Ok(OwnerCompactionCandidate {
                    identity,
                    digest,
                    result,
                })
            })
            .collect()
    }

    /// Removes one still-identical terminal row in a retired scope. Before
    /// calling this for accepted or aborted, the caller must authenticate an
    /// identical exact-key durable Run result. The permanent scope fence stays.
    ///
    /// # Errors
    ///
    /// The scope or result is invalid, changed, or the commit fails.
    pub fn owner_v2_compact_candidate(
        &mut self,
        producer: &str,
        audience: &str,
        scope: &str,
        effect: &str,
        digest: &str,
        expected: &OwnerEffectResult,
    ) -> Result<bool, CoreError> {
        if !matches!(
            expected.state,
            ManagedOwnerStateV1::Accepted
                | ManagedOwnerStateV1::Aborted
                | ManagedOwnerStateV1::KnownUnsent
        ) {
            return Err(CoreError::InvalidEnvelope(
                "unsettled managed effect".into(),
            ));
        }
        let tx = self.begin()?;
        let closed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM delivery_scopes WHERE producer=?1 AND scope_key=?2 AND closed_ms IS NOT NULL)",
            params![producer, scope], |row| row.get(0),
        )?;
        if !closed {
            return Err(CoreError::Fence("managed owner scope not retired".into()));
        }
        let Some(existing) = row(&tx, scope, effect)? else {
            tx.commit()?;
            return Ok(false);
        };
        if existing.0 != producer || existing.1 != audience || existing.2 != digest {
            return Err(CoreError::Fence("managed effect identity conflict".into()));
        }
        if !matches!(existing.7.as_str(), "accepted" | "aborted" | "known_unsent")
            || outcome(&existing.7, existing.8, existing.9, existing.10)? != *expected
        {
            tx.commit()?;
            return Ok(false);
        }
        let count = tx.execute(
            "DELETE FROM managed_owner_effects WHERE producer=?1 AND audience=?2 AND producer_scope=?3 AND effect_id=?4 AND effect_digest=?5",
            params![producer, audience, scope, effect, digest],
        )?;
        tx.commit()?;
        Ok(count == 1)
    }

    /// Counts retained rows for an authenticated producer, audience and scope.
    ///
    /// # Errors
    ///
    /// The database cannot be read.
    pub fn owner_v2_scope_count(
        &self,
        producer: &str,
        audience: &str,
        scope: &str,
    ) -> Result<u64, CoreError> {
        self.connection.query_row(
            "SELECT COUNT(*) FROM managed_owner_effects WHERE producer=?1 AND audience=?2 AND producer_scope=?3",
            params![producer, audience, scope], |row| row.get(0),
        ).map_err(Into::into)
    }
    /// Reads the immutable target required to reconcile an existing effect.
    /// No payload is returned and a corrupted association refuses.
    ///
    /// # Errors
    ///
    /// The authenticated identity, digest, stored content or database is invalid.
    pub fn owner_v2_recovery_identity(
        &self,
        producer: &str,
        audience: &str,
        scope: &str,
        effect: &str,
        digest: &str,
    ) -> Result<Option<OwnerRecoveryIdentity>, CoreError> {
        let Some((
            old_producer,
            old_audience,
            old_digest,
            receipt,
            route,
            raw_intent,
            payload,
            _,
            _,
            _,
            _,
        )) = row(&self.connection, scope, effect)?
        else {
            return Ok(None);
        };
        if old_producer != producer || old_audience != audience || old_digest != digest {
            return Err(CoreError::Fence("managed effect identity conflict".into()));
        }
        let invalid = || CoreError::Integrity("managed effect identity malformed".into());
        let intent: OutboxIntentV1 = serde_json::from_slice(&raw_intent).map_err(|_| invalid())?;
        if intent.producer_scope != scope
            || intent.effect_id != effect
            || !hash(&route)
            || !identifier(&receipt)
            || !payload.is_empty()
            || !hash(&intent.payload_sha256)
            || intent.payload_length > bridge_protocol::managed_owner::MAX_OWNER_TEXT_BYTES as u64
            || egress_intent_digest(&intent).map_err(|_| invalid())? != digest
        {
            return Err(invalid());
        }
        Ok(Some(OwnerRecoveryIdentity {
            intent,
            run_receipt_id: receipt,
            route_fingerprint: route,
        }))
    }

    /// Looks up the original durable result for an authenticated producer and
    /// audience. Absence is a snapshot, not a delayed-dispatch fence.
    ///
    /// # Errors
    ///
    /// The stored association conflicts, is malformed, or storage is unavailable.
    pub fn owner_v2_lookup(
        &self,
        producer: &str,
        audience: &str,
        scope: &str,
        effect: &str,
        digest: &str,
    ) -> Result<Option<OwnerEffectResult>, CoreError> {
        if ![producer, audience, scope, effect]
            .iter()
            .all(|value| identifier(value))
            || !hash(digest)
        {
            return Err(CoreError::InvalidEnvelope(
                "managed effect identity invalid".into(),
            ));
        }
        let Some((
            old_producer,
            old_audience,
            old_digest,
            _,
            _,
            _,
            _,
            state,
            protocol,
            native_id,
            reason,
        )) = row(&self.connection, scope, effect)?
        else {
            return Ok(None);
        };
        if old_producer != producer || old_audience != audience || old_digest != digest {
            return Err(CoreError::Fence("managed effect identity conflict".into()));
        }
        Ok(Some(outcome(&state, protocol, native_id, reason)?))
    }

    /// Commits the invoking fence before any possible owner I/O. An exact
    /// known-unsent effect can be re-reserved; accepted, invoking and unknown
    /// effects only return their original state and never start another write.
    ///
    /// # Errors
    ///
    /// Validation, capacity, frozen identity, admission or the commit failed.
    /// A commit error is uncertain and must be reconciled by the same key.
    pub fn owner_v2_reserve(
        &mut self,
        effect: &OwnerEffect<'_>,
    ) -> Result<OwnerReservation, CoreError> {
        let intent = checked_effect(effect)?;
        let limit = self
            .limits()
            .max_retained_events
            .min(MAX_OWNER_EFFECTS as usize) as u64;
        let (tx, admission) = self.begin_admission()?;
        if let Some(existing) = row(&tx, &effect.intent.producer_scope, &effect.intent.effect_id)? {
            if existing.4 != effect.route_fingerprint {
                return Err(CoreError::Fence(
                    "managed owner target route changed".into(),
                ));
            }
            if !same_effect(&existing, effect, &intent) {
                return Err(CoreError::Fence("managed effect identity conflict".into()));
            }
            let previous = outcome(&existing.7, existing.8, existing.9, existing.10)?;
            if previous.state != ManagedOwnerStateV1::KnownUnsent {
                tx.commit()?;
                return Ok(OwnerReservation::Existing(previous));
            }
            admission.check_ingress()?;
            require_open_scope(&tx, effect.producer, &effect.intent.producer_scope)?;
            tx.execute("UPDATE managed_owner_effects SET state='invoking',call_id=?1,protocol=NULL,native_id=NULL,reason=NULL WHERE producer_scope=?2 AND effect_id=?3 AND state='known_unsent'", params![effect.call_id, effect.intent.producer_scope, effect.intent.effect_id])?;
        } else {
            admission.check_ingress()?;
            require_open_scope(&tx, effect.producer, &effect.intent.producer_scope)?;
            let count: u64 =
                tx.query_row("SELECT COUNT(*) FROM managed_owner_effects", [], |row| {
                    row.get(0)
                })?;
            let producer_count: u64 = tx.query_row(
                "SELECT COUNT(*) FROM managed_owner_effects WHERE producer=?1",
                params![effect.producer],
                |row| row.get(0),
            )?;
            if count >= limit || producer_count >= MAX_OWNER_EFFECTS_PER_PRODUCER {
                return Err(CoreError::Capacity {
                    limit: "managed owner effect capacity".into(),
                });
            }
            tx.execute("INSERT INTO managed_owner_effects(producer_scope,effect_id,producer,audience,effect_digest,run_receipt_id,route_fingerprint,intent_json,payload,state,call_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,X'','invoking',?9)", params![effect.intent.producer_scope, effect.intent.effect_id, effect.producer, effect.audience, effect.digest, effect.run_receipt_id, effect.route_fingerprint, intent, effect.call_id])?;
        }
        tx.commit()?;
        Ok(OwnerReservation::Invoke)
    }

    /// Durably fences local new/late dispatch before asking Run to abort the
    /// original effect. An absent effect receives a permanent local intention;
    /// a pending abort is replayable only with the same complete association.
    ///
    /// # Errors
    ///
    /// Validation, identity conflict, capacity or the durable commit failed.
    pub fn owner_v2_begin_abort(
        &mut self,
        effect: &OwnerEffect<'_>,
    ) -> Result<OwnerReservation, CoreError> {
        let intent = checked_effect(effect)?;
        let limit = self
            .limits()
            .max_retained_events
            .min(MAX_OWNER_EFFECTS as usize) as u64;
        let tx = self.begin()?;
        if let Some(existing) = row(&tx, &effect.intent.producer_scope, &effect.intent.effect_id)? {
            if existing.4 != effect.route_fingerprint {
                return Err(CoreError::Fence(
                    "managed owner target route changed".into(),
                ));
            }
            if !same_effect(&existing, effect, &intent) {
                return Err(CoreError::Fence("managed effect identity conflict".into()));
            }
            let previous = outcome(&existing.7, existing.8, existing.9, existing.10)?;
            if matches!(
                previous.state,
                ManagedOwnerStateV1::Accepted | ManagedOwnerStateV1::Aborted
            ) {
                tx.commit()?;
                return Ok(OwnerReservation::Existing(previous));
            }
            tx.execute("UPDATE managed_owner_effects SET state='abort_pending',protocol=NULL,native_id=NULL,reason=CASE WHEN state IN ('unknown','abort_pending') THEN reason ELSE NULL END WHERE producer_scope=?1 AND effect_id=?2", params![effect.intent.producer_scope, effect.intent.effect_id])?;
        } else {
            require_open_scope(&tx, effect.producer, &effect.intent.producer_scope)?;
            let count: u64 =
                tx.query_row("SELECT COUNT(*) FROM managed_owner_effects", [], |row| {
                    row.get(0)
                })?;
            let producer_count: u64 = tx.query_row(
                "SELECT COUNT(*) FROM managed_owner_effects WHERE producer=?1",
                params![effect.producer],
                |row| row.get(0),
            )?;
            if count >= limit || producer_count >= MAX_OWNER_EFFECTS_PER_PRODUCER {
                return Err(CoreError::Capacity {
                    limit: "managed owner effect capacity".into(),
                });
            }
            tx.execute("INSERT INTO managed_owner_effects(producer_scope,effect_id,producer,audience,effect_digest,run_receipt_id,route_fingerprint,intent_json,payload,state,call_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,X'','abort_pending',?9)", params![effect.intent.producer_scope, effect.intent.effect_id, effect.producer, effect.audience, effect.digest, effect.run_receipt_id, effect.route_fingerprint, intent, effect.call_id])?;
        }
        tx.commit()?;
        Ok(OwnerReservation::Invoke)
    }

    /// Rechecks the original caller's invoking fence immediately before the
    /// owner write. The caller must hold its custody lock around this read.
    ///
    /// # Errors
    ///
    /// The identity or database is invalid or unavailable.
    pub fn owner_v2_invoking(
        &self,
        scope: &str,
        effect: &str,
        call_id: &str,
    ) -> Result<bool, CoreError> {
        if ![scope, effect, call_id]
            .iter()
            .all(|value| identifier(value))
        {
            return Err(CoreError::InvalidEnvelope(
                "managed effect identity invalid".into(),
            ));
        }
        self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_owner_effects WHERE producer_scope=?1 AND effect_id=?2 AND call_id=?3 AND state='invoking')",
            params![scope, effect, call_id], |row| row.get(0),
        ).map_err(Into::into)
    }

    /// Commits an authenticated, exact-key Run result. The caller must first
    /// verify the pinned peer, route, store, digest and Run's writer fence.
    /// Only accepted, aborted and unknown results may change local state.
    /// Contradictory terminal results fail closed and never reopen dispatch.
    ///
    /// # Errors
    ///
    /// The association, result shape, terminal history or durable commit fails.
    pub fn owner_v2_apply_run_result(
        &mut self,
        scope: &str,
        effect: &str,
        digest: &str,
        result: &OwnerEffectResult,
    ) -> Result<OwnerEffectResult, CoreError> {
        if ![scope, effect].iter().all(|value| identifier(value)) || !hash(digest) {
            return Err(CoreError::InvalidEnvelope(
                "managed effect identity invalid".into(),
            ));
        }
        let state = match result.state {
            ManagedOwnerStateV1::Accepted => "accepted",
            ManagedOwnerStateV1::Unknown => "unknown",
            ManagedOwnerStateV1::Aborted => "aborted",
            ManagedOwnerStateV1::KnownUnsent => {
                return Err(CoreError::InvalidEnvelope("unfenced Run state".into()));
            }
        };
        outcome(
            state,
            result.protocol.clone(),
            result.native_id.clone(),
            result.reason.clone(),
        )?;
        let tx = self.begin()?;
        let existing = row(&tx, scope, effect)?
            .ok_or_else(|| CoreError::Fence("managed effect missing".into()))?;
        if existing.2 != digest {
            return Err(CoreError::Fence("managed effect identity conflict".into()));
        }
        let previous = outcome(&existing.7, existing.8, existing.9, existing.10)?;
        match (previous.state, result.state) {
            (ManagedOwnerStateV1::Accepted, ManagedOwnerStateV1::Accepted)
                if previous == *result =>
            {
                tx.commit()?;
                return Ok(previous);
            }
            (ManagedOwnerStateV1::Accepted, ManagedOwnerStateV1::Unknown)
            | (ManagedOwnerStateV1::Aborted, ManagedOwnerStateV1::Unknown)
            | (ManagedOwnerStateV1::Unknown, ManagedOwnerStateV1::Unknown)
            | (ManagedOwnerStateV1::Aborted, ManagedOwnerStateV1::Aborted) => {
                tx.commit()?;
                return Ok(previous);
            }
            (ManagedOwnerStateV1::Accepted | ManagedOwnerStateV1::Aborted, _) => {
                return Err(CoreError::Integrity(
                    "managed owner terminal contradiction".into(),
                ));
            }
            _ => (),
        }
        tx.execute("UPDATE managed_owner_effects SET state=?1,protocol=?2,native_id=?3,reason=?4 WHERE producer_scope=?5 AND effect_id=?6 AND effect_digest=?7",
            params![state, result.protocol, result.native_id, result.reason, scope, effect, digest])?;
        tx.commit()?;
        Ok(result.clone())
    }

    /// Durably records one correlated owner result against its invoking call.
    ///
    /// # Errors
    ///
    /// The result shape is invalid, the invoking fence changed, or commit failed.
    /// A failed commit never grants permission to issue a second native write.
    pub fn owner_v2_finish(
        &mut self,
        scope: &str,
        effect: &str,
        call_id: &str,
        result: &OwnerEffectResult,
    ) -> Result<(), CoreError> {
        if ![scope, effect, call_id]
            .iter()
            .all(|value| identifier(value))
        {
            return Err(CoreError::InvalidEnvelope(
                "managed effect identity invalid".into(),
            ));
        }
        let state = match result.state {
            ManagedOwnerStateV1::Accepted => "accepted",
            ManagedOwnerStateV1::KnownUnsent => "known_unsent",
            ManagedOwnerStateV1::Unknown => "unknown",
            ManagedOwnerStateV1::Aborted => {
                return Err(CoreError::InvalidEnvelope(
                    "owner abort requires Run fence".into(),
                ));
            }
        };
        outcome(
            state,
            result.protocol.clone(),
            result.native_id.clone(),
            result.reason.clone(),
        )?;
        let tx = self.begin()?;
        let may_finish_abort = result.state != ManagedOwnerStateV1::KnownUnsent;
        let count = tx.execute("UPDATE managed_owner_effects SET state=CASE WHEN state='abort_pending' AND ?1='unknown' THEN 'abort_pending' ELSE ?1 END,protocol=?2,native_id=?3,reason=?4 WHERE producer_scope=?5 AND effect_id=?6 AND call_id=?7 AND (state='invoking' OR (state='abort_pending' AND ?8))", params![state, result.protocol, result.native_id, result.reason, scope, effect, call_id, may_finish_abort])?;
        if count != 1 {
            return Err(CoreError::Fence(
                "managed effect invoking fence changed".into(),
            ));
        }
        tx.commit()?;
        Ok(())
    }
}
