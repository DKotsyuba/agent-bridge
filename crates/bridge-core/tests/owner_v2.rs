//! Synthetic durable owner effect custody, including migration and restart.
use crate::common;

use bridge_core::{
    Limits, Storage,
    owner_v2::{OwnerEffect, OwnerEffectResult, OwnerReservation},
};
use bridge_protocol::{
    attempt::{ActorRoleV1, ActorV1, IncarnationV1},
    managed_owner::*,
};
use sha2::{Digest, Sha256};

/// One valid frozen synthetic target and message intent.
fn intent() -> OutboxIntentV1 {
    let bridge_store = "01234567-89ab-4cde-8fab-0123456789ab";
    let bridge_route = RouteV1 {
        component_store_id: bridge_store.into(),
        route_id: "bridge".into(),
        worker_uid: 1000,
    };
    OutboxIntentV1 {
        effect_id: "effect-a".into(),
        producer_scope: "pool-scope".into(),
        event_key: "event".into(),
        payload_sha256: format!("{:x}", Sha256::digest(b"synthetic message")),
        payload_length: 17,
        target_binding: BindingV1 {
            pool_store_id: "pool-store".into(),
            pool_id: "pool".into(),
            member_id: "member".into(),
            binding_generation: 1,
            attempt: AttemptRefV1 {
                run_store_id: "store_run".into(),
                lineage_root_id: "root".into(),
                execution_id: "execution".into(),
                sequence: 1,
                attempt_id: "attempt".into(),
                launch_id: bridge_store.into(),
            },
            actor: ActorV1 {
                address: "lab/codex/store/session".into(),
                role: ActorRoleV1::Root,
                native_id: "session".into(),
                epoch: 1,
            },
            run_route: RouteV1 {
                component_store_id: "store_run".into(),
                route_id: "run".into(),
                worker_uid: 1000,
            },
            bridge_route: bridge_route.clone(),
        },
        expected_incarnation: IncarnationV1 {
            host_id: "lab".into(),
            boot_id: bridge_store.into(),
            pid_namespace_inode: 2,
            uid: 1000,
            pid: 42,
            start_ticks: 7,
        },
        bridge_route,
        mode: ManagedModeV1::Message,
        retention: ManagedRetentionV1::KeepAll,
    }
}

/// Builds an exact reservation without leaking the fixture body into diagnostics.
fn effect<'a>(
    intent: &'a OutboxIntentV1,
    digest: &'a str,
    route: &'a str,
    call: &'a str,
) -> OwnerEffect<'a> {
    OwnerEffect {
        producer: "pool",
        audience: "backend",
        intent,
        digest,
        run_receipt_id: "receipt",
        route_fingerprint: route,
        call_id: call,
        text: "synthetic message",
    }
}

/// A crash after invoking becomes unknown across restart and cannot re-invoke;
/// a later attempt cannot change effect digest, content, target, route or owner.
#[test]
fn invoking_survives_restart_without_redispatch() {
    let dir = common::TempDir::new("owner-v2");
    let path = dir.path("custody.db");
    let intent = intent();
    let digest = egress_intent_digest(&intent).unwrap();
    let route = "a".repeat(64);
    {
        let mut store = Storage::open(&path, Limits::new(10)).unwrap();
        assert!(matches!(
            store
                .owner_v2_reserve(&effect(&intent, &digest, &route, "call-a"))
                .unwrap(),
            OwnerReservation::Invoke
        ));
    }
    let mut store = Storage::open(&path, Limits::new(10)).unwrap();
    assert_eq!(
        store
            .owner_v2_lookup("pool", "backend", "pool-scope", "effect-a", &digest)
            .unwrap()
            .unwrap()
            .state,
        ManagedOwnerStateV1::Unknown
    );
    let recovery = store
        .owner_v2_recovery_identity("pool", "backend", "pool-scope", "effect-a", &digest)
        .unwrap()
        .unwrap();
    assert_eq!(recovery.intent, intent);
    assert_eq!(recovery.run_receipt_id, "receipt");
    assert_eq!(recovery.route_fingerprint, route);
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&intent, &digest, &route, "call-b"))
            .unwrap(),
        OwnerReservation::Existing(OwnerEffectResult {
            state: ManagedOwnerStateV1::Unknown,
            ..
        })
    ));
    let mut changed = intent.clone();
    changed.target_binding.binding_generation += 1;
    let changed_digest = egress_intent_digest(&changed).unwrap();
    assert!(
        store
            .owner_v2_reserve(&effect(&changed, &changed_digest, &route, "call-c"))
            .is_err()
    );
    assert!(
        store
            .owner_v2_reserve(&effect(&intent, &digest, &"b".repeat(64), "call-c"))
            .is_err()
    );
}

/// A known-unsent terminal result may reserve the same effect under a new
/// dispatch ID; an accepted terminal result cannot invoke again.
#[test]
fn known_unsent_same_effect_can_retry_but_acceptance_cannot() {
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    let intent = intent();
    let digest = egress_intent_digest(&intent).unwrap();
    let route = "a".repeat(64);
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&intent, &digest, &route, "call-a"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    store
        .owner_v2_finish(
            "pool-scope",
            "effect-a",
            "call-a",
            &OwnerEffectResult {
                state: ManagedOwnerStateV1::KnownUnsent,
                protocol: None,
                native_id: None,
                reason: Some("not_idle".into()),
            },
        )
        .unwrap();
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&intent, &digest, &route, "call-b"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    assert!(
        store
            .owner_v2_finish(
                "pool-scope",
                "effect-a",
                "call-a",
                &OwnerEffectResult {
                    state: ManagedOwnerStateV1::KnownUnsent,
                    protocol: None,
                    native_id: None,
                    reason: Some("not_idle".into())
                }
            )
            .is_err()
    );
    store
        .owner_v2_finish(
            "pool-scope",
            "effect-a",
            "call-b",
            &OwnerEffectResult {
                state: ManagedOwnerStateV1::Accepted,
                protocol: Some("codex_turn".into()),
                native_id: Some("native-turn".into()),
                reason: None,
            },
        )
        .unwrap();
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&intent, &digest, &route, "call-c"))
            .unwrap(),
        OwnerReservation::Existing(OwnerEffectResult {
            state: ManagedOwnerStateV1::Accepted,
            ..
        })
    ));
}

/// A real schema-seven database migrates additively, preserving old custody.
#[test]
fn schema_seven_gains_empty_owner_ledger_without_changing_events() {
    let dir = common::TempDir::new("owner-v2-migrate");
    let path = dir.path("custody.db");
    let old = common::keep_all(
        "agent-run",
        "old-event",
        &common::codex("session"),
        bridge_core::Mode::Message,
    );
    {
        let mut store = Storage::open(&path, Limits::new(10)).unwrap();
        store.register_source_tag("agent-run", "agent-run").unwrap();
        store.publish(&old, 1_000).unwrap();
    }
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("DROP TABLE managed_owner_effects; UPDATE schema_meta SET value='7' WHERE key='schema_version';").unwrap();
    }
    let mut store = Storage::open(&path, Limits::new(10)).unwrap();
    assert!(store.publish(&old, 1_001).unwrap().receipt.replayed);
    assert!(
        store
            .owner_v2_lookup("pool", "backend", "pool-scope", "effect-a", &"a".repeat(64))
            .unwrap()
            .is_none()
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let schema: String = connection
        .query_row(
            "SELECT value FROM schema_meta WHERE key='schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema, "9");
}

/// Scope retirement accounts for possible owner effects, retains their
/// outcomes, and refuses both new effects and known-unsent re-reservations.
#[test]
fn scope_retirement_fences_new_dispatch_and_preserves_unknown() {
    use bridge_core::{GrantConfig, ProducerAuthorizer, ProducerPolicy};
    use bridge_protocol::{RetireDeliveryScopeParams, RetirementAction};
    use std::sync::Arc;
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    let grant = GrantConfig {
        token: "synthetic-scope-token".into(),
        publisher: "pool".into(),
        recipients: vec!["*".into()],
        kinds: vec!["*".into()],
        modes: vec!["message".into()],
        policies: vec!["keep_all".into()],
        admin: false,
        managed_feedback: false,
        diagnostics: false,
        producer_v1: Some(ProducerPolicy {
            delivery_scopes: true,
            ..ProducerPolicy::default()
        }),
    };
    store
        .install_producer_authorizer(Arc::new(ProducerAuthorizer::new(&[grant]).unwrap()))
        .unwrap();
    let unknown = intent();
    let unknown_digest = egress_intent_digest(&unknown).unwrap();
    let route = "a".repeat(64);
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&unknown, &unknown_digest, &route, "call-a"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    let mut unsent = intent();
    unsent.effect_id = "effect-b".into();
    let unsent_digest = egress_intent_digest(&unsent).unwrap();
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&unsent, &unsent_digest, &route, "call-b"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    store
        .owner_v2_finish(
            "pool-scope",
            "effect-b",
            "call-b",
            &OwnerEffectResult {
                state: ManagedOwnerStateV1::KnownUnsent,
                protocol: None,
                native_id: None,
                reason: Some("not_idle".into()),
            },
        )
        .unwrap();
    let retirement = store
        .retire_delivery_scope(
            "synthetic-scope-token",
            "retire",
            &RetireDeliveryScopeParams {
                scope_key: "pool-scope".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1_000,
        )
        .unwrap();
    assert_eq!(retirement.receipt.preserved_possible_effect, 1);
    assert_eq!(retirement.receipt.already_terminal, 1);
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&unknown, &unknown_digest, &route, "later-a"))
            .unwrap(),
        OwnerReservation::Existing(OwnerEffectResult {
            state: ManagedOwnerStateV1::Unknown,
            ..
        })
    ));
    assert!(
        store
            .owner_v2_reserve(&effect(&unsent, &unsent_digest, &route, "later-b"))
            .is_err()
    );
    assert!(matches!(
        store
            .owner_v2_begin_abort(&effect(&unsent, &unsent_digest, &route, "abort-retired"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    let mut new_effect = intent();
    new_effect.effect_id = "effect-c".into();
    let new_digest = egress_intent_digest(&new_effect).unwrap();
    assert!(
        store
            .owner_v2_reserve(&effect(&new_effect, &new_digest, &route, "later-c"))
            .is_err()
    );
}

/// Concurrent same-effect dispatches serialize at the durable invoking fence;
/// at most one caller is authorized to contact the native owner.
#[test]
fn concurrent_dispatch_reserves_only_one_native_write() {
    use std::sync::{Arc, Barrier, Mutex};
    let store = Arc::new(Mutex::new(
        Storage::open_in_memory(Limits::new(10)).unwrap(),
    ));
    let barrier = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        let workers: Vec<_> = ["call-a", "call-b"]
            .into_iter()
            .map(|call| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let intent = intent();
                    let digest = egress_intent_digest(&intent).unwrap();
                    let route = "a".repeat(64);
                    barrier.wait();
                    matches!(
                        store
                            .lock()
                            .unwrap()
                            .owner_v2_reserve(&effect(&intent, &digest, &route, call))
                            .unwrap(),
                        OwnerReservation::Invoke
                    )
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|invoke| **invoke).count(), 1);
}

/// An abort is durably fenced before a late publisher can reserve; only a
/// writer-fenced Run result can turn the pending intention into aborted.
#[test]
fn abort_before_publish_and_lost_run_ack_are_permanent_fences() {
    let dir = common::TempDir::new("owner-v2-abort");
    let path = dir.path("custody.db");
    let intent = intent();
    let digest = egress_intent_digest(&intent).unwrap();
    let route = "a".repeat(64);
    {
        let mut store = Storage::open(&path, Limits::new(10)).unwrap();
        assert!(matches!(
            store
                .owner_v2_begin_abort(&effect(&intent, &digest, &route, "abort-a"))
                .unwrap(),
            OwnerReservation::Invoke
        ));
        assert!(matches!(
            store
                .owner_v2_reserve(&effect(&intent, &digest, &route, "late-publish"))
                .unwrap(),
            OwnerReservation::Existing(OwnerEffectResult {
                state: ManagedOwnerStateV1::Unknown,
                ..
            })
        ));
    }
    let mut store = Storage::open(&path, Limits::new(10)).unwrap();
    assert!(matches!(
        store
            .owner_v2_begin_abort(&effect(&intent, &digest, &route, "abort-replay"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    let aborted = OwnerEffectResult {
        state: ManagedOwnerStateV1::Aborted,
        protocol: None,
        native_id: None,
        reason: None,
    };
    assert_eq!(
        store
            .owner_v2_apply_run_result("pool-scope", "effect-a", &digest, &aborted)
            .unwrap(),
        aborted
    );
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&intent, &digest, &route, "late-again"))
            .unwrap(),
        OwnerReservation::Existing(OwnerEffectResult {
            state: ManagedOwnerStateV1::Aborted,
            ..
        })
    ));
    assert!(matches!(
        store
            .owner_v2_begin_abort(&effect(&intent, &digest, &route, "abort-again"))
            .unwrap(),
        OwnerReservation::Existing(OwnerEffectResult {
            state: ManagedOwnerStateV1::Aborted,
            ..
        })
    ));
}

/// A concurrent original writer's accepted result is never overwritten by an
/// older abort response, and an unfenced known-unsent result cannot reopen it.
#[test]
fn abort_and_writer_race_preserve_terminal_evidence() {
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    let intent = intent();
    let digest = egress_intent_digest(&intent).unwrap();
    let route = "a".repeat(64);
    assert!(matches!(
        store
            .owner_v2_reserve(&effect(&intent, &digest, &route, "dispatch"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    assert!(matches!(
        store
            .owner_v2_begin_abort(&effect(&intent, &digest, &route, "abort"))
            .unwrap(),
        OwnerReservation::Invoke
    ));
    let unsent = OwnerEffectResult {
        state: ManagedOwnerStateV1::KnownUnsent,
        protocol: None,
        native_id: None,
        reason: Some("qualification_pending".into()),
    };
    assert!(
        store
            .owner_v2_finish("pool-scope", "effect-a", "dispatch", &unsent)
            .is_err()
    );
    let accepted = OwnerEffectResult {
        state: ManagedOwnerStateV1::Accepted,
        protocol: Some("codex_turn".into()),
        native_id: Some("native-turn".into()),
        reason: None,
    };
    store
        .owner_v2_finish("pool-scope", "effect-a", "dispatch", &accepted)
        .unwrap();
    let unknown = OwnerEffectResult {
        state: ManagedOwnerStateV1::Unknown,
        protocol: None,
        native_id: None,
        reason: Some("native_uncertain".into()),
    };
    assert_eq!(
        store
            .owner_v2_apply_run_result("pool-scope", "effect-a", &digest, &unknown)
            .unwrap(),
        accepted
    );
    let aborted = OwnerEffectResult {
        state: ManagedOwnerStateV1::Aborted,
        protocol: None,
        native_id: None,
        reason: None,
    };
    assert!(
        store
            .owner_v2_apply_run_result("pool-scope", "effect-a", &digest, &aborted)
            .is_err()
    );
    assert_eq!(
        store
            .owner_v2_lookup("pool", "backend", "pool-scope", "effect-a", &digest)
            .unwrap()
            .unwrap(),
        accepted
    );
}

/// A pending abort closes the final pre-write check and keeps its original
/// unknown reason and marker when an in-flight writer finishes uncertainly.
#[test]
fn abort_preserves_unknown_reason_and_prevents_the_invoking_check() {
    let dir = common::TempDir::new("owner-abort-reason");
    let path = dir.path("owner.db");
    let mut store = Storage::open(&path, Limits::new(10)).unwrap();
    let intent = intent();
    let digest = egress_intent_digest(&intent).unwrap();
    let route = "a".repeat(64);
    store
        .owner_v2_reserve(&effect(&intent, &digest, &route, "call"))
        .unwrap();
    assert!(
        store
            .owner_v2_invoking("pool-scope", "effect-a", "call")
            .unwrap()
    );
    let unknown = OwnerEffectResult {
        state: ManagedOwnerStateV1::Unknown,
        protocol: None,
        native_id: None,
        reason: Some("channel_failed".into()),
    };
    store
        .owner_v2_finish("pool-scope", "effect-a", "call", &unknown)
        .unwrap();
    store
        .owner_v2_begin_abort(&effect(&intent, &digest, &route, "abort"))
        .unwrap();
    assert!(
        !store
            .owner_v2_invoking("pool-scope", "effect-a", "call")
            .unwrap()
    );
    assert_eq!(
        store
            .owner_v2_lookup("pool", "backend", "pool-scope", "effect-a", &digest)
            .unwrap()
            .unwrap(),
        unknown
    );
    store
        .owner_v2_finish("pool-scope", "effect-a", "call", &unknown)
        .unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    let state: String = sql
        .query_row("SELECT state FROM managed_owner_effects", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(state, "abort_pending");
    assert_eq!(
        store
            .owner_v2_lookup("pool", "backend", "pool-scope", "effect-a", &digest)
            .unwrap()
            .unwrap(),
        unknown
    );
}

/// One producer cannot exhaust another's quota, and no message text is
/// retained in the managed-owner ledger.
#[test]
fn producer_capacity_is_isolated_and_payload_is_not_stored() {
    use bridge_core::owner_v2::MAX_OWNER_EFFECTS_PER_PRODUCER;
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    let route = "a".repeat(64);
    for number in 0..MAX_OWNER_EFFECTS_PER_PRODUCER {
        let mut intent = intent();
        intent.effect_id = format!("effect-{number}");
        let digest = egress_intent_digest(&intent).unwrap();
        assert!(matches!(
            store
                .owner_v2_reserve(&effect(&intent, &digest, &route, "call"))
                .unwrap(),
            OwnerReservation::Invoke
        ));
    }
    let mut extra = intent();
    extra.effect_id = "extra".into();
    let digest = egress_intent_digest(&extra).unwrap();
    assert!(matches!(
        store.owner_v2_reserve(&effect(&extra, &digest, &route, "call")),
        Err(bridge_core::CoreError::Capacity { .. })
    ));
    let mut other = effect(&extra, &digest, &route, "call");
    other.producer = "another-producer";
    assert!(matches!(
        store.owner_v2_reserve(&other).unwrap(),
        OwnerReservation::Invoke
    ));
    let dir = common::TempDir::new("owner-quota");
    let path = dir.path("owner.db");
    let mut file_store = Storage::open(&path, Limits::new(10)).unwrap();
    file_store
        .owner_v2_reserve(&effect(&extra, &digest, &route, "call"))
        .unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    let retained_text: u64 = sql
        .query_row(
            "SELECT COUNT(*) FROM managed_owner_effects WHERE length(payload) != 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_text, 0);
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // The inspector accepts only a private ledger; the default creation mode
    // depends on the caller's umask, so state the fixture's mode explicitly.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let capacity = bridge_core::owner_v2::inspect_owner_capacity(
        &path,
        std::fs::metadata(&path).unwrap().uid(),
        4,
    )
    .unwrap();
    assert_eq!(
        (
            capacity.store_used,
            capacity.store_remaining,
            capacity.producer_limit
        ),
        (1, 3, 4)
    );
    assert_eq!(capacity.producers.len(), 1);
    assert_eq!(
        (capacity.producers[0].used, capacity.producers[0].remaining),
        (1, 3)
    );
}

/// Version-eight rows are migrated without retaining their old payload bytes.
#[test]
fn schema_eight_scrubs_existing_payloads() {
    let dir = common::TempDir::new("owner-v8-scrub");
    let path = dir.path("owner.db");
    let intent = intent();
    let digest = egress_intent_digest(&intent).unwrap();
    {
        let mut store = Storage::open(&path, Limits::new(10)).unwrap();
        store
            .owner_v2_reserve(&effect(&intent, &digest, &"a".repeat(64), "call"))
            .unwrap();
    }
    {
        let sql = rusqlite::Connection::open(&path).unwrap();
        sql.execute(
            "UPDATE managed_owner_effects SET payload=?1",
            [b"synthetic message".as_slice()],
        )
        .unwrap();
        sql.execute(
            "UPDATE schema_meta SET value='8' WHERE key='schema_version'",
            [],
        )
        .unwrap();
    }
    let store = Storage::open(&path, Limits::new(10)).unwrap();
    assert_eq!(
        store
            .owner_v2_recovery_identity("pool", "backend", "pool-scope", "effect-a", &digest)
            .unwrap()
            .unwrap()
            .intent,
        intent
    );
    let sql = rusqlite::Connection::open(&path).unwrap();
    let length: u64 = sql
        .query_row(
            "SELECT length(payload) FROM managed_owner_effects",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(length, 0);
}
