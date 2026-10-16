//! Real isolated SQLite/socket controls for generic unknown producers. No
//! consumer source, installed daemon or real native session is touched.
mod common;
use bridge_core::dispatch::{DispatchTiming, EffectiveMode, Lifecycle, Outcome, Selection};
use bridge_core::service::GrantConfig;
use bridge_core::{
    ProducerAuthorizer, ProducerPolicy, Storage, UniversalLimits, VerifiedRegistration,
};
use bridge_protocol::*;
use common::{TempDir, attest, codex};
use std::sync::Arc;

/// Synthetic configured credentials; these are not installed or actual secrets.
const TOKEN: &str = "fixture-report-maker-token";
/// A second independent unknown producer credential used for privacy controls.
const OTHER: &str = "fixture-second-producer-token";
/// Arbitrary unknown producer config; opt-in policy is fully declarative.
fn grant(token: &str, producer: &str) -> GrantConfig {
    GrantConfig {
        token: token.into(),
        publisher: producer.into(),
        recipients: vec!["*".into()],
        kinds: vec!["done".into(), "progress".into()],
        modes: vec!["message".into(), "inject".into(), "auto".into()],
        policies: vec!["keep_all".into(), "latest".into(), "batch".into()],
        admin: false,
        producer_v1: Some(ProducerPolicy {
            registration: true,
            native_scopes: vec!["*".into()],
            reply_policies: vec!["self".into(), "shared_session".into()],
            direct_address: true,
            delivery_scopes: true,
            ..ProducerPolicy::default()
        }),
    }
}
/// Opens a fresh isolated fixture store with the same immutable authority for
/// arbitrary producers. Reopening reinstalls credentials without losing IDs.
fn store(path: &std::path::Path) -> Storage {
    let mut storage = Storage::open(path, bridge_core::Limits::new(100)).unwrap();
    storage
        .install_producer_authorizer(Arc::new(
            ProducerAuthorizer::new(&[
                grant(TOKEN, "report-maker"),
                grant(OTHER, "unknown-next-tool"),
            ])
            .unwrap(),
        ))
        .unwrap();
    storage
        .register_source_tag("report-maker", "report-maker")
        .unwrap();
    storage
        .register_source_tag("unknown-next-tool", "unknown-next-tool")
        .unwrap();
    storage
}
/// A genuine-looking fixture fact; only synthetic trusted test code creates it.
fn origin(use_key: &str, actor: &str) -> VerifiedRegistration {
    VerifiedRegistration {
        caller_address: codex("caller"),
        native_actor_id: actor.into(),
        actor_role: ActorRole::Root,
        destination: codex("caller"),
        observed_at_ms: 990,
        endpoint_epoch: 1,
        harness_pid: 42,
        harness_start_time: 900,
        evidence_use_key: use_key.into(),
        evidence_expires_at_ms: 5000,
    }
}
/// Product-independent registration intention; no native evidence is a wire
/// argument in this trusted core fixture.
fn registration(operation: &str) -> RegisterCallParams {
    RegisterCallParams {
        operation_key: operation.into(),
        evidence: None,
        reply_policy: ReplyPolicy::SelfActor,
        allowed_modes: None,
        allowed_kinds: None,
        max_payload_bytes: None,
        route_expires_at_ms: None,
        assertion_audience: None,
        invocation_key: None,
    }
}
/// Opaque generic publication into a route, with optional producer lifetime.
fn publication(route: &str, event: &str, lifetime: Option<&str>) -> PublishParams {
    PublishParams {
        destination: Destination::Route {
            route_key: route.into(),
        },
        event_id: event.into(),
        kind: "done".into(),
        payload: Payload::new("opaque producer result").unwrap(),
        mode: Mode::Message,
        policy: Policy::KeepAll,
        metadata: Metadata::new(),
        expires_at_ms: None,
        delivery_scope_key: lifetime.map(str::to_owned),
    }
}

/// Actual v1 latest publications expose independent lifetime watermarks while
/// legacy scopes remain readable and malformed retained scopes fail closed.
#[test]
fn scoped_latest_retention_uses_the_lifetime_watermark() {
    let dir = TempDir::new("retention-scope");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    for (id, lifetime, revision) in [
        ("a1", Some("one"), 1),
        ("a2", Some("one"), 2),
        ("b1", Some("two"), 7),
        ("legacy", None, 3),
    ] {
        let mut event = publication(&route.route_key, id, lifetime);
        event.policy = Policy::Latest {
            stream: "view".into(),
            revision,
        };
        storage.publish_v1(TOKEN, &event, &|| 1001).unwrap();
    }
    for (id, expected) in [("a1", 2), ("a2", 2), ("b1", 7), ("legacy", 3)] {
        assert_eq!(
            storage
                .retention("report-maker", id)
                .unwrap()
                .unwrap()
                .latest_watermark,
            Some(expected)
        );
    }
    let sql = rusqlite::Connection::open(&path).unwrap();
    for malformed in [
        "broken".to_string(),
        [
            "report-maker",
            "x",
            "done",
            "message",
            "",
            "",
            "latest",
            "view",
            "wrong",
        ]
        .join("\u{1f}"),
    ] {
        sql.execute(
            "UPDATE events SET scope_key=?1 WHERE event_id='a1'",
            [malformed],
        )
        .unwrap();
        assert!(matches!(
            storage.retention("report-maker", "a1"),
            Err(bridge_core::CoreError::Integrity(_))
        ));
    }
}

/// Retiring a lifetime permanently rejects manual retries. A late unsent
/// result never disposes earlier possible effects; zero-effect work closes,
/// and neither kind remains in the scheduler's eligible rotation.
#[test]
fn retired_scope_unsent_preserves_history_and_rejects_retry() {
    use bridge_core::recovery::{DeliveryState, EvidenceTier};
    for history in [false, true] {
        let dir = TempDir::new("retired-unsent");
        let mut storage = store(&dir.path("state.db"));
        let route = storage
            .register_call(
                TOKEN,
                "register",
                &registration("job"),
                Some(&origin("use", "root")),
                &|| 1000,
            )
            .unwrap();
        storage
            .publish_v1(
                TOKEN,
                &publication(&route.route_key, "event", Some("life")),
                &|| 1001,
            )
            .unwrap();
        let recipient = codex("caller");
        let attestation = attest(&recipient, Lifecycle::Inactive, 1);
        let Selection::Attempt(mut current) = storage
            .reserve_next(
                &attestation,
                EffectiveMode::Message,
                1002,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("reservation")
        };
        storage
            .mark_invoking(&current.fence, &attestation, 1003)
            .unwrap();
        if history {
            storage
                .record_outcome(
                    &current.fence,
                    Outcome::OutcomeUnknown {
                        reason: "fixture original unknown".into(),
                    },
                    1004,
                )
                .unwrap();
            storage
                .authorize_manual_retry(
                    "report-maker",
                    "event",
                    "operator",
                    "fixture deliberate duplicate risk",
                    1005,
                )
                .unwrap();
            let Selection::Attempt(next) = storage
                .reserve_next(
                    &attestation,
                    EffectiveMode::Message,
                    1006,
                    &DispatchTiming::default(),
                )
                .unwrap()
            else {
                panic!("retry reservation")
            };
            current = next;
            storage
                .mark_invoking(&current.fence, &attestation, 1007)
                .unwrap();
        }
        storage
            .retire_delivery_scope(
                TOKEN,
                "retire",
                &RetireDeliveryScopeParams {
                    scope_key: "life".into(),
                    action: RetirementAction::RetireUnhanded,
                },
                &|| 1008,
            )
            .unwrap();
        storage
            .record_outcome(
                &current.fence,
                Outcome::KnownUnsent {
                    evidence: "fixture latest helper never wrote".into(),
                },
                1009,
            )
            .unwrap();
        let evidence = storage
            .delivery_evidence("report-maker", "event")
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence.delivery,
            if history {
                DeliveryState::Review
            } else {
                DeliveryState::Disposed
            }
        );
        if history {
            assert!(
                evidence
                    .tiers
                    .iter()
                    .any(|row| row.tier == EvidenceTier::Unknown)
            );
            assert!(
                evidence.incident.is_some(),
                "preserved uncertainty stays visible"
            );
        }
        assert!(
            storage
                .authorize_manual_retry(
                    "report-maker",
                    "event",
                    "operator",
                    "fixture blocked retry",
                    1010
                )
                .is_err()
        );
        assert!(
            storage
                .recipients_with_work(100_000, 100, None)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            storage
                .reserve_next(
                    &attestation,
                    EffectiveMode::Message,
                    100_000,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        );
        assert!(
            storage
                .next_pending(&recipient.to_canonical_string(), 100)
                .unwrap()
                .is_empty()
        );
    }
}

/// A still-uncertain retired event refuses operator retry without clearing
/// its retained incident, state or audit history.
#[test]
fn retired_scope_manual_retry_is_fenced_before_any_mutation() {
    let dir = TempDir::new("retired-retry");
    let mut storage = store(&dir.path("state.db"));
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    storage
        .publish_v1(
            TOKEN,
            &publication(&route.route_key, "event", Some("life")),
            &|| 1001,
        )
        .unwrap();
    let attestation = attest(&codex("caller"), Lifecycle::Inactive, 1);
    let Selection::Attempt(current) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1002,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("reservation")
    };
    storage
        .mark_invoking(&current.fence, &attestation, 1003)
        .unwrap();
    storage
        .record_outcome(
            &current.fence,
            Outcome::OutcomeUnknown {
                reason: "fixture unknown".into(),
            },
            1004,
        )
        .unwrap();
    storage
        .retire_delivery_scope(
            TOKEN,
            "retire",
            &RetireDeliveryScopeParams {
                scope_key: "life".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1005,
        )
        .unwrap();
    let before = storage.delivery_evidence("report-maker", "event").unwrap();
    let audit = storage.audit_entries(100).unwrap();
    assert!(matches!(
        storage.authorize_manual_retry(
            "report-maker",
            "event",
            "operator",
            "fixture blocked retry",
            1006
        ),
        Err(bridge_core::CoreError::Fence(_))
    ));
    assert_eq!(
        storage.delivery_evidence("report-maker", "event").unwrap(),
        before
    );
    assert_eq!(storage.audit_entries(100).unwrap(), audit);
}

/// An orphan unhanded row from an older build cannot spin in work rotation or
/// appear dispatchable. Its content-free diagnostics expose the scope fence.
#[test]
fn retired_scope_legacy_unhanded_row_has_consistent_visible_fence() {
    let dir = TempDir::new("retired-orphan");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    storage
        .publish_v1(
            TOKEN,
            &publication(&route.route_key, "event", Some("life")),
            &|| 1001,
        )
        .unwrap();
    storage
        .retire_delivery_scope(
            TOKEN,
            "retire",
            &RetireDeliveryScopeParams {
                scope_key: "life".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1002,
        )
        .unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE events SET delivery='unhanded' WHERE event_id='event'",
            [],
        )
        .unwrap();
    let recipient = codex("caller");
    assert!(
        storage
            .recipients_with_work(2000, 100, None)
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .next_pending(&recipient.to_canonical_string(), 100)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                2000,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    );
    assert!(
        storage
            .delivery_evidence("report-maker", "event")
            .unwrap()
            .unwrap()
            .hold_reason
            .unwrap()
            .contains("scope retired")
    );
}
/// Checks atomic claims/route/request commit, loss of receipt recovery, no
/// cross-producer evidence reuse and logical scopes surviving renewal/restart.
#[test]
fn registration_atomicity_replay_identity_and_restart() {
    let dir = TempDir::new("universal-registration");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let sql = rusqlite::Connection::open(&path).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_request BEFORE INSERT ON registration_requests BEGIN SELECT RAISE(ABORT,'fixture rollback'); END;").unwrap();
    let err = storage
        .register_call(
            TOKEN,
            "req-1",
            &registration("job-1"),
            Some(&origin("use-1", "root")),
            &|| 1000,
        )
        .unwrap_err();
    assert_eq!(err.effect, Some(MutationEffect::NotCommitted));
    for table in [
        "return_routes",
        "registration_requests",
        "evidence_uses",
        "producer_scopes",
    ] {
        assert_eq!(
            sql.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    sql.execute_batch("DROP TRIGGER fail_request;").unwrap();
    let first = storage
        .register_call(
            TOKEN,
            "req-1",
            &registration("job-1"),
            Some(&origin("use-1", "root")),
            &|| 1000,
        )
        .unwrap();
    assert!(
        storage
            .register_call(
                OTHER,
                "foreign",
                &registration("other-job"),
                Some(&origin("use-1", "root")),
                &|| 1001
            )
            .is_err()
    );
    assert!(
        storage
            .register_call(
                TOKEN,
                "req-2",
                &registration("job-1"),
                Some(&origin("use-2", "other-actor")),
                &|| 1001
            )
            .is_err()
    );
    let mut renewed = origin("use-2", "root");
    renewed.endpoint_epoch = 9;
    renewed.harness_pid = 100;
    renewed.harness_start_time = 999;
    let again = storage
        .register_call(
            TOKEN,
            "req-2",
            &registration("job-1"),
            Some(&renewed),
            &|| 1002,
        )
        .unwrap();
    assert_eq!(again.route_key, first.route_key);
    assert_eq!(again.caller_scope, first.caller_scope);
    let committed = storage
        .registration_evidence_committed(TOKEN, "req-1", "use-1")
        .unwrap();
    assert_eq!(
        committed.claim,
        bridge_core::RegistrationClaimState::CommittedToRequest
    );
    drop(storage);
    let mut storage = store(&path);
    assert_eq!(
        storage
            .register_call(TOKEN, "req-1", &registration("job-1"), None, &|| 2000)
            .unwrap(),
        first
    );
    assert!(
        storage
            .register_call(TOKEN, "req-new", &registration("job-1"), None, &|| 2000)
            .is_err()
    );
    assert!(
        storage
            .registration_replay(TOKEN, "req-1", &registration("changed-job"))
            .is_err()
    );
}
/// Publication intent/envelope rollback is one transaction; close never changes
/// original custody and tagged address/route identities cannot be substituted.
#[test]
fn publication_intent_atomicity_close_and_cross_owner_privacy() {
    let dir = TempDir::new("universal-publish");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_intent BEFORE INSERT ON publication_intents BEGIN SELECT RAISE(ABORT,'fixture rollback'); END;").unwrap();
    let request = publication(&route.route_key, "event", None);
    assert_eq!(
        storage
            .publish_v1(TOKEN, &request, &|| 1001)
            .unwrap_err()
            .effect,
        Some(MutationEffect::NotCommitted)
    );
    assert_eq!(
        sql.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    sql.execute_batch("DROP TRIGGER fail_intent;").unwrap();
    let first = storage.publish_v1(TOKEN, &request, &|| 1002).unwrap();
    storage
        .close_route(
            TOKEN,
            "close",
            &CloseRouteParams {
                route_key: route.route_key.clone(),
                reason: None,
            },
            &|| 1003,
        )
        .unwrap();
    assert!(
        storage
            .publish_v1(
                TOKEN,
                &publication(&route.route_key, "new-event", None),
                &|| 1004
            )
            .is_err()
    );
    assert_eq!(
        storage
            .publish_v1(TOKEN, &request, &|| 1004)
            .unwrap()
            .receipt,
        first.receipt
    );
    let mut changed = request.clone();
    changed.destination = Destination::Address {
        address: codex("caller").to_canonical_string(),
    };
    assert!(storage.publish_v1(TOKEN, &changed, &|| 1004).is_err());
    assert!(
        storage
            .publish_v1(
                OTHER,
                &publication(&route.route_key, "other", None),
                &|| 1004
            )
            .is_err()
    );
    assert!(matches!(
        storage
            .status_v1(
                OTHER,
                &StatusSelector::Route {
                    route_key: route.route_key
                },
                1004
            )
            .unwrap(),
        StatusResult::Route { route: None }
    ));
}
/// Retiring before publication installs a permanent tombstone; exact event
/// replay and sibling scopes retain immutable facts across restart.
#[test]
fn retirement_tombstone_replay_and_scoped_coalescing() {
    let dir = TempDir::new("universal-retire");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    let retired = storage
        .retire_delivery_scope(
            TOKEN,
            "retire-first",
            &RetireDeliveryScopeParams {
                scope_key: "old-life".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1001,
        )
        .unwrap();
    assert_eq!(retired.receipt.disposed, 0);
    assert!(
        storage
            .publish_v1(
                TOKEN,
                &publication(&route.route_key, "late", "old-life".into()),
                &|| 1002
            )
            .is_err()
    );
    let mut a = publication(&route.route_key, "a", Some("new-life"));
    a.policy = Policy::Latest {
        stream: "progress".into(),
        revision: 1,
    };
    let accepted = storage.publish_v1(TOKEN, &a, &|| 1003).unwrap();
    let mut b = a.clone();
    b.event_id = "b".into();
    b.delivery_scope_key = Some("sibling-life".into());
    storage.publish_v1(TOKEN, &b, &|| 1003).unwrap();
    let receipt = storage
        .retire_delivery_scope(
            TOKEN,
            "retire-new",
            &RetireDeliveryScopeParams {
                scope_key: "new-life".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1004,
        )
        .unwrap();
    assert_eq!(receipt.receipt.disposed, 1);
    assert_eq!(
        storage.publish_v1(TOKEN, &a, &|| 1005).unwrap().receipt,
        accepted.receipt
    );
    assert!(matches!(
        storage
            .status_v1(
                TOKEN,
                &StatusSelector::Event {
                    event_id: "b".into()
                },
                1005
            )
            .unwrap(),
        StatusResult::Event {
            event: Some(EventStatus {
                delivery: DeliveryStatus {
                    delivery: DeliveryState::Unhanded,
                    ..
                },
                ..
            })
        }
    ));
    drop(storage);
    let mut storage = store(&path);
    assert!(
        storage
            .retire_delivery_scope(
                TOKEN,
                "retire-new",
                &RetireDeliveryScopeParams {
                    scope_key: "new-life".into(),
                    action: RetirementAction::RetireUnhanded
                },
                &|| 2000
            )
            .unwrap()
            .replayed
    );
    assert!(
        storage
            .publish_v1(
                TOKEN,
                &publication(&route.route_key, "late-again", Some("old-life")),
                &|| 2000
            )
            .is_err()
    );
}
/// A reservation is safely revoked; an already invoking unknown effect remains
/// retained, receives no second native attempt and keeps late evidence allowed.
#[test]
fn reserved_retirement_fences_invoking_and_preserves_unknown() {
    let dir = TempDir::new("universal-attempt");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    storage
        .publish_v1(
            TOKEN,
            &publication(&route.route_key, "reserved", Some("reserved-life")),
            &|| 1001,
        )
        .unwrap();
    let recipient = codex("caller");
    let attestation = attest(&recipient, Lifecycle::Inactive, 1);
    let Selection::Attempt(reserved) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1002,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("expected reservation")
    };
    let receipt = storage
        .retire_delivery_scope(
            TOKEN,
            "retire-reserved",
            &RetireDeliveryScopeParams {
                scope_key: "reserved-life".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1003,
        )
        .unwrap();
    assert_eq!(receipt.receipt.disposed, 1);
    assert!(
        storage
            .mark_invoking(&reserved.fence, &attestation, 1004)
            .is_err()
    );
    storage
        .publish_v1(
            TOKEN,
            &publication(&route.route_key, "unknown", Some("unknown-life")),
            &|| 1004,
        )
        .unwrap();
    let Selection::Attempt(reserved) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1005,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("expected reservation")
    };
    storage
        .mark_invoking(&reserved.fence, &attestation, 1006)
        .unwrap();
    storage
        .record_outcome(
            &reserved.fence,
            Outcome::OutcomeUnknown {
                reason: "fixture uncertain handoff".into(),
            },
            1007,
        )
        .unwrap();
    let receipt = storage
        .retire_delivery_scope(
            TOKEN,
            "retire-unknown",
            &RetireDeliveryScopeParams {
                scope_key: "unknown-life".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1008,
        )
        .unwrap();
    assert_eq!(receipt.receipt.preserved_possible_effect, 1);
    assert_eq!(receipt.receipt.disposed, 0);
    assert!(matches!(
        storage
            .reserve_next(
                &attestation,
                EffectiveMode::Message,
                1009,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
}
/// Hard tombstone capacity and immutable authority installation never evict or
/// reopen prior identities, and expiry is sampled under the transaction lock.
#[test]
fn authority_capacity_and_commit_clock_are_explicit() {
    let dir = TempDir::new("universal-caps");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let auth = storage.producer_authorizer().unwrap();
    storage.install_producer_authorizer(auth).unwrap();
    assert!(
        storage
            .install_producer_authorizer(Arc::new(
                ProducerAuthorizer::new(&[grant(TOKEN, "report-maker")]).unwrap()
            ))
            .is_err()
    );
    storage
        .configure_universal_limits(UniversalLimits {
            max_open_routes: 1,
            max_retained_routes: 1,
            ..UniversalLimits::default()
        })
        .unwrap();
    assert!(
        storage
            .register_call(
                TOKEN,
                "expired",
                &registration("expired"),
                Some(&origin("expired-use", "root")),
                &|| 6000
            )
            .is_err()
    );
    let first = storage
        .register_call(
            TOKEN,
            "first",
            &registration("one"),
            Some(&origin("one-use", "root")),
            &|| 1000,
        )
        .unwrap();
    storage
        .close_route(
            TOKEN,
            "close-one",
            &CloseRouteParams {
                route_key: first.route_key,
                reason: None,
            },
            &|| 1001,
        )
        .unwrap();
    assert_eq!(
        storage
            .register_call(
                TOKEN,
                "second",
                &registration("two"),
                Some(&origin("two-use", "root")),
                &|| 1002
            )
            .unwrap_err()
            .class,
        ErrorClass::Capacity
    );
}

/// Current token/policy changes after restart do not rewrite accepted identity;
/// revoked credentials disclose nothing and narrower grants fence only new work.
#[test]
fn rotated_credential_and_tightened_policy_recover_only_history() {
    let dir = TempDir::new("universal-rotation");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let receipt = storage
        .register_call(
            TOKEN,
            "registration",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    let request = publication(&receipt.route_key, "event", None);
    let accepted = storage.publish_v1(TOKEN, &request, &|| 1001).unwrap();
    drop(storage);
    let rotated = "fixture-rotated-producer-token";
    let mut next = grant(rotated, "report-maker");
    next.kinds = vec!["progress".into()];
    next.producer_v1.as_mut().unwrap().registration = false;
    let mut storage = Storage::open(&path, bridge_core::Limits::new(100)).unwrap();
    storage
        .install_producer_authorizer(Arc::new(ProducerAuthorizer::new(&[next]).unwrap()))
        .unwrap();
    assert_eq!(
        storage
            .registration_replay(rotated, "registration", &registration("job"))
            .unwrap(),
        Some(receipt.clone())
    );
    assert_eq!(
        storage
            .publish_v1(rotated, &request, &|| 2000)
            .unwrap()
            .receipt,
        accepted.receipt
    );
    assert_eq!(
        storage
            .publish_v1(
                rotated,
                &publication(&receipt.route_key, "new-event", None),
                &|| 2000
            )
            .unwrap_err()
            .class,
        ErrorClass::Forbidden
    );
    assert_eq!(
        storage
            .registration_replay(TOKEN, "registration", &registration("job"))
            .unwrap_err()
            .class,
        ErrorClass::Auth
    );
}
/// Real protected-core Unix exchanges validate the public wire/correlation and
/// policy-only capabilities; native call verification remains adapter-owned.
#[test]
fn core_socket_v1_roundtrip_and_unknown_version_refusal() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let dir = TempDir::new("universal-socket");
    let socket = common::short_socket("v1");
    let service = bridge_core::start_service(bridge_core::Config {
        database: dir.path("state.db"),
        socket: socket.clone(),
        limits: bridge_core::Limits::new(100),
        grants: vec![grant(TOKEN, "report-maker")],
        universal_limits: UniversalLimits::default(),
    })
    .unwrap();
    let request = Request::new(
        "publish-1",
        Secret::new(TOKEN),
        Operation::Publish(PublishParams {
            destination: Destination::Address {
                address: codex("socket-caller").to_canonical_string(),
            },
            ..publication("unused", "socket-event", None)
        }),
    )
    .unwrap();
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    stream
        .write_all(&encode_request(&request).unwrap())
        .unwrap();
    stream.write_all(b"\n").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let response = decode_response(line.trim_end().as_bytes(), &request).unwrap();
    assert!(response.success);
    let caps = Request::new(
        "caps",
        Secret::new(TOKEN),
        Operation::Capabilities(CapabilitiesParams {}),
    )
    .unwrap();
    stream.write_all(&encode_request(&caps).unwrap()).unwrap();
    stream.write_all(b"\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    let response = decode_response(line.trim_end().as_bytes(), &caps).unwrap();
    assert!(matches!(
        response.result,
        Some(OperationResult::Capabilities(Capabilities {
            features: Features {
                host_observations: false,
                ..
            },
            ..
        }))
    ));
    let mut unsupported = serde_json::to_value(&request).unwrap();
    unsupported["api_version"] = serde_json::json!(2);
    unsupported["request_id"] = serde_json::json!("unsupported");
    unsupported["params"]["event_id"] = serde_json::json!("must-not-exist");
    stream
        .write_all(serde_json::to_string(&unsupported).unwrap().as_bytes())
        .unwrap();
    stream.write_all(b"\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    let response: Response = serde_json::from_str(line.trim_end()).unwrap();
    assert_eq!(response.error.unwrap().class, ErrorClass::Unsupported);
    assert!(matches!(
        service
            .with_storage(|s| s.status_v1(
                TOKEN,
                &StatusSelector::Event {
                    event_id: "must-not-exist".into()
                },
                2000
            ))
            .unwrap(),
        StatusResult::Event { event: None }
    ));
    drop(reader);
    drop(stream);
    service.shutdown();
    service.join();
}
/// Shared destination never merges actual native root/child actor scopes.
#[test]
fn root_and_child_scopes_remain_distinct_with_same_destination() {
    let dir = TempDir::new("universal-child");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let root = storage
        .register_call(
            TOKEN,
            "root",
            &registration("root-job"),
            Some(&origin("root-use", "root")),
            &|| 1000,
        )
        .unwrap();
    let mut child = origin("child-use", "child-1");
    child.actor_role = ActorRole::Child;
    let mut intent = registration("child-job");
    intent.reply_policy = ReplyPolicy::SharedSession;
    let child = storage
        .register_call(TOKEN, "child", &intent, Some(&child), &|| 1001)
        .unwrap();
    assert_ne!(root.caller_scope, child.caller_scope);
    assert_eq!(root.destination_scope, child.destination_scope);
}

/// Exact schema-five fixture preserves accepted bytes/hash, unknown attempt and
/// evidence through the additive migration; legacy replay never creates v1 intent.
#[test]
fn exact_schema_five_migration_preserves_unknown_and_legacy_identity() {
    use sha2::{Digest, Sha256};
    let dir = TempDir::new("universal-v5");
    let path = dir.path("state.db");
    let recipient = codex("legacy-recipient");
    let envelope = common::keep_all(
        "report-maker",
        "legacy-v5",
        &recipient,
        bridge_core::Mode::Message,
    );
    let bytes = envelope.canonical_bytes();
    let hash = envelope.envelope_hash();
    let manifest = bridge_core::framing::frame_manifest(&[("report-maker", &envelope)]).unwrap();
    let manifest_hash = format!("{:x}", Sha256::digest(manifest.as_bytes()));
    {
        let sql = rusqlite::Connection::open(&path).unwrap();
        sql.execute_batch(include_str!("fixtures/schema-v5.sql"))
            .unwrap();
        sql.execute(
            "INSERT INTO schema_meta(key,value) VALUES('schema_version','5')",
            [],
        )
        .unwrap();
        sql.execute("UPDATE counters SET value=1 WHERE name IN('acceptance_seq','retained_events','attempt_seq','evidence_seq')",[]).unwrap();
        sql.execute(
            "INSERT INTO source_tags(publisher_id,tag) VALUES('report-maker','report-maker')",
            [],
        )
        .unwrap();
        sql.execute("INSERT INTO events(publisher_id,event_id,envelope_hash,envelope_json,state,acceptance_seq,accepted_at_ms,recipient,policy_class,delivery,attempt_seq,mode,attempts_made) VALUES('report-maker','legacy-v5',?1,?2,'pending',1,900,?3,'keep_all','review',1,'message',1)",rusqlite::params![hash.as_str(),bytes,recipient.to_canonical_string()]).unwrap();
        sql.execute("INSERT INTO attempts(attempt_seq,state,requested_mode,effective_mode,recipient,actor,endpoint_epoch,granted,manifest,manifest_hash,deadline_ms,created_ms,updated_ms,proof_ref) VALUES(1,'outcome_unknown','message','message',?1,'legacy-recipient',1,'inject,message',?2,?3,1000,900,901,'legacy-proof')",rusqlite::params![recipient.to_canonical_string(),manifest,manifest_hash]).unwrap();
        sql.execute("INSERT INTO attempt_members(attempt_seq,ordinal,publisher_id,event_id,envelope_hash) VALUES(1,0,'report-maker','legacy-v5',?1)",rusqlite::params![hash.as_str()]).unwrap();
        sql.execute("INSERT INTO evidence(evidence_seq,publisher_id,event_id,attempt_seq,tier,detail,at_ms) VALUES(1,'report-maker','legacy-v5',1,'unknown','fixture unresolved handoff',901)",[]).unwrap();
    }
    let mut storage = store(&path);
    let sql = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        sql.query_row(
            "SELECT value FROM schema_meta WHERE key='schema_version'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "6"
    );
    let after:(Vec<u8>,String,String,String)=sql.query_row("SELECT envelope_json,envelope_hash,delivery,delivery_scope_key FROM events WHERE event_id='legacy-v5'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(
        after,
        (bytes, hash.as_str().into(), "review".into(), "".into())
    );
    assert_eq!(
        sql.query_row("SELECT state FROM attempts WHERE attempt_seq=1", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap(),
        "outcome_unknown"
    );
    assert_eq!(
        sql.query_row("SELECT tier FROM evidence WHERE evidence_seq=1", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap(),
        "unknown"
    );
    assert!(storage.publish(&envelope, 2000).unwrap().receipt.replayed);
    let Selection::Idle = storage
        .reserve_next(
            &attest(&recipient, Lifecycle::Inactive, 1),
            EffectiveMode::Message,
            2000,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("unknown effect was replayed")
    };
    let mut v1 = publication("unused", "legacy-v5", None);
    v1.destination = Destination::Address {
        address: recipient.to_canonical_string(),
    };
    v1.kind = "done".into();
    assert_eq!(
        storage.publish_v1(TOKEN, &v1, &|| 2000).unwrap_err().reason,
        "legacy_event_identity"
    );
    assert_eq!(
        sql.query_row("SELECT COUNT(*) FROM publication_intents", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

/// Shared-address children cannot implicitly return as independently addressed
/// callers; real own-address children remain allowed without product branches.
#[test]
fn child_self_policy_requires_independent_actual_address() {
    let dir = TempDir::new("universal-self-child");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let mut child = origin("child-use", "child-1");
    child.actor_role = ActorRole::Child;
    assert_eq!(
        storage
            .register_call(
                TOKEN,
                "child",
                &registration("child-job"),
                Some(&child),
                &|| 1000
            )
            .unwrap_err()
            .reason,
        "shared_session_policy_required"
    );
    assert_eq!(
        storage
            .registration_evidence_committed(TOKEN, "child", "child-use")
            .unwrap()
            .claim,
        bridge_core::RegistrationClaimState::NotVisible
    );
    child.native_actor_id = child.caller_address.native_session_id.clone();
    assert!(
        storage
            .register_call(
                TOKEN,
                "child",
                &registration("child-job"),
                Some(&child),
                &|| 1001
            )
            .is_ok()
    );
}

/// Two real SQLite writer connections exercise both deterministic commit orders
/// for publication versus route/lifetime closure. The first clock barrier is
/// reached only after BEGIN IMMEDIATE, so the competing mutation cannot pass it.
#[test]
fn publication_close_and_retirement_serialize_at_commit() {
    for retire in [false, true] {
        for fence_first in [false, true] {
            let dir = TempDir::new("universal-race");
            let path = dir.path("state.db");
            let mut first = store(&path);
            let route = first
                .register_call(
                    TOKEN,
                    "register",
                    &registration("job"),
                    Some(&origin("use", "root")),
                    &|| 1000,
                )
                .unwrap();
            let auth = first.producer_authorizer().unwrap();
            let mut second = Storage::open(&path, bridge_core::Limits::new(100)).unwrap();
            second.install_producer_authorizer(auth).unwrap();
            let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let first_route = route.route_key.clone();
            let first_worker = std::thread::spawn(move || {
                let clock = || {
                    acquired_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    1010
                };
                if fence_first {
                    if retire {
                        first
                            .retire_delivery_scope(
                                TOKEN,
                                "fence",
                                &RetireDeliveryScopeParams {
                                    scope_key: "generation".into(),
                                    action: RetirementAction::RetireUnhanded,
                                },
                                &clock,
                            )
                            .map(|_| ())
                    } else {
                        first
                            .close_route(
                                TOKEN,
                                "fence",
                                &CloseRouteParams {
                                    route_key: first_route,
                                    reason: None,
                                },
                                &clock,
                            )
                            .map(|_| ())
                    }
                } else {
                    first
                        .publish_v1(
                            TOKEN,
                            &publication(
                                &first_route,
                                "event",
                                if retire { Some("generation") } else { None },
                            ),
                            &clock,
                        )
                        .map(|_| ())
                }
            });
            acquired_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            let second_route = route.route_key;
            let second_worker = std::thread::spawn(move || {
                if fence_first {
                    second
                        .publish_v1(
                            TOKEN,
                            &publication(
                                &second_route,
                                "event",
                                if retire { Some("generation") } else { None },
                            ),
                            &|| 1011,
                        )
                        .map(|_| ())
                } else if retire {
                    second
                        .retire_delivery_scope(
                            TOKEN,
                            "fence",
                            &RetireDeliveryScopeParams {
                                scope_key: "generation".into(),
                                action: RetirementAction::RetireUnhanded,
                            },
                            &|| 1011,
                        )
                        .map(|_| ())
                } else {
                    second
                        .close_route(
                            TOKEN,
                            "fence",
                            &CloseRouteParams {
                                route_key: second_route,
                                reason: None,
                            },
                            &|| 1011,
                        )
                        .map(|_| ())
                }
            });
            release_tx.send(()).unwrap();
            assert!(first_worker.join().unwrap().is_ok());
            let second_result = second_worker.join().unwrap();
            if fence_first {
                assert!(second_result.is_err());
            } else {
                assert!(second_result.is_ok());
            }
            let sql = rusqlite::Connection::open(&path).unwrap();
            assert_eq!(
                sql.query_row("SELECT COUNT(*) FROM publication_intents", [], |r| r
                    .get::<_, u64>(0))
                    .unwrap(),
                u64::from(!fence_first)
            );
        }
    }
}

/// Even a stale persisted reservation presented after retirement cannot cross
/// the shared final invoking guard. Fixture restoration models an unsettled
/// reservation; immutable manifest/hash/recipient/epoch remain untouched.
#[test]
fn committed_lifetime_fence_blocks_stale_reserved_manifest() {
    let dir = TempDir::new("universal-invoke-fence");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    storage
        .publish_v1(
            TOKEN,
            &publication(&route.route_key, "event", Some("generation")),
            &|| 1001,
        )
        .unwrap();
    let recipient = codex("caller");
    let attestation = attest(&recipient, Lifecycle::Inactive, 1);
    let Selection::Attempt(reserved) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1002,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("expected reservation")
    };
    storage
        .retire_delivery_scope(
            TOKEN,
            "retire",
            &RetireDeliveryScopeParams {
                scope_key: "generation".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1003,
        )
        .unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    sql.execute(
        "UPDATE attempts SET state='reserved',lease_expires_ms=?1 WHERE attempt_seq=?2",
        rusqlite::params![reserved.lease_expires_ms, reserved.fence.attempt_seq],
    )
    .unwrap();
    sql.execute("UPDATE events SET delivery='reserved',attempt_seq=?1 WHERE publisher_id='report-maker' AND event_id='event'",rusqlite::params![reserved.fence.attempt_seq]).unwrap();
    assert!(
        storage
            .mark_invoking(&reserved.fence, &attestation, 1004)
            .is_err()
    );
    assert_eq!(
        sql.query_row(
            "SELECT state FROM attempts WHERE attempt_seq=?1",
            rusqlite::params![reserved.fence.attempt_seq],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "reserved"
    );
}
/// Same producer/group/destination batches cannot mix independent lifetimes;
/// retired inject work cannot be returned at a natural hook context point.
#[test]
fn scoped_batch_and_inject_retirement_remain_isolated() {
    let dir = TempDir::new("universal-batch");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let mut intent = registration("job");
    intent.allowed_modes = Some(vec![Mode::Message, Mode::Inject]);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &intent,
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    for (id, scope) in [("a1", "one"), ("a2", "one"), ("b1", "two")] {
        let mut event = publication(&route.route_key, id, Some(scope));
        event.policy = Policy::Batch {
            group: "same-group".into(),
        };
        storage.publish_v1(TOKEN, &event, &|| 1001).unwrap();
    }
    let recipient = codex("caller");
    let idle = attest(&recipient, Lifecycle::Inactive, 1);
    let Selection::Attempt(reserved) = storage
        .reserve_next(
            &idle,
            EffectiveMode::Message,
            1002,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("expected batch")
    };
    assert_eq!(
        reserved
            .members
            .iter()
            .map(|m| m.event_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a1", "a2"]
    );
    storage
        .retire_delivery_scope(
            TOKEN,
            "retire-one",
            &RetireDeliveryScopeParams {
                scope_key: "one".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1003,
        )
        .unwrap();
    let mut inject = publication(&route.route_key, "inject", Some("injected-life"));
    inject.mode = Mode::Inject;
    storage.publish_v1(TOKEN, &inject, &|| 1004).unwrap();
    storage
        .retire_delivery_scope(
            TOKEN,
            "retire-inject",
            &RetireDeliveryScopeParams {
                scope_key: "injected-life".into(),
                action: RetirementAction::RetireUnhanded,
            },
            &|| 1005,
        )
        .unwrap();
    assert!(matches!(
        storage
            .drain_inject(
                &attest(&recipient, Lifecycle::Active, 1),
                1006,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
    let Selection::Attempt(next) = storage
        .reserve_next(
            &idle,
            EffectiveMode::Message,
            1006,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("sibling batch missing")
    };
    assert_eq!(next.members[0].event_id, "b1");
}

/// Explicit route/event expiry fences new work but exact accepted intent recovers
/// immutable custody; closing an expired route cannot extend or reopen it.
#[test]
fn accepted_retry_after_route_and_event_expiry_preserves_receipt() {
    let dir = TempDir::new("universal-expiry");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let mut intent = registration("job");
    intent.route_expires_at_ms = Some(1050);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &intent,
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    let mut event = publication(&route.route_key, "event", None);
    event.expires_at_ms = Some(1040);
    let accepted = storage.publish_v1(TOKEN, &event, &|| 1010).unwrap();
    storage.expire_due(1041).unwrap();
    assert_eq!(
        storage.publish_v1(TOKEN, &event, &|| 1060).unwrap().receipt,
        accepted.receipt
    );
    assert_eq!(
        storage
            .publish_v1(TOKEN, &publication(&route.route_key, "new", None), &|| 1060)
            .unwrap_err()
            .reason,
        "route_expired"
    );
    let closed = storage
        .close_route(
            TOKEN,
            "close-expired",
            &CloseRouteParams {
                route_key: route.route_key.clone(),
                reason: None,
            },
            &|| 1060,
        )
        .unwrap();
    assert_eq!(closed.receipt.state, RouteState::Expired);
    assert!(closed.receipt.closed_at_ms.is_none());
    assert!(matches!(
        storage
            .status_v1(
                TOKEN,
                &StatusSelector::Route {
                    route_key: route.route_key
                },
                1061
            )
            .unwrap(),
        StatusResult::Route {
            route: Some(RouteStatus {
                state: RouteState::Expired,
                ..
            })
        }
    ));
}

/// Exchanges one actual v1 frame with a private fixture service under two-second
/// I/O bounds. Missing/invalid response is an error; no mutation retry is hidden.
fn fixture_exchange(socket: &std::path::Path, request: &Request) -> Result<Response, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket).map_err(|_| "connect".to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(&encode_request(request).unwrap())
        .map_err(|_| "write".to_string())?;
    stream.write_all(b"\n").map_err(|_| "write".to_string())?;
    let mut line = String::new();
    if BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|_| "read".to_string())?
        == 0
    {
        return Err("empty response".into());
    }
    decode_response(line.trim_end().as_bytes(), request).map_err(|_| "invalid response".into())
}
/// Status diagnostics sanitize all control code points only at the public
/// projection. Actual socket response remains encodable and stored legacy note,
/// unknown evidence and recipient hold bytes are not rewritten.
#[test]
fn public_status_diagnostics_normalize_controls_without_rewriting_history() {
    let dir = TempDir::new("universal-diagnostics");
    let path = dir.path("state.db");
    let socket = common::short_socket("diag-v1");
    let service = bridge_core::start_service(bridge_core::Config {
        database: path.clone(),
        socket: socket.clone(),
        limits: bridge_core::Limits::new(100),
        grants: vec![grant(TOKEN, "report-maker")],
        universal_limits: UniversalLimits::default(),
    })
    .unwrap();
    let reason = "native\nuncertain\t\u{0000}\u{007f}\u{0085}";
    let hold = "waiting\r\n\u{0001}\u{009f}control";
    service.with_storage(|s| {
        let route = s
            .register_call(
                TOKEN,
                "register",
                &registration("job"),
                Some(&origin("use", "root")),
                &|| 1000,
            )
            .unwrap();
        s.publish_v1(
            TOKEN,
            &publication(&route.route_key, "event", None),
            &|| 1001,
        )
        .unwrap();
        let recipient = codex("caller");
        let a = attest(&recipient, Lifecycle::Inactive, 1);
        let Selection::Attempt(r) = s
            .reserve_next(&a, EffectiveMode::Message, 1002, &DispatchTiming::default())
            .unwrap()
        else {
            panic!("reservation")
        };
        s.mark_invoking(&r.fence, &a, 1003).unwrap();
        s.record_outcome(
            &r.fence,
            Outcome::OutcomeUnknown {
                reason: reason.into(),
            },
            1004,
        )
        .unwrap();
        s.publish_v1(
            TOKEN,
            &publication(&route.route_key, "hold-event", None),
            &|| 1005,
        )
        .unwrap();
        s.record_hold(&recipient, hold, 1005).unwrap();
    });
    let request = Request::new(
        "status",
        Secret::new(TOKEN),
        Operation::Status(StatusParams {
            selector: StatusSelector::Event {
                event_id: "event".into(),
            },
        }),
    )
    .unwrap();
    let response = fixture_exchange(&socket, &request);
    service.shutdown();
    service.join();
    let response =
        response.expect("control-containing legacy diagnostics must remain valid public responses");
    let Some(OperationResult::Status(StatusResult::Event { event: Some(event) })) = response.result
    else {
        panic!("event status")
    };
    assert_eq!(event.delivery.delivery, DeliveryState::Review);
    assert!(event.delivery.tiers.contains(&EvidenceTier::Unknown));
    for value in [event.delivery.note, event.delivery.hold_reason]
        .into_iter()
        .flatten()
    {
        assert!(!value.chars().any(char::is_control));
        assert!(value.len() <= 512);
    }
    let sql = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        sql.query_row(
            "SELECT detail FROM evidence WHERE tier='unknown'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        reason
    );
    assert_eq!(
        sql.query_row("SELECT reason FROM recipient_holds", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        hold
    );
    assert!(
        sql.query_row("SELECT note FROM attempts", [], |r| r.get::<_, String>(0))
            .unwrap()
            .contains(reason)
    );
}
/// Valid legacy grant duplicate declarations remain accepted, while both outer
/// and nested public capability sets are unique and valid on the actual socket.
#[test]
fn public_capabilities_normalize_valid_legacy_duplicate_grants() {
    let dir = TempDir::new("universal-legacy-caps");
    let socket = common::short_socket("dup-v1");
    let mut legacy = grant(TOKEN, "legacy-opaque-producer");
    legacy.producer_v1 = None;
    legacy.modes = vec!["message".into(), "message".into(), "inject".into()];
    legacy.policies = vec!["keep_all".into(), "keep_all".into(), "batch".into()];
    legacy.kinds = vec!["done".into(), "done".into(), "progress".into()];
    assert!(legacy.validate().is_ok());
    let original = legacy.clone();
    let service = bridge_core::start_service(bridge_core::Config {
        database: dir.path("state.db"),
        socket: socket.clone(),
        limits: bridge_core::Limits::new(100),
        grants: vec![legacy],
        universal_limits: UniversalLimits::default(),
    })
    .unwrap();
    let request = Request::new(
        "caps",
        Secret::new(TOKEN),
        Operation::Capabilities(CapabilitiesParams {}),
    )
    .unwrap();
    let response = fixture_exchange(&socket, &request);
    service.shutdown();
    service.join();
    let response =
        response.expect("valid legacy duplicate grants must remain readable as capabilities");
    let Some(OperationResult::Capabilities(caps)) = response.result else {
        panic!("capabilities")
    };
    caps.validate().unwrap();
    assert!(
        caps.operations
            .iter()
            .all(|operation| !operation.contains("profile") && !operation.contains("enroll")),
        "no runtime profile operation is exposed: {:?}",
        caps.operations
    );
    assert!(
        caps.native_contracts.is_empty(),
        "no predeclared native build is advertised"
    );
    assert_eq!(caps.modes, vec![Mode::Message, Mode::Inject]);
    assert_eq!(caps.grant.allowed_modes, caps.modes);
    assert_eq!(caps.policies, vec![PolicyKind::KeepAll, PolicyKind::Batch]);
    assert_eq!(caps.grant.allowed_policies, caps.policies);
    assert_eq!(caps.grant.allowed_kinds, vec!["done", "progress"]);
    assert_eq!(original.modes.len(), 3);
    assert_eq!(original.kinds.len(), 3);
}
/// Preserve fences only new custody, keeps existing dispatch eligible, freezes
/// all four disjoint first-snapshot counts across later same-action requests and
/// restart, and cannot be upgraded to RetireUnhanded by another request.
#[test]
fn preserve_lifetime_keeps_dispatch_and_freezes_disjoint_snapshot() {
    let dir = TempDir::new("universal-preserve");
    let path = dir.path("state.db");
    let mut storage = store(&path);
    let route = storage
        .register_call(
            TOKEN,
            "register",
            &registration("job"),
            Some(&origin("use", "root")),
            &|| 1000,
        )
        .unwrap();
    for id in ["unknown", "safe", "terminal"] {
        let mut event = publication(&route.route_key, id, Some("generation"));
        if id == "terminal" {
            event.expires_at_ms = Some(1003);
        }
        storage.publish_v1(TOKEN, &event, &|| 1001).unwrap();
    }
    let recipient = codex("caller");
    let a = attest(&recipient, Lifecycle::Inactive, 1);
    let Selection::Attempt(r) = storage
        .reserve_next(&a, EffectiveMode::Message, 1002, &DispatchTiming::default())
        .unwrap()
    else {
        panic!("unknown reservation")
    };
    assert_eq!(r.members[0].event_id, "unknown");
    storage.mark_invoking(&r.fence, &a, 1002).unwrap();
    storage
        .record_outcome(
            &r.fence,
            Outcome::OutcomeUnknown {
                reason: "fixture unknown".into(),
            },
            1002,
        )
        .unwrap();
    storage.expire_due(1004).unwrap();
    let params = RetireDeliveryScopeParams {
        scope_key: "generation".into(),
        action: RetirementAction::Preserve,
    };
    let first = storage
        .retire_delivery_scope(TOKEN, "preserve-first", &params, &|| 1005)
        .unwrap();
    assert_eq!(
        (
            first.receipt.disposed,
            first.receipt.already_terminal,
            first.receipt.preserved_possible_effect,
            first.receipt.preserved_unhanded
        ),
        (0, 1, 1, 1)
    );
    assert!(
        storage
            .publish_v1(
                TOKEN,
                &publication(&route.route_key, "late", Some("generation")),
                &|| 1006
            )
            .is_err()
    );
    let Selection::Attempt(safe) = storage
        .reserve_next(&a, EffectiveMode::Message, 1006, &DispatchTiming::default())
        .unwrap()
    else {
        panic!("preserve must keep accepted dispatch")
    };
    assert_eq!(safe.members[0].event_id, "safe");
    storage.mark_invoking(&safe.fence, &a, 1007).unwrap();
    storage
        .record_outcome(
            &safe.fence,
            Outcome::NativeAccepted {
                evidence: "fixture native acceptance".into(),
            },
            1008,
        )
        .unwrap();
    let later = storage
        .retire_delivery_scope(TOKEN, "preserve-later", &params, &|| 1009)
        .unwrap();
    assert_eq!(
        later.receipt,
        RetireReceipt {
            request_id: "preserve-later".into(),
            ..first.receipt.clone()
        }
    );
    assert!(
        storage
            .retire_delivery_scope(
                TOKEN,
                "changed-action",
                &RetireDeliveryScopeParams {
                    scope_key: "generation".into(),
                    action: RetirementAction::RetireUnhanded
                },
                &|| 1010
            )
            .is_err()
    );
    drop(storage);
    let mut storage = store(&path);
    let replay = storage
        .retire_delivery_scope(TOKEN, "preserve-first", &params, &|| 2000)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, first.receipt);
    let again = storage
        .retire_delivery_scope(TOKEN, "after-restart", &params, &|| 2000)
        .unwrap();
    assert_eq!(
        again.receipt,
        RetireReceipt {
            request_id: "after-restart".into(),
            ..first.receipt
        }
    );
}
/// A producer whose grant permits only `auto` publishes by exact address to a
/// recipient whose adapter loaded only the message path: `auto` is admitted
/// (it resolves to message while positively inactive), explicit `message` and
/// `inject` stay outside the unchanged grant, and with no loaded path `auto` is
/// refused as unsupported before any custody row exists.
#[test]
fn auto_only_grant_reaches_a_message_only_recipient_and_nothing_else() {
    let dir = TempDir::new("universal-auto-only");
    let path = dir.path("state.db");
    let mut storage = Storage::open(&path, bridge_core::Limits::new(100)).unwrap();
    let mut only_auto = grant(TOKEN, "report-maker");
    only_auto.modes = vec!["auto".into()];
    storage
        .install_producer_authorizer(Arc::new(ProducerAuthorizer::new(&[only_auto]).unwrap()))
        .unwrap();
    storage
        .register_source_tag("report-maker", "report-maker")
        .unwrap();
    let recipient = codex("thread-message-only");
    let direct = |event: &str, mode: Mode| PublishParams {
        destination: Destination::Address {
            address: recipient.to_canonical_string(),
        },
        mode,
        ..publication("unused", event, None)
    };
    let loaded = |inject: bool, message: bool| {
        bridge_core::dispatch::Attestation::verified(
            recipient.clone(),
            "thread-message-only",
            1,
            Lifecycle::Inactive,
            bridge_core::dispatch::Capabilities { inject, message },
            "fixture-proof",
        )
        .unwrap()
    };
    let events = |sql: &rusqlite::Connection| {
        sql.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, u64>(0))
            .unwrap()
    };
    let sql = rusqlite::Connection::open(&path).unwrap();

    storage
        .observe_binding(&loaded(false, true), 1_000)
        .unwrap();
    storage
        .publish_v1(TOKEN, &direct("auto-ok", Mode::Auto), &|| 1_001)
        .unwrap();
    assert_eq!(events(&sql), 1);
    for mode in [Mode::Message, Mode::Inject] {
        let error = storage
            .publish_v1(
                TOKEN,
                &direct(&format!("not-granted-{mode:?}"), mode),
                &|| 1_002,
            )
            .unwrap_err();
        assert_eq!(error.class, ErrorClass::Forbidden, "{mode:?}");
    }
    assert_eq!(events(&sql), 1, "ungranted modes created no custody");

    storage
        .observe_binding(&loaded(false, false), 2_000)
        .unwrap();
    let error = storage
        .publish_v1(TOKEN, &direct("auto-none", Mode::Auto), &|| 2_001)
        .unwrap_err();
    assert_eq!(error.class, ErrorClass::Unsupported);
    assert_eq!(events(&sql), 1, "no loaded path created no custody");
}
