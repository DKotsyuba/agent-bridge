//! Dispatch-time selection between the two existing delivery paths.
//!
//! `auto` has no independent transport. Selection happens when dispatching,
//! not when accepting the event: the immutable envelope keeps
//! `requested_mode = auto`, and the attempt records the effective carrier.
//! Both choices share the event identity, attempt ownership and
//! deduplication rules, and exactly one path is ever invoked for one event.
//!
//! The owner accepts one timing edge as minor: a recipient's state may
//! change between the fresh activity check and the invocation. Selection
//! records the observed state and timestamp instead of trying to eliminate
//! the race; no new atomic host API is introduced for it.

use crate::lifecycle::{GuardDecision, LifecycleState, NoWakePolicy, Observation};

/// Which existing carrier an attempt is (to be) invoked through.
///
/// There is no third value: `auto` selects one of these two and is never a
/// carrier itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CarrierName {
    /// The quiet root hook drain at a natural context point.
    Inject,
    /// The queue/later message carrier creating a distinct later step.
    Message,
}

impl CarrierName {
    /// Canonical carrier name, matching core mode names.
    pub const fn as_str(self) -> &'static str {
        match self {
            CarrierName::Inject => "inject",
            CarrierName::Message => "message",
        }
    }
}

/// The decision made for one event at dispatch time.
///
/// `Hold` is a first-class outcome, not an error: the event stays with the
/// core's custody, visibly, until trustworthy evidence exists or an
/// operator acts. Nothing here expires or drops the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Proceed through exactly this carrier.
    Invoke(CarrierName),
    /// Do not invoke; the reason names the exact rule that held.
    Hold(&'static str),
}

/// What selection observed, recorded on the attempt for later evidence.
///
/// This is the accepted timing race made visible: the state and moment the
/// decision was based on, plus whether a cheap recheck was already
/// available. It is evidence, never a second invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionBasis {
    /// The effective lifecycle state the decision used (after freshness,
    /// source and epoch degradation in [`Observation::effective_state`]).
    pub effective_state: LifecycleState,
    /// Unix epoch milliseconds of the observation the decision used.
    pub observed_at_ms: u64,
    /// Whether a cheaper, newer recheck was already available and used.
    pub used_cheap_recheck: bool,
}

/// Selects the effective carrier for one event at dispatch time.
///
/// For `requested = inject` or `message` the requested carrier is used
/// (still subject to the no-wake/permission guards for `message`). For
/// `auto`: `Active` selects inject, `Idle` selects message, and everything
/// else — pause, permission/input wait, disconnected, archived, unknown —
/// holds. The no-wake policy applies to both carriers before any
/// invocation. Pure function; it never invokes anything itself.
pub fn select(
    requested: bridge_core::Mode,
    observation: &Observation,
    now_ms: u64,
    max_observation_age_ms: u64,
    current_epoch: crate::attest::BindingEpoch,
    canonical_address: &str,
    policy: &NoWakePolicy,
) -> (Selection, SelectionBasis) {
    let effective_state =
        observation.effective_state(now_ms, max_observation_age_ms, current_epoch);
    let basis = SelectionBasis {
        effective_state,
        observed_at_ms: observation.observed_at_ms,
        used_cheap_recheck: false,
    };
    let carrier = match requested {
        bridge_core::Mode::Inject => CarrierName::Inject,
        bridge_core::Mode::Message => CarrierName::Message,
        bridge_core::Mode::Auto => match effective_state {
            LifecycleState::Active => CarrierName::Inject,
            LifecycleState::Idle => CarrierName::Message,
            LifecycleState::Paused => {
                return (
                    Selection::Hold("auto holds: recipient explicitly paused"),
                    basis,
                );
            }
            LifecycleState::PermissionWait => {
                return (
                    Selection::Hold("auto holds: permission wait is not wakeable"),
                    basis,
                );
            }
            LifecycleState::InputWait => {
                return (
                    Selection::Hold("auto holds: input wait is not wakeable"),
                    basis,
                );
            }
            LifecycleState::Disconnected => {
                return (
                    Selection::Hold("auto holds: disconnected is not inactive"),
                    basis,
                );
            }
            LifecycleState::Archived => {
                return (
                    Selection::Hold("auto holds: archived target rejects and holds"),
                    basis,
                );
            }
            LifecycleState::Unknown => {
                return (
                    Selection::Hold("auto holds: unknown is not inactive"),
                    basis,
                );
            }
        },
    };
    match crate::lifecycle::guard_invocation(canonical_address, carrier, effective_state, policy) {
        GuardDecision::Allow => (Selection::Invoke(carrier), basis),
        GuardDecision::Hold(reason) => (Selection::Hold(reason), basis),
    }
}

/// Re-selects for a still-pending, never-handed event after a verified
/// state change.
///
/// Permitted only while the event has never been handed to either path: a
/// verified change from active to inactive may select `message` instead of
/// waiting indefinitely for a hook. Mere absence of a hook, or a timeout,
/// is not evidence of inactivity and never authorizes this. Once either
/// path might have received the event, uncertainty must be reconciled —
/// the other path is never sent as a fallback.
pub fn reselect_if_never_handed(
    previous: &Selection,
    observation: &Observation,
    now_ms: u64,
    max_observation_age_ms: u64,
    current_epoch: crate::attest::BindingEpoch,
    canonical_address: &str,
    policy: &NoWakePolicy,
) -> (Selection, SelectionBasis) {
    match previous {
        Selection::Invoke(CarrierName::Message) | Selection::Hold(_) => {
            // Nothing was handed to inject yet; a fresh verified
            // observation may legitimately change the decision.
        }
        Selection::Invoke(CarrierName::Inject) => {
            // A previous inject selection that has not been handed is the
            // only switchable case; fall through to fresh selection.
        }
    }
    let (selection, mut basis) = select(
        bridge_core::Mode::Auto,
        observation,
        now_ms,
        max_observation_age_ms,
        current_epoch,
        canonical_address,
        policy,
    );
    basis.used_cheap_recheck = true;
    (selection, basis)
}

#[cfg(test)]
mod tests {
    //! Unit checks for auto selection and its guards.

    use super::*;
    use crate::attest::BindingEpoch;
    use crate::lifecycle::{ObservationSource, PauseCause};
    use bridge_core::Mode;

    fn observation(state: LifecycleState, at_ms: u64) -> Observation {
        Observation {
            state,
            source: ObservationSource::OwnerSession,
            binding_epoch: BindingEpoch(1),
            observed_at_ms: at_ms,
        }
    }

    #[test]
    fn auto_maps_active_to_inject_and_idle_to_message() {
        let policy = NoWakePolicy::default();
        let (selection, basis) = select(
            Mode::Auto,
            &observation(LifecycleState::Active, 1_000),
            1_000,
            500,
            BindingEpoch(1),
            "a",
            &policy,
        );
        assert_eq!(selection, Selection::Invoke(CarrierName::Inject));
        assert_eq!(basis.effective_state, LifecycleState::Active);
        let (selection, _) = select(
            Mode::Auto,
            &observation(LifecycleState::Idle, 1_000),
            1_000,
            500,
            BindingEpoch(1),
            "a",
            &policy,
        );
        assert_eq!(selection, Selection::Invoke(CarrierName::Message));
    }

    #[test]
    fn auto_holds_everything_it_cannot_classify() {
        let policy = NoWakePolicy::default();
        for state in [
            LifecycleState::Paused,
            LifecycleState::PermissionWait,
            LifecycleState::InputWait,
            LifecycleState::Disconnected,
            LifecycleState::Archived,
            LifecycleState::Unknown,
        ] {
            let (selection, _) = select(
                Mode::Auto,
                &observation(state, 1_000),
                1_000,
                500,
                BindingEpoch(1),
                "a",
                &policy,
            );
            assert!(matches!(selection, Selection::Hold(_)), "{state:?}");
        }
    }

    #[test]
    fn explicit_no_wake_entry_holds_both_carriers() {
        let mut policy = NoWakePolicy::default();
        policy.pause("a", PauseCause::BridgePause);
        for mode in [Mode::Inject, Mode::Message, Mode::Auto] {
            let (selection, _) = select(
                mode,
                &observation(LifecycleState::Idle, 1_000),
                1_000,
                500,
                BindingEpoch(1),
                "a",
                &policy,
            );
            assert!(matches!(selection, Selection::Hold(_)), "{mode:?}");
        }
    }

    #[test]
    fn reselect_switches_only_never_handed_events() {
        let policy = NoWakePolicy::default();
        let (previous, _) = select(
            Mode::Auto,
            &observation(LifecycleState::Active, 1_000),
            1_000,
            60_000,
            BindingEpoch(1),
            "a",
            &policy,
        );
        assert_eq!(previous, Selection::Invoke(CarrierName::Inject));
        // Verified active -> idle while never handed: switch to message.
        let (selection, basis) = reselect_if_never_handed(
            &previous,
            &observation(LifecycleState::Idle, 2_000),
            2_000,
            60_000,
            BindingEpoch(1),
            "a",
            &policy,
        );
        assert_eq!(selection, Selection::Invoke(CarrierName::Message));
        assert!(basis.used_cheap_recheck);
        // An unclassifiable new observation still holds.
        let (selection, _) = reselect_if_never_handed(
            &previous,
            &observation(LifecycleState::Unknown, 2_000),
            2_000,
            60_000,
            BindingEpoch(1),
            "a",
            &policy,
        );
        assert!(matches!(selection, Selection::Hold(_)));
    }
}
