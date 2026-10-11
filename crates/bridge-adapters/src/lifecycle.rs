//! Loaded lifecycle observation and the explicit no-wake policy.
//!
//! The `auto` selector and the message carrier are allowed to act on
//! lifecycle evidence only through this module, whose central rule is
//! negative: **unknown, disconnected and `notLoaded` are never inactive**.
//! An active execution includes work awaiting a tool result; an approval or
//! input wait is never reclassified as wakeable idle and is never answered
//! by a notification. A Bridge pause and a native Stop/interrupt are
//! different events, wired explicitly, and lost lifecycle evidence means no
//! new automatic invocation.

use std::collections::BTreeMap;

use crate::attest::BindingEpoch;

/// Observed lifecycle state of one native recipient session.
///
/// States are mutually exclusive observations from the actual owner session,
/// not deductions from silence, queue contents or a secondary App Server's
/// connection-local status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleState {
    /// Currently executing, including work that is awaiting a tool result;
    /// momentarily not generating is not idle.
    Active,
    /// Genuinely at a natural end: no work in flight, no pending input.
    Idle,
    /// Under an explicit pause (Bridge no-wake policy or observed native
    /// pause); distinct from an interrupt event.
    Paused,
    /// Blocked on a can_use_tool style permission request; never answered
    /// or resolved by Bridge.
    PermissionWait,
    /// Blocked waiting for human input; not wakeable by notification.
    InputWait,
    /// The endpoint is gone; queue entries may persist, but that is storage
    /// acceptance, not delivery, and never idleness.
    Disconnected,
    /// The native target is archived; publication rejects and holds rather
    /// than unarchiving, resuming or relabeling.
    Archived,
    /// No trustworthy lifecycle evidence; holds visibly instead of guessing.
    Unknown,
}

impl LifecycleState {
    /// Canonical state name for records and status output.
    pub const fn as_str(self) -> &'static str {
        match self {
            LifecycleState::Active => "active",
            LifecycleState::Idle => "idle",
            LifecycleState::Paused => "paused",
            LifecycleState::PermissionWait => "permission_wait",
            LifecycleState::InputWait => "input_wait",
            LifecycleState::Disconnected => "disconnected",
            LifecycleState::Archived => "archived",
            LifecycleState::Unknown => "unknown",
        }
    }

    /// Whether a recipient in this state may be woken by the `message`
    /// carrier.
    ///
    /// Only genuine [`LifecycleState::Idle`] may. Active recipients must not
    /// be interrupted; paused, waiting, disconnected, archived and unknown
    /// recipients hold. This is the one place the wakeability rule lives.
    pub const fn wakeable(self) -> bool {
        matches!(self, LifecycleState::Idle)
    }
}

/// Where a lifecycle observation came from.
///
/// Only the actual owner session's evidence is authoritative. A secondary
/// App Server's local status (for example a queue helper's connection-local
/// `notLoaded`) says nothing about the recipient and is never usable for
/// selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationSource {
    /// Authoritative evidence from the recipient's actual owner session.
    OwnerSession,
    /// Connection-local status of a secondary helper or App Server;
    /// explicitly insufficient for activity decisions.
    SecondaryAppServer,
}

/// One lifecycle observation, bound to an epoch and a moment.
///
/// `observed_at_ms` bounds freshness at the point of use: an observation
/// older than the caller's maximum staleness is treated as
/// [`LifecycleState::Unknown`], never as its last-known value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The observed state.
    pub state: LifecycleState,
    /// Who observed it.
    pub source: ObservationSource,
    /// Binding epoch the observation was made under; a later epoch on the
    /// binding invalidates it.
    pub binding_epoch: BindingEpoch,
    /// Unix epoch milliseconds of observation.
    pub observed_at_ms: u64,
}

impl Observation {
    /// The effective state for selection after freshness and source checks.
    ///
    /// Returns [`LifecycleState::Unknown`] when the observation is stale
    /// (`older_than_ms`), comes from a secondary App Server, or was taken
    /// under a different binding epoch than `current_epoch`. The observed
    /// state itself is never "rounded" to a friendlier one.
    pub fn effective_state(
        &self,
        now_ms: u64,
        max_age_ms: u64,
        current_epoch: BindingEpoch,
    ) -> LifecycleState {
        if self.source != ObservationSource::OwnerSession {
            return LifecycleState::Unknown;
        }
        if self.binding_epoch != current_epoch {
            return LifecycleState::Unknown;
        }
        if now_ms.saturating_sub(self.observed_at_ms) > max_age_ms {
            return LifecycleState::Unknown;
        }
        self.state
    }
}

/// Why a pause exists; Bridge pauses and native interrupts stay distinct.
///
/// Both cause a no-wake hold, but they are recorded and cleared separately
/// so a native Stop event can never silently create (or lift) an explicit
/// Bridge pause, and stale history can never prove a permanent pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauseCause {
    /// An explicit Bridge no-wake policy entry for this recipient.
    BridgePause,
    /// An observed native Stop/interrupt event (its own scoped native
    /// behavior, not a universal pause guarantee).
    NativeInterrupt,
}

/// The durable, explicit no-wake policy covering `auto` AND `message`.
///
/// Entries are per exact canonical address string; there is deliberately no
/// wildcard, name or project form. Adding an entry never wakes anyone and
/// removing one never answers anything — it only re-opens future selection.
#[derive(Debug, Default, Clone)]
pub struct NoWakePolicy {
    pauses: BTreeMap<String, PauseCause>,
}

impl NoWakePolicy {
    /// Records one no-wake entry for an exact canonical address.
    ///
    /// Inserting the same address again replaces the cause; both pause
    /// kinds hold equally.
    pub fn pause(&mut self, canonical_address: &str, cause: PauseCause) {
        self.pauses.insert(canonical_address.to_string(), cause);
    }

    /// Clears one no-wake entry.
    ///
    /// A native interrupt entry is never cleared by a Bridge unpause and
    /// vice versa: the recorded cause must match.
    pub fn resume(&mut self, canonical_address: &str, cause: PauseCause) -> bool {
        match self.pauses.get(canonical_address) {
            Some(recorded) if *recorded == cause => {
                self.pauses.remove(canonical_address);
                true
            }
            _ => false,
        }
    }

    /// Whether this exact address currently holds under the policy.
    pub fn is_paused(&self, canonical_address: &str) -> bool {
        self.pauses.contains_key(canonical_address)
    }

    /// The recorded cause for a held address, if any.
    pub fn cause(&self, canonical_address: &str) -> Option<PauseCause> {
        self.pauses.get(canonical_address).copied()
    }
}

/// Guard outcome for one prospective carrier invocation.
///
/// `Hold` carries the rule that blocked the invocation; it never implies the
/// event was delivered, expired or dropped — custody stays with the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    /// The invocation may proceed through the named carrier.
    Allow,
    /// The invocation is blocked; the reason names the exact rule.
    Hold(&'static str),
}

/// Applies the no-wake policy and permission/input guards to one carrier
/// invocation.
///
/// Rules, in order: an explicit no-wake entry holds both carriers; a
/// permission or input wait holds both (a notification must never answer or
/// be answered as approval); non-idle, non-active states hold the message
/// carrier because only genuine idleness is wakeable; the inject carrier is
/// not gated here — hooks drain at natural points regardless of activity,
/// and never wake the recipient.
pub fn guard_invocation(
    canonical_address: &str,
    carrier: crate::auto::CarrierName,
    state: LifecycleState,
    policy: &NoWakePolicy,
) -> GuardDecision {
    if policy.is_paused(canonical_address) {
        return GuardDecision::Hold("explicit no-wake policy entry");
    }
    match state {
        LifecycleState::PermissionWait => {
            GuardDecision::Hold("permission request must never be answered by a notification")
        }
        LifecycleState::InputWait => GuardDecision::Hold("input wait is not wakeable idle"),
        LifecycleState::Active
        | LifecycleState::Idle
        | LifecycleState::Paused
        | LifecycleState::Disconnected
        | LifecycleState::Archived
        | LifecycleState::Unknown => {
            if carrier == crate::auto::CarrierName::Message && !state.wakeable() {
                GuardDecision::Hold("message carrier requires genuine idleness")
            } else {
                GuardDecision::Allow
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for lifecycle rules and the no-wake policy.

    use super::*;

    fn observation(state: LifecycleState) -> Observation {
        Observation {
            state,
            source: ObservationSource::OwnerSession,
            binding_epoch: BindingEpoch(1),
            observed_at_ms: 10_000,
        }
    }

    #[test]
    fn unknown_disconnected_and_stale_are_never_inactive() {
        assert!(!LifecycleState::Unknown.wakeable());
        assert!(!LifecycleState::Disconnected.wakeable());
        assert!(!LifecycleState::Archived.wakeable());
        assert!(!LifecycleState::PermissionWait.wakeable());
        assert!(LifecycleState::Idle.wakeable());
        // Stale owner evidence degrades to unknown, not to the old value.
        let stale = observation(LifecycleState::Idle);
        assert_eq!(
            stale.effective_state(50_000, 1_000, BindingEpoch(1)),
            LifecycleState::Unknown
        );
        // Secondary App Server status is never authoritative.
        let secondary = Observation {
            source: ObservationSource::SecondaryAppServer,
            ..observation(LifecycleState::Idle)
        };
        assert_eq!(
            secondary.effective_state(10_000, 1_000, BindingEpoch(1)),
            LifecycleState::Unknown
        );
        // Wrong epoch invalidates the observation.
        let old_epoch = observation(LifecycleState::Active);
        assert_eq!(
            old_epoch.effective_state(10_000, 1_000, BindingEpoch(2)),
            LifecycleState::Unknown
        );
    }

    #[test]
    fn no_wake_policy_covers_both_carriers_and_keeps_causes_distinct() {
        let mut policy = NoWakePolicy::default();
        policy.pause("h/claude-code/s/sess", PauseCause::NativeInterrupt);
        for carrier in [
            crate::auto::CarrierName::Inject,
            crate::auto::CarrierName::Message,
        ] {
            assert_eq!(
                guard_invocation(
                    "h/claude-code/s/sess",
                    carrier,
                    LifecycleState::Idle,
                    &policy
                ),
                GuardDecision::Hold("explicit no-wake policy entry")
            );
        }
        // A Bridge unpause cannot clear a native interrupt entry.
        assert!(!policy.resume("h/claude-code/s/sess", PauseCause::BridgePause));
        assert!(policy.is_paused("h/claude-code/s/sess"));
        assert!(policy.resume("h/claude-code/s/sess", PauseCause::NativeInterrupt));
        assert!(!policy.is_paused("h/claude-code/s/sess"));
    }

    #[test]
    fn waits_are_never_answerable_or_wakeable() {
        let policy = NoWakePolicy::default();
        for state in [LifecycleState::PermissionWait, LifecycleState::InputWait] {
            for carrier in [
                crate::auto::CarrierName::Inject,
                crate::auto::CarrierName::Message,
            ] {
                assert!(matches!(
                    guard_invocation("a", carrier, state, &policy),
                    GuardDecision::Hold(_)
                ));
            }
        }
        // Message on non-idle states holds; inject is not activity-gated.
        assert!(matches!(
            guard_invocation(
                "a",
                crate::auto::CarrierName::Message,
                LifecycleState::Active,
                &policy
            ),
            GuardDecision::Hold(_)
        ));
        assert_eq!(
            guard_invocation(
                "a",
                crate::auto::CarrierName::Inject,
                LifecycleState::Active,
                &policy
            ),
            GuardDecision::Allow
        );
        assert_eq!(
            guard_invocation(
                "a",
                crate::auto::CarrierName::Message,
                LifecycleState::Idle,
                &policy
            ),
            GuardDecision::Allow
        );
    }
}
