//! Claude `later` carrier: held receipts, daemon callbacks and
//! written-without-receipt.
//!
//! Claude `message` maps to an authenticated native peer send with
//! `priority = later`: the payload produces a distinct subsequent step
//! after the current work. `default` and `next` are **not** `later` and
//! are never used for message ([`PeerPriority::is_message_carrier`]).
//!
//! Two second-review corrections live here:
//!
//! - **held is nonterminal.** The old ephemeral 1.5 s reply socket could
//!   miss a later release or drop, so held receipts are observed by a
//!   stable daemon callback bound to the endpoint epoch and message id
//!   ([`HeldTracker`]); a daemon restart converts unresolved held
//!   messages to uncertainty rather than guessing. Any post-hold retry
//!   requires positive proof that the exact loaded native classification
//!   means no context acceptance — never a timer.
//! - **written_no_receipt is its own state.** An immediate idle-Claude
//!   acceptance under NORMAL success can come back with no receipt;
//!   that is tracked separately ([`WrittenNoReceipt`]) and closed only
//!   by a positive exact-session marker+digest match. An absent marker
//!   never retries.
//!
//! Peer inject is prohibited on this host; the quiet path is the root
//! hook drain in [`crate::hook`], and `shouldQuery = false` as a
//! quiet-delivery request on a peer socket is refused by construction —
//! no such operation exists here.

use std::collections::BTreeMap;

use crate::attest::BindingEpoch;

/// Peer send priority as observed on the native peer protocol.
///
/// Only `Later` is the message carrier. `Default` and `Next` fold into or
/// steer the receiver's current work in the tested cases and must never be
/// substituted for `later`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerPriority {
    /// Folds into current work; not the message carrier.
    Default,
    /// Steers the current turn; not the message carrier.
    Next,
    /// Produces a distinct subsequent step; the message carrier.
    Later,
}

impl PeerPriority {
    /// Whether this priority is the Claude message carrier.
    pub const fn is_message_carrier(self) -> bool {
        matches!(self, PeerPriority::Later)
    }
}

/// Native message id assigned by the peer protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub String);

/// Observation of one `later` send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaterOutcome {
    /// The peer accepted the message for a later step. `receipt` is the
    /// native acknowledgement when one arrived in the same exchange; the
    /// receipt-less case is [`LaterOutcome::WrittenNoReceipt`], not this.
    Accepted { msg_id: MessageId },
    /// The write completed under NORMAL success but no receipt came back;
    /// tracked separately from both acceptance and failure.
    WrittenNoReceipt { msg_id: MessageId },
    /// The native side held the message (a nonterminal condition); a
    /// stable daemon callback will observe release or drop.
    Held { msg_id: MessageId },
    /// The peer refused the send outright; positively not accepted.
    Refused { reason: &'static str },
}

/// Callback observation delivered by the stable held-receipt daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldCallback {
    /// The held message was released into context.
    Released,
    /// The held message was dropped by the native side.
    Dropped,
}

/// Per-message state of the held-receipt tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldState {
    /// Held under a binding epoch, awaiting a callback.
    Held,
    /// A callback arrived and was recorded.
    Closed(HeldCallback),
    /// The daemon restarted (or a reply was missed) while held; the
    /// eventual state is unknown and must be reconciled positively.
    Uncertain,
}

/// Stable daemon-callback registry for held messages.
///
/// Callbacks are keyed by the exact `(binding epoch, message id)` they
/// were bound to: a callback from another epoch does not apply. A daemon
/// restart ([`HeldTracker::daemon_restarted`]) marks every still-held
/// message [`LaterOutcome`]-level uncertainty instead of assuming release
/// or drop. Lookups never mutate state; only explicit callbacks and the
/// restart marker do.
#[derive(Debug, Default)]
pub struct HeldTracker {
    entries: BTreeMap<(u64, String), HeldState>,
}

impl HeldTracker {
    /// Registers one held message under its epoch and id.
    pub fn held(&mut self, epoch: BindingEpoch, msg_id: &MessageId) {
        self.entries
            .insert((epoch.0, msg_id.0.clone()), HeldState::Held);
    }

    /// Applies one daemon callback.
    ///
    /// Returns `true` when a held entry consumed it. Callbacks for
    /// unknown pairs, already-closed entries or foreign epochs return
    /// `false` and change nothing (a stale callback can never close a
    /// renewed binding's message).
    pub fn callback(
        &mut self,
        epoch: BindingEpoch,
        msg_id: &MessageId,
        callback: HeldCallback,
    ) -> bool {
        match self.entries.get_mut(&(epoch.0, msg_id.0.clone())) {
            Some(HeldState::Held) => {
                self.entries
                    .insert((epoch.0, msg_id.0.clone()), HeldState::Closed(callback));
                true
            }
            _ => false,
        }
    }

    /// Marks a daemon restart.
    ///
    /// Every still-held (not yet closed) entry becomes uncertain: missed
    /// replies are recorded as uncertainty, never guessed into release or
    /// drop. Returns how many entries were converted.
    pub fn daemon_restarted(&mut self) -> usize {
        let mut converted = 0;
        for state in self.entries.values_mut() {
            if *state == HeldState::Held {
                *state = HeldState::Uncertain;
                converted += 1;
            }
        }
        converted
    }

    /// Current state of one held message, if tracked.
    pub fn state(&self, epoch: BindingEpoch, msg_id: &MessageId) -> Option<&HeldState> {
        self.entries.get(&(epoch.0, msg_id.0.clone()))
    }
}

/// Positive proof that a held message never reached context.
///
/// Constructible only from an affirmative native classification of the
/// exact loaded host (for example a persisted "dropped before context"
/// state). Its existence is the sole key that unlocks a post-hold retry
/// decision — which itself remains an explicit, audited core decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositiveNoAcceptance {
    /// Human-readable description of the positive native evidence.
    pub evidence: String,
}

/// Decision requested of held-message reconciliation.
///
/// [`HeldReconciliation::resolve`] maps the available material to an
/// outcome; the caller cannot ask for a retry without the positive proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldReconciliation {
    /// Resolve one held or uncertain message.
    Resolve {
        /// Epoch the message was held under.
        epoch: BindingEpoch,
        /// Native message id.
        msg_id: MessageId,
        /// Positive no-acceptance proof, if one exists.
        positive_no_acceptance: Option<PositiveNoAcceptance>,
    },
}

impl HeldReconciliation {
    /// Resolves a reconciliation request.
    ///
    /// Closed entries stay closed (idempotent); uncertain or held entries
    /// without positive proof remain retained (the returned outcome says
    /// so); only positive proof of no acceptance permits marking the
    /// attempt positively unsent. Nothing is ever replayed here.
    pub fn resolve(&self, tracker: &HeldTracker) -> crate::dispatch::AttemptOutcome {
        use crate::dispatch::AttemptOutcome;
        let HeldReconciliation::Resolve {
            epoch,
            msg_id,
            positive_no_acceptance,
        } = self;
        match tracker.state(*epoch, msg_id) {
            Some(HeldState::Closed(callback)) => match callback {
                HeldCallback::Released => AttemptOutcome::Accepted,
                HeldCallback::Dropped => AttemptOutcome::PositivelyUnsent {
                    reason: "native side positively dropped the held message",
                },
            },
            Some(HeldState::Uncertain) | Some(HeldState::Held) => {
                if positive_no_acceptance.is_some() {
                    AttemptOutcome::PositivelyUnsent {
                        reason: "positive native classification: no context acceptance",
                    }
                } else {
                    AttemptOutcome::PossiblyAccepted {
                        reason: "held or uncertain without positive no-acceptance proof",
                    }
                }
            }
            None => AttemptOutcome::PossiblyAccepted {
                reason: "no tracked held entry; handoff state unknown",
            },
        }
    }
}

/// Closure attempt for a written-without-receipt message.
///
/// An immediate idle-Claude acceptance under NORMAL success may carry no
/// receipt. Closure requires a **positive** exact-session marker+digest
/// match: the marker text found in that session matching the digest of
/// what was sent. An absent marker never retries — it escalates to an
/// exceptional incident instead of routine unknown alarms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenNoReceipt {
    /// Native message id of the receipt-less write.
    pub msg_id: MessageId,
    /// SHA-256 hex digest of the payload as written.
    pub payload_digest: String,
    /// Marker evidence found in the exact session, once observed.
    pub marker: Option<MarkerMatch>,
}

/// A positive marker+digest match observed in one exact session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerMatch {
    /// The session the marker was found in (must equal the recipient's).
    pub session_id: String,
    /// The digest as reconstructed from the observed marker.
    pub observed_digest: String,
}

impl WrittenNoReceipt {
    /// Attempts closure from an observed marker.
    ///
    /// Closes only when the marker is in the exact recipient session and
    /// its digest equals the written digest. Mismatch keeps the entry
    /// open — `false` never means "not delivered" and never retries.
    pub fn attempt_closure(&mut self, marker: MarkerMatch) -> bool {
        if marker.observed_digest == self.payload_digest {
            self.marker = Some(marker);
            true
        } else {
            false
        }
    }

    /// Whether positive closure succeeded.
    pub fn closed(&self) -> bool {
        self.marker.is_some()
    }

    /// Outcome contribution: closed is acceptance evidence; open is a
    /// distinct written-no-receipt uncertainty, not a routine unknown.
    pub fn outcome(&self) -> crate::dispatch::AttemptOutcome {
        if self.closed() {
            crate::dispatch::AttemptOutcome::Accepted
        } else {
            crate::dispatch::AttemptOutcome::PossiblyAccepted {
                reason: "written without receipt; closure marker not yet observed",
            }
        }
    }
}

/// The Claude `uds_unconfirmed` observation.
///
/// A normal peer delivery can wake the receiver while the sender's UDS
/// channel reports unconfirmed. That is conservative
/// [`crate::dispatch::AttemptOutcome::PossiblyAccepted`] territory: no
/// retry loop, and transcript absence of `msg_id` (observed in the live
/// test) never authorizes replay.
pub fn uds_unconfirmed_outcome() -> crate::dispatch::AttemptOutcome {
    crate::dispatch::AttemptOutcome::PossiblyAccepted {
        reason: "uds unconfirmed; visible acknowledgement may exist without it",
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for the later carrier, held receipts and closure.

    use super::*;

    #[test]
    fn only_later_is_the_message_carrier() {
        assert!(PeerPriority::Later.is_message_carrier());
        assert!(!PeerPriority::Default.is_message_carrier());
        assert!(!PeerPriority::Next.is_message_carrier());
    }

    #[test]
    fn held_callbacks_are_epoch_bound_and_restart_uncertain() {
        let mut tracker = HeldTracker::default();
        let msg = MessageId("m-1".into());
        tracker.held(BindingEpoch(1), &msg);
        // A callback from a foreign epoch does not apply.
        assert!(!tracker.callback(BindingEpoch(2), &msg, HeldCallback::Released));
        assert!(tracker.state(BindingEpoch(1), &msg).is_some());
        // Release under the bound epoch closes the entry.
        assert!(tracker.callback(BindingEpoch(1), &msg, HeldCallback::Released));
        assert!(!tracker.callback(BindingEpoch(1), &msg, HeldCallback::Dropped));
        // A second held message turns uncertain on daemon restart.
        let msg2 = MessageId("m-2".into());
        tracker.held(BindingEpoch(1), &msg2);
        assert_eq!(tracker.daemon_restarted(), 1);
        assert_eq!(
            tracker.state(BindingEpoch(1), &msg2),
            Some(&HeldState::Uncertain)
        );
        // Uncertain without positive proof stays retained.
        let reconciliation = HeldReconciliation::Resolve {
            epoch: BindingEpoch(1),
            msg_id: msg2.clone(),
            positive_no_acceptance: None,
        };
        assert!(matches!(
            reconciliation.resolve(&tracker),
            crate::dispatch::AttemptOutcome::PossiblyAccepted { .. }
        ));
        // Positive proof converts it to positively unsent.
        let reconciliation = HeldReconciliation::Resolve {
            epoch: BindingEpoch(1),
            msg_id: msg2,
            positive_no_acceptance: Some(PositiveNoAcceptance {
                evidence: "persisted drop-before-context state".into(),
            }),
        };
        assert!(matches!(
            reconciliation.resolve(&tracker),
            crate::dispatch::AttemptOutcome::PositivelyUnsent { .. }
        ));
        // A released entry is acceptance; a dropped entry is positively
        // unsent.
        assert_eq!(
            HeldReconciliation::Resolve {
                epoch: BindingEpoch(1),
                msg_id: msg.clone(),
                positive_no_acceptance: None,
            }
            .resolve(&tracker),
            crate::dispatch::AttemptOutcome::Accepted
        );
    }

    #[test]
    fn written_no_receipt_closes_only_on_positive_marker_match() {
        let mut entry = WrittenNoReceipt {
            msg_id: MessageId("m-3".into()),
            payload_digest: "digest-a".into(),
            marker: None,
        };
        assert!(!entry.closed());
        // Wrong digest or wrong session does not close and does not retry.
        assert!(!entry.attempt_closure(MarkerMatch {
            session_id: "session-9".into(),
            observed_digest: "digest-b".into(),
        }));
        assert!(!entry.closed());
        assert!(entry.attempt_closure(MarkerMatch {
            session_id: "session-9".into(),
            observed_digest: "digest-a".into(),
        }));
        assert!(entry.closed());
        assert_eq!(entry.outcome(), crate::dispatch::AttemptOutcome::Accepted);
        let open = WrittenNoReceipt {
            msg_id: MessageId("m-4".into()),
            payload_digest: "digest-c".into(),
            marker: None,
        };
        assert!(matches!(
            open.outcome(),
            crate::dispatch::AttemptOutcome::PossiblyAccepted { .. }
        ));
    }

    #[test]
    fn uds_unconfirmed_is_conservative() {
        assert!(matches!(
            uds_unconfirmed_outcome(),
            crate::dispatch::AttemptOutcome::PossiblyAccepted { .. }
        ));
    }
}
