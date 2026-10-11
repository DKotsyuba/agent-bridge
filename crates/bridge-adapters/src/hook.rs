//! Quiet root hook drain: manifest committed before any payload reply.
//!
//! `inject` keeps events in Bridge until a qualified root hook — a
//! `PostToolUse` or `UserPromptSubmit` (or equivalent natural context
//! point) — asks for them at a moment the recipient chose itself. The
//! drain never wakes the recipient: no peer send, no
//! `shouldQuery = false` on a peer socket (prohibited), no timeout-to-
//! message fallback. An event that never meets a hook simply stays.
//!
//! The ordering rule is structural: [`HookDrain::drain`] takes the commit
//! closure for the handoff manifest and calls it **before** any payload is
//! returned to the hook. If the commit fails, no payload exists to fail
//! with. After a possible payload reply, uncertainty is marked — a missing
//! acknowledgement, a crash after reply, partial stdout or a late return
//! never trigger an invisible retry or a reoffer.
//!
//! A child tool call never drains the parent's notification: drain
//! requests carry the attested caller, and a non-root actor refuses.

use crate::attest::{ActorRole, AttestedCaller};

/// The natural context points a root hook may drain at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookEvent {
    /// After a tool call completed inside the root session.
    PostToolUse,
    /// At the submit of a user prompt in the root session.
    UserPromptSubmit,
}

impl HookEvent {
    /// Canonical event name.
    pub const fn as_str(self) -> &'static str {
        match self {
            HookEvent::PostToolUse => "post_tool_use",
            HookEvent::UserPromptSubmit => "user_prompt_submit",
        }
    }
}

/// One hook's request to drain pending root-targeted events.
///
/// `caller` is the fail-closed attested caller of the hook; `event` is the
/// natural context point; `at_ms` is the hook's observation time.
#[derive(Debug, Clone)]
pub struct DrainRequest<'a> {
    /// Attested caller operating the hook (must be the root actor).
    pub caller: &'a AttestedCaller,
    /// The natural context point the hook fired at.
    pub event: HookEvent,
    /// Unix epoch milliseconds of the hook firing.
    pub at_ms: u64,
    /// Deadline for the whole drain exchange.
    pub deadline_ms: u64,
}

/// The handoff manifest committed before any payload reply.
///
/// Freezes what is about to be handed to the hook: which event, to which
/// root session and actor, at which context point, with which digest. The
/// commit is the "possible handoff" boundary — after it, missing
/// acknowledgements are uncertainty, not non-delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffManifest {
    /// Publisher-stable event id being handed.
    pub event_id: String,
    /// Canonical address of the root recipient.
    pub recipient: String,
    /// Root actor the payload is rendered for.
    pub actor_native_id: String,
    /// Digest of the rendered payload bytes.
    pub payload_digest: String,
    /// The context point the handoff occurs at.
    pub hook_event: HookEvent,
    /// When the handoff was committed.
    pub committed_at_ms: u64,
}

/// Result of committing a handoff manifest.
///
/// The commit is expected to be the core's transactional "invoking/hook
/// payload handed" state change; its failure means nothing was handed.
pub type CommitResult = Result<(), &'static str>;

/// The fault envelope a drain can fail into.
///
/// Every variant maps to a conservative outcome: before-reply crashes
/// after a successful commit are uncertain emissions (the manifest
/// committed but the hook may never have printed); anything after a
/// possible reply is possible acceptance; nothing here is ever
/// "definitely not delivered" without positive evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookFault {
    /// The hook process died before any payload reply.
    CrashBeforeReply,
    /// The hook died after a partial stdout write.
    CrashAfterPartialStdout,
    /// The hook was killed (signal) at an unknown point.
    Killed,
    /// The hook returned after the deadline.
    LateReturn,
    /// The hook reported busy and drained nothing.
    Busy,
    /// An fsync-level persistence failure while committing.
    FsyncFailure,
}

/// The distinct drain outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainOutcome {
    /// The hook took the payload and fully flushed stdout: positive
    /// emission evidence (which is not, by itself, proof of host context
    /// acceptance).
    Emitted {
        /// Digest of the payload the hook flushed.
        payload_digest: String,
    },
    /// The manifest committed and a reply may have happened; emission is
    /// uncertain and retained.
    UncertainEmission { reason: &'static str },
    /// Nothing was handed (commit failed, guard refused, busy or
    /// pre-commit crash); positively unsent.
    NotHanded { reason: &'static str },
}

/// The quiet root hook drain.
///
/// One type, one method. `drain` enforces, in order: root-only callers
/// (children never drain the parent's data), deadline, the guard decision
/// from the caller's own policy, the manifest commit, and only then the
/// payload reply through `emit`. `emit` returns the hook's transport
/// result; the mapping from [`HookFault`]s is total and conservative.
pub struct HookDrain;

impl HookDrain {
    /// Drains one pending root-targeted event at a natural context point.
    ///
    /// `commit` receives the frozen [`HandoffManifest`] and must persist
    /// it before returning `Ok(())`; `emit` hands the rendered payload to
    /// the hook transport and reports what the transport observed. The
    /// payload bytes are produced only after a successful commit, so a
    /// failed commit can never leak a half-handed payload. This method
    /// consumes the request: there is no retry or reoffer path, and no
    /// API surface here can wake the recipient.
    pub fn drain(
        request: &DrainRequest<'_>,
        manifest: HandoffManifest,
        guard: crate::lifecycle::GuardDecision,
        commit: impl FnOnce(&HandoffManifest) -> CommitResult,
        emit: impl FnOnce(&HandoffManifest) -> Result<EmittedFlush, HookFault>,
    ) -> Result<DrainOutcome, crate::AdapterError> {
        if request.caller.actor.role != ActorRole::Root {
            return Err(crate::AdapterError::ChildRefused(
                "a child tool call must not consume the parent's notification",
            ));
        }
        if request.at_ms > request.deadline_ms {
            return Ok(DrainOutcome::NotHanded {
                reason: "drain deadline exceeded before handoff",
            });
        }
        if let crate::lifecycle::GuardDecision::Hold(reason) = guard {
            return Ok(DrainOutcome::NotHanded { reason });
        }
        if commit(&manifest).is_err() {
            return Ok(DrainOutcome::NotHanded {
                reason: "handoff manifest commit refused; nothing was handed",
            });
        }
        match emit(&manifest) {
            Ok(flush) => Ok(DrainOutcome::Emitted {
                payload_digest: flush.payload_digest,
            }),
            Err(HookFault::CrashBeforeReply) => Ok(DrainOutcome::UncertainEmission {
                reason: "hook crashed after commit but before any payload reply",
            }),
            Err(HookFault::CrashAfterPartialStdout) => Ok(DrainOutcome::UncertainEmission {
                reason: "hook died after a partial stdout write",
            }),
            Err(HookFault::Killed) => Ok(DrainOutcome::UncertainEmission {
                reason: "hook killed at an unknown point after commit",
            }),
            Err(HookFault::LateReturn) => Ok(DrainOutcome::UncertainEmission {
                reason: "hook returned after the drain deadline",
            }),
            Err(HookFault::Busy) => Ok(DrainOutcome::NotHanded {
                reason: "hook reported busy; nothing was handed",
            }),
            Err(HookFault::FsyncFailure) => Ok(DrainOutcome::NotHanded {
                reason: "manifest persistence failed; treat as not handed and reconcile the commit",
            }),
        }
    }
}

/// What a successful hook emission observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedFlush {
    /// Digest of the payload the hook flushed to stdout.
    pub payload_digest: String,
}

#[cfg(test)]
mod tests {
    //! Unit checks for the drain ordering, guards and fault envelope.

    use super::*;
    use crate::attest::{ActorId, AttestedCaller, BindingEpoch, ProtectedChannel};
    use crate::lifecycle::GuardDecision;
    use bridge_core::{Harness, NativeAddress};

    fn root_caller() -> AttestedCaller {
        AttestedCaller {
            address: NativeAddress::new("h", Harness::ClaudeCode, "s", "sess").unwrap(),
            actor: ActorId::root("sess").unwrap(),
            epoch: BindingEpoch(1),
            observed_at_ms: 1_000,
            channel: ProtectedChannel::ClaudePreToolUse,
        }
    }

    fn manifest() -> HandoffManifest {
        HandoffManifest {
            event_id: "evt-1".into(),
            recipient: "h/claude-code/s/sess".into(),
            actor_native_id: "sess".into(),
            payload_digest: "digest-1".into(),
            hook_event: HookEvent::PostToolUse,
            committed_at_ms: 1_500,
        }
    }

    fn request(caller: &AttestedCaller) -> DrainRequest<'_> {
        DrainRequest {
            caller,
            event: HookEvent::PostToolUse,
            at_ms: 1_500,
            deadline_ms: 2_000,
        }
    }

    #[test]
    fn manifest_commits_before_any_payload_reply() {
        let caller = root_caller();
        let committed_first = std::cell::Cell::new(false);
        let outcome = HookDrain::drain(
            &request(&caller),
            manifest(),
            GuardDecision::Allow,
            |_| {
                committed_first.set(true);
                Ok(())
            },
            |_| {
                assert!(committed_first.get(), "payload produced before commit");
                Ok(EmittedFlush {
                    payload_digest: "digest-1".into(),
                })
            },
        )
        .unwrap();
        assert_eq!(
            outcome,
            DrainOutcome::Emitted {
                payload_digest: "digest-1".into()
            }
        );
    }

    #[test]
    fn failed_commit_hands_nothing() {
        let caller = root_caller();
        let mut emitted = false;
        let outcome = HookDrain::drain(
            &request(&caller),
            manifest(),
            GuardDecision::Allow,
            |_| Err("storage refused"),
            |_| {
                emitted = true;
                Ok(EmittedFlush {
                    payload_digest: "digest-1".into(),
                })
            },
        )
        .unwrap();
        assert!(!emitted);
        assert!(matches!(outcome, DrainOutcome::NotHanded { .. }));
    }

    #[test]
    fn children_never_drain_the_parent_notification() {
        let mut child = root_caller();
        child.actor = ActorId::child("agent-a").unwrap();
        let outcome = HookDrain::drain(
            &request(&child),
            manifest(),
            GuardDecision::Allow,
            |_| unreachable!("commit must not run for a child"),
            |_| unreachable!("emit must not run for a child"),
        );
        assert!(matches!(outcome, Err(crate::AdapterError::ChildRefused(_))));
    }

    #[test]
    fn fault_envelope_maps_conservatively() {
        let caller = root_caller();
        let faults = [
            (HookFault::CrashBeforeReply, false),
            (HookFault::CrashAfterPartialStdout, false),
            (HookFault::Killed, false),
            (HookFault::LateReturn, false),
            (HookFault::Busy, true),
            (HookFault::FsyncFailure, true),
        ];
        for (fault, not_handed) in faults {
            let outcome = HookDrain::drain(
                &request(&caller),
                manifest(),
                GuardDecision::Allow,
                |_| Ok(()),
                |_| Err(fault.clone()),
            )
            .unwrap();
            assert_eq!(
                matches!(outcome, DrainOutcome::NotHanded { .. }),
                not_handed
            );
            // Every post-commit fault stays uncertain-or-not-handed; none
            // is ever silently "not delivered".
            assert!(!matches!(outcome, DrainOutcome::Emitted { .. }));
        }
    }

    #[test]
    fn guards_and_deadline_hold_without_invocation() {
        let caller = root_caller();
        let held = HookDrain::drain(
            &request(&caller),
            manifest(),
            GuardDecision::Hold("explicit no-wake policy entry"),
            |_| unreachable!(),
            |_| unreachable!(),
        )
        .unwrap();
        assert!(matches!(held, DrainOutcome::NotHanded { .. }));
        let late = DrainRequest {
            deadline_ms: 1_000,
            ..request(&caller)
        };
        let outcome = HookDrain::drain(
            &late,
            manifest(),
            GuardDecision::Allow,
            |_| unreachable!(),
            |_| unreachable!(),
        )
        .unwrap();
        assert!(matches!(outcome, DrainOutcome::NotHanded { .. }));
    }
}
