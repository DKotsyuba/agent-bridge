//! Queue-only Codex message carrier and its confined helper.
//!
//! `message` for Codex is `thread/queue/add` against the same attested
//! native store, performed by an allowlisted helper process that may not
//! load, resume or start the target session. The confinement here is
//! threefold:
//!
//! 1. **Surface confinement** — the carrier trait exposes exactly one
//!    operation, `queue_add`. No load, resume, start, unarchive or
//!    relabel operation exists on this module's public surface, so no
//!    caller can ask for one and no implementation can provide one.
//! 2. **Launch confinement** — [`HelperSpec`] validates an allowlisted
//!    absolute executable and builds the exact argv and scrubbed
//!    environment the helper runs with: no shell, no inherited
//!    harness environment, no target-launching subcommands, payload
//!    passed only as a file path.
//! 3. **Evidence honesty** — helper-connection-local `notLoaded` is
//!    reported as exactly that (it says nothing about recipient
//!    idleness), queue acceptance is storage acceptance (not delivery),
//!    and `clientUserMessageId` correlates positively but never
//!    deduplicates.
//!
//! OS-level sandbox enforcement (no-network/no-child-process) is a
//! deployment property the qualification task re-attests on the loaded
//! host; the fixture helper asserts its own restrictions so the contract
//! is testable now.

use std::path::{Path, PathBuf};

/// Validated launch specification for the allowlisted queue helper.
///
/// The executable must be absolute and equal (after canonicalization by
/// the caller) to one allowlisted entry; the store path must be absolute.
/// The payload travels only as a file path, never as an argv string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperSpec {
    /// Allowlisted absolute path of the helper executable.
    pub executable: PathBuf,
    /// Absolute path of the attested native store to add to.
    pub store_path: PathBuf,
}

impl HelperSpec {
    /// The exact argv the helper is launched with.
    ///
    /// Always `["add", <store>, <thread>, <payload-file>]`: the queue-add
    /// verb comes first with no subcommand space, and no argument is ever
    /// interpreted by a shell. This is the complete argv — there is no
    /// variant that loads, resumes or starts anything.
    pub fn argv(&self, thread_id: &str, payload_path: &Path) -> Vec<String> {
        vec![
            "add".to_string(),
            self.store_path.to_string_lossy().into_owned(),
            thread_id.to_string(),
            payload_path.to_string_lossy().into_owned(),
        ]
    }

    /// Validates the spec against an allowlist.
    ///
    /// Returns [`crate::AdapterError::Invalid`] when the executable or
    /// store is not absolute, or the executable is not one of the
    /// allowlisted absolute paths. Nothing is executed here.
    pub fn validate_against(&self, allowlist: &[PathBuf]) -> Result<(), crate::AdapterError> {
        if !self.executable.is_absolute() || !self.store_path.is_absolute() {
            return Err(crate::AdapterError::Invalid(
                "helper executable and store must be absolute paths".into(),
            ));
        }
        if !allowlist.contains(&self.executable) {
            return Err(crate::AdapterError::Invalid(
                "helper executable is not allowlisted".into(),
            ));
        }
        Ok(())
    }

    /// The minimal environment the helper runs with.
    ///
    /// A fixed `PATH` plus the caller-supplied store-related variables;
    /// everything inherited from the calling process — in particular any
    /// `CODEX_*` values — is dropped, so the helper can never mistake
    /// foreign harness environment for instructions or identity.
    pub fn environment() -> Vec<(String, String)> {
        vec![("PATH".to_string(), "/usr/bin:/bin".to_string())]
    }
}

/// The one operation the Codex carrier surface offers.
///
/// Implemented by the real helper transport in the qualified build and by
/// owned fixture processes in tests. The trait deliberately has a single
/// method: queue-only is a property of the shape of this surface, not a
/// runtime check someone could forget.
pub trait CodexQueueCarrier {
    /// Adds one payload to the recipient thread's native queue.
    ///
    /// Never loads, resumes or starts the target session; never answers or
    /// creates a permission state; returns one of the distinct
    /// [`QueueOutcome`] observations.
    fn queue_add(&mut self, spec: &HelperSpec, thread_id: &str, payload: &str) -> QueueOutcome;
}

/// Distinct observations of one queue-add attempt.
///
/// None of these mean "delivered": native queue acceptance is storage
/// acceptance. `RemovedOrUnknown` in particular is *not* non-delivery — a
/// user may edit or delete, history may be incomplete and a race may be
/// unresolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueOutcome {
    /// The native queue accepted the entry; `client_user_message_id`
    /// correlates positively with a retained `userMessage.clientId`.
    NativeAccepted {
        /// Correlation id as assigned by the native queue.
        client_user_message_id: String,
    },
    /// The helper's connection is local-only and the target is not loaded
    /// **on this connection**; says nothing about recipient idleness.
    NotLoadedConnectionLocal,
    /// The native side reported busy; a distinct later successor is
    /// expected, not an error.
    Busy,
    /// The queue target is archived: publication rejects and the event
    /// holds; Bridge never unarchives, resumes or relabels it.
    ArchivedTarget,
    /// The entry is absent from both queue and retained history; removed
    /// or unknown — never proof of non-delivery.
    RemovedOrUnknown,
    /// A transport-level failure before any possible acceptance;
    /// positively unsent.
    NotSent {
        /// Why nothing could have been accepted.
        reason: &'static str,
    },
}

/// Result of correlating a `clientUserMessageId` against native evidence.
///
/// Reconnaissance established the tested bundled engine retains
/// `userMessage.clientId` matching the client id, **and** that a duplicate
/// id experiment created two entries and turns: the correlation is
/// positive evidence of identity, never a deduplication mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Correlation {
    /// The id matches a retained queue/history entry; correlation only.
    Present {
        /// False by construction: correlation never deduplicates.
        deduplicates: bool,
    },
    /// Absent from queue and retained history: removed or unknown.
    RemovedOrUnknown,
}

/// Correlates a queue-assigned client message id.
///
/// `in_queue`/`in_retained_history` are direct observations of the
/// attested native store. Present-when-absent-elsewhere is still only
/// correlation; absence everywhere is [`Correlation::RemovedOrUnknown`]
/// and never authorizes a resend by itself.
pub fn correlate(
    client_user_message_id: &str,
    in_queue: bool,
    in_retained_history: bool,
) -> Correlation {
    let _ = client_user_message_id;
    if in_queue || in_retained_history {
        Correlation::Present {
            deduplicates: false,
        }
    } else {
        Correlation::RemovedOrUnknown
    }
}

/// Maps a [`QueueOutcome`] onto the shared attempt-outcome vocabulary.
///
/// Queue acceptance and busy are possible acceptance (queue entries
/// persist while nothing consumes them — custody continues); archived is a
/// permanent refusal; helper-not-sent is positively unsent. The
/// connection-local `notLoaded` never becomes "inactive" on any path.
pub fn attempt_outcome(outcome: &QueueOutcome) -> crate::dispatch::AttemptOutcome {
    use crate::dispatch::AttemptOutcome;
    match outcome {
        QueueOutcome::NativeAccepted { .. } | QueueOutcome::Busy => {
            AttemptOutcome::PossiblyAccepted {
                reason: "native queue accepted or busy; storage acceptance, not delivery",
            }
        }
        QueueOutcome::NotLoadedConnectionLocal => AttemptOutcome::PossiblyAccepted {
            reason: "queue state unknown under a connection-local notLoaded",
        },
        QueueOutcome::ArchivedTarget => AttemptOutcome::Refused {
            reason: "archived queue target rejects publication",
        },
        QueueOutcome::RemovedOrUnknown => AttemptOutcome::PossiblyAccepted {
            reason: "absence from queue and history is not non-delivery",
        },
        QueueOutcome::NotSent { reason } => AttemptOutcome::PositivelyUnsent { reason },
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for the queue-only surface and its evidence honesty.

    use super::*;

    #[test]
    fn helper_argv_is_exactly_queue_add_with_scrubbed_env() {
        let spec = HelperSpec {
            executable: PathBuf::from("/opt/bridge/codex-queue-helper"),
            store_path: PathBuf::from("/users/x/.codex/store.db"),
        };
        assert_eq!(
            spec.argv("thread-1", Path::new("/tmp/payload.json")),
            vec![
                "add".to_string(),
                "/users/x/.codex/store.db".to_string(),
                "thread-1".to_string(),
                "/tmp/payload.json".to_string(),
            ]
        );
        // Environment drops everything inherited, CODEX_* included.
        let env = HelperSpec::environment();
        assert_eq!(env.len(), 1);
        assert!(env.iter().all(|(key, _)| !key.starts_with("CODEX_")));
    }

    #[test]
    fn helper_executable_must_be_allowlisted_and_absolute() {
        let spec = HelperSpec {
            executable: PathBuf::from("/opt/bridge/codex-queue-helper"),
            store_path: PathBuf::from("/store"),
        };
        let allowlist = [PathBuf::from("/opt/bridge/codex-queue-helper")];
        assert!(spec.validate_against(&allowlist).is_ok());
        assert!(spec.validate_against(&[]).is_err());
        let relative = HelperSpec {
            executable: PathBuf::from("codex-queue-helper"),
            store_path: PathBuf::from("/store"),
        };
        assert!(relative.validate_against(&allowlist).is_err());
    }

    #[test]
    fn correlation_is_positive_but_never_deduplication() {
        assert_eq!(
            correlate("cu-1", true, false),
            Correlation::Present {
                deduplicates: false
            }
        );
        assert_eq!(
            correlate("cu-1", false, true),
            Correlation::Present {
                deduplicates: false
            }
        );
        assert_eq!(
            correlate("cu-1", false, false),
            Correlation::RemovedOrUnknown
        );
    }

    #[test]
    fn outcomes_map_to_retained_or_refused_never_to_non_delivery() {
        assert!(matches!(
            attempt_outcome(&QueueOutcome::ArchivedTarget),
            crate::dispatch::AttemptOutcome::Refused { .. }
        ));
        assert!(matches!(
            attempt_outcome(&QueueOutcome::NotSent { reason: "refused" }),
            crate::dispatch::AttemptOutcome::PositivelyUnsent { .. }
        ));
        for outcome in [
            QueueOutcome::NativeAccepted {
                client_user_message_id: "cu-1".into(),
            },
            QueueOutcome::NotLoadedConnectionLocal,
            QueueOutcome::Busy,
            QueueOutcome::RemovedOrUnknown,
        ] {
            assert!(
                matches!(
                    attempt_outcome(&outcome),
                    crate::dispatch::AttemptOutcome::PossiblyAccepted { .. }
                ),
                "{outcome:?}"
            );
        }
    }
}
