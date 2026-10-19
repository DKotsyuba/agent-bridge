//! OpenCode MESSAGE delivery through its already-live native owner only.
//! Native HTTP and inference remain owned by the launcher. No guessed port,
//! independent scheduler, database write or alternate route is introduced.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bridge_core::dispatch::{AttemptRecord, Attestation, DispatchCarrier, Lifecycle, Outcome};
use bridge_core::{Harness, NativeAddress};

use crate::registry::{RecipientBinding, Registry};
use crate::server::lock_registry;

/// Routes a registered OpenCode session to the current exact direct-parent
/// owner. Absence or failure holds; no fallback can create another native turn.
pub struct OpenCodeOwnerCarrier {
    /// Shared protected lifecycle/epoch registry; never locked across owner I/O.
    registry: Arc<Mutex<Registry>>,
}

impl OpenCodeOwnerCarrier {
    /// Shares the daemon's existing registry without starting a process or task.
    pub fn new(registry: Arc<Mutex<Registry>>) -> Self {
        Self { registry }
    }

    /// Revalidates current process/store/executable facts outside the registry
    /// lock, verifies the live direct-parent owner and closes selection with a
    /// locked snapshot equality check. Every failure precedes native input.
    fn route(
        &self,
        recipient: &NativeAddress,
    ) -> Result<(Attestation, RecipientBinding, PathBuf), String> {
        if recipient.harness != Harness::OpenCode {
            return Err("not an OpenCode recipient".into());
        }
        crate::registry::refresh_stale(&self.registry);
        let candidate = lock_registry(&self.registry).message_candidate(recipient)?;
        let (attestation, binding) = candidate.validate()?;
        let socket = crate::owner::locate(&self.registry, binding.harness)?
            .ok_or("OpenCode has no supported native owner")?;
        lock_registry(&self.registry).message_current(&candidate)?;
        Ok((attestation, binding, socket))
    }
}

impl DispatchCarrier for OpenCodeOwnerCarrier {
    /// Attests only a genuine registered OpenCode actor and a positively proven
    /// owner route while positively idle. Busy/unknown/permission states hold
    /// before reserving an attempt; an epoch race at send is a zero-effect deferral.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        let (attestation, _, _) = self.route(recipient)?;
        if attestation.lifecycle() != Lifecycle::Inactive {
            return Err("native owner recipient is not positively idle".into());
        }
        Ok(attestation)
    }

    /// Hands the frozen manifest once to the same epoch while positively idle.
    /// Only a correlated opencode_input receipt proves durable native admission;
    /// post-write uncertainty is retained and never retried or rerouted here.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        let address = match NativeAddress::parse(&attempt.fence.recipient) {
            Ok(address) => address,
            Err(_) => {
                return Outcome::KnownUnsent {
                    evidence: "invalid OpenCode recipient".into(),
                };
            }
        };
        let (attestation, binding, socket) = match self.route(&address) {
            Ok(route) => route,
            Err(reason) => {
                return Outcome::KnownUnsent {
                    evidence: format!("OpenCode owner route not proven: {reason}"),
                };
            }
        };
        if binding.epoch != attempt.fence.endpoint_epoch
            || attestation.lifecycle() != Lifecycle::Inactive
        {
            return Outcome::DeferredKnownUnsent {
                evidence: "OpenCode epoch or idle lifecycle changed before handoff".into(),
            };
        }
        crate::owner::deliver(
            &self.registry,
            &socket,
            binding.harness,
            Harness::OpenCode,
            &crate::owner::Handoff {
                thread_id: &address.native_session_id,
                call_id: &format!(
                    "agent-bridge-{}-{}",
                    attempt.fence.attempt_seq,
                    crate::registry::prefix_within(&attempt.fence.manifest_hash, 16)
                ),
                text: &attempt.manifest,
                deadline_ms: attempt.deadline_ms,
            },
        )
    }
}
