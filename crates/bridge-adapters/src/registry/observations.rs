//! Exact content-free reads of existing protected bindings. No enumeration,
//! native proof, journal/custody write or message carrier participates.

use super::*;
use bridge_protocol::{
    Host, RecipientCapabilities, RecipientLifecycle, RecipientObservationState,
    ResolveRecipientParams,
};

/// Immutable private read snapshot; validate OS facts outside the registry lock,
/// then compare the entire binding and effective policy under the lock last.
pub(crate) struct ObservationCandidate {
    /// Exact binding including endpoint epoch, store and lifecycle.
    binding: Binding,
    /// Harness policy that bounds support and selects the native namespace.
    policy: HarnessPolicy,
    /// Required live process and private store owner.
    owner_uid: u32,
    /// Host-wide message disablement at snapshot time.
    message_disabled: bool,
}

impl ObservationCandidate {
    /// Checks expected facts when resolving, then live process/store/executable
    /// facts twice to refuse a process changed during filesystem/environment I/O.
    /// Expected inputs only filter the protected binding; failures reveal nothing.
    pub(crate) fn live(&self, expected: Option<&ResolveRecipientParams>) -> bool {
        if expected.is_some_and(|p| {
            self.binding.store.to_str() != Some(p.expected_store.as_str())
                || self.binding.harness
                    != (p.expected_harness_pid, p.expected_harness_start_time_secs)
        }) {
            return false;
        }
        let Ok(facts) = live_binding(&self.binding, &self.policy, self.owner_uid) else {
            return false;
        };
        product_marked(&facts, &self.policy)
            && live_binding(&self.binding, &self.policy, self.owner_uid)
                .is_ok_and(|last| last == facts)
    }

    /// Returns only owner lifecycle and currently bounded carrier support.
    /// Callers must first validate live facts and the final registry fence.
    pub(crate) fn observation(&self) -> RecipientObservationState {
        RecipientObservationState::Observed {
            lifecycle: match self.binding.lifecycle {
                Lifecycle::Active => RecipientLifecycle::Active,
                Lifecycle::Inactive => RecipientLifecycle::Inactive,
                Lifecycle::AwaitingInput => RecipientLifecycle::AwaitingInput,
                Lifecycle::Unknown => RecipientLifecycle::Unknown,
            },
            capabilities: RecipientCapabilities {
                inject: self.binding.capabilities.inject && self.policy.inject,
                message: self.binding.capabilities.message
                    && self.policy.message
                    && !self.message_disabled,
            },
        }
    }
}

impl Registry {
    /// Derives exactly one logical address solely from configured host/harness
    /// namespace and the bounded requested session. Reads no bindings/processes.
    /// Unsupported harness policy or malformed identity returns absence.
    pub(crate) fn observation_address(&self, host: Host, session: &str) -> Option<NativeAddress> {
        let harness = match host {
            Host::Codex => Harness::CODEX,
            Host::ClaudeCode => Harness::CLAUDE_CODE,
            Host::OpenCode => Harness::OPENCODE,
        };
        let policy = self.policy(harness)?;
        NativeAddress::new(&self.config.host_id, harness, &policy.namespace, session).ok()
    }

    /// Snapshots exactly one nonretired, proven binding after grant checks.
    /// No process query, fallback, enumeration or registry mutation occurs.
    pub(crate) fn observation_candidate(
        &self,
        address: &NativeAddress,
    ) -> Option<ObservationCandidate> {
        let binding = self.bindings.get(&address.to_canonical_string())?;
        if binding.retired || binding.pending {
            return None;
        }
        Some(ObservationCandidate {
            binding: binding.clone(),
            policy: self.policy(address.harness)?.clone(),
            owner_uid: self.owner_uid,
            message_disabled: self.message_disabled.contains(&address.harness),
        })
    }

    /// Final pure read fence rejects any intervening binding/policy/disablement
    /// change, including same-epoch lifecycle changes and retirement.
    pub(crate) fn observation_current(&self, snapshot: &ObservationCandidate) -> bool {
        self.bindings
            .get(&snapshot.binding.address.to_canonical_string())
            == Some(&snapshot.binding)
            && self.policy(snapshot.binding.address.harness) == Some(&snapshot.policy)
            && self
                .message_disabled
                .contains(&snapshot.binding.address.harness)
                == snapshot.message_disabled
    }
}
