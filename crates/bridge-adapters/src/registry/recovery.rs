//! Recover MESSAGE eligibility from a verified native endpoint after process exit.
//! The persisted replacement is retired for caller and inject authority until its own hook.

use super::*;
use crate::server::lock_registry;
use std::time::{Duration, Instant};

/// Retry native discovery at most twice a minute per unchanged held endpoint.
const RETRY: Duration = Duration::from_secs(30);
/// Minimum interval between metadata probes of a still-live verified replacement.
const RECHECK: Duration = Duration::from_secs(10);
/// Static diagnostics allowed across the account-worker boundary.
pub(crate) const NO_SOCKET: &str = "ended binding has no replacement socket";
/// A socket or descriptor exists without sufficient peer/session evidence.
pub(crate) const UNVERIFIED: &str = "replacement session identity unverified";
/// The kernel could not prove the old incarnation ended.
pub(crate) const UNKNOWN: &str = "recipient harness identity unavailable";

/// Rechecks a target of the existing fair pending-work sweep. Only a dead binding
/// starts discovery. A genuine hook supersedes even an in-progress probe by epoch.
pub(crate) fn recover(registry: &Mutex<Registry>, address: &NativeAddress) -> Result<(), String> {
    let key = address.to_canonical_string();
    let candidate = {
        let registry = lock_registry(registry);
        if !registry.native_discovery_enabled() {
            return Ok(());
        }
        let Some(binding) = registry.bindings.get(&key) else {
            return Ok(());
        };
        if binding.pending
            || !binding.qualified.message
            || registry.message_is_disabled(address.harness)
        {
            return Ok(());
        }
        if let Some((epoch, until, Err(reason))) = registry.recovery_probes.get(&key)
            && *epoch == binding.epoch
            && Instant::now() < *until
        {
            return Err(reason.clone());
        }
        MessageCandidate {
            binding: binding.clone(),
            owner_uid: registry.owner_uid,
            policy: registry.policy(address.harness).ok_or(UNVERIFIED)?.clone(),
        }
    };
    if !candidate.policy.message {
        return Ok(());
    }
    let state = candidate.binding.incarnation_state();
    match state {
        os::IncarnationState::Live if candidate.binding.discovered.is_none() => return Ok(()),
        os::IncarnationState::Live => (),
        os::IncarnationState::Unknown => return Err(UNKNOWN.into()),
        os::IncarnationState::Ended => (),
    }
    // Desktop gateways retain their original one-shot proof and route selection.
    if candidate.needs_gateway() {
        return Ok(());
    }
    let epoch = candidate.binding.epoch;
    {
        let mut registry = lock_registry(registry);
        registry.message_current(&candidate)?;
        if let Some((old, until, verdict)) = registry.recovery_probes.get(&key)
            && *old == epoch
            && Instant::now() < *until
            && (verdict.is_err() || state == os::IncarnationState::Live)
        {
            return verdict.clone();
        }

        registry.recovery_probes.insert(
            key.clone(),
            (
                epoch,
                Instant::now() + RETRY,
                Err("recipient harness incarnation ended".into()),
            ),
        );
    }
    let replacement = discover(&candidate, state);
    let mut registry = lock_registry(registry);
    registry.message_current(&candidate)?;
    let mut replacement = match replacement {
        Ok(binding) => binding,
        Err(reason) => {
            registry
                .recovery_probes
                .insert(key, (epoch, Instant::now() + RETRY, Err(reason.clone())));
            return Err(reason);
        }
    };
    if replacement.incarnation_state() != os::IncarnationState::Live {
        return Err(UNVERIFIED.into());
    }
    if state == os::IncarnationState::Live {
        if replacement.discovered != candidate.binding.discovered {
            return Err(UNVERIFIED.into());
        }
        if replacement == candidate.binding {
            registry
                .recovery_probes
                .insert(key, (epoch, Instant::now() + RECHECK, Ok(())));
            return Ok(());
        }
    } else {
        replacement.epoch = next_epoch(
            registry.epoch_floor,
            Some(epoch),
            bridge_core::service::current_unix_millis(),
        )?;
    }
    let epoch = replacement.epoch;
    registry.bindings.insert(key.clone(), replacement);
    if let Err(error) = registry.persist_routes() {
        registry.bindings.insert(key, candidate.binding);
        return Err(error);
    }
    registry
        .recovery_probes
        .insert(key, (epoch, Instant::now() + RECHECK, Ok(())));
    Ok(())
}

/// Checks the kernel socket peer, marked loaded executable and process-selected
/// store before asking the native endpoint about the session. No payload is sent.
fn discover(candidate: &MessageCandidate, state: os::IncarnationState) -> Result<Binding, String> {
    let old = &candidate.binding;
    let uid = candidate.owner_uid;
    private_store(&old.store, uid).map_err(|_| UNVERIFIED)?;
    let thread = &old.address.native_session_id;
    let (stream, facts, hint) = if old.address.harness == Harness::CODEX {
        let (_, stream, facts) =
            crate::codex_live::connect_control(&old.store, uid, true)?.ok_or(NO_SOCKET)?;
        (stream, facts, None)
    } else {
        let (socket, hint) = crate::claude::replacement_inbox(&old.store, thread, uid)?;
        crate::owner::check_socket(&socket, uid).map_err(|_| UNVERIFIED)?;
        let (stream, facts) =
            os::connect_verified(&socket, Instant::now() + Duration::from_secs(1), true)?;
        (stream, facts, Some(hint))
    };
    replacement_process(&facts, old.harness.0, state, uid)?;
    drop(stream);
    let identity = facts.kernel_incarnation.as_ref().ok_or(UNVERIFIED)?;
    if !product_marked(&facts, &candidate.policy) {
        return Err(UNVERIFIED.into());
    }
    let mut binding = old.clone();
    binding.harness = (facts.pid, facts.start_time);
    binding.birth = None;
    binding.discovered = Some(DiscoveredPeer {
        incarnation: identity.clone(),
        requires_managed_ancestry: old.requires_managed_ancestry(),
    });
    binding.managed_incarnation = None;
    binding.executable = facts.exe.clone().ok_or(UNVERIFIED)?;
    live_binding(&binding, &candidate.policy, uid).map_err(|_| UNVERIFIED)?;
    if crate::owner::checked_locator(binding.harness, Some(identity))?.is_some()
        || (old.address.harness == Harness::CODEX
            && os::process_env_checked(facts.pid, "CODEX_APP_TOOLS_PIPE_PATH")
                .map_err(|_| UNVERIFIED)?
                .is_some())
    {
        return Err("replacement requires a verified native hook".into());
    }
    binding.retired = true;
    binding.desktop_idle_message = false;
    binding.desktop_idle_transcript = None;
    binding.wake = None;
    binding.transcript = None;
    binding.capabilities = Capabilities {
        inject: false,
        message: true,
    };
    if let Some(hint) = hint {
        if hint.pid != facts.pid || !descriptor_written_after_start(&facts, hint.written_at) {
            return Err(UNVERIFIED.into());
        }
        binding.lifecycle = hint.lifecycle;
    } else {
        let physical = MessageCandidate {
            binding: binding.clone(),
            ..candidate.clone()
        };
        let (_, route) = physical.validate()?;
        let endpoint = crate::codex_live::locate(&route, true)?.ok_or(NO_SOCKET)?;
        binding.lifecycle = match endpoint.state(thread, Duration::from_secs(1))? {
            crate::codex_live::State::Idle => Lifecycle::Inactive,
            crate::codex_live::State::Active => Lifecycle::Active,
            crate::codex_live::State::NotLoaded => return Err(UNVERIFIED.into()),
        };
    }
    Ok(binding)
}

/// Requires the connection-proven peer to belong to the account and rejects a
/// purported replacement at the PID that was just classified as ended.
fn replacement_process(
    facts: &ProcessFacts,
    old_pid: u32,
    state: os::IncarnationState,
    uid: u32,
) -> Result<(), String> {
    if facts.uid != Some(uid) || (state == os::IncarnationState::Ended && facts.pid == old_pid) {
        return Err(UNVERIFIED.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A real connected peer may reverify itself while live but a purported
    /// ended binding cannot be rediscovered through the same PID.
    #[test]
    fn connected_replacement_must_have_a_distinct_pid_after_exit() {
        let pid = std::process::id();
        let facts = os::process_facts_managed(pid).unwrap();
        let uid = facts.uid.unwrap();
        assert!(replacement_process(&facts, pid, os::IncarnationState::Live, uid).is_ok());
        assert!(replacement_process(&facts, pid, os::IncarnationState::Ended, uid).is_err());
    }
}
