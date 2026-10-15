//! MESSAGE-only physical gateway recovery for an idle Codex Desktop address whose
//! harness incarnation ended (an application update or restart) before any hook
//! of the new incarnation arrived.
//!
//! The normal route needs the recorded harness incarnation alive, which an idle
//! thread cannot restore: nothing fires a hook until it next runs. This route
//! instead reaches the *same native thread* through the application's own
//! thread-addressed message tool, exposed by the signed frontend of the current
//! Desktop harness of the same store. It is a physical gateway, not a rebinding:
//! it grants no caller authority, no call evidence and no inject, never renews
//! the binding's harness, and ends at the thread's own next hook, which renews
//! the binding the ordinary way. An unspent proof survives a daemon restart (the
//! journal restore keeps a Codex binding whose incarnation is gone only while it
//! carries one); a spent one never does.
//!
//! Evidence, all protected (kernel process facts, the owner-only store and the
//! binding journal; never labels, working directories or self assertions):
//!
//! - **Positive idle.** A [`WakeProof`] is stamped only when a hook of the address
//!   owner itself leaves the lifecycle positively `Inactive` on a Desktop harness
//!   and is cleared by every other lifecycle and a renewal. A `SessionEnd` that
//!   keeps the existing narrow retired-Desktop idle exception keeps the proof
//!   stamped before it; any other `SessionEnd` clears it, and a retired binding
//!   without that exception is never eligible.
//! - **Exact stable thread.** The stamp binds the transcript's device and inode,
//!   its length, its nanosecond modification and status-change times (a write
//!   anywhere in the file moves them, and a program cannot set the status-change
//!   time back), a SHA-256 of its last [`TAIL_BYTES`] and the thread id read from
//!   the transcript's own `session_meta` header, all read from one opened
//!   descriptor whose metadata is identical before and after the read and whose
//!   path still resolves to the same owned regular file. The gateway is attested
//!   only if the same stamp is read again after the old incarnation is gone; any
//!   growth, rewrite, replacement, touch or unreadable header holds. No time window
//!   substitutes for this proof. A host that appends after its `Stop` hook merely
//!   invalidates the stamp (a hold), never makes a thread look idle.
//! - **Unique live gateway.** Exactly one distinct live harness incarnation that
//!   started after the recorded one, running the recorded executable unchanged
//!   since it started, with the same store and the application's native pipe, owning a probe-verified
//!   frontend. Zero or several hold.
//!
//! The committed gateway is a fresh, strictly larger endpoint epoch persisted in
//! the route journal before core fences it; a failed commit leaves the previous
//! binding. Eligibility is one-shot and spent *before* the first native write:
//! [`Registry::spend_wake`] records the spend in the journal first (a failed record
//! is a known-unsent hold), so neither a crash nor a restart can revive it, and
//! only a refusal that proves nothing was written gives it back
//! ([`Registry::restore_wake`]).

use std::io::{Seek, SeekFrom};

use super::*;

/// Largest transcript header line read for `session_meta`, in bytes (a native
/// header carries the session's instructions and can exceed 64 KiB).
const HEAD_BYTES: u64 = 1_048_576;

/// Number of trailing transcript bytes fingerprinted.
const TAIL_BYTES: u64 = 65_536;

/// Private evidence that an address was positively idle, bound to the exact
/// stable transcript, plus the physical gateway committed for it (if any).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WakeProof {
    /// Device and inode of the owned regular transcript at the positive idle.
    transcript: (u64, u64),
    /// Transcript length in bytes at the positive idle.
    len: u64,
    /// Transcript modification time (seconds, nanoseconds) at the positive idle.
    mtime: (i64, i64),
    /// Transcript status-change time (seconds, nanoseconds) at the positive idle.
    ctime: (i64, i64),
    /// Lowercase hex SHA-256 of the last [`TAIL_BYTES`] of the transcript.
    tail: String,
    /// Harness incarnation `(pid, start_time)` committed as the physical gateway
    /// with the current endpoint epoch; absent until a gateway was committed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<(u32, u64)>,
}

/// Reads the exact stable identity of the binding's retained transcript: the
/// canonical owned regular file inside the store's sessions directory
/// ([`retained_transcript`]), opened without trusting the path afterwards, whose
/// first line is a `session_meta` record naming exactly the address's thread id,
/// with its length, nanosecond times and tail fingerprint read from one
/// descriptor whose full metadata is the same before and after the read, and
/// whose path still passes [`retained_transcript`] with the same device and inode
/// afterwards (owner, link count and canonical location are re-proven). `None`
/// for anything missing, replaced, unreadable, unnamed or changing while read;
/// absence is never positive evidence.
pub(super) fn read_stamp(binding: &Binding, owner_uid: u32) -> Option<WakeProof> {
    let identity = retained_transcript(binding, owner_uid)?;
    let mut file = std::fs::File::open(binding.transcript.as_ref()?).ok()?;
    let before = file.metadata().ok()?;
    if (before.dev(), before.ino()) != identity {
        return None;
    }
    let mut head = Vec::new();
    (&mut file).take(HEAD_BYTES).read_to_end(&mut head).ok()?;
    let line = &head[..head.iter().position(|byte| *byte == b'\n')?];
    let meta: serde_json::Value = serde_json::from_slice(line).ok()?;
    if meta.get("type")?.as_str()? != "session_meta"
        || meta.get("payload")?.get("id")?.as_str()? != binding.address.native_session_id
    {
        return None;
    }
    let len = before.len();
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL_BYTES)))
        .ok()?;
    let tail = sha256_reader(&mut (&mut file).take(TAIL_BYTES)).ok()?;
    let after = file.metadata().ok()?;
    let times = |meta: &std::fs::Metadata| {
        (
            (meta.dev(), meta.ino(), meta.len()),
            (meta.mtime(), meta.mtime_nsec()),
            (meta.ctime(), meta.ctime_nsec()),
        )
    };
    (times(&before) == times(&after) && retained_transcript(binding, owner_uid) == Some(identity))
        .then_some(WakeProof {
            transcript: identity,
            len,
            mtime: (before.mtime(), before.mtime_nsec()),
            ctime: (before.ctime(), before.ctime_nsec()),
            tail,
            gateway: None,
        })
}

impl WakeProof {
    /// Forgets the committed physical gateway (it was bound to a process of an
    /// earlier daemon life), so the next use re-qualifies and re-commits one with
    /// a fresh epoch.
    pub(super) fn forget_gateway(&mut self) {
        self.gateway = None;
    }
}

impl MessageCandidate {
    /// Whether this binding can only be reached through a physical gateway: a
    /// Codex binding whose recorded incarnation is gone and which carries a
    /// positive-idle proof. A live binding qualifies the ordinary way; a retired
    /// one only through the existing narrow retired-Desktop idle exception (its
    /// pre-end positive idle with the same retained transcript inode), never as a
    /// blanket; anything else uses no route.
    pub(crate) fn needs_gateway(&self) -> bool {
        let binding = &self.binding;
        binding.address.harness == Harness::Codex
            && binding.wake.as_ref().is_some_and(|wake| {
                !binding.retired
                    || (binding.desktop_idle_message
                        && binding.desktop_idle_transcript == Some(wake.transcript))
            })
            && !os::incarnation_alive(binding.harness.0, binding.harness.1)
    }

    /// Whether this is a live Codex Desktop binding that may be woken by its
    /// unspent idle proof instead of a lifecycle: not retired, lifecycle `Unknown`
    /// and carrying the proof, with its recorded incarnation alive.
    pub(crate) fn needs_idle_proof(&self) -> bool {
        let binding = &self.binding;
        binding.address.harness == Harness::Codex
            && !binding.retired
            && binding.lifecycle == Lifecycle::Unknown
            && binding.wake.is_some()
            && os::incarnation_alive(binding.harness.0, binding.harness.1)
    }

    /// The physical gateway incarnation already committed for this snapshot's
    /// endpoint epoch, if any.
    pub(crate) fn committed_gateway(&self) -> Option<(u32, u64)> {
        self.binding.wake.as_ref()?.gateway
    }

    /// Whether `gateway` is a live Desktop harness for this binding: the same
    /// user, started from the binding's exact recorded executable (a trusted,
    /// non-writable file unchanged since before it started, as for any harness),
    /// the same canonical owner-only store, with the application's native pipe in
    /// its own environment, and started strictly after the recorded incarnation.
    /// Pure OS facts; I/O only
    /// reads process facts and file identity.
    pub(crate) fn qualifies_gateway(&self, gateway: (u32, u64)) -> bool {
        let binding = &self.binding;
        let Some(facts) = os::process_facts(gateway.0) else {
            return false;
        };
        facts.uid == Some(self.owner_uid)
            && facts.start_time == gateway.1
            && facts.start_time > binding.harness.1
            && facts.exe.as_ref() == Some(&binding.executable)
            && harness_store(&facts, Harness::Codex).is_some_and(|store| store == binding.store)
            && private_store(&binding.store, self.owner_uid).is_ok()
            && executable_current(&binding.executable, &facts, self.owner_uid).is_ok()
            && os::process_env(facts.pid, "CODEX_APP_TOOLS_PIPE_PATH").is_some()
    }

    /// Proves the thread is still exactly as stamped at its positive idle: the
    /// retained transcript reads back with the same identity, length, tail
    /// fingerprint and `session_meta` thread id. Any change, or anything
    /// unreadable, is "not proven idle". Reads a bounded head and tail of one
    /// file; never holds the registry lock.
    ///
    /// # Errors
    ///
    /// No proof is held, or the transcript is unreadable, names another thread or
    /// differs from the stamp.
    pub(crate) fn proves_idle(&self) -> Result<(), String> {
        let wake = self
            .binding
            .wake
            .as_ref()
            .ok_or("no positive idle proof for the gateway route")?;
        let current = read_stamp(&self.binding, self.owner_uid)
            .ok_or("the retained transcript is unreadable or no longer the exact thread")?;
        if (
            current.transcript,
            current.len,
            current.mtime,
            current.ctime,
            &current.tail,
        ) != (
            wake.transcript,
            wake.len,
            wake.mtime,
            wake.ctime,
            &wake.tail,
        ) {
            return Err("the thread transcript changed since its positive idle (not idle)".into());
        }
        Ok(())
    }

    /// The fresh logical and physical fence run *after* the one-shot proof was
    /// spent (`proof` is the spent value, the snapshot was taken after the spend)
    /// and again at the last pre-write boundary. Everything the attest proved must
    /// still hold, with the proof now absent: the binding is exactly at `epoch`
    /// (any hook that renewed it replaced the binding and changed the epoch), the
    /// recorded incarnation is still dead, a retired binding still has its narrow
    /// idle exception for the same transcript, `gateway` still qualifies (live,
    /// same executable, store and native pipe, later born), and the transcript
    /// still reads back as exactly the spent stamp. I/O is file and process facts
    /// only, never under the registry lock; the caller finishes with
    /// [`Registry::message_current`] on this snapshot.
    ///
    /// # Errors
    ///
    /// Any fact changed or became unprovable.
    pub(crate) fn revalidate_spent(
        &self,
        epoch: u64,
        proof: &WakeProof,
        gateway: (u32, u64),
    ) -> Result<(), String> {
        let binding = &self.binding;
        let live = os::incarnation_alive(binding.harness.0, binding.harness.1);
        // A live proof route (its own harness, lifecycle still `Unknown`) or a
        // dead-incarnation gateway: each keeps exactly its own preconditions, and a
        // hook that moved the lifecycle (or renewed the binding) refuses either.
        let route_holds = if live {
            gateway == binding.harness
                && !binding.retired
                && binding.lifecycle == Lifecycle::Unknown
                && self.live_check().is_ok()
        } else {
            !(binding.retired
                && !(binding.desktop_idle_message
                    && binding.desktop_idle_transcript == Some(proof.transcript)))
                && self.qualifies_gateway(gateway)
        };
        if binding.address.harness != Harness::Codex
            || binding.epoch != epoch
            || binding.wake.is_some()
            || !route_holds
        {
            return Err("the gateway route changed after its proof was reserved".into());
        }
        let current = read_stamp(binding, self.owner_uid)
            .ok_or("the retained transcript is unreadable or no longer the exact thread")?;
        if (
            current.transcript,
            current.len,
            current.mtime,
            current.ctime,
            &current.tail,
        ) != (
            proof.transcript,
            proof.len,
            proof.mtime,
            proof.ctime,
            &proof.tail,
        ) {
            return Err("the thread transcript changed after its proof was reserved".into());
        }
        Ok(())
    }

    /// Validates the committed gateway route and returns its MESSAGE-only
    /// attestation (`Inactive`, no inject) and snapshot. Requires the gateway
    /// to qualify now and the transcript to read back byte-for-byte as stamped at
    /// the positive idle (same identity, length, tail and session id). Every
    /// other state, including a changed, unreadable or unproven transcript,
    /// holds. The snapshot names the gateway as its harness and requires the
    /// application route, never a helper.
    pub(crate) fn validate_gateway(&self) -> Result<(Attestation, RecipientBinding), String> {
        let binding = &self.binding;
        let wake = binding
            .wake
            .as_ref()
            .filter(|_| self.needs_gateway())
            .ok_or("no positive idle proof for the gateway route")?;
        let gateway = wake
            .gateway
            .ok_or("no physical gateway committed for this route")?;
        if !self.qualifies_gateway(gateway) {
            return Err("the committed Desktop gateway is gone or no longer qualified".into());
        }
        self.proves_idle()?;
        let attestation = Attestation::verified(
            binding.address.clone(),
            binding.address.native_session_id.clone(),
            binding.epoch,
            Lifecycle::Inactive,
            Capabilities {
                inject: false,
                message: binding.capabilities.message && self.policy.message,
            },
            proof(format!(
                "codex-gateway:{}@{}:epoch{}",
                gateway.0, gateway.1, binding.epoch
            )),
        )
        .map_err(|error| error.to_string())?;
        Ok((
            attestation,
            RecipientBinding {
                harness: gateway,
                epoch: binding.epoch,
                store: binding.store.clone(),
                executable: binding.executable.clone(),
                transcript: binding.transcript.clone(),
                desktop_message_only: true,
                gateway: true,
            },
        ))
    }
}

impl Registry {
    /// Commits `gateway` as the physical gateway of the snapshot's address with a
    /// fresh, strictly larger endpoint epoch, persisted in the route journal
    /// before returning. Core fences that epoch when the attestation built from
    /// the returned state is reserved, so no send can precede it.
    ///
    /// The commit only succeeds on exactly the snapshot (nothing renewed,
    /// retired, consumed or restamped since) while the recorded incarnation is
    /// still gone and the gateway still qualifies; a persistence failure restores
    /// the previous binding, so a failed write never leaves a usable route.
    ///
    /// # Errors
    ///
    /// The binding changed or vanished, the old incarnation is alive again, the
    /// gateway does not qualify, the carrier is disabled or the journal write
    /// failed.
    pub(crate) fn commit_gateway(
        &mut self,
        snapshot: &MessageCandidate,
        gateway: (u32, u64),
        now_ms: u64,
    ) -> Result<(), String> {
        let key = snapshot.binding.address.to_canonical_string();
        if self
            .message_disabled
            .contains(&snapshot.binding.address.harness)
            || !snapshot.needs_gateway()
            || !snapshot.qualifies_gateway(gateway)
        {
            return Err("the gateway route is not available".into());
        }
        let binding = self
            .bindings
            .get_mut(&key)
            .filter(|binding| **binding == snapshot.binding)
            .ok_or("the binding changed before the gateway was committed")?;
        let previous = binding.clone();
        binding.epoch = now_ms.max(binding.epoch.saturating_add(1));
        if let Some(wake) = binding.wake.as_mut() {
            wake.gateway = Some(gateway);
        }
        if let Err(error) = self.persist_routes() {
            self.bindings.insert(key, previous);
            return Err(error);
        }
        Ok(())
    }

    /// Spends the one-shot wake proof of `address` *before* the first native
    /// write, for the binding at exactly `epoch`, and returns it together with the
    /// exact binding as it stands after the spend. The spend is journaled before
    /// this returns; if the journal cannot record it the proof is put back and the
    /// error is returned, so the caller sends nothing (a known-unsent hold). A
    /// daemon crash or restart after this point can therefore never revive the
    /// proof, whatever the outcome of the write.
    ///
    /// # Errors
    ///
    /// No binding at that epoch, no proof to spend, or the journal write failed.
    pub(crate) fn spend_wake(
        &mut self,
        address: &NativeAddress,
        epoch: u64,
    ) -> Result<SpentWake, String> {
        let key = address.to_canonical_string();
        let binding = self
            .bindings
            .get_mut(&key)
            .filter(|binding| binding.epoch == epoch)
            .ok_or("the gateway binding changed before the hand-off")?;
        let proof = binding
            .wake
            .take()
            .ok_or("the gateway proof was already spent")?;
        let after = binding.clone();
        if let Err(error) = self.persist_routes() {
            if let Some(binding) = self.bindings.get_mut(&key) {
                binding.wake = Some(proof);
            }
            return Err(error);
        }
        Ok(SpentWake {
            proof,
            binding: after,
        })
    }

    /// Gives back a proof spent by [`Registry::spend_wake`] after the hand-off was
    /// refused *before any native write* (known-unsent). Best effort and strictly
    /// conservative: the binding must still be *exactly* the one that stood right
    /// after the spend (same epoch, harness, lifecycle, capabilities and every
    /// other field, proof absent), so a non-renewing hook that moved the lifecycle
    /// meanwhile, a renewal or any other change keeps the proof spent; and if the
    /// journal cannot record the restore it stays spent (the address then holds
    /// until its own next hook), never the other way round. An accepted or
    /// possibly delivered hand-off never restores.
    pub(crate) fn restore_wake(&mut self, address: &NativeAddress, spent: SpentWake) {
        let key = address.to_canonical_string();
        let Some(binding) = self.bindings.get_mut(&key) else {
            return;
        };
        if *binding != spent.binding {
            return;
        }
        binding.wake = Some(spent.proof);
        if self.persist_routes().is_err()
            && let Some(binding) = self.bindings.get_mut(&key)
        {
            binding.wake = None;
        }
    }
}

/// A spent one-shot wake proof together with the exact binding at the moment of
/// the spend; the only thing [`Registry::restore_wake`] accepts, so a restore can
/// never revive a proof over a binding that changed in any way.
#[derive(Debug, Clone)]
pub(crate) struct SpentWake {
    /// The spent proof.
    proof: WakeProof,
    /// The binding right after the spend (proof absent).
    binding: Binding,
}

impl SpentWake {
    /// The spent proof, for the final fence.
    pub(crate) fn proof(&self) -> &WakeProof {
        &self.proof
    }
}

#[cfg(test)]
mod tests {
    //! The transcript stamp that makes "idle" provable after a restart.

    use super::*;
    use serde_json::json;

    /// A Codex binding over a canonical scratch store with `transcript` retained.
    fn binding_for(store: &Path, thread: &str, transcript: &Path) -> Binding {
        Binding {
            address: NativeAddress::new("h", Harness::Codex, "ns", thread).unwrap(),
            harness: (1, 2),
            epoch: 3,
            capabilities: Capabilities {
                inject: true,
                message: true,
            },
            qualified: Capabilities {
                inject: true,
                message: true,
            },
            version: "qualified".into(),
            lifecycle: Lifecycle::Inactive,
            transcript: Some(transcript.to_path_buf()),
            store: store.to_path_buf(),
            executable: "/tmp/executable".into(),
            retired: false,
            desktop_idle_message: false,
            desktop_idle_transcript: None,
            wake: None,
            pending: false,
        }
    }

    /// A fresh canonical store with a `sessions` directory.
    fn store(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("m2{tag}{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sessions")).unwrap();
        dir.canonicalize().unwrap()
    }

    /// The uid that owns the files this test creates.
    fn uid() -> u32 {
        os::process_facts(std::process::id()).unwrap().uid.unwrap()
    }

    /// The stamp names the exact thread, file identity, length and tail: it is
    /// stable for unchanged bytes and differs for growth, a same-length rewrite
    /// of the tail and a replaced file; it is refused for another thread id, an
    /// unterminated or non-`session_meta` header, a symlink and a path outside
    /// the store's sessions directory.
    #[test]
    fn stamp_is_exact_and_refuses_anything_unproven() {
        let store = store("stp");
        let path = store.join("sessions").join("t.jsonl");
        let write = |header: &str, body: &str| {
            std::fs::write(&path, format!("{header}{body}")).unwrap();
        };
        let header = format!("{}\n", json!({"type":"session_meta","payload":{"id":"t1"}}));
        write(&header, "{\"n\":1}\n{\"n\":2}\n");
        let binding = binding_for(&store, "t1", &path);
        let stamp = read_stamp(&binding, uid()).expect("exact thread header");
        assert_eq!(read_stamp(&binding, uid()), Some(stamp.clone()));

        write(&header, "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n");
        let grown = read_stamp(&binding, uid()).unwrap();
        assert!(grown.len > stamp.len && grown.tail != stamp.tail);
        write(&header, "{\"n\":1}\n{\"n\":9}\n");
        let rewritten = read_stamp(&binding, uid()).unwrap();
        assert_eq!(rewritten.len, stamp.len);
        assert_ne!(rewritten.tail, stamp.tail, "same length, other tail bytes");
        write(&header, "{\"n\":1}\n{\"n\":2}\n");
        let touched = read_stamp(&binding, uid()).unwrap();
        assert_eq!(
            (touched.transcript, touched.len, &touched.tail),
            (stamp.transcript, stamp.len, &stamp.tail),
            "same bytes back"
        );
        assert_ne!(
            (touched.mtime, touched.ctime),
            (stamp.mtime, stamp.ctime),
            "a write anywhere moves the nanosecond times even when the bytes match"
        );
        let copy = path.with_extension("copy");
        std::fs::copy(&path, &copy).unwrap();
        std::fs::rename(&copy, &path).unwrap();
        let replaced = read_stamp(&binding, uid()).unwrap();
        assert_ne!(replaced.transcript, stamp.transcript, "a new inode");

        assert!(read_stamp(&binding_for(&store, "other", &path), uid()).is_none());
        write("{\"type\":\"session_meta\"", "");
        assert!(read_stamp(&binding, uid()).is_none(), "unterminated header");
        write(
            &format!("{}\n", json!({"type":"event_msg","payload":{"id":"t1"}})),
            "",
        );
        assert!(read_stamp(&binding, uid()).is_none(), "not session_meta");
        write(&header, "x");
        assert!(read_stamp(&binding, uid() + 1).is_none(), "foreign owner");
        let link = store.join("sessions").join("link.jsonl");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_stamp(&binding_for(&store, "t1", &link), uid()).is_none());
        let outside = store.join("outside.jsonl");
        std::fs::write(&outside, &header).unwrap();
        assert!(read_stamp(&binding_for(&store, "t1", &outside), uid()).is_none());
        std::fs::remove_dir_all(&store).unwrap();
    }

    /// The spend is journaled before it takes effect and is refused (the proof put
    /// back, nothing to send) when the journal cannot record it; a spent proof stays
    /// spent, is restored only at its own epoch and only when the journal accepts it.
    #[test]
    fn the_proof_is_spent_in_the_journal_before_a_send() {
        use std::os::unix::fs::PermissionsExt;
        let store = store("spn");
        let path = store.join("sessions").join("t.jsonl");
        std::fs::write(
            &path,
            format!("{}\n", json!({"type":"session_meta","payload":{"id":"t1"}})),
        )
        .unwrap();
        let mut registry = Registry::new(
            RegistryConfig {
                host_id: "h".into(),
                harnesses: Vec::new(),
                profiles: Vec::new(),
                intermediates: Vec::new(),
                max_call_age_ms: 600_000,
                relays: Vec::new(),
                audiences: Vec::new(),
                legacy_owner_relays: 0,
            },
            uid(),
        )
        .unwrap();
        let journal = store.join("routes");
        std::fs::create_dir(&journal).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
        registry
            .attach_journal(&journal.join("c.bindings.json"), 1)
            .unwrap();
        let mut binding = binding_for(&store, "t1", &path);
        binding.wake = read_stamp(&binding, uid());
        assert!(binding.wake.is_some());
        let address = binding.address.clone();
        let key = address.to_canonical_string();
        registry.bindings.insert(key.clone(), binding);

        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(registry.spend_wake(&address, 3).is_err());
        assert!(
            registry.bindings[&key].wake.is_some(),
            "an unrecorded spend puts the proof back: nothing is sent"
        );
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(registry.spend_wake(&address, 99).is_err(), "another epoch");
        let spent = registry.spend_wake(&address, 3).unwrap();
        assert!(registry.bindings[&key].wake.is_none());
        assert!(registry.spend_wake(&address, 3).is_err(), "one shot");
        let snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(journal.join("c.bindings.json")).unwrap())
                .unwrap();
        assert!(snapshot["bindings"][0].get("wake").is_none(), "journaled");

        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o500)).unwrap();
        registry.restore_wake(&address, spent.clone());
        assert!(
            registry.bindings[&key].wake.is_none(),
            "a restore the journal cannot record stays spent"
        );
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A non-renewing hook moved the lifecycle (same epoch) after the spend:
        // the binding is no longer the one that was spent, so nothing is revived.
        registry.bindings.get_mut(&key).unwrap().lifecycle = Lifecycle::Active;
        registry.restore_wake(&address, spent.clone());
        assert!(
            registry.bindings[&key].wake.is_none(),
            "a changed lifecycle at the same epoch keeps the proof spent"
        );
        registry.bindings.get_mut(&key).unwrap().lifecycle = Lifecycle::Inactive;
        registry.bindings.get_mut(&key).unwrap().epoch = 4;
        registry.restore_wake(&address, spent.clone());
        assert!(
            registry.bindings[&key].wake.is_none(),
            "another epoch keeps the proof spent"
        );
        registry.bindings.get_mut(&key).unwrap().epoch = 3;
        registry.restore_wake(&address, spent);
        assert!(
            registry.bindings[&key].wake.is_some(),
            "unchanged: restored"
        );
        std::fs::remove_dir_all(&store).unwrap();
    }
    /// Journal restoration of a Codex route whose recorded PID is held by an
    /// unrelated live process with another start time (PID reuse): that process is
    /// never authority and the incarnation is gone. The row survives only as an
    /// *unspent*-proof gateway candidate of a still-configured exact thread and
    /// store, with its committed gateway forgotten; a row without a proof and one
    /// whose Codex harness policy is no longer configured are dropped.
    #[test]
    fn a_reused_pid_is_gone_and_only_an_unspent_configured_proof_survives() {
        use std::os::unix::fs::PermissionsExt;
        let store = store("pid");
        let path = store.join("sessions").join("t.jsonl");
        std::fs::write(
            &path,
            format!("{}\n", json!({"type":"session_meta","payload":{"id":"t1"}})),
        )
        .unwrap();
        let stranger = super::super::tests::LiveChild::own(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .unwrap(),
        );
        let live = os::process_facts(stranger.id()).unwrap();
        let config = |configured: bool| RegistryConfig {
            host_id: "h".into(),
            harnesses: Vec::new(),
            profiles: if configured {
                vec![Profile {
                    namespace: "ns".into(),
                    harness: Harness::Codex,
                    store: store.clone(),
                    executables: vec![QualifiedExecutable {
                        path: "/tmp/executable".into(),
                        sha256: "0".repeat(64),
                        version: "qualified".into(),
                        inject: true,
                        message: true,
                        signature: None,
                    }],
                }]
            } else {
                Vec::new()
            },
            intermediates: Vec::new(),
            max_call_age_ms: 600_000,
            relays: Vec::new(),
            audiences: Vec::new(),
            legacy_owner_relays: 0,
        };
        let journal = store.join("routes");
        std::fs::create_dir(&journal).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = journal.join("c.bindings.json");
        let mut seed = Registry::new(config(true), uid()).unwrap();
        seed.attach_journal(&file, 1).unwrap();
        let mut proven = binding_for(&store, "t1", &path);
        proven.wake = read_stamp(&proven, uid());
        assert!(proven.wake.is_some());
        proven.harness = (live.pid, live.start_time + 7);
        proven.wake.as_mut().unwrap().gateway = Some((live.pid, live.start_time + 7));
        let mut bare = binding_for(&store, "t2", &path);
        bare.harness = (live.pid, live.start_time + 7);
        for binding in [&proven, &bare] {
            seed.bindings
                .insert(binding.address.to_canonical_string(), binding.clone());
        }
        seed.persist_routes().unwrap();
        drop(seed);

        for configured in [true, false] {
            let mut cold = Registry::new(config(configured), uid()).unwrap();
            let restored = cold.attach_journal(&file, 9_000).unwrap();
            assert!(restored.is_empty(), "a reused PID attests nothing");
            let kept = cold.bindings.get(&proven.address.to_canonical_string());
            assert_eq!(kept.is_some(), configured, "configured={configured}");
            assert!(
                !cold
                    .bindings
                    .contains_key(&bare.address.to_canonical_string()),
                "no proof: dropped"
            );
            if let Some(kept) = kept {
                assert_eq!(kept.harness, proven.harness, "the recorded incarnation");
                assert_eq!(kept.wake.as_ref().unwrap().gateway, None);
                assert!(cold.attest_recipient(&proven.address).is_err());
            }
        }
        std::fs::remove_dir_all(&store).unwrap();
    }
    /// A journal text in the exact shape the installed build writes (rows with
    /// `wake` but neither `gateway` nor `pending`, rows without `wake`, and a
    /// retired Desktop tombstone) loads and keeps its routes:
    /// every wake route of a gone Codex incarnation under a still-configured policy
    /// survives inert with its idle proof byte-for-byte (its epoch, recorded
    /// incarnation and transcript identity unchanged, no gateway, no capability
    /// attested, never promoted), rows without a proof are dropped, the retired
    /// tombstone keeps its exact epoch and fences, and the journal written back
    /// still carries all wake routes at mode 0600.
    #[test]
    fn a_current_shape_journal_loads_and_keeps_every_wake_route() {
        use std::os::unix::fs::PermissionsExt;
        let store = store("cur");
        let path = store.join("sessions").join("t.jsonl");
        let mut gone = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let gone_pid = gone.id();
        gone.wait().unwrap();
        assert!(os::process_facts(gone_pid).is_none(), "the PID is gone");
        let proof = |n: u64| {
            json!({
                "transcript": [16_777_232 + n, 9_000_000 + n],
                "len": 4_096 + n,
                "mtime": [1_792_010_000 + n as i64, 123_456_789],
                "ctime": [1_792_010_001 + n as i64, 987_654_321],
                "tail": format!("{n:0>64x}"),
            })
        };
        let row = |thread: &str, wake: Option<serde_json::Value>| {
            let mut binding = binding_for(&store, thread, &path);
            binding.harness = (gone_pid, 1_792_000_000);
            binding.epoch = 1_792_010_500;
            let mut value = serde_json::to_value(&binding).unwrap();
            let fields = value.as_object_mut().unwrap();
            fields.remove("wake");
            fields.remove("pending");
            if let Some(wake) = wake {
                fields.insert("wake".into(), wake);
            }
            value
        };
        let mut tombstone = row("tomb", None);
        tombstone["retired"] = json!(true);
        tombstone["desktop_idle_message"] = json!(true);
        tombstone["desktop_idle_transcript"] = json!([7, 8]);
        let rows = [
            row("w1", Some(proof(1))),
            row("plain", None),
            row("w2", Some(proof(2))),
            tombstone,
            row("w3", Some(proof(3))),
        ];
        let directory = store.join("routes");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = directory.join("c.bindings.json");
        std::fs::write(&file, json!({"schema": 1, "bindings": rows}).to_string()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = RegistryConfig {
            host_id: "h".into(),
            harnesses: Vec::new(),
            profiles: vec![Profile {
                namespace: "ns".into(),
                harness: Harness::Codex,
                store: store.clone(),
                executables: vec![QualifiedExecutable {
                    path: "/tmp/executable".into(),
                    sha256: "0".repeat(64),
                    version: "qualified".into(),
                    inject: true,
                    message: true,
                    signature: None,
                }],
            }],
            intermediates: Vec::new(),
            max_call_age_ms: 600_000,
            relays: Vec::new(),
            audiences: Vec::new(),
            legacy_owner_relays: 0,
        };
        let mut cold = Registry::new(config, uid()).unwrap();
        let restored = cold.attach_journal(&file, 9_000).unwrap();
        assert!(restored.is_empty(), "no gone route is attested");
        for (n, thread) in [(1, "w1"), (2, "w2"), (3, "w3")] {
            let address = NativeAddress::new("h", Harness::Codex, "ns", thread).unwrap();
            let kept = cold
                .bindings
                .get(&address.to_canonical_string())
                .unwrap_or_else(|| panic!("{thread}: the wake route was dropped"));
            let expected: WakeProof = serde_json::from_value(proof(n)).unwrap();
            assert_eq!(kept.wake.as_ref(), Some(&expected), "{thread}: exact proof");
            assert_eq!(kept.wake.as_ref().unwrap().gateway, None);
            assert_eq!(kept.epoch, 1_792_010_500, "{thread}: epoch preserved");
            assert_eq!(kept.harness, (gone_pid, 1_792_000_000));
            assert!(!kept.pending && !kept.retired);
            assert!(cold.attest_recipient(&address).is_err(), "{thread}: inert");
        }
        let plain = NativeAddress::new("h", Harness::Codex, "ns", "plain").unwrap();
        assert!(!cold.bindings.contains_key(&plain.to_canonical_string()));
        let tomb = NativeAddress::new("h", Harness::Codex, "ns", "tomb").unwrap();
        let tomb = &cold.bindings[&tomb.to_canonical_string()];
        assert!(tomb.retired && tomb.epoch == 1_792_010_500);
        assert!(tomb.desktop_idle_message && tomb.wake.is_none());

        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let carrying = written["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row.get("wake").is_some())
            .count();
        assert_eq!(carrying, 3, "the journal still carries every wake route");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&store).unwrap();
    }

    /// Parse-only control against a private COPY of an installed route journal
    /// (never the live file): the whole file decodes under the strict row types and
    /// every row that carries `wake` keeps it. Run with
    /// `BRIDGE_JOURNAL_COPY=/path/to/copy cargo test -- --ignored`.
    #[test]
    #[ignore = "needs BRIDGE_JOURNAL_COPY naming a private copy of a route journal"]
    fn a_copied_installed_journal_decodes_with_every_wake_row() {
        let copy = std::env::var_os("BRIDGE_JOURNAL_COPY").expect("BRIDGE_JOURNAL_COPY");
        let bytes = std::fs::read(copy).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let snapshot: RouteSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(snapshot.schema, 1);
        let rows = raw["bindings"].as_array().unwrap();
        assert_eq!(snapshot.bindings.len(), rows.len());
        let raw_wake = rows.iter().filter(|row| row.get("wake").is_some()).count();
        let decoded = snapshot
            .bindings
            .iter()
            .filter(|b| b.wake.is_some())
            .count();
        assert!(raw_wake > 0, "the copy carries wake routes");
        assert_eq!(decoded, raw_wake, "no wake route is lost on decode");
    }
    /// The proof behind a live Unknown route's wake (not a lifecycle, which stays
    /// `Unknown`): a live Codex harness whose route carries an unspent
    /// idle proof is attested `Inactive`, message-only and as a proof route only
    /// while the exact transcript stamp reads back unchanged; a transcript that
    /// grew or was replaced while the verifier was pending leaves it `Unknown`
    /// (held). After the proof is spent, the last-write fence passes only while the
    /// binding is still `Unknown` at the same epoch with the proof absent, and a
    /// hook that moved the lifecycle, or any transcript change, refuses it.
    #[test]
    fn a_promoted_pending_route_wakes_only_on_an_exact_unspent_proof() {
        let store = store("prf");
        let exe = store.join("harness");
        let child = super::super::tests::live_child(&exe, "CODEX_HOME", &store);
        let facts = os::process_facts(child.id()).unwrap();
        let config = RegistryConfig {
            host_id: "h".into(),
            harnesses: Vec::new(),
            profiles: vec![Profile {
                namespace: "ns".into(),
                harness: Harness::Codex,
                store: store.clone(),
                executables: vec![QualifiedExecutable {
                    path: exe.clone(),
                    sha256: file_sha256(&exe).unwrap(),
                    version: "qualified".into(),
                    inject: true,
                    message: true,
                    signature: None,
                }],
            }],
            intermediates: Vec::new(),
            max_call_age_ms: 600_000,
            relays: Vec::new(),
            audiences: Vec::new(),
            legacy_owner_relays: 0,
        };
        let mut registry = Registry::new(config, uid()).unwrap();
        let path = store.join("sessions").join("t.jsonl");
        let header = format!("{}\n", json!({"type":"session_meta","payload":{"id":"t1"}}));
        for change in ["none", "append", "replace"] {
            std::fs::write(&path, format!("{header}{{\"n\":1}}\n")).unwrap();
            let mut binding = binding_for(&store, "t1", &path);
            binding.executable = exe.clone();
            binding.harness = (facts.pid, facts.start_time);
            binding.lifecycle = Lifecycle::Unknown;
            binding.wake = read_stamp(&binding, uid());
            assert!(binding.wake.is_some());
            let address = binding.address.clone();
            registry
                .bindings
                .insert(address.to_canonical_string(), binding);
            match change {
                "append" => {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap();
                    writeln!(file, "{{\"n\":2}}").unwrap();
                }
                "replace" => {
                    let copy = path.with_extension("copy");
                    std::fs::copy(&path, &copy).unwrap();
                    std::fs::rename(&copy, &path).unwrap();
                }
                _ => {}
            }
            let candidate = registry.message_candidate(&address).unwrap();
            assert!(candidate.needs_idle_proof());
            let (attestation, snapshot) = candidate.validate().unwrap();
            if change != "none" {
                assert_eq!(
                    attestation.lifecycle(),
                    Lifecycle::Unknown,
                    "{change}: held"
                );
                assert!(!snapshot.gateway);
                continue;
            }
            assert_eq!(attestation.lifecycle(), Lifecycle::Inactive);
            assert!(snapshot.gateway && !snapshot.desktop_message_only);

            // Spend, then the last-write fence.
            let proof = registry
                .spend_wake(&address, snapshot.epoch)
                .unwrap()
                .proof()
                .clone();
            let spent = registry.message_candidate(&address).unwrap();
            assert!(
                !spent.needs_idle_proof(),
                "spent: nothing left to wake with"
            );
            spent
                .revalidate_spent(snapshot.epoch, &proof, snapshot.harness)
                .expect("unchanged world passes the final fence");
            std::fs::write(&path, format!("{header}{{\"n\":9}}\n")).unwrap();
            assert!(
                spent
                    .revalidate_spent(snapshot.epoch, &proof, snapshot.harness)
                    .is_err(),
                "a changed transcript refuses the final fence"
            );
            // Isolate the lifecycle guard with an explicit positive control: put the
            // exact bytes back, stamp a FRESH proof from the current file (simulating,
            // for this unit test only, the earlier owner observation) and spend it
            // again, so the world is unchanged and the final fence passes. Only the
            // lifecycle then differs in the negative step, and the earlier (stale)
            // proof and its transcript times play no part.
            std::fs::write(&path, format!("{header}{{\"n\":1}}\n")).unwrap();
            let key = address.to_canonical_string();
            let current = registry.bindings[&key].clone();
            registry.bindings.get_mut(&key).unwrap().wake = read_stamp(&current, uid());
            assert!(registry.bindings[&key].wake.is_some(), "fresh exact stamp");
            let fresh = registry
                .spend_wake(&address, snapshot.epoch)
                .unwrap()
                .proof()
                .clone();
            registry
                .message_candidate(&address)
                .unwrap()
                .revalidate_spent(snapshot.epoch, &fresh, snapshot.harness)
                .expect("positive control: the unchanged fresh world passes the final fence");
            registry.bindings.get_mut(&key).unwrap().lifecycle = Lifecycle::Active;
            let moved = registry.message_candidate(&address).unwrap();
            assert!(
                moved
                    .revalidate_spent(snapshot.epoch, &fresh, snapshot.harness)
                    .is_err(),
                "a hook that moved only the lifecycle refuses the final fence"
            );
        }
        std::fs::remove_dir_all(&store).unwrap();
    }
}
