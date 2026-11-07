//! Durable one-shot claims for unproven Linux Codex wake episodes.
//!
//! Claims live beside the route journal so old Bridge versions can still read
//! that journal. They never grant caller authority or prove delivery.

use super::*;
use std::os::unix::fs::DirBuilderExt;

/// Bound retained episode claims without evicting an uncertain wake.
const MAX_COLD_CLAIMS: usize = 16_384;
/// Private directory beside the recipient worker's route journal.
const DIRECTORY: &str = ".bridge-cold-wakes";

/// Hashes the exact recipient and native completed turn without storing either.
/// The empty turn is reserved for a native thread with no turns.
pub(crate) fn episode_digest(address: &NativeAddress, turn: &str) -> Result<String, String> {
    address.validate().map_err(|error| error.to_string())?;
    if !turn.is_empty() {
        bridge_protocol::validate_id("turn_id", turn, MAX_NATIVE_ID_BYTES)
            .map_err(|_| "invalid native turn identifier")?;
    }
    let mut hash = Sha256::new();
    hash.update(address.to_canonical_string().as_bytes());
    hash.update([0]);
    hash.update(turn.as_bytes());
    Ok(format!("{:x}", hash.finalize()))
}

/// Confirms a directory is owned and private without following its final link.
fn private_dir(path: &Path, uid: u32) -> Result<std::fs::Metadata, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "cold wake directory unavailable")?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err("cold wake directory is not private and owned".into());
    }
    Ok(metadata)
}

/// Finds the private claim directory, creating it only for an actual claim.
fn directory(journal: &Path, uid: u32, create: bool) -> Result<Option<PathBuf>, String> {
    let parent = journal.parent().ok_or("cold wake journal has no parent")?;
    private_dir(parent, uid)?;
    let dir = parent.join(DIRECTORY);
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => std::fs::File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| "cold wake directory could not be committed")?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err("cold wake directory could not be created".into()),
            }
        }
        Err(_) => return Err("cold wake directory unavailable".into()),
    }
    private_dir(&dir, uid)?;
    Ok(Some(dir))
}

/// Whether a particular completed-turn episode has not been claimed.
fn available(journal: &Path, uid: u32, digest: &str) -> Result<(), String> {
    let Some(dir) = directory(journal, uid, false)? else {
        return Ok(());
    };
    match std::fs::symlink_metadata(dir.join(digest)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("this native wake episode was already claimed or is unavailable".into()),
    }
}

/// A claim identifies the exact file created for one completed-turn episode.
pub(crate) struct ColdClaim {
    /// Exact protected marker path and directory.
    path: PathBuf,
    /// Marker device/inode, so refund cannot remove another claim.
    identity: (u64, u64),
    /// Directory device/inode, so replacement cannot inherit the claim.
    directory: (u64, u64),
    /// Owner expected for both objects.
    uid: u32,
}

impl ColdClaim {
    /// Checks the same private directory and marker still back this claim.
    fn current(&self) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or("cold wake marker has no directory")?;
        let dir = private_dir(parent, self.uid)?;
        let file =
            std::fs::symlink_metadata(&self.path).map_err(|_| "cold wake marker unavailable")?;
        if (dir.dev(), dir.ino()) != self.directory
            || !file.is_file()
            || file.uid() != self.uid
            || file.mode() & 0o077 != 0
            || file.nlink() != 1
            || (file.dev(), file.ino()) != self.identity
        {
            return Err("cold wake marker changed".into());
        }
        Ok(())
    }
}

/// Refuses new claims at the bound without evicting old uncertain outcomes.
fn check_capacity(dir: &Path, limit: usize) -> Result<(), String> {
    let mut count = 0;
    for entry in std::fs::read_dir(dir).map_err(|_| "cold wake directory unreadable")? {
        entry.map_err(|_| "cold wake directory unreadable")?;
        count += 1;
        if count >= limit {
            return Err("cold wake claim capacity exhausted".into());
        }
    }
    Ok(())
}

/// Atomically claims one episode and durably records it before native I/O.
fn claim(journal: &Path, uid: u32, digest: &str) -> Result<ColdClaim, String> {
    let dir = directory(journal, uid, true)?.ok_or("cold wake directory unavailable")?;
    let dir_metadata = private_dir(&dir, uid)?;
    check_capacity(&dir, MAX_COLD_CLAIMS)?;
    let path = dir.join(digest);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| "cold wake episode already claimed or unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cold wake marker unavailable")?;
    let claim = ColdClaim {
        path,
        identity: (metadata.dev(), metadata.ino()),
        directory: (dir_metadata.dev(), dir_metadata.ino()),
        uid,
    };
    claim.current()?;
    file.sync_all()
        .and_then(|()| std::fs::File::open(&dir)?.sync_all())
        .and_then(|()| std::fs::File::open(journal.parent().expect("validated parent"))?.sync_all())
        .map_err(|_| "cold wake claim could not be committed")?;
    Ok(claim)
}

impl Registry {
    /// Checks the exact frozen binding and the episode's durable one-shot claim.
    pub(crate) fn cold_wake_available(
        &self,
        snapshot: &MessageCandidate,
        turn: &str,
    ) -> Result<(), String> {
        self.message_current(snapshot)?;
        let journal = self
            .journal
            .as_ref()
            .ok_or("cold wake needs a route journal")?;
        available(
            journal,
            self.owner_uid,
            &episode_digest(&snapshot.binding.address, turn)?,
        )
    }

    /// Persists the target-owned episode claim under the registry lock.
    pub(crate) fn claim_cold_wake(
        &self,
        snapshot: &MessageCandidate,
        turn: &str,
    ) -> Result<ColdClaim, String> {
        self.message_current(snapshot)?;
        let journal = self
            .journal
            .as_ref()
            .ok_or("cold wake needs a route journal")?;
        claim(
            journal,
            self.owner_uid,
            &episode_digest(&snapshot.binding.address, turn)?,
        )
    }

    /// Fences the spent claim and exact binding after recording it.
    pub(crate) fn cold_wake_current(
        &self,
        snapshot: &MessageCandidate,
        turn: &str,
        claim: &ColdClaim,
    ) -> Result<(), String> {
        self.message_current(snapshot)?;
        let journal = self
            .journal
            .as_ref()
            .ok_or("cold wake needs a route journal")?;
        let dir =
            directory(journal, self.owner_uid, false)?.ok_or("cold wake directory unavailable")?;
        if claim.uid != self.owner_uid
            || claim.path.parent() != Some(dir.as_path())
            || claim.path.file_name().and_then(|name| name.to_str())
                != Some(episode_digest(&snapshot.binding.address, turn)?.as_str())
        {
            return Err("cold wake episode changed".into());
        }
        claim.current()
    }

    /// Refunds only an unchanged claim when no native resume was written.
    pub(crate) fn restore_cold_wake(
        &self,
        snapshot: &MessageCandidate,
        turn: &str,
        claim: ColdClaim,
    ) {
        if self.cold_wake_current(snapshot, turn, &claim).is_err() {
            return;
        }
        if std::fs::remove_file(&claim.path).is_ok()
            && let Some(parent) = claim.path.parent()
        {
            let _ = std::fs::File::open(parent).and_then(|file| file.sync_all());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Makes a private, test-owned directory under the selected task TMPDIR.
    fn fixture(name: &str) -> (PathBuf, PathBuf, u32) {
        let root = std::env::temp_dir().join(format!("cold-{}-{name}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let uid = os::process_facts(std::process::id()).unwrap().uid.unwrap();
        (root.clone(), root.join("c.bindings.json"), uid)
    }

    /// Claims survive reopening and distinguish recipients and completed turns.
    #[test]
    fn claims_are_durable_one_shot_per_exact_episode() {
        let (root, journal, uid) = fixture("episodes");
        let a = NativeAddress::new("host", Harness::CODEX, "ns", "thread-a").unwrap();
        let b = NativeAddress::new("host", Harness::CODEX, "ns", "thread-b").unwrap();
        let first = episode_digest(&a, "turn-1").unwrap();
        let next = episode_digest(&a, "turn-2").unwrap();
        let other = episode_digest(&b, "turn-1").unwrap();
        assert_ne!(first, next);
        assert_ne!(first, other);
        assert!(available(&journal, uid, &first).is_ok());
        let held = claim(&journal, uid, &first).unwrap();
        assert!(held.current().is_ok());
        assert!(available(&journal, uid, &first).is_err());
        assert!(claim(&journal, uid, &first).is_err());
        assert!(claim(&journal, uid, &next).is_ok());
        assert!(claim(&journal, uid, &other).is_ok());
        assert_ne!(episode_digest(&a, "").unwrap(), first);
        assert!(episode_digest(&a, "bad\nturn").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Replacement, an unsafe directory and a full ledger never grant a claim.
    #[test]
    fn marker_replacement_and_capacity_fail_closed() {
        let (root, journal, uid) = fixture("refusal");
        let address = NativeAddress::new("host", Harness::CODEX, "ns", "thread").unwrap();
        let digest = episode_digest(&address, "turn").unwrap();
        let held = claim(&journal, uid, &digest).unwrap();
        let dir = held.path.parent().unwrap();
        assert!(check_capacity(dir, 1).is_err());
        assert!(check_capacity(dir, 2).is_ok());
        let moved = dir.join("old");
        std::fs::rename(&held.path, moved).unwrap();
        std::fs::write(&held.path, b"").unwrap();
        assert!(
            held.current().is_err(),
            "another inode cannot inherit a claim"
        );
        std::fs::remove_dir_all(dir).unwrap();
        std::os::unix::fs::symlink(&root, dir).unwrap();
        assert!(available(&journal, uid, &digest).is_err());
        assert!(claim(&journal, uid, &digest).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Claim, proof spend and refund fence a changed binding across a restart.
    #[test]
    fn shared_episode_claim_survives_binding_renewal_and_restart() {
        let (root, journal, uid) = fixture("registry");
        let sessions = root.join("store/sessions");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&sessions)
            .unwrap();
        let transcript = sessions.join("thread.jsonl");
        std::fs::write(
            &transcript,
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"thread\"}}\n",
        )
        .unwrap();
        let address = NativeAddress::new("host", Harness::CODEX, "ns", "thread").unwrap();
        let policy = HarnessPolicy {
            harness: Harness::CODEX,
            namespace: "ns".into(),
            inject: true,
            message: true,
            executable_markers: Vec::new(),
            store_env: None,
            store_home: None,
            child_address: None,
            caller_proof: Vec::new(),
        };
        let config = RegistryConfig {
            host_id: "host".into(),
            harnesses: vec![policy.clone()],
            profiles: Vec::new(),
            intermediates: Vec::new(),
            max_call_age_ms: 600_000,
            relays: Vec::new(),
            audiences: Vec::new(),
            legacy_owner_relays: 0,
        };
        let mut registry = Registry::new(config.clone(), uid).unwrap();
        registry.attach_journal(&journal, 1).unwrap();
        let mut binding = Binding {
            address: address.clone(),
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
            lifecycle: Lifecycle::Unknown,
            transcript: Some(transcript),
            store: root.join("store"),
            executable: root.join("codex"),
            retired: true,
            desktop_idle_message: false,
            desktop_idle_transcript: None,
            wake: None,
            pending: false,
            role: None,
        };
        binding.wake = Some(gateway::read_stamp(&binding, uid).unwrap());
        let candidate = MessageCandidate {
            binding: binding.clone(),
            policy,
            owner_uid: uid,
        };
        registry
            .bindings
            .insert(address.to_canonical_string(), binding);
        registry.persist_routes().unwrap();

        // Two source workers share this one recipient-side claim.
        let claim = registry.claim_cold_wake(&candidate, "turn-1").unwrap();
        assert!(registry.claim_cold_wake(&candidate, "turn-1").is_err());
        let spent = registry
            .spend_wake(&address, candidate.binding.epoch)
            .unwrap();
        let after_spend = candidate.after_live_resume_spend();
        registry
            .cold_wake_current(&after_spend, "turn-1", &claim)
            .unwrap();
        registry.restore_wake(&address, spent);
        registry.restore_cold_wake(&candidate, "turn-1", claim);
        assert!(registry.cold_wake_available(&candidate, "turn-1").is_ok());

        let held = registry.claim_cold_wake(&candidate, "turn-1").unwrap();
        registry
            .bindings
            .get_mut(&address.to_canonical_string())
            .unwrap()
            .epoch += 1;
        registry.persist_routes().unwrap();
        registry.restore_cold_wake(&candidate, "turn-1", held);
        let mut restarted = Registry::new(config, uid).unwrap();
        restarted.attach_journal(&journal, 2).unwrap();
        let current = restarted.live_resume_candidate(&address).unwrap();
        assert!(restarted.cold_wake_available(&current, "turn-1").is_err());
        assert!(restarted.cold_wake_available(&current, "turn-2").is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
