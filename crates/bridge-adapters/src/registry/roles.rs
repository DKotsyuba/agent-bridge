//! Durable role fences for managed frontends and detached consumers.
//!
//! This private journal is independent of both routes and consume receipts.
//! A frontend incarnation is recorded before an authenticated frontend action;
//! restart or reparenting cannot turn that process into a resident consumer.

use super::attempt::{AttemptError, ResultV1};
use super::*;

/// Maximum remembered live or potentially live frontend incarnations.
const MAX_FRONTENDS: usize = 4_096;

/// Numbered private frontend table, tied to a store and one kernel boot and PID
/// namespace. The bootstrap tick is never renewed on a same-boot restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleJournal {
    /// Exact journal schema; unknown formats refuse managed operations.
    schema: u32,
    /// Route store whose managed roles this table protects.
    store_id: String,
    /// Kernel boot for both the bootstrap point and recorded processes.
    boot_id: String,
    /// Bridge's PID namespace inode.
    pid_namespace_inode: u64,
    /// Same-UID owner of every frontend and consumer.
    uid: u32,
    /// Fresh kernel birth tick sampled before first enabling this table.
    initialized_ticks: u64,
    /// Successfully qualified frontend incarnations, retained while possibly live.
    frontends: Vec<os::attempt::KernelIncarnation>,
    /// Successfully qualified consumers; the same incarnation cannot later
    /// acquire frontend authority even after reparenting or an exec.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    consumers: Vec<os::attempt::KernelIncarnation>,
}

/// In-memory role state; any uncertain commit fences managed roles until restart.
#[derive(Debug, Default)]
pub(super) struct RoleState {
    /// Private journal path after the route journal is attached.
    path: Option<PathBuf>,
    /// Validated durable table, if initialized successfully.
    journal: Option<RoleJournal>,
    /// Missing proof or a possibly committed write requires recovery.
    poisoned: bool,
    /// A write may have committed before its error was observed.
    uncertain: bool,
}

impl RoleJournal {
    /// Validates all saved identities without attempting to promote old rows.
    fn valid(&self, store_id: &str, uid: u32) -> bool {
        let mut unique = std::collections::HashSet::new();
        self.schema == 1
            && self.store_id == store_id
            && os::attempt::canonical_uuid(&self.boot_id)
            && self.pid_namespace_inode != 0
            && self.uid == uid
            && self.initialized_ticks != 0
            && self.frontends.len() <= MAX_FRONTENDS
            && self.consumers.len() <= MAX_FRONTENDS
            && self.frontends.iter().chain(&self.consumers).all(|entry| {
                entry.uid == uid
                    && entry.pid != 0
                    && entry.start_ticks != 0
                    && entry.boot_id == self.boot_id
                    && entry.pid_namespace_inode == self.pid_namespace_inode
                    && unique.insert(entry)
            })
    }

    /// Creates a new per-boot/namespace bootstrap point using a fresh kernel
    /// thread sample, never wall-clock seconds or a caller-supplied timestamp.
    fn initialize(store_id: &str, uid: u32) -> Result<Self, String> {
        let current = os::attempt::kernel_incarnation(std::process::id(), uid)
            .map_err(|_| "frontend role identity unavailable")?;
        let initialized_ticks = os::attempt::sample_start_ticks()
            .map_err(|_| "frontend role initialization unavailable")?;
        if initialized_ticks < current.start_ticks {
            return Err("frontend role initialization unavailable".into());
        }
        Ok(Self {
            schema: 1,
            store_id: store_id.into(),
            boot_id: current.boot_id,
            pid_namespace_inode: current.pid_namespace_inode,
            uid,
            initialized_ticks,
            frontends: Vec::new(),
            consumers: Vec::new(),
        })
    }
}

/// A role is retained when its exact process exists or cannot be proven gone.
fn frontend_may_be_live(identity: &os::attempt::KernelIncarnation) -> bool {
    match os::attempt::kernel_incarnation(identity.pid, identity.uid) {
        Ok(current) => current == *identity,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && os::attempt::definitely_gone(identity.pid) =>
        {
            false
        }
        Err(_) => true,
    }
}

impl Registry {
    /// Redirects a synthetic role journal to an unavailable parent and returns
    /// its original path for fixture restoration.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn fixture_fail_frontend_role_commit(&mut self) -> PathBuf {
        let original = self
            .frontend_roles
            .path
            .clone()
            .expect("fixture role journal");
        self.frontend_roles.path = Some(
            original
                .parent()
                .expect("fixture parent")
                .join("missing-fixture-parent/frontend-roles.json"),
        );
        original
    }

    /// Restores the synthetic journal path without clearing a poisoned state.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn fixture_restore_frontend_role_commit(&mut self, original: PathBuf) {
        self.frontend_roles.path = Some(original);
    }

    /// A corrupt or uncertain role table cannot support managed capability
    /// advertisement, even to a separately authenticated Run reader.
    pub(super) fn ensure_frontend_roles(&self) -> ResultV1<()> {
        if self.frontend_roles.poisoned || self.frontend_roles.journal.is_none() {
            return Err(AttemptError {
                code: "recovery_required",
                recovery: if self.frontend_roles.uncertain {
                    "same_key_lookup"
                } else {
                    "operator"
                },
            });
        }
        Ok(())
    }

    /// Attaches or initializes the independent role journal only when managed
    /// tools are enabled. Corruption or uncertain writes fail managed roles
    /// closed without poisoning unrelated legacy routes.
    pub(super) fn attach_frontend_roles(&mut self, route_path: &Path) {
        if self.config.managed_tools.is_empty() {
            return;
        }
        let path = route_path.with_extension("frontend-roles.json");
        self.frontend_roles.path = Some(path.clone());
        let loaded = remove_stale_journal_temps(&path, self.owner_uid).and_then(|()| {
            read_private_journal(&path, self.owner_uid).and_then(|bytes| {
                bytes
                    .map(|bytes| {
                        serde_json::from_slice::<RoleJournal>(&bytes)
                            .map_err(|_| "frontend role journal malformed".to_string())
                    })
                    .transpose()
            })
        });
        let current = os::attempt::kernel_incarnation(std::process::id(), self.owner_uid);
        let journal = match (loaded, current) {
            (Ok(Some(journal)), Ok(current)) if journal.valid(&self.store_id, self.owner_uid) => {
                if journal.boot_id == current.boot_id
                    && journal.pid_namespace_inode == current.pid_namespace_inode
                {
                    os::attempt::sample_start_ticks()
                        .ok()
                        .filter(|now| {
                            journal.initialized_ticks <= *now
                                && journal
                                    .frontends
                                    .iter()
                                    .chain(&journal.consumers)
                                    .all(|entry| entry.start_ticks <= *now)
                        })
                        .map(|_| (journal, false))
                } else {
                    RoleJournal::initialize(&self.store_id, self.owner_uid)
                        .ok()
                        .map(|journal| (journal, true))
                }
            }
            (Ok(None), Ok(_)) => RoleJournal::initialize(&self.store_id, self.owner_uid)
                .ok()
                .map(|journal| (journal, true)),
            _ => None,
        };
        let Some((journal, needs_commit)) = journal else {
            self.frontend_roles.poisoned = true;
            return;
        };
        self.frontend_roles.journal = Some(journal);
        if needs_commit && self.persist_frontend_roles().is_err() {
            self.frontend_roles.poisoned = true;
            self.frontend_roles.uncertain = true;
        }
    }

    /// Commits only role data, atomically and privately, before its authority is
    /// used. The separate file avoids coupling it to legacy route persistence.
    fn persist_frontend_roles(&self) -> Result<(), String> {
        let path = self
            .frontend_roles
            .path
            .as_ref()
            .ok_or("frontend role journal missing")?;
        let journal = self
            .frontend_roles
            .journal
            .as_ref()
            .ok_or("frontend role journal missing")?;
        if !journal.valid(&self.store_id, self.owner_uid) {
            return Err("frontend role journal invalid".into());
        }
        let bytes =
            serde_json::to_vec(journal).map_err(|_| "frontend role journal encoding failed")?;
        if bytes.len() as u64 > MAX_ROUTE_SNAPSHOT_BYTES {
            return Err("frontend role journal oversized".into());
        }
        write_private_journal(path, &bytes)
    }

    /// Requires a successfully initialized table in this exact boot/namespace.
    fn checked_frontend_roles(
        &self,
        identity: &os::attempt::KernelIncarnation,
    ) -> ResultV1<&RoleJournal> {
        self.ensure_frontend_roles()?;
        let failed = || AttemptError {
            code: "recovery_required",
            recovery: if self.frontend_roles.uncertain {
                "same_key_lookup"
            } else {
                "operator"
            },
        };
        let journal = self
            .frontend_roles
            .journal
            .as_ref()
            .filter(|_| !self.frontend_roles.poisoned)
            .ok_or_else(failed)?;
        if identity.uid != self.owner_uid
            || identity.boot_id != journal.boot_id
            || identity.pid_namespace_inode != journal.pid_namespace_inode
        {
            return Err(failed());
        }
        Ok(journal)
    }

    /// Durably records one authenticated frontend incarnation before allowing
    /// its frontend operation; it can never later satisfy a consumer role.
    pub(super) fn remember_frontend(
        &mut self,
        identity: &os::attempt::KernelIncarnation,
    ) -> ResultV1<()> {
        let journal = self.checked_frontend_roles(identity)?;
        if journal.consumers.contains(identity) {
            return Err(AttemptError {
                code: "peer_not_authorized",
                recovery: "none",
            });
        }
        if journal.frontends.contains(identity) {
            return Ok(());
        }
        let journal = self
            .frontend_roles
            .journal
            .as_mut()
            .expect("checked journal");
        if journal.frontends.len() >= MAX_FRONTENDS {
            journal.frontends.retain(frontend_may_be_live);
        }
        if journal.frontends.len() >= MAX_FRONTENDS {
            return Err(AttemptError {
                code: "capacity_exhausted",
                recovery: "operator",
            });
        }
        journal.frontends.push(identity.clone());
        if self.persist_frontend_roles().is_err() {
            self.frontend_roles.poisoned = true;
            self.frontend_roles.uncertain = true;
            return Err(AttemptError {
                code: "recovery_required",
                recovery: "same_key_lookup",
            });
        }
        Ok(())
    }

    /// Durably records a proven consumer before a managed action; this same
    /// process incarnation cannot subsequently assume the frontend role.
    pub(super) fn remember_consumer(
        &mut self,
        identity: &os::attempt::KernelIncarnation,
    ) -> ResultV1<()> {
        let journal = self.checked_frontend_roles(identity)?;
        if journal.frontends.contains(identity) {
            return Err(AttemptError {
                code: "peer_not_authorized",
                recovery: "none",
            });
        }
        if journal.consumers.contains(identity) {
            return Ok(());
        }
        let journal = self
            .frontend_roles
            .journal
            .as_mut()
            .expect("checked journal");
        if journal.consumers.len() >= MAX_FRONTENDS {
            journal.consumers.retain(frontend_may_be_live);
        }
        if journal.consumers.len() >= MAX_FRONTENDS {
            return Err(AttemptError {
                code: "capacity_exhausted",
                recovery: "operator",
            });
        }
        journal.consumers.push(identity.clone());
        if self.persist_frontend_roles().is_err() {
            self.frontend_roles.poisoned = true;
            self.frontend_roles.uncertain = true;
            return Err(AttemptError {
                code: "recovery_required",
                recovery: "same_key_lookup",
            });
        }
        Ok(())
    }

    /// Establishes detached managed-consumer role, including same-build
    /// bootstrap, durable frontend exclusions and a complete kernel ancestry.
    pub(super) fn verify_detached_consumer(
        &self,
        identity: &os::attempt::KernelIncarnation,
        producer: &str,
        audience: &str,
    ) -> ResultV1<()> {
        let journal = self.checked_frontend_roles(identity)?;
        let refused = || AttemptError {
            code: "peer_not_authorized",
            recovery: "none",
        };
        if journal.frontends.contains(identity) {
            return Err(refused());
        }
        let consumer = self
            .config
            .audiences
            .iter()
            .find(|entry| entry.producer == producer && entry.name == audience)
            .ok_or_else(refused)?;
        let shared_build = self.config.managed_tools.iter().any(|tool| {
            tool.frontend.path == consumer.executable.path
                || tool
                    .frontend
                    .sha256
                    .eq_ignore_ascii_case(&consumer.executable.sha256)
        });
        let mut excluded = journal.frontends.clone();
        excluded.extend(
            self.bindings
                .values()
                .filter_map(|binding| binding.managed_incarnation.clone()),
        );
        excluded.extend(
            self.root_launches
                .values()
                .map(|root| root.incarnation.clone()),
        );
        if !os::attempt::detached_consumer(identity, &excluded).map_err(|_| refused())? {
            return Err(refused());
        }
        if shared_build && identity.start_ticks <= journal.initialized_ticks {
            return Err(AttemptError {
                code: "relaunch_required",
                recovery: "none",
            });
        }
        Ok(())
    }
}
