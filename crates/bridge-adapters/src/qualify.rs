//! Loaded-version attestation, baseline alignment and install gates.
//!
//! Qualification works on what is actually **loaded**, never on what is on
//! disk: a bundled daemon, desktop frontend or helper at rest proves
//! nothing about the running endpoint. These records make that explicit —
//! [`LoadedVersion`] separates disk from loaded and requires re-attestation
//! whenever they disagree, [`BaselineAlignment`] records the delta between
//! a pinned research checkout and the actual installed release before any
//! integration claim, and [`CapabilityReadiness`] keeps unsupported
//! capabilities visible instead of hidden behind an endless queue.

/// One component whose loaded version was attested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedVersion {
    /// Human-readable component name (for example "codex bundled daemon").
    pub component: String,
    /// Version found on disk for this component.
    pub disk_version: String,
    /// Version observed on the actually loaded endpoint, if it could be
    /// attested; `None` means not yet attested — never "same as disk".
    pub loaded_version: Option<String>,
    /// Unix epoch milliseconds of the attestation attempt.
    pub attested_at_ms: u64,
}

impl LoadedVersion {
    /// Whether disk and loaded versions are positively known to match.
    ///
    /// `false` when the loaded version is unattested or differs: the
    /// caller must re-attest before qualifying behavior against
    /// observations made on another version.
    pub fn loaded_matches_disk(&self) -> bool {
        match &self.loaded_version {
            Some(loaded) => loaded == &self.disk_version,
            None => false,
        }
    }

    /// Whether this record is fresh enough to rely on at `now_ms`.
    pub fn is_fresh(&self, now_ms: u64, max_age_ms: u64) -> bool {
        now_ms.saturating_sub(self.attested_at_ms) <= max_age_ms
    }
}

/// Recorded alignment between a pinned research checkout and reality.
///
/// Existing family checkouts are pinned historical baselines: their
/// versions are not claims about what is installed or loaded. Before any
/// integration, each component's delta is recorded here so alignment is a
/// visible step, not an assumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineAlignment {
    /// Component being aligned.
    pub component: String,
    /// Version (or commit) of the pinned baseline checkout.
    pub pinned_baseline: String,
    /// Version of the actually installed release, once observed.
    pub installed_release: Option<String>,
    /// Bounded description of the gap: identical, ahead, behind or
    /// unattested.
    pub delta: String,
    /// Whether the baseline may be treated as representative of the
    /// installed release for the aligned behavior.
    pub representative: bool,
}

/// Readiness of one carrier capability for qualification claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityReadiness {
    /// Qualified on the loaded host; claims may reference it.
    Qualified { loaded_version: String },
    /// Not qualified yet; the reason names what is missing (for example
    /// "requires authorized installation test").
    Pending { reason: String },
    /// Genuinely unsupported on the loaded host; reported explicitly
    /// before any full-auto promise is made.
    Unsupported { reason: String },
}

/// The standalone-scope qualification report for one host.
///
/// Collects version attestations, baseline alignments and carrier
/// readiness into one immutable snapshot a reviewer can read. Actual
/// loaded GUI/frontend hook installation, actor separation and lifecycle
/// qualification remain explicitly gated work ([`CapabilityReadiness`]
/// entries say so); this type never claims them by omission.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QualificationReport {
    /// Loaded-version attestations per component.
    pub versions: Vec<LoadedVersion>,
    /// Baseline alignments recorded before integration.
    pub baselines: Vec<BaselineAlignment>,
    /// Readiness per carrier capability.
    pub carriers: Vec<(&'static str, CapabilityReadiness)>,
}

impl QualificationReport {
    /// Whether every recorded version attestation positively matches disk.
    ///
    /// An empty list is `false`, not `true`: no attestation is not
    /// qualification.
    pub fn versions_attested(&self) -> bool {
        !self.versions.is_empty() && self.versions.iter().all(LoadedVersion::loaded_matches_disk)
    }

    /// Whether every recorded carrier is qualified.
    ///
    /// Pending and unsupported carriers make this `false`; the report
    /// itself still records them honestly.
    pub fn carriers_qualified(&self) -> bool {
        !self.carriers.is_empty()
            && self
                .carriers
                .iter()
                .all(|(_, readiness)| matches!(readiness, CapabilityReadiness::Qualified { .. }))
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for qualification records.

    use super::*;

    #[test]
    fn disk_version_never_stands_in_for_loaded() {
        let unattested = LoadedVersion {
            component: "codex bundled daemon".into(),
            disk_version: "0.9.0".into(),
            loaded_version: None,
            attested_at_ms: 1_000,
        };
        assert!(!unattested.loaded_matches_disk());
        let matching = LoadedVersion {
            loaded_version: Some("0.9.0".into()),
            ..unattested
        };
        assert!(matching.loaded_matches_disk());
        let differing = LoadedVersion {
            loaded_version: Some("0.10.0".into()),
            ..matching.clone()
        };
        assert!(!differing.loaded_matches_disk());
        assert!(matching.is_fresh(1_500, 1_000));
        assert!(!matching.is_fresh(5_000, 1_000));
    }

    #[test]
    fn reports_do_not_claim_qualification_by_omission() {
        let empty = QualificationReport::default();
        assert!(!empty.versions_attested());
        assert!(!empty.carriers_qualified());
        let pending = QualificationReport {
            versions: vec![LoadedVersion {
                component: "claude desktop".into(),
                disk_version: "2.1.295".into(),
                loaded_version: Some("2.1.295".into()),
                attested_at_ms: 1_000,
            }],
            baselines: vec![BaselineAlignment {
                component: "claude desktop".into(),
                pinned_baseline: "bridge-deferred-20261011".into(),
                installed_release: Some("2.1.295".into()),
                delta: "identical".into(),
                representative: true,
            }],
            carriers: vec![(
                "message",
                CapabilityReadiness::Qualified {
                    loaded_version: "2.1.295".into(),
                },
            )],
        };
        assert!(pending.versions_attested());
        assert!(pending.carriers_qualified());
        let with_pending = QualificationReport {
            carriers: vec![(
                "inject",
                CapabilityReadiness::Pending {
                    reason: "requires authorized installation test".into(),
                },
            )],
            ..pending
        };
        assert!(!with_pending.carriers_qualified());
    }
}
