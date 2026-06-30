//! Installed-artifact catalogue and plan diff.
//!
//! A lightweight, domain-agnostic view of what is currently installed in an
//! environment, plus the diff against a plan's declared artifact set that
//! produces the download/apply work-list.
//!
//! To keep this crate free of a `greentic-deploy-spec` dependency, the
//! catalogue is expressed in this module's own simple types. The deployer-side
//! caller projects its domain types — a `Revision`'s `pack_list` entries, the
//! revision `bundle_digest`, component refs — into a [`InstalledCatalogue`] of
//! [`InstalledArtifact`]s before calling [`diff`]. No persistence lives here;
//! the installed set is derived from the environment document on demand.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::plan::PlanArtifact;

/// One installed artifact, keyed by `name`. `digest` is the content digest in
/// `sha256:<hex>` form (the format used across the deployer's pack-list and
/// bundle digests).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledArtifact {
    pub name: String,
    pub version: String,
    pub digest: String,
}

/// The set of artifacts currently installed in an environment. Names are
/// expected to be unique; the caller owns deduplication when projecting from
/// the environment document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledCatalogue {
    pub artifacts: Vec<InstalledArtifact>,
}

impl InstalledCatalogue {
    /// Build a catalogue from an installed-artifact list.
    pub fn new(artifacts: Vec<InstalledArtifact>) -> Self {
        Self { artifacts }
    }

    /// Look up an installed artifact by name (first match wins).
    pub fn get(&self, name: &str) -> Option<&InstalledArtifact> {
        self.artifacts.iter().find(|a| a.name == name)
    }
}

/// What a planned artifact requires relative to the installed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAction {
    /// Not installed — must be downloaded and installed.
    Add,
    /// Installed under the same name but a different digest — must be
    /// downloaded and replaced.
    Update,
    /// Installed with a matching digest — no work needed.
    Unchanged,
}

/// One planned artifact paired with the action the diff resolved for it, plus
/// the prior installed entry (for `Update`/`Unchanged`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanItem {
    pub action: ArtifactAction,
    pub planned: PlanArtifact,
    pub installed: Option<InstalledArtifact>,
}

/// The result of diffing an installed catalogue against a plan's artifacts: one
/// [`PlanItem`] per planned artifact, plus the installed artifacts that the
/// plan no longer references (prune candidates — removal is opt-in, never
/// implied by a diff).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkList {
    pub items: Vec<PlanItem>,
    pub removed: Vec<InstalledArtifact>,
}

impl WorkList {
    /// Planned artifacts that must be fetched — i.e. `Add` or `Update`.
    /// `Unchanged` artifacts are skipped.
    pub fn to_download(&self) -> Vec<&PlanArtifact> {
        self.items
            .iter()
            .filter(|i| matches!(i.action, ArtifactAction::Add | ArtifactAction::Update))
            .map(|i| &i.planned)
            .collect()
    }

    /// Whether any artifact needs fetching (`Add` or `Update`).
    pub fn has_work(&self) -> bool {
        self.items
            .iter()
            .any(|i| matches!(i.action, ArtifactAction::Add | ArtifactAction::Update))
    }
}

/// Diff an installed catalogue against a plan's declared artifacts.
///
/// Each planned artifact becomes a [`PlanItem`]: `Add` if not installed,
/// `Unchanged` if installed with a matching digest, `Update` otherwise.
/// Installed artifacts whose name does not appear in the plan are surfaced as
/// `removed` (prune candidates). Result order mirrors input order: `items`
/// follows `planned`, `removed` follows `catalogue.artifacts`.
pub fn diff(catalogue: &InstalledCatalogue, planned: &[PlanArtifact]) -> WorkList {
    // First-match-wins lookup (consistent with `InstalledCatalogue::get`); the
    // caller owns deduplication of the installed set.
    let mut installed_by_name: HashMap<&str, &InstalledArtifact> = HashMap::new();
    for a in &catalogue.artifacts {
        installed_by_name.entry(a.name.as_str()).or_insert(a);
    }

    let mut items = Vec::with_capacity(planned.len());
    for p in planned {
        let (action, installed) = match installed_by_name.get(p.name.as_str()) {
            None => (ArtifactAction::Add, None),
            Some(inst) => {
                let action = if digests_match(&inst.digest, &p.digest) {
                    ArtifactAction::Unchanged
                } else {
                    ArtifactAction::Update
                };
                (action, Some((*inst).clone()))
            }
        };
        items.push(PlanItem {
            action,
            planned: p.clone(),
            installed,
        });
    }

    let planned_names: HashSet<&str> = planned.iter().map(|p| p.name.as_str()).collect();
    let removed = catalogue
        .artifacts
        .iter()
        .filter(|a| !planned_names.contains(a.name.as_str()))
        .cloned()
        .collect();

    WorkList { items, removed }
}

/// Compare two `sha256:<hex>` digests, tolerating surrounding whitespace and
/// hex case. A mismatch (including a missing/extra prefix) conservatively
/// counts as different, yielding an `Update` rather than silently skipping.
fn digests_match(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(name: &str, version: &str, digest: &str) -> InstalledArtifact {
        InstalledArtifact {
            name: name.to_string(),
            version: version.to_string(),
            digest: digest.to_string(),
        }
    }

    fn planned(name: &str, version: &str, digest: &str) -> PlanArtifact {
        PlanArtifact {
            name: name.to_string(),
            version: version.to_string(),
            digest: digest.to_string(),
            source: Some(format!("oci://example/{name}:{version}")),
        }
    }

    fn action_for<'a>(work: &'a WorkList, name: &str) -> &'a PlanItem {
        work.items
            .iter()
            .find(|i| i.planned.name == name)
            .expect("plan item present")
    }

    #[test]
    fn diff_classifies_add_update_unchanged_and_remove() {
        let cat = InstalledCatalogue::new(vec![
            installed("a", "1.0.0", "sha256:aaa"),
            installed("b", "1.0.0", "sha256:bbb"),
            installed("c", "1.0.0", "sha256:ccc"),
        ]);
        let plan = vec![
            planned("a", "1.0.0", "sha256:aaa"), // unchanged
            planned("b", "2.0.0", "sha256:b22"), // update (digest differs)
            planned("d", "1.0.0", "sha256:ddd"), // add (new)
        ];

        let work = diff(&cat, &plan);

        assert_eq!(action_for(&work, "a").action, ArtifactAction::Unchanged);
        assert_eq!(action_for(&work, "b").action, ArtifactAction::Update);
        assert_eq!(action_for(&work, "d").action, ArtifactAction::Add);

        // Update/Unchanged carry the prior installed entry; Add does not.
        assert_eq!(
            action_for(&work, "b").installed.as_ref().unwrap().digest,
            "sha256:bbb"
        );
        assert!(action_for(&work, "d").installed.is_none());

        // `c` is installed but not in the plan -> prune candidate.
        let removed_names: Vec<_> = work.removed.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(removed_names, vec!["c"]);
    }

    #[test]
    fn to_download_includes_only_add_and_update() {
        let cat = InstalledCatalogue::new(vec![
            installed("a", "1.0.0", "sha256:aaa"),
            installed("b", "1.0.0", "sha256:bbb"),
        ]);
        let plan = vec![
            planned("a", "1.0.0", "sha256:aaa"), // unchanged
            planned("b", "2.0.0", "sha256:b22"), // update
            planned("d", "1.0.0", "sha256:ddd"), // add
        ];

        let work = diff(&cat, &plan);
        assert!(work.has_work());
        let names: Vec<_> = work.to_download().iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["b", "d"]);
    }

    #[test]
    fn matching_digest_is_unchanged_even_with_version_bump() {
        // Same content digest but a different version string still counts as
        // unchanged — the digest is the source of truth for "already have it".
        let cat = InstalledCatalogue::new(vec![installed("a", "1.0.0", "sha256:aaa")]);
        let plan = vec![planned("a", "1.0.1", "sha256:aaa")];
        let work = diff(&cat, &plan);
        assert_eq!(action_for(&work, "a").action, ArtifactAction::Unchanged);
        assert!(!work.has_work());
    }

    #[test]
    fn digest_comparison_is_case_insensitive() {
        let cat = InstalledCatalogue::new(vec![installed("a", "1.0.0", "sha256:ABCDEF")]);
        let plan = vec![planned("a", "1.0.0", "sha256:abcdef")];
        let work = diff(&cat, &plan);
        assert_eq!(action_for(&work, "a").action, ArtifactAction::Unchanged);
    }

    #[test]
    fn empty_catalogue_makes_everything_an_add() {
        let cat = InstalledCatalogue::default();
        let plan = vec![
            planned("a", "1.0.0", "sha256:aaa"),
            planned("b", "1.0.0", "sha256:bbb"),
        ];
        let work = diff(&cat, &plan);
        assert!(work.items.iter().all(|i| i.action == ArtifactAction::Add));
        assert!(work.removed.is_empty());
        assert_eq!(work.to_download().len(), 2);
    }

    #[test]
    fn empty_plan_marks_everything_removed() {
        let cat = InstalledCatalogue::new(vec![
            installed("a", "1.0.0", "sha256:aaa"),
            installed("b", "1.0.0", "sha256:bbb"),
        ]);
        let work = diff(&cat, &[]);
        assert!(work.items.is_empty());
        assert!(!work.has_work());
        assert_eq!(work.removed.len(), 2);
    }

    #[test]
    fn catalogue_get_finds_by_name() {
        let cat = InstalledCatalogue::new(vec![installed("a", "1.0.0", "sha256:aaa")]);
        assert_eq!(cat.get("a").unwrap().digest, "sha256:aaa");
        assert!(cat.get("missing").is_none());
    }
}
