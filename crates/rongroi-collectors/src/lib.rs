// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Collectors read one kind of artifact from a [`Host`] and report what they saw.
//! Rules for writing one are in `crates/rongroi-collectors/AGENTS.md` and `CONVENTIONS.md` §3.

pub mod bam;
pub mod evtx;
pub mod failure;
pub mod fivem_dir;
pub mod paths;
pub mod pca;
pub mod posture;
pub mod prefetch;
pub mod process;
pub mod scan;

use rongroi_core::model::{CollectorRun, UnmeasuredReason};
use rongroi_host::Host;

/// Reads one kind of artifact. Implementations must be read-only and must never panic.
pub trait Collector {
    /// Stable id, equal to the `collector` field of the rules that read it.
    fn id(&self) -> &'static str;
    /// Every observation field name this collector can emit, sorted.
    ///
    /// This is the vocabulary a rule's `match` may name, and `cargo xtask check-rules` rejects a
    /// rule that names anything outside it (ADR 0026). It is a declaration rather than something
    /// derived from the code, so it can drift from what `collect` really puts in a field map; what
    /// holds the two together is the `every_emitted_field_is_declared` test in this file, which
    /// runs every collector over every fixture host and fails on a field no list names.
    ///
    /// There is deliberately no default implementation: a new collector that forgets this does not
    /// compile, rather than declaring an empty vocabulary that would reject every rule written for
    /// it.
    fn fields(&self) -> &'static [&'static str];
    /// Every reason this collector can give for not having looked, in a run or in `gaps`.
    ///
    /// This is what a rule's `unmeasured_when` may name, and `cargo xtask check-rules` rejects a
    /// rule that declares a reason its collector cannot produce (ADR 0027) — a declaration that can
    /// never come true, which since ADR 0027 also silently suppresses nothing. `collector_unavailable`
    /// is not listed by anyone: the engine produces it when no run for the collector exists at all.
    ///
    /// Like [`Collector::fields`] it is a declaration, bound to the code by the
    /// `every_reason_a_collector_reports_is_declared` test in this file rather than derived from it,
    /// and with the same limit: a reason no fixture host provokes cannot be proved reachable.
    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason];
    /// Looks at the host.
    fn collect(&self, host: &dyn Host) -> CollectorRun;
}

/// Every collector in this build.
pub fn all() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(bam::Bam),
        Box::new(evtx::Evtx::default()),
        Box::new(fivem_dir::FivemDir),
        Box::new(pca::Pca),
        Box::new(posture::Posture),
        Box::new(prefetch::Prefetch),
        Box::new(process::Process),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use rongroi_core::model::{CollectorRun, UnmeasuredReason};
    use rongroi_host::FixtureHost;

    use super::*;

    /// Every fixture host in the repository, in name order.
    fn fixture_hosts() -> Vec<(String, PathBuf)> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/hosts");
        let mut hosts: Vec<(String, PathBuf)> = std::fs::read_dir(&dir)
            .expect("fixtures/hosts is readable")
            .map(|entry| entry.expect("a readable directory entry"))
            .filter(|entry| entry.path().join("host.yaml").is_file())
            .map(|entry| {
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                )
            })
            .collect();
        hosts.sort();
        assert!(!hosts.is_empty(), "no fixture host was found");
        hosts
    }

    /// `Collector::fields` is a declaration, and `cargo xtask check-rules` rejects a rule that names
    /// a field outside it (ADR 0026). A declaration that has drifted from what `collect` emits turns
    /// that gate into a wrong answer in either direction — a real field rejected, or a renamed one
    /// still accepted — so the two are bound here rather than by review.
    ///
    /// This proves one half: no collector emits a field it did not declare. The other half — that a
    /// declared field is reachable at all — is what the fixture hosts cannot prove, since a name is
    /// only seen on a host that produces it; `fields_are_sorted_and_unique` is what keeps the lists
    /// readable, and ADR 0026 records the limit.
    #[test]
    fn every_emitted_field_is_declared() {
        for (name, dir) in fixture_hosts() {
            let host = FixtureHost::load(&dir).expect("a fixture host loads");
            for collector in all() {
                let declared: BTreeSet<&str> = collector.fields().iter().copied().collect();
                let CollectorRun::Measured { observations, .. } = collector.collect(&host) else {
                    continue;
                };
                for observation in &observations {
                    for field in observation.fields.keys() {
                        assert!(
                            declared.contains(field.as_str()),
                            "fixtures/hosts/{name}: collector `{}` emitted `{field}`, which `Collector::fields` does not declare",
                            collector.id()
                        );
                    }
                }
            }
        }
    }

    /// A gap names the field it is a gap in, so a `gaps` key outside the declared list is the same
    /// drift as an undeclared observation field: a rule matching that field would be `NotFound`
    /// where the collector meant `Unmeasured`.
    #[test]
    fn every_gap_key_is_a_declared_field() {
        for (name, dir) in fixture_hosts() {
            let host = FixtureHost::load(&dir).expect("a fixture host loads");
            for collector in all() {
                let declared: BTreeSet<&str> = collector.fields().iter().copied().collect();
                let CollectorRun::Measured { gaps, .. } = collector.collect(&host) else {
                    continue;
                };
                for field in gaps.keys() {
                    assert!(
                        declared.contains(field.as_str()),
                        "fixtures/hosts/{name}: collector `{}` gapped `{field}`, which `Collector::fields` does not declare",
                        collector.id()
                    );
                }
            }
        }
    }

    /// `Collector::unmeasured_reasons` is a declaration too, and since ADR 0027 it decides which
    /// `unmeasured_when` entries `check-rules` accepts. A collector that reports a reason it did
    /// not declare would have that reason rejected in every rule written for it, so the two are
    /// bound here the same way the field lists are.
    ///
    /// This proves one half — nothing reported is undeclared. The other half is what the fixture
    /// hosts cannot prove: a reason is only seen on a host that provokes it. ADR 0027 records it.
    #[test]
    fn every_reason_a_collector_reports_is_declared() {
        for (name, dir) in fixture_hosts() {
            let host = FixtureHost::load(&dir).expect("a fixture host loads");
            for collector in all() {
                let declared: BTreeSet<&str> = collector
                    .unmeasured_reasons()
                    .iter()
                    .map(|reason| reason.as_str())
                    .collect();
                let reported: Vec<UnmeasuredReason> = match collector.collect(&host) {
                    CollectorRun::Unmeasured { reason, .. } => vec![reason],
                    CollectorRun::Measured { gaps, .. } => gaps.values().copied().collect(),
                };
                for reason in reported {
                    assert!(
                        declared.contains(reason.as_str()),
                        "fixtures/hosts/{name}: collector `{}` reported `{}`, which `Collector::unmeasured_reasons` does not declare",
                        collector.id(),
                        reason.as_str()
                    );
                }
            }
        }
    }

    /// The lists are read by a person writing a rule and by `check-rules` when it names what a
    /// collector can emit, so an unsorted or duplicated entry is a defect in both.
    #[test]
    fn fields_are_sorted_and_unique() {
        for collector in all() {
            let declared = collector.fields();
            let mut sorted = declared.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted,
                declared.to_vec(),
                "collector `{}` declares fields that are unsorted or repeated",
                collector.id()
            );
        }
    }

    /// Two collectors sharing an id would make `collector:` in a rule ambiguous, and `check-rules`
    /// resolves a rule's collector by that id alone.
    #[test]
    fn collector_ids_are_unique() {
        let ids: BTreeSet<&str> = all().iter().map(|collector| collector.id()).collect();
        assert_eq!(ids.len(), all().len(), "two collectors share an id");
    }
}
