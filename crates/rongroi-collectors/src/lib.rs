// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Collectors read one kind of artifact from a [`Host`] and report what they saw.
//! Rules for writing one are in `crates/rongroi-collectors/AGENTS.md` and `CONVENTIONS.md` §3.

pub mod bam;
pub mod driver_service;
pub mod evtx;
pub mod failure;
pub mod fivem_dir;
pub mod paths;
pub mod pca;
pub mod posture;
pub mod prefetch;
pub mod process;
pub mod scan;
pub mod usn;

use rongroi_core::model::{CollectorRun, UnmeasuredReason};
use rongroi_host::Host;

/// What kind of value an observation field carries, so that `cargo xtask check-rules` can refuse an
/// operator the field cannot take (ADR 0029).
///
/// The engine never sees this: it dispatches on the JSON value it is handed, and the rules bundle
/// loads in a build whose collectors this declaration does not reach. It exists so that a rule
/// asking `name|gt: 3` is refused at review time rather than reported `not_found` for ever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// A string with no order of its own: a path, a file name, a channel, a status word.
    Text,
    /// A JSON number: a count, a size, an id.
    Number,
    /// A JSON boolean.
    Bool,
    /// A string holding one instant, written by `jiff::Timestamp::to_string` (RFC 3339, UTC).
    Timestamp,
}

impl FieldKind {
    /// Stable identifier used in the messages `check-rules` prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Number => "a number",
            Self::Bool => "a boolean",
            Self::Timestamp => "a timestamp",
        }
    }
}

/// One observation field a collector declares it can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// The field name a rule's `match` may use.
    pub name: &'static str,
    /// What kind of value it carries.
    pub kind: FieldKind,
}

impl Field {
    /// A field carrying text.
    pub const fn text(name: &'static str) -> Self {
        Self {
            name,
            kind: FieldKind::Text,
        }
    }

    /// A field carrying a number.
    pub const fn number(name: &'static str) -> Self {
        Self {
            name,
            kind: FieldKind::Number,
        }
    }

    /// A field carrying a boolean.
    pub const fn boolean(name: &'static str) -> Self {
        Self {
            name,
            kind: FieldKind::Bool,
        }
    }

    /// A field carrying one instant as RFC 3339 text.
    pub const fn timestamp(name: &'static str) -> Self {
        Self {
            name,
            kind: FieldKind::Timestamp,
        }
    }
}

/// Reads one kind of artifact. Implementations must be read-only and must never panic.
pub trait Collector {
    /// Stable id, equal to the `collector` field of the rules that read it.
    fn id(&self) -> &'static str;
    /// Every observation field this collector can emit, with the kind of value it carries, sorted
    /// by name.
    ///
    /// This is the vocabulary a rule's `match` may name, and `cargo xtask check-rules` rejects a
    /// rule that names anything outside it (ADR 0026). Since ADR 0029 each entry also carries a
    /// [`FieldKind`], and `check-rules` rejects an operator the kind cannot take — an ordinal
    /// comparison against a field that is only ever text, for one. It is a declaration rather than
    /// something derived from the code, so it can drift from what `collect` really puts in a field
    /// map; what holds the two together is `every_emitted_field_is_declared` and
    /// `every_emitted_value_has_its_declared_kind` in this file, which run every collector over
    /// every fixture host and fail on a field no list names or a value of the wrong shape.
    ///
    /// There is deliberately no default implementation: a new collector that forgets this does not
    /// compile, rather than declaring an empty vocabulary that would reject every rule written for
    /// it.
    fn fields(&self) -> &'static [Field];
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
    /// The **discriminator**: the field whose value says which of several places this collector reads
    /// an observation is about, when it reads more than one, or `None` (ADR 0044).
    ///
    /// Two things follow from declaring one. A place that could not be read is reported as
    /// `DiscriminatorGaps` for that value rather than as a gap for the whole run, so a rule whose
    /// `match` rules that place out keeps the answer the other places give it. And
    /// `cargo xtask check-baseline` does not count an observation that differs from a rule **only** in
    /// the discriminator as confronting that rule: it is about another place, so it was never asked
    /// the rule's question (ADR 0033, amended).
    ///
    /// The collector promises that every observation it emits carries the field. That promise is bound
    /// by `every_observation_carries_its_collectors_discriminator` in this file, and
    /// `discriminator_gaps_name_the_declared_discriminator` binds the gaps to the declaration.
    fn discriminator(&self) -> Option<&'static str> {
        None
    }
    /// The two timestamp fields that bound what this collector's source could see, when it has
    /// such a span, or `None` (ADR 0051).
    ///
    /// The timeline shows the span beside the times, because "nothing recorded here" can only be read
    /// inside it. `Coverage::place` narrows it to the one observation about the whole source, for a
    /// collector whose other observations carry the same two fields about something smaller.
    fn coverage(&self) -> Option<Coverage> {
        None
    }
    /// Looks at the host.
    fn collect(&self, host: &dyn Host) -> CollectorRun;
}

/// What [`Collector::coverage`] declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    /// The timestamp field holding the oldest time the source still holds.
    pub from: &'static str,
    /// The timestamp field holding the newest.
    pub to: &'static str,
    /// The discriminator value of the observation about the whole source, when there is one.
    pub place: Option<&'static str>,
}

/// Every collector in this build.
pub fn all() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(bam::Bam),
        Box::new(driver_service::DriverService::default()),
        Box::new(evtx::Evtx::default()),
        Box::new(fivem_dir::FivemDir),
        Box::new(pca::Pca),
        Box::new(posture::Posture),
        Box::new(prefetch::Prefetch),
        Box::new(process::Process),
        Box::new(usn::Usn::default()),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
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
                let declared: BTreeSet<&str> =
                    collector.fields().iter().map(|field| field.name).collect();
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

    /// A declared [`FieldKind`] is what `check-rules` refuses an operator against, so a kind that
    /// does not match the value a collector really emits would refuse a correct rule, or — worse —
    /// accept `oldest_record_time|gt:` against a field that turns out to hold a count.
    ///
    /// This proves the same half `every_emitted_field_is_declared` proves, and has the same limit: a
    /// field no fixture host produces is not checked here. `Timestamp` is checked as far as it can
    /// be from this side — the value is a string that `rongroi_core::rules::is_rfc3339` accepts,
    /// which is the same function the engine's ordinal comparison parses with.
    #[test]
    fn every_emitted_value_has_its_declared_kind() {
        for (name, dir) in fixture_hosts() {
            let host = FixtureHost::load(&dir).expect("a fixture host loads");
            for collector in all() {
                let declared: BTreeMap<&str, FieldKind> = collector
                    .fields()
                    .iter()
                    .map(|field| (field.name, field.kind))
                    .collect();
                let CollectorRun::Measured { observations, .. } = collector.collect(&host) else {
                    continue;
                };
                for observation in &observations {
                    for (field, value) in &observation.fields {
                        let Some(kind) = declared.get(field.as_str()) else {
                            continue; // `every_emitted_field_is_declared` is what reports this one.
                        };
                        let ok = match kind {
                            FieldKind::Text => value.is_string(),
                            FieldKind::Number => value.is_number(),
                            FieldKind::Bool => value.is_boolean(),
                            // The engine's own test for one, so the kind is bound to what
                            // `<field>|gt:` will actually be able to put in order (ADR 0029).
                            FieldKind::Timestamp => {
                                value.as_str().is_some_and(rongroi_core::rules::is_rfc3339)
                            }
                        };
                        assert!(
                            ok,
                            "fixtures/hosts/{name}: collector `{}` emitted `{field}` as {value}, which is not {}",
                            collector.id(),
                            kind.as_str()
                        );
                    }
                }
            }
        }
    }

    /// A declared span names two fields the collector declares as timestamps, and a place only for a
    /// collector with a discriminator (ADR 0051).
    #[test]
    fn a_declared_coverage_names_declared_timestamps() {
        let mut declared = 0;
        for collector in all() {
            let Some(coverage) = collector.coverage() else {
                continue;
            };
            declared += 1;
            for name in [coverage.from, coverage.to] {
                assert!(
                    collector
                        .fields()
                        .iter()
                        .any(|field| field.name == name && field.kind == FieldKind::Timestamp),
                    "collector `{}` declares coverage by `{name}`, which is not one of its timestamp fields",
                    collector.id()
                );
            }
            assert!(
                coverage.place.is_none() || collector.discriminator().is_some(),
                "collector `{}` scopes its coverage to a place without a discriminator",
                collector.id()
            );
        }
        assert_eq!(declared, 2, "evtx and usn declare a span");
    }

    /// A gap names the field it is a gap in, so a `gaps` key outside the declared list is the same
    /// drift as an undeclared observation field: a rule matching that field would be `NotFound`
    /// where the collector meant `Unmeasured`.
    #[test]
    fn every_gap_key_is_a_declared_field() {
        for (name, dir) in fixture_hosts() {
            let host = FixtureHost::load(&dir).expect("a fixture host loads");
            for collector in all() {
                let declared: BTreeSet<&str> =
                    collector.fields().iter().map(|field| field.name).collect();
                let CollectorRun::Measured {
                    gaps,
                    discriminator_gaps,
                    ..
                } = collector.collect(&host)
                else {
                    continue;
                };
                let every_gap = gaps.keys().chain(
                    discriminator_gaps
                        .iter()
                        .flat_map(|place| place.gaps.keys()),
                );
                for field in every_gap {
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
                    CollectorRun::Measured {
                        gaps,
                        discriminator_gaps,
                        ..
                    } => gaps
                        .values()
                        .chain(
                            discriminator_gaps
                                .iter()
                                .flat_map(|place| place.gaps.values()),
                        )
                        .copied()
                        .collect(),
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

    /// `DiscriminatorGaps` reach a rule through the value of one field, and stop an observation from
    /// satisfying `exists: false` only when it carries that value. An observation about an unreadable
    /// place that did **not** carry the field would slip past both, and a rule asking for an absent
    /// field would be `found` about a place nobody read — the collapse ADR 0029 exists to prevent. So
    /// every observation of a collector that declares a discriminator carries it (ADR 0044).
    #[test]
    fn every_observation_carries_its_collectors_discriminator() {
        let mut seen = 0;
        for (name, dir) in fixture_hosts() {
            let host = FixtureHost::load(&dir).expect("a fixture host loads");
            for collector in all() {
                let Some(discriminator) = collector.discriminator() else {
                    continue;
                };
                let CollectorRun::Measured { observations, .. } = collector.collect(&host) else {
                    continue;
                };
                for observation in &observations {
                    seen += 1;
                    assert!(
                        observation
                            .fields
                            .get(discriminator)
                            .is_some_and(serde_json::Value::is_string),
                        "fixtures/hosts/{name}: collector `{}` emitted an observation without its discriminator `{discriminator}`: {observation:?}",
                        collector.id()
                    );
                }
            }
        }
        assert!(seen > 0, "no fixture host produced an observation to check");
    }

    /// A place's gaps name the field the collector declared as its discriminator, that field is one it
    /// declares it can emit, and a collector without one reports none: otherwise the engine would be
    /// scoping gaps by a field no rule author was told about (ADR 0044). At least one fixture host has
    /// to produce such gaps, or this test proves nothing.
    #[test]
    fn discriminator_gaps_name_the_declared_discriminator() {
        let mut seen = 0;
        for (name, dir) in fixture_hosts() {
            let host = FixtureHost::load(&dir).expect("a fixture host loads");
            for collector in all() {
                if let Some(discriminator) = collector.discriminator() {
                    assert!(
                        collector
                            .fields()
                            .iter()
                            .any(|field| field.name == discriminator),
                        "collector `{}` declares `{discriminator}` as its discriminator and not as a field",
                        collector.id()
                    );
                }
                let CollectorRun::Measured {
                    discriminator_gaps, ..
                } = collector.collect(&host)
                else {
                    continue;
                };
                for place in &discriminator_gaps {
                    seen += 1;
                    assert_eq!(
                        Some(place.discriminator.as_str()),
                        collector.discriminator(),
                        "fixtures/hosts/{name}: collector `{}`",
                        collector.id()
                    );
                }
            }
        }
        assert!(seen > 0, "no fixture host produced discriminator gaps");
    }

    /// The lists are read by a person writing a rule and by `check-rules` when it names what a
    /// collector can emit, so an unsorted or duplicated entry is a defect in both.
    #[test]
    fn fields_are_sorted_and_unique() {
        for collector in all() {
            let declared: Vec<&str> = collector.fields().iter().map(|field| field.name).collect();
            let mut sorted = declared.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted,
                declared,
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
