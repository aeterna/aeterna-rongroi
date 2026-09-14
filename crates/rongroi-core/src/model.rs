// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Data model shared by collectors, the engine, the CLI and the desktop app.
//! Names follow the glossary in `CONVENTIONS.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bundle::BundleInfo;
use crate::provenance::Provenance;

/// Version of the report JSON format. A breaking change is a major application release.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// One typed fact a collector saw on the host, for example `{"secure_boot": "disabled"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Id of the collector that produced this observation.
    pub collector: String,
    /// Field values. Rules match on these keys.
    pub fields: BTreeMap<String, serde_json::Value>,
}

/// Why a collector, or one field of it, could not look.
///
/// Twelve reasons, and the split between them is the whole of how this program distinguishes "we
/// checked and there was nothing" from "we could not check". Four of them — [`Self::NotOnThisOs`],
/// [`Self::ServiceDisabled`], [`Self::SourceAbsent`] and [`Self::SourceEmpty`] — describe a machine
/// that is behaving exactly as Windows ships it, and ADR 0030 records, for each one, the ordinary
/// condition that produces it and how common that condition is. A reason that fires on an ordinary
/// machine is worse than no reason at all, so none of them may be read as a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmeasuredReason {
    /// The scan is not running on Windows.
    NotWindows,
    /// This Windows version does not keep the artifact at all.
    ///
    /// A fact about the operating system rather than about the machine's history: PCA's files
    /// arrived in Windows 11 22H2, so on anything older their absence carries no information
    /// (ADR 0020, ADR 0030).
    NotOnThisOs,
    /// Reading the artifact needs administrator rights.
    NotAdmin,
    /// The collector did not look, so nothing was attempted.
    ///
    /// Distinct from every reason that describes a failed attempt: OVAL calls it `not collected`,
    /// "no attempt was made to collect items on the system". A log after a budget has already been
    /// spent was never opened, and reporting that as a failed read would name a failure that did not
    /// happen (ADR 0030).
    NotAttempted,
    /// Windows denied access to the artifact.
    AccessDenied,
    /// The Windows service that writes the artifact is switched off.
    ///
    /// Not "somebody removed the record": a machine whose `EnablePrefetcher` is `0` or `2` is one
    /// where Windows never wrote an application-launch record to remove (ADR 0030).
    ServiceDisabled,
    /// The place the artifact is kept is not on this machine.
    ///
    /// Split from [`Self::SourceEmpty`] because the two mean opposite things and one word for both
    /// was the coarsest part of this vocabulary. OVAL's `does not exist` requires that "the
    /// underlying structure is installed on the system" before an absence is a meaningful answer;
    /// this is the case where it is not (ADR 0030).
    SourceAbsent,
    /// The place the artifact is kept is on this machine and holds nothing.
    ///
    /// The state an artifact reaches when it reads perfectly and says nothing, which is the hole no
    /// error anywhere reveals. It is **not** evidence that anything was removed: Windows itself
    /// empties BAM of entries older than seven days at every boot (ADR 0030).
    SourceEmpty,
    /// Part of the artifact was read and part of it was not.
    ///
    /// OVAL's `incomplete`: "only some of the matching items have been identified". Before ADR 0030
    /// a partly-read Prefetch folder produced `not_found` — "the collector looked and nothing
    /// matched" — for a folder whose missing half was never read.
    Partial,
    /// A wall-clock or record budget ended the read.
    ///
    /// This program's own limit, not the machine's, so the report names the limit rather than
    /// blaming the artifact (ADR 0024, ADR 0030).
    BudgetSpent,
    /// The artifact exists but could not be read or understood.
    ReadFailed,
    /// No collector for this rule is available in this build.
    CollectorUnavailable,
}

impl UnmeasuredReason {
    /// Stable identifier used in JSON and translation keys.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotWindows => "not_windows",
            Self::NotOnThisOs => "not_on_this_os",
            Self::NotAdmin => "not_admin",
            Self::NotAttempted => "not_attempted",
            Self::AccessDenied => "access_denied",
            Self::ServiceDisabled => "service_disabled",
            Self::SourceAbsent => "source_absent",
            Self::SourceEmpty => "source_empty",
            Self::Partial => "partial",
            Self::BudgetSpent => "budget_spent",
            Self::ReadFailed => "read_failed",
            Self::CollectorUnavailable => "collector_unavailable",
        }
    }

    /// Whether this reason is one fact about the **scan** rather than one about the machine.
    ///
    /// Such a reason applies to every rule it stopped at once, so a view states it once above the
    /// evidence instead of repeating it as a row per rule: N red-looking lines carrying one fact is
    /// the shape that teaches a reviewer to stop reading (ADR 0027, ADR 0030).
    pub fn is_scope_statement(self) -> bool {
        matches!(self, Self::NotAdmin | Self::NotAttempted)
    }

    /// Whether a view must list this reason even when the rule declared it in `unmeasured_when`.
    ///
    /// All three say that the artifact was reachable and that the read of it did not finish:
    /// [`Self::Partial`] because some of it did not yield a record, [`Self::BudgetSpent`] because a
    /// limit **this program chose** ended the read, [`Self::ReadFailed`] because what was there could
    /// not be read or understood. A rule author cannot declare any of them away, because none is a
    /// fact about the machine for them to have anticipated: an ordinary Windows PC has a readable
    /// `SecureBoot` key, so a rule saying it expects that key to be unreadable is not describing a
    /// kind of machine, it is describing a fault — and a fault is what a reviewer needs as a row
    /// (ADR 0030, ADR 0027).
    ///
    /// `check-rules` refuses to load a rule that names one of these in `unmeasured_when`, so the
    /// declaration cannot rot back in. This is the answer for bundles that gate does not see.
    pub fn is_always_listed(self) -> bool {
        matches!(self, Self::Partial | Self::BudgetSpent | Self::ReadFailed)
    }
}

/// Result of running one collector against a host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CollectorRun {
    /// The collector looked. Fields it could not read are listed in `gaps`.
    Measured {
        /// Collector id.
        collector: String,
        /// What the collector saw.
        observations: Vec<Observation>,
        /// Fields the collector could not read, with the reason, for every observation of the run.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        gaps: BTreeMap<String, UnmeasuredReason>,
        /// Fields the collector could not read for **one value of its discriminator** only — one of
        /// the several places it reads — while the others were read (ADR 0044). Empty for a
        /// collector that declares no discriminator.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        discriminator_gaps: Vec<DiscriminatorGaps>,
    },
    /// The collector could not look at all.
    Unmeasured {
        /// Collector id.
        collector: String,
        /// Why it could not look.
        reason: UnmeasuredReason,
    },
}

/// Gaps confined to the observations whose **discriminator** carries one value (ADR 0044).
///
/// A discriminator is the field a collector uses to say which of the things it reads an observation is
/// about: `fivem_dir`'s `location`. When one of those things could not be read and the others were,
/// a run-wide gap would make every rule on the collector `unmeasured`, including rules that can only
/// ever match an observation from a place that was read. These gaps reach a rule only when the rule's
/// `match` could be satisfied by an observation carrying `value`, and they stop an observation carrying
/// `value` from satisfying `<field>|exists: false` for a field listed here.
///
/// The collector promises that **every** observation it emits about that place carries
/// `discriminator: value`. The engine cannot check that promise; `rongroi-collectors` binds it with a
/// test over every fixture host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscriminatorGaps {
    /// The observation field that says which place an observation is about.
    pub discriminator: String,
    /// The value that field carries on every observation about the place that could not be read.
    pub value: serde_json::Value,
    /// Fields that could not be read there, with the reason.
    pub gaps: BTreeMap<String, UnmeasuredReason>,
}

impl DiscriminatorGaps {
    /// Whether `observation` is about the place these gaps describe.
    ///
    /// Compared exactly, not with a rule's ASCII fold: both sides are written by the same collector,
    /// and a value it spells two ways is a defect in the collector rather than something to hide.
    pub fn describes(&self, observation: &Observation) -> bool {
        observation.fields.get(&self.discriminator) == Some(&self.value)
    }
}

impl CollectorRun {
    /// Id of the collector this run belongs to.
    pub fn collector(&self) -> &str {
        match self {
            Self::Measured { collector, .. } | Self::Unmeasured { collector, .. } => collector,
        }
    }
}

/// What a piece of evidence can show. There is deliberately no "level" or score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// A program ran.
    Execution,
    /// A file or program existed; it does not show that it ran.
    Presence,
    /// Traces were removed or altered.
    Tamper,
    /// A machine setting that makes cheating easier.
    Posture,
    /// Background information for the reviewer.
    Context,
}

impl Strength {
    /// Stable identifier used in JSON and translation keys.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Presence => "presence",
            Self::Tamper => "tamper",
            Self::Posture => "posture",
            Self::Context => "context",
        }
    }
}

/// Who is looking at the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The player checking their own PC: everything is shown.
    #[serde(rename = "self")]
    SelfCheck,
    /// Screenshare with staff: consent first, only matches, redacted paths.
    Ss,
}

/// The result of one rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EvidenceState {
    /// The rule matched; the matching observations are attached.
    Found {
        /// Observations that matched the rule.
        observations: Vec<Observation>,
    },
    /// The collector looked and nothing matched.
    NotFound {
        /// How far back the source can see, in words for the user.
        retention: String,
    },
    /// The collector could not look.
    Unmeasured {
        /// Why it could not look.
        reason: UnmeasuredReason,
        /// Whether the rule named this reason in its `unmeasured_when`.
        ///
        /// A rule author who writes "PCA does not exist on Windows 10" into the rule has said that
        /// this outcome carries no information on such a machine; a reason they did not name means
        /// something they did not anticipate stopped the measurement, which is the only unmeasured
        /// result worth listing to a reviewer (ADR 0027).
        ///
        /// Additive like `own_traces` and `unmatched`, and [`REPORT_SCHEMA_VERSION`] stays at 1: a
        /// report written before the field existed reads back `false`, which lists it — the same
        /// behaviour that report had.
        #[serde(default)]
        expected: bool,
    },
}

/// Evidence for one rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Id of the rule (`UUIDv4`).
    pub rule_id: String,
    /// Collector the rule reads.
    pub collector: String,
    /// What this evidence can show.
    pub strength: Strength,
    /// Found, `NotFound` or Unmeasured.
    #[serde(flatten)]
    pub state: EvidenceState,
}

/// When the running Windows kernel started counting, for reading the times in a report against it
/// (ADR 0039).
///
/// Context, never evidence: no rule reads it and nothing is concluded from it. It is not when a person
/// last turned the PC on — a "Shut down" with Fast Startup, which is Windows' default, hibernates the
/// kernel rather than ending it, and sleep and hibernation do not start the count again — so a start
/// days before the scan is the ordinary state of a PC that is shut down every night.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BootTime {
    /// Windows answered.
    Measured {
        /// The scan's own clock minus the time since the start, UTC, RFC 3339, to the second.
        ///
        /// Expressed on the clock the scan read, so a clock that was changed after the start moves
        /// this value and not [`BootTime::Measured::seconds_since_boot`]; a record written before such
        /// a change carries a time on the old clock.
        booted_at: String,
        /// Whole seconds Windows counted between its start and the scan, sleep and hibernation
        /// included. What was measured; `booted_at` is derived from it.
        seconds_since_boot: u64,
    },
    /// Windows was not asked or did not answer. Never a guessed time.
    Unmeasured {
        /// Why there is no value.
        reason: UnmeasuredReason,
    },
}

impl Default for BootTime {
    /// What a report written before this field existed reads back as: nothing was tried, which is
    /// what that report did (ADR 0030, ADR 0039).
    fn default() -> Self {
        Self::Unmeasured {
            reason: UnmeasuredReason::NotAttempted,
        }
    }
}

impl BootTime {
    /// The start `since_boot` before `generated_at`, the scan's own RFC 3339 time.
    ///
    /// A `generated_at` that does not parse, or a count that reaches back before the clock can go, is
    /// `read_failed` rather than a time this program made up.
    pub fn from_elapsed(generated_at: &str, since_boot: std::time::Duration) -> Self {
        let read_failed = Self::Unmeasured {
            reason: UnmeasuredReason::ReadFailed,
        };
        let Ok(now) = generated_at.parse::<jiff::Timestamp>() else {
            return read_failed;
        };
        let seconds = since_boot.as_secs();
        let Ok(signed) = i64::try_from(seconds) else {
            return read_failed;
        };
        // Truncated to the second on both sides: `GetTickCount64` moves in steps of 10 to 16 ms, and
        // a fraction of a second here would claim a precision the reading does not have.
        let Ok(now) = jiff::Timestamp::from_second(now.as_second()) else {
            return read_failed;
        };
        let Ok(booted_at) = now.checked_sub(jiff::SignedDuration::from_secs(signed)) else {
            return read_failed;
        };
        Self::Measured {
            booted_at: booted_at.to_string(),
            seconds_since_boot: seconds,
        }
    }
}

/// Facts about the scan itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportHeader {
    /// Report format version, see [`REPORT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Who built this binary and from what.
    pub provenance: Provenance,
    /// The embedded rules bundle.
    pub rules_bundle: BundleInfo,
    /// `windows` or `other`.
    pub platform: String,
    /// Windows build number, when known.
    pub os_build: Option<String>,
    /// Whether the scan ran with administrator rights, when known.
    pub elevated: Option<bool>,
    /// When the scan ran, UTC, RFC 3339.
    pub generated_at: String,
    /// When the running Windows kernel started counting (ADR 0039). Additive, and
    /// [`REPORT_SCHEMA_VERSION`] stays at 1: a report written before it existed reads back
    /// `unmeasured` / `not_attempted`.
    #[serde(default)]
    pub boot_time: BootTime,
}

/// One observation that describes aeterna-rongroi itself rather than the machine it scanned.
///
/// The program's own process is running while it scans, so a collector that enumerates the machine
/// sees it. Keeping it in its own bucket shows the reader what the tool did without presenting it as
/// evidence about the PC; dropping it silently would hide that (ADR 0010).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnTraceEntry {
    /// Id of the collector that saw it.
    pub collector: String,
    /// The observation, as that collector reported it.
    pub observation: Observation,
}

/// Observations of one collector that no rule matched.
///
/// A collector reads the machine whether or not a rule asks about what it finds, and an observation
/// reaches [`Evidence`] only inside [`EvidenceState::Found`]. Without this bucket, everything a
/// collector saw that no rule matched would be read and then discarded (ADR 0014).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnmatchedGroup {
    /// Id of the collector that saw them.
    pub collector: String,
    /// The observations, as that collector reported them.
    pub observations: Vec<Observation>,
}

/// A full scan result, before a view decides what to show.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Facts about the scan.
    pub header: ReportHeader,
    /// One entry per active rule.
    pub evidence: Vec<Evidence>,
    /// What this program itself left in what the collectors saw. Added to the format without a
    /// [`REPORT_SCHEMA_VERSION`] change: a report written before it existed reads back with none.
    #[serde(default)]
    pub own_traces: Vec<OwnTraceEntry>,
    /// Unmatched observations: what the collectors saw that no rule matched, grouped by collector.
    /// Additive like `own_traces`, and for the same reason: a report written before it existed
    /// reads back with none, which is what it meant (ADR 0014).
    #[serde(default)]
    pub unmatched: Vec<UnmatchedGroup>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// One day, two hours, three minutes and four seconds before the scan, and the fraction of a
    /// second on each side dropped rather than rounded into a precision the counter does not have.
    #[test]
    fn the_boot_time_is_the_scan_time_minus_the_count() {
        assert_eq!(
            BootTime::from_elapsed("2026-01-01T00:00:00Z", Duration::from_millis(93_784_999)),
            BootTime::Measured {
                booted_at: "2025-12-30T21:56:56Z".to_owned(),
                seconds_since_boot: 93_784,
            }
        );
        assert_eq!(
            BootTime::from_elapsed("2026-09-13T10:27:03.3128928Z", Duration::from_secs(32_571)),
            BootTime::Measured {
                booted_at: "2026-09-13T01:24:12Z".to_owned(),
                seconds_since_boot: 32_571,
            }
        );
    }

    /// A machine that has only just started is an answer, not a missing value.
    #[test]
    fn zero_seconds_since_boot_is_the_scan_time_itself() {
        assert_eq!(
            BootTime::from_elapsed("2026-01-01T00:00:00Z", Duration::ZERO),
            BootTime::Measured {
                booted_at: "2026-01-01T00:00:00Z".to_owned(),
                seconds_since_boot: 0,
            }
        );
    }

    /// Neither case can come from a real scan; both would otherwise need a time to be invented.
    #[test]
    fn a_time_that_cannot_be_computed_is_read_failed_not_a_guess() {
        let read_failed = BootTime::Unmeasured {
            reason: UnmeasuredReason::ReadFailed,
        };
        assert_eq!(
            BootTime::from_elapsed("not a time", Duration::from_secs(1)),
            read_failed
        );
        assert_eq!(
            BootTime::from_elapsed("2026-01-01T00:00:00Z", Duration::from_secs(u64::MAX)),
            read_failed
        );
        assert_eq!(
            BootTime::from_elapsed(
                "2026-01-01T00:00:00Z",
                Duration::from_hours(1_000_000 * 365 * 24)
            ),
            read_failed
        );
    }

    /// The header shape both front ends read, and the shape a report from before ADR 0039 reads
    /// back as.
    #[test]
    fn the_boot_time_serialises_as_a_tagged_state() {
        let measured = BootTime::from_elapsed("2026-01-01T00:00:00Z", Duration::from_secs(60));
        assert_eq!(
            serde_json::to_value(&measured).unwrap(),
            serde_json::json!({
                "state": "measured",
                "booted_at": "2025-12-31T23:59:00Z",
                "seconds_since_boot": 60
            })
        );
        let unmeasured = BootTime::Unmeasured {
            reason: UnmeasuredReason::NotWindows,
        };
        assert_eq!(
            serde_json::to_value(&unmeasured).unwrap(),
            serde_json::json!({ "state": "unmeasured", "reason": "not_windows" })
        );
        assert_eq!(
            BootTime::default(),
            BootTime::Unmeasured {
                reason: UnmeasuredReason::NotAttempted
            }
        );
    }
}
