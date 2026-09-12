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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmeasuredReason {
    /// The scan is not running on Windows.
    NotWindows,
    /// The artifact does not exist on this Windows version.
    NotOnThisOs,
    /// Reading the artifact needs administrator rights.
    NotAdmin,
    /// Windows denied access to the artifact.
    AccessDenied,
    /// The Windows service that produces the artifact is disabled.
    ServiceDisabled,
    /// The artifact is not present or not reported on this machine.
    SourceMissing,
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
            Self::AccessDenied => "access_denied",
            Self::ServiceDisabled => "service_disabled",
            Self::SourceMissing => "source_missing",
            Self::ReadFailed => "read_failed",
            Self::CollectorUnavailable => "collector_unavailable",
        }
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
        /// Fields the collector could not read, with the reason.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        gaps: BTreeMap<String, UnmeasuredReason>,
    },
    /// The collector could not look at all.
    Unmeasured {
        /// Collector id.
        collector: String,
        /// Why it could not look.
        reason: UnmeasuredReason,
    },
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
