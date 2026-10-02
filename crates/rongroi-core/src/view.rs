// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a Self or SS view may show. Privacy is decided here, not in the UI (AGENTS.md hard rule 5).

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

mod session;

pub use session::{
    AnchorName, Comparison, Duration, DurationUnit, IndexBeside, LineState, Relation, SessionEnd,
    SessionLine, SessionStart, SessionState, SessionStatement,
};

use crate::model::{
    AgeCount, AgeRows, AnchorState, BootTime, Evidence, EvidenceState, Mode, Observation,
    OwnTraceEntry, Report, ReportHeader, SensitiveKind, Strength, UnmatchedGroup, UnmeasuredReason,
    UnmeasuredSource,
};

/// The order collectors are shown in, by both front ends: the rows of one collector together, and
/// entries of the timeline that carry the same time (ADR 0045, ADR 0051). A collector not named here
/// follows the named ones.
pub const COLLECTOR_ORDER: [&str; 13] = [
    "posture",
    "driver_service",
    "autostart",
    "defender_exclusion",
    "fivem_dir",
    "fivem_servers",
    "net_config",
    "process",
    "evtx",
    "prefetch",
    "bam",
    "pca",
    "usn",
];

/// Observation fields SS mode never shows, by collector, even on a match (ADR 0054, ADR 0060).
///
/// A hosts line's address can name the player's own server; its kind, which `net_config` emits
/// beside it as `address_kind`, is what separates a blocklist from a redirect and is what SS mode
/// shows in its place (ADR 0054, owner decision 2). A scheduled task's path can carry an account SID,
/// and a `Run` value's name is whatever the program chose, so `autostart`'s `entry` is withheld; the
/// file it starts, its `path`, is shown and redacted like every path (ADR 0060, owner decision 3).
pub const SS_WITHHELD_FIELDS: [(&str, &str); 2] =
    [("net_config", "address"), ("autostart", "entry")];

/// What SS mode shows in place of a server identity the player did not agree to show (ADR 0052).
pub const SERVER_IDENTITY_PLACEHOLDER: &str = "%SERVER_IDENTITY%";
/// What SS mode shows in place of an account identifier the player did not agree to show (ADR 0052).
pub const ACCOUNT_IDENTIFIER_PLACEHOLDER: &str = "%ACCOUNT_IDENTIFIER%";

/// The placeholder for one kind of sensitive value.
pub fn placeholder(kind: SensitiveKind) -> &'static str {
    match kind {
        SensitiveKind::ServerIdentity => SERVER_IDENTITY_PLACEHOLDER,
        SensitiveKind::AccountIdentifier => ACCOUNT_IDENTIFIER_PLACEHOLDER,
    }
}

/// What the player agreed SS mode may show beyond its default, each answered on its own, default
/// no (ADR 0052). Self mode ignores it: it shows everything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsOptions {
    /// Show server identities: an endpoint, a server cache folder's name.
    #[serde(default)]
    pub server_identity: bool,
    /// Show account identifiers.
    #[serde(default)]
    pub account_identifier: bool,
}

impl SsOptions {
    /// Whether values of `kind` are shown.
    pub fn shows(self, kind: SensitiveKind) -> bool {
        match kind {
            SensitiveKind::ServerIdentity => self.server_identity,
            SensitiveKind::AccountIdentifier => self.account_identifier,
        }
    }
}

/// Replacement for the user-profile part of a path in SS mode.
pub const USERPROFILE_PLACEHOLDER: &str = "%USERPROFILE%";

/// Counts of evidence an SS view does not list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenCounts {
    /// Rules that looked and found nothing.
    pub not_found: usize,
    /// Rules that could not look for a reason the rule itself named in `unmeasured_when`.
    ///
    /// Split from the unexpected ones because one integer mixing "this version of Windows keeps no
    /// such record" with "the folder would not open" says nothing a reader can use (ADR 0027).
    pub unmeasured_expected: usize,
    /// Rules that could not look for a reason the rule did not name. SS mode lists such a result,
    /// so the only ones counted here are the `not_admin` results the scope statement carries.
    pub unmeasured_unexpected: usize,
    /// Unmatched observations. SS mode counts them instead of listing them (ADR 0014).
    pub unmatched: usize,
}

/// Facts about the scan as a whole, stated once above the evidence rather than on every rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeNotes {
    /// How many rules were unmeasured because the scan did not have administrator rights.
    ///
    /// It is one fact about the scan and it applies to every rule at once, so repeating it per rule
    /// would show a reviewer N red-looking lines that all say the same thing. It is also the one
    /// unmeasured reason with a remedy: it is what makes the restart-as-administrator offer worth
    /// taking (ADR 0012, ADR 0027).
    ///
    /// This is not a hidden count and must not be added to them: in SS mode the same rules are
    /// counted in [`HiddenCounts::unmeasured_expected`] or [`HiddenCounts::unmeasured_unexpected`],
    /// which together account for every unlisted result. Self mode lists all of them and carries
    /// this number as well.
    pub not_admin: usize,
    /// How many rules were unmeasured because the collector never looked at their source.
    ///
    /// The same shape as [`Self::not_admin`] and here for the same reason: a source this program
    /// stopped short of is one fact about how far the scan got, not N facts about the PC. Additive
    /// to the view, and [`crate::model::REPORT_SCHEMA_VERSION`] stays at 1 (ADR 0030).
    #[serde(default)]
    pub not_attempted: usize,
    /// How many rules were unmeasured because their collector reads only in a full scan and the
    /// player chose the standard one (ADR 0052). One fact about the scan, like the two above.
    #[serde(default)]
    pub not_consented: usize,
}

/// How many pieces of the evidence a view lists are in each state (ADR 0045).
///
/// Three counts of states, never added into one number: each still needs its rows read, which is
/// what separates them from the pass/fail total ADR 0002 rules out. SS mode counts what its view
/// lists here and everything else in [`HiddenCounts`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedCounts {
    /// Listed evidence whose rule matched.
    pub found: usize,
    /// Listed evidence that looked and found nothing.
    pub not_found: usize,
    /// Listed evidence that could not look, for any reason.
    pub unmeasured: usize,
}

fn listed_counts(evidence: &[Evidence]) -> ListedCounts {
    let mut counts = ListedCounts::default();
    for item in evidence {
        match item.state {
            EvidenceState::Found { .. } => counts.found += 1,
            EvidenceState::NotFound { .. } => counts.not_found += 1,
            EvidenceState::Unmeasured { .. } => counts.unmeasured += 1,
        }
    }
    counts
}

/// A report as one audience may see it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportView {
    /// Audience.
    pub mode: Mode,
    /// Facts about the scan.
    pub header: ReportHeader,
    /// Evidence this view shows.
    pub evidence: Vec<Evidence>,
    /// What this program itself left in what the collectors saw. Shown in both modes: hiding "this
    /// was us" from the person watching a screenshare would be less transparent, not more (ADR 0010).
    pub own_traces: Vec<OwnTraceEntry>,
    /// What the collectors saw that no rule matched. Self mode lists it; SS mode leaves it empty
    /// and counts it in `hidden.unmatched` (ADR 0014).
    pub unmatched: Vec<UnmatchedGroup>,
    /// Facts about the scan itself, above the evidence in both modes.
    #[serde(default)]
    pub scope: ScopeNotes,
    /// How many of `evidence` are in each state (ADR 0045). Additive; the report schema stays at 1.
    #[serde(default)]
    pub listed: ListedCounts,
    /// What this view does not list.
    pub hidden: HiddenCounts,
    /// The times this view may show, in order (ADR 0051). Additive; the report schema stays at 1.
    #[serde(default)]
    pub timeline: Timeline,
    /// [`COLLECTOR_ORDER`], so the desktop groups rows in the order the core orders the timeline.
    #[serde(default)]
    pub collector_order: Vec<String>,
    /// The span each listed `found` or `not_found` row's count is for, by rule id: the coverage band
    /// of the place its collector's coverage names — for `usn`, the journal (ADR 0047, amendment of
    /// 2026-09-30, decision 3). Built here so the CLI and the desktop cannot disagree, in both modes.
    /// Additive; the report schema stays at 1.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub row_bands: BTreeMap<String, RowBand>,
    /// How far back each source reaches on this PC, beside when parts of it were set up (ADR 0061).
    /// The same in both modes: a trace age names no program and no file. Additive; the report schema
    /// stays at 1.
    #[serde(default)]
    pub trace_ages: TraceAges,
    /// `FiveM`'s side beside Windows' records of programs that ran, when the readable sources reach
    /// back to `FiveM`'s last write (ADR 0061), at most one; then each edition's last session beside its
    /// own folders (ADR 0062), at most one per edition. Not evidence and never counted. Additive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_source: Vec<CrossSourceStatement>,
}

/// The span one row's count is for (ADR 0047, amendment of 2026-09-30, decision 3).
///
/// A count the change journal gives is a count for the span it still held when the scan read it — on
/// one Windows 11 PC, 39 minutes — and nothing older. Shown without that span, "nothing deleted" reads
/// as "nothing was ever deleted". A `found` row carries it beside its own place's first and last time,
/// which are that place's records and not the span; a `not_found` row carries it as "nothing within
/// this span". An `unmeasured` row has none: when the read did not finish the span is not what the
/// counts cover, and when it never started there is none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RowBand {
    /// The oldest and newest record the source held.
    Span {
        /// The oldest time the source holds.
        from: String,
        /// The newest.
        to: String,
    },
    /// The source was read and held no record, so there is no span, rather than a missing one.
    NoSpan,
}

/// Where a timeline entry came from (ADR 0051).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntrySource {
    /// The scan's own time: when it ran, or when Windows last started (ADR 0039).
    Anchor,
    /// An observation a rule matched, listed as that rule's evidence.
    Evidence {
        /// The rule.
        rule_id: String,
    },
    /// An observation a timeline selector selected.
    Selector {
        /// The timeline selector, for its text and ordinary causes.
        selector_id: String,
    },
    /// An unmatched observation. Self mode only.
    Observation,
}

/// One time value on the timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// The time, as the report holds it: RFC 3339, UTC.
    pub at: String,
    /// The collector that recorded it; `None` for an anchor.
    pub collector: Option<String>,
    /// The field that holds it, or `generated_at` / `boot_time` for an anchor.
    pub field: String,
    /// The value of the collector's discriminator on the observation, when it declares one.
    pub place: Option<String>,
    /// Where it came from.
    pub source: EntrySource,
    /// The observation's `name`, or its `path` when it has no name, redacted as its row is.
    pub subject: Option<String>,
}

/// The span one source could see, from its oldest to its newest record (ADR 0051).
///
/// "Nothing in this span" can be read only inside a band. Outside it the source saw nothing at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageBand {
    /// The collector.
    pub collector: String,
    /// The discriminator value of the observation, when the collector declares one.
    pub place: Option<String>,
    /// The observation's `name` or `path`, redacted as a row is.
    pub subject: Option<String>,
    /// The oldest time the source holds.
    pub from: String,
    /// The newest.
    pub to: String,
}

/// The times a report holds, in order, with the spans that bound them (ADR 0051).
///
/// Nothing here is computed from the entries: no gap, no count, no summary. An order of recorded
/// times is not an order of events, and a record that is absent was not necessarily removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline {
    /// Oldest first. Entries with the same time keep anchors first, then [`COLLECTOR_ORDER`].
    pub entries: Vec<TimelineEntry>,
    /// One per source that reports the span it could see.
    pub bands: Vec<CoverageBand>,
    /// Sources, or places, whose times could not be read, with the reason, in place of a band.
    pub unmeasured: Vec<UnmeasuredSource>,
}

/// The reasons a view states once above the evidence instead of as a row per rule (ADR 0027,
/// ADR 0030).
fn scope_notes(report: &Report) -> ScopeNotes {
    let counted = |wanted: UnmeasuredReason| {
        report
            .evidence
            .iter()
            .filter(|item| matches!(item.state, EvidenceState::Unmeasured { reason, .. } if reason == wanted))
            .count()
    };
    ScopeNotes {
        not_admin: counted(UnmeasuredReason::NotAdmin),
        not_attempted: counted(UnmeasuredReason::NotAttempted),
        not_consented: counted(UnmeasuredReason::NotConsented),
    }
}

/// Whether an SS view lists this piece of evidence, rather than only counting it.
///
/// A match is always listed. A posture rule that looked is listed whatever it found, because the
/// machine's posture is the thing an SS reviewer came for (ADR 0011). An unmeasured result is listed
/// only when its reason is one the rule did not name in `unmeasured_when`: a reason the author
/// declared is one they said happens on ordinary machines, and a row per such rule is the "sea of
/// red flags" that teaches a reviewer to stop reading (ADR 0027).
///
/// Two exceptions in each direction, both from [`UnmeasuredReason`] and both about who the fact
/// belongs to (ADR 0030):
///
/// - `not_admin` and `not_attempted` are never a row. Each is one fact about the **scan** that
///   applies to every rule it stopped, and each is stated once in [`ScopeNotes`].
/// - `partial`, `budget_spent` and `read_failed` are always a row, declared or not. Each says the
///   artifact was reachable and that the read of it did not finish, which is not something a rule
///   author could have anticipated about the machine and so is not theirs to declare away
///   (ADR 0030, ADR 0032).
fn ss_lists(item: &Evidence) -> bool {
    match &item.state {
        EvidenceState::Found { .. } => true,
        EvidenceState::NotFound { .. } => item.strength == Strength::Posture,
        EvidenceState::Unmeasured { reason, .. } if reason.is_scope_statement() => false,
        EvidenceState::Unmeasured { reason, .. } if reason.is_always_listed() => true,
        EvidenceState::Unmeasured { expected, .. } => !expected,
    }
}

/// Builds the view for `mode`.
///
/// - Self: everything, unchanged.
/// - SS: what [`ss_lists`] admits, with user names in paths replaced by
///   [`USERPROFILE_PLACEHOLDER`] ([`redact_profile_paths`], with the header's `profiles_directory`);
///   every other piece of evidence is counted in [`HiddenCounts`]; unmatched observations are counted
///   and none are listed (ADR 0014). Its header is [`shown_header`] (ADR 0049).
///
/// Both modes carry the same [`ScopeNotes`]: they are facts about the scan, and SS mode's filter is
/// about evidence.
pub fn for_mode(report: &Report, mode: Mode) -> ReportView {
    for_mode_with(report, mode, SsOptions::default())
}

/// Builds the view for `mode`, with what the player agreed SS mode may show (ADR 0052).
///
/// In SS mode every value of a field a collector declared sensitive is replaced by its
/// [`placeholder`] unless `options` shows its kind — in the evidence, the timeline, own traces and
/// everything counted — before anything else is built, so no later step can reach the value.
pub fn for_mode_with(report: &Report, mode: Mode, options: SsOptions) -> ReportView {
    match mode {
        Mode::SelfCheck => build(report, mode),
        Mode::Ss => build(&masked(report, options), mode),
    }
}

/// `report` with each sensitive value `options` does not show replaced by its placeholder.
fn masked(report: &Report, options: SsOptions) -> Report {
    let mut report = report.clone();
    let sensitive = std::mem::take(&mut report.sensitive_fields);
    let mask = |observation: &mut Observation| {
        let Some(fields) = sensitive.get(&observation.collector) else {
            return;
        };
        for (field, kind) in fields {
            if options.shows(*kind) {
                continue;
            }
            if let Some(value) = observation.fields.get_mut(field) {
                *value = serde_json::Value::from(placeholder(*kind));
            }
        }
    };
    for item in &mut report.evidence {
        if let EvidenceState::Found { observations } = &mut item.state {
            observations.iter_mut().for_each(mask);
        }
    }
    for selection in &mut report.timeline_selections {
        selection.observations.iter_mut().for_each(mask);
    }
    for group in &mut report.unmatched {
        group.observations.iter_mut().for_each(mask);
    }
    for entry in &mut report.own_traces {
        mask(&mut entry.observation);
    }
    report.sensitive_fields = sensitive;
    report
}

fn build(report: &Report, mode: Mode) -> ReportView {
    match mode {
        Mode::SelfCheck => ReportView {
            mode,
            header: report.header.clone(),
            evidence: report.evidence.clone(),
            own_traces: report.own_traces.clone(),
            unmatched: report.unmatched.clone(),
            scope: scope_notes(report),
            listed: listed_counts(&report.evidence),
            hidden: HiddenCounts::default(),
            timeline: timeline_of(report, mode),
            collector_order: collector_order(),
            row_bands: row_bands(report, &report.evidence),
            trace_ages: trace_ages_of(report, mode),
            cross_source: cross_source_of(report),
        },
        Mode::Ss => {
            let machine_root = report
                .header
                .profiles_directory
                .as_deref()
                .and_then(MachineRoot::parse);
            let machine_root = machine_root.as_ref();
            let mut hidden = HiddenCounts::default();
            let mut evidence = Vec::new();
            for item in &report.evidence {
                if ss_lists(item) {
                    evidence.push(redacted(item, machine_root));
                    continue;
                }
                match &item.state {
                    EvidenceState::NotFound { .. } => hidden.not_found += 1,
                    EvidenceState::Unmeasured { expected: true, .. } => {
                        hidden.unmeasured_expected += 1;
                    }
                    EvidenceState::Unmeasured { .. } => hidden.unmeasured_unexpected += 1,
                    // `ss_lists` admits every match, so nothing reaches here.
                    EvidenceState::Found { .. } => {}
                }
            }
            // Counted, never listed. SS mode promises the person being screenshared that only what
            // matches a rule is shown; a raw listing of every file and process name a collector saw
            // would break that promise, and no redaction pass makes such a listing safe (ADR 0014).
            hidden.unmatched = report
                .unmatched
                .iter()
                .map(|group| group.observations.len())
                .sum();
            let listed = listed_counts(&evidence);
            let row_bands = row_bands(report, &evidence);
            ReportView {
                mode,
                header: shown_header(report),
                evidence,
                own_traces: report
                    .own_traces
                    .iter()
                    .map(|entry| redacted_own_trace(entry, machine_root))
                    .collect(),
                unmatched: Vec::new(),
                scope: scope_notes(report),
                listed,
                hidden,
                timeline: timeline_of(report, mode),
                collector_order: collector_order(),
                row_bands,
                trace_ages: trace_ages_of(report, mode),
                cross_source: cross_source_of(report),
            }
        }
    }
}

/// How far back each source reaches on this PC, beside when parts of this PC were set up (ADR 0061).
///
/// Nothing here is sorted by age, coloured, compared, summed or named "short": rows follow
/// [`COLLECTOR_ORDER`], anchors first, and a reviewer compares them. A source that was not read is a
/// row with its reason in place of the time and the count — never a zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceAges {
    /// When Windows last started, then the header's anchors, each with its days before the scan.
    pub anchors: Vec<AnchorAge>,
    /// One per source, or per place or log of one.
    pub rows: Vec<TraceAge>,
    /// The logs the bundle does not read, folded into one line (ADR 0061, owner decision 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folded_logs: Option<FoldedLogs>,
}

/// One anchor as the trace-ages section shows it (ADR 0061).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorAge {
    /// `boot_time`, or the anchor's [`crate::model::AnchorKind`] identifier.
    pub anchor: String,
    /// Its date and days before the scan, or why there is none.
    #[serde(flatten)]
    pub state: AnchorAgeState,
}

/// An anchor's date, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AnchorAgeState {
    /// Read.
    Measured {
        /// The UTC date; for `boot_time`, the header's time to the second (ADR 0039).
        on: String,
        /// Whole days between it and the scan.
        days_before: i64,
        /// What was read, as the header names it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        /// How many earlier installations Windows Setup kept, for that anchor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kept: Option<u32>,
    },
    /// Not read.
    Unmeasured {
        /// Why.
        reason: UnmeasuredReason,
    },
}

/// How far back one source reaches (ADR 0061).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceAge {
    /// The collector.
    pub collector: String,
    /// The place, for a collector with a row per place: `fivem_dir`'s folder, `usn`'s journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// The log's file name, for `evtx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// What it holds, or why it was not read.
    #[serde(flatten)]
    pub state: TraceAgeState,
    /// For Legacy's resource cache, per launch mode: its index folder's creation date beside the oldest
    /// cache file's, shown and never compared (ADR 0062 section 4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index_beside: Vec<IndexBeside>,
}

/// What one source holds, or why it was not read (ADR 0061).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TraceAgeState {
    /// Read.
    Measured {
        /// The oldest time it still holds, as the report holds it; absent when it holds none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oldest: Option<String>,
        /// Whole days between the oldest time and the scan.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        days_before: Option<i64>,
        /// How much it holds.
        count: u64,
        /// Shown beside it and never compared: a log's size and maximum, a journal's size.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        extra: BTreeMap<String, serde_json::Value>,
    },
    /// Not read: `not_admin` is "not known", never "empty".
    Unmeasured {
        /// Why.
        reason: UnmeasuredReason,
    },
}

/// The logs the bundle does not read, as one line: how many there are, how many hold records, and
/// how many could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldedLogs {
    /// The collector, `evtx`.
    pub collector: String,
    /// How many logs.
    pub logs: u64,
    /// How many of them hold at least one record.
    pub with_records: u64,
    /// How many of them could not be read.
    pub not_read: u64,
}

/// Facts from different collectors printed together (ADR 0061 section 3, amended by ADR 0062 section 1)
/// — not evidence: no state, no rule, no strength, never counted. There is at most one of the first
/// kind and at most one session statement per edition; `kind` tells them apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CrossSourceStatement {
    /// `FiveM`'s folders beside Prefetch, BAM and PCA (ADR 0061).
    FivemAndRecords(RecordsStatement),
    /// One edition's last session beside its own folders (ADR 0062).
    Session(SessionStatement),
}

/// `FiveM`'s side beside Windows' records of programs that ran (ADR 0061, section 3).
///
/// It is built only when Prefetch or BAM was read, held no entry for the names `FiveM`'s timeline
/// selectors list, and still reaches back further than `FiveM`'s last write; the ordinary causes of the
/// same result are always printed with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordsStatement {
    /// `FiveM`'s side.
    pub fivem: FivemSide,
    /// Prefetch, BAM and PCA, each always, in that order.
    pub sources: Vec<SourceLine>,
}

/// What `FiveM`'s own folders say: a presence, a count and times, never a path or a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FivemSide {
    /// The editions whose `FiveM.exe` is present: `legacy`, `enhanced`.
    pub editions: Vec<String>,
    /// The UTC date `FiveM`'s log, crash and cache folders were last written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folders_written: Option<String>,
    /// Whole days between that write and the scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folders_days_before: Option<i64>,
    /// How many Enhanced server cache folders there are.
    pub server_folders: u64,
    /// The UTC date the latest of them was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers_written: Option<String>,
}

/// One of Windows' records of programs that ran, in one of the ADR's line forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLine {
    /// `prefetch`, `bam` or `pca`.
    pub collector: String,
    /// Its line.
    #[serde(flatten)]
    pub line: SourceLineKind,
}

/// The line forms of ADR 0061 section 3. A source that was not read is never folded into "no entry".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "line", rename_all = "snake_case")]
pub enum SourceLineKind {
    /// Read, and `FiveM`'s selectors selected something: how many entries, and the latest date.
    Selected {
        /// Entries selected.
        entries: u64,
        /// The UTC date of the latest.
        latest: String,
    },
    /// Read, nothing selected, and it reaches back further than `FiveM`'s last write.
    NoEntry {
        /// Entries it holds.
        entries: u64,
        /// The UTC date of the oldest.
        oldest: String,
        /// Whole days between the oldest and the scan.
        days_before: i64,
    },
    /// Read, nothing selected, and it holds nothing as old as `FiveM`'s last write, so it could not
    /// show it.
    CouldNotShow {
        /// Entries it holds.
        entries: u64,
    },
    /// Not read: whether it holds an entry is not known.
    NotRead {
        /// Why.
        reason: UnmeasuredReason,
    },
    /// Prefetch is switched off on this PC, so it keeps no such record.
    SwitchedOff,
}

/// The timeline selectors that select `FiveM`'s and GTA V's executables by name on Windows' records of
/// programs that ran (ADR 0051 section 4, first row): two per collector. Their ids are never reused,
/// and `the_fivem_selectors_are_in_the_embedded_bundle` binds this list to the rules tree.
pub const FIVEM_SELECTORS: [(&str, &str); 6] = [
    ("prefetch", "a81a1693-2982-4004-8f40-186c2b90a6a2"),
    ("prefetch", "d377e008-0a08-4d6e-adf2-f6cbc8b978db"),
    ("bam", "19dc7372-391e-4874-9c94-92ee6170f2df"),
    ("bam", "bf213176-ed26-4c02-935e-99925abc7db7"),
    ("pca", "6487719d-15cf-422c-8b8a-858647091fd1"),
    ("pca", "eaf79187-e067-43ed-9afe-bffe65e6b2e5"),
];

/// The three records the statement compares `FiveM`'s side with, in the order it prints them.
const RECORDS_OF_RUNS: [&str; 3] = ["prefetch", "bam", "pca"];
/// `fivem_dir`'s places of `FiveM.exe` and the server cache (ADR 0036, ADR 0053).
const FIVEM_EXE_PLACES: [(&str, &str); 2] =
    [("legacy_exe", "legacy"), ("enhanced_exe", "enhanced")];
/// `fivem_dir`'s Enhanced server cache place.
const SERVER_CACHE_PLACE: &str = "enhanced_server_cache";

/// The trace ages `mode` may show (ADR 0061). The same in both modes apart from redaction: an age is a
/// fact about a source, like a coverage band, computed over every observation of it.
pub fn trace_ages(report: &Report, mode: Mode) -> TraceAges {
    trace_ages_of(report, mode)
}

/// The cross-source statements: ADR 0061's, when its conditions hold, and one session statement per
/// edition (ADR 0062). The same in both modes: they hold no path, no file name, no user name and no
/// server name.
pub fn cross_source(report: &Report, _mode: Mode) -> Vec<CrossSourceStatement> {
    cross_source_of(report)
}

/// Every observation of `collector` a trace age is read from — what a rule matched and what none did —
/// each once.
fn observations_of<'r>(report: &'r Report, collector: &str) -> Vec<&'r Observation> {
    let mut seen: HashSet<String> = HashSet::new();
    band_sources(report)
        .filter(|observation| observation.collector == collector)
        .filter(|observation| seen.insert(serde_json::to_string(observation).unwrap_or_default()))
        .collect()
}

fn scan_time(report: &Report) -> Option<jiff::Timestamp> {
    report.header.generated_at.parse().ok()
}

/// Whole days from `earlier` to `later`, rounded down.
fn days_between(later: jiff::Timestamp, earlier: jiff::Timestamp) -> i64 {
    (later.as_second() - earlier.as_second()).div_euclid(86_400)
}

fn utc_date(time: jiff::Timestamp) -> String {
    time.to_zoned(jiff::tz::TimeZone::UTC).date().to_string()
}

fn trace_ages_of(report: &Report, mode: Mode) -> TraceAges {
    let machine_root = match mode {
        Mode::SelfCheck => None,
        Mode::Ss => report
            .header
            .profiles_directory
            .as_deref()
            .and_then(MachineRoot::parse),
    };
    let redact = |text: String| match mode {
        Mode::SelfCheck => text,
        Mode::Ss => redact_with(&text, machine_root.as_ref()),
    };
    let mut collectors: Vec<&String> = report.age_fields.keys().collect();
    collectors.sort_by_key(|id| collector_rank(Some(id)));
    let mut rows = Vec::new();
    let mut folded_logs = None;
    for collector in collectors {
        let (mut collector_rows, folded) = age_rows(report, collector);
        for row in &mut collector_rows {
            row.subject = row.subject.take().map(&redact);
            if row.collector == "fivem_dir"
                && row.place.as_deref() == Some(session::LEGACY_SERVER_CACHE)
                && matches!(row.state, TraceAgeState::Measured { .. })
            {
                row.index_beside = session::index_beside(report);
            }
        }
        rows.extend(collector_rows);
        folded_logs = folded_logs.or(folded);
    }
    TraceAges {
        anchors: anchor_ages(report),
        rows,
        folded_logs,
    }
}

fn anchor_ages(report: &Report) -> Vec<AnchorAge> {
    let scan = scan_time(report);
    let scan_date = scan.map(|scan| scan.to_zoned(jiff::tz::TimeZone::UTC).date());
    let mut anchors = vec![AnchorAge {
        anchor: "boot_time".to_owned(),
        state: match &report.header.boot_time {
            BootTime::Measured {
                booted_at,
                seconds_since_boot,
            } => AnchorAgeState::Measured {
                on: booted_at.clone(),
                days_before: i64::try_from(seconds_since_boot / 86_400).unwrap_or(i64::MAX),
                source: None,
                kept: None,
            },
            BootTime::Unmeasured { reason } => AnchorAgeState::Unmeasured { reason: *reason },
        },
    }];
    for anchor in &report.header.anchors {
        let state = match &anchor.state {
            AnchorState::Measured { on, source, kept } => {
                let days = on
                    .parse::<jiff::civil::Date>()
                    .ok()
                    .zip(scan_date)
                    .and_then(|(on, scan)| on.until(scan).ok())
                    .map(|span| i64::from(span.get_days()));
                match days {
                    Some(days_before) => AnchorAgeState::Measured {
                        on: on.clone(),
                        days_before,
                        source: Some(source.clone()),
                        kept: *kept,
                    },
                    // A date the report cannot put a day count on is not shown as one.
                    None => AnchorAgeState::Unmeasured {
                        reason: UnmeasuredReason::ReadFailed,
                    },
                }
            }
            AnchorState::Unmeasured { reason } => AnchorAgeState::Unmeasured { reason: *reason },
        };
        anchors.push(AnchorAge {
            anchor: anchor.anchor.as_str().to_owned(),
            state,
        });
    }
    anchors
}

/// Why a log was not read, from the `read` word `evtx` gives it (`collectors::failure`), in the
/// vocabulary every other row uses. A refusal to a scan without administrator rights is `not_admin`,
/// as the collectors decide it.
fn reason_of_read(read: &str, elevated: Option<bool>) -> UnmeasuredReason {
    match read {
        "access_denied" if elevated == Some(false) => UnmeasuredReason::NotAdmin,
        "access_denied" => UnmeasuredReason::AccessDenied,
        "budget_exhausted" => UnmeasuredReason::BudgetSpent,
        "not_attempted" | "parse_unavailable" => UnmeasuredReason::NotAttempted,
        _ => UnmeasuredReason::ReadFailed,
    }
}

/// The source's own reason it was not read, for the whole collector or one place of it.
fn unmeasured_reason(
    report: &Report,
    collector: &str,
    place: Option<&str>,
) -> Option<UnmeasuredReason> {
    report
        .unmeasured_sources
        .iter()
        .find(|source| source.collector == collector && source.place.as_deref() == place)
        .map(|source| source.reason)
}

/// The rows of one collector, and for a collector with a row per value the values folded away.
fn age_rows(report: &Report, collector: &str) -> (Vec<TraceAge>, Option<FoldedLogs>) {
    let Some(declared) = report.age_fields.get(collector) else {
        return (Vec::new(), None);
    };
    let source = AgeSource {
        report,
        collector,
        declared,
        observations: observations_of(report, collector),
        whole: unmeasured_reason(report, collector, None),
        scan: scan_time(report),
    };
    match &declared.rows {
        AgeRows::One => {
            let state = match source.whole {
                Some(reason) => TraceAgeState::Unmeasured { reason },
                None => source.measure(&source.observations, None),
            };
            (vec![source.row(None, None, state)], None)
        }
        AgeRows::PerPlace => (source.per_place(), None),
        AgeRows::PerValue { field } => source.per_value(field),
    }
}

/// One collector's observations and what it declared about their age.
struct AgeSource<'r> {
    report: &'r Report,
    collector: &'r str,
    declared: &'r crate::model::AgeFields,
    observations: Vec<&'r Observation>,
    /// Why the whole collector was not read, when it was not.
    whole: Option<UnmeasuredReason>,
    scan: Option<jiff::Timestamp>,
}

impl AgeSource<'_> {
    fn row(
        &self,
        place: Option<String>,
        subject: Option<String>,
        state: TraceAgeState,
    ) -> TraceAge {
        TraceAge {
            collector: self.collector.to_owned(),
            place,
            subject,
            state,
            index_beside: Vec::new(),
        }
    }

    /// The collector's own declaration, over `observations`.
    fn measure(&self, observations: &[&Observation], place: Option<&str>) -> TraceAgeState {
        let declared = self.declared;
        match place.and_then(|place| declared.by_place.iter().find(|by| by.place == place)) {
            Some(by) => measure(
                observations,
                &by.oldest,
                &by.count,
                &declared.extra,
                by.without.as_deref(),
                self.scan,
            ),
            None => measure(
                observations,
                &declared.oldest,
                &declared.count,
                &declared.extra,
                None,
                self.scan,
            ),
        }
    }

    /// A row per declared place. A place with no observation, or whose folder is absent, is
    /// `source_absent`; one that could not be read carries its reason.
    fn per_place(&self) -> Vec<TraceAge> {
        self.declared
            .places
            .iter()
            .map(|place| {
                let reason = self
                    .whole
                    .or_else(|| unmeasured_reason(self.report, self.collector, Some(place)));
                let here: Vec<&Observation> = self
                    .observations
                    .iter()
                    .copied()
                    .filter(|observation| {
                        place_of(self.report, observation).as_deref() == Some(place)
                    })
                    .collect();
                let absent = here.iter().all(|observation| {
                    observation
                        .fields
                        .get("folder")
                        .and_then(serde_json::Value::as_str)
                        == Some("absent")
                });
                let state = match reason {
                    Some(reason) => TraceAgeState::Unmeasured { reason },
                    None if here.is_empty() || absent => TraceAgeState::Unmeasured {
                        reason: UnmeasuredReason::SourceAbsent,
                    },
                    None => self.measure(&here, Some(place)),
                };
                self.row(Some(place.clone()), None, state)
            })
            .collect()
    }

    /// A row per value of `field` among the values listed first, and the rest folded.
    fn per_value(&self, field: &str) -> (Vec<TraceAge>, Option<FoldedLogs>) {
        let mut groups: BTreeMap<String, Vec<&Observation>> = BTreeMap::new();
        for observation in &self.observations {
            if let Some(value) = observation
                .fields
                .get(field)
                .and_then(serde_json::Value::as_str)
            {
                groups
                    .entry(value.to_owned())
                    .or_default()
                    .push(observation);
            }
        }
        if groups.is_empty()
            && let Some(reason) = self.whole
        {
            return (
                vec![self.row(None, None, TraceAgeState::Unmeasured { reason })],
                None,
            );
        }
        let mut rows = Vec::new();
        for first in &self.declared.first {
            let state = match groups.get(first) {
                Some(group) => self.state_of(group),
                None => TraceAgeState::Unmeasured {
                    reason: self.whole.unwrap_or(UnmeasuredReason::SourceAbsent),
                },
            };
            rows.push(self.row(None, Some(first.clone()), state));
        }
        let mut folded = FoldedLogs {
            collector: self.collector.to_owned(),
            logs: 0,
            with_records: 0,
            not_read: 0,
        };
        for (value, group) in &groups {
            if self.declared.first.contains(value) {
                continue;
            }
            folded.logs += 1;
            match self.state_of(group) {
                TraceAgeState::Measured { count, .. } if count > 0 => folded.with_records += 1,
                TraceAgeState::Measured { .. } => {}
                TraceAgeState::Unmeasured { .. } => folded.not_read += 1,
            }
        }
        (rows, (folded.logs > 0).then_some(folded))
    }

    /// One value's observations: measured when one carries the counted field — a log's account —
    /// and otherwise the reason its `read` word gives.
    fn state_of(&self, group: &[&Observation]) -> TraceAgeState {
        let counted = group.iter().any(|observation| match &self.declared.count {
            AgeCount::Field { field } => observation.fields.contains_key(field),
            AgeCount::Observations => true,
        });
        if counted {
            return self.measure(group, None);
        }
        let read = group
            .iter()
            .find_map(|observation| {
                observation
                    .fields
                    .get("read")
                    .and_then(serde_json::Value::as_str)
            })
            .unwrap_or_default();
        TraceAgeState::Unmeasured {
            reason: reason_of_read(read, self.report.header.elevated),
        }
    }
}

/// What a row's observations hold: the oldest of `oldest` over them, the count, and `extra` beside
/// them — a time as the latest among them, anything else as the first. `without` keeps only the
/// observations that lack that field.
fn measure(
    observations: &[&Observation],
    oldest: &[String],
    count: &AgeCount,
    extra: &[String],
    without: Option<&str>,
    scan: Option<jiff::Timestamp>,
) -> TraceAgeState {
    let kept: Vec<&Observation> = observations
        .iter()
        .copied()
        .filter(|observation| without.is_none_or(|field| !observation.fields.contains_key(field)))
        .collect();
    let oldest_time = kept
        .iter()
        .flat_map(|observation| {
            oldest
                .iter()
                .filter_map(|field| time_of(observation, field))
        })
        .filter_map(|text| {
            text.parse::<jiff::Timestamp>()
                .ok()
                .map(|time| (time, text))
        })
        .min_by_key(|(time, _)| *time);
    let count = match count {
        AgeCount::Observations => kept
            .iter()
            .filter(|observation| {
                oldest
                    .iter()
                    .any(|field| time_of(observation, field).is_some())
            })
            .count() as u64,
        AgeCount::Field { field } => kept
            .iter()
            .filter_map(|observation| {
                observation
                    .fields
                    .get(field)
                    .and_then(serde_json::Value::as_u64)
            })
            .sum(),
    };
    let mut beside = BTreeMap::new();
    for field in extra {
        let values: Vec<&serde_json::Value> = observations
            .iter()
            .filter_map(|observation| observation.fields.get(field))
            .collect();
        let latest = values
            .iter()
            .filter_map(|value| value.as_str())
            .filter_map(|text| {
                text.parse::<jiff::Timestamp>()
                    .ok()
                    .map(|time| (time, text))
            })
            .max_by_key(|(time, _)| *time);
        if let Some((_, text)) = latest {
            beside.insert(field.clone(), serde_json::Value::from(text));
        } else if let Some(value) = values.first() {
            beside.insert(field.clone(), (*value).clone());
        }
    }
    TraceAgeState::Measured {
        oldest: oldest_time.map(|(_, text)| text.to_owned()),
        days_before: oldest_time
            .zip(scan)
            .map(|((time, _), scan)| days_between(scan, time)),
        count,
        extra: beside,
    }
}

/// ADR 0061's statement, when its conditions hold, then one session statement per edition that has one
/// (ADR 0062).
fn cross_source_of(report: &Report) -> Vec<CrossSourceStatement> {
    let mut statements = records_statement(report);
    statements.extend(
        session::sessions(report)
            .into_iter()
            .map(CrossSourceStatement::Session),
    );
    statements
}

fn records_statement(report: &Report) -> Vec<CrossSourceStatement> {
    let Some(scan) = scan_time(report) else {
        return Vec::new();
    };
    // Condition 3: the bundle holds FiveM's selectors on every one of the three records. Without
    // them "selected nothing" cannot be said of any, and nothing is shown.
    let held = FIVEM_SELECTORS.iter().all(|(collector, id)| {
        report
            .timeline_selectors
            .get(*collector)
            .is_some_and(|ids| ids.iter().any(|held| held == id))
    });
    if !held {
        return Vec::new();
    }
    let Some(fivem) = fivem_side(report, scan) else {
        return Vec::new();
    };
    let Some(t) = fivem.1 else {
        return Vec::new();
    };
    let sources: Vec<SourceLine> = RECORDS_OF_RUNS
        .iter()
        .map(|collector| SourceLine {
            collector: (*collector).to_owned(),
            line: source_line(report, collector, t, scan),
        })
        .collect();
    // Condition 2: Prefetch or BAM was read, selected nothing, and reaches back further than T. PCA
    // alone never makes the statement: it records launches from File Explorer only.
    let reaches_back = sources.iter().any(|source| {
        source.collector != "pca" && matches!(source.line, SourceLineKind::NoEntry { .. })
    });
    if !reaches_back {
        return Vec::new();
    }
    vec![CrossSourceStatement::FivemAndRecords(RecordsStatement {
        fivem: fivem.0,
        sources,
    })]
}

/// `FiveM`'s side, and T — the later of the folders' last write and the latest server cache folder's —
/// when `FiveM`'s side was read and is present (condition 1).
fn fivem_side(
    report: &Report,
    scan: jiff::Timestamp,
) -> Option<(FivemSide, Option<jiff::Timestamp>)> {
    let observations = observations_of(report, "fivem_dir");
    let location = |observation: &Observation| {
        observation
            .fields
            .get("location")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let editions: Vec<String> = FIVEM_EXE_PLACES
        .iter()
        .filter(|(place, _)| {
            observations.iter().any(|observation| {
                location(observation).as_deref() == Some(place)
                    && observation.fields.contains_key("path")
            })
        })
        .map(|(_, edition)| (*edition).to_owned())
        .collect();
    let activity: Vec<String> = report
        .age_fields
        .get("fivem_dir")
        .map(|declared| declared.places.clone())
        .unwrap_or_default();
    let latest = |field: &str, keep: &dyn Fn(&Observation) -> bool| {
        observations
            .iter()
            .filter(|observation| keep(observation))
            .filter_map(|observation| time_of(observation, field))
            .filter_map(|text| text.parse::<jiff::Timestamp>().ok())
            .max()
    };
    let folders = latest("latest_modified_at", &|observation| {
        location(observation).is_some_and(|place| activity.contains(&place))
    });
    let is_server = |observation: &Observation| {
        location(observation).as_deref() == Some(SERVER_CACHE_PLACE)
            && !observation.fields.contains_key("folder")
    };
    let server_folders = observations
        .iter()
        .filter(|observation| is_server(observation))
        .count() as u64;
    let servers = latest("modified_at", &is_server);
    if editions.is_empty() && server_folders == 0 {
        return None;
    }
    let t = folders.into_iter().chain(servers).max();
    Some((
        FivemSide {
            editions,
            folders_written: folders.map(utc_date),
            folders_days_before: folders.map(|time| days_between(scan, time)),
            server_folders,
            servers_written: servers.map(utc_date),
        },
        t,
    ))
}

/// One record's line (ADR 0061 section 3).
fn source_line(
    report: &Report,
    collector: &str,
    t: jiff::Timestamp,
    scan: jiff::Timestamp,
) -> SourceLineKind {
    if let Some(reason) = unmeasured_reason(report, collector, None) {
        return match reason {
            UnmeasuredReason::ServiceDisabled => SourceLineKind::SwitchedOff,
            // Read, or looked for, and holding nothing: it holds nothing as old as T either.
            UnmeasuredReason::SourceEmpty
            | UnmeasuredReason::SourceAbsent
            | UnmeasuredReason::NotOnThisOs => SourceLineKind::CouldNotShow { entries: 0 },
            reason => SourceLineKind::NotRead { reason },
        };
    }
    let ids: Vec<&str> = FIVEM_SELECTORS
        .iter()
        .filter(|(on, _)| *on == collector)
        .map(|(_, id)| *id)
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let selected: Vec<&Observation> = report
        .timeline_selections
        .iter()
        .filter(|selection| ids.contains(&selection.selector_id.as_str()))
        .flat_map(|selection| &selection.observations)
        .filter(|observation| seen.insert(serde_json::to_string(observation).unwrap_or_default()))
        .collect();
    if !selected.is_empty() {
        let latest = selected
            .iter()
            .filter_map(|observation| time_of(observation, "last_run"))
            .filter_map(|text| text.parse::<jiff::Timestamp>().ok())
            .max();
        return SourceLineKind::Selected {
            entries: selected.len() as u64,
            latest: latest.map(utc_date).unwrap_or_default(),
        };
    }
    let (rows, _) = age_rows(report, collector);
    match rows.into_iter().next().map(|row| row.state) {
        Some(TraceAgeState::Measured {
            oldest: Some(oldest),
            count,
            ..
        }) => match oldest.parse::<jiff::Timestamp>() {
            Ok(oldest) if oldest < t => SourceLineKind::NoEntry {
                entries: count,
                oldest: utc_date(oldest),
                days_before: days_between(scan, oldest),
            },
            _ => SourceLineKind::CouldNotShow { entries: count },
        },
        Some(TraceAgeState::Measured { count, .. }) => {
            SourceLineKind::CouldNotShow { entries: count }
        }
        Some(TraceAgeState::Unmeasured { reason }) => SourceLineKind::NotRead { reason },
        None => SourceLineKind::NotRead {
            reason: UnmeasuredReason::CollectorUnavailable,
        },
    }
}

fn collector_order() -> Vec<String> {
    COLLECTOR_ORDER.iter().map(|id| (*id).to_owned()).collect()
}

/// Where `collector` sorts among collectors: its place in [`COLLECTOR_ORDER`], or after all of them.
fn collector_rank(collector: Option<&str>) -> usize {
    match collector {
        // Anchors first: they are the scan's own times.
        None => 0,
        Some(id) => COLLECTOR_ORDER
            .iter()
            .position(|known| *known == id)
            .map_or(COLLECTOR_ORDER.len() + 1, |index| index + 1),
    }
}

/// The timeline `mode` may show (ADR 0051).
///
/// - Self: every timestamp field of every observation the report holds — evidence, timeline
///   selections and unmatched — with the anchors, the bands and the unmeasured sources.
/// - SS: the times in the evidence SS mode lists, the times timeline selectors selected, the anchors,
///   the bands and the unmeasured sources. Nothing an SS view counts instead of listing reaches it
///   except through a reviewed timeline selector. Subjects and places are redacted as rows are.
///
/// An observation reached by more than one route is shown once, as evidence before selector before
/// unmatched. Which fields are times comes from `report.timestamp_fields` and nothing else.
pub fn timeline(report: &Report, mode: Mode) -> Timeline {
    match mode {
        Mode::SelfCheck => timeline_of(report, mode),
        Mode::Ss => timeline_of(&masked(report, SsOptions::default()), mode),
    }
}

fn timeline_of(report: &Report, mode: Mode) -> Timeline {
    let machine_root = match mode {
        Mode::SelfCheck => None,
        Mode::Ss => report
            .header
            .profiles_directory
            .as_deref()
            .and_then(MachineRoot::parse),
    };
    let redact = |text: String| match mode {
        Mode::SelfCheck => text,
        Mode::Ss => redact_with(&text, machine_root.as_ref()),
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut entries = anchors(&report.header);
    for (observation, source) in routes(report, mode) {
        let key = serde_json::to_string(observation).unwrap_or_default();
        if !seen.insert(key) {
            continue;
        }
        let Some(fields) = report.timestamp_fields.get(&observation.collector) else {
            continue;
        };
        let place = place_of(report, observation).map(redact);
        let subject = subject_of(observation).map(redact);
        for field in fields {
            let Some(at) = time_of(observation, field) else {
                continue;
            };
            entries.push(TimelineEntry {
                at: at.to_owned(),
                collector: Some(observation.collector.clone()),
                field: field.clone(),
                place: place.clone(),
                source: source.clone(),
                subject: subject.clone(),
            });
        }
    }
    // Stable: entries with one time and one collector keep the order they were reached in.
    entries.sort_by_cached_key(|entry| {
        (
            entry.at.parse::<jiff::Timestamp>().ok(),
            collector_rank(entry.collector.as_deref()),
        )
    });

    Timeline {
        entries,
        bands: bands(report, redact),
        unmeasured: report.unmeasured_sources.clone(),
    }
}

/// Every observation `mode` may take times from, with where it came from, in the order that decides
/// which route an observation reached by two is shown as.
fn routes(report: &Report, mode: Mode) -> Vec<(&Observation, EntrySource)> {
    let mut routes = Vec::new();
    for item in &report.evidence {
        if mode == Mode::Ss && !ss_lists(item) {
            continue;
        }
        if let EvidenceState::Found { observations } = &item.state {
            for observation in observations {
                let source = EntrySource::Evidence {
                    rule_id: item.rule_id.clone(),
                };
                routes.push((observation, source));
            }
        }
    }
    for selection in &report.timeline_selections {
        for observation in &selection.observations {
            let source = EntrySource::Selector {
                selector_id: selection.selector_id.clone(),
            };
            routes.push((observation, source));
        }
    }
    if mode == Mode::SelfCheck {
        for group in &report.unmatched {
            for observation in &group.observations {
                routes.push((observation, EntrySource::Observation));
            }
        }
    }
    routes
}

/// The span each source could see, from every observation that carries its coverage fields — in both
/// modes, because a span is a fact about the source rather than about a program or a file.
fn bands(report: &Report, redact: impl Fn(String) -> String) -> Vec<CoverageBand> {
    let observations = band_sources(report);
    let mut seen: HashSet<String> = HashSet::new();
    let mut bands = Vec::new();
    for observation in observations {
        let Some(coverage) = report.coverage_fields.get(&observation.collector) else {
            continue;
        };
        let place = place_of(report, observation);
        if coverage.place.is_some() && coverage.place != place {
            continue;
        }
        let (Some(from), Some(to)) = (
            time_of(observation, &coverage.from),
            time_of(observation, &coverage.to),
        ) else {
            continue;
        };
        let key = serde_json::to_string(observation).unwrap_or_default();
        if !seen.insert(key) {
            continue;
        }
        bands.push(CoverageBand {
            collector: observation.collector.clone(),
            place: place.map(&redact),
            subject: subject_of(observation).map(&redact),
            from: from.to_owned(),
            to: to.to_owned(),
        });
    }
    bands.sort_by_cached_key(|band| {
        (
            collector_rank(Some(&band.collector)),
            band.from.parse::<jiff::Timestamp>().ok(),
        )
    });
    bands
}

/// Every observation a band can be read from: what a rule matched, and what no rule matched. The same
/// set in both modes, because a span is a fact about the source rather than about a program or a file.
fn band_sources(report: &Report) -> impl Iterator<Item = &Observation> {
    report
        .evidence
        .iter()
        .filter_map(|item| match &item.state {
            EvidenceState::Found { observations } => Some(observations.iter()),
            _ => None,
        })
        .flatten()
        .chain(
            report
                .unmatched
                .iter()
                .flat_map(|group| &group.observations),
        )
}

/// The span each `found` or `not_found` row in `evidence` is for, when its collector's coverage names
/// one place (ADR 0047, amendment of 2026-09-30, decision 3). A collector whose coverage names no
/// place — `evtx`, a band per log — gets none, and neither does a row whose collector's place was not
/// observed at all.
fn row_bands(report: &Report, evidence: &[Evidence]) -> BTreeMap<String, RowBand> {
    let mut row_bands = BTreeMap::new();
    for item in evidence {
        if matches!(item.state, EvidenceState::Unmeasured { .. }) {
            continue;
        }
        let Some(coverage) = report.coverage_fields.get(&item.collector) else {
            continue;
        };
        let Some(wanted) = coverage.place.as_deref() else {
            continue;
        };
        let Some(source) = band_sources(report).find(|observation| {
            observation.collector == item.collector
                && place_of(report, observation).as_deref() == Some(wanted)
        }) else {
            continue;
        };
        let band = match (
            time_of(source, &coverage.from),
            time_of(source, &coverage.to),
        ) {
            (Some(from), Some(to)) => RowBand::Span {
                from: from.to_owned(),
                to: to.to_owned(),
            },
            _ => RowBand::NoSpan,
        };
        row_bands.insert(item.rule_id.clone(), band);
    }
    row_bands
}

/// The scan's own times: when it ran, and when Windows last started when that was measured.
fn anchors(header: &ReportHeader) -> Vec<TimelineEntry> {
    let anchor = |field: &str, at: &str| TimelineEntry {
        at: at.to_owned(),
        collector: None,
        field: field.to_owned(),
        place: None,
        source: EntrySource::Anchor,
        subject: None,
    };
    let mut anchors = vec![anchor("generated_at", &header.generated_at)];
    if let BootTime::Measured { booted_at, .. } = &header.boot_time {
        anchors.push(anchor("boot_time", booted_at));
    }
    anchors
}

/// A field's value when it is a time the engine can put in order, and nothing otherwise.
fn time_of<'o>(observation: &'o Observation, field: &str) -> Option<&'o str> {
    observation
        .fields
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.parse::<jiff::Timestamp>().is_ok())
}

fn place_of(report: &Report, observation: &Observation) -> Option<String> {
    let discriminator = report.discriminators.get(&observation.collector)?;
    observation
        .fields
        .get(discriminator)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn subject_of(observation: &Observation) -> Option<String> {
    ["name", "path"].iter().find_map(|field| {
        observation
            .fields
            .get(*field)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    })
}

fn redacted(item: &Evidence, machine_root: Option<&MachineRoot>) -> Evidence {
    let mut item = item.clone();
    if let EvidenceState::Found { observations } = &mut item.state {
        for observation in observations {
            for (collector, field) in SS_WITHHELD_FIELDS {
                if observation.collector == collector {
                    observation.fields.remove(field);
                }
            }
            for value in observation.fields.values_mut() {
                redact_value(value, machine_root);
            }
        }
    }
    item
}

/// An own trace as SS mode shows it. It is always listed — the mode's "matches and posture only"
/// filter is about evidence, and this is not evidence — but its paths are of the same shape as any
/// other and carry the same user name, so they go through the same redaction (ADR 0010).
fn redacted_own_trace(entry: &OwnTraceEntry, machine_root: Option<&MachineRoot>) -> OwnTraceEntry {
    let mut entry = entry.clone();
    for value in entry.observation.fields.values_mut() {
        redact_value(value, machine_root);
    }
    entry
}

fn redact_value(value: &mut serde_json::Value, machine_root: Option<&MachineRoot>) {
    match value {
        serde_json::Value::String(text) => *text = redact_with(text, machine_root),
        serde_json::Value::Array(items) => {
            for item in items {
                redact_value(item, machine_root);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                redact_value(item, machine_root);
            }
        }
        _ => {}
    }
}

/// The header as it may be shown outside a view: without `profiles_directory`, which only redaction
/// needs, and which a setting chosen by whoever set up the machine could make carry a name (ADR 0049).
pub fn shown_header(report: &Report) -> ReportHeader {
    ReportHeader {
        profiles_directory: None,
        ..report.header.clone()
    }
}

/// Replaces the name after every profile root in `input` with [`USERPROFILE_PLACEHOLDER`], together
/// with everything before it back to the drive letter (ADR 0049).
///
/// A path starts at a drive: an ASCII letter and `:`, or an ASCII letter and `$` straight after a
/// separator (the administrative share `\\host\X$\`), then a separator. Its folders are read the way
/// Windows reads them: separators are `\` or `/` in any mix and any run, a `.` folder is dropped, a `..`
/// folder removes the one before it, and a folder is compared without a `:` suffix or the dots and
/// spaces it ends in, in ASCII case. A folder is a name when the folders before it are one profile
/// root: `Users`, `Documents and Settings` or `DOCUME~` and digits on any drive, or
/// `profiles_directory` on its own drive. A path ends at the end of `input`, at a byte no Windows file
/// name holds, or where another drive-rooted path starts. A root with no name after it is left alone.
pub fn redact_profile_paths(input: &str, profiles_directory: Option<&str>) -> String {
    redact_with(
        input,
        profiles_directory.and_then(MachineRoot::parse).as_ref(),
    )
}

fn redact_with(input: &str, machine_root: Option<&MachineRoot>) -> String {
    let lower = input.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut copied_to = 0;
    let mut i = 0;
    while i < bytes.len() {
        if let Some(names_end) = names_end(bytes, i, machine_root) {
            // `i` is an ASCII letter and `names_end` the end of a segment, which is an ASCII byte or
            // the end, so both are char boundaries.
            out.push_str(&input[copied_to..i]);
            out.push_str(USERPROFILE_PLACEHOLDER);
            copied_to = names_end;
            i = names_end;
            continue;
        }
        i += 1;
    }
    out.push_str(&input[copied_to..]);
    out
}

fn is_separator(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

/// The machine's `ProfilesDirectory` as [`redact_profile_paths`] matches it: its drive letter and the
/// folders after it, read the way a path's folders are.
struct MachineRoot {
    drive: u8,
    folders: Vec<Vec<u8>>,
}

impl MachineRoot {
    /// `None` unless `dir` is a drive letter, `:` and a separator. A `%` left in it is a variable the
    /// scan did not expand, so it names no folder and is not matched.
    fn parse(dir: &str) -> Option<Self> {
        let lower = dir.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let drive_rooted = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && is_separator(bytes[2]);
        if !drive_rooted || dir.contains('%') {
            return None;
        }
        let mut folders: Vec<Vec<u8>> = Vec::new();
        for (start, end) in segments(bytes, 2) {
            match &bytes[start..end] {
                b"." => {}
                b".." => {
                    folders.pop();
                }
                folder => folders.push(folder_key(folder).to_vec()),
            }
        }
        Some(Self {
            drive: bytes[0],
            folders,
        })
    }
}

/// When a drive-rooted path starts at `i` of `bytes` (lower-cased) and names a profile, where its last
/// name ends.
fn names_end(bytes: &[u8], i: usize, machine_root: Option<&MachineRoot>) -> Option<usize> {
    let drive = *bytes.get(i)?;
    let marker = *bytes.get(i + 1)?;
    let is_drive = drive.is_ascii_alphabetic()
        && (marker == b':' || (marker == b'$' && i > 0 && is_separator(bytes[i - 1])))
        && is_separator(*bytes.get(i + 2)?);
    if !is_drive {
        return None;
    }
    let machine_root = machine_root.filter(|root| root.drive == drive);
    let mut folders: Vec<&[u8]> = Vec::new();
    let mut last = None;
    for (start, end) in segments(bytes, i + 2) {
        match &bytes[start..end] {
            b"." => {}
            b".." => {
                folders.pop();
            }
            folder => {
                folders.push(folder_key(folder));
                if is_name(&folders, machine_root) {
                    last = Some(end);
                }
            }
        }
    }
    last
}

/// The byte ranges of a path's segments, from the separator at `at` to where the path ends.
///
/// The path ends at the end of `bytes`, at a byte no Windows file name holds, at an ASCII letter
/// followed by `:` and a separator, which starts the next drive-rooted path, or after a segment that is
/// one ASCII letter and `$`, which starts the next share path. Any other `:` stays in its segment: past
/// the drive it can only name a stream. Ending at every place another path starts keeps the work
/// linear in the length of `bytes`: each path is read only up to the next one.
fn segments(bytes: &[u8], at: usize) -> Vec<(usize, usize)> {
    let mut segments = Vec::new();
    let mut start = at;
    let mut j = at;
    while j < bytes.len() {
        let byte = bytes[j];
        let share = j == start
            && byte.is_ascii_alphabetic()
            && bytes.get(j + 1) == Some(&b'$')
            && bytes.get(j + 2).is_some_and(|&after| is_separator(after));
        if share {
            // Kept as this path's last folder, so that a profile folder named like a share marker
            // is still a name here.
            segments.push((j, j + 2));
            return segments;
        }
        let next_path = byte.is_ascii_alphabetic()
            && bytes.get(j + 1) == Some(&b':')
            && bytes.get(j + 2).is_some_and(|&after| is_separator(after));
        if next_path || byte < 0x20 || matches!(byte, b'"' | b'<' | b'>' | b'|' | b'*' | b'?') {
            break;
        }
        if is_separator(byte) {
            if j > start {
                segments.push((start, j));
            }
            start = j + 1;
        }
        j += 1;
    }
    if j > start {
        segments.push((start, j));
    }
    segments
}

/// A folder as it is compared: without a `:` suffix, and without the dots and spaces it ends in.
fn folder_key(folder: &[u8]) -> &[u8] {
    let folder = folder
        .iter()
        .position(|&byte| byte == b':')
        .map_or(folder, |colon| &folder[..colon]);
    let kept = folder
        .iter()
        .rposition(|&byte| byte != b'.' && byte != b' ')
        .map_or(0, |last| last + 1);
    &folder[..kept]
}

/// Whether the last of `folders` is a name: the folders before it are one profile root.
fn is_name(folders: &[&[u8]], machine_root: Option<&MachineRoot>) -> bool {
    let Some((_, parents)) = folders.split_last() else {
        return false;
    };
    let fixed = matches!(parents, [root] if is_fixed_root(root));
    let machine = machine_root.is_some_and(|root| {
        parents.len() == root.folders.len()
            && parents
                .iter()
                .zip(&root.folders)
                .all(|(folder, root)| *folder == root.as_slice())
    });
    fixed || machine
}

/// `users`, `documents and settings`, or `docume~` and digits: the 8.3 short name of the second.
fn is_fixed_root(folder: &[u8]) -> bool {
    folder == b"users"
        || folder == b"documents and settings"
        || folder
            .strip_prefix(b"docume~")
            .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::bundle::BundleInfo;
    use crate::model::{Observation, UnmatchedGroup, UnmeasuredReason};
    use crate::provenance::Provenance;

    const USER: &str = "fixtureuser";

    /// With the roots every machine has and no machine root.
    fn redact(input: &str) -> String {
        redact_profile_paths(input, None)
    }

    #[test]
    fn redacts_backslash_and_forward_slash_paths() {
        assert_eq!(
            redact(r"C:\Users\fixtureuser\AppData\Local\FiveM\x.dll"),
            r"%USERPROFILE%\AppData\Local\FiveM\x.dll"
        );
        assert_eq!(
            redact("d:/users/สมชาย/Desktop/a.exe"),
            "%USERPROFILE%/Desktop/a.exe"
        );
    }

    #[test]
    fn redacts_every_occurrence_and_leaves_other_text() {
        let input = r"from C:\USERS\a\x to C:\Users\b\y (D:\Games\users\z)";
        assert_eq!(
            redact(input),
            r"from %USERPROFILE%\x to %USERPROFILE%\y (D:\Games\users\z)"
        );
    }

    #[test]
    fn profile_root_without_name_is_unchanged() {
        assert_eq!(redact(r"C:\Users\"), r"C:\Users\");
        assert_eq!(redact("no paths here"), "no paths here");
    }

    /// The roots every machine has, measured on current Windows (ADR 0049): the alias of `Users` kept
    /// for old programs, its 8.3 short name, and the administrative share of a drive.
    #[test]
    fn redacts_the_alias_its_short_name_and_the_administrative_share() {
        for (input, expected) in [
            (
                r"C:\Documents and Settings\bob\AppData\x.sys",
                r"%USERPROFILE%\AppData\x.sys",
            ),
            (r"c:\DOCUMENTS AND SETTINGS\bob", "%USERPROFILE%"),
            (r"C:\DOCUME~1\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\docume~12\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (
                r"\\localhost\C$\Users\bob\x.exe",
                r"\\localhost\%USERPROFILE%\x.exe",
            ),
            (
                r"\\?\UNC\127.0.0.1\c$\DOCUME~1\bob\x.exe",
                r"\\?\UNC\127.0.0.1\%USERPROFILE%\x.exe",
            ),
            (r"\\?\C:\Users\bob\x.exe", r"\\?\%USERPROFILE%\x.exe"),
            (r"C:\Users/bob\x.exe", r"%USERPROFILE%\x.exe"),
            (
                r"C:/Documents and Settings\bob/x.exe",
                "%USERPROFILE%/x.exe",
            ),
            (r"C:\\Users\\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\Users. \bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\DOCUME~1.\bob", "%USERPROFILE%"),
        ] {
            assert_eq!(redact(input), expected, "{input}");
        }
    }

    /// What is not a profile root stays as it is: a root with no name, a short name that is not
    /// followed by digits, a `$` that is not a drive of a share, and a root folder that is not the
    /// first folder on its drive.
    #[test]
    fn leaves_what_is_not_a_profile_root() {
        for input in [
            r"C:\Documents and Settings\",
            r"C:\DOCUME~1\",
            r"C:\DOCUME~\bob\x",
            r"C:\DOCUME~1a\bob\x",
            r"C:\Documents\bob\x",
            r"price$\Users\bob",
            r"\\host\share$\Users\bob",
            r"D:\Games\users\z",
            r"C:\Windows\System32\drivers\x.sys",
        ] {
            assert_eq!(redact(input), input);
        }
    }

    /// The machine's own root, on its own drive and in either separator and case; the fixed roots
    /// still apply beside it.
    #[test]
    fn redacts_the_machine_profile_root_on_its_own_drive() {
        let root = Some(r"D:\Data\Profiles");
        for (input, expected) in [
            (r"D:\Data\Profiles\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"d:/data/PROFILES/bob", "%USERPROFILE%"),
            (r"\\host\D$\Data\Profiles\bob\x", r"\\host\%USERPROFILE%\x"),
            (r"C:\Users\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"E:\Data\Profiles\bob\x.exe", r"E:\Data\Profiles\bob\x.exe"),
            (r"D:\Data\bob\x.exe", r"D:\Data\bob\x.exe"),
            (r"D:\Data\Profiles\", r"D:\Data\Profiles\"),
            (r"D:\\Data.\\Profiles\bob", "%USERPROFILE%"),
        ] {
            assert_eq!(redact_profile_paths(input, root), expected, "{input}");
        }
    }

    /// Every root is checked at every folder, so the name after the longer root is replaced as well as
    /// name after the longer root is the one replaced.
    #[test]
    fn a_machine_root_under_users_replaces_the_name_after_it() {
        assert_eq!(
            redact_profile_paths(r"C:\Users\Profiles\bob\x", Some(r"C:\Users\Profiles\")),
            r"%USERPROFILE%\x"
        );
    }

    /// A drive root as the machine's root costs the first folder of every path on that drive and on no
    /// other (ADR 0049).
    #[test]
    fn a_drive_root_as_the_machine_root_redacts_the_first_folder_of_that_drive_only() {
        assert_eq!(
            redact_profile_paths(r"D:\bob\x.exe", Some(r"D:\")),
            r"%USERPROFILE%\x.exe"
        );
        assert_eq!(
            redact_profile_paths(r"C:\Windows\x.exe", Some(r"D:\")),
            r"C:\Windows\x.exe"
        );
    }

    /// A value the scan could not expand, or one that is not drive-rooted, names no folder: only the
    /// fixed roots apply.
    #[test]
    fn a_machine_root_that_is_not_a_drive_rooted_folder_is_ignored() {
        for root in [
            r"%SystemDrive%\Profiles",
            r"\\server\profiles",
            "Profiles",
            "D:",
            "",
        ] {
            assert_eq!(
                redact_profile_paths(r"D:\Profiles\bob\x", Some(root)),
                r"D:\Profiles\bob\x",
                "{root:?}"
            );
            assert_eq!(
                redact_profile_paths(r"C:\Users\bob\x", Some(root)),
                r"%USERPROFILE%\x",
                "{root:?}"
            );
        }
    }

    /// A name that is not ASCII is copied out whole and replaced whole, at every root.
    #[test]
    fn a_name_that_is_not_ascii_is_replaced_whole() {
        assert_eq!(
            redact_profile_paths(r"D:\โปรไฟล์\สมชาย\x", Some(r"D:\โปรไฟล์")),
            r"%USERPROFILE%\x"
        );
        assert_eq!(redact(r"C:\DOCUME~1\สมชาย"), "%USERPROFILE%");
    }

    /// The SS view redacts with the root the report carries and does not pass the root on.
    #[test]
    fn ss_view_redacts_under_the_machine_root_and_drops_it_from_the_header() {
        let mut report = report();
        report.header.profiles_directory = Some(r"D:\Profiles".to_owned());
        if let EvidenceState::Found { observations } = &mut report.evidence[0].state {
            observations[0].fields.insert(
                "path".to_owned(),
                serde_json::Value::from(format!(r"D:\Profiles\{USER}\tools\x.dll")),
            );
        }

        let ss = for_mode(&report, Mode::Ss);
        let EvidenceState::Found { observations } = &ss.evidence[0].state else {
            panic!("{:?}", ss.evidence[0]);
        };
        assert_eq!(
            observations[0]
                .fields
                .get("path")
                .and_then(serde_json::Value::as_str),
            Some(r"%USERPROFILE%\tools\x.dll")
        );
        assert_eq!(ss.header.profiles_directory, None);
        let json = serde_json::to_string(&ss).unwrap();
        assert!(!json.contains(USER), "{json}");
        assert!(!json.contains("profiles_directory"), "{json}");

        let own = for_mode(&report, Mode::SelfCheck);
        assert_eq!(
            own.header.profiles_directory.as_deref(),
            Some(r"D:\Profiles")
        );
    }

    /// A second path that follows a name with no separator between them is a path of its own, and its
    /// name is replaced too.
    #[test]
    fn a_path_that_follows_a_name_directly_is_redacted_on_its_own() {
        for (input, expected) in [
            (
                r"C:\Users\bob;C:\Users\alice\bin",
                r"%USERPROFILE%%USERPROFILE%\bin",
            ),
            (
                r"C:\Users\bob C:\Users\alice\x",
                r"%USERPROFILE%%USERPROFILE%\x",
            ),
            (
                r#""C:\Users\bob" "C:\Users\alice\x""#,
                r#""%USERPROFILE%" "%USERPROFILE%\x""#,
            ),
            (r"C:\Users\bob,D:\Users\alice", "%USERPROFILE%%USERPROFILE%"),
            (
                r"C:\Users\bob|\\host\c$\Users\alice",
                r"%USERPROFILE%|\\host\%USERPROFILE%",
            ),
        ] {
            assert_eq!(redact(input), expected, "{input}");
        }
    }

    /// `.` and `..` folders are applied, a `:` suffix and trailing dots or spaces are not part of a
    /// folder's name, and a name reached again through `..` is replaced with the rest.
    #[test]
    fn folders_are_read_the_way_windows_reads_them() {
        for (input, expected) in [
            (r"C:\Users\.\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\.\Users\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\Users\..\Users\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\Windows\..\Users\bob\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\Users\bob\..\alice\x.exe", r"%USERPROFILE%\x.exe"),
            (r"C:\..\..\Users\bob", "%USERPROFILE%"),
            (
                r"C:\Users::$INDEX_ALLOCATION\bob\x.sys",
                r"%USERPROFILE%\x.sys",
            ),
            (
                r"C:\Documents and Settings:$I30:$INDEX_ALLOCATION\bob\x",
                r"%USERPROFILE%\x",
            ),
            (r"C:\Users\bob\..", r"%USERPROFILE%\.."),
        ] {
            assert_eq!(redact(input), expected, "{input}");
        }
        assert_eq!(redact(r"C:\Users\..\Windows\x"), r"C:\Users\..\Windows\x");
    }

    /// A drive root as the machine's root does not hide the fixed roots on the same drive: the name
    /// after the longest root is the one replaced.
    #[test]
    fn a_drive_root_as_the_machine_root_still_replaces_the_name_under_users() {
        for (input, expected) in [
            (r"C:\Users\bob\x.sys", r"%USERPROFILE%\x.sys"),
            (r"D:\Documents and Settings\bob\x", r"%USERPROFILE%\x"),
        ] {
            let root = &input[..3];
            assert_eq!(redact_profile_paths(input, Some(root)), expected, "{input}");
        }
    }

    /// The machine's root is read like a path: trailing dots, repeated separators and `.` do not stop
    /// it matching.
    #[test]
    fn the_machine_root_is_read_the_way_a_path_is() {
        for root in [
            r"D:\Profiles.",
            r"D:\\Profiles\",
            r"D:\.\Profiles",
            r"d:/PROFILES ",
        ] {
            assert_eq!(
                redact_profile_paths(r"D:\Profiles\bob\x", Some(root)),
                r"%USERPROFILE%\x",
                "{root:?}"
            );
        }
    }

    /// A share marker needs the separator before its letter, so one at the very start of a string is
    /// not a drive.
    #[test]
    fn a_share_marker_at_the_start_of_a_string_is_not_a_drive() {
        assert_eq!(redact(r"C$\Users\bob"), r"C$\Users\bob");
    }

    /// Nested values and own traces are redacted with the machine's root too.
    #[test]
    fn ss_view_redacts_own_traces_and_nested_values_under_the_machine_root() {
        let mut report = report();
        report.header.profiles_directory = Some(r"D:\Profiles".to_owned());
        report.own_traces[0].observation.fields.insert(
            "path".to_owned(),
            serde_json::Value::from(format!(r"D:\Profiles\{USER}\Downloads\aeterna-rongroi.exe")),
        );
        if let EvidenceState::Found { observations } = &mut report.evidence[0].state {
            observations[0].fields.insert(
                "paths".to_owned(),
                serde_json::json!([{ "path": format!(r"D:\Profiles\{USER}\a.dll") }]),
            );
        }

        let ss = for_mode(&report, Mode::Ss);

        assert_eq!(
            ss.own_traces[0]
                .observation
                .fields
                .get("path")
                .and_then(serde_json::Value::as_str),
            Some(r"%USERPROFILE%\Downloads\aeterna-rongroi.exe")
        );
        let json = serde_json::to_string(&ss).unwrap();
        assert!(!json.contains(USER), "{json}");
    }

    /// What the app reads outside a view carries no machine root either.
    #[test]
    fn the_shown_header_has_no_profiles_directory() {
        let mut report = report();
        report.header.profiles_directory = Some(r"D:\Profiles".to_owned());
        let header = shown_header(&report);
        assert_eq!(header.profiles_directory, None);
        assert_eq!(header.generated_at, report.header.generated_at);
    }

    /// Every place another path starts ends the one before it, so a string of many share markers
    /// costs work in proportion to its length; a profile folder named like a share marker is still a
    /// name.
    #[test]
    fn a_string_of_many_share_markers_is_read_once() {
        assert_eq!(redact(r"C:\Users\c$\x"), r"%USERPROFILE%\x");
        assert_eq!(
            redact(r"C:\Temp\\host\d$\Users\bob\x"),
            r"C:\Temp\\host\%USERPROFILE%\x"
        );
        let markers = r"\c$".repeat(200_000);
        let started = std::time::Instant::now();
        assert_eq!(redact(&markers), markers);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    fn header() -> ReportHeader {
        ReportHeader {
            schema_version: 1,
            provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
            rules_bundle: BundleInfo {
                schema_version: 1,
                sha256: "0".repeat(64),
                rule_count: 3,
            },
            platform: "windows".to_owned(),
            os_build: None,
            elevated: Some(false),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            boot_time: crate::model::BootTime::default(),
            profiles_directory: None,
            scan_tier: crate::model::ScanTier::Standard,
            anchors: Vec::new(),
        }
    }

    /// One piece of evidence of each shape the two modes treat differently.
    fn evidence() -> Vec<Evidence> {
        let found = Evidence {
            rule_id: "found".to_owned(),
            collector: "fivem_dir".to_owned(),
            strength: Strength::Presence,
            state: EvidenceState::Found {
                observations: vec![Observation {
                    collector: "fivem_dir".to_owned(),
                    fields: BTreeMap::from([(
                        "path".to_owned(),
                        serde_json::Value::from(format!(
                            r"C:\Users\{USER}\AppData\Local\FiveM\FiveM.app\plugins\x.dll"
                        )),
                    )]),
                }],
            },
        };
        let not_found = Evidence {
            rule_id: "not-found".to_owned(),
            collector: "fivem_dir".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::NotFound {
                retention: "7 days".to_owned(),
            },
        };
        // A posture rule that said in `unmeasured_when` that this reason happens on some machines.
        let expected_unmeasured = Evidence {
            rule_id: "posture".to_owned(),
            collector: "posture".to_owned(),
            strength: Strength::Posture,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::AccessDenied,
                expected: true,
            },
        };
        // A reason its rule did not name: something the author did not anticipate stopped the read.
        let unexpected_unmeasured = Evidence {
            rule_id: "unexpected".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::ReadFailed,
                expected: false,
            },
        };
        // A fact about the scan rather than about the machine, whatever the rule declared.
        let not_admin = Evidence {
            rule_id: "not-admin".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::NotAdmin,
                expected: false,
            },
        };
        // A source this program stopped short of: one fact about how far the scan got, like
        // `not_admin`, and never a row of its own (ADR 0030).
        let not_attempted = Evidence {
            rule_id: "not-attempted".to_owned(),
            collector: "evtx".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::NotAttempted,
                expected: true,
            },
        };
        // Declared by its rule and listed anyway: "part of this was read" is a fact about what this
        // program did, not one the author could have anticipated about the machine (ADR 0030).
        let partial = Evidence {
            rule_id: "partial".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Execution,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::Partial,
                expected: true,
            },
        };
        vec![
            found,
            not_found,
            expected_unmeasured,
            unexpected_unmeasured,
            not_admin,
            not_attempted,
            partial,
        ]
    }

    fn report() -> Report {
        Report {
            header: header(),
            evidence: evidence(),
            own_traces: vec![OwnTraceEntry {
                collector: "process".to_owned(),
                observation: Observation {
                    collector: "process".to_owned(),
                    fields: BTreeMap::from([
                        (
                            "name".to_owned(),
                            serde_json::Value::from("aeterna-rongroi.exe"),
                        ),
                        (
                            "path".to_owned(),
                            serde_json::Value::from(format!(
                                r"C:\Users\{USER}\Downloads\aeterna-rongroi.exe"
                            )),
                        ),
                    ]),
                },
            }],
            // What `fivem_dir` saw that no rule matched, written by hand: this report has no bundle.
            unmatched: vec![UnmatchedGroup {
                collector: "fivem_dir".to_owned(),
                observations: vec![Observation {
                    collector: "fivem_dir".to_owned(),
                    fields: BTreeMap::from([(
                        "path".to_owned(),
                        serde_json::Value::from(format!(
                            r"C:\Users\{USER}\AppData\Local\FiveM\FiveM.app\plugins\overlay.dll"
                        )),
                    )]),
                }],
            }],
            timeline_selections: Vec::new(),
            timestamp_fields: BTreeMap::new(),
            discriminators: BTreeMap::new(),
            coverage_fields: BTreeMap::new(),
            unmeasured_sources: Vec::new(),
            sensitive_fields: BTreeMap::new(),
            age_fields: BTreeMap::new(),
            timeline_selectors: BTreeMap::new(),
        }
    }

    #[test]
    fn self_view_shows_everything_unchanged() {
        let report = report();
        let view = for_mode(&report, Mode::SelfCheck);
        assert_eq!(view.evidence, report.evidence);
        assert_eq!(view.hidden, HiddenCounts::default());
    }

    /// A hosts line's address never reaches an SS view, even on a match; its kind does, and Self mode
    /// keeps both (ADR 0054, owner decision 2). Only `net_config`'s field is withheld.
    #[test]
    fn ss_view_withholds_the_hosts_address_and_keeps_its_kind() {
        let observation = |collector: &str| Observation {
            collector: collector.to_owned(),
            fields: BTreeMap::from([
                ("location".to_owned(), serde_json::Value::from("hosts")),
                ("host_name".to_owned(), serde_json::Value::from("fivem.net")),
                ("address".to_owned(), serde_json::Value::from("192.0.2.10")),
                ("address_kind".to_owned(), serde_json::Value::from("public")),
            ]),
        };
        let mut report = report();
        report.evidence = ["net_config", "other"]
            .into_iter()
            .map(|collector| Evidence {
                rule_id: collector.to_owned(),
                collector: collector.to_owned(),
                strength: Strength::Posture,
                state: EvidenceState::Found {
                    observations: vec![observation(collector)],
                },
            })
            .collect();
        let fields = |view: &ReportView, index: usize| match &view.evidence[index].state {
            EvidenceState::Found { observations } => observations[0].fields.clone(),
            state => panic!("expected a match, got {state:?}"),
        };
        let ss = for_mode(&report, Mode::Ss);
        let hosts = fields(&ss, 0);
        assert!(!hosts.contains_key("address"), "{hosts:?}");
        assert_eq!(hosts["address_kind"], "public");
        assert_eq!(hosts["host_name"], "fivem.net");
        assert!(fields(&ss, 1).contains_key("address"));
        let own = for_mode(&report, Mode::SelfCheck);
        assert_eq!(fields(&own, 0)["address"], "192.0.2.10");
    }

    /// A scheduled task's path or a `Run` value's name never reaches an SS view; the service's name,
    /// where the entry is registered and the file it starts do, the file with the profile redacted
    /// (ADR 0060, owner decision 3).
    #[test]
    fn ss_view_withholds_an_autostart_entry_and_keeps_its_file() {
        let mut report = report();
        report.evidence = vec![Evidence {
            rule_id: "autostart".to_owned(),
            collector: "autostart".to_owned(),
            strength: Strength::Posture,
            state: EvidenceState::Found {
                observations: vec![Observation {
                    collector: "autostart".to_owned(),
                    fields: BTreeMap::from([
                        ("location".to_owned(), serde_json::Value::from("task")),
                        (
                            "entry".to_owned(),
                            serde_json::Value::from(r"\Updater-S-1-5-21-1-2-3-1001"),
                        ),
                        (
                            "path".to_owned(),
                            serde_json::Value::from(r"C:\Users\alex\AppData\Local\x.exe"),
                        ),
                    ]),
                }],
            },
        }];
        let fields = |view: &ReportView| match &view.evidence[0].state {
            EvidenceState::Found { observations } => observations[0].fields.clone(),
            state => panic!("expected a match, got {state:?}"),
        };
        let ss = fields(&for_mode(&report, Mode::Ss));
        assert!(!ss.contains_key("entry"), "{ss:?}");
        assert_eq!(ss["location"], "task");
        assert_eq!(ss["path"], r"%USERPROFILE%\AppData\Local\x.exe");
        let own = fields(&for_mode(&report, Mode::SelfCheck));
        assert_eq!(own["entry"], r"\Updater-S-1-5-21-1-2-3-1001");
    }

    #[test]
    fn ss_view_shows_found_and_posture_and_counts_the_rest() {
        let view = for_mode(&report(), Mode::Ss);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert_eq!(ids, ["found", "unexpected", "partial"]);
        assert_eq!(
            view.hidden,
            HiddenCounts {
                not_found: 1,
                unmeasured_expected: 2,
                unmeasured_unexpected: 1,
                unmatched: 1
            }
        );
    }

    /// The whole of what `unmeasured_when` does to a view: a reason the rule named is a number, and
    /// a reason it did not name is a line, because that one says something nobody anticipated
    /// stopped the measurement (ADR 0027).
    #[test]
    fn ss_view_lists_an_unexpected_unmeasured_result_and_counts_an_expected_one() {
        let view = for_mode(&report(), Mode::Ss);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(ids.contains(&"unexpected"), "{ids:?}");
        assert!(!ids.contains(&"posture"), "{ids:?}");
        assert_eq!(view.hidden.unmeasured_expected, 2);
    }

    /// Self mode lists both, as it lists everything else.
    #[test]
    fn self_view_lists_both_the_expected_and_the_unexpected_unmeasured_result() {
        let view = for_mode(&report(), Mode::SelfCheck);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(ids.contains(&"unexpected"), "{ids:?}");
        assert!(ids.contains(&"posture"), "{ids:?}");
        assert_eq!(view.hidden, HiddenCounts::default());
    }

    /// A posture rule is listed in SS mode whatever its state — except when it could not look for a
    /// reason it had itself declared, which is a number about the scan and not a row about the PC.
    #[test]
    fn ss_view_does_not_list_a_posture_rule_that_expected_to_be_unmeasured() {
        let view = for_mode(&report(), Mode::Ss);
        assert!(
            !view.evidence.iter().any(|e| e.rule_id == "posture"),
            "{:?}",
            view.evidence
        );
    }

    /// Missing administrator rights is one fact about the scan that applies to every rule at once,
    /// and the one unmeasured reason with a remedy, so it is stated once above the evidence and
    /// never as a row of its own in SS mode (ADR 0012, ADR 0027).
    #[test]
    fn not_admin_is_a_scope_statement_in_both_modes_and_never_an_ss_row() {
        let report = report();
        assert_eq!(for_mode(&report, Mode::SelfCheck).scope.not_admin, 1);
        let ss = for_mode(&report, Mode::Ss);
        assert_eq!(ss.scope.not_admin, 1);
        assert!(
            !ss.evidence.iter().any(|e| e.rule_id == "not-admin"),
            "{:?}",
            ss.evidence
        );
        // Still accounted for: the hidden counts cover every result the view does not list.
        assert_eq!(ss.hidden.unmeasured_unexpected, 1);
    }

    /// Self mode passes unmatched observations through whole. For a collector that ships without a
    /// rule they are the only place what it saw can be read at all (ADR 0014).
    #[test]
    fn self_view_shows_unmatched_observations() {
        let report = report();
        assert_eq!(
            for_mode(&report, Mode::SelfCheck).unmatched,
            report.unmatched
        );
    }

    /// SS mode's promise is "only what matches a rule, paths redacted". A raw listing of every file
    /// and process name a collector saw would break that promise whatever the redaction, so SS mode
    /// counts unmatched observations and lists none of them (ADR 0014).
    #[test]
    fn ss_view_lists_no_unmatched_observations_and_counts_them() {
        let view = for_mode(&report(), Mode::Ss);
        assert!(view.unmatched.is_empty(), "{:?}", view.unmatched);
        assert_eq!(view.hidden.unmatched, 1);
    }

    /// Own traces are transparency about the tool, not evidence about the machine, so SS mode's
    /// "only matches and posture" filter does not apply to them: hiding "this was us" from the
    /// person watching the screenshare would be less transparent, not more (ADR 0010).
    #[test]
    fn both_views_show_own_traces() {
        let report = report();
        assert_eq!(
            for_mode(&report, Mode::SelfCheck).own_traces,
            report.own_traces
        );
        assert_eq!(for_mode(&report, Mode::Ss).own_traces.len(), 1);
    }

    #[test]
    fn ss_view_redacts_the_path_of_an_own_trace() {
        let view = for_mode(&report(), Mode::Ss);
        let path = view.own_traces[0]
            .observation
            .fields
            .get("path")
            .and_then(serde_json::Value::as_str);
        assert_eq!(path, Some(r"%USERPROFILE%\Downloads\aeterna-rongroi.exe"));
        // The name is not a path and is not touched; PRIVACY.md says so (ADR 0010).
        assert_eq!(
            view.own_traces[0]
                .observation
                .fields
                .get("name")
                .and_then(serde_json::Value::as_str),
            Some("aeterna-rongroi.exe")
        );
    }

    /// The reasons a rule author cannot declare away. Each says the artifact was reachable and that
    /// the read of it did not finish, which is a fact about the scan and not one about the machine,
    /// so SS mode lists them even though the rule named them (ADR 0030).
    #[test]
    fn ss_view_lists_a_partial_result_even_though_its_rule_declared_it() {
        let view = for_mode(&report(), Mode::Ss);
        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(ids.contains(&"partial"), "{ids:?}");
    }

    /// The case ADR 0032 added, from the far side of the gate that now refuses the declaration:
    /// `expected: true` on a `read_failed` result is what an old bundle, or a rule set this build
    /// did not check, still hands the view. It is listed regardless — the guarantee belongs here and
    /// not only in `check-rules`.
    #[test]
    fn ss_view_lists_a_read_failed_result_even_though_its_rule_declared_it() {
        let mut report = report();
        report.evidence = vec![Evidence {
            rule_id: "read-failed".to_owned(),
            collector: "posture".to_owned(),
            strength: Strength::Posture,
            state: EvidenceState::Unmeasured {
                reason: UnmeasuredReason::ReadFailed,
                expected: true,
            },
        }];

        let view = for_mode(&report, Mode::Ss);

        let ids: Vec<&str> = view.evidence.iter().map(|e| e.rule_id.as_str()).collect();
        assert_eq!(ids, ["read-failed"]);
        // Listed, so it is not also counted: every result is in exactly one of the two places. The
        // report's unmatched observations are untouched by this and are counted as they always are.
        assert_eq!(view.hidden.unmeasured_expected, 0);
        assert_eq!(view.hidden.unmeasured_unexpected, 0);
    }

    /// A source the collector never looked at is the same shape as missing administrator rights:
    /// one fact about how far the scan got, stated once above the evidence in both modes and never
    /// as a row of its own (ADR 0030).
    #[test]
    fn not_attempted_is_a_scope_statement_in_both_modes_and_never_an_ss_row() {
        let report = report();
        assert_eq!(for_mode(&report, Mode::SelfCheck).scope.not_attempted, 1);
        let ss = for_mode(&report, Mode::Ss);
        assert_eq!(ss.scope.not_attempted, 1);
        assert!(
            !ss.evidence.iter().any(|e| e.rule_id == "not-attempted"),
            "{:?}",
            ss.evidence
        );
        // Still accounted for: it was declared, so it is one of the expected ones.
        assert_eq!(ss.hidden.unmeasured_expected, 2);
    }

    /// The two questions [`UnmeasuredReason`] answers for a view, asserted on every reason at once
    /// so that one added later cannot quietly default to "ordinary row".
    #[test]
    fn every_reason_says_whether_it_is_a_scope_statement_or_always_listed() {
        use UnmeasuredReason as R;
        for reason in [
            R::NotWindows,
            R::NotOnThisOs,
            R::NotAdmin,
            R::NotAttempted,
            R::AccessDenied,
            R::ServiceDisabled,
            R::SourceAbsent,
            R::SourceEmpty,
            R::Partial,
            R::BudgetSpent,
            R::ReadFailed,
            R::CollectorUnavailable,
            R::OtherVolume,
        ] {
            let scope = reason.is_scope_statement();
            let listed = reason.is_always_listed();
            assert!(
                !(scope && listed),
                "{} is both a scope statement and always listed",
                reason.as_str()
            );
            assert_eq!(
                scope,
                matches!(reason, R::NotAdmin | R::NotAttempted),
                "{}",
                reason.as_str()
            );
            assert_eq!(
                listed,
                matches!(reason, R::Partial | R::BudgetSpent | R::ReadFailed),
                "{}",
                reason.as_str()
            );
        }
    }

    #[test]
    fn ss_view_never_contains_the_user_name() {
        let json = serde_json::to_string(&for_mode(&report(), Mode::Ss)).unwrap();
        assert!(!json.contains(USER), "{json}");
        assert!(json.contains("%USERPROFILE%"));
    }

    /// Three counts of what each view lists, never one number (ADR 0045).
    #[test]
    fn listed_counts_are_the_states_of_what_each_view_lists() {
        let own = for_mode(&report(), Mode::SelfCheck);
        assert_eq!(
            own.listed,
            ListedCounts {
                found: 1,
                not_found: 1,
                unmeasured: 5
            }
        );
        let ss = for_mode(&report(), Mode::Ss);
        assert_eq!(
            ss.listed,
            ListedCounts {
                found: 1,
                not_found: 0,
                unmeasured: 2
            }
        );
    }

    /// In SS mode the listed counts and the hidden counts together account for every rule once.
    #[test]
    fn ss_listed_and_hidden_counts_account_for_every_result() {
        let report = report();
        let view = for_mode(&report, Mode::Ss);
        let listed = view.listed.found + view.listed.not_found + view.listed.unmeasured;
        let hidden = view.hidden.not_found
            + view.hidden.unmeasured_expected
            + view.hidden.unmeasured_unexpected;
        assert_eq!(listed + hidden, report.evidence.len());
        assert_eq!(listed, view.evidence.len());
    }

    fn observed(collector: &str, pairs: &[(&str, &str)]) -> Observation {
        Observation {
            collector: collector.to_owned(),
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), serde_json::Value::from(*v)))
                .collect(),
        }
    }

    /// A report holding one time on each route: a rule's evidence, a timeline selector's selection,
    /// an unmatched observation, a coverage band and an unmeasured place.
    fn timed_report() -> Report {
        let mut report = report();
        report.header.boot_time = crate::model::BootTime::Measured {
            booted_at: "2025-12-31T00:00:00Z".to_owned(),
            seconds_since_boot: 86_400,
        };
        let found = observed(
            "prefetch",
            &[("name", "found.exe"), ("last_run", "2025-12-30T00:00:00Z")],
        );
        report.evidence = vec![Evidence {
            rule_id: "found".to_owned(),
            collector: "prefetch".to_owned(),
            strength: Strength::Tamper,
            state: EvidenceState::Found {
                observations: vec![found],
            },
        }];
        let selected = observed(
            "prefetch",
            &[
                ("name", "FIVEM.EXE"),
                ("last_run", "2025-12-29T00:00:00.5Z"),
                ("path", &format!(r"C:\Users\{USER}\x.pf")),
            ],
        );
        let unselected = observed(
            "prefetch",
            &[
                ("path", &format!(r"C:\Users\{USER}\secret.pf")),
                ("last_run", "2025-12-28T00:00:00Z"),
            ],
        );
        let log = observed(
            "evtx",
            &[
                ("path", r"C:\Windows\System32\winevt\Logs\System.evtx"),
                ("oldest_record_time", "2025-11-01T00:00:00Z"),
                ("newest_record_time", "2025-12-31T12:00:00Z"),
            ],
        );
        report.timeline_selections = vec![crate::model::TimelineSelection {
            selector_id: "selector".to_owned(),
            collector: "prefetch".to_owned(),
            observations: vec![selected.clone()],
        }];
        report.unmatched = vec![
            UnmatchedGroup {
                collector: "prefetch".to_owned(),
                observations: vec![selected, unselected],
            },
            UnmatchedGroup {
                collector: "evtx".to_owned(),
                observations: vec![log],
            },
        ];
        report.timestamp_fields = BTreeMap::from([
            ("prefetch".to_owned(), vec!["last_run".to_owned()]),
            (
                "evtx".to_owned(),
                vec![
                    "newest_record_time".to_owned(),
                    "oldest_record_time".to_owned(),
                ],
            ),
        ]);
        report.coverage_fields = BTreeMap::from([(
            "evtx".to_owned(),
            crate::model::CoverageFields {
                from: "oldest_record_time".to_owned(),
                to: "newest_record_time".to_owned(),
                place: None,
            },
        )]);
        report.unmeasured_sources = vec![UnmeasuredSource {
            collector: "usn".to_owned(),
            place: None,
            reason: UnmeasuredReason::NotAdmin,
        }];
        report
    }

    fn at_and_source(timeline: &Timeline) -> Vec<(String, EntrySource)> {
        timeline
            .entries
            .iter()
            .map(|entry| (entry.at.clone(), entry.source.clone()))
            .collect()
    }

    /// Self mode: every time on every route, oldest first, each observation once — the selected one
    /// as the selector's, not also as an unmatched one.
    #[test]
    fn the_self_timeline_holds_every_time_in_order_and_each_observation_once() {
        let timeline = timeline(&timed_report(), Mode::SelfCheck);
        let selector = EntrySource::Selector {
            selector_id: "selector".to_owned(),
        };
        let evidence = EntrySource::Evidence {
            rule_id: "found".to_owned(),
        };
        assert_eq!(
            at_and_source(&timeline),
            vec![
                ("2025-11-01T00:00:00Z".to_owned(), EntrySource::Observation),
                ("2025-12-28T00:00:00Z".to_owned(), EntrySource::Observation),
                ("2025-12-29T00:00:00.5Z".to_owned(), selector),
                ("2025-12-30T00:00:00Z".to_owned(), evidence),
                ("2025-12-31T00:00:00Z".to_owned(), EntrySource::Anchor),
                ("2025-12-31T12:00:00Z".to_owned(), EntrySource::Observation),
                ("2026-01-01T00:00:00Z".to_owned(), EntrySource::Anchor),
            ]
        );
        assert_eq!(timeline.entries[2].subject.as_deref(), Some("FIVEM.EXE"));
        assert_eq!(timeline.entries[4].field, "boot_time");
        assert_eq!(
            timeline.bands,
            vec![CoverageBand {
                collector: "evtx".to_owned(),
                place: None,
                subject: Some(r"C:\Windows\System32\winevt\Logs\System.evtx".to_owned()),
                from: "2025-11-01T00:00:00Z".to_owned(),
                to: "2025-12-31T12:00:00Z".to_owned(),
            }]
        );
        assert_eq!(timeline.unmeasured.len(), 1);
    }

    /// SS mode: the listed evidence, the selection, the anchors, the band and the unmeasured source —
    /// and nothing an SS view only counts. The unmatched observation nobody selected, with its path,
    /// does not reach it.
    #[test]
    fn the_ss_timeline_shows_only_listed_evidence_selections_anchors_and_bands() {
        let report = timed_report();
        let view = for_mode(&report, Mode::Ss);
        let timeline = &view.timeline;
        let sources: Vec<EntrySource> = timeline
            .entries
            .iter()
            .map(|entry| entry.source.clone())
            .collect();
        assert_eq!(
            sources,
            vec![
                EntrySource::Selector {
                    selector_id: "selector".to_owned()
                },
                EntrySource::Evidence {
                    rule_id: "found".to_owned()
                },
                EntrySource::Anchor,
                EntrySource::Anchor,
            ]
        );
        assert_eq!(timeline.bands.len(), 1);
        assert_eq!(timeline.unmeasured.len(), 1);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("secret.pf"), "{json}");
        assert!(!json.contains("2025-12-28"), "{json}");
        assert!(!json.contains(USER), "{json}");
        // The count is unchanged by the selector: both prefetch observations are still unmatched.
        assert_eq!(view.hidden.unmatched, 3);
    }

    /// The core does not guess which fields are times: a report with no declarations, as every
    /// report before ADR 0051 was, has only the anchors.
    #[test]
    fn without_declared_timestamp_fields_only_the_anchors_are_on_the_timeline() {
        let mut report = timed_report();
        report.timestamp_fields.clear();
        let timeline = timeline(&report, Mode::SelfCheck);
        assert!(
            timeline
                .entries
                .iter()
                .all(|entry| entry.source == EntrySource::Anchor),
            "{timeline:?}"
        );
    }

    /// A band scoped to one place is read only from the observation about that place.
    #[test]
    fn a_band_scoped_to_a_place_comes_from_that_place_only() {
        let mut report = timed_report();
        let journal = observed(
            "usn",
            &[
                ("location", "journal"),
                ("first_seen", "2025-12-01T00:00:00Z"),
                ("last_seen", "2025-12-31T00:00:00Z"),
            ],
        );
        let folder = observed(
            "usn",
            &[
                ("location", "prefetch"),
                ("first_seen", "2025-12-15T00:00:00Z"),
                ("last_seen", "2025-12-16T00:00:00Z"),
            ],
        );
        report.unmatched.push(UnmatchedGroup {
            collector: "usn".to_owned(),
            observations: vec![journal, folder],
        });
        report
            .discriminators
            .insert("usn".to_owned(), "location".to_owned());
        report.coverage_fields.insert(
            "usn".to_owned(),
            crate::model::CoverageFields {
                from: "first_seen".to_owned(),
                to: "last_seen".to_owned(),
                place: Some("journal".to_owned()),
            },
        );
        let timeline = timeline(&report, Mode::SelfCheck);
        let usn: Vec<&CoverageBand> = timeline
            .bands
            .iter()
            .filter(|band| band.collector == "usn")
            .collect();
        assert_eq!(usn.len(), 1, "{usn:?}");
        assert_eq!(usn[0].place.as_deref(), Some("journal"));
        assert_eq!(usn[0].from, "2025-12-01T00:00:00Z");
    }

    /// A report with the change journal's own observation, unmatched, and three `usn` rows: one
    /// found, one not found and one unmeasured, all `context`.
    fn journal_report(journal_times: bool) -> Report {
        let mut report = timed_report();
        let mut journal = vec![("location", "journal")];
        if journal_times {
            journal.push(("first_seen", "2025-12-31T23:21:00Z"));
            journal.push(("last_seen", "2026-01-01T00:00:00Z"));
        }
        report.unmatched.push(UnmatchedGroup {
            collector: "usn".to_owned(),
            observations: vec![observed("usn", &journal)],
        });
        report
            .discriminators
            .insert("usn".to_owned(), "location".to_owned());
        report.coverage_fields.insert(
            "usn".to_owned(),
            crate::model::CoverageFields {
                from: "first_seen".to_owned(),
                to: "last_seen".to_owned(),
                place: Some("journal".to_owned()),
            },
        );
        let row = |rule_id: &str, state| Evidence {
            rule_id: rule_id.to_owned(),
            collector: "usn".to_owned(),
            strength: Strength::Context,
            state,
        };
        report.evidence.extend([
            row(
                "deleted",
                EvidenceState::Found {
                    observations: vec![observed(
                        "usn",
                        &[
                            ("location", "plugins"),
                            ("first_seen", "2025-12-31T23:40:00Z"),
                            ("last_seen", "2025-12-31T23:41:00Z"),
                        ],
                    )],
                },
            ),
            row(
                "renamed",
                EvidenceState::NotFound {
                    retention: "Only the span the change journal still held.".to_owned(),
                },
            ),
            row(
                "elsewhere",
                EvidenceState::Unmeasured {
                    reason: UnmeasuredReason::OtherVolume,
                    expected: true,
                },
            ),
        ]);
        report
    }

    /// Every `usn` row that looked carries the journal's span, in both modes; one that could not
    /// look carries none, and a collector whose coverage names no place (`evtx`) is left alone
    /// (ADR 0047, amendment of 2026-09-30, decision 3).
    #[test]
    fn each_row_of_a_collector_whose_coverage_names_a_place_carries_that_places_span() {
        let report = journal_report(true);
        let span = RowBand::Span {
            from: "2025-12-31T23:21:00Z".to_owned(),
            to: "2026-01-01T00:00:00Z".to_owned(),
        };

        let own = for_mode(&report, Mode::SelfCheck);
        assert_eq!(
            own.row_bands,
            BTreeMap::from([
                ("deleted".to_owned(), span.clone()),
                ("renamed".to_owned(), span.clone()),
            ])
        );

        // SS mode lists the match and counts the rest: `context` not found, and an expected reason.
        let ss = for_mode(&report, Mode::Ss);
        assert_eq!(ss.row_bands, BTreeMap::from([("deleted".to_owned(), span)]));
        assert!(ss.evidence.iter().all(|item| item.rule_id != "renamed"));
    }

    /// A journal read in full that held no record has no span, and the row says so rather than
    /// showing nothing.
    #[test]
    fn a_source_that_held_no_record_gives_its_rows_no_span_rather_than_none() {
        let own = for_mode(&journal_report(false), Mode::SelfCheck);
        assert_eq!(own.row_bands.get("renamed"), Some(&RowBand::NoSpan));
        assert_eq!(own.row_bands.get("deleted"), Some(&RowBand::NoSpan));
        assert_eq!(own.row_bands.get("elsewhere"), None);
    }

    /// A report whose collector's place was never observed — `usn` refused, say — gives no band, and
    /// a view without one serializes as it did before the field existed.
    #[test]
    fn without_the_places_observation_there_is_no_row_band() {
        let mut report = journal_report(true);
        report.unmatched.retain(|group| group.collector != "usn");
        let own = for_mode(&report, Mode::SelfCheck);
        assert!(own.row_bands.is_empty(), "{:?}", own.row_bands);
        let json = serde_json::to_string(&own).unwrap();
        assert!(!json.contains("row_bands"), "{json}");
    }

    #[test]
    fn both_views_carry_the_collector_order() {
        for mode in [Mode::SelfCheck, Mode::Ss] {
            assert_eq!(
                for_mode(&report(), mode).collector_order,
                COLLECTOR_ORDER.map(str::to_owned).to_vec()
            );
        }
    }

    fn number_observation(collector: &str, pairs: &[(&str, serde_json::Value)]) -> Observation {
        Observation {
            collector: collector.to_owned(),
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        }
    }

    fn age(
        oldest: &[&str],
        count: AgeCount,
        rows: AgeRows,
        places: &[&str],
        extra: &[&str],
    ) -> crate::model::AgeFields {
        let owned = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        crate::model::AgeFields {
            oldest: owned(oldest),
            count,
            rows,
            places: owned(places),
            extra: owned(extra),
            first: Vec::new(),
            by_place: Vec::new(),
        }
    }

    /// A report as `scan::run` declares it, with Prefetch read, BAM not read without administrator
    /// rights, two event logs read and one refused, the journal, and `FiveM`'s Legacy install whose logs
    /// were last written on 2026-01-09. The scan ran on 2026-01-10.
    /// What `scan::run` declares for the six collectors ADR 0061 names.
    fn aged_fields() -> BTreeMap<String, crate::model::AgeFields> {
        let field = |name: &str| AgeCount::Field {
            field: name.to_owned(),
        };
        let mut evtx = age(
            &["oldest_record_time"],
            field("entries"),
            AgeRows::PerValue {
                field: "log".to_owned(),
            },
            &[],
            &["size_bytes", "max_size_bytes"],
        );
        evtx.first = vec!["Security.evtx".to_owned(), "System.evtx".to_owned()];
        let mut fivem = age(
            &["earliest_created_at", "earliest_modified_at"],
            field("files"),
            AgeRows::PerPlace,
            &["legacy_logs", "enhanced_server_cache"],
            &["latest_modified_at"],
        );
        fivem.by_place = vec![crate::model::AgePlace {
            place: "enhanced_server_cache".to_owned(),
            oldest: vec!["created_at".to_owned(), "modified_at".to_owned()],
            count: AgeCount::Observations,
            without: Some("folder".to_owned()),
        }];
        BTreeMap::from([
            (
                "prefetch".to_owned(),
                age(
                    &["last_run"],
                    field("entries"),
                    AgeRows::One,
                    &[],
                    &["enable_prefetcher"],
                ),
            ),
            (
                "bam".to_owned(),
                age(&["last_run"], field("entries"), AgeRows::One, &[], &[]),
            ),
            (
                "pca".to_owned(),
                age(
                    &["last_run"],
                    AgeCount::Observations,
                    AgeRows::One,
                    &[],
                    &[],
                ),
            ),
            (
                "usn".to_owned(),
                age(
                    &["first_seen"],
                    field("records"),
                    AgeRows::PerPlace,
                    &["journal"],
                    &["last_seen", "trimmed"],
                ),
            ),
            ("evtx".to_owned(), evtx),
            ("fivem_dir".to_owned(), fivem),
        ])
    }

    /// What the collectors saw on that PC, none of it matched by a rule.
    /// Two event logs read, one refused, and one empty.
    fn aged_logs() -> Vec<Observation> {
        use serde_json::json;
        vec![
            number_observation(
                "evtx",
                &[
                    ("log", json!("System.evtx")),
                    ("entries", json!(40)),
                    ("size_bytes", json!(1_048_576)),
                    ("max_size_bytes", json!(1_052_672)),
                    ("oldest_record_time", json!("2026-01-01T00:00:00Z")),
                ],
            ),
            number_observation(
                "evtx",
                &[
                    ("log", json!("Security.evtx")),
                    ("read", json!("access_denied")),
                ],
            ),
            number_observation(
                "evtx",
                &[("log", json!("Other.evtx")), ("entries", json!(0))],
            ),
            number_observation(
                "evtx",
                &[("log", json!("Busy.evtx")), ("entries", json!(3))],
            ),
        ]
    }

    /// `FiveM` Legacy with a log folder; Enhanced's server cache absent.
    fn aged_fivem() -> Vec<Observation> {
        use serde_json::json;
        vec![
            number_observation(
                "fivem_dir",
                &[
                    ("location", json!("legacy_exe")),
                    (
                        "path",
                        json!(format!(r"C:\Users\{USER}\AppData\Local\FiveM\FiveM.exe")),
                    ),
                ],
            ),
            number_observation(
                "fivem_dir",
                &[
                    ("location", json!("legacy_logs")),
                    ("folder", json!("listed")),
                    ("files", json!(3)),
                    ("earliest_created_at", json!("2025-12-20T00:00:00Z")),
                    ("earliest_modified_at", json!("2025-12-21T00:00:00Z")),
                    ("latest_modified_at", json!("2026-01-09T10:00:00Z")),
                ],
            ),
            number_observation(
                "fivem_dir",
                &[
                    ("location", json!("enhanced_server_cache")),
                    ("folder", json!("absent")),
                ],
            ),
        ]
    }

    fn aged_unmatched() -> Vec<UnmatchedGroup> {
        use serde_json::json;
        let prefetch = vec![
            number_observation(
                "prefetch",
                &[
                    ("name", json!("a.exe")),
                    ("last_run", json!("2025-12-01T08:00:00Z")),
                ],
            ),
            number_observation(
                "prefetch",
                &[
                    ("name", json!("b.exe")),
                    ("last_run", json!("2026-01-05T00:00:00Z")),
                ],
            ),
            number_observation("prefetch", &[("entries", json!(2)), ("files", json!(2))]),
            number_observation(
                "prefetch",
                &[("folder", json!("listed")), ("enable_prefetcher", json!(3))],
            ),
        ];
        let pca = vec![number_observation(
            "pca",
            &[
                ("name", json!("c.exe")),
                ("last_run", json!("2026-01-10T00:00:00Z")),
            ],
        )];
        let evtx = aged_logs();
        let fivem = aged_fivem();
        let usn = vec![number_observation(
            "usn",
            &[
                ("location", json!("journal")),
                ("records", json!(900)),
                ("first_seen", json!("2026-01-10T11:21:00Z")),
                ("last_seen", json!("2026-01-10T12:00:00Z")),
                ("trimmed", json!(true)),
            ],
        )];
        [
            ("prefetch", prefetch),
            ("pca", pca),
            ("evtx", evtx),
            ("usn", usn),
            ("fivem_dir", fivem),
        ]
        .into_iter()
        .map(|(collector, observations)| UnmatchedGroup {
            collector: collector.to_owned(),
            observations,
        })
        .collect()
    }

    fn aged_report() -> Report {
        let mut report = report();
        report.header.generated_at = "2026-01-10T12:00:00Z".to_owned();
        report.header.elevated = Some(false);
        report.evidence = Vec::new();
        report.own_traces = Vec::new();
        report.age_fields = aged_fields();
        report.discriminators = BTreeMap::from([
            ("usn".to_owned(), "location".to_owned()),
            ("fivem_dir".to_owned(), "location".to_owned()),
        ]);
        report.unmatched = aged_unmatched();
        report.unmeasured_sources = vec![
            UnmeasuredSource {
                collector: "bam".to_owned(),
                place: None,
                reason: UnmeasuredReason::NotAdmin,
            },
            // What a refused log gaps for the whole run: the rows keep each log's own answer.
            UnmeasuredSource {
                collector: "evtx".to_owned(),
                place: None,
                reason: UnmeasuredReason::NotAdmin,
            },
        ];
        report.timeline_selectors =
            FIVEM_SELECTORS
                .iter()
                .fold(BTreeMap::new(), |mut held, (collector, id)| {
                    held.entry((*collector).to_owned())
                        .or_insert_with(Vec::new)
                        .push((*id).to_owned());
                    held
                });
        report
    }

    fn state_of_row<'a>(
        ages: &'a TraceAges,
        collector: &str,
        key: Option<&str>,
    ) -> &'a TraceAgeState {
        &ages
            .rows
            .iter()
            .find(|row| {
                row.collector == collector
                    && (key.is_none()
                        || row.place.as_deref() == key
                        || row.subject.as_deref() == key)
            })
            .unwrap_or_else(|| panic!("no row for {collector} {key:?}: {:?}", ages.rows))
            .state
    }

    /// Each source's row: in the collector order, the oldest time with its whole days before the
    /// scan, the count, what is shown beside it; a source not read without administrator rights is
    /// that reason and not a zero; the logs the bundle reads come first and the rest fold (ADR 0061).
    #[test]
    fn trace_ages_state_each_sources_oldest_time_count_and_reason() {
        let ages = trace_ages(&aged_report(), Mode::SelfCheck);
        let order: Vec<(&str, Option<&str>)> = ages
            .rows
            .iter()
            .map(|row| {
                (
                    row.collector.as_str(),
                    row.place.as_deref().or(row.subject.as_deref()),
                )
            })
            .collect();
        assert_eq!(
            order,
            vec![
                ("fivem_dir", Some("legacy_logs")),
                ("fivem_dir", Some("enhanced_server_cache")),
                ("evtx", Some("Security.evtx")),
                ("evtx", Some("System.evtx")),
                ("prefetch", None),
                ("bam", None),
                ("pca", None),
                ("usn", Some("journal")),
            ]
        );
        assert_eq!(
            state_of_row(&ages, "prefetch", None),
            &TraceAgeState::Measured {
                oldest: Some("2025-12-01T08:00:00Z".to_owned()),
                days_before: Some(40),
                count: 2,
                extra: BTreeMap::from([("enable_prefetcher".to_owned(), serde_json::json!(3))]),
            }
        );
        assert_eq!(
            state_of_row(&ages, "bam", None),
            &TraceAgeState::Unmeasured {
                reason: UnmeasuredReason::NotAdmin
            }
        );
        assert_eq!(
            state_of_row(&ages, "evtx", Some("Security.evtx")),
            &TraceAgeState::Unmeasured {
                reason: UnmeasuredReason::NotAdmin
            }
        );
        let TraceAgeState::Measured {
            count,
            extra,
            days_before,
            ..
        } = state_of_row(&ages, "evtx", Some("System.evtx"))
        else {
            panic!("System.evtx was read");
        };
        assert_eq!((*count, *days_before), (40, Some(9)));
        assert_eq!(extra["max_size_bytes"], serde_json::json!(1_052_672));
        assert_eq!(
            ages.folded_logs,
            Some(FoldedLogs {
                collector: "evtx".to_owned(),
                logs: 2,
                with_records: 1,
                not_read: 0,
            })
        );
        assert_eq!(
            state_of_row(&ages, "fivem_dir", Some("enhanced_server_cache")),
            &TraceAgeState::Unmeasured {
                reason: UnmeasuredReason::SourceAbsent
            }
        );
        let TraceAgeState::Measured { oldest, count, .. } =
            state_of_row(&ages, "fivem_dir", Some("legacy_logs"))
        else {
            panic!("the log folder was read");
        };
        assert_eq!(
            (oldest.as_deref(), *count),
            (Some("2025-12-20T00:00:00Z"), 3)
        );
        let TraceAgeState::Measured {
            days_before, extra, ..
        } = state_of_row(&ages, "usn", Some("journal"))
        else {
            panic!("the journal was read");
        };
        assert_eq!(*days_before, Some(0));
        assert_eq!(extra["trimmed"], serde_json::json!(true));
        // SS mode shows the same section: an age names no program and no file.
        assert_eq!(for_mode(&aged_report(), Mode::Ss).trace_ages, ages);
    }

    /// Enhanced's server cache is counted and dated by its server folders, not by the folder that
    /// holds them.
    #[test]
    fn the_server_cache_row_counts_server_folders() {
        use serde_json::json;
        let mut report = aged_report();
        let group = report
            .unmatched
            .iter_mut()
            .find(|group| group.collector == "fivem_dir")
            .unwrap();
        group
            .observations
            .retain(|observation| observation.fields["location"] != json!("enhanced_server_cache"));
        group.observations.extend([
            number_observation(
                "fivem_dir",
                &[
                    ("location", json!("enhanced_server_cache")),
                    ("folder", json!("listed")),
                    ("files", json!(0)),
                    ("created_at", json!("2020-01-01T00:00:00Z")),
                ],
            ),
            number_observation(
                "fivem_dir",
                &[
                    ("location", json!("enhanced_server_cache")),
                    ("created_at", json!("2025-12-25T00:00:00Z")),
                    ("modified_at", json!("2026-01-02T00:00:00Z")),
                ],
            ),
            number_observation(
                "fivem_dir",
                &[
                    ("location", json!("enhanced_server_cache")),
                    ("created_at", json!("2025-12-28T00:00:00Z")),
                    ("modified_at", json!("2026-01-03T00:00:00Z")),
                ],
            ),
        ]);
        let ages = trace_ages(&report, Mode::SelfCheck);
        let TraceAgeState::Measured { oldest, count, .. } =
            state_of_row(&ages, "fivem_dir", Some("enhanced_server_cache"))
        else {
            panic!("the server cache was read");
        };
        assert_eq!(
            (oldest.as_deref(), *count),
            (Some("2025-12-25T00:00:00Z"), 2)
        );
    }

    /// When Windows last started first, then each header anchor, with whole days before the scan's
    /// UTC date; an unmeasured anchor keeps its reason (ADR 0061).
    #[test]
    fn anchors_are_boot_time_then_the_header_anchors_in_days() {
        use crate::model::{Anchor, AnchorKind};
        let mut report = aged_report();
        report.header.boot_time = BootTime::Measured {
            booted_at: "2026-01-07T00:00:00Z".to_owned(),
            seconds_since_boot: 302_400,
        };
        report.header.anchors = vec![
            Anchor {
                anchor: AnchorKind::InstallDate,
                state: AnchorState::Measured {
                    on: "2025-11-11".to_owned(),
                    source: "HKLM".to_owned(),
                    kept: None,
                },
            },
            Anchor {
                anchor: AnchorKind::UsnJournalCreated,
                state: AnchorState::Unmeasured {
                    reason: UnmeasuredReason::NotAdmin,
                },
            },
        ];
        let ages = trace_ages(&report, Mode::Ss);
        assert_eq!(
            ages.anchors,
            vec![
                AnchorAge {
                    anchor: "boot_time".to_owned(),
                    state: AnchorAgeState::Measured {
                        on: "2026-01-07T00:00:00Z".to_owned(),
                        days_before: 3,
                        source: None,
                        kept: None,
                    },
                },
                AnchorAge {
                    anchor: "install_date".to_owned(),
                    state: AnchorAgeState::Measured {
                        on: "2025-11-11".to_owned(),
                        days_before: 60,
                        source: Some("HKLM".to_owned()),
                        kept: None,
                    },
                },
                AnchorAge {
                    anchor: "usn_journal_created".to_owned(),
                    state: AnchorAgeState::Unmeasured {
                        reason: UnmeasuredReason::NotAdmin,
                    },
                },
            ]
        );
    }

    fn prefetch_group(report: &mut Report) -> &mut Vec<Observation> {
        &mut report
            .unmatched
            .iter_mut()
            .find(|group| group.collector == "prefetch")
            .unwrap()
            .observations
    }

    /// ADR 0061's statements among the cross-source statements, leaving out the session statements.
    fn records(report: &Report) -> Vec<RecordsStatement> {
        cross_source(report, Mode::SelfCheck)
            .into_iter()
            .filter_map(|statement| match statement {
                CrossSourceStatement::FivemAndRecords(statement) => Some(statement),
                CrossSourceStatement::Session(_) => None,
            })
            .collect()
    }

    fn line_of(statement: &RecordsStatement, collector: &str) -> SourceLineKind {
        statement
            .sources
            .iter()
            .find(|source| source.collector == collector)
            .unwrap()
            .line
            .clone()
    }

    /// Prefetch was read, holds no `FiveM` name, and reaches back before `FiveM`'s logs were last written:
    /// the statement is shown, BAM is "not read" rather than "no entry", and PCA, which holds nothing as
    /// old, could not show it (ADR 0061 section 3).
    #[test]
    fn the_statement_shows_when_a_readable_source_reaches_back_to_fivems_last_write() {
        let report = aged_report();
        let statements = cross_source(&report, Mode::SelfCheck);
        let records = records(&report);
        let [statement] = records.as_slice() else {
            panic!("{statements:?}");
        };
        assert_eq!(statement.fivem.editions, vec!["legacy".to_owned()]);
        assert_eq!(
            statement.fivem.folders_written.as_deref(),
            Some("2026-01-09")
        );
        assert_eq!(statement.fivem.folders_days_before, Some(1));
        assert_eq!(
            line_of(statement, "prefetch"),
            SourceLineKind::NoEntry {
                entries: 2,
                oldest: "2025-12-01".to_owned(),
                days_before: 40,
            }
        );
        assert_eq!(
            line_of(statement, "bam"),
            SourceLineKind::NotRead {
                reason: UnmeasuredReason::NotAdmin
            }
        );
        assert_eq!(
            line_of(statement, "pca"),
            SourceLineKind::CouldNotShow { entries: 1 }
        );
        // In SS mode too: it holds no path and no name.
        let ss = for_mode(&report, Mode::Ss);
        assert_eq!(ss.cross_source, statements);
        let json = serde_json::to_string(&ss.cross_source).unwrap();
        assert!(!json.contains(USER), "{json}");
    }

    /// A `FiveM` name selected in Prefetch: its line says so, and with BAM not read no source is left to
    /// make the statement.
    #[test]
    fn no_statement_when_the_readable_source_holds_a_fivem_entry() {
        let mut report = aged_report();
        let selected = observed(
            "prefetch",
            &[("name", "FiveM.exe"), ("last_run", "2026-01-08T00:00:00Z")],
        );
        report.timeline_selections = vec![crate::model::TimelineSelection {
            selector_id: FIVEM_SELECTORS[0].1.to_owned(),
            collector: "prefetch".to_owned(),
            observations: vec![selected],
        }];
        assert_eq!(records(&report), vec![]);
        assert_eq!(
            source_line(
                &report,
                "prefetch",
                "2026-01-09T10:00:00Z".parse().unwrap(),
                scan_time(&report).unwrap()
            ),
            SourceLineKind::Selected {
                entries: 1,
                latest: "2026-01-08".to_owned(),
            }
        );
    }

    /// Each condition that is not met leaves no statement: Prefetch reaching back less far than
    /// `FiveM`'s last write, Prefetch switched off, PCA alone, no `FiveM`, and no `FiveM` selector in the
    /// bundle.
    #[test]
    fn no_statement_when_any_condition_fails() {
        use serde_json::json;

        // Prefetch's oldest is after FiveM's last write: it could not show it.
        let mut later = aged_report();
        for observation in prefetch_group(&mut later) {
            if observation.fields.contains_key("last_run") {
                observation
                    .fields
                    .insert("last_run".to_owned(), json!("2026-01-09T11:00:00Z"));
            }
        }
        assert_eq!(records(&later), vec![]);
        assert_eq!(
            source_line(
                &later,
                "prefetch",
                "2026-01-09T10:00:00Z".parse().unwrap(),
                scan_time(&later).unwrap()
            ),
            SourceLineKind::CouldNotShow { entries: 2 }
        );

        // Prefetch switched off.
        let mut off = aged_report();
        off.unmeasured_sources.push(UnmeasuredSource {
            collector: "prefetch".to_owned(),
            place: None,
            reason: UnmeasuredReason::ServiceDisabled,
        });
        assert_eq!(records(&off), vec![]);
        assert_eq!(
            source_line(
                &off,
                "prefetch",
                "2026-01-09T10:00:00Z".parse().unwrap(),
                scan_time(&off).unwrap()
            ),
            SourceLineKind::SwitchedOff
        );

        // Only PCA reaches back: never a statement on its own.
        let mut pca_only = later.clone();
        let pca = pca_only
            .unmatched
            .iter_mut()
            .find(|group| group.collector == "pca")
            .unwrap();
        pca.observations = vec![observed(
            "pca",
            &[("name", "c.exe"), ("last_run", "2025-06-01T00:00:00Z")],
        )];
        assert_eq!(records(&pca_only), vec![]);

        // No FiveM.exe and no server cache folder.
        let mut no_fivem = aged_report();
        let fivem = no_fivem
            .unmatched
            .iter_mut()
            .find(|group| group.collector == "fivem_dir")
            .unwrap();
        fivem
            .observations
            .retain(|observation| observation.fields["location"] != json!("legacy_exe"));
        assert_eq!(records(&no_fivem), vec![]);

        // A bundle without FiveM's selectors on BAM.
        let mut no_selectors = aged_report();
        no_selectors.timeline_selectors.remove("bam");
        assert_eq!(records(&no_selectors), vec![]);
    }

    /// The selectors the statement names are the ones the rules tree holds, on the collectors it says.
    #[test]
    fn the_fivem_selectors_are_in_the_embedded_bundle() {
        let bundle = crate::bundle::Bundle::embedded().unwrap();
        for (collector, id) in FIVEM_SELECTORS {
            let rule = bundle
                .rules()
                .iter()
                .map(|sourced| &sourced.rule)
                .find(|rule| rule.id == id)
                .unwrap_or_else(|| panic!("{id} is not in the bundle"));
            assert!(rule.is_timeline_selector(), "{id}");
            assert_eq!(rule.collector, collector, "{id}");
            assert!(rule.match_fields().any(|field| field == "name"), "{id}");
        }
    }

    // ---- ADR 0062: the session statement ----

    fn session_report(
        observations: Vec<Observation>,
        unread: &[(&str, UnmeasuredReason)],
    ) -> Report {
        let mut report = report();
        report.header.generated_at = "2026-01-10T12:00:00Z".to_owned();
        report.evidence = Vec::new();
        report.own_traces = Vec::new();
        report.discriminators = BTreeMap::from([("fivem_dir".to_owned(), "location".to_owned())]);
        let mut groups: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
        for observation in observations {
            groups
                .entry(observation.collector.clone())
                .or_default()
                .push(observation);
        }
        report.unmatched = groups
            .into_iter()
            .map(|(collector, observations)| UnmatchedGroup {
                collector,
                observations,
            })
            .collect();
        report.unmeasured_sources = unread
            .iter()
            .map(|(collector, reason)| UnmeasuredSource {
                collector: (*collector).to_owned(),
                place: None,
                reason: *reason,
            })
            .collect();
        report
    }

    fn run(collector: &str, name: &str, edition: &str, field: &str, at: &str) -> Observation {
        observed(
            collector,
            &[("name", name), ("fivem_edition", edition), (field, at)],
        )
    }

    fn folder(location: &str, pairs: &[(&str, serde_json::Value)]) -> Observation {
        let mut fields = vec![
            ("location", serde_json::json!(location)),
            ("folder", serde_json::json!("listed")),
        ];
        fields.extend(pairs.iter().cloned());
        number_observation("fivem_dir", &fields)
    }

    fn sessions_of(report: &Report) -> Vec<SessionStatement> {
        cross_source(report, Mode::SelfCheck)
            .into_iter()
            .filter_map(|statement| match statement {
                CrossSourceStatement::Session(session) => Some(session),
                CrossSourceStatement::FivemAndRecords(_) => None,
            })
            .collect()
    }

    fn known(
        statement: &SessionStatement,
    ) -> (
        &SessionStart,
        &SessionEnd,
        Option<Duration>,
        &[SessionLine],
        &[String],
    ) {
        match &statement.state {
            SessionState::Known {
                start,
                end,
                before_scan,
                lines,
                causes,
            } => (start, end, *before_scan, lines, causes),
            SessionState::NotKnown { .. } => panic!("{statement:?}"),
        }
    }

    fn minutes(amount: i64) -> Duration {
        Duration {
            amount,
            unit: DurationUnit::Minutes,
        }
    }

    fn compared(relation: Relation, duration: Duration) -> Comparison {
        Comparison { relation, duration }
    }

    fn line(lines: &[SessionLine], source: &str, variant: Option<&str>) -> LineState {
        lines
            .iter()
            .find(|line| line.source == source && line.variant.as_deref() == variant)
            .unwrap_or_else(|| panic!("{source} {variant:?} in {lines:?}"))
            .state
            .clone()
    }

    /// A Legacy session read elevated: Prefetch's `FiveM.exe` gives the start, BAM's the end, and each
    /// source is compared with the start only; the index of each launch mode takes its own form, and a
    /// `db` that could not be listed reads "not read: the folder could not be listed" (decision 2ก).
    #[test]
    fn a_legacy_session_compares_each_source_with_its_start() {
        let report = session_report(legacy_session(), &[]);
        let sessions = sessions_of(&report);
        let [legacy] = sessions.as_slice() else {
            panic!("{sessions:?}");
        };
        legacy_session_reads_as_read(legacy);
    }

    /// The records and folders of [`a_legacy_session_compares_each_source_with_its_start`].
    fn legacy_session() -> Vec<Observation> {
        use serde_json::json;
        vec![
            run(
                "prefetch",
                "fivem.exe",
                "legacy",
                "last_run",
                "2026-01-10T10:00:00Z",
            ),
            // GTA V's own executable is never an anchor, even with an edition.
            run(
                "prefetch",
                "gta5.exe",
                "legacy",
                "last_run",
                "2026-01-10T11:00:00Z",
            ),
            run(
                "bam",
                "FiveM.exe",
                "legacy",
                "last_run",
                "2026-01-10T10:30:00Z",
            ),
            folder(
                "legacy_logs",
                &[
                    ("files", json!(3)),
                    ("latest_created_at", json!("2026-01-10T10:00:30Z")),
                    ("latest_modified_at", json!("2026-01-10T10:25:00Z")),
                ],
            ),
            folder(
                "legacy_cache",
                &[
                    ("files", json!(9)),
                    ("latest_modified_at", json!("2026-01-09T09:00:00Z")),
                ],
            ),
            folder(
                "legacy_server_cache",
                &[
                    ("variant", json!("default")),
                    ("files", json!(4)),
                    ("earliest_created_at", json!("2025-10-01T00:00:00Z")),
                    ("index_created_at", json!("2025-12-20T00:00:00Z")),
                    ("index_files", json!(2)),
                    ("index_latest_modified_at", json!("2026-01-10T10:01:00Z")),
                ],
            ),
            folder(
                "legacy_server_cache",
                &[
                    ("variant", json!("priv")),
                    ("files", json!(1)),
                    ("index_created_at", json!("2025-12-21T00:00:00Z")),
                    ("index_modified_at", json!("2026-01-10T10:01:00Z")),
                ],
            ),
            folder(
                "legacy_server_cache",
                &[
                    ("variant", json!("fxdk")),
                    ("files", json!(0)),
                    ("index_created_at", json!("2025-12-22T00:00:00Z")),
                    ("index_files", json!(0)),
                ],
            ),
        ]
    }

    fn legacy_session_reads_as_read(legacy: &SessionStatement) {
        assert_eq!(legacy.edition, "legacy");
        let (start, end, before_scan, lines, causes) = known(legacy);
        assert_eq!(
            *start,
            SessionStart::Prefetch {
                at: "2026-01-10T10:00:00Z".to_owned(),
                name: AnchorName::FivemExe
            }
        );
        assert_eq!(
            *end,
            SessionEnd::Bam {
                at: "2026-01-10T10:30:00Z".to_owned()
            }
        );
        assert_eq!(
            before_scan,
            Some(Duration {
                amount: 1,
                unit: DurationUnit::Hours
            })
        );
        assert_eq!(
            line(lines, "legacy_logs", None),
            LineState::Compared {
                created: Some(compared(Relation::AfterStart, minutes(0))),
                written: compared(Relation::AfterStart, minutes(25)),
            }
        );
        assert_eq!(
            line(lines, "legacy_cache", None),
            LineState::Compared {
                created: None,
                written: compared(
                    Relation::BeforeStart,
                    Duration {
                        amount: 25,
                        unit: DurationUnit::Hours
                    }
                ),
            }
        );
        legacy_index_lines_read_as_read(lines, causes);
    }

    fn legacy_index_lines_read_as_read(lines: &[SessionLine], causes: &[String]) {
        assert_eq!(
            line(lines, "legacy_resource_index", Some("default")),
            LineState::Compared {
                created: None,
                written: compared(Relation::AfterStart, minutes(1)),
            }
        );
        assert_eq!(
            line(lines, "legacy_resource_index", Some("priv")),
            LineState::NotListed
        );
        assert_eq!(
            line(lines, "legacy_resource_index", Some("fxdk")),
            LineState::NoFile
        );
        // A launch source: no end cause.
        assert_eq!(causes[0], "standing_still");
        assert!(!causes.iter().any(|cause| cause == "ended_abruptly"));
    }

    /// The margin is ten minutes before the start: nine minutes before reads "after" with nothing to
    /// count, eleven reads "before".
    #[test]
    fn the_margin_is_ten_minutes_before_the_start() {
        let start: jiff::Timestamp = "2026-01-10T10:00:00Z".parse().unwrap();
        let at = |text: &str| text.parse::<jiff::Timestamp>().unwrap();
        assert_eq!(
            session::against_start(at("2026-01-10T09:51:00Z"), start),
            compared(Relation::AfterStart, minutes(0))
        );
        assert_eq!(
            session::against_start(at("2026-01-10T09:49:00Z"), start),
            compared(Relation::BeforeStart, minutes(11))
        );
        assert_eq!(
            Duration::of_seconds(3 * 86_400 + 5),
            Duration {
                amount: 3,
                unit: DurationUnit::Days
            }
        );
    }

    /// An Enhanced session: its log folder is a launch source compared with the start, and its latest
    /// write with the end too. Its per-server cache is not compared (owner decision 12), so there is no
    /// join line and no join cause; the end cause follows the first. `GTA5_Enhanced.exe` is never an
    /// anchor, and the 100-nanosecond fractions Prefetch and BAM keep are not printed.
    #[test]
    fn an_enhanced_session_compares_its_logs_with_the_end_too() {
        use serde_json::json;
        let mut observations = vec![
            run(
                "prefetch",
                "FiveM.exe",
                "enhanced",
                "last_run",
                "2026-01-10T09:00:00.2231407Z",
            ),
            run(
                "prefetch",
                "GTA5_Enhanced.exe",
                "enhanced",
                "last_run",
                "2026-01-10T09:02:00Z",
            ),
            run(
                "bam",
                "FiveM.exe",
                "enhanced",
                "last_run",
                "2026-01-10T10:00:00.9999999Z",
            ),
            run(
                "bam",
                "GTA5_Enhanced.exe",
                "enhanced",
                "last_run",
                "2026-01-10T11:00:00Z",
            ),
            folder(
                "enhanced_logs",
                &[
                    ("files", json!(33)),
                    ("latest_created_at", json!("2026-01-10T09:00:04Z")),
                    ("latest_modified_at", json!("2026-01-10T09:30:00Z")),
                ],
            ),
            folder(
                "enhanced_server_cache",
                &[
                    ("files", json!(0)),
                    ("latest_modified_at", json!("2025-12-01T00:00:00Z")),
                ],
            ),
        ];
        observations.push(number_observation(
            "fivem_dir",
            &[
                ("location", json!("enhanced_server_cache")),
                ("modified_at", json!("2026-01-10T09:05:00Z")),
            ],
        ));
        let report = session_report(observations, &[]);
        let sessions = sessions_of(&report);
        let [enhanced] = sessions.as_slice() else {
            panic!("{sessions:?}");
        };
        assert_eq!(enhanced.edition, "enhanced");
        let (start, end, _, lines, causes) = known(enhanced);
        assert!(matches!(start, SessionStart::Prefetch { at, .. } if at == "2026-01-10T09:00:00Z"));
        assert_eq!(
            *end,
            SessionEnd::Bam {
                at: "2026-01-10T10:00:00Z".to_owned()
            }
        );
        assert_eq!(
            line(lines, "enhanced_logs", None),
            LineState::Compared {
                created: Some(compared(Relation::AfterStart, minutes(0))),
                written: compared(Relation::BeforeEnd, minutes(30)),
            }
        );
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(
            causes[..2],
            ["standing_still", "ended_abruptly"].map(str::to_owned)
        );
    }

    /// A BAM time earlier than the start is not this run's end: "not recorded", and the age is from the
    /// start. A source not there and a place not read keep their own lines.
    #[test]
    fn a_bam_time_before_the_start_is_not_the_end() {
        use serde_json::json;
        let mut report = session_report(
            vec![
                run(
                    "prefetch",
                    "FiveM.exe",
                    "legacy",
                    "last_run",
                    "2026-01-10T10:00:00Z",
                ),
                run(
                    "bam",
                    "FiveM_b3095_GTAProcess.exe",
                    "legacy",
                    "last_run",
                    "2026-01-09T10:00:00Z",
                ),
                folder("legacy_logs", &[("files", json!(0))]),
            ],
            &[],
        );
        report.unmeasured_sources.push(UnmeasuredSource {
            collector: "fivem_dir".to_owned(),
            place: Some("legacy_cache".to_owned()),
            reason: UnmeasuredReason::AccessDenied,
        });
        let sessions = sessions_of(&report);
        let (_, end, before_scan, lines, _) = known(&sessions[0]);
        assert_eq!(*end, SessionEnd::NotRecorded);
        assert_eq!(
            before_scan,
            Some(Duration {
                amount: 2,
                unit: DurationUnit::Hours
            })
        );
        assert_eq!(line(lines, "legacy_logs", None), LineState::NoFile);
        assert_eq!(
            line(lines, "legacy_cache", None),
            LineState::NotRead {
                reason: UnmeasuredReason::AccessDenied
            }
        );
        assert_eq!(
            line(lines, "legacy_resource_index", None),
            LineState::NotThere
        );
    }

    /// Under a limited token: a running Legacy client gives the start and "still running"; Enhanced,
    /// present and not running, is "not known" — never compared with the scan's time. Nothing running
    /// and nothing present: no statement.
    #[test]
    fn a_limited_scan_uses_the_running_process_and_says_not_known_otherwise() {
        let unread = [
            ("prefetch", UnmeasuredReason::NotAdmin),
            ("bam", UnmeasuredReason::NotAdmin),
        ];
        let observations = vec![
            run(
                "process",
                "FiveM.exe",
                "legacy",
                "started_at",
                "2026-01-10T11:40:00Z",
            ),
            run(
                "process",
                "FiveM_b3095_GTAProcess.exe",
                "legacy",
                "started_at",
                "2026-01-10T11:41:00Z",
            ),
            observed(
                "fivem_dir",
                &[
                    ("location", "enhanced_exe"),
                    (
                        "path",
                        r"C:\Users\fixtureuser\AppData\Local\FiveM for GTAV Enhanced\FiveM.exe",
                    ),
                ],
            ),
        ];
        let report = session_report(observations.clone(), &unread);
        let sessions = sessions_of(&report);
        let [legacy, enhanced] = sessions.as_slice() else {
            panic!("{sessions:?}");
        };
        let (start, end, before_scan, lines, _) = known(legacy);
        assert_eq!(
            *start,
            SessionStart::Process {
                at: "2026-01-10T11:40:00Z".to_owned(),
                name: AnchorName::FivemExe
            }
        );
        assert_eq!(*end, SessionEnd::StillRunning);
        assert_eq!(before_scan, None);
        assert_eq!(line(lines, "legacy_logs", None), LineState::NotThere);
        assert_eq!(
            enhanced.state,
            SessionState::NotKnown {
                prefetch: UnmeasuredReason::NotAdmin,
                bam: UnmeasuredReason::NotAdmin
            }
        );
        let ss = serde_json::to_string(&for_mode(&report, Mode::Ss).cross_source).unwrap();
        assert!(!ss.contains(USER), "{ss}");

        let nothing = session_report(observations[2..].to_vec(), &unread);
        assert_eq!(sessions_of(&nothing).len(), 1);
        let absent = session_report(Vec::new(), &unread);
        assert_eq!(sessions_of(&absent), vec![]);
    }

    /// Prefetch switched off with BAM read: the start says so, Legacy has nothing to compare, and
    /// Enhanced's log folder is compared with the end alone. Read, with nothing of an edition: no
    /// statement for it.
    #[test]
    fn prefetch_switched_off_leaves_the_end_comparison() {
        use serde_json::json;
        let report = session_report(
            vec![
                // A stale record of a switched-off Prefetch is not this run's start.
                run(
                    "prefetch",
                    "FiveM.exe",
                    "enhanced",
                    "last_run",
                    "2025-06-01T00:00:00Z",
                ),
                run(
                    "bam",
                    "FiveM.exe",
                    "enhanced",
                    "last_run",
                    "2026-01-10T10:00:00Z",
                ),
                folder(
                    "enhanced_logs",
                    &[
                        ("files", json!(2)),
                        ("latest_created_at", json!("2026-01-10T09:00:00Z")),
                        ("latest_modified_at", json!("2026-01-10T09:59:00Z")),
                    ],
                ),
            ],
            &[("prefetch", UnmeasuredReason::ServiceDisabled)],
        );
        let sessions = sessions_of(&report);
        let [enhanced] = sessions.as_slice() else {
            panic!("{sessions:?}");
        };
        let (start, _, _, lines, causes) = known(enhanced);
        assert_eq!(*start, SessionStart::SwitchedOff);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(
            line(lines, "enhanced_logs", None),
            LineState::Compared {
                created: None,
                written: compared(Relation::NearEnd, minutes(1)),
            }
        );
        assert!(causes.iter().any(|cause| cause == "ended_abruptly"));

        let nothing = session_report(
            vec![run(
                "prefetch",
                "other.exe",
                "legacy",
                "last_run",
                "2026-01-10T10:00:00Z",
            )],
            &[],
        );
        assert_eq!(sessions_of(&nothing), vec![]);
    }
}
