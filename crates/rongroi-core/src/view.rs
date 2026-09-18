// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a Self or SS view may show. Privacy is decided here, not in the UI (AGENTS.md hard rule 5).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::model::{
    BootTime, Evidence, EvidenceState, Mode, Observation, OwnTraceEntry, Report, ReportHeader,
    Strength, UnmatchedGroup, UnmeasuredReason, UnmeasuredSource,
};

/// The order collectors are shown in, by both front ends: the rows of one collector together, and
/// entries of the timeline that carry the same time (ADR 0045, ADR 0051). A collector not named here
/// follows the named ones.
pub const COLLECTOR_ORDER: [&str; 10] = [
    "posture",
    "driver_service",
    "fivem_dir",
    "net_config",
    "process",
    "evtx",
    "prefetch",
    "bam",
    "pca",
    "usn",
];

/// Observation fields SS mode never shows, by collector, even on a match (ADR 0054).
///
/// A hosts line's address can name the player's own server; its kind, which `net_config` emits
/// beside it as `address_kind`, is what separates a blocklist from a redirect and is what SS mode
/// shows in its place (owner decision 2).
pub const SS_WITHHELD_FIELDS: [(&str, &str); 1] = [("net_config", "address")];

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
            timeline: timeline(report, mode),
            collector_order: collector_order(),
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
                timeline: timeline(report, mode),
                collector_order: collector_order(),
            }
        }
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
    let observations = report
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
        );
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

    #[test]
    fn both_views_carry_the_collector_order() {
        for mode in [Mode::SelfCheck, Mode::Ss] {
            assert_eq!(
                for_mode(&report(), mode).collector_order,
                COLLECTOR_ORDER.map(str::to_owned).to_vec()
            );
        }
    }
}
