// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What a Self or SS view may show. Privacy is decided here, not in the UI (AGENTS.md hard rule 5).

use serde::{Deserialize, Serialize};

use crate::model::{
    Evidence, EvidenceState, Mode, OwnTraceEntry, Report, ReportHeader, Strength, UnmatchedGroup,
    UnmeasuredReason,
};

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
            }
        }
    }
}

fn redacted(item: &Evidence, machine_root: Option<&MachineRoot>) -> Evidence {
    let mut item = item.clone();
    if let EvidenceState::Found { observations } = &mut item.state {
        for observation in observations {
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
/// The path ends at the end of `bytes`, at a byte no Windows file name holds, or at an ASCII letter
/// followed by `:` and a separator, which starts the next drive-rooted path. Any other `:` stays in its
/// segment: past the drive it can only name a stream.
fn segments(bytes: &[u8], at: usize) -> Vec<(usize, usize)> {
    let mut segments = Vec::new();
    let mut start = at;
    let mut j = at;
    while j < bytes.len() {
        let byte = bytes[j];
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

    /// The machine's root is tried before a fixed root it could share a first folder with, so the
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
        }
    }

    #[test]
    fn self_view_shows_everything_unchanged() {
        let report = report();
        let view = for_mode(&report, Mode::SelfCheck);
        assert_eq!(view.evidence, report.evidence);
        assert_eq!(view.hidden, HiddenCounts::default());
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
}
