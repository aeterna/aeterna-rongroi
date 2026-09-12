// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What the Background Activity Moderator recorded about programs that ran.
//!
//! BAM keeps one key per user account under
//! `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`, and inside each of them one value
//! per executable: **the value's name is the executable's path and the value's data is the artifact**
//! (`rongroi_parsers::bam`). The collector enumerates the account keys and their value names, reads
//! each value's bytes through the `Host` and hands them to that parser; it decodes nothing itself
//! (ADR 0013, ADR 0022).
//!
//! No rule reads this collector (ADR 0023), so what it sees is listed in Self mode as unmatched
//! observations and counted, never listed, in SS mode (ADR 0014).
//!
//! # The account is never reported, and the path usually is not either
//!
//! - **The SID is withheld whole**, and no part of it goes out: not the SID, not a hash of it, not
//!   its last segment, not an index invented per run. It names one account *and* — through the
//!   installation identifier in the middle of it — one machine, which is the linkage ADR 0021
//!   refused to create for a volume serial number. What is reported is how many accounts had
//!   records, which is a count and not an identifier.
//! - **A path is emitted only when it begins with a drive letter**, the one shape
//!   `rongroi_core::view::redact_user_paths` can reach, exactly as `pca` decides it. BAM is expected
//!   to spell paths in the `\Device\HarddiskVolumeN\…` form — unverified, see ADR 0023 — and such a
//!   path carries `\Users\<account>\` with no drive letter in front of it, so it would reach an SS
//!   viewer unredacted while the code around it says paths are redacted.
//! - **The undecoded tail of a value is never emitted**, under any name. `rongroi_parsers::bam`
//!   keeps bytes 12.. verbatim and gives them no meaning; naming them here would put a guess into
//!   evidence a server admin is asked to trust (ADR 0013). How many bytes the value held is
//!   reported, because whether a value is still the documented 24 is the first thing ADR 0013 says
//!   to check on a current build.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};
use rongroi_parsers::bam::{self, BamEntry};
use rongroi_parsers::error::ParseError;

use crate::failure::{read_failure, reason_for};
use crate::paths::{UNREDACTABLE_FORM, file_name, is_drive_rooted};
use crate::{Collector, Field};

/// The key holding one subkey per user account that BAM has recorded anything for.
pub const USER_SETTINGS_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";

const ID: &str = "bam";

/// Why the account a record belongs to is not in the report, as the account observation states it.
const SID_WITHHELD: &str = "per_user_identifier";

/// Every reason this collector gives for not having looked (`Collector::unmeasured_reasons`).
///
/// The BAM key is not there; it is there and holds no record; some of its values decoded and some
/// did not; or the registry read was denied, denied without administrator rights, or failed.
///
/// `service_disabled` is **not** here, and the omission is the point: BAM's own scavenger deletes
/// every entry older than seven days at each boot, which is Microsoft's code running on schedule and
/// not a service being off. Nothing this collector reads distinguishes "the service is disabled"
/// from "the scavenger has run", so it does not claim to (ADR 0030).
const REASONS: [UnmeasuredReason; 7] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::SourceEmpty,
    UnmeasuredReason::Partial,
    UnmeasuredReason::ReadFailed,
];

/// Every field this collector can emit.
///
/// A key it could not enumerate is a gap in all of them. One value it could not read or decode is
/// not: see the comment on [`Bam::collect`].
const FIELDS: [Field; 13] = [
    Field::number("entries"),
    Field::boolean("intact"),
    Field::timestamp("last_run"),
    Field::number("moderation_state"),
    Field::text("name"),
    Field::text("path"),
    Field::text("path_withheld"),
    Field::text("read"),
    Field::number("rejected"),
    Field::text("sid_withheld"),
    Field::number("users"),
    Field::number("value_bytes"),
    Field::number("values"),
];

/// The fields that describe one program BAM recorded, as opposed to what the key held.
///
/// The subset a content-level reason gaps: `source_empty` and `partial` both describe a key this
/// collector **did** enumerate, so gapping `users`, `values`, `entries`, `rejected` or `intact` —
/// which were measured — would claim it had not (ADR 0030).
const RECORD_FIELDS: [&str; 6] = [
    "last_run",
    "moderation_state",
    "name",
    "path",
    "path_withheld",
    "value_bytes",
];

/// The `bam` collector.
#[derive(Debug, Default, Clone, Copy)]
pub struct Bam;

impl Collector for Bam {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    /// Enumerates the account keys under [`USER_SETTINGS_KEY`] and reads every value in each of them.
    ///
    /// Three kinds of failure, classified differently on purpose:
    ///
    /// - the account list could not be read: nothing was read at all, so every field is a gap;
    /// - **one account's values could not be listed**: an unknown number of records is missing, so
    ///   the run is gapped as well — this follows `pca`, where one unreadable file loses a whole
    ///   class of launches, rather than `prefetch`, where one unreadable file loses one program;
    /// - **one value could not be read or decoded**: that loses one program's record and says
    ///   nothing about the others, which is the per-item case ADR 0009 settled. It is named, counted
    ///   in `rejected`, and turns `intact` false, and it is not a gap.
    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }

        let accounts = match host.subkeys(USER_SETTINGS_KEY) {
            // BAM is not on this machine: the service is not there, or this Windows never had it.
            // That is not the statement "no program ran" — it is the absence of the record that
            // would have said either way, so it must not reach a rule as `NotFound` (ADR 0023).
            Ok(None) => {
                return CollectorRun::Unmeasured {
                    collector: ID.to_owned(),
                    reason: UnmeasuredReason::SourceAbsent,
                };
            }
            Ok(Some(accounts)) => accounts,
            Err(error) => {
                // The key is there and Windows would not hand it over. It is emitted as an
                // observation as well as gapped, because with no rule reading this collector a
                // `gaps` entry reaches no screen, and an artifact this program could not read is
                // what an evader would arrange.
                return CollectorRun::Measured {
                    collector: ID.to_owned(),
                    observations: vec![status(None, read_failure(&error))],
                    gaps: gaps(reason_for(host, &error)),
                };
            }
        };

        let mut observations = Vec::new();
        let mut first_failure = None;
        let mut values = 0_usize;
        let mut parsed = 0_usize;
        let mut rejected = 0_usize;

        for account in &accounts {
            let key = format!(r"{USER_SETTINGS_KEY}\{account}");
            let names = match host.value_names(&key) {
                // Listed a moment ago and gone now. Windows writes this key while a scan runs, so
                // this is ordinary and is counted as neither read nor refused (ADR 0019).
                Ok(None) => continue,
                Ok(Some(names)) => names,
                Err(error) => {
                    // The same shape as the whole-key refusal above, and deliberately so: the only
                    // thing that would distinguish them is the account, which is withheld.
                    observations.push(status(None, read_failure(&error)));
                    first_failure = first_failure.or_else(|| Some(reason_for(host, &error)));
                    continue;
                }
            };
            values += names.len();
            for name in &names {
                match host.read_bytes(&key, name) {
                    Ok(None) => {}
                    Ok(Some(bytes)) => match bam::parse_value(&bytes) {
                        Ok(entry) => {
                            parsed += 1;
                            observations.push(execution(name, bytes.len(), &entry));
                        }
                        Err(error) => {
                            rejected += 1;
                            observations.push(status(Some(name), parse_failure(&error)));
                        }
                    },
                    Err(error) => {
                        rejected += 1;
                        observations.push(status(Some(name), read_failure(&error)));
                    }
                }
            }
        }
        observations.push(account_of(accounts.len(), values, parsed, rejected));

        let gaps = match first_failure {
            Some(reason) => gaps(reason),
            // The key is there and nothing at all is recorded under it. That is not "no program
            // ran": Windows' own `BampScavengeUserSettings` deletes every entry older than seven
            // days at each boot, so a key that holds nothing is what a machine unused for a week
            // looks like the moment it starts (ADR 0030).
            None if values == 0 => record_gaps(UnmeasuredReason::SourceEmpty),
            // Some of the values decoded and some did not, so an unknown number of programs is
            // missing from what was read.
            None if rejected > 0 => record_gaps(UnmeasuredReason::Partial),
            None => BTreeMap::new(),
        };
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
        }
    }
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// A gap in what one recorded program would have said, leaving what the key held measured.
fn record_gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    RECORD_FIELDS
        .iter()
        .map(|field| ((*field).to_owned(), reason))
        .collect()
}

/// One program BAM recorded, from one registry value that decoded.
///
/// `value_bytes` is how many bytes the value held. ADR 0013 names it as the first thing to check on a
/// current Windows build — whether a value is still the 24 the write-ups describe — and it is the one
/// number here that means the same thing on every machine.
fn execution(path: &str, value_bytes: usize, entry: &BamEntry) -> Observation {
    let mut fields = BTreeMap::new();
    if let Some(name) = file_name(path) {
        fields.insert("name".to_owned(), serde_json::Value::from(name));
    }
    insert_path(&mut fields, path);
    // The instant BAM stored, as it stored it. A `FILETIME` of zero is 1601-01-01 and reaches the
    // report as that: whether it means "never ran" is a judgement for a rule, and a collector that
    // turned it into an absence would take that judgement away (ADR 0013).
    if let Some(at) = entry.last_run {
        fields.insert(
            "last_run".to_owned(),
            serde_json::Value::from(at.to_string()),
        );
    }
    // The parser's own name for bytes 8..12. A value too short to hold them omits the field rather
    // than reporting a zero it did not read.
    if let Some(state) = entry.moderation_state {
        fields.insert(
            "moderation_state".to_owned(),
            serde_json::Value::from(state),
        );
    }
    fields.insert(
        "value_bytes".to_owned(),
        serde_json::Value::from(value_bytes),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// What BAM held, how much of it decoded, and whose records these are not.
///
/// `values: 0` under a key that exists is the one question about this artifact that exact equality
/// can usefully ask: a machine whose BAM state was cleared. `intact` is `rejected == 0`, the same
/// field and the same meaning `pca` and `prefetch` give it.
///
/// `users` is how many accounts had a key, which is a count and not an identifier — the only thing
/// this collector says about whose records it read.
fn account_of(users: usize, values: usize, parsed: usize, rejected: usize) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("users".to_owned(), serde_json::Value::from(users));
    fields.insert("values".to_owned(), serde_json::Value::from(values));
    fields.insert("entries".to_owned(), serde_json::Value::from(parsed));
    fields.insert("rejected".to_owned(), serde_json::Value::from(rejected));
    fields.insert("intact".to_owned(), serde_json::Value::from(rejected == 0));
    // Said out loud once per run rather than left out, as `prefetch` says what it withheld: a reader
    // who knows BAM is keyed by SID would otherwise have to guess whether this program read the
    // accounts and dropped them, or never read them. It read them and does not report them.
    fields.insert(
        "sid_withheld".to_owned(),
        serde_json::Value::from(SID_WITHHELD),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// One thing that yielded nothing, with what stopped it: a value when `path` is given, and a key
/// when it is not.
///
/// It carries no `name` and no `value_bytes`, so a rule written for a program that ran never matches
/// one of these, and it carries `read`, which no other observation does, so a rule written for it
/// never matches a program that ran.
fn status(path: Option<&str>, read: &'static str) -> Observation {
    let mut fields = BTreeMap::new();
    if let Some(path) = path {
        insert_path(&mut fields, path);
    }
    fields.insert("read".to_owned(), serde_json::Value::from(read));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// Writes the path the artifact spelled, or says that it was withheld.
///
/// Silently omitting it would read as "BAM recorded no path", which is never what happened: the
/// path is the value's name and is always there.
fn insert_path(fields: &mut BTreeMap<String, serde_json::Value>, path: &str) {
    if is_drive_rooted(path) {
        fields.insert("path".to_owned(), serde_json::Value::from(path));
    } else {
        fields.insert(
            "path_withheld".to_owned(),
            serde_json::Value::from(UNREDACTABLE_FORM),
        );
    }
}

/// Value of the `read` field for a value whose bytes arrived and did not decode.
///
/// `rongroi_parsers::bam` accepts any length of at least eight bytes, so the only failure it has
/// today is a value too short to hold the timestamp. `malformed` covers whatever a later version of
/// that parser adds: a finer word invented here for a failure this collector has not seen would be a
/// guess in evidence.
fn parse_failure(error: &ParseError) -> &'static str {
    match error {
        ParseError::Truncated { .. } => "truncated",
        ParseError::Malformed { .. } => "malformed",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn fixture(name: &str) -> FixtureHost {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    fn measured(run: &CollectorRun) -> (&[Observation], &BTreeMap<String, UnmeasuredReason>) {
        match run {
            CollectorRun::Measured {
                observations, gaps, ..
            } => (observations, gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn field<'a>(observation: &'a Observation, name: &str) -> Option<&'a serde_json::Value> {
        observation.fields.get(name)
    }

    fn text<'a>(observation: &'a Observation, name: &str) -> Option<&'a str> {
        field(observation, name).and_then(serde_json::Value::as_str)
    }

    /// The one observation that says what BAM held.
    fn account(observations: &[Observation]) -> &Observation {
        observations
            .iter()
            .find(|observation| observation.fields.contains_key("users"))
            .expect("every measured run that enumerated the key has an account")
    }

    /// The programs BAM recorded: the observations that carry a name.
    fn executions(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("name"))
            .collect()
    }

    /// The things that yielded nothing: the observations that carry a `read`.
    fn refusals(observations: &[Observation]) -> Vec<&Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields.contains_key("read"))
            .collect()
    }

    #[test]
    fn a_bam_value_is_observed() {
        let run = Bam.collect(&fixture("bam-entries-present"));
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");

        let records = executions(observations);
        assert_eq!(records.len(), 2, "{records:?}");
        assert_eq!(records[0].collector, "bam");
        assert_eq!(text(records[0], "name"), Some("example.exe"));
        assert_eq!(
            text(records[0], "path"),
            Some(r"C:\Users\fixtureuser\Downloads\example.exe")
        );
        assert_eq!(text(records[0], "last_run"), Some("2020-01-01T00:00:00Z"));
        assert_eq!(field(records[0], "moderation_state"), Some(&0_u64.into()));
        assert_eq!(field(records[0], "value_bytes"), Some(&24_u64.into()));
    }

    /// The account is what a rule can ask a question of: a cleared BAM state is `values: 0`, and a
    /// key holding a value this program could not decode is `intact: false`.
    #[test]
    fn the_key_says_what_it_held_and_how_much_of_it_decoded() {
        let run = Bam.collect(&fixture("bam-entries-present"));
        let (observations, _) = measured(&run);
        let account = account(observations);
        assert_eq!(field(account, "users"), Some(&1_u64.into()));
        assert_eq!(field(account, "values"), Some(&2_u64.into()));
        assert_eq!(field(account, "entries"), Some(&2_u64.into()));
        assert_eq!(field(account, "rejected"), Some(&0_u64.into()));
        assert_eq!(field(account, "intact"), Some(&true.into()));
        assert_eq!(text(account, "sid_withheld"), Some(SID_WITHHELD));
    }

    /// **The whole point of this collector's field list.** BAM is keyed by SID and its value names
    /// are executable paths in a form redaction cannot reach. The fixture's own account name is long
    /// enough to assert absent, which a real machine's need not be — the upstream Prefetch corpus
    /// has a one-letter one, and `contains("a")` is true of almost any JSON — so the assertion that
    /// carries the weight is on the *shapes*: no SID, no device path, no `\Users\` segment, and no
    /// field carrying the account under any name.
    #[test]
    fn no_account_and_no_device_path_reaches_an_observation() {
        let run = Bam.collect(&fixture("bam-device-paths"));
        let (observations, _) = measured(&run);
        let json = serde_json::to_string(&observations).unwrap().to_uppercase();

        for leaked in [
            "S-1-5-",
            "HARDDISKVOLUME",
            "\\\\DEVICE\\\\",
            "\\\\USERS\\\\",
            "USERSETTINGS",
            "SID\"",
            "USER_SID",
            "ACCOUNT",
            "DEVICEUSER",
        ] {
            assert!(
                !json.contains(leaked),
                "{leaked} reached an observation: {json}"
            );
        }

        // The device-path record is still reported, with the path withheld and the name kept.
        let records = executions(observations);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(text(records[0], "name"), Some("tool.exe"));
        assert_eq!(field(records[0], "path"), None);
        assert_eq!(text(records[0], "path_withheld"), Some(UNREDACTABLE_FORM));
    }

    /// Two accounts are two keys, and the report says how many there were and nothing else about
    /// them. Their records are not separated by account either: which account ran what is the
    /// question the SID would answer, and it is the one this collector does not ask.
    #[test]
    fn more_than_one_account_is_a_count_and_nothing_more() {
        let run = Bam.collect(&fixture("bam-two-accounts"));
        let (observations, _) = measured(&run);

        let account = account(observations);
        assert_eq!(field(account, "users"), Some(&2_u64.into()));
        assert_eq!(field(account, "values"), Some(&2_u64.into()));
        assert_eq!(executions(observations).len(), 2);

        let json = serde_json::to_string(&observations).unwrap();
        assert!(!json.contains("S-1-5-"), "{json}");
    }

    /// BAM is not on this machine at all. Nothing was read, so nothing can be said about what ran —
    /// a rule must not read this as "the program did not run".
    #[test]
    fn no_bam_key_is_unmeasured() {
        assert_eq!(
            Bam.collect(&fixture("bam-not-present")),
            CollectorRun::Unmeasured {
                collector: "bam".to_owned(),
                reason: UnmeasuredReason::SourceAbsent,
            }
        );
    }

    /// The key is there and holds no record, which is the opposite statement from the key not being
    /// there and used to share one word with it.
    ///
    /// **It is not evidence that anything was removed.** `BampScavengeUserSettings` deletes every
    /// entry older than seven days at each boot — Microsoft's own code, on every machine, by design
    /// — so a PC that has been off for a week reaches this state on its own the moment it starts.
    /// The count is still measured and is not gapped, so a rule may still ask what the key held
    /// (ADR 0030).
    #[test]
    fn an_empty_key_is_source_empty_and_still_says_it_held_nothing() {
        let run = Bam.collect(&fixture("bam-empty"));
        let (observations, gaps) = measured(&run);
        assert_eq!(observations.len(), 1, "{observations:?}");
        assert_eq!(field(account(observations), "users"), Some(&0_u64.into()));
        assert_eq!(field(account(observations), "values"), Some(&0_u64.into()));
        for name in RECORD_FIELDS {
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::SourceEmpty),
                "{name}"
            );
        }
        assert_eq!(gaps.get("users"), None);
        assert_eq!(gaps.get("values"), None);
    }

    /// The expected outcome of a scan without an elevated token, if that is what this key needs —
    /// which nothing in this repository establishes (ADR 0023). The collector attempts the read and
    /// classifies what came back, so it is right either way, and `not_admin` is the signal that
    /// makes the restart-as-administrator offer worth taking (ADR 0012).
    #[test]
    fn access_denied_without_admin_rights_is_a_not_admin_gap_and_is_still_shown() {
        let run = Bam.collect(&fixture("bam-access-denied"));
        let (observations, gaps) = measured(&run);

        assert_eq!(observations.len(), 1, "{observations:?}");
        assert_eq!(text(&observations[0], "read"), Some("access_denied"));
        assert_eq!(observations[0].fields.get("path"), None);
        for field in FIELDS {
            let name = field.name;
            assert_eq!(gaps.get(name), Some(&UnmeasuredReason::NotAdmin), "{name}");
        }
    }

    /// Denied while the rights were already held is a different fact: restarting would not help, and
    /// the report must not suggest it would.
    #[test]
    fn access_denied_with_admin_rights_is_an_access_denied_gap() {
        let run = Bam.collect(&fixture("bam-access-denied-elevated"));
        let (observations, gaps) = measured(&run);

        assert_eq!(text(&observations[0], "read"), Some("access_denied"));
        for field in FIELDS {
            let name = field.name;
            assert_eq!(
                gaps.get(name),
                Some(&UnmeasuredReason::AccessDenied),
                "{name}"
            );
        }
    }

    /// One account's key cannot be read while another's can. The readable one is still reported, and
    /// the run is gapped: an unknown number of records is missing, which is `pca`'s case rather than
    /// `prefetch`'s.
    #[test]
    fn one_unreadable_account_is_reported_and_gaps_the_run() {
        let run = Bam.collect(&fixture("bam-account-denied"));
        let (observations, gaps) = measured(&run);

        let refused = refusals(observations);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(text(refused[0], "read"), Some("access_denied"));
        assert_eq!(executions(observations).len(), 1);
        assert_eq!(field(account(observations), "users"), Some(&2_u64.into()));
        for field in FIELDS {
            let name = field.name;
            assert_eq!(gaps.get(name), Some(&UnmeasuredReason::NotAdmin), "{name}");
        }
    }

    /// A value too short to hold the timestamp is one program's record lost, not the key's. It is
    /// named, counted and does not gap the run — and the value beside it is still read.
    #[test]
    fn a_value_of_the_wrong_length_is_named_and_does_not_gap_the_run() {
        let run = Bam.collect(&fixture("bam-malformed-value"));
        let (observations, gaps) = measured(&run);
        // Two of three values did not decode, so an unknown number of programs is missing from what
        // was read: `partial`, not "nothing matched" (ADR 0030). What the key held is still
        // measured, so the counts are not gapped.
        for name in RECORD_FIELDS {
            assert_eq!(gaps.get(name), Some(&UnmeasuredReason::Partial), "{name}");
        }
        assert_eq!(gaps.get("values"), None);

        let refused = refusals(observations);
        assert_eq!(refused.len(), 2, "{refused:?}");
        // In the order the values are enumerated: `short.exe` before `unreadable.exe`.
        assert_eq!(text(refused[0], "read"), Some("truncated"));
        assert_eq!(text(refused[1], "read"), Some("failed"));
        assert_eq!(executions(observations).len(), 1);

        let account = account(observations);
        assert_eq!(field(account, "values"), Some(&3_u64.into()));
        assert_eq!(field(account, "entries"), Some(&1_u64.into()));
        assert_eq!(field(account, "rejected"), Some(&2_u64.into()));
        assert_eq!(field(account, "intact"), Some(&false.into()));
    }

    /// A value longer than the write-ups describe is decoded as far as it is understood and reported
    /// with what it actually held, which is how a Windows build that changed the layout becomes
    /// visible rather than silently wrong (ADR 0013).
    #[test]
    fn a_value_that_is_not_the_documented_length_is_reported_with_its_length() {
        let run = Bam.collect(&fixture("bam-longer-value"));
        let (observations, _) = measured(&run);
        let records = executions(observations);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(field(records[0], "value_bytes"), Some(&40_u64.into()));
        assert_eq!(field(records[0], "moderation_state"), Some(&7_u64.into()));
    }

    /// A value larger than a host reads in one piece (ADR 0022) is refused whole, and the refusal is
    /// reported rather than counted away. The fixture is built here rather than committed: a 64 KiB
    /// file in the repository would be a fixture nobody could read.
    #[test]
    fn a_value_over_the_size_bound_is_reported_as_too_large() {
        let over = "a".repeat(rongroi_host::MAX_REGISTRY_VALUE_BYTES + 1);
        let host = FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nregistry:\n  '{USER_SETTINGS_KEY}\\S-1-5-21-0-0-0-1001':\n    \
                 'C:\\Users\\fixtureuser\\Downloads\\huge.exe':\n      content: \"{over}\"\n"
            ),
            "inline",
        )
        .unwrap();

        let run = Bam.collect(&host);
        let (observations, gaps) = measured(&run);
        // The key was enumerated and one of its values was not read, which is `partial`.
        assert_eq!(
            gaps.get("name"),
            Some(&UnmeasuredReason::Partial),
            "{gaps:?}"
        );

        let refused = refusals(observations);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(text(refused[0], "read"), Some("too_large"));
        assert_eq!(
            text(refused[0], "path"),
            Some(r"C:\Users\fixtureuser\Downloads\huge.exe")
        );
        assert_eq!(
            field(account(observations), "rejected"),
            Some(&1_u64.into())
        );
    }

    #[test]
    fn non_windows_is_unmeasured() {
        assert_eq!(
            Bam.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: "bam".to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    /// The key this collector reads is the one `rongroi_parsers::bam` documents, spelled once.
    #[test]
    fn the_key_is_the_one_the_parser_documents() {
        assert_eq!(
            USER_SETTINGS_KEY,
            r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        );
    }

    /// Every way a value's bytes can fail to decode has a word of its own, so that a reviewer is not
    /// told "malformed" about two different machines.
    #[test]
    fn every_parse_failure_has_its_own_word() {
        assert_eq!(
            parse_failure(&ParseError::Truncated {
                expected: 8,
                found: 7
            }),
            "truncated"
        );
        assert_eq!(
            parse_failure(&ParseError::Malformed {
                field: "record",
                detail: String::new()
            }),
            "malformed"
        );
    }
}
