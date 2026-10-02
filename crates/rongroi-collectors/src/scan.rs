// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! One full scan: run every collector, evaluate the bundle, freeze the report.
//! The CLI and the desktop app both call [`run`], so they cannot disagree about a result.

use std::collections::BTreeMap;

use rongroi_core::bundle::Bundle;
use rongroi_core::engine::{self, SelfIdentity};
use rongroi_core::model::{
    AgeCount, AgeFields, AgePlace, AgeRows, Anchor, AnchorKind, AnchorState, BootTime,
    CollectorRun, CoverageFields, REPORT_SCHEMA_VERSION, Report, ReportHeader, ScanTier,
    UnmeasuredReason, UnmeasuredSource,
};
use rongroi_core::provenance::Provenance;
use rongroi_host::{Host, Platform, RegistryData};

/// Inputs that come from outside the scan: build provenance, the clock, and what this program is.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Provenance of the running binary.
    pub provenance: Provenance,
    /// Scan time, UTC, RFC 3339.
    pub generated_at: String,
    /// What this program is, so that the engine can tell its own traces from evidence about the
    /// machine (ADR 0010). Computed by the caller's `main`, never read from the running process
    /// here, so that a fixture can exercise the whole path.
    pub self_identity: SelfIdentity,
    /// Which scan the player chose before it started (ADR 0052). A collector whose tier is above it
    /// is not called.
    pub tier: ScanTier,
}

/// Runs every collector against `host` and evaluates `bundle`.
pub fn run(host: &dyn Host, bundle: &Bundle, context: ScanContext) -> Report {
    // Before the collectors, so that the count is read as close as possible to `generated_at`, which
    // the caller took just before this call: the `evtx` collector alone may run for 30 seconds, and
    // reading the count after it would move the start that much earlier (ADR 0039).
    let boot_time = boot_time(host, &context.generated_at);
    let profiles_directory = profiles_directory(host);
    let collectors = crate::all();
    let tier = context.tier;
    let runs: Vec<CollectorRun> = collectors
        .iter()
        .map(|collector| {
            if collector.tier() > tier {
                // Not called at all: no function of it touches the machine (ADR 0052).
                CollectorRun::Unmeasured {
                    collector: collector.id().to_owned(),
                    reason: UnmeasuredReason::NotConsented,
                }
            } else {
                collector.collect(host)
            }
        })
        .collect();
    let anchors = anchors(host, &runs, &context.generated_at);
    let header = ReportHeader {
        schema_version: REPORT_SCHEMA_VERSION,
        provenance: context.provenance,
        rules_bundle: bundle.info().clone(),
        platform: host.platform().as_str().to_owned(),
        os_build: host.os_build(),
        elevated: host.is_elevated(),
        generated_at: context.generated_at,
        boot_time,
        profiles_directory,
        scan_tier: tier,
        anchors,
    };
    let mut report = engine::evaluate(bundle, &runs, header, &context.self_identity);
    declare_times(&mut report, &collectors, &runs);
    declare_sensitive(&mut report, &collectors);
    declare_ages(&mut report, &collectors, bundle);
    report
}

/// Copies into the report how each collector's observations say how far back its source reaches
/// (ADR 0061). For a collector with a row per value — `evtx`, a row per log — the values listed first
/// are the ones the bundle reads: the logs its rules and timeline selectors name by channel.
fn declare_ages(report: &mut Report, collectors: &[Box<dyn crate::Collector>], bundle: &Bundle) {
    let count = |count: crate::AgeCount| match count {
        crate::AgeCount::Observations => AgeCount::Observations,
        crate::AgeCount::Field(field) => AgeCount::Field {
            field: field.to_owned(),
        },
    };
    let owned = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
    for collector in collectors {
        let Some(age) = collector.age() else {
            continue;
        };
        let (rows, first) = match age.rows {
            crate::AgeRows::One => (AgeRows::One, Vec::new()),
            crate::AgeRows::PerPlace => (AgeRows::PerPlace, Vec::new()),
            crate::AgeRows::PerValue(field) => (
                AgeRows::PerValue {
                    field: field.to_owned(),
                },
                logs_the_bundle_reads(bundle, collector.id()),
            ),
        };
        report.age_fields.insert(
            collector.id().to_owned(),
            AgeFields {
                oldest: owned(age.oldest),
                count: count(age.count),
                rows,
                places: owned(age.places),
                extra: owned(age.extra),
                first,
                by_place: age
                    .by_place
                    .iter()
                    .map(|place| AgePlace {
                        place: place.place.to_owned(),
                        oldest: owned(place.oldest),
                        count: count(place.count),
                        without: place.without.map(str::to_owned),
                    })
                    .collect(),
            },
        );
    }
}

/// The file names of the logs the bundle's rules and timeline selectors on `collector` name by
/// `channel`, sorted: `Microsoft-Windows-CodeIntegrity/Operational` is written to
/// `Microsoft-Windows-CodeIntegrity%4Operational.evtx`, as Windows names a channel's file. Empty for any
/// collector but `evtx`.
fn logs_the_bundle_reads(bundle: &Bundle, collector: &str) -> Vec<String> {
    if collector != "evtx" {
        return Vec::new();
    }
    let mut logs = std::collections::BTreeSet::new();
    for sourced in bundle.rules() {
        let rule = &sourced.rule;
        if rule.collector != collector || rule.status == rongroi_core::rules::Status::Deprecated {
            continue;
        }
        let Some(value) = rule.matcher.get("channel") else {
            continue;
        };
        let channels: Vec<&str> = match value {
            serde_json::Value::String(channel) => vec![channel.as_str()],
            serde_json::Value::Array(channels) => channels
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect(),
            _ => Vec::new(),
        };
        for channel in channels {
            logs.insert(format!("{}.evtx", channel.replace('/', "%4")));
        }
    }
    logs.into_iter().collect()
}

/// Where Windows keeps the installation's own values.
const CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
/// Where Windows Setup keeps a `Source OS (Updated on …)` subkey per installation a feature upgrade
/// replaced (ADR 0061). Not documented by Microsoft.
const SETUP: &str = r"HKLM\SYSTEM\Setup";
/// The start of those subkeys' names, compared without case.
const SOURCE_OS: &str = "Source OS";

/// The anchors: dated facts about when parts of this PC were set up (ADR 0061, owner decision 5).
///
/// Every one is read without administrator rights except the change journal's, which comes from the
/// `usn` collector's run rather than from a second read of the journal. Each is a UTC date; a read that
/// fails is `unmeasured` with its reason, never a guessed date. `boot_time` is not here: it keeps its
/// own header field and its precision (ADR 0039).
fn anchors(host: &dyn Host, runs: &[CollectorRun], generated_at: &str) -> Vec<Anchor> {
    let windows = host.platform() == Platform::Windows;
    let system_drive = host.env_var("SystemDrive").filter(|drive| {
        let bytes = drive.as_bytes();
        bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    });
    let local_app_data = host
        .env_var(crate::fivem_dir::LOCAL_APP_DATA)
        .map(|base| base.trim_end_matches(['\\', '/']).to_owned())
        .filter(|base| !base.is_empty());
    let under = |base: &Option<String>, relative: &str| {
        base.as_ref().map(|base| format!(r"{base}\{relative}"))
    };
    let legacy = crate::fivem_dir::LEGACY_PROGRAM_RELATIVE_PATH;
    let enhanced = crate::fivem_dir::ENHANCED_PROGRAM_RELATIVE_PATH;
    let folders = [
        (
            AnchorKind::SystemDriveRootCreated,
            system_drive.as_ref().map(|drive| format!(r"{drive}\")),
            r"%SystemDrive%\".to_owned(),
        ),
        (
            AnchorKind::RecycleBinCreated,
            system_drive
                .as_ref()
                .map(|drive| format!(r"{drive}\$Recycle.Bin")),
            r"%SystemDrive%\$Recycle.Bin".to_owned(),
        ),
        (
            AnchorKind::FivemLegacyProgramFolderCreated,
            under(&local_app_data, legacy),
            format!(r"%LOCALAPPDATA%\{legacy}"),
        ),
        (
            AnchorKind::FivemLegacyAppFolderCreated,
            under(&local_app_data, &format!(r"{legacy}\FiveM.app")),
            format!(r"%LOCALAPPDATA%\{legacy}\FiveM.app"),
        ),
        (
            AnchorKind::FivemEnhancedProgramFolderCreated,
            under(&local_app_data, enhanced),
            format!(r"%LOCALAPPDATA%\{enhanced}"),
        ),
    ];
    let mut anchors = vec![install_date(host), setup_earliest_install(host)];
    anchors.push(usn_journal_created(runs, generated_at));
    for (kind, path, source) in folders {
        let state = if windows {
            folder_created(host, path.as_deref(), source)
        } else {
            unmeasured_anchor(UnmeasuredReason::NotWindows)
        };
        anchors.push(Anchor {
            anchor: kind,
            state,
        });
    }
    anchors
}

fn unmeasured_anchor(reason: UnmeasuredReason) -> AnchorState {
    AnchorState::Unmeasured { reason }
}

/// The UTC date of `time`, the one precision an anchor carries (ADR 0061, owner decision 4).
fn utc_date(time: jiff::Timestamp) -> String {
    time.to_zoned(jiff::tz::TimeZone::UTC).date().to_string()
}

/// A date read from a `REG_DWORD` of seconds since 1970, as `InstallDate` is.
fn registry_date(host: &dyn Host, key: &str) -> Result<Option<String>, UnmeasuredReason> {
    match host.read_value(key, "InstallDate") {
        Ok(Some(RegistryData::Dword(seconds))) => jiff::Timestamp::from_second(i64::from(seconds))
            .map(|time| Some(utc_date(time)))
            .map_err(|_| UnmeasuredReason::ReadFailed),
        Ok(Some(_)) => Err(UnmeasuredReason::ReadFailed),
        Ok(None) => Ok(None),
        Err(error) => Err(crate::failure::reason_for(host, &error)),
    }
}

/// `InstallDate`: when this installation was installed or last upgraded to a new feature version.
fn install_date(host: &dyn Host) -> Anchor {
    let state = if host.platform() == Platform::Windows {
        match registry_date(host, CURRENT_VERSION) {
            Ok(Some(on)) => AnchorState::Measured {
                on,
                source: format!(r"{CURRENT_VERSION}\InstallDate"),
                kept: None,
            },
            Ok(None) => unmeasured_anchor(UnmeasuredReason::SourceAbsent),
            Err(reason) => unmeasured_anchor(reason),
        }
    } else {
        unmeasured_anchor(UnmeasuredReason::NotWindows)
    };
    Anchor {
        anchor: AnchorKind::InstallDate,
        state,
    }
}

/// The earliest `InstallDate` among the `Source OS (Updated on …)` subkeys, and how many there are.
/// No subkey name leaves this function: each carries a date to the second.
fn setup_earliest_install(host: &dyn Host) -> Anchor {
    let state = if host.platform() == Platform::Windows {
        match host.subkeys(SETUP) {
            Ok(Some(names)) => {
                let kept: Vec<String> = names
                    .into_iter()
                    .filter(|name| {
                        name.get(..SOURCE_OS.len())
                            .is_some_and(|head| head.eq_ignore_ascii_case(SOURCE_OS))
                    })
                    .collect();
                let mut dates = Vec::new();
                let mut failure = None;
                for name in &kept {
                    match registry_date(host, &format!(r"{SETUP}\{name}")) {
                        Ok(Some(date)) => dates.push(date),
                        Ok(None) => {}
                        Err(reason) => failure = failure.or(Some(reason)),
                    }
                }
                match (dates.into_iter().min(), failure) {
                    // A subkey whose date could not be read could hold the earliest one.
                    (_, Some(reason)) => unmeasured_anchor(reason),
                    (Some(on), None) => AnchorState::Measured {
                        on,
                        source: format!(r"{SETUP}\Source OS (Updated on …)\InstallDate"),
                        kept: u32::try_from(kept.len()).ok(),
                    },
                    (None, None) if kept.is_empty() => {
                        unmeasured_anchor(UnmeasuredReason::SourceAbsent)
                    }
                    (None, None) => unmeasured_anchor(UnmeasuredReason::ReadFailed),
                }
            }
            Ok(None) => unmeasured_anchor(UnmeasuredReason::SourceAbsent),
            Err(error) => unmeasured_anchor(crate::failure::reason_for(host, &error)),
        }
    } else {
        unmeasured_anchor(UnmeasuredReason::NotWindows)
    };
    Anchor {
        anchor: AnchorKind::SetupEarliestInstall,
        state,
    }
}

/// The date the `usn` collector read from the journal identifier, from its run: the journal is read
/// once per scan. A date after the scan's own is not a creation time and is not shown.
fn usn_journal_created(runs: &[CollectorRun], generated_at: &str) -> Anchor {
    let state = match runs.iter().find(|run| run.collector() == "usn") {
        None => unmeasured_anchor(UnmeasuredReason::CollectorUnavailable),
        Some(CollectorRun::Unmeasured { reason, .. }) => unmeasured_anchor(*reason),
        Some(CollectorRun::Measured { observations, .. }) => {
            let scan_date = generated_at.parse::<jiff::Timestamp>().ok().map(utc_date);
            let on = observations
                .iter()
                .find(|observation| {
                    observation.fields.get("location")
                        == Some(&serde_json::Value::from(crate::usn::JOURNAL_LOCATION))
                })
                .and_then(|journal| journal.fields.get("journal_created_on"))
                .and_then(serde_json::Value::as_str)
                .filter(|on| scan_date.as_deref().is_some_and(|scan| *on <= scan));
            match on {
                Some(on) => AnchorState::Measured {
                    on: on.to_owned(),
                    source: "%SystemDrive% change journal identifier".to_owned(),
                    kept: None,
                },
                None => unmeasured_anchor(UnmeasuredReason::ReadFailed),
            }
        }
    };
    Anchor {
        anchor: AnchorKind::UsnJournalCreated,
        state,
    }
}

/// A folder's own creation date, read without listing its parent.
fn folder_created(host: &dyn Host, path: Option<&str>, source: String) -> AnchorState {
    let Some(path) = path else {
        // The variable that says where the folder is was not set: nothing was looked at.
        return unmeasured_anchor(UnmeasuredReason::ReadFailed);
    };
    match host.times(path) {
        Ok(Some(times)) => match times.created {
            Some(created) => AnchorState::Measured {
                on: utc_date(created),
                source,
                kept: None,
            },
            None => unmeasured_anchor(UnmeasuredReason::ReadFailed),
        },
        Ok(None) => unmeasured_anchor(UnmeasuredReason::SourceAbsent),
        Err(error) => unmeasured_anchor(crate::failure::reason_for(host, &error)),
    }
}

/// Copies into the report which fields each collector declared sensitive, for `view` to hide in SS
/// mode (ADR 0052), whatever the tier of the scan.
fn declare_sensitive(report: &mut Report, collectors: &[Box<dyn crate::Collector>]) {
    for collector in collectors {
        let fields: BTreeMap<String, rongroi_core::model::SensitiveKind> = collector
            .fields()
            .iter()
            .filter_map(|field| Some((field.name.to_owned(), field.sensitive?)))
            .collect();
        if !fields.is_empty() {
            report
                .sensitive_fields
                .insert(collector.id().to_owned(), fields);
        }
    }
}

/// Copies into the report what the timeline needs to know and the core cannot: which fields are
/// times, which field names a place, which fields bound a source, and which sources of times could
/// not be read (ADR 0051).
fn declare_times(
    report: &mut Report,
    collectors: &[Box<dyn crate::Collector>],
    runs: &[CollectorRun],
) {
    for collector in collectors {
        let id = collector.id();
        let timestamps: Vec<&'static str> = collector
            .fields()
            .iter()
            .filter(|field| field.kind == crate::FieldKind::Timestamp && field.on_timeline)
            .map(|field| field.name)
            .collect();
        if timestamps.is_empty() {
            continue;
        }
        report.timestamp_fields.insert(
            id.to_owned(),
            timestamps.iter().map(|name| (*name).to_owned()).collect(),
        );
        if let Some(discriminator) = collector.discriminator() {
            report
                .discriminators
                .insert(id.to_owned(), discriminator.to_owned());
        }
        if let Some(coverage) = collector.coverage() {
            report.coverage_fields.insert(
                id.to_owned(),
                CoverageFields {
                    from: coverage.from.to_owned(),
                    to: coverage.to.to_owned(),
                    place: coverage.place.map(str::to_owned),
                },
            );
        }
        let Some(run) = runs.iter().find(|run| run.collector() == id) else {
            continue;
        };
        report
            .unmeasured_sources
            .extend(unmeasured_sources(id, &timestamps, run));
    }
}

/// Where `run` could not read one of `timestamps`: the whole collector, or one of its places.
///
/// One entry per place, with the reason of the first timestamp field that place could not read. A
/// place whose gaps name no timestamp field — a file that could not be hashed — is not a source of
/// times that failed, and is left to the rows.
fn unmeasured_sources(
    collector: &str,
    timestamps: &[&str],
    run: &CollectorRun,
) -> Vec<UnmeasuredSource> {
    let first_gap = |gaps: &BTreeMap<String, UnmeasuredReason>| {
        timestamps
            .iter()
            .find_map(|field| gaps.get(*field).copied())
    };
    let source = |place: Option<String>, reason| UnmeasuredSource {
        collector: collector.to_owned(),
        place,
        reason,
    };
    match run {
        // A scope fact, stated once above the evidence; the source was never read, not unreadable.
        CollectorRun::Unmeasured {
            reason: UnmeasuredReason::NotConsented,
            ..
        } => Vec::new(),
        CollectorRun::Unmeasured { reason, .. } => vec![source(None, *reason)],
        CollectorRun::Measured {
            gaps,
            discriminator_gaps,
            ..
        } => first_gap(gaps)
            .map(|reason| source(None, reason))
            .into_iter()
            .chain(discriminator_gaps.iter().filter_map(|place| {
                let reason = first_gap(&place.gaps)?;
                Some(source(place.value.as_str().map(str::to_owned), reason))
            }))
            .collect(),
    }
}

/// When the running Windows kernel started counting, or why there is no value (ADR 0039).
///
/// Every failure is `read_failed`, as the `posture` collector reports a platform read that failed:
/// on a live host `GetTickCount64` has no failure to report, so this is reached by a fixture that did
/// not describe the count, never by a machine.
fn boot_time(host: &dyn Host, generated_at: &str) -> BootTime {
    if host.platform() != Platform::Windows {
        return BootTime::Unmeasured {
            reason: UnmeasuredReason::NotWindows,
        };
    }
    match host.since_boot() {
        Ok(since_boot) => BootTime::from_elapsed(generated_at, since_boot),
        Err(_) => BootTime::Unmeasured {
            reason: UnmeasuredReason::ReadFailed,
        },
    }
}

/// Where Windows keeps `ProfilesDirectory`, the folder new profiles are created in.
const PROFILE_LIST: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// The machine's profile root, for SS-mode redaction and nothing else (ADR 0049).
///
/// Every reason there is no value — not Windows, absent, unreadable, another type, not expandable —
/// is `None`: the view then redacts with the roots every machine has, and a reason would be a field
/// nothing reads.
pub(crate) fn profiles_directory(host: &dyn Host) -> Option<String> {
    if host.platform() != Platform::Windows {
        return None;
    }
    let Ok(Some(RegistryData::Text(stored))) = host.read_value(PROFILE_LIST, "ProfilesDirectory")
    else {
        return None;
    };
    expand_profiles_directory(&stored, host.env_var("SystemDrive").as_deref())
}

/// `stored` with a leading `%SystemDrive%` replaced by `system_drive`, kept only when the result is
/// drive-rooted and holds no other variable.
fn expand_profiles_directory(stored: &str, system_drive: Option<&str>) -> Option<String> {
    const VARIABLE: &str = "%SystemDrive%";
    let expanded = match stored.get(..VARIABLE.len()) {
        Some(head) if head.eq_ignore_ascii_case(VARIABLE) => {
            let drive = system_drive.filter(|drive| {
                let bytes = drive.as_bytes();
                bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
            })?;
            format!("{drive}{}", &stored[VARIABLE.len()..])
        }
        _ => stored.to_owned(),
    };
    (crate::paths::is_drive_rooted(&expanded) && !expanded.contains('%')).then_some(expanded)
}

#[cfg(test)]
mod tests {
    use rongroi_host::FixtureHost;

    use super::*;

    fn host(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    /// Every collector with a timestamp field is declared, with its discriminator and span.
    #[test]
    fn the_report_declares_every_collectors_times() {
        let bundle = Bundle::embedded().unwrap();
        let report = run(
            &host("platform: windows\n"),
            &bundle,
            ScanContext {
                provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
                generated_at: "2026-01-01T00:00:00Z".to_owned(),
                self_identity: SelfIdentity::default(),
                tier: ScanTier::Standard,
            },
        );
        for collector in crate::all() {
            let declared = collector
                .fields()
                .iter()
                .any(|field| field.kind == crate::FieldKind::Timestamp && field.on_timeline);
            assert_eq!(
                report.timestamp_fields.contains_key(collector.id()),
                declared,
                "{}",
                collector.id()
            );
        }
        assert_eq!(
            report.timestamp_fields.get("prefetch"),
            Some(&vec!["last_run".to_owned()])
        );
        assert_eq!(
            report.discriminators.get("usn").map(String::as_str),
            Some("location")
        );
        assert_eq!(
            report
                .coverage_fields
                .get("usn")
                .and_then(|c| c.place.as_deref()),
            Some("journal")
        );
        assert!(!report.timestamp_fields.contains_key("posture"));
        // `started_at` is read for ADR 0062's session statement only, never as a timeline time
        // (owner decision 8, 2026-10-02): `process` declares no timeline field, so none of its
        // times is an entry and an unread process list is not an unmeasured timeline source.
        assert!(!report.timestamp_fields.contains_key("process"));
    }

    fn context(tier: ScanTier) -> ScanContext {
        ScanContext {
            provenance: Provenance::from_parts(None, "0.0.0-test", None, None),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            self_identity: SelfIdentity::default(),
            tier,
        }
    }

    /// A standard scan never calls a `full` collector: its run is `not_consented`, its rules are
    /// unmeasured for that reason, and the header says which scan it was. A full scan calls every
    /// collector (ADR 0052).
    #[test]
    fn a_standard_scan_does_not_call_a_full_collector_and_a_full_scan_does() {
        let bundle = Bundle::embedded().unwrap();
        let host =
            host("platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\n");
        let full: Vec<&'static str> = crate::all()
            .iter()
            .filter(|collector| collector.tier() == ScanTier::Full)
            .map(|collector| collector.id())
            .collect();
        assert!(full.contains(&"fivem_servers"), "{full:?}");

        let standard = run(&host, &bundle, context(ScanTier::Standard));
        assert_eq!(standard.header.scan_tier, ScanTier::Standard);
        for item in standard
            .evidence
            .iter()
            .filter(|item| full.contains(&item.collector.as_str()))
        {
            assert!(
                matches!(
                    item.state,
                    rongroi_core::model::EvidenceState::Unmeasured {
                        reason: UnmeasuredReason::NotConsented,
                        ..
                    }
                ),
                "{item:?}"
            );
        }
        assert!(
            !standard
                .unmatched
                .iter()
                .any(|group| full.contains(&group.collector.as_str())),
            "a standard scan holds observations of a full collector"
        );
        assert!(
            standard
                .unmeasured_sources
                .iter()
                .all(|source| source.reason != UnmeasuredReason::NotConsented)
        );

        let full_scan = run(&host, &bundle, context(ScanTier::Full));
        assert_eq!(full_scan.header.scan_tier, ScanTier::Full);
        assert!(
            full_scan
                .unmatched
                .iter()
                .any(|group| group.collector == "fivem_servers"),
            "{:?}",
            full_scan.unmatched
        );
        // Declared whatever the tier, so a view can hide the field in either report.
        for report in [&standard, &full_scan] {
            assert_eq!(
                report.sensitive_fields["fivem_servers"]["server_folder"],
                rongroi_core::model::SensitiveKind::ServerIdentity
            );
        }
    }

    #[test]
    fn only_a_full_scan_asks_about_sensitive_kinds() {
        assert!(crate::sensitive_kinds(ScanTier::Standard).is_empty());
        assert!(
            crate::sensitive_kinds(ScanTier::Full)
                .contains(&rongroi_core::model::SensitiveKind::ServerIdentity)
        );
    }

    /// Only a `full` collector may mark a field sensitive: a standard scan's reads are what every
    /// player agrees to, so nothing it reads is hidden behind a separate answer (ADR 0052).
    #[test]
    fn no_standard_collector_declares_a_sensitive_field() {
        for collector in crate::all() {
            if collector.tier() == ScanTier::Standard {
                assert!(
                    collector
                        .fields()
                        .iter()
                        .all(|field| field.sensitive.is_none()),
                    "{}",
                    collector.id()
                );
            }
        }
    }

    #[test]
    fn a_source_of_times_that_could_not_be_read_is_named_with_its_place() {
        let unmeasured = CollectorRun::Unmeasured {
            collector: "usn".to_owned(),
            reason: UnmeasuredReason::NotAdmin,
        };
        assert_eq!(
            unmeasured_sources("usn", &["first_seen"], &unmeasured),
            vec![UnmeasuredSource {
                collector: "usn".to_owned(),
                place: None,
                reason: UnmeasuredReason::NotAdmin,
            }]
        );
        let gaps = |field: &str, reason| BTreeMap::from([(field.to_owned(), reason)]);
        let measured = CollectorRun::Measured {
            collector: "fivem_dir".to_owned(),
            observations: Vec::new(),
            gaps: gaps("sha256", UnmeasuredReason::ReadFailed),
            discriminator_gaps: vec![
                rongroi_core::model::DiscriminatorGaps {
                    discriminator: "location".to_owned(),
                    value: serde_json::Value::from("legacy_logs"),
                    gaps: gaps("created_at", UnmeasuredReason::AccessDenied),
                },
                rongroi_core::model::DiscriminatorGaps {
                    discriminator: "location".to_owned(),
                    value: serde_json::Value::from("plugins"),
                    gaps: gaps("signature", UnmeasuredReason::AccessDenied),
                },
            ],
        };
        assert_eq!(
            unmeasured_sources("fivem_dir", &["created_at", "modified_at"], &measured),
            vec![UnmeasuredSource {
                collector: "fivem_dir".to_owned(),
                place: Some("legacy_logs".to_owned()),
                reason: UnmeasuredReason::AccessDenied,
            }]
        );
    }

    fn fixture_host(name: &str) -> FixtureHost {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/hosts")
            .join(name);
        FixtureHost::load(&dir).unwrap()
    }

    fn anchor_state(report: &Report, kind: AnchorKind) -> AnchorState {
        report
            .header
            .anchors
            .iter()
            .find(|anchor| anchor.anchor == kind)
            .unwrap()
            .state
            .clone()
    }

    /// Every anchor as a UTC date, from the registry, the drive's own folders, `FiveM`'s program folder
    /// and the change journal's run; Windows Setup's earliest installation with how many it kept, and
    /// an edition that is not installed as `source_absent` (ADR 0061, owner decision 5).
    #[test]
    fn the_anchors_are_utc_dates_with_what_was_read() {
        let bundle = Bundle::embedded().unwrap();
        let report = run(
            &fixture_host("trace-ages-elevated"),
            &bundle,
            context(ScanTier::Standard),
        );
        let on = |kind| match anchor_state(&report, kind) {
            AnchorState::Measured { on, .. } => on,
            AnchorState::Unmeasured { reason } => panic!("{kind:?}: {reason:?}"),
        };
        assert_eq!(on(AnchorKind::InstallDate), "2025-10-21");
        assert_eq!(on(AnchorKind::UsnJournalCreated), "2018-03-01");
        assert_eq!(on(AnchorKind::SystemDriveRootCreated), "2018-03-02");
        assert_eq!(on(AnchorKind::RecycleBinCreated), "2018-03-02");
        assert_eq!(
            on(AnchorKind::FivemLegacyProgramFolderCreated),
            "2024-05-10"
        );
        assert_eq!(on(AnchorKind::FivemLegacyAppFolderCreated), "2024-05-10");
        assert_eq!(
            anchor_state(&report, AnchorKind::SetupEarliestInstall),
            AnchorState::Measured {
                on: "2018-03-02".to_owned(),
                source: r"HKLM\SYSTEM\Setup\Source OS (Updated on …)\InstallDate".to_owned(),
                kept: Some(2),
            }
        );
        assert_eq!(
            anchor_state(&report, AnchorKind::FivemEnhancedProgramFolderCreated),
            AnchorState::Unmeasured {
                reason: UnmeasuredReason::SourceAbsent
            }
        );
        // No anchor carries a time: a date is what it is compared in, and a second matches reports.
        for anchor in &report.header.anchors {
            if let AnchorState::Measured { on, .. } = &anchor.state {
                assert!(
                    on.parse::<jiff::civil::Date>().is_ok() && on.len() == 10,
                    "{on}"
                );
            }
        }
    }

    /// Without administrator rights the journal is `not_admin`, and the rest still read; on another
    /// operating system every anchor is `not_windows`.
    #[test]
    fn an_anchor_that_could_not_be_read_says_why() {
        let bundle = Bundle::embedded().unwrap();
        let limited = run(
            &fixture_host("trace-ages-limited"),
            &bundle,
            context(ScanTier::Standard),
        );
        assert_eq!(
            anchor_state(&limited, AnchorKind::UsnJournalCreated),
            AnchorState::Unmeasured {
                reason: UnmeasuredReason::NotAdmin
            }
        );
        assert!(matches!(
            anchor_state(&limited, AnchorKind::InstallDate),
            AnchorState::Measured { .. }
        ));
        let other = run(
            &host("platform: other\n"),
            &bundle,
            context(ScanTier::Standard),
        );
        assert_eq!(other.header.anchors.len(), 8);
        for anchor in &other.header.anchors {
            assert_eq!(
                anchor.state,
                AnchorState::Unmeasured {
                    reason: UnmeasuredReason::NotWindows
                },
                "{:?}",
                anchor.anchor
            );
        }
    }

    /// Each collector that declares an age is in the report, and `evtx` lists first the logs the
    /// bundle's rules and selectors name by channel (ADR 0061, owner decision 3).
    #[test]
    fn the_report_declares_ages_and_the_logs_the_bundle_reads() {
        let bundle = Bundle::embedded().unwrap();
        let report = run(
            &host("platform: windows\n"),
            &bundle,
            context(ScanTier::Standard),
        );
        for collector in crate::all() {
            assert_eq!(
                report.age_fields.contains_key(collector.id()),
                collector.age().is_some(),
                "{}",
                collector.id()
            );
        }
        let first = &report.age_fields["evtx"].first;
        for log in [
            "Security.evtx",
            "System.evtx",
            "Microsoft-Windows-CodeIntegrity%4Operational.evtx",
            "Microsoft-Windows-Windows Defender%4Operational.evtx",
        ] {
            assert!(first.iter().any(|name| name == log), "{log}: {first:?}");
        }
    }

    #[test]
    fn a_windows_host_that_answers_gives_a_measured_boot_time() {
        assert_eq!(
            boot_time(
                &host("platform: windows\nmilliseconds_since_boot: 3600000\n"),
                "2026-01-01T00:00:00Z"
            ),
            BootTime::Measured {
                booted_at: "2025-12-31T23:00:00Z".to_owned(),
                seconds_since_boot: 3600,
            }
        );
    }

    /// Not a value, and not the failure a Windows host would report: there is no Windows to ask.
    #[test]
    fn a_host_that_is_not_windows_is_not_windows_even_with_a_count() {
        assert_eq!(
            boot_time(
                &host("platform: other\nmilliseconds_since_boot: 3600000\n"),
                "2026-01-01T00:00:00Z"
            ),
            BootTime::Unmeasured {
                reason: UnmeasuredReason::NotWindows
            }
        );
        assert_eq!(
            boot_time(&rongroi_host::NonWindowsHost, "2026-01-01T00:00:00Z"),
            BootTime::Unmeasured {
                reason: UnmeasuredReason::NotWindows
            }
        );
    }

    #[test]
    fn a_windows_host_that_cannot_answer_is_read_failed_never_a_guess() {
        assert_eq!(
            boot_time(&host("platform: windows\n"), "2026-01-01T00:00:00Z"),
            BootTime::Unmeasured {
                reason: UnmeasuredReason::ReadFailed
            }
        );
    }

    #[test]
    fn the_stored_profiles_directory_is_expanded_with_the_system_drive() {
        assert_eq!(
            profiles_directory(&host(
                "platform: windows\nenv:\n  SystemDrive: 'D:'\nregistry:\n  'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList':\n    ProfilesDirectory: '%SystemDrive%\\Profiles'\n"
            ))
            .as_deref(),
            Some(r"D:\Profiles")
        );
        assert_eq!(
            expand_profiles_directory(r"%systemdrive%\Users", Some("C:")).as_deref(),
            Some(r"C:\Users")
        );
        assert_eq!(
            expand_profiles_directory(r"E:\Profiles", None).as_deref(),
            Some(r"E:\Profiles")
        );
    }

    /// Each is a value that names no folder this program can match, so redaction keeps to the roots
    /// every machine has.
    #[test]
    fn a_profiles_directory_that_is_not_a_drive_rooted_folder_is_none() {
        for (stored, system_drive) in [
            (r"%SystemDrive%\Users", None),
            (r"%SystemDrive%\Users", Some("")),
            (r"%SystemDrive%\Users", Some(r"C:\")),
            (r"%SystemRoot%\Profiles", Some("C:")),
            (r"C:\Users\%USERNAME%", Some("C:")),
            (r"\\server\profiles", Some("C:")),
            ("Users", Some("C:")),
            ("", Some("C:")),
        ] {
            assert_eq!(
                expand_profiles_directory(stored, system_drive),
                None,
                "{stored:?} with {system_drive:?}"
            );
        }
    }

    #[test]
    fn no_profiles_directory_without_windows_or_without_the_value() {
        let key =
            "registry:\n  'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList':\n";
        assert_eq!(
            profiles_directory(&host(&format!(
                "platform: other\n{key}    ProfilesDirectory: 'C:\\Users'\n"
            ))),
            None
        );
        assert_eq!(profiles_directory(&host("platform: windows\n")), None);
        assert_eq!(
            profiles_directory(&host(&format!(
                "platform: windows\n{key}    ProfilesDirectory: 1\n"
            ))),
            None
        );
    }
}
