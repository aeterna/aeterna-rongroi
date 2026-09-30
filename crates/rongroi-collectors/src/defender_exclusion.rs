// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What Microsoft Defender is told not to scan (ADR 0060, section 9).
//!
//! The value **names** of `Exclusions\Paths`, `Exclusions\Processes` and `Exclusions\Extensions` under
//! Defender's own key and under its policy key: one observation per exclusion, with its `kind`, which
//! key set it (`set_by`), the exclusion as written, and — for a path or a process — whether it covers
//! one of `FiveM`'s folders (`covers_fivem`). Of `IpAddresses`, only how many values it holds: an address
//! can name a person's or a company's network, so none is read. `TemporaryPaths` is not read.
//!
//! A token without administrator rights is refused the whole read (measured on a runner and a Windows
//! 11 PC, ADR 0060), so the run is `not_admin` there, and `access_denied` when an elevated read is
//! refused. Nothing is opened for writing.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform};

use crate::{Collector, Field, failure, fivem_dir, paths};

const ID: &str = "defender_exclusion";

/// Defender's own settings, and the key Group Policy writes them to.
pub const ROOTS: [(&str, &str); 2] = [
    (
        "settings",
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions",
    ),
    (
        "policy",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
    ),
];

/// The subkeys whose value names are exclusions, with the value of `kind` for each.
pub const KINDS: [(&str, &str); 3] = [
    ("Paths", "path"),
    ("Processes", "process"),
    ("Extensions", "extension"),
];

/// The subkey whose values are only counted.
pub const IP_ADDRESSES: &str = "IpAddresses";

static FIELDS: [Field; 5] = [
    Field::boolean("covers_fivem"),
    Field::text("exclusion"),
    Field::number("ip_addresses"),
    Field::text("kind"),
    Field::text("set_by"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// Reads Microsoft Defender's exclusions.
#[derive(Debug, Clone, Copy)]
pub struct DefenderExclusion;

impl Collector for DefenderExclusion {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        let unmeasured = |reason| CollectorRun::Unmeasured {
            collector: ID.to_owned(),
            reason,
        };
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let folders = fivem_folders(host);
        let mut observations = Vec::new();
        let mut gaps = BTreeMap::new();
        for (set_by, root) in ROOTS {
            for (subkey, kind) in KINDS {
                let names = match host.value_names(&format!(r"{root}\{subkey}")) {
                    Ok(Some(names)) => names,
                    Ok(None) => continue,
                    Err(error) => return unmeasured(failure::reason_for(host, &error)),
                };
                for exclusion in names {
                    let mut fields = BTreeMap::new();
                    if kind != "extension" {
                        match covers(host, &exclusion, &folders) {
                            Cover::Answer(covers) => {
                                fields.insert(
                                    "covers_fivem".to_owned(),
                                    serde_json::Value::from(covers),
                                );
                            }
                            Cover::NotAPath => {}
                            Cover::NoFolders => {
                                gaps.insert(
                                    "covers_fivem".to_owned(),
                                    UnmeasuredReason::ReadFailed,
                                );
                            }
                        }
                    }
                    fields.insert("kind".to_owned(), serde_json::Value::from(kind));
                    fields.insert("set_by".to_owned(), serde_json::Value::from(set_by));
                    fields.insert("exclusion".to_owned(), serde_json::Value::from(exclusion));
                    observations.push(Observation {
                        collector: ID.to_owned(),
                        fields,
                    });
                }
            }
            match host.value_names(&format!(r"{root}\{IP_ADDRESSES}")) {
                Ok(Some(names)) => observations.push(Observation {
                    collector: ID.to_owned(),
                    fields: BTreeMap::from([
                        ("set_by".to_owned(), serde_json::Value::from(set_by)),
                        (
                            "ip_addresses".to_owned(),
                            serde_json::Value::from(names.len()),
                        ),
                    ]),
                }),
                Ok(None) => {}
                Err(error) => return unmeasured(failure::reason_for(host, &error)),
            }
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

/// `FiveM`'s three folders, as `fivem_dir` names them, where this account's environment places them —
/// whether or not they exist on this PC (ADR 0060, owner decision 7).
fn fivem_folders(host: &dyn Host) -> Vec<String> {
    let under = |variable: &str, relative: &str| {
        host.env_var(variable)
            .filter(|root| paths::is_drive_rooted(root))
            .map(|root| format!(r"{}\{relative}", root.trim_end_matches(['\\', '/'])))
    };
    [
        under(
            fivem_dir::LOCAL_APP_DATA,
            fivem_dir::LEGACY_PROGRAM_RELATIVE_PATH,
        ),
        under(
            fivem_dir::LOCAL_APP_DATA,
            fivem_dir::ENHANCED_PROGRAM_RELATIVE_PATH,
        ),
        under(
            fivem_dir::ROAMING_APP_DATA,
            fivem_dir::ENHANCED_PROGRAM_RELATIVE_PATH,
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// What can be said of one exclusion and `FiveM`'s folders.
#[derive(Debug, PartialEq, Eq)]
enum Cover {
    Answer(bool),
    /// A wildcard, a variable this account does not have, or not a drive-letter path: how Defender
    /// reads it is not established here, so nothing is said.
    NotAPath,
    /// No `FiveM` folder could be placed, because this account has neither `%LOCALAPPDATA%` nor
    /// `%APPDATA%`.
    NoFolders,
}

/// Whether `exclusion` is one of `folders`, a folder above one (a drive root included), or inside one,
/// compared without ASCII case and without a trailing separator.
fn covers(host: &dyn Host, exclusion: &str, folders: &[String]) -> Cover {
    if exclusion.contains(['*', '?']) {
        return Cover::NotAPath;
    }
    let Some(expanded) = expand(host, exclusion) else {
        return Cover::NotAPath;
    };
    let expanded = expanded.replace('/', "\\");
    if !paths::is_drive_rooted(&expanded) {
        return Cover::NotAPath;
    }
    if folders.is_empty() {
        return Cover::NoFolders;
    }
    let exclusion = expanded.trim_end_matches('\\');
    Cover::Answer(folders.iter().any(|folder| {
        folder.eq_ignore_ascii_case(exclusion)
            || is_under(folder, exclusion)
            || is_under(exclusion, folder)
    }))
}

/// `text` with every `%…%` replaced by this account's value, or `None` when one is not set or a `%`
/// has no partner.
fn expand(host: &dyn Host, text: &str) -> Option<String> {
    let mut expanded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        let value = host.env_var(&after[..end])?;
        expanded.push_str(value.trim_end_matches(['\\', '/']));
        rest = &after[end + 1..];
    }
    expanded.push_str(rest);
    Some(expanded)
}

/// Whether `path` is inside the folder `root`, compared without ASCII case.
fn is_under(path: &str, root: &str) -> bool {
    path.len() > root.len()
        && path.is_char_boundary(root.len())
        && path[..root.len()].eq_ignore_ascii_case(root)
        && path[root.len()..].starts_with('\\')
}

#[cfg(test)]
mod tests {
    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    const ENV: &str = "platform: windows\nelevated: true\nenv:\n  LOCALAPPDATA: 'C:\\Users\\alex\\AppData\\Local'\n  APPDATA: 'C:\\Users\\alex\\AppData\\Roaming'\n  USERPROFILE: 'C:\\Users\\alex'\n";

    fn inline(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    fn observations(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn exclusion<'a>(observations: &'a [Observation], text: &str) -> &'a Observation {
        observations
            .iter()
            .find(|o| o.fields.get("exclusion").and_then(|v| v.as_str()) == Some(text))
            .unwrap_or_else(|| panic!("no {text}: {observations:?}"))
    }

    #[test]
    fn a_folder_is_covered_when_the_exclusion_is_it_above_it_or_inside_it() {
        let host = inline(ENV);
        let folders = fivem_folders(&host);
        assert_eq!(folders.len(), 3);
        for (text, expected) in [
            (r"C:\", Cover::Answer(true)),
            (r"c:\users\alex\appdata\local\fivem\", Cover::Answer(true)),
            (
                r"C:\Users\alex\AppData\Local\FiveM\FiveM.app\data",
                Cover::Answer(true),
            ),
            (r"%APPDATA%\FiveM for GTAV Enhanced", Cover::Answer(true)),
            (r"%USERPROFILE%", Cover::Answer(true)),
            (
                r"C:\Users\alex\AppData\Local\FiveMods",
                Cover::Answer(false),
            ),
            (r"D:\", Cover::Answer(false)),
            (r"C:\Users\alex\Downloads", Cover::Answer(false)),
            (r"C:\Users\*\AppData", Cover::NotAPath),
            (r"%UNSET%\x", Cover::NotAPath),
            ("FiveM.exe", Cover::NotAPath),
        ] {
            assert_eq!(covers(&host, text, &folders), expected, "{text}");
        }
        assert_eq!(covers(&host, r"C:\", &[]), Cover::NoFolders);
    }

    #[test]
    fn every_exclusion_is_listed_with_its_kind_and_key_and_addresses_are_only_counted() {
        let host = inline(&format!(
            "{ENV}registry:\n  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths':\n    'C:\\': 0\n    'D:\\Build': 0\n  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes':\n    'C:\\Users\\alex\\AppData\\Local\\FiveM\\FiveM.exe': 0\n  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions':\n    '.asi': 0\n  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\IpAddresses':\n    '192.0.2.10': 0\n    '192.0.2.11': 0\n  'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths':\n    'E:\\Games': 0\n"
        ));
        let run = DefenderExclusion.collect(&host);
        let observations = observations(&run);
        let root = exclusion(observations, r"C:\");
        assert_eq!(root.fields["kind"], "path");
        assert_eq!(root.fields["set_by"], "settings");
        assert_eq!(root.fields["covers_fivem"], true);
        assert_eq!(
            exclusion(observations, r"D:\Build").fields["covers_fivem"],
            false
        );
        let process = exclusion(observations, r"C:\Users\alex\AppData\Local\FiveM\FiveM.exe");
        assert_eq!(process.fields["kind"], "process");
        assert_eq!(process.fields["covers_fivem"], true);
        let extension = exclusion(observations, ".asi");
        assert_eq!(extension.fields["kind"], "extension");
        assert!(!extension.fields.contains_key("covers_fivem"));
        let policy = exclusion(observations, r"E:\Games");
        assert_eq!(policy.fields["set_by"], "policy");
        let counted: Vec<&Observation> = observations
            .iter()
            .filter(|o| o.fields.contains_key("ip_addresses"))
            .collect();
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].fields["ip_addresses"], 2);
        let all = format!("{observations:?}");
        assert!(!all.contains("192.0.2"), "{all}");
    }

    #[test]
    fn a_refusal_is_not_admin_without_rights_and_access_denied_with_them() {
        for (elevated, reason) in [
            ("false", UnmeasuredReason::NotAdmin),
            ("true", UnmeasuredReason::AccessDenied),
        ] {
            let host = inline(&format!(
                "platform: windows\nelevated: {elevated}\naccess_denied: ['HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths']\n"
            ));
            assert_eq!(
                DefenderExclusion.collect(&host),
                CollectorRun::Unmeasured {
                    collector: ID.to_owned(),
                    reason,
                }
            );
        }
    }

    #[test]
    fn no_exclusion_is_a_measurement_and_another_os_is_not() {
        let run = DefenderExclusion.collect(&inline(ENV));
        assert!(observations(&run).is_empty());
        assert_eq!(
            DefenderExclusion.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    #[test]
    fn a_path_with_no_fivem_folder_to_compare_is_a_gap() {
        let host = inline(
            "platform: windows\nregistry:\n  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths':\n    'C:\\': 0\n",
        );
        match DefenderExclusion.collect(&host) {
            CollectorRun::Measured { gaps, .. } => {
                assert_eq!(
                    gaps.get("covers_fivem"),
                    Some(&UnmeasuredReason::ReadFailed)
                );
            }
            other @ CollectorRun::Unmeasured { .. } => panic!("{other:?}"),
        }
    }
}
