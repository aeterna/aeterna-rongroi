// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The names of the per-server cache folders `FiveM` for GTA V Enhanced keeps (ADR 0055), read only in a
//! full scan (ADR 0052).
//!
//! `%LOCALAPPDATA%\FiveM for GTAV Enhanced\servercache` holds one folder per server the game joined,
//! named with 40 hexadecimal characters (measured on one Windows 11 PC, ADR 0053). What the name is
//! computed from is **not established**: it did not match any endpoint or address in that PC's logs
//! (ADR 0055). It is the same for the same server on the same PC, so it can match two reports, and it is
//! what `fivem_dir` leaves out of its folder activity (ADR 0053).
//!
//! One observation about the folder — whether it is there and how many server folders it holds — and one
//! per server folder with its name and its creation and last-write times from the folder's listing.
//! Nothing inside a server folder is listed or opened. The name is a **server identity**, which SS mode
//! hides unless the player agrees to show it (ADR 0052).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, Observation, ScanTier, SensitiveKind, UnmeasuredReason};
use rongroi_host::{Host, Platform, SourceError};

use crate::{Collector, Field, fivem_dir};

const ID: &str = "fivem_servers";

/// Enhanced's server cache folder, relative to `%LOCALAPPDATA%` (ADR 0053).
pub const SERVER_CACHE_RELATIVE_PATH: &str = r"FiveM for GTAV Enhanced\servercache";

static FIELDS: [Field; 5] = [
    Field::timestamp("created_at"),
    Field::text("folder"),
    Field::timestamp("modified_at"),
    Field::text("server_folder").sensitive(SensitiveKind::ServerIdentity),
    Field::number("server_folders"),
];

static REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// Reads the names of Enhanced's server cache folders.
#[derive(Debug, Default, Clone, Copy)]
pub struct FivemServers;

impl Collector for FivemServers {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn tier(&self) -> ScanTier {
        ScanTier::Full
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        let unmeasured = |reason| CollectorRun::Unmeasured {
            collector: ID.to_owned(),
            reason,
        };
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        let Some(base) = host.env_var(fivem_dir::LOCAL_APP_DATA) else {
            return unmeasured(UnmeasuredReason::ReadFailed);
        };
        let base = base.trim_end_matches(['\\', '/']);
        if base.is_empty() {
            return unmeasured(UnmeasuredReason::ReadFailed);
        }
        let folder = format!(r"{base}\{SERVER_CACHE_RELATIVE_PATH}");
        let entries = match host.list_dir(&folder) {
            // Not there: Enhanced is not installed for this user, or has joined no server.
            Ok(None) => {
                return measured(vec![place(fivem_dir::FOLDER_ABSENT, None)], None);
            }
            Ok(Some(entries)) => entries,
            Err(error) => {
                let reason = match error {
                    SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
                    SourceError::Failed(_)
                    | SourceError::Unsupported(_)
                    | SourceError::TooLarge { .. } => UnmeasuredReason::ReadFailed,
                };
                return measured(
                    vec![place(fivem_dir::FOLDER_UNREADABLE, None)],
                    Some(reason),
                );
            }
        };
        let mut servers: Vec<_> = entries
            .into_iter()
            .filter(|entry| !entry.is_file && fivem_dir::is_server_folder(&entry.name))
            .collect();
        servers.sort_by(|a, b| (a.created, &a.name).cmp(&(b.created, &b.name)));
        let mut observations = vec![place(fivem_dir::FOLDER_LISTED, Some(servers.len()))];
        observations.extend(servers.into_iter().map(|entry| {
            let mut fields = BTreeMap::new();
            fields.insert(
                "server_folder".to_owned(),
                serde_json::Value::from(entry.name),
            );
            fivem_dir::insert_times(&mut fields, entry.created, entry.modified);
            Observation {
                collector: ID.to_owned(),
                fields,
            }
        }));
        measured(observations, None)
    }
}

/// The observation about the server cache folder as a whole.
fn place(folder: &str, server_folders: Option<usize>) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert("folder".to_owned(), serde_json::Value::from(folder));
    if let Some(count) = server_folders {
        fields.insert("server_folders".to_owned(), serde_json::Value::from(count));
    }
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// A measured run; an unreadable folder is a gap in every field.
fn measured(observations: Vec<Observation>, gap: Option<UnmeasuredReason>) -> CollectorRun {
    CollectorRun::Measured {
        collector: ID.to_owned(),
        observations,
        gaps: gap
            .map(|reason| {
                FIELDS
                    .iter()
                    .map(|field| (field.name.to_owned(), reason))
                    .collect()
            })
            .unwrap_or_default(),
        discriminator_gaps: Vec::new(),
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

    fn host(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    fn observations(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    #[test]
    fn it_is_read_only_in_a_full_scan_and_its_name_is_a_server_identity() {
        assert_eq!(FivemServers.tier(), ScanTier::Full);
        let name = FIELDS
            .iter()
            .find(|field| field.name == "server_folder")
            .unwrap();
        assert_eq!(name.sensitive, Some(SensitiveKind::ServerIdentity));
        assert!(
            FIELDS
                .iter()
                .filter(|field| field.name != "server_folder")
                .all(|field| field.sensitive.is_none())
        );
    }

    #[test]
    fn each_server_folder_is_named_with_its_times_and_nothing_else_is() {
        let run = FivemServers.collect(&fixture("fivem-dir-folder-activity"));
        let observations = observations(&run);
        assert_eq!(observations[0].fields["folder"], "listed");
        assert_eq!(observations[0].fields["server_folders"], 2);
        let servers: Vec<&BTreeMap<String, serde_json::Value>> =
            observations[1..].iter().map(|o| &o.fields).collect();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["server_folder"], "a".repeat(40));
        assert_eq!(servers[0]["created_at"], "2026-09-09T14:32:00Z");
        assert_eq!(servers[0]["modified_at"], "2026-09-15T09:18:00Z");
        // Its contents were refused, and nothing here lists them, so it is named like the other.
        assert_eq!(servers[1]["server_folder"], "b".repeat(40));
        let text = serde_json::to_string(observations).unwrap();
        assert!(!text.contains(".bak"), "{text}");
    }

    #[test]
    fn a_missing_folder_is_absent_and_a_refused_one_is_a_gap() {
        let absent =
            host("platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\n");
        let run = FivemServers.collect(&absent);
        assert_eq!(observations(&run).len(), 1);
        assert_eq!(observations(&run)[0].fields["folder"], "absent");

        let refused = host(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\naccess_denied:\n  - 'C:\\Users\\a\\AppData\\Local\\FiveM for GTAV Enhanced\\servercache'\n",
        );
        let CollectorRun::Measured {
            observations, gaps, ..
        } = FivemServers.collect(&refused)
        else {
            panic!("expected a measured run");
        };
        assert_eq!(observations[0].fields["folder"], "unreadable");
        assert_eq!(gaps["server_folder"], UnmeasuredReason::AccessDenied);
    }

    #[test]
    fn without_local_app_data_or_windows_nothing_is_read() {
        assert_eq!(
            FivemServers.collect(&host("platform: windows\n")),
            CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::ReadFailed,
            }
        );
        assert_eq!(
            FivemServers.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }
}
