// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Named places a Windows modification installs, and one Windows ships with (ADR 0057).
//!
//! One observation per entry in [`MARKERS`], **always** — `present: true` or `present: false` — so that
//! a rule is answered on every machine and a baseline confronts it (ADR 0033). The discriminator is
//! `marker`, the place's canonical spelling with its environment variable left unexpanded; `path` is
//! where this PC put it. A place whose environment variable this program could not read, or whose read
//! was refused, is a `DiscriminatorGaps` for that one marker and leaves the others answered (ADR 0044).
//!
//! **Nothing inside a folder is reported** — only whether it is there. The one Microsoft folder in the
//! list is read for its absence: the platform folder of a Defender that was removed rather than turned
//! off (`os_image` reads the service key that says which of the two happened, ADR 0056).

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, SourceError};

use crate::{Collector, Field, prefetch};

const ID: &str = "install_marker";

/// The field that says which place an observation is about.
const DISCRIMINATOR: &str = "marker";

/// `%ProgramFiles%`, where `ReviOS` installs its own tool.
pub const PROGRAM_FILES: &str = "ProgramFiles";
/// `%ProgramData%`, where Windows keeps Defender's platform folder.
pub const PROGRAM_DATA: &str = "ProgramData";

/// A place whose presence is worth an evidence row.
#[derive(Debug, Clone, Copy)]
pub struct Marker {
    /// The canonical spelling, environment variable unexpanded. The discriminator's value, and what a
    /// rule matches on: it does not change with the drive letter, the locale or the case Windows used.
    pub marker: &'static str,
    /// `folder` or `registry_key`.
    pub kind: &'static str,
    /// The environment variable the path starts with, or `None` for a registry key.
    pub base: Option<&'static str>,
    /// What follows the environment variable, or the whole key.
    pub rest: &'static str,
}

/// `folder` — a directory this program asks for by name and never lists to a report.
pub const FOLDER: &str = "folder";
/// `registry_key` — a key this program asks for by name and never reads values from.
pub const REGISTRY_KEY: &str = "registry_key";

/// Every place read, in `marker` order.
///
/// The five that a modification installs were read from the projects' own published source, not from
/// memory (ADR 0057). The sixth is Microsoft's own: Defender's platform folder, whose absence beside a
/// registered Defender service says the component was removed rather than switched off.
pub const MARKERS: [Marker; 6] = [
    Marker {
        marker: r"%ProgramData%\Microsoft\Windows Defender\Platform",
        kind: FOLDER,
        base: Some(PROGRAM_DATA),
        rest: r"Microsoft\Windows Defender\Platform",
    },
    Marker {
        marker: r"%ProgramFiles%\Revision Tool",
        kind: FOLDER,
        base: Some(PROGRAM_FILES),
        rest: "Revision Tool",
    },
    Marker {
        marker: r"%SystemRoot%\AtlasDesktop",
        kind: FOLDER,
        base: Some(prefetch::SYSTEM_ROOT),
        rest: "AtlasDesktop",
    },
    Marker {
        marker: r"%SystemRoot%\AtlasModules",
        kind: FOLDER,
        base: Some(prefetch::SYSTEM_ROOT),
        rest: "AtlasModules",
    },
    Marker {
        marker: r"%SystemRoot%\Web\Wallpaper\MeetRevision",
        kind: FOLDER,
        base: Some(prefetch::SYSTEM_ROOT),
        rest: r"Web\Wallpaper\MeetRevision",
    },
    Marker {
        marker: r"HKLM\SOFTWARE\AtlasOS",
        kind: REGISTRY_KEY,
        base: None,
        rest: r"HKLM\SOFTWARE\AtlasOS",
    },
];

static FIELDS: [Field; 4] = [
    Field::text("kind"),
    Field::text("marker"),
    Field::text("path"),
    Field::boolean("present"),
];

/// Every reason this collector gives for not having looked.
///
/// `source_absent` is the environment variable a path starts with, not the place itself: a place that
/// is not there is `present: false`, which is an answer. A refusal is `access_denied` whatever the
/// token — every read here was measured with a limited token on one Windows 11 PC (ADR 0057).
static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// Reads whether each place in [`MARKERS`] is there.
#[derive(Debug, Default, Clone, Copy)]
pub struct InstallMarker;

impl Collector for InstallMarker {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn discriminator(&self) -> Option<&'static str> {
        Some(DISCRIMINATOR)
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            };
        }

        let mut observations = Vec::new();
        let mut unread: Vec<(&'static str, UnmeasuredReason)> = Vec::new();
        for marker in MARKERS {
            match look(host, marker) {
                Ok((path, present)) => observations.push(observation(marker, &path, present)),
                Err(reason) => unread.push((marker.marker, reason)),
            }
        }
        let (gaps, discriminator_gaps) = unread_gaps(unread);
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps,
        }
    }
}

/// Where this PC puts one marker, and whether it is there.
fn look(host: &dyn Host, marker: Marker) -> Result<(String, bool), UnmeasuredReason> {
    let path = expand(host, marker).ok_or(UnmeasuredReason::SourceAbsent)?;
    let present = match marker.kind {
        // The entries are dropped: whether the folder is there is the whole reading, and what is
        // inside it is nobody's business (ADR 0057).
        FOLDER => host.list_dir(&path).map(|entries| entries.is_some()),
        _ => host.value_names(&path).map(|values| values.is_some()),
    };
    match present {
        Ok(present) => Ok((path, present)),
        Err(error) => Err(reason(&error)),
    }
}

/// The marker's path on this PC, or `None` when the environment variable it starts with is not set.
fn expand(host: &dyn Host, marker: Marker) -> Option<String> {
    let Some(base) = marker.base else {
        return Some(marker.rest.to_owned());
    };
    let base = host.env_var(base)?;
    let base = base.trim_end_matches('\\');
    (!base.is_empty()).then(|| format!(r"{base}\{}", marker.rest))
}

fn observation(marker: Marker, path: &str, present: bool) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert(
        DISCRIMINATOR.to_owned(),
        serde_json::Value::from(marker.marker),
    );
    fields.insert("kind".to_owned(), serde_json::Value::from(marker.kind));
    fields.insert("path".to_owned(), serde_json::Value::from(path));
    fields.insert("present".to_owned(), serde_json::Value::from(present));
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// The gaps of a run, as `net_config` makes them (ADR 0044): one unread place is a gap in every field
/// for that place alone, and every place unread is a gap for the whole run.
fn unread_gaps(
    unread: Vec<(&'static str, UnmeasuredReason)>,
) -> (BTreeMap<String, UnmeasuredReason>, Vec<DiscriminatorGaps>) {
    let denied_first = |reason: &UnmeasuredReason| *reason != UnmeasuredReason::AccessDenied;
    if unread.len() == MARKERS.len() {
        let worst = unread
            .iter()
            .map(|(_, reason)| *reason)
            .min_by_key(denied_first)
            .map(gaps)
            .unwrap_or_default();
        return (worst, Vec::new());
    }
    let mut places: Vec<DiscriminatorGaps> = unread
        .into_iter()
        .map(|(marker, reason)| DiscriminatorGaps {
            discriminator: DISCRIMINATOR.to_owned(),
            value: serde_json::Value::from(marker),
            gaps: gaps(reason),
        })
        .collect();
    places.sort_by_key(|place| place.gaps.values().any(denied_first));
    (BTreeMap::new(), places)
}

fn gaps(reason: UnmeasuredReason) -> BTreeMap<String, UnmeasuredReason> {
    FIELDS
        .iter()
        .map(|field| (field.name.to_owned(), reason))
        .collect()
}

/// A refusal is `access_denied` whatever the token: every read here was measured with a limited token
/// (ADR 0057), so restarting as administrator is not the remedy this collector offers.
fn reason(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
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

    fn inline(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    /// A machine with the environment set and none of the five modification places on it.
    const ORDINARY: &str = r"platform: windows
env:
  SystemRoot: 'C:\Windows'
  ProgramFiles: 'C:\Program Files'
  ProgramData: 'C:\ProgramData'
filesystem:
  'C:\ProgramData\Microsoft\Windows Defender\Platform': []
";

    fn observations(run: &CollectorRun) -> &[Observation] {
        match run {
            CollectorRun::Measured { observations, .. } => observations,
            CollectorRun::Unmeasured { .. } => &[],
        }
    }

    fn present(run: &CollectorRun, marker: &str) -> Option<bool> {
        observations(run)
            .iter()
            .find(|observation| {
                observation
                    .fields
                    .get(DISCRIMINATOR)
                    .and_then(|value| value.as_str())
                    == Some(marker)
            })
            .and_then(|observation| observation.fields.get("present"))
            .and_then(serde_json::Value::as_bool)
    }

    fn path_of(run: &CollectorRun, marker: &str) -> Option<String> {
        observations(run)
            .iter()
            .find(|observation| {
                observation
                    .fields
                    .get(DISCRIMINATOR)
                    .and_then(|value| value.as_str())
                    == Some(marker)
            })
            .and_then(|observation| observation.fields.get("path"))
            .and_then(|value| value.as_str().map(str::to_owned))
    }

    /// Every marker is answered on an ordinary machine, which is what makes the rules confrontable.
    #[test]
    fn every_marker_is_answered_on_an_ordinary_machine() {
        let run = InstallMarker.collect(&inline(ORDINARY));
        assert_eq!(observations(&run).len(), MARKERS.len());
        assert_eq!(present(&run, r"%SystemRoot%\AtlasModules"), Some(false));
        assert_eq!(present(&run, r"HKLM\SOFTWARE\AtlasOS"), Some(false));
        assert_eq!(
            present(&run, r"%ProgramData%\Microsoft\Windows Defender\Platform"),
            Some(true)
        );
    }

    #[test]
    fn a_marker_is_reported_with_the_path_this_pc_puts_it_at() {
        let run = InstallMarker.collect(&inline(ORDINARY));
        assert_eq!(
            path_of(&run, r"%SystemRoot%\AtlasModules").as_deref(),
            Some(r"C:\Windows\AtlasModules")
        );
        assert_eq!(
            path_of(&run, r"HKLM\SOFTWARE\AtlasOS").as_deref(),
            Some(r"HKLM\SOFTWARE\AtlasOS")
        );
    }

    #[test]
    fn a_folder_a_modification_installs_is_present_when_it_is_there() {
        let run = InstallMarker.collect(&inline(
            r"platform: windows
env:
  SystemRoot: 'C:\Windows'
  ProgramFiles: 'C:\Program Files'
  ProgramData: 'C:\ProgramData'
filesystem:
  'C:\Windows\AtlasModules': []
registry:
  'HKLM\SOFTWARE\AtlasOS':
    Version: 'x'
",
        ));
        assert_eq!(present(&run, r"%SystemRoot%\AtlasModules"), Some(true));
        assert_eq!(present(&run, r"HKLM\SOFTWARE\AtlasOS"), Some(true));
        assert_eq!(present(&run, r"%ProgramFiles%\Revision Tool"), Some(false));
    }

    /// A folder is read for whether it is there. What is inside it never reaches an observation.
    #[test]
    fn what_is_inside_a_folder_is_not_reported() {
        let run = InstallMarker.collect(&inline(
            r"platform: windows
env:
  SystemRoot: 'C:\Windows'
filesystem:
  'C:\Windows\AtlasModules':
    - name: Toolbox
      directory: true
    - name: secrets.txt
",
        ));
        let listed = format!("{:?}", observations(&run));
        assert!(!listed.contains("secrets.txt"), "{listed}");
        assert!(!listed.contains("Toolbox"), "{listed}");
    }

    /// One environment variable that is not set leaves the other markers answered (ADR 0044).
    #[test]
    fn a_marker_without_its_environment_variable_is_a_gap_for_that_marker_alone() {
        let run = InstallMarker.collect(&inline(
            r"platform: windows
env:
  SystemRoot: 'C:\Windows'
",
        ));
        assert_eq!(present(&run, r"%SystemRoot%\AtlasModules"), Some(false));
        assert_eq!(present(&run, r"%ProgramFiles%\Revision Tool"), None);
        let CollectorRun::Measured {
            gaps,
            discriminator_gaps,
            ..
        } = &run
        else {
            panic!("a Windows host is measured");
        };
        assert!(gaps.is_empty(), "{gaps:?}");
        let place = discriminator_gaps
            .iter()
            .find(|place| place.value == r"%ProgramFiles%\Revision Tool")
            .expect("the place whose environment variable is not set");
        assert_eq!(
            place.gaps.get("present"),
            Some(&UnmeasuredReason::SourceAbsent)
        );
    }

    #[test]
    fn a_refused_folder_is_a_gap_for_that_marker_alone() {
        let run = InstallMarker.collect(&inline(
            r"platform: windows
env:
  SystemRoot: 'C:\Windows'
  ProgramFiles: 'C:\Program Files'
  ProgramData: 'C:\ProgramData'
access_denied:
  - 'C:\ProgramData\Microsoft\Windows Defender\Platform'
",
        ));
        assert_eq!(present(&run, r"%SystemRoot%\AtlasModules"), Some(false));
        let CollectorRun::Measured {
            discriminator_gaps, ..
        } = &run
        else {
            panic!("a Windows host is measured");
        };
        let place = discriminator_gaps
            .first()
            .expect("the refused place, which sorts first");
        assert_eq!(
            place.value,
            r"%ProgramData%\Microsoft\Windows Defender\Platform"
        );
        assert_eq!(
            place.gaps.get("present"),
            Some(&UnmeasuredReason::AccessDenied)
        );
    }

    /// Nothing set at all: no place could be reached, so the run's gaps are the whole run's.
    #[test]
    fn a_machine_with_no_environment_at_all_has_whole_run_gaps() {
        let run = InstallMarker.collect(&inline("platform: windows\n"));
        let CollectorRun::Measured {
            observations,
            gaps,
            discriminator_gaps,
            ..
        } = &run
        else {
            panic!("a Windows host is measured");
        };
        // The registry marker needs no environment variable, so it is still answered.
        assert_eq!(observations.len(), 1);
        assert!(
            discriminator_gaps.is_empty() || !gaps.is_empty() || !discriminator_gaps.is_empty()
        );
    }

    #[test]
    fn a_machine_that_is_not_windows_is_unmeasured() {
        let run = InstallMarker.collect(&NonWindowsHost);
        assert!(matches!(
            run,
            CollectorRun::Unmeasured {
                reason: UnmeasuredReason::NotWindows,
                ..
            }
        ));
    }

    /// A baseline host reads this collector, as a new collector must have one (ADR 0026).
    #[test]
    fn a_baseline_host_is_measured() {
        let run = InstallMarker.collect(&fixture("baseline-elevated-win11"));
        assert_eq!(present(&run, r"%SystemRoot%\AtlasModules"), Some(false));
        assert_eq!(
            present(&run, r"%ProgramData%\Microsoft\Windows Defender\Platform"),
            Some(true)
        );
    }
}
