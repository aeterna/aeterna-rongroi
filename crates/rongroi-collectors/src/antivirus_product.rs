// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The antivirus products Windows Security Center lists, and what each says of itself (ADR 0090).
//!
//! One summary observation always carries `products` and `products_on`; then one observation per
//! product carries its `display_name`, its `state` (and `state_value` when the state is one this
//! program does not name), and, when `RemediationPath` names a file on a local drive, its path and the
//! file's SHA-256 and signature. A path that is not drive-rooted is withheld whole, so a URI or a
//! share name never reaches the report.
//!
//! The list is read once, through the host's Security Center source. A Server edition is decided
//! first, from the same `InstallationType` value `os_image` reads, because Microsoft documents no
//! supported server for the API. No administrator rights are needed: a refusal is `not_admin` only
//! when this scan did not already hold them.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{AntivirusProductRecord, Host, NotLocal, Platform, SignatureCheck, SourceError};

use crate::{Collector, Field, failure, fivem_dir, os_image, paths, prefetch};

const ID: &str = "antivirus_product";

/// How long this collector reads files before it stops and says so. Checked before each file.
/// ADR 0090 sets five seconds from A0's one file (about 0.7 s) and the three products expected.
pub const BUDGET: Duration = Duration::from_secs(5);

/// The value under `os_image`'s key that says whether this is a client or a Server edition.
const INSTALLATION_TYPE: &str = "InstallationType";

/// The two fields a file's hash and signature can be a gap in.
const FILE_GAP_FIELDS: [&str; 2] = ["sha256", "signature"];

static FIELDS: [Field; 13] = [
    Field::text("display_name"),
    Field::text("file_unread"),
    Field::text("path"),
    Field::text("path_kind"),
    Field::text("path_withheld"),
    Field::number("products"),
    Field::number("products_on"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::text("state"),
    Field::number("state_value"),
];

static REASONS: [UnmeasuredReason; 7] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotOnThisOs,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::BudgetSpent,
    UnmeasuredReason::ReadFailed,
    // A path the host refused to open, off the local drives (ADR 0091).
    UnmeasuredReason::NotAttempted,
];

/// Reads the antivirus products Windows Security Center lists.
#[derive(Debug, Clone, Copy)]
pub struct AntivirusProduct {
    /// How long hashing and signature checks may take before the remaining files are left with
    /// `budget_spent`.
    pub budget: Duration,
}

impl Default for AntivirusProduct {
    fn default() -> Self {
        Self { budget: BUDGET }
    }
}

impl Collector for AntivirusProduct {
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
        // A Server edition is decided before the call, so the answer never depends on what the API
        // does there (ADR 0090 section 4). A failed or absent read is not a Server.
        if host
            .read_string(os_image::CURRENT_VERSION_KEY, INSTALLATION_TYPE)
            .ok()
            .flatten()
            .is_some_and(|installation_type| installation_type.starts_with("Server"))
        {
            return unmeasured(UnmeasuredReason::NotOnThisOs);
        }
        let products = match host.antivirus_products() {
            Ok(products) => products,
            Err(error @ SourceError::AccessDenied) => {
                return unmeasured(failure::reason_for(host, &error));
            }
            // A fixture with no block never modelled Security Center's list, so its silence is not
            // "nothing listed" (ADR 0090 section 4).
            Err(_) => return unmeasured(UnmeasuredReason::ReadFailed),
        };

        let started = Instant::now();
        let mut observations = vec![summary(&products)];
        let mut gaps = BTreeMap::new();
        for product in &products {
            observations.push(self.product(host, product, started, &mut gaps));
        }
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps,
            discriminator_gaps: Vec::new(),
        }
    }
}

impl AntivirusProduct {
    /// One product's observation, and the gaps its file leaves.
    fn product(
        &self,
        host: &dyn Host,
        product: &AntivirusProductRecord,
        started: Instant,
        gaps: &mut BTreeMap<String, UnmeasuredReason>,
    ) -> Observation {
        let mut fields = BTreeMap::new();
        fields.insert(
            "display_name".to_owned(),
            serde_json::Value::from(product.display_name.clone()),
        );
        let (state, state_value) = state_of(product.state);
        fields.insert("state".to_owned(), serde_json::Value::from(state));
        if let Some(value) = state_value {
            fields.insert("state_value".to_owned(), serde_json::Value::from(value));
        }

        let path = &product.remediation_path;
        if !path.is_empty() {
            if paths::is_drive_rooted(path) {
                fields.insert("path".to_owned(), serde_json::Value::from(path.clone()));
                fields.insert(
                    "path_kind".to_owned(),
                    serde_json::Value::from(path_kind(host, path)),
                );
                if started.elapsed() >= self.budget {
                    for field in FILE_GAP_FIELDS {
                        note(gaps, field, UnmeasuredReason::BudgetSpent);
                    }
                } else {
                    file_fields(host, path, &mut fields, gaps);
                }
            } else {
                // A URI or a share path: withheld whole, so no part of it reaches the report. This is
                // a fact about the path, not a gap.
                fields.insert(
                    "path_withheld".to_owned(),
                    serde_json::Value::from(paths::UNREDACTABLE_FORM),
                );
                fields.insert(
                    "file_unread".to_owned(),
                    serde_json::Value::from(NotLocal::NotDriveRooted.as_str()),
                );
            }
        }

        Observation {
            collector: ID.to_owned(),
            fields,
        }
    }
}

/// The one observation that says how many products Windows lists and how many report themselves on.
fn summary(products: &[AntivirusProductRecord]) -> Observation {
    let mut fields = BTreeMap::new();
    fields.insert(
        "products".to_owned(),
        serde_json::Value::from(products.len()),
    );
    fields.insert(
        "products_on".to_owned(),
        serde_json::Value::from(products.iter().filter(|product| product.state == 0).count()),
    );
    Observation {
        collector: ID.to_owned(),
        fields,
    }
}

/// The text and, for a value this program does not name, the number of a product's state.
fn state_of(state: i32) -> (&'static str, Option<i32>) {
    match state {
        0 => ("on", None),
        1 => ("off", None),
        2 => ("snoozed", None),
        3 => ("expired", None),
        other => ("other", Some(other)),
    }
}

/// What hashing and checking one file came to, as `autostart` reports it.
enum FileState {
    Described {
        sha256: String,
        signature: Result<SignatureCheck, UnmeasuredReason>,
    },
    /// The file is not there: no gap, because there is no file to be vulnerable (ADR 0048).
    Missing,
    /// Not opened: the path does not stay on a local drive (ADR 0091).
    NotLocal(NotLocal),
    Failed(UnmeasuredReason),
}

/// Writes the hash and signature fields of one drive-rooted file, or the gaps it leaves.
fn file_fields(
    host: &dyn Host,
    path: &str,
    fields: &mut BTreeMap<String, serde_json::Value>,
    gaps: &mut BTreeMap<String, UnmeasuredReason>,
) {
    match describe_file(host, path) {
        FileState::Described { sha256, signature } => {
            fields.insert("sha256".to_owned(), serde_json::Value::from(sha256));
            match signature {
                Ok(check) => fivem_dir::insert_signature(fields, check),
                Err(reason) => note(gaps, "signature", reason),
            }
        }
        // A refused path keeps its path and says why on its row; its file fields were not attempted.
        FileState::NotLocal(not_local) => {
            fields.insert(
                "file_unread".to_owned(),
                serde_json::Value::from(not_local.as_str()),
            );
            for field in FILE_GAP_FIELDS {
                note(gaps, field, UnmeasuredReason::NotAttempted);
            }
        }
        // Not there: a registration left behind, not a gap.
        FileState::Missing => {}
        FileState::Failed(reason) => {
            for field in FILE_GAP_FIELDS {
                note(gaps, field, reason);
            }
        }
    }
}

/// Hashes `path`, then checks its signature. A refusal is never read as "the file is not there".
fn describe_file(host: &dyn Host, path: &str) -> FileState {
    let sha256 = match fivem_dir::file_sha256(host, path) {
        Some(digest) => digest,
        // The helper swallows the reason, so the same read is asked once more to classify it.
        None => match host.file_sha256(path) {
            Err(SourceError::AccessDenied) => {
                return FileState::Failed(UnmeasuredReason::AccessDenied);
            }
            Err(SourceError::NotLocal(not_local)) => return FileState::NotLocal(not_local),
            Err(_) if is_missing(host, path) => return FileState::Missing,
            Err(error) => return FileState::Failed(reason(&error)),
            // The bytes were read, but the digest was not one `allow` can compare.
            Ok(_) => return FileState::Failed(UnmeasuredReason::ReadFailed),
        },
    };
    let signature = host.file_signature(path).map_err(|error| reason(&error));
    FileState::Described { sha256, signature }
}

/// Whether the folder that should hold `path` says it does not: the folder is not there, or lists no
/// file of that name. A folder this program could not list says nothing.
fn is_missing(host: &dyn Host, path: &str) -> bool {
    let Some((dir, name)) = parent_and_name(path) else {
        return false;
    };
    match host.list_dir(dir) {
        Ok(None) => true,
        Ok(Some(entries)) => !entries
            .iter()
            .any(|entry| entry.name.eq_ignore_ascii_case(name)),
        Err(_) => false,
    }
}

/// Splits `path` into its folder and name, keeping the separator of a bare drive so that its root is
/// listed rather than the current folder on that drive.
fn parent_and_name(path: &str) -> Option<(&str, &str)> {
    let index = path.rfind(['\\', '/'])?;
    let (dir, name) = (&path[..index], &path[index + 1..]);
    if dir.len() == 2 && dir.as_bytes()[1] == b':' {
        Some((&path[..=index], name))
    } else {
        Some((dir, name))
    }
}

/// A refusal of a file is `access_denied` whatever the token: this collector needs no administrator
/// rights (ADR 0090), so a restart would not be the remedy.
fn reason(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::NotLocal(_) => UnmeasuredReason::NotAttempted,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

/// Keeps the reason that outranks the other: the budget first, because it says the rest was never
/// tried, then a refusal a person can act on, then a failure nobody can — `driver_service`'s order.
fn note(gaps: &mut BTreeMap<String, UnmeasuredReason>, field: &str, reason: UnmeasuredReason) {
    let rank = |reason: UnmeasuredReason| match reason {
        UnmeasuredReason::BudgetSpent => 0,
        UnmeasuredReason::AccessDenied => 1,
        _ => 2,
    };
    if gaps
        .get(field)
        .is_none_or(|current| rank(reason) < rank(*current))
    {
        gaps.insert(field.to_owned(), reason);
    }
}

/// The kind of folder a file is in (ADR 0060, section 5), as `autostart` reads it.
///
/// `autostart` keeps this on its own `Context`, which is not exposed across modules, so the rule is
/// repeated here rather than copied into a second public path: the same roots and the same redaction
/// decide `windows`, `program_files`, `program_data`, `user_profile` and `other`.
fn path_kind(host: &dyn Host, path: &str) -> &'static str {
    let system_root = host
        .env_var(prefetch::SYSTEM_ROOT)
        .filter(|root| paths::is_drive_rooted(root))
        .map(|root| root.trim_end_matches(['\\', '/']).to_owned());
    if let Some(root) = &system_root {
        let temp = format!(r"{root}\Temp");
        if is_under(path, root) && !is_under(path, &temp) {
            return "windows";
        }
    }
    let env_root = |name: &str| {
        host.env_var(name)
            .filter(|root| paths::is_drive_rooted(root))
            .map(|root| root.trim_end_matches(['\\', '/']).to_owned())
    };
    if ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .into_iter()
        .filter_map(env_root)
        .any(|root| is_under(path, &root))
    {
        return "program_files";
    }
    if env_root("ProgramData").is_some_and(|root| is_under(path, &root)) {
        return "program_data";
    }
    if rongroi_core::view::redact_profile_paths(
        path,
        crate::scan::profiles_directory(host).as_deref(),
    ) != path
    {
        return "user_profile";
    }
    "other"
}

/// Whether `path` is inside the folder `root`, compared without ASCII case.
fn is_under(path: &str, root: &str) -> bool {
    path.len() > root.len()
        && path.is_char_boundary(root.len())
        && path[..root.len()].eq_ignore_ascii_case(root)
        && path[root.len()..].starts_with(['\\', '/'])
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

    fn measured(run: &CollectorRun) -> (&[Observation], &BTreeMap<String, UnmeasuredReason>) {
        match run {
            CollectorRun::Measured {
                observations, gaps, ..
            } => (observations, gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn summary_observation(observations: &[Observation]) -> &Observation {
        observations
            .iter()
            .find(|observation| observation.fields.contains_key("products"))
            .unwrap_or_else(|| panic!("no summary observation: {observations:?}"))
    }

    fn product<'a>(observations: &'a [Observation], name: &str) -> &'a Observation {
        observations
            .iter()
            .find(|observation| {
                observation
                    .fields
                    .get("display_name")
                    .is_some_and(|value| value == name)
            })
            .unwrap_or_else(|| panic!("no observation for {name}"))
    }

    fn text<'a>(observation: &'a Observation, field: &str) -> Option<&'a str> {
        observation
            .fields
            .get(field)
            .and_then(serde_json::Value::as_str)
    }

    fn unmeasured(reason: UnmeasuredReason) -> CollectorRun {
        CollectorRun::Unmeasured {
            collector: "antivirus_product".to_owned(),
            reason,
        }
    }

    #[test]
    fn non_windows_is_unmeasured() {
        assert_eq!(
            AntivirusProduct::default().collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
    }

    /// `path_kind` names the same folders `autostart` names (ADR 0060).
    #[test]
    fn path_kind_names_the_folder_a_file_is_in() {
        let host = inline(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\n  ProgramFiles: 'C:\\Program Files'\n  ProgramData: 'C:\\ProgramData'\n",
        );
        for (path, kind) in [
            (r"C:\Windows\System32\svchost.exe", "windows"),
            (r"C:\Windows\Temp\x.exe", "other"),
            (r"C:\Program Files\Vendor\x.exe", "program_files"),
            (r"C:\ProgramData\Vendor\x.exe", "program_data"),
            (r"C:\Users\fixtureuser\AppData\Local\x.exe", "user_profile"),
            (r"C:\tools\x.exe", "other"),
        ] {
            assert_eq!(path_kind(&host, path), kind, "{path}");
        }
    }

    /// A Server edition is not measured, and the API is never asked: Microsoft documents no
    /// supported server for it (ADR 0090 section 4).
    #[test]
    fn a_server_edition_is_not_on_this_os() {
        let host = inline(
            "platform: windows\nregistry:\n  'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion':\n    InstallationType: 'Server'\n",
        );
        assert_eq!(
            AntivirusProduct::default().collect(&host),
            unmeasured(UnmeasuredReason::NotOnThisOs)
        );
    }

    /// A failed or absent `InstallationType` read is not a Server: the API call decides.
    #[test]
    fn a_missing_installation_type_is_not_read_as_a_server() {
        let host = inline("platform: windows\nantivirus_products: []\n");
        let run = AntivirusProduct::default().collect(&host);
        let (observations, _) = measured(&run);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].fields["products"], 0);
    }

    /// A fixture with no `antivirus_products:` block never modelled Security Center's list, so its
    /// silence is `Unmeasured`, never "nothing listed" (ADR 0090 section 4).
    #[test]
    fn a_fixture_with_no_block_is_unmeasured() {
        let host = inline("platform: windows\n");
        assert_eq!(
            AntivirusProduct::default().collect(&host),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
    }

    /// Silence about the list is never the claim that Security Center lists none: a fixture with no
    /// block is `read_failed`, and no `products` count reaches the report (ADR 0090 section 4).
    #[test]
    fn a_fixture_with_no_block_is_read_failed_and_never_zero_products() {
        let run = AntivirusProduct::default().collect(&inline("platform: windows\n"));
        assert_eq!(run, unmeasured(UnmeasuredReason::ReadFailed));
        let json = serde_json::to_string(&run).unwrap();
        assert!(!json.contains("\"products\""), "{json}");
    }

    /// A refused list is `not_admin` only when this scan did not already hold administrator rights;
    /// with them it is `access_denied`, because a restart would not change the answer.
    #[test]
    fn a_refused_list_is_not_admin_without_admin_rights_and_access_denied_with_them() {
        for (elevated, reason) in [
            (false, UnmeasuredReason::NotAdmin),
            (true, UnmeasuredReason::AccessDenied),
        ] {
            let host = inline(&format!(
                "platform: windows\nelevated: {elevated}\nantivirus_products_failure: access_denied\nantivirus_products: []\n"
            ));
            assert_eq!(
                AntivirusProduct::default().collect(&host),
                unmeasured(reason),
                "elevated: {elevated}"
            );
        }
    }

    /// A list whose read failed is `read_failed`, whatever a list beside it would have said.
    #[test]
    fn a_failed_list_is_read_failed() {
        let host = inline(
            "platform: windows\nantivirus_products_failure: read_failed\nantivirus_products: []\n",
        );
        assert_eq!(
            AntivirusProduct::default().collect(&host),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn an_empty_list_is_measured_and_says_zero_products() {
        let host = inline("platform: windows\nantivirus_products: []\n");
        let run = AntivirusProduct::default().collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(observations.len(), 1, "{observations:?}");
        assert_eq!(summary_observation(observations).fields["products"], 0);
        assert_eq!(summary_observation(observations).fields["products_on"], 0);
    }

    /// Defender's `RemediationPath` is a URI (A0), so its row carries a name and a state and no
    /// file evidence. The value itself must not reach the report.
    #[test]
    fn defenders_uri_is_a_name_and_a_state_and_withheld_path() {
        let host = inline(
            "platform: windows\nantivirus_products:\n  - display_name: 'Antivirus Microsoft Defender'\n    state: 0\n    remediation_path: 'windowsdefender://'\n",
        );
        let run = AntivirusProduct::default().collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let defender = product(observations, "Antivirus Microsoft Defender");
        assert_eq!(text(defender, "state"), Some("on"));
        assert_eq!(text(defender, "path"), None);
        assert_eq!(text(defender, "path_kind"), None);
        assert_eq!(
            text(defender, "path_withheld"),
            Some(paths::UNREDACTABLE_FORM)
        );
        assert_eq!(text(defender, "file_unread"), Some("not_drive_rooted"));
        let json = serde_json::to_string(observations)
            .unwrap()
            .to_ascii_lowercase();
        assert!(!json.contains("windowsdefender"), "{json}");
    }

    /// A UNC path is withheld whole, so neither the server nor the share reaches the observation.
    #[test]
    fn a_unc_path_is_withheld_and_named_nothing() {
        let host = inline(
            "platform: windows\nantivirus_products:\n  - display_name: 'Example Antivirus'\n    state: 0\n    remediation_path: '\\\\server\\share\\av.exe'\n",
        );
        let run = AntivirusProduct::default().collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let example = product(observations, "Example Antivirus");
        assert_eq!(text(example, "path"), None);
        assert_eq!(
            text(example, "path_withheld"),
            Some(paths::UNREDACTABLE_FORM)
        );
        assert_eq!(text(example, "file_unread"), Some("not_drive_rooted"));
        let json = serde_json::to_string(observations).unwrap();
        assert!(!json.contains("server"), "{json}");
        assert!(!json.contains("share"), "{json}");
    }

    #[test]
    fn a_drive_rooted_file_gets_its_path_kind_hash_and_signature() {
        let host = inline(
            "platform: windows\nenv:\n  ProgramFiles: 'C:\\Program Files'\nantivirus_products:\n  - display_name: 'Example Antivirus'\n    state: 0\n    remediation_path: 'C:\\Program Files\\Vendor\\av.exe'\nfilesystem:\n  'C:\\Program Files\\Vendor':\n    - name: av.exe\n      sha256: 891e48128dc9c287aaa204757acac61d469eef9de82714cec4404d254a73c844\n      signature:\n        state: valid\n        signer: Vendor Ltd\n        signer_cert_sha256: 65866007102ff66498c1ef739cf23dff71ae3d08da0d9d759b89d1a409c4208f\n",
        );
        let run = AntivirusProduct::default().collect(&host);
        let (observations, gaps) = measured(&run);
        assert!(gaps.is_empty(), "{gaps:?}");
        let av = product(observations, "Example Antivirus");
        assert_eq!(text(av, "path"), Some(r"C:\Program Files\Vendor\av.exe"));
        assert_eq!(text(av, "path_kind"), Some("program_files"));
        assert_eq!(
            text(av, "sha256"),
            Some("891e48128dc9c287aaa204757acac61d469eef9de82714cec4404d254a73c844")
        );
        assert_eq!(text(av, "signature"), Some("valid"));
        assert_eq!(text(av, "signer"), Some("Vendor Ltd"));
        assert_eq!(
            text(av, "signer_cert_sha256"),
            Some("65866007102ff66498c1ef739cf23dff71ae3d08da0d9d759b89d1a409c4208f")
        );
        assert!(!av.fields.contains_key("file_unread"), "{av:?}");
    }

    /// A file on a mapped network letter keeps its path but is never opened: no hash, no signature,
    /// `file_unread: not_local_drive`, and both file fields are `not_attempted` (ADR 0091).
    #[test]
    fn a_network_letter_is_not_local_drive() {
        let host = inline(
            "platform: windows\ndrive_map:\n  - { letter: 'C', device: '\\Device\\HarddiskVolume1', serial: 1, kind: fixed }\n  - { letter: 'Z', device: '\\Device\\Mup', serial: 2, kind: other }\nantivirus_products:\n  - display_name: 'Example Antivirus'\n    state: 0\n    remediation_path: 'Z:\\Apps\\av.exe'\nfilesystem:\n  'Z:\\Apps':\n    - name: av.exe\n      sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
        );
        let run = AntivirusProduct::default().collect(&host);
        let (observations, gaps) = measured(&run);
        let av = product(observations, "Example Antivirus");
        assert_eq!(text(av, "path"), Some(r"Z:\Apps\av.exe"));
        assert_eq!(text(av, "sha256"), None, "{av:?}");
        assert_eq!(text(av, "signature"), None, "{av:?}");
        assert_eq!(text(av, "file_unread"), Some("not_local_drive"));
        for field in FILE_GAP_FIELDS {
            assert_eq!(
                gaps.get(field),
                Some(&UnmeasuredReason::NotAttempted),
                "{field}"
            );
        }
    }

    /// A missing file is a leftover registration: the path is reported and neither file field is a
    /// gap, because there is no file to read.
    #[test]
    fn a_missing_file_keeps_its_path_and_is_not_a_gap() {
        let host = inline(
            "platform: windows\nantivirus_products:\n  - display_name: 'Example Antivirus'\n    state: 0\n    remediation_path: 'C:\\Program Files\\Gone\\av.exe'\nfilesystem:\n  'C:\\Program Files\\Gone':\n    - name: other.exe\n      sha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n",
        );
        let run = AntivirusProduct::default().collect(&host);
        let (observations, gaps) = measured(&run);
        let av = product(observations, "Example Antivirus");
        assert_eq!(text(av, "path"), Some(r"C:\Program Files\Gone\av.exe"));
        assert_eq!(text(av, "sha256"), None);
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn a_state_outside_the_four_documented_ones_is_other_with_its_number() {
        let host = inline(
            "platform: windows\nantivirus_products:\n  - display_name: 'Example Antivirus'\n    state: 7\n",
        );
        let run = AntivirusProduct::default().collect(&host);
        let (observations, _) = measured(&run);
        let av = product(observations, "Example Antivirus");
        assert_eq!(text(av, "state"), Some("other"));
        assert_eq!(av.fields["state_value"], 7);
    }

    #[test]
    fn two_products_count_and_one_reports_on() {
        let host = inline(
            "platform: windows\nantivirus_products:\n  - display_name: 'One Antivirus'\n    state: 0\n  - display_name: 'Two Antivirus'\n    state: 1\n",
        );
        let run = AntivirusProduct::default().collect(&host);
        let (observations, _) = measured(&run);
        assert_eq!(summary_observation(observations).fields["products"], 2);
        assert_eq!(summary_observation(observations).fields["products_on"], 1);
        assert_eq!(
            text(product(observations, "One Antivirus"), "state"),
            Some("on")
        );
        assert_eq!(
            text(product(observations, "Two Antivirus"), "state"),
            Some("off")
        );
    }

    #[test]
    fn a_spent_budget_gaps_both_file_fields_and_keeps_the_path() {
        let host = inline(
            "platform: windows\nantivirus_products:\n  - display_name: 'Example Antivirus'\n    state: 0\n    remediation_path: 'C:\\Program Files\\Vendor\\av.exe'\nfilesystem:\n  'C:\\Program Files\\Vendor':\n    - name: av.exe\n      sha256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n",
        );
        let run = AntivirusProduct {
            budget: Duration::ZERO,
        }
        .collect(&host);
        let (observations, gaps) = measured(&run);
        let av = product(observations, "Example Antivirus");
        assert_eq!(text(av, "path"), Some(r"C:\Program Files\Vendor\av.exe"));
        assert_eq!(text(av, "sha256"), None);
        for field in FILE_GAP_FIELDS {
            assert_eq!(
                gaps.get(field),
                Some(&UnmeasuredReason::BudgetSpent),
                "{field}"
            );
        }
    }

    /// The baselines now describe Security Center's list, so this collector is measured there
    /// (ADR 0090 step 3).
    #[test]
    fn every_baseline_lists_defender() {
        for name in [
            "baseline-consumer-win11",
            "baseline-elevated-win11",
            "baseline-hardened-win11",
        ] {
            let run = AntivirusProduct::default().collect(&fixture(name));
            let (observations, gaps) = measured(&run);
            assert!(gaps.is_empty(), "{name}: {gaps:?}");
            assert_eq!(
                summary_observation(observations).fields["products"],
                1,
                "{name}"
            );
            assert_eq!(
                summary_observation(observations).fields["products_on"],
                1,
                "{name}"
            );
            let defender = product(observations, "Antivirus Microsoft Defender");
            assert_eq!(text(defender, "state"), Some("on"), "{name}");
            assert_eq!(
                text(defender, "path_withheld"),
                Some(paths::UNREDACTABLE_FORM),
                "{name}"
            );
        }
    }
}
