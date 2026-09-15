// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Driver services registered with Windows, and the SHA-256 of each driver's file (ADR 0046, ADR 0048).
//!
//! One observation per key under `HKLM\SYSTEM\CurrentControlSet\Services` whose `Type` is a kernel or
//! file-system driver: its name, its `Start`, the file its `ImagePath` resolves to and that file's
//! SHA-256. It sees drivers **registered** when the scan runs, loaded or not, and nothing that was
//! registered and removed before it.
//!
//! Every driver service is emitted, as `process` emits every process. A file this program could not hash
//! is a gap on `sha256`, so a rule that matched nothing is `unmeasured` rather than `not_found`; a file
//! that is not there is not a gap, because a service key an uninstaller left behind has no file to be
//! vulnerable. No administrator rights are needed: both machines ADR 0046 measured let a token without
//! Administrators read every key and hash every file, so a refusal is `access_denied`, never `not_admin`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rongroi_core::model::{CollectorRun, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, RegistryData, SourceError};

use crate::{Collector, Field, paths, prefetch};

const ID: &str = "driver_service";

/// The key whose subkeys are the services Windows knows (ADR 0046, `CreateServiceW`).
pub const SERVICES_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

/// How long this collector hashes files before it stops and says so. Checked before each file.
/// ADR 0046 measured 15.5 s cold for 140 MiB on a runner and 8.7 s for 286 MiB on a PC.
pub const BUDGET: Duration = Duration::from_secs(30);

/// `SERVICE_KERNEL_DRIVER`.
const KERNEL_DRIVER: u32 = 1;
/// `SERVICE_FILE_SYSTEM_DRIVER`.
const FILE_SYSTEM_DRIVER: u32 = 2;

/// The one field a gap is ever about.
const HASH_FIELD: &str = "sha256";

static FIELDS: [Field; 4] = [
    Field::text("path"),
    Field::text("service"),
    Field::text("sha256"),
    Field::number("start"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::BudgetSpent,
    UnmeasuredReason::ReadFailed,
];

/// Reads the driver services registered on the machine.
#[derive(Debug, Clone, Copy)]
pub struct DriverService {
    /// How long hashing may take before the remaining files are left unhashed with `budget_spent`.
    pub budget: Duration,
}

impl Default for DriverService {
    fn default() -> Self {
        Self { budget: BUDGET }
    }
}

impl Collector for DriverService {
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
        // Every relative form and the absent one resolve under `%SystemRoot%`, so without it no path
        // could be trusted.
        let Some(system_root) = host
            .env_var(prefetch::SYSTEM_ROOT)
            .filter(|root| paths::is_drive_rooted(root))
        else {
            return unmeasured(UnmeasuredReason::ReadFailed);
        };
        let names = match host.subkeys(SERVICES_KEY) {
            Ok(Some(names)) => names,
            // Every Windows has this key; one that is not there was not read.
            Ok(None) => return unmeasured(UnmeasuredReason::ReadFailed),
            Err(error) => return unmeasured(reason(&error)),
        };

        let started = Instant::now();
        let mut observations = Vec::new();
        let mut gap: Option<UnmeasuredReason> = None;
        for name in &names {
            let key = format!(r"{SERVICES_KEY}\{name}");
            let service = match read_service(host, &key) {
                Ok(Some(service)) => service,
                Ok(None) => continue,
                Err(error) => {
                    note(&mut gap, reason(&error));
                    continue;
                }
            };
            let mut fields = BTreeMap::new();
            fields.insert("service".to_owned(), serde_json::Value::from(name.clone()));
            if let Some(start) = service.start {
                fields.insert("start".to_owned(), serde_json::Value::from(start));
            }
            match resolve(&service.image_path, name, &system_root) {
                None => note(&mut gap, UnmeasuredReason::ReadFailed),
                Some(path) => {
                    if started.elapsed() >= self.budget {
                        note(&mut gap, UnmeasuredReason::BudgetSpent);
                    } else {
                        match hash(host, &path) {
                            Hash::Hashed(digest) => {
                                fields
                                    .insert(HASH_FIELD.to_owned(), serde_json::Value::from(digest));
                            }
                            Hash::Missing => {}
                            Hash::Failed(reason) => note(&mut gap, reason),
                        }
                    }
                    fields.insert("path".to_owned(), serde_json::Value::from(path));
                }
            }
            observations.push(Observation {
                collector: ID.to_owned(),
                fields,
            });
        }

        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: gap
                .map(|reason| (HASH_FIELD.to_owned(), reason))
                .into_iter()
                .collect(),
            discriminator_gaps: Vec::new(),
        }
    }
}

/// What a driver service's key says, of the values this collector reads.
struct Service {
    image_path: ImagePath,
    start: Option<u32>,
}

/// A service's `ImagePath` value, as the registry holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImagePath {
    /// No `ImagePath` value.
    Absent,
    /// A `REG_SZ` or `REG_EXPAND_SZ`, unexpanded.
    Text(String),
    /// A value of another type, which no resolver case covers.
    OtherType,
}

/// The driver service at `key`, or `None` when the key is not a kernel or file-system driver.
fn read_service(host: &dyn Host, key: &str) -> Result<Option<Service>, SourceError> {
    let Some(RegistryData::Dword(kind)) = host.read_value(key, "Type")? else {
        return Ok(None);
    };
    if kind != KERNEL_DRIVER && kind != FILE_SYSTEM_DRIVER {
        return Ok(None);
    }
    let image_path = match host.read_value(key, "ImagePath")? {
        None => ImagePath::Absent,
        Some(RegistryData::Text(text)) => ImagePath::Text(text),
        Some(_) => ImagePath::OtherType,
    };
    let start = match host.read_value(key, "Start")? {
        Some(RegistryData::Dword(start)) => Some(start),
        _ => None,
    };
    Ok(Some(Service { image_path, start }))
}

/// The file a driver service's `ImagePath` names, in drive-letter form, or `None` for a form this
/// program does not understand (ADR 0048, "The resolver").
///
/// Every relative path is read under `%SystemRoot%`: `System32\` and `SysWOW64\` were measured, and a
/// wrong reading of another folder hashes a file with a different hash, so it can cost a `not_found`
/// for a driver that is there and never a `found` for one that is not.
pub fn resolve(image_path: &ImagePath, service: &str, system_root: &str) -> Option<String> {
    const SYSTEM_ROOT_PREFIX: &str = r"\SystemRoot\";
    let root = system_root.trim_end_matches(['\\', '/']);
    let text = match image_path {
        ImagePath::OtherType => return None,
        ImagePath::Absent => "",
        ImagePath::Text(text) => text.as_str(),
    };
    let resolved = if text.is_empty() {
        // The default path is built from the service key's own name, so a name that is itself a
        // separator, a `.`/`..` segment, or a data-stream name (R1: `a:b`) is an unknown form too —
        // nothing else here checks it.
        if is_unusable_segment(service) || service.contains(['\\', '/', ':']) {
            return None;
        }
        format!(r"{root}\System32\drivers\{service}.sys")
    } else if let Some(prefix) = text.get(..SYSTEM_ROOT_PREFIX.len())
        && prefix.eq_ignore_ascii_case(SYSTEM_ROOT_PREFIX)
    {
        format!(r"{root}\{}", &text[SYSTEM_ROOT_PREFIX.len()..])
    } else if let Some(rest) = text.strip_prefix(r"\??\") {
        if !paths::is_drive_rooted(rest) {
            return None;
        }
        rest.to_owned()
    } else if paths::is_drive_rooted(text) {
        text.to_owned()
    } else if text.starts_with(['\\', '/'])
        || text.as_bytes().get(1) == Some(&b':')
        || text.contains(['%', '"'])
    {
        // A relative `ImagePath` is only the shape ADR 0048 measured: no leading `\` or `/`, no
        // drive letter, and no `%` or `"` anywhere — not only leading, so `System32\%X%\a.sys` and
        // `System32\drivers\a".sys` are unknown forms rather than a folder named `%X%` or a file
        // named `a".sys`.
        return None;
    } else {
        format!(r"{root}\{text}")
    };
    // F1: every `/` an installer wrote is read as `\`, so the resolved path is always the one shape
    // `rongroi_core::view::redact_user_paths` reaches.
    let resolved = resolved.replace('/', "\\");
    // R1: a `.` or `..` segment (F1), a repeated or trailing separator (an empty segment), a segment
    // ending in `.` or a space, or one that names an alternate data stream with a `:` past the drive,
    // are all unknown forms rather than paths that resolve to the file they appear to name. The
    // segment right after the drive is also refused when it is the legacy profile folder
    // `Documents and Settings` (a junction to `Users` on current Windows), which
    // `rongroi_core::view::redact_user_paths` does not recognise. Together these keep every reported
    // path under a user profile in the one `X:\Users\<name>` shape that function reaches — no such
    // form was measured on either machine.
    let mut segments = resolved.split('\\');
    segments.next(); // the drive segment, e.g. `C:` — not checked here
    for (index, segment) in segments.enumerate() {
        if is_unusable_segment(segment)
            || segment.is_empty()
            || segment.ends_with(['.', ' '])
            || segment.contains(':')
        {
            return None;
        }
        if index == 0 && segment.eq_ignore_ascii_case("Documents and Settings") {
            return None;
        }
    }
    Some(resolved)
}

/// Whether a path segment is `.` or `..` — never a real file or folder name, only a way to walk out
/// of the folder the rest of the path names.
fn is_unusable_segment(segment: &str) -> bool {
    segment == "." || segment == ".."
}

/// What hashing one file came to.
enum Hash {
    Hashed(String),
    /// The file is not there: a leftover service key, not a gap.
    Missing,
    Failed(UnmeasuredReason),
}

/// Hashes `path`. `file_sha256` answers a missing file and an unreadable one with the same kind of
/// error, so after a failure that is not a refusal, the file's folder is listed: a file the folder
/// does not hold is missing. A refusal (F4) is never read as "the file is not there" — the folder is
/// not even listed for one, because a token that cannot open the file may equally be unable to list
/// its folder, and that would say "missing" about a file this program was refused, not absent.
fn hash(host: &dyn Host, path: &str) -> Hash {
    match host.file_sha256(path) {
        Ok(digest) => Hash::Hashed(digest.to_ascii_lowercase()),
        Err(SourceError::AccessDenied) => Hash::Failed(UnmeasuredReason::AccessDenied),
        Err(_) if is_missing(host, path) => Hash::Missing,
        Err(error) => Hash::Failed(reason(&error)),
    }
}

/// Splits `path` into its parent directory and file name, keeping the separator when the parent is a
/// bare drive.
///
/// `std::fs::read_dir("C:")` lists the process's *current directory on drive C:*, not `C:\` — std joins
/// a relative piece onto a bare `X:` prefix without a separator, which Windows treats as drive-relative.
/// A path with no separator at all, such as a plain file name, has no parent to list.
fn parent_and_name(path: &str) -> Option<(&str, &str)> {
    let index = path.rfind(['\\', '/'])?;
    let (dir, name) = (&path[..index], &path[index + 1..]);
    if dir.len() == 2 && dir.as_bytes()[1] == b':' {
        // Keep the separator so the drive's root is listed, not the current directory on that drive.
        Some((&path[..=index], name))
    } else {
        Some((dir, name))
    }
}

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

/// A refusal is `access_denied` whatever the token: rights were measured sufficient without
/// Administrators (ADR 0046), so a restart as administrator is not the remedy this collector offers.
fn reason(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

/// Keeps the reason that outranks the other: the budget first, because it says the rest was never
/// tried, then a refusal a person can act on, then a failure nobody can.
fn note(gap: &mut Option<UnmeasuredReason>, reason: UnmeasuredReason) {
    let rank = |reason: UnmeasuredReason| match reason {
        UnmeasuredReason::BudgetSpent => 0,
        UnmeasuredReason::AccessDenied => 1,
        _ => 2,
    };
    if gap.is_none_or(|current| rank(reason) < rank(current)) {
        *gap = Some(reason);
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

    fn service<'a>(observations: &'a [Observation], name: &str) -> &'a Observation {
        observations
            .iter()
            .find(|observation| observation.fields["service"] == name)
            .unwrap_or_else(|| panic!("no observation for {name}"))
    }

    fn text<'a>(observation: &'a Observation, field: &str) -> Option<&'a str> {
        observation
            .fields
            .get(field)
            .and_then(serde_json::Value::as_str)
    }

    #[test]
    fn a_bare_drive_keeps_its_separator_and_a_path_with_no_separator_has_no_parent() {
        assert_eq!(parent_and_name(r"C:\drv.sys"), Some((r"C:\", "drv.sys")));
        assert_eq!(
            parent_and_name(r"C:\Windows\System32\drivers\a.sys"),
            Some((r"C:\Windows\System32\drivers", "a.sys"))
        );
        assert_eq!(parent_and_name("C:/x.sys"), Some(("C:/", "x.sys")));
        assert_eq!(parent_and_name("drv.sys"), None);
    }

    #[test]
    fn every_known_form_resolves_under_system_root_or_as_written() {
        let root = r"C:\Windows\";
        let text = |value: &str| ImagePath::Text(value.to_owned());
        for (image_path, expected) in [
            (
                ImagePath::Absent,
                Some(r"C:\Windows\System32\drivers\svc.sys"),
            ),
            (text(""), Some(r"C:\Windows\System32\drivers\svc.sys")),
            (
                text(r"\SystemRoot\System32\drivers\a.sys"),
                Some(r"C:\Windows\System32\drivers\a.sys"),
            ),
            (
                text(r"\systemroot\System32\drivers\a.sys"),
                Some(r"C:\Windows\System32\drivers\a.sys"),
            ),
            (
                text(r"System32\drivers\b.sys"),
                Some(r"C:\Windows\System32\drivers\b.sys"),
            ),
            (
                text(r"SysWOW64\drivers\c.sys"),
                Some(r"C:\Windows\SysWOW64\drivers\c.sys"),
            ),
            (text(r"\??\D:\Vendor\d.sys"), Some(r"D:\Vendor\d.sys")),
            (text(r"E:\Vendor\e.sys"), Some(r"E:\Vendor\e.sys")),
            (text(r"\??\Volume{1}\f.sys"), None),
            (text(r"%ProgramFiles%\g.sys"), None),
            (text(r#""C:\Vendor\h.sys""#), None),
            (text(r"\\server\share\i.sys"), None),
            (text(r"\Device\HarddiskVolume3\j.sys"), None),
            (text("C:relative.sys"), None),
            (text(r"System32\%X%\a.sys"), None),
            (text(r#"System32\drivers\a".sys"#), None),
            (ImagePath::OtherType, None),
            // F1: a `.` or `..` segment, in any form the resolver otherwise accepts, is an unknown
            // form rather than a path that walks out of the folder it appears to name.
            (text(r"System32\..\..\Users\bob\x.sys"), None),
            (text(r"\??\C:\Windows\..\Users\bob\x.sys"), None),
            (text(r".\x.sys"), None),
            // F1: mixed separators are normalised to `\` so the resolved path is the one shape
            // `redact_user_paths` reaches, whichever separator the installer that wrote `ImagePath`
            // used.
            (text(r"C:\Users/bob\x.sys"), Some(r"C:\Users\bob\x.sys")),
            (
                text(r"System32/drivers/a.sys"),
                Some(r"C:\Windows\System32\drivers\a.sys"),
            ),
            // R1: a repeated or trailing separator is an empty path segment once every `/` is read
            // as `\` — an unknown form, not the folder or file the non-empty segments name.
            (text(r"C:\\Users\bob\x.sys"), None),
            (text(r"\??\C:\\Users\bob\x.sys"), None),
            (text(r"C://Users/bob/x.sys"), None),
            (text(r"C:\Users\\bob\x.sys"), None),
            // R1: a segment ending in `.` or a space, or naming an alternate data stream with `:`
            // past the drive, is an unknown form — Windows treats each as a different file or folder
            // than the plain name it looks like.
            (text(r"C:\Users.\bob\x.sys"), None),
            (text(r"C:\Users \bob\x.sys"), None),
            (text(r"C:\Users::$INDEX_ALLOCATION\bob\x.sys"), None),
            // R1: `Documents and Settings` is a junction to `Users` on current Windows, and
            // `redact_user_paths` does not know that shape.
            (text(r"C:\Documents and Settings\bob\x.sys"), None),
        ] {
            assert_eq!(
                resolve(&image_path, "svc", root).as_deref(),
                expected,
                "{image_path:?}"
            );
        }
    }

    /// F1: the absent/empty-`ImagePath` default builds its path from the service name, so a service
    /// name that is itself a separator or a `.`/`..` segment must be an unknown form too — otherwise
    /// a service key named `a/..` would resolve outside `System32\drivers`.
    #[test]
    fn an_absent_image_path_with_an_unusable_service_name_is_an_unknown_form() {
        let root = r"C:\Windows\";
        // R1: a colon in the service name reaches an alternate data stream (`a:b`), the same shape
        // refused inside `ImagePath` itself.
        for service in ["a/..", r"a\b", ".", "..", "/", r"\", "a:b"] {
            assert_eq!(
                resolve(&ImagePath::Absent, service, root),
                None,
                "{service}"
            );
            assert_eq!(
                resolve(&ImagePath::Text(String::new()), service, root),
                None,
                "{service}"
            );
        }
        // An ordinary service name is unaffected.
        assert_eq!(
            resolve(&ImagePath::Absent, "svc", root).as_deref(),
            Some(r"C:\Windows\System32\drivers\svc.sys")
        );
    }

    /// F1: a resolved path under a user profile is redacted the same way any other collector's path
    /// is. This calls `rongroi_core::view::redact_user_paths` directly on the string `resolve`
    /// produced, rather than building a `Found` row through the rule engine, because no rule reads
    /// `driver_service` yet in this pull request (ADR 0048) — there is no bundled rule to match it
    /// and construct a real `Found` evidence item from.
    #[test]
    fn a_driver_service_path_under_a_user_profile_is_redacted_by_the_core_view_function() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\vendor':\n    Type: 1\n    ImagePath: '\\??\\C:\\Users\\bob\\AppData\\vendor.sys'\n",
            "inline",
        )
        .unwrap();
        let run = DriverService::default().collect(&host);
        let (observations, _) = measured(&run);
        let vendor = service(observations, "vendor");
        let path = text(vendor, "path").unwrap();
        assert_eq!(path, r"C:\Users\bob\AppData\vendor.sys");

        let redacted = rongroi_core::view::redact_user_paths(path);
        assert_eq!(redacted, r"%USERPROFILE%\AppData\vendor.sys");
        assert!(!redacted.contains("bob"), "{redacted}");

        // R1: `redact_user_paths` folds ASCII case, and `resolve` must not have introduced a
        // separator or segment shape it does not reach — an upper-case `USERS`, and a lower-case
        // drive letter arriving through `\??\`.
        let root = r"C:\Windows";
        for (image_path, expected_redacted) in [
            (
                ImagePath::Text(r"C:\USERS\bob\x.sys".to_owned()),
                r"%USERPROFILE%\x.sys",
            ),
            (
                ImagePath::Text(r"\??\c:\users\bob\x.sys".to_owned()),
                r"%USERPROFILE%\x.sys",
            ),
        ] {
            let resolved = resolve(&image_path, "svc", root).unwrap();
            let redacted = rongroi_core::view::redact_user_paths(&resolved);
            assert_eq!(redacted, expected_redacted, "{image_path:?}");
            assert!(!redacted.contains("bob"), "{redacted}");
        }
    }

    #[test]
    fn every_driver_service_is_listed_with_its_start_path_and_hash() {
        let run = DriverService::default().collect(&fixture("driver-service-forms"));
        let (observations, _) = measured(&run);
        let names: Vec<&str> = observations
            .iter()
            .map(|observation| text(observation, "service").unwrap())
            .collect();
        // `AudioSrv` is a service, not a driver (`Type` 32), so it is not listed.
        assert!(!names.contains(&"AudioSrv"), "{names:?}");
        assert_eq!(names.len(), 10, "{names:?}");

        for (name, path, hash, start) in [
            (
                "absentpath",
                r"C:\Windows\System32\drivers\absentpath.sys",
                "1111111111111111111111111111111111111111111111111111111111111111",
                0,
            ),
            (
                "systemroot",
                r"C:\Windows\System32\drivers\systemroot.sys",
                "2222222222222222222222222222222222222222222222222222222222222222",
                1,
            ),
            (
                "relative",
                r"C:\Windows\System32\drivers\relative.sys",
                "3333333333333333333333333333333333333333333333333333333333333333",
                3,
            ),
            (
                "wow",
                r"C:\Windows\SysWOW64\drivers\wow.sys",
                "5555555555555555555555555555555555555555555555555555555555555555",
                3,
            ),
            (
                "devicepath",
                r"C:\Program Files\Vendor\devicepath.sys",
                "6666666666666666666666666666666666666666666666666666666666666666",
                3,
            ),
            (
                "driveletter",
                r"C:\Program Files\Vendor\driveletter.sys",
                "7777777777777777777777777777777777777777777777777777777777777777",
                4,
            ),
        ] {
            let observation = service(observations, name);
            assert_eq!(text(observation, "path"), Some(path), "{name}");
            // F5: the full 64-character hash, not a prefix — a truncated comparison would not catch a
            // resolver that hashed the wrong file but happened to share a leading digit.
            assert_eq!(text(observation, "sha256"), Some(hash), "{name}");
            assert_eq!(observation.fields["start"], start, "{name}");
            assert_eq!(observation.collector, "driver_service");
        }
    }

    #[test]
    fn a_missing_file_is_listed_without_a_hash_and_is_not_a_gap_by_itself() {
        // F2: the folder exists and lists another file, so a missing `gone.sys` is read through
        // `is_missing`'s `Ok(Some(entries))` branch, not the `Ok(None)` branch a folder with no
        // fixture `filesystem:` entry takes — the branch a real PC's non-empty `System32\drivers`
        // takes.
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\gone':\n    Type: 1\n    ImagePath: 'System32\\drivers\\gone.sys'\nfilesystem:\n  'C:\\Windows\\System32\\drivers':\n    - name: other.sys\n      sha256: 9999999999999999999999999999999999999999999999999999999999999999\n",
            "inline",
        )
        .unwrap();
        let run = DriverService::default().collect(&host);
        let (observations, gaps) = measured(&run);
        let gone = service(observations, "gone");
        assert_eq!(
            text(gone, "path"),
            Some(r"C:\Windows\System32\drivers\gone.sys")
        );
        assert_eq!(gone.fields.get("sha256"), None);
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    /// F2: `is_missing` folds ASCII case, because the registry's `ImagePath` and the file system's
    /// own spelling of a name need not match byte-for-byte. A file the folder lists under a different
    /// case is present, not missing, so the hash failure it already has (no recorded `sha256`) stays
    /// a gap.
    #[test]
    fn a_file_present_under_a_different_ascii_case_keeps_its_hash_failure_as_a_gap() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\caselock':\n    Type: 1\n    ImagePath: 'System32\\drivers\\CaseLock.sys'\nfilesystem:\n  'C:\\Windows\\System32\\drivers':\n    - name: caselock.sys\n",
            "inline",
        )
        .unwrap();
        let run = DriverService::default().collect(&host);
        let (observations, gaps) = measured(&run);
        let caselock = service(observations, "caselock");
        assert_eq!(
            text(caselock, "path"),
            Some(r"C:\Windows\System32\drivers\CaseLock.sys")
        );
        assert_eq!(caselock.fields.get("sha256"), None);
        assert_eq!(
            gaps.get("sha256"),
            Some(&UnmeasuredReason::ReadFailed),
            "{gaps:?}"
        );
    }

    /// F2: a folder listing that is itself refused must not be read as "the file is not there" —
    /// `is_missing`'s `Err(_)` branch keeps the original failure instead of turning it into
    /// `Hash::Missing`. Denying the folder makes both the hash read and the folder listing fail here
    /// (`crates/rongroi-host/src/fixture.rs` `described_file` checks the same `access_denied` list
    /// `list_dir` does), which still exercises the branch: without it, the mutation `Err(_) => true`
    /// would turn this refusal into "not a gap".
    #[test]
    fn a_refused_folder_listing_keeps_the_hash_failure_as_a_gap_instead_of_calling_it_missing() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\naccess_denied: ['C:\\Windows\\System32\\drivers']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\blocked':\n    Type: 1\n    ImagePath: 'System32\\drivers\\blocked.sys'\n",
            "inline",
        )
        .unwrap();
        let run = DriverService::default().collect(&host);
        let (observations, gaps) = measured(&run);
        let blocked = service(observations, "blocked");
        assert_eq!(blocked.fields.get("sha256"), None);
        assert_eq!(
            gaps.get("sha256"),
            Some(&UnmeasuredReason::AccessDenied),
            "{gaps:?}"
        );
    }

    /// F4: a refusal on the file itself never means "not there". Denying only the file (not its
    /// folder) so the folder listing would, if consulted, say the file is absent — without the F4
    /// fix `hash` would call `is_missing`, get `true`, and silently turn the refusal into
    /// `Hash::Missing` with no gap.
    #[test]
    fn a_refused_file_is_access_denied_even_when_the_folder_listing_would_call_it_missing() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\naccess_denied: ['C:\\Windows\\System32\\drivers\\refused-alone.sys']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\refusedalone':\n    Type: 1\n    ImagePath: 'System32\\drivers\\refused-alone.sys'\n",
            "inline",
        )
        .unwrap();
        let run = DriverService::default().collect(&host);
        let (observations, gaps) = measured(&run);
        let refused = service(observations, "refusedalone");
        assert_eq!(
            text(refused, "path"),
            Some(r"C:\Windows\System32\drivers\refused-alone.sys")
        );
        assert_eq!(refused.fields.get("sha256"), None);
        assert_eq!(
            gaps.get("sha256"),
            Some(&UnmeasuredReason::AccessDenied),
            "{gaps:?}"
        );
    }

    #[test]
    fn a_refused_file_outranks_an_unreadable_one_and_an_unknown_form() {
        let run = DriverService::default().collect(&fixture("driver-service-forms"));
        let (observations, gaps) = measured(&run);
        assert_eq!(gaps.get("sha256"), Some(&UnmeasuredReason::AccessDenied));
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        let refused = service(observations, "refused");
        assert_eq!(refused.fields.get("sha256"), None);
        let unreadable = service(observations, "unreadable");
        assert_eq!(unreadable.fields.get("sha256"), None);
        assert_eq!(unreadable.fields.get("start"), None);
        let quoted = service(observations, "quoted");
        assert_eq!(quoted.fields.get("path"), None);
        assert_eq!(quoted.fields.get("sha256"), None);
        assert_eq!(quoted.fields["start"], 3);
        let gone = service(observations, "gone");
        assert_eq!(gone.fields.get("sha256"), None);
    }

    #[test]
    fn an_unreadable_file_or_an_unknown_form_alone_is_read_failed() {
        for image_path in [
            r"'System32\drivers\unreadable.sys'",
            r#"'"C:\Vendor\quoted.sys"'"#,
        ] {
            let yaml = format!(
                "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\one':\n    Type: 1\n    ImagePath: {image_path}\nfilesystem:\n  'C:\\Windows\\System32\\drivers':\n    - name: unreadable.sys\n"
            );
            let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
            let run = DriverService::default().collect(&host);
            let (_, gaps) = measured(&run);
            assert_eq!(
                gaps.get("sha256"),
                Some(&UnmeasuredReason::ReadFailed),
                "{image_path}"
            );
        }
    }

    #[test]
    fn a_spent_budget_leaves_every_service_listed_unhashed_and_outranks_everything() {
        let run = DriverService {
            budget: Duration::ZERO,
        }
        .collect(&fixture("driver-service-forms"));
        let (observations, gaps) = measured(&run);
        assert_eq!(observations.len(), 10);
        assert!(
            observations
                .iter()
                .all(|o| !o.fields.contains_key("sha256"))
        );
        assert_eq!(
            text(service(observations, "relative"), "path"),
            Some(r"C:\Windows\System32\drivers\relative.sys")
        );
        assert_eq!(gaps.get("sha256"), Some(&UnmeasuredReason::BudgetSpent));
    }

    #[test]
    fn a_refused_services_key_is_access_denied_even_without_elevation() {
        assert_eq!(
            DriverService::default().collect(&fixture("driver-service-refused")),
            CollectorRun::Unmeasured {
                collector: "driver_service".to_owned(),
                reason: UnmeasuredReason::AccessDenied,
            }
        );
    }

    #[test]
    fn a_refused_service_key_is_an_access_denied_gap_and_the_rest_are_listed() {
        let host = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\naccess_denied: ['HKLM\\SYSTEM\\CurrentControlSet\\Services\\locked']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\locked':\n    Type: 1\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\open':\n    Type: 1\nfilesystem:\n  'C:\\Windows\\System32\\drivers':\n    - name: open.sys\n      sha256: 8888888888888888888888888888888888888888888888888888888888888888\n",
            "inline",
        )
        .unwrap();
        let run = DriverService::default().collect(&host);
        let (observations, gaps) = measured(&run);
        assert_eq!(observations.len(), 1);
        assert_eq!(text(&observations[0], "service"), Some("open"));
        assert_eq!(gaps.get("sha256"), Some(&UnmeasuredReason::AccessDenied));
    }

    #[test]
    fn no_system_root_no_services_key_and_another_os_are_unmeasured() {
        let unmeasured = |reason| CollectorRun::Unmeasured {
            collector: "driver_service".to_owned(),
            reason,
        };
        let no_root = FixtureHost::from_yaml_str(
            "platform: windows\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbd':\n    Type: 1\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            DriverService::default().collect(&no_root),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        let no_key = FixtureHost::from_yaml_str(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\n",
            "inline",
        )
        .unwrap();
        assert_eq!(
            DriverService::default().collect(&no_key),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        assert_eq!(
            DriverService::default().collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
    }

    /// The baseline reproduces the runner's reading (windows.yml run 34955915842): every driver service, and
    /// every hash, with no gap.
    #[test]
    fn baseline_elevated_win11_reproduces_the_runners_driver_service_reading() {
        let run = DriverService::default().collect(&fixture("baseline-elevated-win11"));
        let (observations, gaps) = measured(&run);
        assert_eq!(observations.len(), 424);
        assert_eq!(
            observations
                .iter()
                .filter(|observation| observation.fields.contains_key("sha256"))
                .count(),
            424
        );
        assert!(gaps.is_empty(), "{gaps:?}");
    }
}
