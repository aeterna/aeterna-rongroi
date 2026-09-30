// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! What Windows starts by itself: program services, `Run` and `RunOnce` values, and scheduled tasks,
//! each with the file that would start (ADR 0060).
//!
//! Three places, told apart by `location`, the discriminator (ADR 0044):
//!
//! - **`service`** — every key directly under `HKLM\SYSTEM\CurrentControlSet\Services` whose `Type`
//!   has bit `0x10` or `0x20` and neither driver bit: its name, `Start`, whether a `TriggerInfo` key
//!   exists, and the file its `ServiceDll` (in `Parameters` or in the key) or else its `ImagePath` names.
//! - **`run`** — the values of `Run` and `RunOnce` under `HKLM`, `HKLM\SOFTWARE\WOW6432Node` and `HKCU`:
//!   the value's name, which hive, whether it is `RunOnce`, and the file its command line names.
//! - **`task`** — the XML files under `%SystemRoot%\System32\Tasks`, parsed by
//!   `rongroi_parsers::task`: the task's path, whether it is enabled, the kinds of its triggers, and one
//!   observation per `Exec` action with the file its `Command` names. A task whose actions are all COM
//!   handlers is not reported. The files are refused without administrator rights, which is
//!   `not_admin` for this place alone; one file refused to an elevated read is an `access_denied` gap
//!   for this place alone (owner decision 9).
//!
//! **Arguments are never reported**, nor whether there were any: a command line is read only to find
//! where the program's path ends (ADR 0060, section 4). A file under `%SystemRoot%` is reported by its
//! path alone; every other file is hashed and its embedded signature checked, under a 30-second budget
//! of its own (section 7, option B).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

use rongroi_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, RegistryData, SignatureCheck, SourceError};
use rongroi_parsers::task;

use crate::{Collector, Field, driver_service, failure, paths, prefetch};

const ID: &str = "autostart";

/// The field that says which place an observation is about.
const DISCRIMINATOR: &str = "location";

/// Value of `location` for a program service.
pub const SERVICE_LOCATION: &str = "service";
/// Value of `location` for a `Run` or `RunOnce` value.
pub const RUN_LOCATION: &str = "run";
/// Value of `location` for a scheduled task's `Exec` action.
pub const TASK_LOCATION: &str = "task";

/// How long this collector hashes and checks files before it stops and says so. Checked before each
/// file. ADR 0060 measured 26.5 s cold for the 29 files outside `%SystemRoot%` on a runner.
pub const BUDGET: Duration = Duration::from_secs(30);

/// `SERVICE_WIN32_OWN_PROCESS` and `SERVICE_WIN32_SHARE_PROCESS`; the per-user variants are built on
/// them.
const PROGRAM_BITS: u32 = 0x10 | 0x20;
/// `SERVICE_KERNEL_DRIVER` and `SERVICE_FILE_SYSTEM_DRIVER`, which `driver_service` reads.
const DRIVER_BITS: u32 = 0x1 | 0x2;

/// The three roots of `Run` and `RunOnce`, with the value of `hive` for each.
pub const RUN_ROOTS: [(&str, &str); 3] = [
    ("machine", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"),
    (
        "machine_32",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion",
    ),
    ("user", r"HKCU\Software\Microsoft\Windows\CurrentVersion"),
];

/// The task files' folder, relative to `%SystemRoot%`.
pub const TASKS_RELATIVE_PATH: &str = r"System32\Tasks";

/// Folders below the task folder deeper than this are not walked; the Task Scheduler's own tree is
/// three or four deep.
const MAX_TASK_DEPTH: usize = 32;

/// The machine variables a command line may use (ADR 0060, section 3).
pub const MACHINE_VARIABLES: [&str; 8] = [
    "SystemRoot",
    "windir",
    "SystemDrive",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "ProgramData",
    "CommonProgramFiles",
];

/// The profile variables an `HKCU` value, or a task that runs as this account, may also use: this
/// account's own, from this program's environment (ADR 0060, section 3).
pub const PROFILE_VARIABLES: [&str; 5] = ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"];

/// The fields that describe the file an entry names.
const FILE_GAP_FIELDS: [&str; 2] = ["sha256", "signature"];

static FIELDS: [Field; 17] = [
    Field::boolean("enabled"),
    Field::text("entry"),
    Field::text("hive"),
    Field::text("location"),
    Field::text("path"),
    Field::text("path_kind"),
    Field::boolean("run_once"),
    Field::text("service"),
    Field::boolean("service_dll"),
    Field::text("sha256"),
    Field::text("signature"),
    Field::text("signer"),
    Field::text("signer_cert_sha256"),
    Field::number("start"),
    Field::boolean("starts_by_itself"),
    Field::boolean("trigger_start"),
    Field::text("triggers"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::BudgetSpent,
    UnmeasuredReason::ReadFailed,
];

/// Reads what Windows starts by itself.
#[derive(Debug, Clone, Copy)]
pub struct Autostart {
    /// How long hashing and signature checks may take before the remaining files are left with
    /// `budget_spent`.
    pub budget: Duration,
}

impl Default for Autostart {
    fn default() -> Self {
        Self { budget: BUDGET }
    }
}

impl Collector for Autostart {
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
        let unmeasured = |reason| CollectorRun::Unmeasured {
            collector: ID.to_owned(),
            reason,
        };
        if host.platform() != Platform::Windows {
            return unmeasured(UnmeasuredReason::NotWindows);
        }
        // Relative forms, the task folder and the `windows` kind of path all start at `%SystemRoot%`.
        let Some(system_root) = host
            .env_var(prefetch::SYSTEM_ROOT)
            .filter(|root| paths::is_drive_rooted(root))
            .map(|root| root.trim_end_matches(['\\', '/']).to_owned())
        else {
            return unmeasured(UnmeasuredReason::ReadFailed);
        };
        let context = Context::new(host, system_root);
        let places = [services(&context), run_values(&context), tasks(&context)];
        self.finish(&context, places)
    }
}

impl Autostart {
    /// Hashes and checks the files the places named, then writes the observations and the gaps.
    fn finish(&self, context: &Context<'_>, places: [Place; 3]) -> CollectorRun {
        let files = self.describe_files(context, &places);
        let mut observations = Vec::new();
        let mut unread = Vec::new();
        let mut place_gaps: Vec<(&'static str, BTreeMap<String, UnmeasuredReason>)> = Vec::new();
        for place in places {
            let mut gaps = place.gaps;
            if let Some(reason) = place.unread {
                unread.push((place.location, reason));
                for field in &FIELDS {
                    note(&mut gaps, field.name, reason);
                }
            }
            for entry in place.entries {
                let mut fields = entry.fields;
                fields.insert(
                    DISCRIMINATOR.to_owned(),
                    serde_json::Value::from(place.location),
                );
                fields.insert(
                    "starts_by_itself".to_owned(),
                    serde_json::Value::from(entry.starts_by_itself),
                );
                match entry.file {
                    Resolution::Path(path) => {
                        fields.insert(
                            "path_kind".to_owned(),
                            serde_json::Value::from(context.path_kind(&path)),
                        );
                        match files.get(&path.to_ascii_lowercase()) {
                            Some(FileState::Described { sha256, signature }) => {
                                fields.insert(
                                    "sha256".to_owned(),
                                    serde_json::Value::from(sha256.clone()),
                                );
                                match signature {
                                    Ok(check) => insert_signature(&mut fields, check.clone()),
                                    Err(reason) => note(&mut gaps, "signature", *reason),
                                }
                            }
                            Some(FileState::Failed(reason)) => {
                                for field in FILE_GAP_FIELDS {
                                    note(&mut gaps, field, *reason);
                                }
                            }
                            // Under `%SystemRoot%` (not read by design), or not there.
                            Some(FileState::Missing) | None => {}
                        }
                        fields.insert("path".to_owned(), serde_json::Value::from(path));
                    }
                    Resolution::Missing => {}
                    Resolution::Unknown(reason) => {
                        for field in FILE_GAP_FIELDS {
                            note(&mut gaps, field, reason);
                        }
                    }
                }
                observations.push(Observation {
                    collector: ID.to_owned(),
                    fields,
                });
            }
            if !gaps.is_empty() {
                place_gaps.push((place.location, gaps));
            }
        }

        // No place read at all: a gap for the whole run, as `net_config` makes one (ADR 0044).
        if unread.len() == 3 {
            let worst = unread
                .iter()
                .map(|(_, reason)| *reason)
                .min_by_key(|reason| rank(*reason))
                .unwrap_or(UnmeasuredReason::ReadFailed);
            return CollectorRun::Measured {
                collector: ID.to_owned(),
                observations,
                gaps: FIELDS
                    .iter()
                    .map(|field| (field.name.to_owned(), worst))
                    .collect(),
                discriminator_gaps: Vec::new(),
            };
        }
        // The engine reports the first place whose gaps reach a rule, so the reason that outranks the
        // others comes first: the budget, then a refusal, then a failure (as `driver_service` ranks).
        place_gaps.sort_by_key(|(_, gaps)| gaps.values().map(|reason| rank(*reason)).min());
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps: place_gaps
                .into_iter()
                .map(|(location, gaps)| DiscriminatorGaps {
                    discriminator: DISCRIMINATOR.to_owned(),
                    value: serde_json::Value::from(location),
                    gaps,
                })
                .collect(),
        }
    }

    /// Hashes and checks every file outside `%SystemRoot%` once, however many entries name it, the
    /// files of entries that start by themselves first, until the budget is spent.
    fn describe_files(
        &self,
        context: &Context<'_>,
        places: &[Place; 3],
    ) -> HashMap<String, FileState> {
        let mut first = Vec::new();
        let mut then = Vec::new();
        let mut seen = BTreeSet::new();
        for pass in [true, false] {
            for entry in places.iter().flat_map(|place| &place.entries) {
                let Resolution::Path(path) = &entry.file else {
                    continue;
                };
                if entry.starts_by_itself != pass
                    || context.path_kind(path) == "windows"
                    || !seen.insert(path.to_ascii_lowercase())
                {
                    continue;
                }
                if pass {
                    first.push(path.clone());
                } else {
                    then.push(path.clone());
                }
            }
        }
        let started = Instant::now();
        let mut files = HashMap::new();
        for path in first.into_iter().chain(then) {
            let state = if started.elapsed() >= self.budget {
                FileState::Failed(UnmeasuredReason::BudgetSpent)
            } else {
                describe_file(context.host, &path)
            };
            files.insert(path.to_ascii_lowercase(), state);
        }
        files
    }
}

/// What hashing and checking one file came to.
enum FileState {
    Described {
        sha256: String,
        signature: Result<SignatureCheck, UnmeasuredReason>,
    },
    /// The file is not there: a registration left behind, not a gap (ADR 0048).
    Missing,
    Failed(UnmeasuredReason),
}

fn describe_file(host: &dyn Host, path: &str) -> FileState {
    let sha256 = match host.file_sha256(path) {
        Ok(digest) => match lowercase_digest(&digest) {
            Some(digest) => digest,
            None => return FileState::Failed(UnmeasuredReason::ReadFailed),
        },
        // A refusal is never read as "the file is not there" (ADR 0048, F4).
        Err(SourceError::AccessDenied) => {
            return FileState::Failed(UnmeasuredReason::AccessDenied);
        }
        Err(_) if is_missing(host, path) => return FileState::Missing,
        Err(error) => return FileState::Failed(reason(&error)),
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
    let index = path.rfind('\\')?;
    let (dir, name) = (&path[..index], &path[index + 1..]);
    if dir.len() == 2 && dir.as_bytes()[1] == b':' {
        Some((&path[..=index], name))
    } else {
        Some((dir, name))
    }
}

/// What Windows said about one file's embedded signature, as `fivem_dir` writes it (ADR 0035).
fn insert_signature(fields: &mut BTreeMap<String, serde_json::Value>, signature: SignatureCheck) {
    let state = match signature {
        SignatureCheck::Valid {
            signer,
            signer_cert_sha256,
        } => {
            let Some(cert) = lowercase_digest(&signer_cert_sha256) else {
                return;
            };
            fields.insert("signer".to_owned(), serde_json::Value::from(signer));
            fields.insert(
                "signer_cert_sha256".to_owned(),
                serde_json::Value::from(cert),
            );
            "valid"
        }
        SignatureCheck::NoEmbeddedSignature => "no_embedded_signature",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::UnverifiableOffline => "unverifiable_offline",
    };
    fields.insert("signature".to_owned(), serde_json::Value::from(state));
}

fn lowercase_digest(digest: &str) -> Option<String> {
    let digest = digest.to_ascii_lowercase();
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(digest)
}

/// A refusal of something no administrator right is needed for is `access_denied` (ADR 0060: the
/// services and `Run` keys, and the files they name, were read with a limited token).
fn reason(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

/// The budget first, because it says the rest was never tried, then a refusal a person can act on,
/// then a failure nobody can — `driver_service`'s order.
fn rank(reason: UnmeasuredReason) -> u8 {
    match reason {
        UnmeasuredReason::BudgetSpent => 0,
        UnmeasuredReason::AccessDenied | UnmeasuredReason::NotAdmin => 1,
        _ => 2,
    }
}

/// Keeps, for one field, the reason that outranks the other.
fn note(gaps: &mut BTreeMap<String, UnmeasuredReason>, field: &str, reason: UnmeasuredReason) {
    let current = gaps.get(field).copied();
    if current.is_none_or(|current| rank(reason) < rank(current)) {
        gaps.insert(field.to_owned(), reason);
    }
}

// ---------------------------------------------------------------------------------------------------
// What every place shares
// ---------------------------------------------------------------------------------------------------

/// What one place read: its entries, the gaps confined to it, and whether it could not be read at all.
struct Place {
    location: &'static str,
    entries: Vec<Entry>,
    gaps: BTreeMap<String, UnmeasuredReason>,
    unread: Option<UnmeasuredReason>,
}

impl Place {
    fn new(location: &'static str) -> Self {
        Self {
            location,
            entries: Vec::new(),
            gaps: BTreeMap::new(),
            unread: None,
        }
    }

    fn unread(location: &'static str, reason: UnmeasuredReason) -> Self {
        Self {
            unread: Some(reason),
            ..Self::new(location)
        }
    }

    /// A part of this place that could not be read: every field is a gap for it.
    fn note_unread_part(&mut self, reason: UnmeasuredReason) {
        for field in &FIELDS {
            note(&mut self.gaps, field.name, reason);
        }
    }
}

/// One service, `Run` value or `Exec` action.
struct Entry {
    fields: BTreeMap<String, serde_json::Value>,
    starts_by_itself: bool,
    file: Resolution,
}

/// The file a command line names (ADR 0060, section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The file, drive-letter form.
    Path(String),
    /// An unquoted command line with a space where no prefix names an existing file: the program is
    /// not there, which is not a gap (ADR 0048).
    Missing,
    /// A form this program does not read, or a read that failed on the way: a gap on `sha256` and
    /// `signature`.
    Unknown(UnmeasuredReason),
}

/// A folder's file names, lower-cased, as one listing gave them: `None` when the folder is not there.
type Listing = Result<Option<BTreeSet<String>>, UnmeasuredReason>;

/// What every place reads with: the host, `%SystemRoot%`, the variables, and the folder listings the
/// command-line resolver has already made.
struct Context<'h> {
    host: &'h dyn Host,
    system_root: String,
    profiles_directory: Option<String>,
    listings: RefCell<HashMap<String, Listing>>,
}

impl<'h> Context<'h> {
    fn new(host: &'h dyn Host, system_root: String) -> Self {
        Self {
            host,
            system_root,
            profiles_directory: crate::scan::profiles_directory(host),
            listings: RefCell::new(HashMap::new()),
        }
    }

    /// The value of `name` when a command line in this scope may use it.
    fn variable(&self, name: &str, profile: bool) -> Option<String> {
        let allowed = MACHINE_VARIABLES
            .iter()
            .chain(if profile { &PROFILE_VARIABLES[..] } else { &[] })
            .any(|allowed| allowed.eq_ignore_ascii_case(name));
        if !allowed {
            return None;
        }
        if name.eq_ignore_ascii_case("SystemRoot") {
            return Some(self.system_root.clone());
        }
        self.host.env_var(name)
    }

    /// Whether a file of that name is in its folder, by the folder's listing, read once.
    fn file_exists(&self, path: &str) -> Result<bool, UnmeasuredReason> {
        let Some((dir, name)) = parent_and_name(path) else {
            return Ok(false);
        };
        let key = dir.to_ascii_lowercase();
        let mut listings = self.listings.borrow_mut();
        let listing = listings
            .entry(key)
            .or_insert_with(|| match self.host.list_dir(dir) {
                Ok(None) => Ok(None),
                Ok(Some(entries)) => Ok(Some(
                    entries
                        .into_iter()
                        .filter(|entry| entry.is_file)
                        .map(|entry| entry.name.to_ascii_lowercase())
                        .collect(),
                )),
                Err(error) => Err(reason(&error)),
            });
        match listing {
            Ok(None) => Ok(false),
            Ok(Some(names)) => Ok(names.contains(&name.to_ascii_lowercase())),
            Err(reason) => Err(*reason),
        }
    }

    /// The kind of folder a file is in (ADR 0060, section 5).
    fn path_kind(&self, path: &str) -> &'static str {
        let temp = format!(r"{}\Temp", self.system_root);
        if is_under(path, &self.system_root) && !is_under(path, &temp) {
            return "windows";
        }
        let env_root = |name: &str| {
            self.host
                .env_var(name)
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
        if rongroi_core::view::redact_profile_paths(path, self.profiles_directory.as_deref())
            != path
        {
            return "user_profile";
        }
        "other"
    }

    /// The file a service's `ImagePath` or a `Run` value's command line names.
    fn resolve_command_line(&self, text: &str, profile: bool) -> Resolution {
        let text = text.trim_matches([' ', '\t']);
        if let Some(rest) = text.strip_prefix('"') {
            let Some((quoted, _)) = rest.split_once('"') else {
                return Resolution::Unknown(UnmeasuredReason::ReadFailed);
            };
            return self.resolve_program(quoted, profile);
        }
        let Some(expanded) = self.expand(text, profile) else {
            return Resolution::Unknown(UnmeasuredReason::ReadFailed);
        };
        let Some(rooted) = self.rooted(&expanded) else {
            return Resolution::Unknown(UnmeasuredReason::ReadFailed);
        };
        if !rooted.contains(' ') {
            return checked(&rooted);
        }
        // `CreateProcessW`'s documented order for an unquoted command line: each prefix ending at a
        // space, shortest first, with `.exe` added when it has no extension, then the whole line.
        let mut failure = None;
        let ends = rooted
            .char_indices()
            .filter(|(_, character)| *character == ' ')
            .map(|(index, _)| index)
            .chain([rooted.len()]);
        for end in ends {
            let prefix = &rooted[..end];
            if prefix.ends_with(' ') {
                continue;
            }
            let candidate = with_exe(&prefix.replace('/', "\\"));
            if paths::is_refused_form(&candidate) {
                continue;
            }
            match self.file_exists(&candidate) {
                Ok(true) => return Resolution::Path(candidate),
                Ok(false) => {}
                Err(reason) => failure = Some(reason),
            }
        }
        failure.map_or(Resolution::Missing, Resolution::Unknown)
    }

    /// The file a text that is a program alone names: a quoted path's inside, a `ServiceDll`, or a
    /// task's `Command`.
    fn resolve_program(&self, text: &str, profile: bool) -> Resolution {
        let Some(expanded) = self.expand(text.trim_matches([' ', '\t']), profile) else {
            return Resolution::Unknown(UnmeasuredReason::ReadFailed);
        };
        match self.rooted(&expanded) {
            Some(rooted) => checked(&rooted),
            None => Resolution::Unknown(UnmeasuredReason::ReadFailed),
        }
    }

    /// `text` with every `%…%` replaced, or `None` when a variable is not one this scope may use or a
    /// `%` has no partner.
    fn expand(&self, text: &str, profile: bool) -> Option<String> {
        let mut expanded = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find('%') {
            expanded.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let end = after.find('%')?;
            let value = self.variable(&after[..end], profile)?;
            expanded.push_str(value.trim_end_matches(['\\', '/']));
            rest = &after[end + 1..];
        }
        expanded.push_str(rest);
        Some(expanded)
    }

    /// A path in drive-letter form, from the forms ADR 0048 reads: `\SystemRoot\…`, `\??\X:\…`,
    /// `X:\…`, and a relative path under `%SystemRoot%`. Anything else is `None`.
    fn rooted(&self, text: &str) -> Option<String> {
        const SYSTEM_ROOT_PREFIX: &str = r"\SystemRoot\";
        if let Some(prefix) = text.get(..SYSTEM_ROOT_PREFIX.len())
            && prefix.eq_ignore_ascii_case(SYSTEM_ROOT_PREFIX)
        {
            return Some(format!(
                r"{}\{}",
                self.system_root,
                &text[SYSTEM_ROOT_PREFIX.len()..]
            ));
        }
        if let Some(rest) = text.strip_prefix(r"\??\") {
            return paths::is_drive_rooted(rest).then(|| rest.to_owned());
        }
        if paths::is_drive_rooted(text) {
            return Some(text.to_owned());
        }
        if text.is_empty()
            || text.starts_with(['\\', '/'])
            || text.as_bytes().get(1) == Some(&b':')
            || text.contains(['%', '"'])
        {
            return None;
        }
        Some(format!(r"{}\{text}", self.system_root))
    }
}

/// A resolved path, its separators read as `\`, unless it is a form this program refuses.
fn checked(path: &str) -> Resolution {
    let path = path.replace('/', "\\");
    if path.contains('"') || paths::is_refused_form(&path) {
        Resolution::Unknown(UnmeasuredReason::ReadFailed)
    } else {
        Resolution::Path(path)
    }
}

/// `path` with `.exe` added when its last segment has no extension.
fn with_exe(path: &str) -> String {
    let name = path.rsplit('\\').next().unwrap_or(path);
    if name.contains('.') {
        path.to_owned()
    } else {
        format!("{path}.exe")
    }
}

/// Whether `path` is inside the folder `root`, compared without ASCII case.
fn is_under(path: &str, root: &str) -> bool {
    path.len() > root.len()
        && path.is_char_boundary(root.len())
        && path[..root.len()].eq_ignore_ascii_case(root)
        && path[root.len()..].starts_with('\\')
}

// ---------------------------------------------------------------------------------------------------
// service
// ---------------------------------------------------------------------------------------------------

fn services(context: &Context<'_>) -> Place {
    let host = context.host;
    let names = match host.subkeys(driver_service::SERVICES_KEY) {
        Ok(Some(names)) => names,
        // Every Windows has this key; one that is not there was not read.
        Ok(None) => return Place::unread(SERVICE_LOCATION, UnmeasuredReason::ReadFailed),
        Err(error) => return Place::unread(SERVICE_LOCATION, reason(&error)),
    };
    let mut place = Place::new(SERVICE_LOCATION);
    for name in names {
        let key = format!(r"{}\{name}", driver_service::SERVICES_KEY);
        match service(context, &key, &name) {
            Ok(Some(entry)) => place.entries.push(entry),
            Ok(None) => {}
            Err(reason) => place.note_unread_part(reason),
        }
    }
    place
}

/// The program service at `key`, or `None` when the key is not one.
fn service(
    context: &Context<'_>,
    key: &str,
    name: &str,
) -> Result<Option<Entry>, UnmeasuredReason> {
    let host = context.host;
    let read = |value: &str| host.read_value(key, value).map_err(|error| reason(&error));
    let Some(RegistryData::Dword(kind)) = read("Type")? else {
        return Ok(None);
    };
    if kind & PROGRAM_BITS == 0 || kind & DRIVER_BITS != 0 {
        return Ok(None);
    }
    let start = match read("Start")? {
        Some(RegistryData::Dword(start)) => Some(start),
        _ => None,
    };
    let subkeys = host
        .subkeys(key)
        .map_err(|error| reason(&error))?
        .unwrap_or_default();
    let has = |wanted: &str| subkeys.iter().any(|name| name.eq_ignore_ascii_case(wanted));
    let trigger_start = has("TriggerInfo");

    let mut fields = BTreeMap::new();
    fields.insert("service".to_owned(), serde_json::Value::from(name));
    if let Some(start) = start {
        fields.insert("start".to_owned(), serde_json::Value::from(start));
    }
    fields.insert(
        "trigger_start".to_owned(),
        serde_json::Value::from(trigger_start),
    );

    let dll = if has("Parameters") {
        match host.read_value(&format!(r"{key}\Parameters"), "ServiceDll") {
            Ok(None) => read("ServiceDll")?,
            Ok(found) => found,
            // Measured refused to a limited token for 3 of 230 services on a PC (ADR 0060).
            Err(error) => {
                return Ok(Some(Entry {
                    fields,
                    starts_by_itself: starts(start, trigger_start),
                    file: Resolution::Unknown(failure::reason_for(host, &error)),
                }));
            }
        }
    } else {
        read("ServiceDll")?
    };
    let file = match dll {
        Some(RegistryData::Text(dll)) => {
            fields.insert("service_dll".to_owned(), serde_json::Value::from(true));
            context.resolve_program(&dll, false)
        }
        Some(_) => Resolution::Unknown(UnmeasuredReason::ReadFailed),
        None => {
            fields.insert("service_dll".to_owned(), serde_json::Value::from(false));
            match read("ImagePath")? {
                Some(RegistryData::Text(image_path)) => {
                    context.resolve_command_line(&image_path, false)
                }
                _ => Resolution::Unknown(UnmeasuredReason::ReadFailed),
            }
        }
    };
    Ok(Some(Entry {
        fields,
        starts_by_itself: starts(start, trigger_start),
        file,
    }))
}

/// Section 6: boot, system and automatic start by themselves, and on demand does when a trigger is
/// registered; disabled never does.
fn starts(start: Option<u32>, trigger_start: bool) -> bool {
    matches!(start, Some(0..=2)) || (start == Some(3) && trigger_start)
}

// ---------------------------------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------------------------------

fn run_values(context: &Context<'_>) -> Place {
    let host = context.host;
    let mut place = Place::new(RUN_LOCATION);
    let mut unread = 0;
    for (hive, root) in RUN_ROOTS {
        for (subkey, run_once) in [("Run", false), ("RunOnce", true)] {
            let key = format!(r"{root}\{subkey}");
            let names = match host.value_names(&key) {
                Ok(Some(names)) => names,
                // No key, no value: a measurement, as every `RunOnce` on the PC measured was.
                Ok(None) => continue,
                Err(error) => {
                    unread += 1;
                    place.note_unread_part(reason(&error));
                    continue;
                }
            };
            for name in names {
                let file = match host.read_value(&key, &name) {
                    Ok(Some(RegistryData::Text(command))) => {
                        context.resolve_command_line(&command, hive == "user")
                    }
                    Ok(Some(_)) => Resolution::Unknown(UnmeasuredReason::ReadFailed),
                    // Removed between listing and reading.
                    Ok(None) => continue,
                    Err(error) => Resolution::Unknown(reason(&error)),
                };
                let mut fields = BTreeMap::new();
                fields.insert("entry".to_owned(), serde_json::Value::from(name));
                fields.insert("hive".to_owned(), serde_json::Value::from(hive));
                fields.insert("run_once".to_owned(), serde_json::Value::from(run_once));
                // Explorer's own switch is in `StartupApproved`, which is not read (section 6).
                place.entries.push(Entry {
                    fields,
                    starts_by_itself: true,
                    file,
                });
            }
        }
    }
    if unread == RUN_ROOTS.len() * 2 {
        let worst = place
            .gaps
            .values()
            .copied()
            .min_by_key(|reason| rank(*reason));
        return Place::unread(RUN_LOCATION, worst.unwrap_or(UnmeasuredReason::ReadFailed));
    }
    place
}

// ---------------------------------------------------------------------------------------------------
// task
// ---------------------------------------------------------------------------------------------------

fn tasks(context: &Context<'_>) -> Place {
    let host = context.host;
    let root = format!(r"{}\{TASKS_RELATIVE_PATH}", context.system_root);
    let top = match host.list_dir(&root) {
        Ok(Some(entries)) => entries,
        // Every Windows has this folder; one that is not there was not read.
        Ok(None) => return Place::unread(TASK_LOCATION, UnmeasuredReason::ReadFailed),
        // Refused to a token without administrator rights (measured, ADR 0060).
        Err(error) => return Place::unread(TASK_LOCATION, failure::reason_for(host, &error)),
    };
    let identity = Identity::of(host);
    let mut place = Place::new(TASK_LOCATION);
    let mut folders = vec![(String::new(), top, 0_usize)];
    let mut files = Vec::new();
    while let Some((relative, mut entries, depth)) = folders.pop() {
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        for entry in entries {
            let child = format!(r"{relative}\{}", entry.name);
            if entry.is_file {
                files.push(child);
                continue;
            }
            if depth + 1 > MAX_TASK_DEPTH {
                place.note_unread_part(UnmeasuredReason::ReadFailed);
                continue;
            }
            match host.list_dir(&format!("{root}{child}")) {
                Ok(Some(inside)) => folders.push((child, inside, depth + 1)),
                Ok(None) => {}
                Err(error) => place.note_unread_part(failure::reason_for(host, &error)),
            }
        }
    }
    files.sort();
    for entry_path in files {
        let parsed = match host.read_file(&format!("{root}{entry_path}")) {
            Ok(Some(bytes)) => task::parse_task(&bytes),
            Ok(None) => continue,
            // One file refused to an elevated read is a gap for this place (owner decision 9).
            Err(error) => {
                place.note_unread_part(failure::reason_for(host, &error));
                continue;
            }
        };
        let Ok(parsed) = parsed else {
            place.note_unread_part(UnmeasuredReason::ReadFailed);
            continue;
        };
        let enabled = parsed.enabled.unwrap_or(true);
        let kinds: BTreeSet<&str> = parsed.triggers.iter().map(|kind| kind.as_str()).collect();
        let triggers = kinds.into_iter().collect::<Vec<_>>().join(",");
        let starts_by_itself = enabled && !parsed.triggers.is_empty();
        let profile = identity.is(parsed.principal_user_id.as_deref());
        for command in parsed.exec_commands {
            let file = match command {
                Some(command) => {
                    // `Command` is a program alone, so it is read whole, quoted or not.
                    let command = command.trim_matches([' ', '\t']);
                    let bare = command
                        .strip_prefix('"')
                        .and_then(|inner| inner.strip_suffix('"'))
                        .unwrap_or(command);
                    context.resolve_program(bare, profile)
                }
                None => Resolution::Unknown(UnmeasuredReason::ReadFailed),
            };
            let mut fields = BTreeMap::new();
            fields.insert(
                "entry".to_owned(),
                serde_json::Value::from(entry_path.clone()),
            );
            fields.insert("enabled".to_owned(), serde_json::Value::from(enabled));
            fields.insert(
                "triggers".to_owned(),
                serde_json::Value::from(triggers.clone()),
            );
            place.entries.push(Entry {
                fields,
                starts_by_itself,
                file,
            });
        }
    }
    place
}

/// Who this program runs as, to compare with a task's principal. Never reported.
struct Identity {
    sid: Option<String>,
    user: Option<String>,
    domain_user: Option<String>,
}

impl Identity {
    fn of(host: &dyn Host) -> Self {
        let user = host.env_var("USERNAME").filter(|user| !user.is_empty());
        let domain_user = user.as_ref().and_then(|user| {
            host.env_var("USERDOMAIN")
                .filter(|domain| !domain.is_empty())
                .map(|domain| format!(r"{domain}\{user}"))
        });
        Self {
            sid: host.account_sid().ok(),
            user,
            domain_user,
        }
    }

    /// Whether a principal's `UserId` — a SID, `DOMAIN\name` or a name — is this account.
    fn is(&self, user_id: Option<&str>) -> bool {
        let Some(user_id) = user_id.map(str::trim) else {
            return false;
        };
        [&self.sid, &self.user, &self.domain_user]
            .into_iter()
            .flatten()
            .any(|mine| mine.eq_ignore_ascii_case(user_id))
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

    fn measured(run: &CollectorRun) -> (&[Observation], &[DiscriminatorGaps]) {
        match run {
            CollectorRun::Measured {
                observations,
                discriminator_gaps,
                gaps,
                ..
            } => {
                assert!(gaps.is_empty(), "{gaps:?}");
                (observations, discriminator_gaps)
            }
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn by<'a>(observations: &'a [Observation], field: &str, value: &str) -> &'a Observation {
        observations
            .iter()
            .find(|observation| {
                observation.fields.get(field).and_then(|v| v.as_str()) == Some(value)
            })
            .unwrap_or_else(|| panic!("no observation with {field} = {value}: {observations:?}"))
    }

    fn text<'a>(observation: &'a Observation, field: &str) -> Option<&'a str> {
        observation
            .fields
            .get(field)
            .and_then(serde_json::Value::as_str)
    }

    fn place_gaps<'a>(
        places: &'a [DiscriminatorGaps],
        location: &str,
    ) -> Option<&'a BTreeMap<String, UnmeasuredReason>> {
        places
            .iter()
            .find(|place| place.value == location)
            .map(|place| &place.gaps)
    }

    fn context(host: &FixtureHost) -> Context<'_> {
        Context::new(host, r"C:\Windows".to_owned())
    }

    const ENV: &str = "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\n  windir: 'C:\\Windows'\n  ProgramFiles: 'C:\\Program Files'\n  ProgramFiles(x86): 'C:\\Program Files (x86)'\n  ProgramData: 'C:\\ProgramData'\n  LOCALAPPDATA: 'C:\\Users\\alex\\AppData\\Local'\n";

    #[test]
    fn every_command_line_form_resolves_as_section_3_says() {
        let host = inline(&format!(
            "{ENV}filesystem:\n  'C:\\Windows\\System32':\n    - name: svchost.exe\n  'C:\\Program Files\\Vendor Tool':\n    - name: tool.exe\n  'C:\\':\n    - name: other.txt\n  'C:\\Program Files':\n    - name: readme.txt\n"
        ));
        let context = context(&host);
        let path = |value: &str| Resolution::Path(value.to_owned());
        let unknown = Resolution::Unknown(UnmeasuredReason::ReadFailed);
        for (line, expected) in [
            (
                r#""C:\Program Files\Vendor Tool\tool.exe" --flag"#,
                path(r"C:\Program Files\Vendor Tool\tool.exe"),
            ),
            (
                r"%SystemRoot%\System32\svchost.exe -k netsvcs -p",
                path(r"C:\Windows\System32\svchost.exe"),
            ),
            (
                r"C:\Program Files\Vendor Tool\tool.exe /silent",
                path(r"C:\Program Files\Vendor Tool\tool.exe"),
            ),
            // `.exe` is added to a prefix with no extension, as `CreateProcessW` adds it.
            (
                r"C:\Program Files\Vendor Tool\tool -x",
                path(r"C:\Program Files\Vendor Tool\tool.exe"),
            ),
            (r"C:\Vendor\agent", path(r"C:\Vendor\agent")),
            (
                r"\SystemRoot\System32\a.exe",
                path(r"C:\Windows\System32\a.exe"),
            ),
            (r"\??\D:\Vendor\b.exe", path(r"D:\Vendor\b.exe")),
            (r"System32\c.exe", path(r"C:\Windows\System32\c.exe")),
            (r"C:/Vendor/d.exe", path(r"C:\Vendor\d.exe")),
            // A prefix that names nothing: the program is not there, which is not a gap.
            (r"C:\Program Files\Gone\gone.exe -x", Resolution::Missing),
            (r"%LOCALAPPDATA%\Vendor\e.exe", unknown.clone()),
            (r"%UNKNOWN%\f.exe", unknown.clone()),
            (r"%SystemRoot\g.exe", unknown.clone()),
            (r#""C:\unterminated.exe"#, unknown.clone()),
            (r"\\server\share\h.exe", unknown.clone()),
            (r"C:\Users\..\Windows\i.exe", unknown.clone()),
            ("", unknown.clone()),
        ] {
            assert_eq!(
                context.resolve_command_line(line, false),
                expected,
                "{line}"
            );
        }
        // An `HKCU` value may use this account's profile variables.
        assert_eq!(
            context.resolve_command_line(r"%LOCALAPPDATA%\Vendor\e.exe", true),
            path(r"C:\Users\alex\AppData\Local\Vendor\e.exe")
        );
    }

    #[test]
    fn a_path_kind_names_the_folder_a_file_is_in() {
        let host = inline(ENV);
        let context = context(&host);
        for (path, kind) in [
            (r"C:\Windows\System32\svchost.exe", "windows"),
            (r"C:\WINDOWS\system32\x.dll", "windows"),
            (r"C:\Windows\Temp\x.exe", "other"),
            (r"C:\Program Files\Vendor\x.exe", "program_files"),
            (r"C:\Program Files (x86)\Vendor\x.exe", "program_files"),
            (r"C:\ProgramData\Vendor\x.exe", "program_data"),
            (r"C:\Users\alex\AppData\Local\x.exe", "user_profile"),
            (r"C:\tools\x.exe", "other"),
            (r"C:\WindowsApps\x.exe", "other"),
        ] {
            assert_eq!(context.path_kind(path), kind, "{path}");
        }
    }

    #[test]
    fn every_place_is_read_with_its_own_fields() {
        let run = Autostart::default().collect(&fixture("autostart-forms"));
        let (observations, places) = measured(&run);

        let svc = by(observations, "service", "VendorSvc");
        assert_eq!(text(svc, "location"), Some("service"));
        assert_eq!(svc.fields["start"], 2);
        assert_eq!(svc.fields["starts_by_itself"], true);
        assert_eq!(svc.fields["service_dll"], false);
        assert_eq!(text(svc, "path"), Some(r"C:\ProgramData\Vendor\svc.exe"));
        assert_eq!(text(svc, "path_kind"), Some("program_data"));
        assert_eq!(text(svc, "signature"), Some("no_embedded_signature"));
        assert_eq!(
            text(svc, "sha256"),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );

        // A shared-process service is described by its `ServiceDll`, under `%SystemRoot%`: path only.
        let dll = by(observations, "service", "SharedSvc");
        assert_eq!(dll.fields["service_dll"], true);
        assert_eq!(dll.fields["trigger_start"], true);
        assert_eq!(dll.fields["starts_by_itself"], true);
        assert_eq!(text(dll, "path"), Some(r"C:\Windows\System32\shared.dll"));
        assert_eq!(text(dll, "path_kind"), Some("windows"));
        assert!(!dll.fields.contains_key("sha256"));
        assert!(!dll.fields.contains_key("signature"));

        let disabled = by(observations, "service", "DisabledSvc");
        assert_eq!(disabled.fields["starts_by_itself"], false);
        // Drivers and services with no `Type` are `driver_service`'s or nobody's.
        assert!(
            observations
                .iter()
                .all(|o| text(o, "service") != Some("kbd"))
        );

        let run = by(observations, "entry", "VendorTray");
        assert_eq!(text(run, "location"), Some("run"));
        assert_eq!(text(run, "hive"), Some("user"));
        assert_eq!(run.fields["run_once"], false);
        assert_eq!(run.fields["starts_by_itself"], true);
        assert_eq!(
            text(run, "path"),
            Some(r"C:\Users\fixtureuser\AppData\Local\Vendor\tray.exe")
        );
        assert_eq!(text(run, "path_kind"), Some("user_profile"));
        assert_eq!(text(run, "signer"), Some("Vendor Ltd"));

        let once = by(observations, "entry", "Setup32");
        assert_eq!(text(once, "hive"), Some("machine_32"));
        assert_eq!(once.fields["run_once"], true);

        let task = by(observations, "entry", r"\Vendor\Updater");
        assert_eq!(text(task, "location"), Some("task"));
        assert_eq!(task.fields["enabled"], true);
        assert_eq!(text(task, "triggers"), Some("calendar,logon"));
        assert_eq!(task.fields["starts_by_itself"], true);
        // The task runs as this account, so its profile variable was expanded.
        assert_eq!(
            text(task, "path"),
            Some(r"C:\Users\fixtureuser\AppData\Local\Contoso\Updater\updater.exe")
        );
        assert_eq!(text(task, "signature"), Some("valid"));

        let off = by(observations, "entry", r"\Disabled");
        assert_eq!(off.fields["enabled"], false);
        assert_eq!(off.fields["starts_by_itself"], false);
        // A task of COM handlers only is not reported.
        assert!(
            observations
                .iter()
                .all(|o| text(o, "entry") != Some(r"\ComOnly"))
        );
        assert!(places.is_empty(), "{places:?}");
    }

    /// ADR 0060, section 4: no argument, and no sign there was one, reaches an observation.
    #[test]
    fn no_argument_reaches_an_observation() {
        let run = Autostart::default().collect(&fixture("autostart-forms"));
        let (observations, _) = measured(&run);
        let all = format!("{observations:?}");
        for argument in ["--background", "/silent", "-k netsvcs", "secret"] {
            assert!(!all.contains(argument), "{argument} in {all}");
        }
    }

    #[test]
    fn a_task_of_another_account_does_not_get_this_accounts_profile() {
        let host = inline(&format!(
            "{ENV}account_sid: S-1-5-21-9-9-9-1001\nfilesystem:\n  'C:\\Windows\\System32\\Tasks':\n    - name: Other\n      content: '<Task><Principals><Principal><UserId>S-1-5-21-9-9-9-1002</UserId></Principal></Principals><Triggers><LogonTrigger/></Triggers><Actions><Exec><Command>%LOCALAPPDATA%\\x.exe</Command><Arguments>secret</Arguments></Exec></Actions></Task>'\n"
        ));
        let run = Autostart::default().collect(&host);
        let (observations, places) = measured(&run);
        let other = by(observations, "entry", r"\Other");
        assert!(!other.fields.contains_key("path"));
        assert_eq!(
            place_gaps(places, "task").and_then(|gaps| gaps.get("signature")),
            Some(&UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn a_refused_task_folder_is_not_admin_without_rights_and_access_denied_with_them() {
        for (elevated, expected) in [
            ("false", UnmeasuredReason::NotAdmin),
            ("true", UnmeasuredReason::AccessDenied),
        ] {
            let host = inline(&format!(
                "{ENV}elevated: {elevated}\naccess_denied: ['C:\\Windows\\System32\\Tasks']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Svc':\n    Type: 16\n    Start: 2\n    ImagePath: 'C:\\Windows\\svc.exe'\n"
            ));
            let run = Autostart::default().collect(&host);
            let (observations, places) = measured(&run);
            // Services are still answered.
            assert_eq!(observations.len(), 1);
            let task = place_gaps(places, "task").unwrap();
            assert_eq!(task.get("signature"), Some(&expected));
            assert_eq!(task.get("path_kind"), Some(&expected));
            assert!(place_gaps(places, "service").is_none());
        }
    }

    /// Owner decision 9: one file refused to an elevated read is `access_denied` for tasks only, and
    /// the other tasks are still read.
    #[test]
    fn one_refused_task_file_is_a_gap_for_tasks_and_the_rest_are_read() {
        let host = inline(&format!(
            "{ENV}elevated: true\naccess_denied: ['C:\\Windows\\System32\\Tasks\\Locked']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbd':\n    Type: 1\nfilesystem:\n  'C:\\Windows\\System32\\Tasks':\n    - name: Locked\n      content: '<Task/>'\n    - name: Open\n      content: '<Task><Triggers><BootTrigger/></Triggers><Actions><Exec><Command>C:\\Windows\\a.exe</Command></Exec></Actions></Task>'\n"
        ));
        let run = Autostart::default().collect(&host);
        let (observations, places) = measured(&run);
        assert_eq!(
            text(by(observations, "entry", r"\Open"), "path"),
            Some(r"C:\Windows\a.exe")
        );
        assert_eq!(
            place_gaps(places, "task").and_then(|gaps| gaps.get("entry")),
            Some(&UnmeasuredReason::AccessDenied)
        );
        assert!(place_gaps(places, "service").is_none());
        assert!(place_gaps(places, "run").is_none());
    }

    #[test]
    fn a_task_file_that_is_not_a_task_is_read_failed_for_tasks() {
        let host = inline(&format!(
            "{ENV}filesystem:\n  'C:\\Windows\\System32\\Tasks':\n    - name: Broken\n      content: '<Task>'\n"
        ));
        let run = Autostart::default().collect(&host);
        let (_, places) = measured(&run);
        assert_eq!(
            place_gaps(places, "task").and_then(|gaps| gaps.get("signature")),
            Some(&UnmeasuredReason::ReadFailed)
        );
    }

    #[test]
    fn a_refused_service_dll_is_not_admin_for_services_only() {
        let host = inline(&format!(
            "{ENV}elevated: false\naccess_denied: ['HKLM\\SYSTEM\\CurrentControlSet\\Services\\Shared\\Parameters']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Shared':\n    Type: 32\n    Start: 3\n    ImagePath: '%SystemRoot%\\System32\\svchost.exe -k x'\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Shared\\Parameters':\n    ServiceDll: 'C:\\Windows\\System32\\x.dll'\nfilesystem:\n  'C:\\Windows\\System32\\Tasks':\n    - name: readme\n      directory: true\n"
        ));
        let run = Autostart::default().collect(&host);
        let (observations, places) = measured(&run);
        let shared = by(observations, "service", "Shared");
        assert!(!shared.fields.contains_key("path"));
        assert!(!shared.fields.contains_key("service_dll"));
        assert_eq!(
            place_gaps(places, "service").and_then(|gaps| gaps.get("signature")),
            Some(&UnmeasuredReason::NotAdmin)
        );
    }

    #[test]
    fn a_spent_budget_leaves_every_file_unhashed_and_outranks_everything() {
        let run = Autostart {
            budget: Duration::ZERO,
        }
        .collect(&fixture("autostart-forms"));
        let (observations, places) = measured(&run);
        assert!(
            observations
                .iter()
                .all(|o| !o.fields.contains_key("sha256"))
        );
        assert!(observations.iter().any(|o| o.fields.contains_key("path")));
        assert_eq!(
            places[0].gaps.get("signature"),
            Some(&UnmeasuredReason::BudgetSpent)
        );
    }

    #[test]
    fn a_missing_file_is_not_a_gap_and_a_refused_one_is() {
        let host = inline(&format!(
            "{ENV}access_denied: ['C:\\Vendor\\locked.exe']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbd':\n    Type: 1\n  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run':\n    Gone: 'C:\\Vendor\\gone.exe'\nfilesystem:\n  'C:\\Vendor':\n    - name: other.exe\n  'C:\\Windows\\System32\\Tasks':\n    - name: readme\n      directory: true\n"
        ));
        let run = Autostart::default().collect(&host);
        let (observations, places) = measured(&run);
        let gone = by(observations, "entry", "Gone");
        assert_eq!(text(gone, "path"), Some(r"C:\Vendor\gone.exe"));
        assert!(!gone.fields.contains_key("sha256"));
        assert!(places.is_empty(), "{places:?}");

        let host = inline(&format!(
            "{ENV}access_denied: ['C:\\Vendor\\locked.exe']\nregistry:\n  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbd':\n    Type: 1\n  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run':\n    Locked: 'C:\\Vendor\\locked.exe'\nfilesystem:\n  'C:\\Windows\\System32\\Tasks':\n    - name: readme\n      directory: true\n"
        ));
        let run = Autostart::default().collect(&host);
        let (_, places) = measured(&run);
        assert_eq!(
            place_gaps(places, "run").and_then(|gaps| gaps.get("sha256")),
            Some(&UnmeasuredReason::AccessDenied)
        );
    }

    #[test]
    fn no_system_root_and_another_os_are_unmeasured_and_nothing_read_is_a_run_wide_gap() {
        let unmeasured = |reason| CollectorRun::Unmeasured {
            collector: "autostart".to_owned(),
            reason,
        };
        assert_eq!(
            Autostart::default().collect(&NonWindowsHost),
            unmeasured(UnmeasuredReason::NotWindows)
        );
        assert_eq!(
            Autostart::default().collect(&inline("platform: windows\n")),
            unmeasured(UnmeasuredReason::ReadFailed)
        );
        let host = inline(&format!(
            "{ENV}elevated: true\naccess_denied: ['HKLM\\SYSTEM\\CurrentControlSet\\Services', 'C:\\Windows\\System32\\Tasks', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce']\n"
        ));
        match Autostart::default().collect(&host) {
            CollectorRun::Measured {
                observations,
                gaps,
                discriminator_gaps,
                ..
            } => {
                assert!(observations.is_empty());
                assert!(discriminator_gaps.is_empty());
                assert_eq!(gaps.get("signature"), Some(&UnmeasuredReason::AccessDenied));
            }
            other @ CollectorRun::Unmeasured { .. } => panic!("{other:?}"),
        }
    }

    /// The baseline reproduces the runner's reading (windows.yml run 36735184291): 278 program
    /// services, 2 `Run` values and 87 task actions, 34 files hashed, and no gap.
    #[test]
    fn baseline_elevated_win11_reproduces_the_runners_autostart_reading() {
        let run = Autostart::default().collect(&fixture("baseline-elevated-win11"));
        let (observations, places) = measured(&run);
        let count = |location: &str| {
            observations
                .iter()
                .filter(|o| text(o, "location") == Some(location))
                .count()
        };
        assert_eq!(
            (count("service"), count("run"), count("task")),
            (278, 2, 87)
        );
        assert_eq!(
            observations
                .iter()
                .filter(|o| o.fields.contains_key("sha256"))
                .count(),
            34
        );
        assert!(places.is_empty(), "{places:?}");
    }

    #[test]
    fn a_principal_is_this_account_by_sid_or_by_name() {
        let identity = Identity {
            sid: Some("S-1-5-21-1-2-3-1001".to_owned()),
            user: Some("alex".to_owned()),
            domain_user: Some(r"PC\alex".to_owned()),
        };
        assert!(identity.is(Some("s-1-5-21-1-2-3-1001")));
        assert!(identity.is(Some("alex")));
        assert!(identity.is(Some(r"pc\ALEX")));
        assert!(!identity.is(Some("S-1-5-18")));
        assert!(!identity.is(None));
    }
}
