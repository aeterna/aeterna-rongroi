// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The settings that decide where this PC's traffic goes, never a record of where it went (ADR 0054).
//!
//! Three places, told apart by `location`, the discriminator (ADR 0044):
//!
//! - **`hosts`** — the hosts file, in the folder Windows' TCP/IP parameters name (`DataBasePath`,
//!   measured `%SystemRoot%\System32\drivers\etc`). One observation for the file: where it is, whether
//!   it is there, and how many lines are in effect. One observation per host name on a line in effect
//!   that is, or ends in `.` followed by, a name on [`LISTED_NAMES`], with the address the line gives it
//!   and the kind of that address. Every other line is counted and never reported.
//! - **`proxy`** — the current user's `Internet Settings` key: whether `ProxyEnable` is on, and whether a
//!   `ProxyServer` and an `AutoConfigURL` value exist. Never their values, and never the `Connections`
//!   subkey, whose value names name the PC's VPN and dial-up connections.
//! - **`firewall`** — the Windows Firewall rules in the local store: how many there are and how many this
//!   program could not parse, and for each rule whose program is in a `FiveM` program folder, its action,
//!   whether it is enabled, its direction, protocol and profiles, and the program's path. Never a rule's
//!   name or description, which a person can write anything in.
//!
//! No place needs administrator rights (measured on one Windows 11 PC, elevated and not, ADR 0054), so a
//! refusal is `access_denied`. Nothing is opened for writing, and no value is read that is not reported.

use std::collections::BTreeMap;

use rongroi_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use rongroi_host::{Host, Platform, RegistryData, SourceError};

use crate::{Collector, Field, evtx, fivem_dir, paths, prefetch};

const ID: &str = "net_config";

/// The field that says which place an observation is about.
const DISCRIMINATOR: &str = "location";

/// Value of `location` for the hosts file.
pub const HOSTS_LOCATION: &str = "hosts";
/// Value of `location` for the current user's proxy settings.
pub const PROXY_LOCATION: &str = "proxy";
/// Value of `location` for the Windows Firewall rules.
pub const FIREWALL_LOCATION: &str = "firewall";

/// The key holding `DataBasePath`, the folder the hosts file is read from.
pub const TCPIP_PARAMETERS: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
/// The hosts folder when `DataBasePath` is not set, relative to `%SystemRoot%`.
const DEFAULT_DATABASE_RELATIVE_PATH: &str = r"System32\drivers\etc";
/// The current user's proxy settings.
pub const INTERNET_SETTINGS: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
/// The Windows Firewall rules in the local store, one `REG_SZ` value per rule (measured, ADR 0054).
pub const FIREWALL_RULES: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// The names a hosts line is reported for, with their subdomains (ADR 0054, owner decision 1). A name
/// joins the list in a change that says which `FiveM` or Rockstar service uses it.
pub const LISTED_NAMES: [&str; 3] = ["cfx.re", "fivem.net", "rockstargames.com"];

/// The `FiveM` program folders a firewall rule's program has to be in, relative to `%LOCALAPPDATA%`.
/// Both, because GTA V Enhanced's own executable runs from inside the Enhanced one (measured, ADR 0054).
const FIVEM_PROGRAM_FOLDERS: [&str; 2] = [
    fivem_dir::LEGACY_PROGRAM_RELATIVE_PATH,
    fivem_dir::ENHANCED_PROGRAM_RELATIVE_PATH,
];

static FIELDS: [Field; 18] = [
    Field::text("action"),
    Field::text("address"),
    Field::text("address_kind"),
    Field::boolean("auto_config_url_set"),
    Field::text("direction"),
    Field::boolean("enabled"),
    Field::number("firewall_rules"),
    Field::text("host_name"),
    Field::number("line"),
    Field::number("lines_in_effect"),
    Field::text("location"),
    Field::text("path"),
    Field::boolean("present"),
    Field::text("profiles"),
    Field::number("protocol"),
    Field::boolean("proxy_enabled"),
    Field::boolean("proxy_server_set"),
    Field::number("unparsed_rules"),
];

static REASONS: [UnmeasuredReason; 3] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// Reads the hosts file, the proxy settings and the firewall rules.
#[derive(Debug, Clone, Copy)]
pub struct NetConfig;

impl Collector for NetConfig {
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
        let places: [(&str, Result<Vec<Observation>, UnmeasuredReason>); 3] = [
            (HOSTS_LOCATION, hosts(host)),
            (PROXY_LOCATION, proxy(host)),
            (FIREWALL_LOCATION, firewall(host)),
        ];
        let mut observations = Vec::new();
        let mut unread = Vec::new();
        for (location, read) in places {
            match read {
                Ok(read) => observations.extend(read),
                Err(reason) => unread.push((location, reason)),
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

/// The gaps of a run, as `fivem_dir` makes them (ADR 0044): each unread place is a gap in every field
/// for the observations about that place only; when no place was read, a gap in every field for the
/// whole run. `access_denied` sorts first, because it is the reason a rule may declare.
fn unread_gaps(
    unread: Vec<(&str, UnmeasuredReason)>,
) -> (BTreeMap<String, UnmeasuredReason>, Vec<DiscriminatorGaps>) {
    let denied_first = |reason: &UnmeasuredReason| *reason != UnmeasuredReason::AccessDenied;
    if unread.len() == 3 {
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
        .map(|(location, reason)| DiscriminatorGaps {
            discriminator: DISCRIMINATOR.to_owned(),
            value: serde_json::Value::from(location),
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

/// A refusal is `access_denied` whatever the token: no place needed administrator rights where it was
/// measured, so a restart as administrator is not the remedy this collector offers.
fn reason(error: &SourceError) -> UnmeasuredReason {
    match error {
        SourceError::AccessDenied => UnmeasuredReason::AccessDenied,
        SourceError::Unsupported(_) | SourceError::Failed(_) | SourceError::TooLarge { .. } => {
            UnmeasuredReason::ReadFailed
        }
    }
}

fn observation(
    location: &str,
    fields: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
) -> Observation {
    let mut map = BTreeMap::new();
    map.insert(DISCRIMINATOR.to_owned(), serde_json::Value::from(location));
    for (name, value) in fields {
        map.insert(name.to_owned(), value);
    }
    Observation {
        collector: ID.to_owned(),
        fields: map,
    }
}

// ---------------------------------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------------------------------

/// The hosts file's observations, or why it could not be read.
fn hosts(host: &dyn Host) -> Result<Vec<Observation>, UnmeasuredReason> {
    let folder = hosts_folder(host)?;
    let path = format!(r"{}\hosts", folder.trim_end_matches(['\\', '/']));
    let bytes = match host.read_file(&path) {
        Ok(Some(bytes)) => bytes,
        // No file: Windows reads no line from it, which is a measurement, not a gap.
        Ok(None) => {
            return Ok(vec![observation(
                HOSTS_LOCATION,
                [
                    ("path", serde_json::Value::from(path)),
                    ("present", serde_json::Value::from(false)),
                ],
            )]);
        }
        Err(error) => return Err(reason(&error)),
    };
    let text = hosts_text(&bytes).ok_or(UnmeasuredReason::ReadFailed)?;
    let parsed = parse_hosts(&text);
    let mut observations = vec![observation(
        HOSTS_LOCATION,
        [
            ("path", serde_json::Value::from(path)),
            ("present", serde_json::Value::from(true)),
            (
                "lines_in_effect",
                serde_json::Value::from(parsed.lines_in_effect),
            ),
        ],
    )];
    observations.extend(parsed.listed.into_iter().map(|entry| {
        observation(
            HOSTS_LOCATION,
            [
                ("line", serde_json::Value::from(entry.line)),
                ("host_name", serde_json::Value::from(entry.host_name)),
                (
                    "address_kind",
                    serde_json::Value::from(address_kind(&entry.address)),
                ),
                ("address", serde_json::Value::from(entry.address)),
            ],
        )
    }));
    Ok(observations)
}

/// The folder the hosts file is read from: `DataBasePath` with `%SystemRoot%` expanded, or
/// `%SystemRoot%\System32\drivers\etc` when the value is not there.
///
/// Whether Windows resolves names from another folder when the value is changed is not established
/// (ADR 0054); the file read is the one the value names, and its path is reported.
fn hosts_folder(host: &dyn Host) -> Result<String, UnmeasuredReason> {
    let system_root = host
        .env_var(prefetch::SYSTEM_ROOT)
        .filter(|root| paths::is_drive_rooted(root));
    let stored = match host.read_value(TCPIP_PARAMETERS, "DataBasePath") {
        Ok(Some(RegistryData::Text(stored))) => Some(stored),
        Ok(None) => None,
        Ok(Some(_)) => return Err(UnmeasuredReason::ReadFailed),
        Err(error) => return Err(reason(&error)),
    };
    let root = system_root.ok_or(UnmeasuredReason::ReadFailed)?;
    let stored =
        stored.unwrap_or_else(|| format!(r"%SystemRoot%\{DEFAULT_DATABASE_RELATIVE_PATH}"));
    evtx::expand_windows_directory(&stored, &root).ok_or(UnmeasuredReason::ReadFailed)
}

/// The file's text, with a UTF-8 byte-order mark skipped, or `None` for a UTF-16 file.
///
/// The PC measured held UTF-8 with a byte-order mark. How Windows reads a UTF-16 hosts file was not
/// measured, so one is not understood rather than read in a way Windows may not read it.
fn hosts_text(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return None;
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// What a hosts file holds, of what this collector reports.
#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedHosts {
    /// Lines that are not blank once a `#` and what follows it are removed.
    lines_in_effect: u64,
    /// Every listed host name on a line in effect, in file order.
    listed: Vec<ListedEntry>,
}

/// One host name on the list, with the address its line gives it.
#[derive(Debug, PartialEq, Eq)]
struct ListedEntry {
    /// The line's number in the file, from 1.
    line: u64,
    /// The name as the line spells it.
    host_name: String,
    /// The address as the line spells it.
    address: String,
}

/// Reads the lines: a `#` starts a comment, space and tab separate the address from the names after
/// it.
fn parse_hosts(text: &str) -> ParsedHosts {
    let mut parsed = ParsedHosts::default();
    for (index, raw) in text.lines().enumerate() {
        let content = raw.split('#').next().unwrap_or_default();
        let mut tokens = content.split([' ', '\t']).filter(|token| !token.is_empty());
        let Some(address) = tokens.next() else {
            continue;
        };
        parsed.lines_in_effect += 1;
        for name in tokens {
            if is_listed(name) {
                parsed.listed.push(ListedEntry {
                    line: index as u64 + 1,
                    host_name: name.to_owned(),
                    address: address.to_owned(),
                });
            }
        }
    }
    parsed
}

/// Whether `name` is a listed name or one of its subdomains, compared without ASCII case and without a
/// trailing `.`.
fn is_listed(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    LISTED_NAMES.iter().any(|listed| {
        name == *listed
            || name
                .strip_suffix(listed)
                .is_some_and(|head| head.ends_with('.'))
    })
}

/// The kind of address a hosts line gives, which is what SS mode shows in its place (ADR 0054, owner
/// decision 2): `loopback`, `unspecified`, `private` (the private IPv4 ranges, IPv4 and IPv6 link-local,
/// and IPv6 unique-local addresses), `public` for every other address, and `not_an_address` for text
/// that is not one.
///
/// Parsed here rather than with `std::net`, which this program does not use (AGENTS.md hard rule 1).
pub fn address_kind(address: &str) -> &'static str {
    // An IPv6 address may carry a zone, `fe80::1%12`.
    let bare = address.split('%').next().unwrap_or_default();
    if let Some(v4) = parse_v4(bare) {
        return v4_kind(v4);
    }
    let Some(v6) = parse_v6(bare) else {
        return "not_an_address";
    };
    match v6 {
        // An IPv4-mapped address, `::ffff:a.b.c.d`, is that IPv4 address.
        [0, 0, 0, 0, 0, 0xffff, high, low] => {
            let [a, b] = high.to_be_bytes();
            let [c, d] = low.to_be_bytes();
            v4_kind([a, b, c, d])
        }
        [0, 0, 0, 0, 0, 0, 0, 1] => "loopback",
        [0, 0, 0, 0, 0, 0, 0, 0] => "unspecified",
        [first, ..] if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80 => "private",
        _ => "public",
    }
}

fn v4_kind(v4: [u8; 4]) -> &'static str {
    match v4 {
        [127, ..] => "loopback",
        [0, 0, 0, 0] => "unspecified",
        [10, ..] | [192, 168, ..] | [169, 254, ..] => "private",
        [172, second, ..] if (16..=31).contains(&second) => "private",
        _ => "public",
    }
}

/// Four decimal numbers from 0 to 255 separated by `.`, with no leading zero.
fn parse_v4(text: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty()
            || part.len() > 3
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    parts.next().is_none().then_some(octets)
}

/// Eight groups of one to four hex digits separated by `:`, at most one `::` standing for as many zero
/// groups as are missing, and an IPv4 address in place of the last two groups.
fn parse_v6(text: &str) -> Option<[u16; 8]> {
    let (head, tail) = match text.split_once("::") {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };
    let head = v6_groups(head, tail.is_none())?;
    let groups = match tail {
        None => head,
        Some(tail) => {
            let tail = v6_groups(tail, true)?;
            if head.len() + tail.len() > 7 {
                return None;
            }
            let mut all = head;
            all.resize(8 - tail.len(), 0);
            all.extend(tail);
            all
        }
    };
    groups.try_into().ok()
}

/// The groups of one side of a `::`, with an IPv4 address allowed last when `ends` is true.
fn v6_groups(text: &str, ends: bool) -> Option<Vec<u16>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let parts: Vec<&str> = text.split(':').collect();
    let mut groups = Vec::with_capacity(8);
    for (index, part) in parts.iter().enumerate() {
        if ends && index + 1 == parts.len() && part.contains('.') {
            let [a, b, c, d] = parse_v4(part)?;
            groups.push(u16::from_be_bytes([a, b]));
            groups.push(u16::from_be_bytes([c, d]));
        } else if (1..=4).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            groups.push(u16::from_str_radix(part, 16).ok()?);
        } else {
            return None;
        }
    }
    (groups.len() <= 8).then_some(groups)
}

// ---------------------------------------------------------------------------------------------------
// proxy
// ---------------------------------------------------------------------------------------------------

/// The proxy observation: `proxy_enabled` when `ProxyEnable` is a `REG_DWORD`, and whether a
/// `ProxyServer` and an `AutoConfigURL` value exist. Their data is never read.
fn proxy(host: &dyn Host) -> Result<Vec<Observation>, UnmeasuredReason> {
    let names = match host.value_names(INTERNET_SETTINGS) {
        Ok(Some(names)) => names,
        // Every Windows account has this key; one that is not there was not read.
        Ok(None) => return Err(UnmeasuredReason::ReadFailed),
        Err(error) => return Err(reason(&error)),
    };
    let has = |wanted: &str| names.iter().any(|name| name.eq_ignore_ascii_case(wanted));
    let mut fields = vec![
        (
            "proxy_server_set",
            serde_json::Value::from(has("ProxyServer")),
        ),
        (
            "auto_config_url_set",
            serde_json::Value::from(has("AutoConfigURL")),
        ),
    ];
    match host.read_value(INTERNET_SETTINGS, "ProxyEnable") {
        Ok(Some(RegistryData::Dword(enabled))) => {
            fields.push(("proxy_enabled", serde_json::Value::from(enabled != 0)));
        }
        // Absent or of another type: how Windows reads either was not measured, so nothing is said.
        Ok(_) => {}
        Err(error) => return Err(reason(&error)),
    }
    Ok(vec![observation(PROXY_LOCATION, fields)])
}

// ---------------------------------------------------------------------------------------------------
// firewall
// ---------------------------------------------------------------------------------------------------

/// The firewall observations: one about the whole store, and one per rule for a program in a `FiveM`
/// program folder.
fn firewall(host: &dyn Host) -> Result<Vec<Observation>, UnmeasuredReason> {
    // Without the folders there is no telling which rules are `FiveM`'s.
    let folders = fivem_folders(host).ok_or(UnmeasuredReason::ReadFailed)?;
    let names = match host.value_names(FIREWALL_RULES) {
        Ok(Some(names)) => names,
        // Every Windows with the firewall service has this key; one that is not there was not read.
        Ok(None) => return Err(UnmeasuredReason::ReadFailed),
        Err(error) => return Err(reason(&error)),
    };
    let mut unparsed: u64 = 0;
    let mut rules = Vec::new();
    for name in &names {
        let text = match host.read_value(FIREWALL_RULES, name) {
            Ok(Some(RegistryData::Text(text))) => text,
            // Gone between the listing and the read.
            Ok(None) => continue,
            Ok(Some(_)) | Err(SourceError::TooLarge { .. }) => {
                unparsed += 1;
                continue;
            }
            Err(error) => return Err(reason(&error)),
        };
        let Some(rule) = parse_rule(&text) else {
            unparsed += 1;
            continue;
        };
        if rule
            .app
            .as_deref()
            .is_some_and(|app| in_folders(app, &folders))
        {
            rules.push(rule);
        }
    }
    let mut observations = vec![observation(
        FIREWALL_LOCATION,
        [
            (
                "firewall_rules",
                serde_json::Value::from(names.len() as u64),
            ),
            ("unparsed_rules", serde_json::Value::from(unparsed)),
        ],
    )];
    observations.extend(rules.into_iter().map(rule_observation));
    Ok(observations)
}

/// Each `FiveM` program folder under `%LOCALAPPDATA%`, lower-cased and ending in `\`.
fn fivem_folders(host: &dyn Host) -> Option<Vec<String>> {
    let base = host
        .env_var(fivem_dir::LOCAL_APP_DATA)
        .filter(|base| paths::is_drive_rooted(base))?;
    let base = base.trim_end_matches(['\\', '/']).replace('/', "\\");
    Some(
        FIVEM_PROGRAM_FOLDERS
            .iter()
            .map(|folder| format!(r"{base}\{folder}\").to_ascii_lowercase())
            .collect(),
    )
}

/// Whether `app` is inside one of `folders`, compared without ASCII case and with `/` read as `\`.
fn in_folders(app: &str, folders: &[String]) -> bool {
    let app = app.replace('/', "\\").to_ascii_lowercase();
    folders
        .iter()
        .any(|folder| app.starts_with(folder.as_str()))
}

/// The keys of one rule this collector reports.
#[derive(Debug, Default, PartialEq, Eq)]
struct FirewallRule {
    action: Option<String>,
    active: Option<String>,
    direction: Option<String>,
    protocol: Option<String>,
    profiles: Vec<String>,
    app: Option<String>,
}

/// Reads one rule value: `v2.<n>` and `|`-separated `key=value` pairs with a trailing `|` (measured,
/// ADR 0054). Anything else is `None` and counted as unparsed. A key may repeat; `Profile` is kept
/// every time, the others the first time.
fn parse_rule(text: &str) -> Option<FirewallRule> {
    let mut parts = text.split('|');
    let version = parts.next()?;
    if !version.starts_with("v2.") {
        return None;
    }
    let mut rule = FirewallRule::default();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=')?;
        let slot = match key {
            "Action" => &mut rule.action,
            "Active" => &mut rule.active,
            "Dir" => &mut rule.direction,
            "Protocol" => &mut rule.protocol,
            "App" => &mut rule.app,
            "Profile" => {
                rule.profiles.push(value.to_owned());
                continue;
            }
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(value.to_owned());
        }
    }
    Some(rule)
}

fn rule_observation(rule: FirewallRule) -> Observation {
    let mut fields = Vec::new();
    if let Some(app) = rule.app {
        fields.push(("path", serde_json::Value::from(app)));
    }
    if let Some(action) = rule.action {
        fields.push(("action", serde_json::Value::from(action)));
    }
    match rule.active.as_deref() {
        Some(active) if active.eq_ignore_ascii_case("TRUE") => {
            fields.push(("enabled", serde_json::Value::from(true)));
        }
        Some(active) if active.eq_ignore_ascii_case("FALSE") => {
            fields.push(("enabled", serde_json::Value::from(false)));
        }
        _ => {}
    }
    if let Some(direction) = rule.direction {
        fields.push(("direction", serde_json::Value::from(direction)));
    }
    if let Some(protocol) = rule
        .protocol
        .and_then(|protocol| protocol.parse::<u64>().ok())
    {
        fields.push(("protocol", serde_json::Value::from(protocol)));
    }
    if !rule.profiles.is_empty() {
        fields.push(("profiles", serde_json::Value::from(rule.profiles.join(","))));
    }
    observation(FIREWALL_LOCATION, fields)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use rongroi_host::{FixtureHost, NonWindowsHost};

    use super::*;

    fn host(yaml: &str) -> FixtureHost {
        FixtureHost::from_yaml_str(yaml, "inline").unwrap()
    }

    fn measured(
        run: &CollectorRun,
    ) -> (
        &[Observation],
        &BTreeMap<String, UnmeasuredReason>,
        &[DiscriminatorGaps],
    ) {
        match run {
            CollectorRun::Measured {
                observations,
                gaps,
                discriminator_gaps,
                ..
            } => (observations, gaps, discriminator_gaps),
            CollectorRun::Unmeasured { .. } => panic!("expected a measured run, got {run:?}"),
        }
    }

    fn at<'a>(observations: &'a [Observation], location: &str) -> Vec<&'a Observation> {
        observations
            .iter()
            .filter(|observation| observation.fields["location"] == location)
            .collect()
    }

    const ENV: &str = "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\n";
    const PROXY_OFF: &str = "  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings':\n    ProxyEnable: 0\n";
    const NO_RULES: &str = "  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules': {}\n";

    fn with_hosts(content: &str) -> FixtureHost {
        host(&format!(
            "{ENV}registry:\n{PROXY_OFF}{NO_RULES}filesystem:\n  'C:\\Windows\\System32\\drivers\\etc':\n    - name: hosts\n      content: {content:?}\n"
        ))
    }

    #[test]
    fn a_non_windows_host_is_not_measured() {
        assert_eq!(
            NetConfig.collect(&NonWindowsHost),
            CollectorRun::Unmeasured {
                collector: ID.to_owned(),
                reason: UnmeasuredReason::NotWindows,
            }
        );
    }

    #[test]
    fn only_lines_naming_a_listed_name_are_reported() {
        let host = with_hosts(
            "# a comment\n\n127.0.0.1 localhost\n0.0.0.0 ads.example.com # blocked\n10.0.0.5\tlauncher.rockstargames.com other.example\n  # indented comment\n192.0.2.7 CFX.RE. notcfx.re\n",
        );
        let run = NetConfig.collect(&host);
        let (observations, gaps, place_gaps) = measured(&run);
        assert!(gaps.is_empty() && place_gaps.is_empty(), "{run:?}");
        let hosts = at(observations, HOSTS_LOCATION);
        assert_eq!(hosts.len(), 3, "{hosts:?}");
        assert_eq!(
            hosts[0].fields["path"],
            r"C:\Windows\System32\drivers\etc\hosts"
        );
        assert_eq!(hosts[0].fields["present"], true);
        assert_eq!(hosts[0].fields["lines_in_effect"], 4);
        assert_eq!(hosts[1].fields["host_name"], "launcher.rockstargames.com");
        assert_eq!(hosts[1].fields["address"], "10.0.0.5");
        assert_eq!(hosts[1].fields["address_kind"], "private");
        assert_eq!(hosts[1].fields["line"], 5);
        assert_eq!(hosts[2].fields["host_name"], "CFX.RE.");
        assert_eq!(hosts[2].fields["address_kind"], "public");
        for observation in &hosts {
            let text = serde_json::to_string(&observation.fields).unwrap();
            assert!(
                !text.contains("example"),
                "an unlisted name was reported: {text}"
            );
        }
    }

    #[test]
    fn a_name_that_only_ends_like_a_listed_one_is_not_listed() {
        assert!(is_listed("fivem.net"));
        assert!(is_listed("runtime.FiveM.net"));
        assert!(is_listed("cfx.re."));
        assert!(!is_listed("notfivem.net"));
        assert!(!is_listed("fivem.net.example"));
        assert!(!is_listed("rockstargames.com-cdn.example"));
    }

    #[test]
    fn every_address_has_one_kind() {
        let cases = [
            ("127.0.0.1", "loopback"),
            ("127.8.8.8", "loopback"),
            ("::1", "loopback"),
            ("0.0.0.0", "unspecified"),
            ("::", "unspecified"),
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("192.168.1.1", "private"),
            ("169.254.0.1", "private"),
            ("fd00::1", "private"),
            ("fe80::1%12", "private"),
            ("::ffff:192.168.0.1", "private"),
            ("192.0.2.1", "public"),
            ("2001:db8::1", "public"),
            ("1::2:3:4:5:6:7", "public"),
            ("::ffff:127.0.0.1", "loopback"),
            ("172.32.0.1", "public"),
            ("server.example", "not_an_address"),
            ("1.2.3", "not_an_address"),
            ("1.2.3.4.5", "not_an_address"),
            ("01.2.3.4", "not_an_address"),
            ("256.0.0.1", "not_an_address"),
            ("1:2:3:4:5:6:7:8:9", "not_an_address"),
            ("1::2::3", "not_an_address"),
            ("1:2:3:4:5:6:7::8", "not_an_address"),
            ("12345::", "not_an_address"),
            (":1", "not_an_address"),
            ("", "not_an_address"),
        ];
        for (address, kind) in cases {
            assert_eq!(address_kind(address), kind, "{address}");
        }
    }

    #[test]
    fn a_missing_hosts_file_is_measured_as_absent() {
        let host = host(&format!("{ENV}registry:\n{PROXY_OFF}{NO_RULES}"));
        let run = NetConfig.collect(&host);
        let (observations, _, place_gaps) = measured(&run);
        assert!(place_gaps.is_empty(), "{run:?}");
        let hosts = at(observations, HOSTS_LOCATION);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].fields["present"], false);
        assert!(!hosts[0].fields.contains_key("lines_in_effect"));
    }

    #[test]
    fn the_hosts_folder_is_the_one_data_base_path_names() {
        let host = host(&format!(
            "{ENV}registry:\n{PROXY_OFF}{NO_RULES}  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters':\n    DataBasePath: '%SystemRoot%\\Custom\\etc'\nfilesystem:\n  'C:\\Windows\\Custom\\etc':\n    - name: hosts\n      content: \"1.2.3.4 fivem.net\\n\"\n"
        ));
        let run = NetConfig.collect(&host);
        let (observations, ..) = measured(&run);
        let hosts = at(observations, HOSTS_LOCATION);
        assert_eq!(hosts[0].fields["path"], r"C:\Windows\Custom\etc\hosts");
        assert_eq!(hosts[1].fields["host_name"], "fivem.net");
    }

    #[test]
    fn an_unexpandable_folder_is_a_gap_for_hosts_only() {
        let host = host(&format!(
            "{ENV}registry:\n{PROXY_OFF}{NO_RULES}  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters':\n    DataBasePath: '%ProgramData%\\etc'\n"
        ));
        let run = NetConfig.collect(&host);
        let (observations, gaps, place_gaps) = measured(&run);
        assert!(gaps.is_empty());
        assert!(at(observations, HOSTS_LOCATION).is_empty());
        assert_eq!(place_gaps.len(), 1, "{run:?}");
        assert_eq!(place_gaps[0].value, HOSTS_LOCATION);
        assert_eq!(place_gaps[0].gaps["address"], UnmeasuredReason::ReadFailed);
    }

    #[test]
    fn a_utf8_mark_is_skipped_and_a_utf16_file_is_not_understood() {
        assert_eq!(
            hosts_text(&[0xEF, 0xBB, 0xBF, b'#', b'\n']).as_deref(),
            Some("#\n")
        );
        assert!(hosts_text(&[0xFF, 0xFE, b'1', 0]).is_none());
        assert!(hosts_text(&[0xFE, 0xFF, 0, b'1']).is_none());
    }

    #[test]
    fn a_refused_hosts_file_is_access_denied_for_that_place() {
        let host = host(&format!(
            "{ENV}registry:\n{PROXY_OFF}{NO_RULES}filesystem:\n  'C:\\Windows\\System32\\drivers\\etc':\n    - name: hosts\naccess_denied:\n  - 'C:\\Windows\\System32\\drivers\\etc\\hosts'\n"
        ));
        let run = NetConfig.collect(&host);
        let (_, _, place_gaps) = measured(&run);
        assert_eq!(place_gaps.len(), 1, "{run:?}");
        assert_eq!(place_gaps[0].value, HOSTS_LOCATION);
        assert_eq!(
            place_gaps[0].gaps["present"],
            UnmeasuredReason::AccessDenied
        );
    }

    #[test]
    fn the_proxy_says_which_values_exist_and_never_their_data() {
        let host = host(&format!(
            "{ENV}registry:\n{NO_RULES}  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings':\n    ProxyEnable: 1\n    ProxyServer: 'proxy.corp.example:8080'\n"
        ));
        let run = NetConfig.collect(&host);
        let (observations, ..) = measured(&run);
        let proxy = at(observations, PROXY_LOCATION);
        assert_eq!(proxy.len(), 1);
        assert_eq!(proxy[0].fields["proxy_enabled"], true);
        assert_eq!(proxy[0].fields["proxy_server_set"], true);
        assert_eq!(proxy[0].fields["auto_config_url_set"], false);
        let text = serde_json::to_string(&proxy[0].fields).unwrap();
        assert!(!text.contains("corp"), "{text}");
    }

    #[test]
    fn a_proxy_enable_of_another_type_is_not_read_as_on_or_off() {
        let host = host(&format!(
            "{ENV}registry:\n{NO_RULES}  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings':\n    ProxyEnable: '1'\n"
        ));
        let run = NetConfig.collect(&host);
        let proxy = at(measured(&run).0, PROXY_LOCATION);
        assert!(!proxy[0].fields.contains_key("proxy_enabled"));
    }

    #[test]
    fn a_missing_internet_settings_key_was_not_read() {
        let host = host(&format!("{ENV}registry:\n{NO_RULES}"));
        let run = NetConfig.collect(&host);
        let place_gaps = measured(&run).2;
        assert_eq!(place_gaps.len(), 1, "{run:?}");
        assert_eq!(place_gaps[0].value, PROXY_LOCATION);
    }

    const FIVEM_TCP: &str = "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|App=c:\\users\\a\\appdata\\local\\fivem\\fivem.exe|Name=anything a person wrote|Desc=more|Defer=User|";

    fn with_rules(rules: &[(&str, &str)]) -> FixtureHost {
        let mut yaml = format!(
            "{ENV}registry:\n{PROXY_OFF}  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules':\n"
        );
        for (name, value) in rules {
            let _ = writeln!(yaml, "    '{name}': {value:?}");
        }
        host(&yaml)
    }

    #[test]
    fn only_rules_for_a_program_in_a_fivem_folder_are_reported_without_their_names() {
        let host = with_rules(&[
            ("{1}", FIVEM_TCP),
            (
                "{2}",
                "v2.10|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=C:/Users/A/AppData/Local/FiveM for GTAV Enhanced/gamecache/x/GTA5_Enhanced.exe|",
            ),
            (
                "{3}",
                "v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\\Program Files\\Other\\other.exe|Name=x|",
            ),
            (
                "{4}",
                "v2.10|Action=Allow|App=C:\\Users\\a\\AppData\\Local\\FiveMods\\x.exe|",
            ),
            ("{5}", "v1.0|garbage"),
            ("{6}", "v2.10|no equals sign|"),
        ]);
        let run = NetConfig.collect(&host);
        let (observations, gaps, place_gaps) = measured(&run);
        assert!(gaps.is_empty() && place_gaps.is_empty(), "{run:?}");
        let firewall = at(observations, FIREWALL_LOCATION);
        assert_eq!(firewall.len(), 3, "{firewall:?}");
        assert_eq!(firewall[0].fields["firewall_rules"], 6);
        assert_eq!(firewall[0].fields["unparsed_rules"], 2);
        let tcp = &firewall[1].fields;
        assert_eq!(tcp["path"], r"c:\users\a\appdata\local\fivem\fivem.exe");
        assert_eq!(tcp["action"], "Allow");
        assert_eq!(tcp["enabled"], true);
        assert_eq!(tcp["direction"], "In");
        assert_eq!(tcp["protocol"], 6);
        assert_eq!(tcp["profiles"], "Private,Public");
        let udp = &firewall[2].fields;
        assert_eq!(udp["enabled"], false);
        assert_eq!(udp["protocol"], 17);
        assert!(!udp.contains_key("profiles"));
        for observation in &firewall {
            let text = serde_json::to_string(&observation.fields).unwrap();
            assert!(
                !text.contains("person wrote") && !text.contains("more"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_rule_value_of_another_type_is_unparsed() {
        let host = host(&format!(
            "{ENV}registry:\n{PROXY_OFF}  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules':\n    '{{1}}': 5\n"
        ));
        let run = NetConfig.collect(&host);
        let firewall = at(measured(&run).0, FIREWALL_LOCATION);
        assert_eq!(firewall[0].fields["unparsed_rules"], 1);
    }

    #[test]
    fn without_local_app_data_the_firewall_place_is_not_read() {
        let host = host(&format!(
            "platform: windows\nenv:\n  SystemRoot: 'C:\\Windows'\nregistry:\n{PROXY_OFF}{NO_RULES}"
        ));
        let run = NetConfig.collect(&host);
        let place_gaps = measured(&run).2;
        assert_eq!(place_gaps.len(), 1, "{run:?}");
        assert_eq!(place_gaps[0].value, FIREWALL_LOCATION);
        assert_eq!(place_gaps[0].gaps["action"], UnmeasuredReason::ReadFailed);
    }

    #[test]
    fn a_refused_firewall_key_is_access_denied_and_sorts_first() {
        let host = host(&format!(
            "platform: windows\nenv:\n  LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local'\nregistry:\n{PROXY_OFF}{NO_RULES}access_denied:\n  - 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules'\n"
        ));
        let run = NetConfig.collect(&host);
        let place_gaps = measured(&run).2;
        assert_eq!(place_gaps.len(), 2, "{run:?}");
        assert_eq!(place_gaps[0].value, FIREWALL_LOCATION);
        assert_eq!(place_gaps[0].gaps["action"], UnmeasuredReason::AccessDenied);
        assert_eq!(place_gaps[1].value, HOSTS_LOCATION);
    }

    #[test]
    fn with_no_place_read_the_whole_run_is_a_gap() {
        let host = host("platform: windows\n");
        let run = NetConfig.collect(&host);
        let (observations, gaps, place_gaps) = measured(&run);
        assert!(observations.is_empty() && place_gaps.is_empty());
        assert_eq!(gaps["location"], UnmeasuredReason::ReadFailed);
    }

    #[test]
    fn a_rule_value_is_parsed_as_measured() {
        let rule = parse_rule(FIVEM_TCP).unwrap();
        assert_eq!(rule.profiles, ["Private", "Public"]);
        assert_eq!(rule.action.as_deref(), Some("Allow"));
        assert!(parse_rule("v3.0|Action=Allow|").is_none());
        assert!(parse_rule("").is_none());
        assert_eq!(parse_rule("v2.10|"), Some(FirewallRule::default()));
    }
}
