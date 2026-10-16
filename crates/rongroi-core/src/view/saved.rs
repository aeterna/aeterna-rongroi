// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A saved report: the SS view as it was on screen, the device list, and the case code the player typed
//! (ADR 0073).
//!
//! The record is serialised once, by [`SavedRecord::to_bytes`], and everything after that — the digest staff
//! note from the screen and the file the player saves — is taken from those bytes. Nothing here signs anything:
//! the digest ties a file to what was on screen and says no more than the screen did (ADR 0040).

use std::collections::HashSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{ReportView, SsOptions, for_mode_with};
use crate::model::{EvidenceState, Mode, Observation, Report};

/// The `kind` every saved record carries, which a reader checks before anything else.
pub const SAVED_RECORD_KIND: &str = "rongroi-saved-report";

/// The saved record's own format version. Additive changes keep it (ADR 0073, DMA plan Q-R3).
pub const SAVED_RECORD_SCHEMA: u32 = 1;

/// The collectors whose every observation the record carries, matched by a rule or not (ADR 0073 §1).
pub const DEVICE_COLLECTORS: [&str; 2] = ["pci_device", "hid_device"];

/// How many characters digest a screen shows large (ADR 0073 §3).
pub const SHOWN_DIGEST_LEN: usize = 16;

/// Crockford's base32 alphabet, without `I`, `L`, `O` and `U`.
const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in a case code (ADR 0073 §2).
pub const CASE_CODE_LEN: usize = 6;

/// Why a typed case code was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseCodeError {
    /// It had a character Crockford's alphabet does not hold, after `I`, `L` and `O` were read as digits.
    NotInAlphabet(char),
    /// It did not have six characters once hyphens and spaces were removed.
    WrongLength(usize),
}

impl std::fmt::Display for CaseCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInAlphabet(c) => write!(f, "a case code cannot hold '{c}'"),
            Self::WrongLength(n) => {
                write!(f, "a case code has {CASE_CODE_LEN} characters, not {n}")
            }
        }
    }
}

impl std::error::Error for CaseCodeError {}

/// Makes a typed case code canonical, as Crockford's specification reads one: upper case, `I` and `L` as `1`,
/// `O` as `0`, hyphens and spaces removed. Returns the six characters, or why there are not six.
///
/// # Errors
///
/// [`CaseCodeError`] when what is left is not six characters of the alphabet.
pub fn canonical_case_code(typed: &str) -> Result<String, CaseCodeError> {
    let mut code = String::with_capacity(CASE_CODE_LEN);
    for c in typed.chars().filter(|c| *c != '-' && !c.is_whitespace()) {
        let c = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !CROCKFORD.contains(c) {
            return Err(CaseCodeError::NotInAlphabet(c));
        }
        code.push(c);
    }
    let count = code.chars().count();
    if count == CASE_CODE_LEN {
        Ok(code)
    } else {
        Err(CaseCodeError::WrongLength(count))
    }
}

/// A canonical case code as it is shown: `XXX-XXX`.
pub fn shown_case_code(canonical: &str) -> String {
    let (left, right) = canonical.split_at(canonical.len().min(3));
    format!("{left}-{right}")
}

/// The times a front end supplies, which the report itself does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedTimes {
    /// When `scan::run` returned.
    pub scan_finished_at: String,
    /// When the record was built.
    pub saved_at: String,
}

/// One saved report (ADR 0073 §1). Field order is the order of the bytes.
#[derive(Debug, Clone, Serialize)]
pub struct SavedRecord {
    /// Always [`SAVED_RECORD_KIND`].
    pub kind: &'static str,
    /// Always [`SAVED_RECORD_SCHEMA`].
    pub schema: u32,
    /// The canonical case code, when the player typed one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_code: Option<String>,
    /// The program's version, from the header's provenance.
    pub rongroi_version: String,
    /// Whether this is an official build (ADR 0007), from the header's provenance.
    pub official_build: bool,
    /// The header's `generated_at`, taken just before the scan started.
    pub scan_started_at: String,
    /// When the scan returned.
    pub scan_finished_at: String,
    /// When this record was built.
    pub saved_at: String,
    /// The SS view, with the options the player chose.
    pub view: ReportView,
    /// Every observation of [`DEVICE_COLLECTORS`], matched by a rule or not, each once.
    pub devices: Vec<Observation>,
}

impl SavedRecord {
    /// The record's bytes: compact UTF-8 JSON, no byte-order mark. Called once; keep the result.
    ///
    /// # Errors
    ///
    /// When serialisation fails, which a record built by [`saved_record`] does not.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// The SHA-256 of `bytes`, as 64 lowercase hex characters.
pub fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Builds the record of `report` as SS mode shows it with `options` (ADR 0073). Never the Self view.
pub fn saved_record(
    report: &Report,
    options: SsOptions,
    case_code: Option<String>,
    times: SavedTimes,
) -> SavedRecord {
    let provenance = &report.header.provenance;
    SavedRecord {
        kind: SAVED_RECORD_KIND,
        schema: SAVED_RECORD_SCHEMA,
        case_code,
        rongroi_version: provenance.version.clone(),
        official_build: provenance.official,
        scan_started_at: report.header.generated_at.clone(),
        scan_finished_at: times.scan_finished_at,
        saved_at: times.saved_at,
        view: for_mode_with(report, Mode::Ss, options),
        devices: devices(report),
    }
}

/// Every device observation the report holds, from matched evidence first and then the unmatched groups,
/// each once.
fn devices(report: &Report) -> Vec<Observation> {
    let matched = report.evidence.iter().filter_map(|item| match &item.state {
        EvidenceState::Found { observations } => Some(observations.iter()),
        _ => None,
    });
    let unmatched = report
        .unmatched
        .iter()
        .map(|group| group.observations.iter());
    let mut seen = HashSet::new();
    matched
        .flatten()
        .chain(unmatched.flatten())
        .filter(|o| DEVICE_COLLECTORS.contains(&o.collector.as_str()))
        .filter(|o| seen.insert(serde_json::to_string(o).unwrap_or_default()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_code_is_made_canonical_as_crockford_says() {
        for (typed, canonical) in [
            ("K7Q-2MX", "K7Q2MX"),
            ("k7q2mx", "K7Q2MX"),
            (" k7q 2mx ", "K7Q2MX"),
            ("IL0-OOA", "11000A"),
        ] {
            assert_eq!(
                canonical_case_code(typed).as_deref(),
                Ok(canonical),
                "{typed}"
            );
        }
    }

    #[test]
    fn a_case_code_outside_the_alphabet_or_of_another_length_is_refused() {
        assert_eq!(
            canonical_case_code("K7Q-2MU"),
            Err(CaseCodeError::NotInAlphabet('U'))
        );
        assert_eq!(
            canonical_case_code("K7Q-2M!"),
            Err(CaseCodeError::NotInAlphabet('!'))
        );
        assert_eq!(
            canonical_case_code("K7Q2M"),
            Err(CaseCodeError::WrongLength(5))
        );
        assert_eq!(canonical_case_code(""), Err(CaseCodeError::WrongLength(0)));
    }

    #[test]
    fn a_canonical_code_is_shown_with_one_hyphen() {
        assert_eq!(shown_case_code("K7Q2MX"), "K7Q-2MX");
    }

    #[test]
    fn the_digest_is_sha256_in_lowercase_hex() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
