// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A saved report: the SS view as it was on screen, the device list, and the case code the player typed
//! (ADR 0073), and — since schema 2 (ADR 0089 §2) — which program produced it and, under a paired server,
//! the binding and policy it produced it under.
//!
//! The record is serialised once, by [`SavedRecord::to_bytes`], and everything after that — the digest staff
//! note from the screen and the file the player saves — is taken from those bytes. Nothing here signs anything:
//! the digest ties a file to what was on screen and says no more than the screen did (ADR 0040).

use std::collections::HashSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{ReportView, SsOptions, for_mode_with};
use crate::canonical::{self, CanonicalError};
use crate::model::{EvidenceState, Mode, Observation, Report};

/// The `kind` every saved record carries, which a reader checks before anything else.
pub const SAVED_RECORD_KIND: &str = "rongroi-saved-report";

/// The saved record's own format version. Additive changes keep it (ADR 0073, DMA plan Q-R3): a
/// reader that finds none of the schema 2 members still reads a schema 1 record, and ADR 0089 §2
/// makes every record this program builds now a schema 2 one.
pub const SAVED_RECORD_SCHEMA: u32 = 2;

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

/// Which program produced a record (ADR 0089 §1): the offline tool of this repository, or the
/// single-shot client of `aeterna-rongroi-connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProducerName {
    /// The offline desktop app and the CLI of this repository.
    RongroiOffline,
    /// The standalone single-shot client of `aeterna-rongroi-connect`.
    RongroiConnect,
}

/// How the program that produced a record ran (ADR 0089 §2). The producer writes it about itself,
/// so a staff screen shows it as "the report says".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProducerMode {
    /// The Offline app, where the player navigates freely.
    Interactive,
    /// Connect: one case per run, with consent and a Send button.
    SingleShot,
}

/// The program that produced a record (ADR 0089 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Producer {
    /// Which program it was.
    pub name: ProducerName,
    /// That program's own version, as its provenance carries it.
    pub version: String,
    /// How it ran.
    pub mode: ProducerMode,
}

/// How the record is tied to the case a Server Kit opened (ADR 0089 §2, §5). Present only when the
/// record was produced for a paired server; the Offline app and the CLI have none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Binding {
    /// The exact `scheme://host:port` origin the record may be sent to.
    pub server_origin: String,
    /// The single-use ticket Server Kit issued (ADR 0089 §5).
    pub ticket: String,
    /// The value the player's pairing code carried, copied through Connect; it ties the record to
    /// the case, not the scan it recorded (ADR 0089 §2).
    pub nonce: String,
    /// When the ticket's lifetime began.
    pub issued_at: String,
    /// When the ticket's lifetime ends; the server decides expiry by its own clock (ADR 0089 §5).
    pub expires_at: String,
}

/// Which named profile a policy came under (ADR 0089 §2). Each name fixes what
/// `required_collectors` may hold; the record carries the list that ran either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// The collectors behind the rules marked `posture` (ADR 0089 §2, Q18).
    Posture,
    /// The same collectors the Offline app runs in a full scan of this `rongroi_version`.
    Standard,
    /// A list the server picked from what this `rongroi_version` knows.
    Custom,
}

/// The policy a Server Kit issued for the scan (ADR 0089 §2, §5). Present only under a paired
/// server; the Offline app grants its own scope and has none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Policy {
    /// Which profile named what the server may require.
    pub profile: Profile,
    /// The collector IDs the server asked for and the player consented to.
    pub required_collectors: Vec<String>,
    /// Whether administrator elevation was required.
    pub require_elevation: bool,
    /// The name shown on the consent screen; inside the policy so
    /// [`crate::canonical::policy_hash`] covers it (ADR 0089 §2).
    pub server_name: String,
    /// The digest the pairing code carried, of the policy without this member
    /// ([`crate::canonical::policy_hash`]); Connect refuses a policy whose digest differs
    /// (ADR 0089 §5).
    pub policy_hash: String,
}

/// Why a saved record could not be built.
#[derive(Debug, thiserror::Error)]
pub enum SavedRecordError {
    /// The record could not be serialised to JSON, to make its `visual_hash` from.
    #[error("the saved record could not be serialised: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The serialised record could not be canonicalised for its `visual_hash` (ADR 0089 §2): a bug
    /// in the record model, which is meant to hold no fractional number.
    #[error("the saved record could not be canonicalised: {0}")]
    Canonicalisation(#[from] CanonicalError),
}

/// One saved report (ADR 0073 §1, ADR 0089 §2). Field order is the order of the bytes.
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
    /// Which program produced this record and how (ADR 0089 §2).
    pub producer: Producer,
    /// The case this record was produced for, when it was (ADR 0089 §2). Absent from an Offline
    /// record, which the player did not make for one case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    /// The policy the scan ran under, when it was produced under one (ADR 0089 §2). Absent from an
    /// Offline record, which runs its own scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
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
    /// The record as [`crate::canonical::visual_hash`] makes it: the first 8 bytes of `SHA-256`
    /// over the record without this member (ADR 0089 §2). Built last, after every other member —
    /// it covers them and never itself.
    pub visual_hash: String,
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
///
/// `producer` says which program built it and how; `binding` and `policy` say under which case and
/// policy, and are `None` for the Offline app and the CLI, which run themselves (ADR 0089 §2). The
/// `visual_hash` is [`crate::canonical::visual_hash`] over the record as it is serialised here,
/// computed after every other member is set (ADR 0089 §2).
///
/// # Errors
///
/// [`SavedRecordError`] when the record could not be serialised or canonicalised, which is a bug in
/// the record model — it holds no fractional number — rather than something the player could change.
pub fn saved_record(
    report: &Report,
    options: SsOptions,
    case_code: Option<String>,
    producer: Producer,
    binding: Option<Binding>,
    policy: Option<Policy>,
    times: SavedTimes,
) -> Result<SavedRecord, SavedRecordError> {
    let provenance = &report.header.provenance;
    let mut record = SavedRecord {
        kind: SAVED_RECORD_KIND,
        schema: SAVED_RECORD_SCHEMA,
        case_code,
        rongroi_version: provenance.version.clone(),
        official_build: provenance.official,
        producer,
        binding,
        policy,
        scan_started_at: report.header.generated_at.clone(),
        scan_finished_at: times.scan_finished_at,
        saved_at: times.saved_at,
        view: for_mode_with(report, Mode::Ss, options),
        devices: devices(report),
        // Replaced below, from the record as it will be serialised. The value the empty member
        // serialises to matters not: `canonical::visual_hash` removes the member before hashing
        // (ADR 0089 §2), so a real value is only ever written afterwards.
        visual_hash: String::new(),
    };
    let value = serde_json::to_value(&record)?;
    record.visual_hash = canonical::visual_hash(&value)?;
    Ok(record)
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
    fn the_schema_2_enums_are_serialised_with_the_names_adr_0089_gives_them() {
        let spelled = [
            serde_json::to_string(&ProducerName::RongroiOffline).unwrap(),
            serde_json::to_string(&ProducerName::RongroiConnect).unwrap(),
            serde_json::to_string(&ProducerMode::Interactive).unwrap(),
            serde_json::to_string(&ProducerMode::SingleShot).unwrap(),
            serde_json::to_string(&Profile::Posture).unwrap(),
            serde_json::to_string(&Profile::Standard).unwrap(),
            serde_json::to_string(&Profile::Custom).unwrap(),
        ];
        assert_eq!(
            spelled,
            [
                "\"rongroi-offline\"",
                "\"rongroi-connect\"",
                "\"interactive\"",
                "\"single-shot\"",
                "\"posture\"",
                "\"standard\"",
                "\"custom\"",
            ]
        );
    }

    #[test]
    fn the_digest_is_sha256_in_lowercase_hex() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
