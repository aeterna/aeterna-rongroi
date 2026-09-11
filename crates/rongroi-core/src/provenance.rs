// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Who built this binary (ADR 0007). Only the upstream release workflow sets
//! `RONGROI_OFFICIAL_BUILD=1`; every other build reports itself as unofficial, as NOTICE section 7(c)
//! requires of modified versions.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Build provenance shown in every report header and in the UI banner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// `true` only for binaries built by the upstream release workflow.
    pub official: bool,
    /// Application version.
    pub version: String,
    /// Git commit the release was built from, when known.
    pub commit: Option<String>,
    /// SHA-256 of the running executable, when it could be read.
    pub exe_sha256: Option<String>,
}

impl Provenance {
    /// Provenance of the running binary.
    pub fn current() -> Self {
        Self::from_parts(
            option_env!("RONGROI_OFFICIAL_BUILD"),
            env!("CARGO_PKG_VERSION"),
            option_env!("RONGROI_COMMIT"),
            exe_sha256(),
        )
    }

    /// Builds provenance from explicit parts. Only the exact flag value `"1"` means official.
    pub fn from_parts(
        official_flag: Option<&str>,
        version: &str,
        commit: Option<&str>,
        exe_sha256: Option<String>,
    ) -> Self {
        Self {
            official: official_flag == Some("1"),
            version: version.to_owned(),
            commit: commit.map(str::to_owned),
            exe_sha256,
        }
    }
}

/// SHA-256 of the running executable. Reading our own file is the only file access in this crate.
pub fn exe_sha256() -> Option<String> {
    let path = std::env::current_exe().ok()?;
    let bytes = std::fs::read(path).ok()?;
    Some(sha256_hex(&bytes))
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in &digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_flag_is_official() {
        assert!(Provenance::from_parts(Some("1"), "0.1.0", None, None).official);
        for flag in [None, Some("0"), Some("true"), Some("yes"), Some("")] {
            assert!(
                !Provenance::from_parts(flag, "0.1.0", None, None).official,
                "{flag:?}"
            );
        }
    }

    #[test]
    fn sha256_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
