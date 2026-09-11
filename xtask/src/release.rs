// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Inputs shared by the release commands (ADR 0008): the release tag, the `CHANGELOG.md` section,
//! `SHA256SUMS` and the report JSON written by the built CLI.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, bail};
use jiff::civil::Date;
use rongroi_core::view::ReportView;

/// A release tag: `vYYYY.MM.DD-X.Y.Z`, or `vYYYY.MM.DD-X.Y.Z-rc.N` for a rehearsal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTag {
    /// Release date written in the tag.
    pub date: Date,
    /// `SemVer` version `X.Y.Z`.
    pub version: String,
    /// `N` of a `-rc.N` rehearsal tag.
    pub rc: Option<u32>,
}

impl ReleaseTag {
    /// Parses a tag, rejecting anything that is not exactly one of the two forms.
    pub fn parse(tag: &str) -> anyhow::Result<Self> {
        let shape = || format!("tag `{tag}` must be vYYYY.MM.DD-X.Y.Z or vYYYY.MM.DD-X.Y.Z-rc.N");
        let rest = tag.strip_prefix('v').with_context(shape)?;
        let (date_text, rest) = rest.split_once('-').with_context(shape)?;
        let date = dotted_date(date_text).with_context(|| {
            format!("tag `{tag}`: `{date_text}` is not a real date written as YYYY.MM.DD")
        })?;
        let (version, rc) = match rest.split_once("-rc.") {
            Some((version, number)) => {
                let rc = plain_number(number).with_context(|| {
                    format!(
                        "tag `{tag}`: `-rc.{number}` needs a whole number without leading zeros"
                    )
                })?;
                (version, Some(rc))
            }
            None => (rest, None),
        };
        if !is_plain_semver(version) {
            bail!("tag `{tag}`: `{version}` is not a version written as X.Y.Z");
        }
        Ok(Self {
            date,
            version: version.to_owned(),
            rc,
        })
    }

    /// A release is a pre-release while the major version is 0, and a rehearsal always is.
    pub fn is_prerelease(&self) -> bool {
        self.rc.is_some() || self.version.starts_with("0.")
    }
}

/// `YYYY.MM.DD` as a calendar date; `None` for any other text or an impossible date.
fn dotted_date(text: &str) -> Option<Date> {
    let mut parts = text.split('.');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    Date::new(digits(year)?, digits(month)?, digits(day)?).ok()
}

/// ASCII digits parsed as a number.
fn digits<T: std::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A number without sign or leading zeros (`0` itself is allowed).
fn plain_number(text: &str) -> Option<u32> {
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    digits(text)
}

/// `X.Y.Z` with plain numbers and no pre-release or build suffix.
fn is_plain_semver(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 3 && parts.iter().all(|part| plain_number(part).is_some())
}

/// The `## [X.Y.Z] - YYYY-MM-DD` section of `CHANGELOG.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangelogSection {
    /// Date in the heading.
    pub date: Date,
    /// Text between the heading and the next `## ` heading, trimmed.
    pub body: String,
}

/// Finds the section for `version`; a missing heading, a heading without a date, or an empty body is an error.
pub fn changelog_section(changelog: &str, version: &str) -> anyhow::Result<ChangelogSection> {
    let prefix = format!("## [{version}]");
    let mut lines = changelog.lines();
    let heading = lines
        .by_ref()
        .find(|line| line.starts_with(&prefix))
        .with_context(|| format!("CHANGELOG.md has no `## [{version}] - YYYY-MM-DD` section"))?;
    let date_text = heading
        .strip_prefix(&prefix)
        .and_then(|rest| rest.trim_start().strip_prefix("- "))
        .map(str::trim)
        .with_context(|| {
            format!("CHANGELOG.md heading `{heading}` must be `## [{version}] - YYYY-MM-DD`")
        })?;
    let date: Date = date_text.parse().with_context(|| {
        format!("CHANGELOG.md heading `{heading}`: `{date_text}` is not a YYYY-MM-DD date")
    })?;
    let body = lines
        .take_while(|line| !line.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n");
    let body = body.trim();
    if body.is_empty() {
        bail!("CHANGELOG.md section `## [{version}]` is empty");
    }
    Ok(ChangelogSection {
        date,
        body: body.to_owned(),
    })
}

/// One line of `SHA256SUMS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// File name without a directory.
    pub name: String,
}

/// `sha256sum` format — `<hash>  <name>` per line — sorted by file name.
pub fn format_sums(sums: &[Checksum]) -> String {
    let mut sorted = sums.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = String::new();
    for sum in &sorted {
        let _ = writeln!(out, "{}  {}", sum.sha256, sum.name);
    }
    out
}

/// Parses `SHA256SUMS` as written by [`format_sums`]. An empty file with no checksum lines is an
/// error.
pub fn parse_sums(text: &str) -> anyhow::Result<Vec<Checksum>> {
    let result: Vec<Checksum> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (sha256, name) = line
                .split_once("  ")
                .with_context(|| format!("SHA256SUMS line `{line}` is not `<sha256>  <file>`"))?;
            let is_hex = sha256
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
            if sha256.len() != 64 || !is_hex {
                bail!("SHA256SUMS line `{line}`: `{sha256}` is not a lowercase SHA-256");
            }
            if name.is_empty() || name.contains(['/', '\\']) {
                bail!("SHA256SUMS line `{line}`: `{name}` must be a bare file name");
            }
            Ok(Checksum {
                sha256: sha256.to_owned(),
                name: name.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if result.is_empty() {
        bail!("SHA256SUMS lists no files");
    }
    Ok(result)
}

/// `text` is a full 40-character lowercase hex commit SHA.
pub fn is_full_sha(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The JSON report the built CLI printed with `scan --json`.
pub fn read_report(path: &Path) -> anyhow::Result<ReportView> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_release_tag() {
        let tag = ReleaseTag::parse("v2026.09.06-0.1.0").unwrap();
        assert_eq!(tag.date, jiff::civil::date(2026, 9, 6));
        assert_eq!(tag.version, "0.1.0");
        assert_eq!(tag.rc, None);
        assert!(tag.is_prerelease());
    }

    #[test]
    fn parses_a_rehearsal_tag() {
        let tag = ReleaseTag::parse("v2026.12.31-1.2.3-rc.2").unwrap();
        assert_eq!(tag.version, "1.2.3");
        assert_eq!(tag.rc, Some(2));
        assert!(tag.is_prerelease());
    }

    #[test]
    fn a_1_x_release_is_not_a_prerelease() {
        assert!(
            !ReleaseTag::parse("v2027.01.15-1.0.0")
                .unwrap()
                .is_prerelease()
        );
    }

    #[test]
    fn rejects_other_tag_shapes() {
        for tag in [
            "2026.09.06-0.1.0",
            "v0.1.0",
            "v2026.9.6-0.1.0",
            "v2026-09-06-0.1.0",
            "v2026.02.30-0.1.0",
            "v2026.09.06-0.1",
            "v2026.09.06-01.0.0",
            "v2026.09.06-0.1.0-rc.",
            "v2026.09.06-0.1.0-rc.01",
            "v2026.09.06-0.1.0-beta.1",
            "v2026.09.06-0.1.0+build",
        ] {
            assert!(ReleaseTag::parse(tag).is_err(), "{tag}");
        }
    }

    const CHANGELOG: &str = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-09-06\n\n### Added\n- First release.\n\n## [0.0.9] - 2026-08-01\n\n### Fixed\n- Old.\n";

    #[test]
    fn finds_the_changelog_section_for_a_version() {
        let section = changelog_section(CHANGELOG, "0.1.0").unwrap();
        assert_eq!(section.date, jiff::civil::date(2026, 9, 6));
        assert_eq!(section.body, "### Added\n- First release.");
    }

    #[test]
    fn changelog_problems_are_errors() {
        let missing = changelog_section(CHANGELOG, "0.2.0").unwrap_err();
        assert!(missing.to_string().contains("no `## [0.2.0]"), "{missing}");
        assert!(changelog_section("## [0.1.0]\n\n### Added\n- x\n", "0.1.0").is_err());
        let empty = changelog_section(
            "## [0.1.0] - 2026-09-06\n\n## [0.0.9] - 2026-08-01\n- x\n",
            "0.1.0",
        )
        .unwrap_err();
        assert!(empty.to_string().contains("is empty"), "{empty}");
    }

    #[test]
    fn sums_round_trip_sorted_by_name() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let text = format_sums(&[
            Checksum {
                sha256: b.clone(),
                name: "z.exe".to_owned(),
            },
            Checksum {
                sha256: a.clone(),
                name: "a.exe".to_owned(),
            },
        ]);
        assert_eq!(text, format!("{a}  a.exe\n{b}  z.exe\n"));
        let parsed = parse_sums(&text).unwrap();
        assert_eq!(parsed[0].name, "a.exe");
        assert_eq!(parsed[1].sha256, b);
    }

    #[test]
    fn rejects_malformed_sums() {
        let a = "a".repeat(64);
        let lines = [
            "abc  a.exe".to_owned(),
            format!("{a}  dir/a.exe"),
            format!("{a} a.exe"),
            format!("{}  a.exe", "A".repeat(64)),
        ];
        for line in &lines {
            assert!(parse_sums(line).is_err(), "{line}");
        }
    }

    #[test]
    fn an_empty_sums_file_is_an_error() {
        let err = parse_sums("").unwrap_err();
        assert!(
            err.to_string().contains("lists no files"),
            "{}",
            err.to_string()
        );
        let err = parse_sums("\n  \n").unwrap_err();
        assert!(
            err.to_string().contains("lists no files"),
            "{}",
            err.to_string()
        );
    }

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn only_full_lowercase_shas_are_accepted() {
        assert!(is_full_sha(COMMIT));
        assert!(!is_full_sha(&COMMIT[..7]));
        assert!(!is_full_sha(&COMMIT.to_uppercase()));
    }
}
