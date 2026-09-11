// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Rule format v1 and the validation shared by the embedded bundle and `cargo xtask check-rules`.
//! The authoring guide is `docs/rules-authoring.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::{Strength, UnmeasuredReason};

/// Version of the rule format.
pub const RULES_SCHEMA_VERSION: u32 = 1;

/// Lifecycle of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Being developed; fixtures optional.
    Experimental,
    /// Believed correct; positive and negative fixtures required.
    Test,
    /// Proven on real traffic; fixtures required.
    Stable,
    /// Kept for history; never evaluated.
    Deprecated,
}

impl Status {
    /// Whether this status requires a positive and a negative fixture.
    pub fn needs_fixtures(self) -> bool {
        matches!(self, Self::Test | Self::Stable)
    }
}

/// Legitimate software excluded from a rule. Identified by hash or signer, never by file name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    /// SHA-256 of the file, 64 hex characters.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Authenticode signer subject.
    #[serde(default)]
    pub signer: Option<String>,
}

/// How a rule relates to another rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelatedKind {
    /// This rule is the renamed version of the other.
    Renamed,
    /// This rule replaces the other.
    Obsolete,
    /// This rule was derived from the other.
    Derived,
    /// This rule merges the other.
    Merged,
    /// The rules look for similar things.
    Similar,
}

/// A link to another rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Related {
    /// Id of the other rule.
    pub id: String,
    /// Kind of relation.
    #[serde(rename = "type")]
    pub kind: RelatedKind,
}

/// A detection rule (`rules/<collector>/<category>/<slug>/rule.yaml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `UUIDv4`, never reused.
    pub id: String,
    /// English title.
    pub title: String,
    /// English description: what it means and why it matters.
    pub description: String,
    /// Lifecycle status.
    pub status: Status,
    /// Collector the rule reads.
    pub collector: String,
    /// What the evidence can show.
    pub strength: Strength,
    /// Field values an observation must have, all of them, to match.
    #[serde(rename = "match")]
    pub matcher: BTreeMap<String, serde_json::Value>,
    /// Legitimate software excluded from matching.
    #[serde(default)]
    pub allow: Vec<Allow>,
    /// How far back the source can see, in words for the user.
    pub retention: String,
    /// Reasons this rule is expected to be unmeasured on some machines.
    #[serde(default)]
    pub unmeasured_when: Vec<UnmeasuredReason>,
    /// What legitimately produces this evidence. Never empty.
    pub falsepositives: Vec<String>,
    /// Sources.
    #[serde(default)]
    pub references: Vec<String>,
    /// Author.
    pub author: String,
    /// Creation date, `YYYY-MM-DD`.
    pub date: String,
    /// Last change date, `YYYY-MM-DD`.
    #[serde(default)]
    pub modified: Option<String>,
    /// Free-form tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Links to other rules.
    #[serde(default)]
    pub related: Vec<Related>,
}

/// A rule together with its path relative to `rules/`.
#[derive(Debug, Clone, PartialEq)]
pub struct SourcedRule {
    /// Path relative to `rules/`, with `/` separators.
    pub path: String,
    /// The parsed rule.
    pub rule: Rule,
}

/// Translated text for one rule; missing parts fall back to English.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTextOverride {
    /// Translated title.
    #[serde(default)]
    pub title: Option<String>,
    /// Translated description.
    #[serde(default)]
    pub description: Option<String>,
    /// Translated false-positive notes.
    #[serde(default)]
    pub falsepositives: Option<Vec<String>>,
    /// Translated look-back note shown for `not_found` evidence.
    #[serde(default)]
    pub retention: Option<String>,
}

/// `language -> rule id -> translated text`.
pub type Translations = BTreeMap<String, BTreeMap<String, RuleTextOverride>>;

/// Text of a rule in one language, with English fallback already applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleText {
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// False-positive notes.
    pub falsepositives: Vec<String>,
    /// How far back the source can see. Reports keep the English `retention`; this is for display.
    pub retention: String,
}

/// A validation problem in the rules tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// File the problem is in, relative to `rules/`.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rules/{}: {}", self.path, self.message)
    }
}

/// Checks everything about rules and translations that does not need fixture files.
pub fn validate(rules: &[SourcedRule], translations: &Translations) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for sourced in rules {
        let mut report = |message: String| {
            problems.push(Problem {
                path: sourced.path.clone(),
                message,
            });
        };
        if !seen_ids.insert(sourced.rule.id.clone()) {
            report(format!(
                "id `{}` is used by more than one rule",
                sourced.rule.id
            ));
        }
        validate_path(sourced, &mut report);
        validate_rule(&sourced.rule, &mut report);
    }
    validate_translations(translations, &seen_ids, &mut problems);
    problems
}

fn validate_path(sourced: &SourcedRule, report: &mut impl FnMut(String)) {
    let segments: Vec<&str> = sourced.path.split('/').collect();
    let [collector, category, slug, "rule.yaml"] = segments.as_slice() else {
        report("rule must live at `<collector>/<category>/<slug>/rule.yaml`".to_owned());
        return;
    };
    if *collector != sourced.rule.collector {
        report(format!(
            "file is under `{collector}/` but declares collector `{}`",
            sourced.rule.collector
        ));
    }
    if !is_snake(collector) {
        report(format!("collector folder `{collector}` must be snake_case"));
    }
    if !is_kebab(category) {
        report(format!("category folder `{category}` must be kebab-case"));
    }
    if !is_kebab(slug) {
        report(format!("slug folder `{slug}` must be kebab-case"));
    }
}

fn validate_rule(rule: &Rule, report: &mut impl FnMut(String)) {
    if !is_uuid_v4(&rule.id) {
        report(format!("id `{}` is not a lowercase UUIDv4", rule.id));
    }
    for (field, value) in [
        ("title", &rule.title),
        ("description", &rule.description),
        ("retention", &rule.retention),
        ("author", &rule.author),
    ] {
        if value.trim().is_empty() {
            report(format!("`{field}` must not be empty"));
        }
    }
    if rule.matcher.is_empty() {
        report("`match` must name at least one field".to_owned());
    }
    if rule.falsepositives.is_empty() || rule.falsepositives.iter().any(|f| f.trim().is_empty()) {
        report("`falsepositives` must list what legitimately produces this evidence".to_owned());
    }
    if !is_date(&rule.date) {
        report(format!("`date` `{}` must be YYYY-MM-DD", rule.date));
    }
    if let Some(modified) = &rule.modified
        && !is_date(modified)
    {
        report(format!("`modified` `{modified}` must be YYYY-MM-DD"));
    }
    for allow in &rule.allow {
        match (&allow.sha256, &allow.signer) {
            (Some(hash), None) if is_sha256(hash) => {}
            (Some(hash), None) => {
                report(format!("allow sha256 `{hash}` must be 64 hex characters"));
            }
            (None, Some(signer)) if !signer.trim().is_empty() => {}
            _ => report("each `allow` entry needs exactly one of `sha256` or `signer`".to_owned()),
        }
    }
    for related in &rule.related {
        if !is_uuid_v4(&related.id) {
            report(format!("related id `{}` is not a UUIDv4", related.id));
        }
    }
}

fn validate_translations(
    translations: &Translations,
    rule_ids: &BTreeSet<String>,
    problems: &mut Vec<Problem>,
) {
    for (lang, texts) in translations {
        let mut report = |message: String| {
            problems.push(Problem {
                path: format!("i18n/{lang}.yaml"),
                message,
            });
        };
        if !is_lang(lang) {
            report(format!(
                "`{lang}` is not a BCP 47 tag such as `th` or `pt-BR`"
            ));
        }
        for (id, text) in texts {
            if !rule_ids.contains(id) {
                report(format!("translation for unknown rule id `{id}`"));
            }
            let empty = |field: Option<&str>| field.is_some_and(|t| t.trim().is_empty());
            let empty_fp = text.falsepositives.as_ref().is_some_and(Vec::is_empty);
            if empty(text.title.as_deref())
                || empty(text.description.as_deref())
                || empty(text.retention.as_deref())
                || empty_fp
            {
                report(format!(
                    "translation for `{id}` has an empty field; omit it to fall back to English"
                ));
            }
        }
    }
}

fn is_uuid_v4(value: &str) -> bool {
    value.len() == 36
        && value == value.to_ascii_lowercase()
        && uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4)
}

fn is_kebab(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_snake(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A small, strict subset of BCP 47: `ll`, `lll`, `ll-RR` or `ll-Ssss`.
pub fn is_lang(value: &str) -> bool {
    let mut parts = value.split('-');
    let language_ok = parts
        .next()
        .is_some_and(|p| (2..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_lowercase()));
    let rest: Vec<&str> = parts.collect();
    let region_ok = match rest.as_slice() {
        [] => true,
        [region] => {
            (region.len() == 2 && region.bytes().all(|b| b.is_ascii_uppercase()))
                || (region.len() == 4 && region.bytes().all(|b| b.is_ascii_alphabetic()))
        }
        _ => false,
    };
    language_ok && region_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r"
id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7
title: Example
description: Example description.
status: test
collector: posture
strength: posture
match:
  secure_boot: disabled
retention: Current setting only.
falsepositives: [Legacy BIOS]
author: tests
date: 2026-09-11
";

    fn sourced(path: &str, yaml: &str) -> SourcedRule {
        SourcedRule {
            path: path.to_owned(),
            rule: serde_saphyr::from_str(yaml).unwrap(),
        }
    }

    #[test]
    fn valid_rule_has_no_problems() {
        let rules = [sourced("posture/boot/example/rule.yaml", VALID)];
        assert_eq!(validate(&rules, &Translations::new()), vec![]);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let rules = [
            sourced("posture/boot/example/rule.yaml", VALID),
            sourced("posture/boot/example-two/rule.yaml", VALID),
        ];
        let problems = validate(&rules, &Translations::new());
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("more than one rule"))
        );
    }

    #[test]
    fn wrong_path_shape_is_rejected() {
        let rules = [sourced("posture/example/rule.yaml", VALID)];
        let problems = validate(&rules, &Translations::new());
        assert!(problems.iter().any(|p| p.message.contains("must live at")));
    }

    #[test]
    fn allow_by_file_name_does_not_parse() {
        let yaml = format!("{VALID}allow:\n  - name: dxgi.dll\n");
        assert!(serde_saphyr::from_str::<Rule>(&yaml).is_err());
    }

    #[test]
    fn short_hash_in_allow_is_rejected() {
        let yaml = format!("{VALID}allow:\n  - sha256: abc\n");
        let rules = [sourced("posture/boot/example/rule.yaml", &yaml)];
        let problems = validate(&rules, &Translations::new());
        assert!(problems.iter().any(|p| p.message.contains("64 hex")));
    }

    #[test]
    fn translation_for_unknown_rule_is_rejected() {
        let rules = [sourced("posture/boot/example/rule.yaml", VALID)];
        let mut translations = Translations::new();
        translations.entry("th".to_owned()).or_default().insert(
            "00000000-0000-4000-8000-000000000000".to_owned(),
            RuleTextOverride {
                title: Some("x".to_owned()),
                ..RuleTextOverride::default()
            },
        );
        let problems = validate(&rules, &translations);
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("unknown rule id"))
        );
    }

    #[test]
    fn empty_translated_retention_is_rejected() {
        let rules = [sourced("posture/boot/example/rule.yaml", VALID)];
        let mut translations = Translations::new();
        translations.entry("th".to_owned()).or_default().insert(
            rules[0].rule.id.clone(),
            RuleTextOverride {
                retention: Some("  ".to_owned()),
                ..RuleTextOverride::default()
            },
        );
        let problems = validate(&rules, &translations);
        assert!(
            problems.iter().any(|p| p.message.contains("empty field")),
            "{problems:?}"
        );
    }

    #[test]
    fn language_tags() {
        for ok in ["th", "en", "vi", "pt-BR", "zh-Hant", "fil"] {
            assert!(is_lang(ok), "{ok}");
        }
        for bad in ["TH", "thai", "pt-br", "en-", "e"] {
            assert!(!is_lang(bad), "{bad}");
        }
    }
}
