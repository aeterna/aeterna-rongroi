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

/// How one `match` entry compares the value a rule carries to the value an observation carries.
///
/// The names are Sigma's, so that a reviewer who knows Sigma reads a rule of ours on sight and a
/// future importer for the Event Log collector is a mapping rather than a translation (ADR 0029).
/// There is deliberately no `re`, no `cidr`, no base64/utf16/windash family and no negation: each is
/// argued against in ADR 0029.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operator {
    /// The value is one the rule names. Written with no `|` suffix at all.
    Equals,
    /// The value sorts after the one the rule names.
    GreaterThan,
    /// The value sorts after the one the rule names, or equals it.
    AtLeast,
    /// The value sorts before the one the rule names.
    LessThan,
    /// The value sorts before the one the rule names, or equals it.
    AtMost,
    /// The text begins with the text the rule names.
    StartsWith,
    /// The text ends with the text the rule names.
    EndsWith,
    /// The text holds the text the rule names somewhere in it.
    Contains,
    /// The field is there (`true`) or is not there (`false`).
    Exists,
}

/// Every operator that is written as a `|` suffix, in the order they are listed to an author.
pub const SUFFIX_OPERATORS: [Operator; 8] = [
    Operator::GreaterThan,
    Operator::AtLeast,
    Operator::LessThan,
    Operator::AtMost,
    Operator::StartsWith,
    Operator::EndsWith,
    Operator::Contains,
    Operator::Exists,
];

impl Operator {
    /// The suffix that names this operator in a `match` key. Equality has none.
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Equals => None,
            Self::GreaterThan => Some("gt"),
            Self::AtLeast => Some("gte"),
            Self::LessThan => Some("lt"),
            Self::AtMost => Some("lte"),
            Self::StartsWith => Some("startswith"),
            Self::EndsWith => Some("endswith"),
            Self::Contains => Some("contains"),
            Self::Exists => Some("exists"),
        }
    }

    /// Whether a list value means "any of these" for this operator.
    ///
    /// The ordinal four and `exists` take exactly one value: `run_count|gt: [2, 5]` has no reading a
    /// reviewer could check by eye, and `exists: [true, false]` is every observation.
    pub fn takes_a_list(self) -> bool {
        matches!(
            self,
            Self::Equals | Self::StartsWith | Self::EndsWith | Self::Contains
        )
    }

    /// Whether this operator compares text, and therefore whether `cased` changes what it does.
    pub fn compares_text(self) -> bool {
        matches!(
            self,
            Self::Equals | Self::StartsWith | Self::EndsWith | Self::Contains
        )
    }

    /// Whether this operator puts the two values in order rather than testing them for sameness.
    pub fn is_ordinal(self) -> bool {
        matches!(
            self,
            Self::GreaterThan | Self::AtLeast | Self::LessThan | Self::AtMost
        )
    }
}

/// What a `match` key asks for: an observation field, and how its value is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKey<'a> {
    /// `field`, or `field|<suffix>` where the suffix is one of [`SUFFIX_OPERATORS`].
    Known {
        /// The observation field the key names.
        field: &'a str,
        /// How its value is compared.
        operator: Operator,
    },
    /// `field|<anything else>`. [`validate`] rejects it, so it never reaches a loaded bundle.
    UnknownOperator {
        /// The observation field the key names.
        field: &'a str,
        /// The suffix that names no operator.
        operator: &'a str,
    },
}

impl<'a> MatchKey<'a> {
    /// The observation field this key names, whatever the suffix says.
    ///
    /// This is what makes the suffix form safe for `gaps`. ADR 0025 rejected a key suffix for
    /// `cased` because the key would stop equalling the field name and a field the collector could
    /// not read would fall out of the `gaps` lookup and report `not_found`. Splitting the key here,
    /// once, and looking `gaps` up on this — never on the key — is what answers that (ADR 0029).
    pub fn field(self) -> &'a str {
        match self {
            Self::Known { field, .. } | Self::UnknownOperator { field, .. } => field,
        }
    }
}

/// Splits a `match` key into the observation field it names and the operator it asks for.
///
/// A key with no `|` is an equality comparison on the whole key, which is what every rule written
/// before ADR 0029 means and still means.
pub fn parse_match_key(key: &str) -> MatchKey<'_> {
    let Some((field, suffix)) = key.split_once('|') else {
        return MatchKey::Known {
            field: key,
            operator: Operator::Equals,
        };
    };
    SUFFIX_OPERATORS
        .iter()
        .find(|operator| operator.as_str() == Some(suffix))
        .map_or(
            MatchKey::UnknownOperator {
                field,
                operator: suffix,
            },
            |operator| MatchKey::Known {
                field,
                operator: *operator,
            },
        )
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
    /// Comparisons an observation must satisfy, all of them, to match.
    ///
    /// Each key is an observation field name, optionally followed by `|` and one of the operators
    /// in [`Operator`]; a key with no `|` asks for equality. A list value means **or** for the
    /// operators that take one (ADR 0029). The keys are kept as written so that
    /// [`parse_match_key`] is the single place that splits them, and so that
    /// [`Rule::match_fields`] — which is what the engine looks up in a run's `gaps` — always
    /// yields a field name rather than a key.
    #[serde(rename = "match")]
    pub matcher: BTreeMap<String, serde_json::Value>,
    /// Fields of `match` whose strings are compared byte for byte instead of without regard to
    /// ASCII case (ADR 0025). Every field left out of this list compares case-insensitively, so a
    /// rule that says nothing gets the behaviour Windows has. It names a **field**, not a key, so
    /// one entry covers every comparison a rule makes against that field, `contains` and
    /// `startswith` included (ADR 0029).
    #[serde(default)]
    pub cased: BTreeSet<String>,
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

impl Rule {
    /// Whether this rule said in `unmeasured_when` that it expects to be unmeasured for `reason`.
    ///
    /// This is the whole of what `unmeasured_when` does: the engine records the answer on the
    /// evidence and the view lists the surprises and counts the rest (ADR 0027). It changes nothing
    /// about whether the rule matches.
    pub fn expects_unmeasured(&self, reason: UnmeasuredReason) -> bool {
        self.unmeasured_when.contains(&reason)
    }

    /// Every `match` key split into the field it names and the operator it asks for.
    pub fn conditions(&self) -> impl Iterator<Item = (MatchKey<'_>, &serde_json::Value)> {
        self.matcher
            .iter()
            .map(|(key, value)| (parse_match_key(key), value))
    }

    /// The observation field names this rule reads, once each.
    ///
    /// This is what the engine looks up in a run's `gaps`, and what `check-rules` checks against the
    /// collector's declared vocabulary. Both must see a field name and never a `match` key, which is
    /// why the split happens here rather than at either call site (ADR 0029).
    pub fn match_fields(&self) -> impl Iterator<Item = &str> {
        self.matcher
            .keys()
            .map(|key| parse_match_key(key).field())
            .collect::<BTreeSet<&str>>()
            .into_iter()
    }
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
    for (key, value) in &rule.matcher {
        validate_condition(key, value, report);
    }
    validate_cased(rule, report);
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

/// Checks one `match` entry: that its key names an operator, and that its value is a shape that
/// operator can compare.
///
/// A value shape the operator cannot compare is never a match, on any machine, which this program
/// shows a player as `not_found` — evidence that a thing was looked for and was not there. That is
/// the same defect ADR 0026 removed for field names, arriving through the value instead.
fn validate_condition(key: &str, value: &serde_json::Value, report: &mut impl FnMut(String)) {
    let operator = match parse_match_key(key) {
        MatchKey::Known { operator, .. } => operator,
        MatchKey::UnknownOperator { field, operator } => {
            report(format!(
                "`match` key `{key}` asks for `{operator}`, which is not an operator; \
                 the operators are {}, and `{field}` on its own compares for equality",
                suffix_operator_names()
            ));
            return;
        }
    };
    if let Some(list) = value.as_array() {
        if !operator.takes_a_list() {
            report(format!("`match` key `{key}` takes one value, not a list"));
            return;
        }
        if list.is_empty() {
            report(format!(
                "`match` key `{key}` has an empty list, which no observation can match"
            ));
            return;
        }
        for element in list {
            validate_value(key, operator, element, report);
        }
        return;
    }
    validate_value(key, operator, value, report);
}

/// Checks one value — a whole `match` value, or one element of a list.
fn validate_value(
    key: &str,
    operator: Operator,
    value: &serde_json::Value,
    report: &mut impl FnMut(String),
) {
    match operator {
        Operator::Equals => {}
        Operator::StartsWith | Operator::EndsWith | Operator::Contains => {
            if value.as_str().is_none_or(str::is_empty) {
                report(format!(
                    "`match` key `{key}` compares text, so its value must be a string with something in it"
                ));
            }
        }
        Operator::GreaterThan | Operator::AtLeast | Operator::LessThan | Operator::AtMost => {
            let ok = value.is_number() || value.as_str().is_some_and(is_rfc3339);
            if !ok {
                report(format!(
                    "`match` key `{key}` puts values in order, so its value must be a number or an \
                     RFC 3339 timestamp such as `2026-09-13T00:00:00Z`"
                ));
            }
        }
        Operator::Exists => {
            if !value.is_boolean() {
                report(format!("`match` key `{key}` takes `true` or `false`"));
            }
        }
    }
}

/// Checks that every `cased` entry names a field some comparison in `match` actually compares text
/// of.
///
/// A `cased` entry that names nothing is not harmless: it reads as "this field is compared exactly"
/// while the field its author meant is still compared case-insensitively (ADR 0025). Since ADR 0029
/// a second shape of the same mistake exists — naming a field that `match` uses only where no text
/// is compared, such as `run_count|gte: 2` or `path|exists: true` — and it reads exactly the same
/// way while doing exactly as little.
fn validate_cased(rule: &Rule, report: &mut impl FnMut(String)) {
    for cased in &rule.cased {
        let mut named = false;
        let mut compares_text = false;
        for (key, value) in rule.conditions() {
            if key.field() != cased {
                continue;
            }
            named = true;
            if let MatchKey::Known { operator, .. } = key
                && operator.compares_text()
                && holds_a_string(value)
            {
                compares_text = true;
            }
        }
        if !named {
            report(format!("`cased` names `{cased}`, which `match` does not"));
        } else if !compares_text {
            report(format!(
                "`cased` names `{cased}`, which `match` compares no text of; \
                 case folding changes nothing there"
            ));
        }
    }
}

/// Whether a `match` value is a string, or a list with a string in it.
fn holds_a_string(value: &serde_json::Value) -> bool {
    value.is_string()
        || value
            .as_array()
            .is_some_and(|list| list.iter().any(serde_json::Value::is_string))
}

/// The suffixes an author may write, for a message that does not need a grep.
fn suffix_operator_names() -> String {
    SUFFIX_OPERATORS
        .iter()
        .filter_map(|operator| operator.as_str())
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `value` is a timestamp this program can put in order.
///
/// ADR 0029 decided that an ordinal comparison of timestamps parses both sides rather than comparing
/// the text, so a rule whose value does not parse can never match and is refused here instead.
pub fn is_rfc3339(value: &str) -> bool {
    value.parse::<jiff::Timestamp>().is_ok()
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

    /// A rule that says nothing about case is case-insensitive: the contributor who has never heard
    /// of `cased` gets the safe comparison.
    #[test]
    fn a_rule_without_cased_names_no_case_sensitive_field() {
        let rules = [sourced("posture/boot/example/rule.yaml", VALID)];
        assert!(rules[0].rule.cased.is_empty());
        assert_eq!(validate(&rules, &Translations::new()), vec![]);
    }

    /// A `cased` entry that matches no `match` field would read as an exact comparison while the
    /// field it meant kept folding — the difference between what the rule says and what it does.
    #[test]
    fn cased_naming_a_field_match_does_not_have_is_rejected() {
        let yaml = format!("{VALID}cased: [secure_bot]\n");
        let rules = [sourced("posture/boot/example/rule.yaml", &yaml)];
        let problems = validate(&rules, &Translations::new());
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("`cased` names `secure_bot`")),
            "{problems:?}"
        );
    }

    #[test]
    fn cased_naming_a_match_field_is_accepted() {
        let yaml = format!("{VALID}cased: [secure_boot]\n");
        let rules = [sourced("posture/boot/example/rule.yaml", &yaml)];
        assert_eq!(validate(&rules, &Translations::new()), vec![]);
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

    /// A rule with `match` replaced by `block`, so one helper serves every rejection below.
    fn with_match(block: &str) -> String {
        VALID.replace(
            "match:\n  secure_boot: disabled\n",
            &format!("match:\n{block}"),
        )
    }

    fn problems_of(yaml: &str) -> Vec<String> {
        let rules = [sourced("posture/boot/example/rule.yaml", yaml)];
        validate(&rules, &Translations::new())
            .into_iter()
            .map(|problem| problem.message)
            .collect()
    }

    /// Every operator this repository has, written the way a rule writes it.
    #[test]
    fn a_match_key_splits_into_a_field_and_an_operator() {
        assert_eq!(
            parse_match_key("secure_boot"),
            MatchKey::Known {
                field: "secure_boot",
                operator: Operator::Equals
            }
        );
        for (suffix, operator) in [
            ("gt", Operator::GreaterThan),
            ("gte", Operator::AtLeast),
            ("lt", Operator::LessThan),
            ("lte", Operator::AtMost),
            ("startswith", Operator::StartsWith),
            ("endswith", Operator::EndsWith),
            ("contains", Operator::Contains),
            ("exists", Operator::Exists),
        ] {
            assert_eq!(
                parse_match_key(&format!("path|{suffix}")),
                MatchKey::Known {
                    field: "path",
                    operator
                }
            );
        }
        assert_eq!(
            parse_match_key("path|matches"),
            MatchKey::UnknownOperator {
                field: "path",
                operator: "matches"
            }
        );
    }

    /// Whatever the suffix says, the field name is what the engine looks `gaps` up on — which is
    /// what makes a key suffix safe here at all (ADR 0025's objection, ADR 0029's answer).
    #[test]
    fn match_fields_yields_field_names_and_never_keys() {
        let yaml =
            with_match("  path|startswith: 'C:\\\\'\n  path|endswith: .exe\n  tpm: absent\n");
        let rule: Rule = serde_saphyr::from_str(&yaml).expect("the rule parses");
        assert_eq!(rule.match_fields().collect::<Vec<_>>(), ["path", "tpm"]);
    }

    /// A suffix that names no operator. Accepting it would evaluate the rule as something other
    /// than what it says, which is the whole reason this project did not adopt Sigma's format.
    #[test]
    fn an_operator_that_is_not_one_of_ours_is_rejected() {
        let problems = problems_of(&with_match("  secure_boot|matches: disabled\n"));
        assert!(
            problems.iter().any(|message| message
                .contains("asks for `matches`, which is not an operator")
                && message.contains("`startswith`")),
            "{problems:?}"
        );
    }

    /// An empty list can never match anything, so a rule carrying one is `not_found` for ever —
    /// which this program shows a player as a thing looked for and not there.
    #[test]
    fn an_empty_value_list_is_rejected() {
        let problems = problems_of(&with_match("  secure_boot: []\n"));
        assert!(
            problems
                .iter()
                .any(|message| message.contains("has an empty list")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_list_is_rejected_where_it_has_no_reading() {
        for block in ["  tpm_spec_version|gt: [1, 2]\n", "  tpm|exists: [true]\n"] {
            let problems = problems_of(&with_match(block));
            assert!(
                problems
                    .iter()
                    .any(|message| message.contains("takes one value, not a list")),
                "{block}: {problems:?}"
            );
        }
    }

    #[test]
    fn a_value_the_operator_cannot_compare_is_rejected() {
        for (block, expected) in [
            (
                "  tpm|startswith: 2\n",
                "must be a string with something in it",
            ),
            (
                "  tpm|contains: ''\n",
                "must be a string with something in it",
            ),
            (
                "  tpm|gt: yesterday\n",
                "must be a number or an \\\n                     RFC 3339 timestamp",
            ),
            ("  tpm|exists: yes please\n", "takes `true` or `false`"),
        ] {
            let expected = expected.replace("\\\n                     ", "");
            let problems = problems_of(&with_match(block));
            assert!(
                problems.iter().any(|message| message.contains(&expected)),
                "{block}: {problems:?}"
            );
        }
    }

    /// An RFC 3339 value is accepted, including one written with an offset rather than `Z`: it is
    /// parsed, so the instant is what counts.
    #[test]
    fn an_ordinal_comparison_accepts_a_timestamp() {
        for value in ["2026-09-13T00:00:00Z", "2026-09-13T07:00:00+07:00"] {
            let problems = problems_of(&with_match(&format!("  tpm|gt: \"{value}\"\n")));
            assert_eq!(problems, Vec::<String>::new(), "{value}");
        }
    }

    /// The second shape of the `cased` mistake ADR 0025 closed: the field is in `match`, but only
    /// where no text is compared, so the line reads as an exact comparison and does nothing.
    #[test]
    fn cased_naming_a_field_no_comparison_compares_text_of_is_rejected() {
        for block in [
            "  tpm_spec_version|gt: 1\n",
            "  tpm_spec_version|exists: true\n",
            "  tpm_spec_version: 2\n",
        ] {
            let problems =
                problems_of(&format!("{}cased: [tpm_spec_version]\n", with_match(block)));
            assert!(
                problems
                    .iter()
                    .any(|message| message.contains("compares no text of")),
                "{block}: {problems:?}"
            );
        }
    }

    #[test]
    fn cased_naming_a_field_a_text_operator_compares_is_accepted() {
        let yaml = format!(
            "{}cased: [tpm]\n",
            with_match("  tpm|startswith: ab\n  tpm|exists: true\n")
        );
        assert_eq!(problems_of(&yaml), Vec::<String>::new());
    }

    /// A list of strings is text the rule compares, so `cased` binds to it.
    #[test]
    fn cased_naming_a_field_matched_against_a_list_of_strings_is_accepted() {
        let yaml = format!("{}cased: [tpm]\n", with_match("  tpm: [absent, present]\n"));
        assert_eq!(problems_of(&yaml), Vec::<String>::new());
    }

    #[test]
    fn the_operators_a_list_may_be_written_for() {
        for operator in SUFFIX_OPERATORS {
            assert_eq!(
                operator.takes_a_list(),
                operator.compares_text(),
                "{operator:?}"
            );
        }
        assert!(Operator::Equals.takes_a_list() && Operator::Equals.compares_text());
        assert_eq!(
            SUFFIX_OPERATORS
                .iter()
                .filter(|operator| operator.is_ordinal())
                .count(),
            4
        );
    }

    #[test]
    fn a_timestamp_is_recognised_and_a_date_alone_is_not() {
        assert!(is_rfc3339("2026-09-13T00:00:00Z"));
        assert!(is_rfc3339("2020-01-01T00:00:00.5Z"));
        assert!(!is_rfc3339("2026-09-13"));
        assert!(!is_rfc3339("yesterday"));
    }
}
