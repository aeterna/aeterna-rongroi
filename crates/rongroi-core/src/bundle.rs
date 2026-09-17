// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The rules bundle embedded in the executable (ADR 0004). One executable hash pins one rule set.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::provenance::sha256_hex;
use crate::rules::{
    self, Problem, RULES_SCHEMA_VERSION, Rule, RuleFiles, RuleText, SourcedRule, Translations,
};

const EMBEDDED: &str = include_str!(concat!(env!("OUT_DIR"), "/rules_bundle.json"));

/// Identity of a rules bundle, shown in every report header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleInfo {
    /// Rule format version.
    pub schema_version: u32,
    /// SHA-256 of the raw bundle.
    pub sha256: String,
    /// Number of rule files in the bundle, deprecated ones and timeline selectors (ADR 0051) included.
    pub rule_count: usize,
}

/// Why a bundle could not be used.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The raw bundle is not the JSON produced by the build.
    #[error("rules bundle is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A rule or translation file does not parse.
    #[error("rules/{path}: {message}")]
    Parse {
        /// File relative to `rules/`.
        path: String,
        /// Parser message.
        message: String,
    },
    /// Files parse but break the rules in `docs/rules-authoring.md`.
    #[error("rules bundle failed validation ({} problem(s))", .0.len())]
    Invalid(Vec<Problem>),
}

#[derive(Deserialize)]
struct RawBundle {
    rules: Vec<RawRule>,
    i18n: Vec<RawTranslation>,
}

#[derive(Deserialize)]
struct RawRule {
    path: String,
    yaml: String,
    /// The CSV files beside the rule, by file name (ADR 0048). Absent for a rule that has none.
    #[serde(default)]
    data: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RawTranslation {
    lang: String,
    yaml: String,
}

/// Parsed, validated rules and translations.
#[derive(Debug, Clone)]
pub struct Bundle {
    rules: Vec<SourcedRule>,
    translations: Translations,
    info: BundleInfo,
}

impl Bundle {
    /// The bundle compiled into this executable.
    pub fn embedded() -> Result<Self, BundleError> {
        Self::from_bundle_json(EMBEDDED)
    }

    /// Parses and validates raw bundle JSON (as produced by `collect_bundle_json`).
    pub fn from_bundle_json(json: &str) -> Result<Self, BundleError> {
        let raw: RawBundle = serde_json::from_str(json)?;

        let mut rules = Vec::with_capacity(raw.rules.len());
        let mut problems = Vec::new();
        for file in raw.rules {
            let mut rule: Rule =
                serde_saphyr::from_str(&file.yaml).map_err(|e| BundleError::Parse {
                    path: file.path.clone(),
                    message: e.to_string(),
                })?;
            for message in rules::expand_match_lists(&mut rule, &file.data) {
                problems.push(Problem {
                    path: file.path.clone(),
                    message,
                });
            }
            rules.push(SourcedRule {
                path: file.path,
                rule,
            });
        }

        let mut translations = Translations::new();
        for file in raw.i18n {
            let texts = if has_content(&file.yaml) {
                serde_saphyr::from_str(&file.yaml).map_err(|e| BundleError::Parse {
                    path: format!("i18n/{}.yaml", file.lang),
                    message: e.to_string(),
                })?
            } else {
                BTreeMap::new()
            };
            translations.insert(file.lang, texts);
        }

        problems.extend(rules::validate(&rules, &translations));
        if !problems.is_empty() {
            return Err(BundleError::Invalid(problems));
        }

        let info = BundleInfo {
            schema_version: RULES_SCHEMA_VERSION,
            sha256: sha256_hex(json.as_bytes()),
            rule_count: rules.len(),
        };
        Ok(Self {
            rules,
            translations,
            info,
        })
    }

    /// All rules, sorted by path.
    pub fn rules(&self) -> &[SourcedRule] {
        &self.rules
    }

    /// Identity of this bundle.
    pub fn info(&self) -> &BundleInfo {
        &self.info
    }

    /// Languages with rule text: `en` plus every translation file.
    pub fn languages(&self) -> Vec<String> {
        std::iter::once("en".to_owned())
            .chain(self.translations.keys().cloned())
            .collect()
    }

    /// Text of a rule in `lang`, falling back to English for anything not translated.
    pub fn text(&self, rule_id: &str, lang: &str) -> Option<RuleText> {
        let sourced = self.rules.iter().find(|s| s.rule.id == rule_id)?;
        let rule = &sourced.rule;
        let translated = self
            .translations
            .get(lang)
            .and_then(|texts| texts.get(rule_id));
        Some(RuleText {
            title: translated
                .and_then(|t| t.title.clone())
                .unwrap_or_else(|| rule.title.clone()),
            description: translated
                .and_then(|t| t.description.clone())
                .unwrap_or_else(|| rule.description.clone()),
            falsepositives: translated
                .and_then(|t| t.falsepositives.clone())
                .unwrap_or_else(|| rule.falsepositives.clone()),
            retention: translated
                .and_then(|t| t.retention.clone())
                .unwrap_or_else(|| rule.retention.clone()),
            status: rule.status,
            files: RuleFiles::of(sourced),
        })
    }
}

/// A translation file with only comments is an empty map, not a parse error.
fn has_content(yaml: &str) -> bool {
    yaml.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && line != "---"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7\ntitle: English title\ndescription: English description.\nstatus: test\ncollector: posture\nstrength: posture\nmatch:\n  secure_boot: disabled\nretention: Now.\nfalsepositives: [Legacy BIOS]\nauthor: tests\ndate: 2026-09-11\n";

    fn bundle_json(th: &str) -> String {
        serde_json::json!({
            "rules": [{ "path": "posture/boot/example/rule.yaml", "yaml": RULE }],
            "i18n": [{ "lang": "th", "yaml": th }],
        })
        .to_string()
    }

    #[test]
    fn embedded_bundle_is_valid() {
        let bundle = Bundle::embedded();
        assert!(bundle.is_ok(), "{:?}", bundle.err());
        assert!(bundle.unwrap().info().rule_count >= 1);
    }

    #[test]
    fn text_falls_back_to_english_per_field() {
        let th = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7:\n  title: หัวข้อภาษาไทย\n";
        let bundle = Bundle::from_bundle_json(&bundle_json(th)).unwrap();
        let text = bundle
            .text("7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7", "th")
            .unwrap();
        assert_eq!(text.title, "หัวข้อภาษาไทย");
        assert_eq!(text.description, "English description.");
        let english = bundle
            .text("7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7", "vi")
            .unwrap();
        assert_eq!(english.title, "English title");
    }

    #[test]
    fn retention_falls_back_to_english_when_not_translated() {
        let id = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7";
        let translated =
            Bundle::from_bundle_json(&bundle_json(&format!("{id}:\n  retention: ตอนนี้\n"))).unwrap();
        assert_eq!(translated.text(id, "th").unwrap().retention, "ตอนนี้");
        assert_eq!(translated.text(id, "vi").unwrap().retention, "Now.");

        let title_only =
            Bundle::from_bundle_json(&bundle_json(&format!("{id}:\n  title: หัวข้อ\n"))).unwrap();
        assert_eq!(title_only.text(id, "th").unwrap().retention, "Now.");
    }

    #[test]
    fn comment_only_translation_file_is_empty() {
        let bundle = Bundle::from_bundle_json(&bundle_json("# nothing yet\n")).unwrap();
        assert_eq!(bundle.languages(), vec!["en".to_owned(), "th".to_owned()]);
    }

    #[test]
    fn hash_changes_when_rules_change() {
        let a = Bundle::from_bundle_json(&bundle_json("")).unwrap();
        let b = Bundle::from_bundle_json(&bundle_json("# changed\n")).unwrap();
        assert_ne!(a.info().sha256, b.info().sha256);
    }

    #[test]
    fn text_carries_the_status_and_files_of_the_rule() {
        let bundle = Bundle::from_bundle_json(&bundle_json("")).unwrap();
        let text = bundle
            .text("7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7", "th")
            .unwrap();
        assert_eq!(text.status, crate::rules::Status::Test);
        assert_eq!(text.files.rule, "rules/posture/boot/example/rule.yaml");
        assert_eq!(text.files.fixtures, "rules/posture/boot/example/tests");
        assert_eq!(
            text.files.collector,
            "crates/rongroi-collectors/src/posture.rs"
        );
        assert!(text.files.references.is_empty());
    }

    /// A path the UI shows must lead somewhere: every embedded rule names files that exist in the
    /// workspace it was built from (ADR 0045).
    #[test]
    fn every_embedded_rule_names_files_that_exist() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bundle = Bundle::embedded().unwrap();
        for sourced in bundle.rules() {
            let files = crate::rules::RuleFiles::of(sourced);
            assert!(root.join(&files.rule).is_file(), "{}", files.rule);
            assert!(root.join(&files.fixtures).is_dir(), "{}", files.fixtures);
            assert!(root.join(&files.collector).is_file(), "{}", files.collector);
        }
    }

    const LISTED_RULE: &str = "id: 7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7\ntitle: Listed\ndescription: Listed description.\nstatus: test\ncollector: posture\nstrength: posture\nmatch_lists:\n  hvci: states.csv\nretention: Now.\nfalsepositives: [Legacy BIOS]\nauthor: tests\ndate: 2026-09-15\n";

    /// ADR 0048: the data file travels in the bundle beside its rule, and the loaded rule's `match`
    /// holds its first column.
    #[test]
    fn a_rule_data_file_is_expanded_when_the_bundle_loads() {
        let json = serde_json::json!({
            "rules": [{
                "path": "posture/memory-integrity/listed/rule.yaml",
                "yaml": LISTED_RULE,
                "data": { "states.csv": "hvci,note\ndisabled,off\n" },
            }],
            "i18n": [],
        })
        .to_string();
        let bundle = Bundle::from_bundle_json(&json).unwrap();
        assert_eq!(
            bundle.rules()[0].rule.matcher.get("hvci"),
            Some(&serde_json::json!(["disabled"]))
        );
    }

    #[test]
    fn a_rule_whose_data_file_is_not_in_the_bundle_is_invalid() {
        let json = serde_json::json!({
            "rules": [{ "path": "posture/memory-integrity/listed/rule.yaml", "yaml": LISTED_RULE }],
            "i18n": [],
        })
        .to_string();
        let Err(BundleError::Invalid(problems)) = Bundle::from_bundle_json(&json) else {
            panic!("expected an invalid bundle");
        };
        assert!(
            problems
                .iter()
                .any(|problem| problem.message.contains("not a file beside rule.yaml")),
            "{problems:?}"
        );
    }
}
