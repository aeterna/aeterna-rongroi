// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! The ordinary retention of each source of a trace age (ADR 0061).
//!
//! One file per collector, `rules/ages/<collector>.yaml`: what the source ordinarily keeps, in words,
//! the references the words rest on, and whether Microsoft documents it. They are reviewed data in the
//! rules bundle, where ordinary causes already are, with their translations in `rules/i18n/<lang>.yaml`
//! as a rule's are — and so they are in the bundle's hash (ADR 0061, owner decision 2).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::rules::Problem;

/// Where a reference must point for `documented: true`: Microsoft's own documentation.
pub const MICROSOFT_LEARN: &str = "https://learn.microsoft.com/";

/// One `rules/ages/<collector>.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgeText {
    /// `UUIDv4`, never reused, and the key of its translations.
    pub id: String,
    /// The collector whose trace ages this text is shown under.
    pub collector: String,
    /// What the source ordinarily keeps, in English. Where Microsoft does not document it, the text
    /// says so and names what the statement rests on.
    pub retention: String,
    /// Whether Microsoft documents the retention the text states.
    pub documented: bool,
    /// What the text rests on: a Microsoft Learn page, or a document in this repository.
    pub references: Vec<String>,
}

/// An age text and the file it came from, relative to `rules/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedAgeText {
    /// `ages/<collector>.yaml`.
    pub path: String,
    /// The text.
    pub text: AgeText,
}

/// An age text in one language, for a front end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgeTextView {
    /// The retention text, translated when a translation exists.
    pub retention: String,
    /// Whether Microsoft documents it.
    pub documented: bool,
    /// What it rests on, unchanged.
    pub references: Vec<String>,
}

/// Checks every age text on its own and against the rule ids beside it: the file is named after its
/// collector, the id is a `UUIDv4` no rule and no other text uses, the text is not empty, it has a
/// reference, and a text marked documented rests on a Microsoft Learn page (ADR 0061).
///
/// Whether each collector that declares an age has a text is a question about the collectors, which
/// this crate cannot see; `cargo xtask check-rules` asks it.
pub fn validate(ages: &[SourcedAgeText], rule_ids: &BTreeSet<String>) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    let mut collectors = BTreeSet::new();
    for sourced in ages {
        let text = &sourced.text;
        let mut report = |message: String| {
            problems.push(Problem {
                path: sourced.path.clone(),
                message,
            });
        };
        if sourced.path != format!("ages/{}.yaml", text.collector) {
            report(format!(
                "an age text for collector `{}` lives at `ages/{}.yaml`",
                text.collector, text.collector
            ));
        }
        if !collectors.insert(text.collector.clone()) {
            report(format!(
                "collector `{}` has more than one age text",
                text.collector
            ));
        }
        if !crate::rules::is_uuid_v4(&text.id) {
            report(format!("id `{}` is not a lower-case UUIDv4", text.id));
        }
        if rule_ids.contains(&text.id) || !seen.insert(text.id.clone()) {
            report(format!("id `{}` is used more than once", text.id));
        }
        if text.retention.trim().is_empty() {
            report("`retention` is empty".to_owned());
        }
        if text
            .references
            .iter()
            .all(|reference| reference.trim().is_empty())
        {
            report("an age text needs at least one reference".to_owned());
        }
        if text.documented
            && !text
                .references
                .iter()
                .any(|reference| reference.starts_with(MICROSOFT_LEARN))
        {
            report(format!(
                "`documented: true` needs a reference on Microsoft Learn ({MICROSOFT_LEARN}…)"
            ));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(collector: &str, documented: bool, references: &[&str]) -> SourcedAgeText {
        SourcedAgeText {
            path: format!("ages/{collector}.yaml"),
            text: AgeText {
                id: "5b0b1f55-4d2c-4c3e-9d8a-7a6b5c4d3e2f".to_owned(),
                collector: collector.to_owned(),
                retention: "Kept until it is full.".to_owned(),
                documented,
                references: references.iter().map(|r| (*r).to_owned()).collect(),
            },
        }
    }

    #[test]
    fn a_documented_text_on_microsoft_learn_passes() {
        let ages = [text(
            "evtx",
            true,
            &["https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key"],
        )];
        assert_eq!(validate(&ages, &BTreeSet::new()), vec![]);
    }

    #[test]
    fn a_text_with_no_reference_is_refused() {
        let problems = validate(&[text("bam", false, &[])], &BTreeSet::new());
        assert!(
            problems
                .iter()
                .any(|problem| problem.message.contains("at least one reference")),
            "{problems:?}"
        );
    }

    #[test]
    fn documented_without_a_microsoft_learn_reference_is_refused() {
        let problems = validate(
            &[text(
                "bam",
                true,
                &["docs/adr/0030-the-words-for-what-was-not-measured.md"],
            )],
            &BTreeSet::new(),
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.message.contains("Microsoft Learn")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_misplaced_text_a_reused_id_and_an_empty_text_are_refused() {
        let mut misplaced = text("pca", false, &["docs/adr/0020-pca.md"]);
        misplaced.path = "ages/prefetch.yaml".to_owned();
        misplaced.text.retention = "  ".to_owned();
        let rule_ids = BTreeSet::from([misplaced.text.id.clone()]);
        let problems: Vec<String> = validate(&[misplaced], &rule_ids)
            .into_iter()
            .map(|problem| problem.message)
            .collect();
        assert!(
            problems.iter().any(|m| m.contains("lives at")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|m| m.contains("more than once")),
            "{problems:?}"
        );
        assert!(problems.iter().any(|m| m.contains("empty")), "{problems:?}");
    }
}
