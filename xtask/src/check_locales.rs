// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask check-locales`: every UI locale must use only keys that exist in English.
//! Missing keys are warnings (they fall back to English); extra keys and extra files are errors.
//! Every collector in this build must have a plain name in English (`report.json`, `collector.<id>`),
//! because the report groups its rows under that name (ADR 0045 §3); a missing one is an error.
//! Rule translations (`rules/i18n/`) are checked by `check-rules`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, bail};
use rongroi_core::rules::is_lang;

const LOCALES: &str = "apps/desktop/src/locales";

/// Everything `run` needs to print or bail on, computed without touching stdout/stderr so tests
/// can assert on the exact error text instead of only on pass/fail.
struct CheckLocalesOutcome {
    errors: Vec<String>,
    warnings: usize,
    languages: usize,
}

pub fn run(root: &Path) -> anyhow::Result<()> {
    let dir = root.join(LOCALES);
    if !dir.is_dir() {
        println!("check-locales: {LOCALES} does not exist yet, nothing to check");
        return Ok(());
    }

    let collector_ids: Vec<&'static str> = rongroi_collectors::all()
        .iter()
        .map(|collector| collector.id())
        .collect();
    let outcome = check(root, &collector_ids)?;
    if outcome.errors.is_empty() {
        println!(
            "check-locales: en + {} language(s) ok, {} untranslated key(s)",
            outcome.languages, outcome.warnings
        );
        Ok(())
    } else {
        for error in &outcome.errors {
            eprintln!("error: {error}");
        }
        bail!("check-locales: {} problem(s)", outcome.errors.len())
    }
}

/// The English locale file that names each collector.
const COLLECTOR_NAMES_FILE: &str = "report.json";

fn check(root: &Path, collector_ids: &[&str]) -> anyhow::Result<CheckLocalesOutcome> {
    let dir = root.join(LOCALES);
    let english_dir = dir.join("en");
    let english_files = json_file_names(&english_dir)?;
    if english_files.is_empty() {
        bail!("check-locales: {LOCALES}/en has no JSON files");
    }

    let mut errors = Vec::new();
    let english_names = if english_files.contains(COLLECTOR_NAMES_FILE) {
        keys(&english_dir.join(COLLECTOR_NAMES_FILE))?
    } else {
        BTreeSet::new()
    };
    for id in collector_ids {
        if !english_names.contains(&format!("collector.{id}")) {
            errors.push(format!(
                "{LOCALES}/en/{COLLECTOR_NAMES_FILE}: collector `{id}` has no plain name (key `collector.{id}`)"
            ));
        }
    }
    let mut warnings = 0;
    let mut languages = 0;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let lang = entry.file_name().to_string_lossy().into_owned();
        if !entry.path().is_dir() || lang == "en" {
            continue;
        }
        languages += 1;
        if !is_lang(&lang) {
            errors.push(format!(
                "{LOCALES}/{lang}: not a BCP 47 tag such as `th` or `pt-BR`"
            ));
        }
        let files = json_file_names(&entry.path())?;
        for file in &files {
            if !english_files.contains(file) {
                errors.push(format!("{LOCALES}/{lang}/{file}: no such file in en/"));
                continue;
            }
            let english = keys(&english_dir.join(file))?;
            let translated = keys(&entry.path().join(file))?;
            for extra in translated.difference(&english) {
                errors.push(format!(
                    "{LOCALES}/{lang}/{file}: key `{extra}` does not exist in English"
                ));
            }
            let missing = english.difference(&translated).count();
            if missing > 0 {
                warnings += missing;
                eprintln!(
                    "warning: {LOCALES}/{lang}/{file}: {missing} key(s) not translated yet (English is shown)"
                );
            }
        }
        for file in english_files.difference(&files) {
            eprintln!(
                "warning: {LOCALES}/{lang}/{file}: file not translated yet (English is shown)"
            );
        }
    }

    Ok(CheckLocalesOutcome {
        errors,
        warnings,
        languages,
    })
}

fn json_file_names(dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if Path::new(&name)
                .extension()
                .is_some_and(|ext| ext == "json")
            {
                names.insert(name);
            }
        }
    }
    Ok(names)
}

fn keys(file: &Path) -> anyhow::Result<BTreeSet<String>> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    let mut out = BTreeSet::new();
    flatten("", &value, &mut out);
    Ok(out)
}

fn flatten(prefix: &str, value: &serde_json::Value, out: &mut BTreeSet<String>) {
    if let serde_json::Value::Object(map) = value {
        for (key, child) in map {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            flatten(&path, child, out);
        }
    } else {
        out.insert(prefix.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A directory under the OS temp dir, unique per test, deleted on drop (even on panic) so a
    /// failed assertion never leaves a fixture tree behind.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the epoch")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "aeterna-rongroi-xtask-check-locales-{}-{label}-{n}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp root");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_locale(root: &Path, lang: &str, file: &str, json: &str) {
        let path = root.join(LOCALES).join(lang).join(file);
        fs::create_dir_all(path.parent().expect("path has a parent")).expect("create parent dirs");
        fs::write(path, json).expect("write locale file");
    }

    #[test]
    fn valid_locales_pass() {
        let tmp = TempRoot::new("valid");
        write_locale(tmp.path(), "en", "common.json", r#"{"app":{"name":"x"}}"#);
        write_locale(tmp.path(), "th", "common.json", r#"{"app":{"name":"y"}}"#);

        let outcome = check(tmp.path(), &[]).expect("check-locales should run to completion");

        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert_eq!(outcome.languages, 1);
        assert_eq!(outcome.warnings, 0);
    }

    /// ADR 0045 §3: the report groups rows under a collector's plain name, so a collector of this
    /// build without one in English is rejected, and the error names it.
    #[test]
    fn collector_without_a_plain_name_is_rejected() {
        let tmp = TempRoot::new("collector-name-missing");
        write_locale(
            tmp.path(),
            "en",
            "report.json",
            r#"{"collector":{"posture":"Security settings"}}"#,
        );

        let outcome =
            check(tmp.path(), &["posture", "bam"]).expect("check-locales should run to completion");

        assert_eq!(outcome.errors.len(), 1, "{:?}", outcome.errors);
        assert!(
            outcome.errors[0].contains(
                "apps/desktop/src/locales/en/report.json: collector `bam` has no plain name (key `collector.bam`)"
            ),
            "{:?}",
            outcome.errors
        );
    }

    #[test]
    fn every_collector_with_a_plain_name_passes() {
        let tmp = TempRoot::new("collector-names-complete");
        write_locale(
            tmp.path(),
            "en",
            "report.json",
            r#"{"collector":{"posture":"Security settings","bam":"BAM"}}"#,
        );

        let outcome =
            check(tmp.path(), &["posture", "bam"]).expect("check-locales should run to completion");

        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    }

    /// The real repository: every collector `rongroi_collectors::all()` returns has its name.
    #[test]
    fn this_repository_names_every_collector() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let ids: Vec<&'static str> = rongroi_collectors::all()
            .iter()
            .map(|collector| collector.id())
            .collect();

        let outcome = check(&root, &ids).expect("check-locales should run to completion");

        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    }

    /// Gate (4): a non-English locale key that does not exist in English must be rejected.
    #[test]
    fn key_not_in_english_is_rejected() {
        let tmp = TempRoot::new("extra-key");
        write_locale(tmp.path(), "en", "common.json", r#"{"app":{"name":"x"}}"#);
        write_locale(
            tmp.path(),
            "th",
            "common.json",
            r#"{"app":{"name":"y","tagline":"z"}}"#,
        );

        let outcome = check(tmp.path(), &[]).expect("check-locales should run to completion");

        assert_eq!(outcome.errors.len(), 1, "{:?}", outcome.errors);
        assert!(
            outcome.errors[0].contains(
                "apps/desktop/src/locales/th/common.json: key `app.tagline` does not exist in English"
            ),
            "{:?}",
            outcome.errors
        );
    }
}
