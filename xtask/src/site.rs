// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `cargo xtask site`: builds the landing page from `site/` and writes `release.json`, the one description
//! of the latest published release that the landing page and other sites read.
//!
//! The release list and `SHA256SUMS` are files the Pages workflow downloads; this command reads files only.
//! Every release so far is a GitHub pre-release, so GitHub's "latest release" is empty and the choice is made
//! here: not a draft, not a `-rc.N` rehearsal, newest `published_at`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::release::{ReleaseTag, parse_sums};

/// Releases listed in `release.json` besides the latest.
const HISTORY: usize = 5;

#[derive(clap::Args)]
pub struct Args {
    /// JSON array from `GET /repos/{repo}/releases`.
    #[arg(long)]
    releases: PathBuf,
    /// Print the tag of the latest published release and stop.
    #[arg(long, conflicts_with_all = ["sums", "out"])]
    latest_tag: bool,
    /// `SHA256SUMS` of that release.
    #[arg(long, required_unless_present = "latest_tag")]
    sums: Option<PathBuf>,
    /// Directory to write the built site into; it must not exist yet.
    #[arg(long, required_unless_present = "latest_tag")]
    out: Option<PathBuf>,
    /// `rules/` as it is in the latest release's tag, counted into `release.json`. Never the working tree:
    /// `dev` can hold rules no release ships yet.
    #[arg(long, required_unless_present = "latest_tag")]
    rules: Option<PathBuf>,
    /// `owner/name` of the repository.
    #[arg(long, default_value = "aeterna/aeterna-rongroi")]
    repo: String,
}

/// The fields of a GitHub release this command reads.
#[derive(Debug, Deserialize)]
pub struct GhRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    published_at: Option<String>,
    html_url: String,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
pub struct GhAsset {
    name: String,
    size: u64,
    browser_download_url: String,
    /// `sha256:<hex>`, computed by GitHub on upload.
    digest: Option<String>,
}

/// `release.json`. Adding a field keeps `schema` at 1; removing one or changing what it means is schema 2.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Manifest {
    schema: u32,
    product: &'static str,
    latest: Latest,
    history: Vec<Past>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Latest {
    version: String,
    tag: String,
    /// `pre-alpha` while GitHub marks the release a pre-release, `stable` after.
    channel: &'static str,
    published_at: String,
    release_url: String,
    sums_url: String,
    files: BTreeMap<&'static str, File>,
    stats: Stats,
}

/// What the release's rule set holds: rules (evidence rows) and timeline selectors (ADR 0051), and the rules
/// by `status`. Counted from the tag's `rules/`, so a page can say "52 rules" without anyone typing 52.
#[derive(Debug, Serialize, PartialEq, Eq, Default)]
pub struct Stats {
    rules: usize,
    selectors: usize,
    experimental: usize,
    test: usize,
    stable: usize,
}

#[derive(Deserialize)]
struct RuleHead {
    status: String,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct File {
    name: String,
    url: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Past {
    version: String,
    tag: String,
    published_at: String,
    release_url: String,
}

pub fn run(root: &Path, args: &Args) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.releases)
        .with_context(|| format!("reading {}", args.releases.display()))?;
    let releases: Vec<GhRelease> =
        serde_json::from_str(&text).context("the release list is not GitHub's release JSON")?;
    let published = published(&releases)?;
    let Some((latest, _)) = published.first() else {
        bail!("site: no published release that is not a rehearsal");
    };
    if args.latest_tag {
        println!("{}", latest.tag_name);
        return Ok(());
    }
    let (Some(sums), Some(out), Some(rules)) = (&args.sums, &args.out, &args.rules) else {
        bail!("site: --sums, --out and --rules are required");
    };
    let sums =
        std::fs::read_to_string(sums).with_context(|| format!("reading {}", sums.display()))?;
    let mut manifest = manifest(&published, &sums, &args.repo)?;
    manifest.latest.stats = count_rules(rules)?;
    build(&root.join("site"), out, &manifest)?;
    println!(
        "site: {} ({}) written to {}",
        manifest.latest.version,
        manifest.latest.tag,
        out.display()
    );
    Ok(())
}

/// Published releases that are not rehearsals, newest first, each with its parsed tag.
fn published(releases: &[GhRelease]) -> anyhow::Result<Vec<(&GhRelease, ReleaseTag)>> {
    let mut found = Vec::new();
    for release in releases.iter().filter(|r| !r.draft) {
        let tag = ReleaseTag::parse(&release.tag_name)?;
        if tag.rc.is_some() {
            continue;
        }
        let Some(at) = &release.published_at else {
            bail!(
                "release {} is not a draft but has no published_at",
                release.tag_name
            );
        };
        let at: jiff::Timestamp = at
            .parse()
            .with_context(|| format!("release {}: published_at `{at}`", release.tag_name))?;
        found.push((release, tag, at));
    }
    found.sort_by_key(|entry| std::cmp::Reverse(entry.2));
    Ok(found.into_iter().map(|(r, t, _)| (r, t)).collect())
}

/// `release.json` for the first of `published`, after checking each executable's GitHub digest against the
/// line for it in `SHA256SUMS`.
fn manifest(
    published: &[(&GhRelease, ReleaseTag)],
    sums: &str,
    repo: &str,
) -> anyhow::Result<Manifest> {
    let Some((release, tag)) = published.first() else {
        bail!("site: no published release that is not a rehearsal");
    };
    let sums = parse_sums(sums)?;
    let prefix = format!(
        "https://github.com/{repo}/releases/download/{}/",
        release.tag_name
    );
    let asset = |name: &str| -> anyhow::Result<&GhAsset> {
        let found = release
            .assets
            .iter()
            .find(|a| a.name == name)
            .with_context(|| format!("release {} has no file `{name}`", release.tag_name))?;
        if found.browser_download_url != format!("{prefix}{name}") {
            bail!(
                "release {}: `{name}` downloads from `{}`, not from this release",
                release.tag_name,
                found.browser_download_url
            );
        }
        Ok(found)
    };
    let file = |name: String| -> anyhow::Result<File> {
        let found = asset(&name)?;
        let listed = sums.iter().find(|s| s.name == name).with_context(|| {
            format!(
                "SHA256SUMS of {} has no line for `{name}`",
                release.tag_name
            )
        })?;
        let digest = found
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
            .with_context(|| format!("GitHub gives no sha256 digest for `{name}`"))?;
        if digest != listed.sha256 {
            bail!(
                "`{name}`: SHA256SUMS says {} but GitHub's digest of the uploaded file is {digest}",
                listed.sha256
            );
        }
        Ok(File {
            url: found.browser_download_url.clone(),
            size: found.size,
            sha256: listed.sha256.clone(),
            name,
        })
    };
    let version = &tag.version;
    let mut files = BTreeMap::new();
    files.insert(
        "gui",
        file(format!("aeterna-rongroi-{version}-windows-x64.exe"))?,
    );
    files.insert(
        "cli",
        file(format!("aeterna-rongroi-cli-{version}-windows-x64.exe"))?,
    );
    Ok(Manifest {
        schema: 1,
        product: "aeterna-rongroi",
        latest: Latest {
            version: version.clone(),
            tag: release.tag_name.clone(),
            channel: if release.prerelease {
                "pre-alpha"
            } else {
                "stable"
            },
            published_at: release.published_at.clone().unwrap_or_default(),
            release_url: release.html_url.clone(),
            sums_url: asset("SHA256SUMS")?.browser_download_url.clone(),
            files,
            stats: Stats::default(),
        },
        history: published
            .iter()
            .skip(1)
            .take(HISTORY)
            .map(|(r, t)| Past {
                version: t.version.clone(),
                tag: r.tag_name.clone(),
                published_at: r.published_at.clone().unwrap_or_default(),
                release_url: r.html_url.clone(),
            })
            .collect(),
    })
}

/// Counts every `rule.yaml` under `rules`: `role: timeline` is a selector, anything else a rule, counted by
/// `status`. An unknown status, or no rule at all, is an error rather than a page that says "0 rules".
fn count_rules(rules: &Path) -> anyhow::Result<Stats> {
    let mut files = Vec::new();
    find_rule_files(rules, &mut files)?;
    let mut stats = Stats::default();
    for path in files {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let head: RuleHead =
            serde_saphyr::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if head.role.as_deref() == Some("timeline") {
            stats.selectors += 1;
            continue;
        }
        stats.rules += 1;
        match head.status.as_str() {
            "experimental" => stats.experimental += 1,
            "test" => stats.test += 1,
            "stable" => stats.stable += 1,
            other => bail!("{}: unknown status `{other}`", path.display()),
        }
    }
    if stats.rules == 0 {
        bail!("site: no rule.yaml under {}", rules.display());
    }
    Ok(stats)
}

fn find_rule_files(dir: &Path, found: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            find_rule_files(&path, found)?;
        } else if path.file_name().is_some_and(|name| name == "rule.yaml") {
            found.push(path);
        }
    }
    Ok(())
}

/// The values `{{rongroi.*}}` placeholders in `site/` are replaced with.
fn placeholders(manifest: &Manifest) -> BTreeMap<&'static str, String> {
    let latest = &manifest.latest;
    BTreeMap::from([
        ("rongroi.version", latest.version.clone()),
        ("rongroi.rules", latest.stats.rules.to_string()),
        ("rongroi.selectors", latest.stats.selectors.to_string()),
        ("rongroi.release_url", latest.release_url.clone()),
        (
            "rongroi.published_date",
            latest.published_at.get(..10).unwrap_or_default().to_owned(),
        ),
    ])
}

/// Replaces every `{{name}}`; an unknown name or an unclosed `{{` is an error, so a typo never reaches the page.
fn fill(text: &str, values: &BTreeMap<&'static str, String>, file: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .with_context(|| format!("{file}: `{{{{` without a closing `}}}}`"))?;
        let name = after[..end].trim();
        let value = values
            .get(name)
            .with_context(|| format!("{file}: unknown placeholder `{{{{{name}}}}}`"))?;
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Copies `site/` to `out`, filling placeholders in HTML, XML and text, and writes `release.json` beside it.
fn build(site: &Path, out: &Path, manifest: &Manifest) -> anyhow::Result<()> {
    if out.exists() {
        bail!("site: {} already exists", out.display());
    }
    let values = placeholders(manifest);
    copy(site, site, out, &values)?;
    let mut json = serde_json::to_string_pretty(manifest)?;
    json.push('\n');
    std::fs::write(out.join("release.json"), json).context("writing release.json")?;
    Ok(())
}

fn copy(
    site: &Path,
    dir: &Path,
    out: &Path,
    values: &BTreeMap<&'static str, String>,
) -> anyhow::Result<()> {
    let target = out.join(dir.strip_prefix(site)?);
    std::fs::create_dir_all(&target).with_context(|| format!("creating {}", target.display()))?;
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            copy(site, &path, out, values)?;
            continue;
        }
        let dest = target.join(entry.file_name());
        let templated = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("html" | "xml" | "txt")
        );
        if templated {
            let shown = path.strip_prefix(site)?.display().to_string();
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            std::fs::write(&dest, fill(&text, values, &shown)?)?;
        } else {
            std::fs::copy(&path, &dest).with_context(|| format!("copying {}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_GUI: &str = "dee6629f9fbbf3d5fa7798ca3a25c2e8777d061515bb594c35ec1e0da2e5589c";
    const SHA_CLI: &str = "f43b0898e6bb752fb330900323378568089546ed17ce4f0509eb81fb390735cc";

    fn asset(tag: &str, name: &str, sha: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "size": 100,
            "browser_download_url":
                format!("https://github.com/aeterna/aeterna-rongroi/releases/download/{tag}/{name}"),
            "digest": format!("sha256:{sha}"),
        })
    }

    fn release(
        tag: &str,
        version: &str,
        published: Option<&str>,
        draft: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "tag_name": tag,
            "draft": draft,
            "prerelease": true,
            "published_at": published,
            "html_url": format!("https://github.com/aeterna/aeterna-rongroi/releases/tag/{tag}"),
            "assets": [
                asset(tag, &format!("aeterna-rongroi-{version}-windows-x64.exe"), SHA_GUI),
                asset(tag, &format!("aeterna-rongroi-cli-{version}-windows-x64.exe"), SHA_CLI),
                asset(tag, "SHA256SUMS", &"0".repeat(64)),
            ],
        })
    }

    fn sums(version: &str) -> String {
        format!(
            "{SHA_GUI}  aeterna-rongroi-{version}-windows-x64.exe\n{SHA_CLI}  aeterna-rongroi-cli-{version}-windows-x64.exe\n"
        )
    }

    fn parse(list: &[serde_json::Value]) -> Vec<GhRelease> {
        serde_json::from_value(serde_json::Value::Array(list.to_vec())).unwrap()
    }

    fn build_manifest(list: &[serde_json::Value], sums_text: &str) -> anyhow::Result<Manifest> {
        let releases = parse(list);
        let published = published(&releases)?;
        manifest(&published, sums_text, "aeterna/aeterna-rongroi")
    }

    #[test]
    fn picks_the_newest_published_release_past_drafts_and_rehearsals() {
        let list = [
            release("v2026.10.10-0.9.0", "0.9.0", None, true),
            release(
                "v2026.10.09-0.8.2-rc.1",
                "0.8.2",
                Some("2026-10-09T10:00:00Z"),
                false,
            ),
            release(
                "v2026.10.09-0.8.1",
                "0.8.1",
                Some("2026-10-09T07:34:16Z"),
                false,
            ),
            release(
                "v2026.10.09-0.8.0",
                "0.8.0",
                Some("2026-10-09T04:52:00Z"),
                false,
            ),
        ];
        let manifest = build_manifest(&list, &sums("0.8.1")).unwrap();
        assert_eq!(manifest.latest.version, "0.8.1");
        assert_eq!(manifest.latest.channel, "pre-alpha");
        assert_eq!(manifest.latest.files["gui"].sha256, SHA_GUI);
        assert_eq!(
            manifest.latest.files["cli"].name,
            "aeterna-rongroi-cli-0.8.1-windows-x64.exe"
        );
        assert_eq!(manifest.history.len(), 1);
        assert_eq!(manifest.history[0].version, "0.8.0");
    }

    #[test]
    fn a_digest_that_differs_from_sha256sums_stops_the_build() {
        let list = [release(
            "v2026.10.09-0.8.1",
            "0.8.1",
            Some("2026-10-09T07:34:16Z"),
            false,
        )];
        let wrong = sums("0.8.1").replace(SHA_CLI, &"1".repeat(64));
        let error = build_manifest(&list, &wrong).unwrap_err().to_string();
        assert!(error.contains("GitHub's digest"), "{error}");
    }

    #[test]
    fn a_missing_executable_stops_the_build() {
        let mut one = release(
            "v2026.10.09-0.8.1",
            "0.8.1",
            Some("2026-10-09T07:34:16Z"),
            false,
        );
        one["assets"].as_array_mut().unwrap().remove(1);
        let error = build_manifest(&[one], &sums("0.8.1"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("has no file"), "{error}");
    }

    #[test]
    fn a_file_served_from_another_place_stops_the_build() {
        let mut one = release(
            "v2026.10.09-0.8.1",
            "0.8.1",
            Some("2026-10-09T07:34:16Z"),
            false,
        );
        one["assets"][0]["browser_download_url"] = "https://example.invalid/x.exe".into();
        let error = build_manifest(&[one], &sums("0.8.1"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not from this release"), "{error}");
    }

    #[test]
    fn only_rehearsals_is_an_error() {
        let list = [release(
            "v2026.10.09-0.8.2-rc.1",
            "0.8.2",
            Some("2026-10-09T10:00:00Z"),
            false,
        )];
        assert!(build_manifest(&list, &sums("0.8.2")).is_err());
    }

    fn write_rule(dir: &Path, path: &str, status: &str, role: Option<&str>) {
        let file = dir.join(path).join("rule.yaml");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let role = role.map(|r| format!("role: {r}\n")).unwrap_or_default();
        std::fs::write(
            file,
            format!("id: x\nstatus: {status}\n{role}collector: prefetch\n"),
        )
        .unwrap();
    }

    #[test]
    fn rules_and_selectors_are_counted_apart() {
        let dir = std::env::temp_dir().join(format!("rongroi-rules-{}", uuid::Uuid::new_v4()));
        write_rule(&dir, "bam/a/one", "experimental", None);
        write_rule(&dir, "bam/a/two", "test", Some("evidence"));
        write_rule(&dir, "pca/timeline/three", "experimental", Some("timeline"));
        std::fs::create_dir_all(dir.join("i18n")).unwrap();
        std::fs::write(dir.join("i18n/th.yaml"), "x: y\n").unwrap();
        let stats = count_rules(&dir).unwrap();
        assert_eq!(
            stats,
            Stats {
                rules: 2,
                selectors: 1,
                experimental: 1,
                test: 1,
                stable: 0,
            }
        );
        write_rule(&dir, "bam/a/four", "retired", None);
        assert!(
            count_rules(&dir)
                .unwrap_err()
                .to_string()
                .contains("unknown status")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_shipped_rules_count_as_every_rule_file() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let stats = count_rules(&root.join("rules")).unwrap();
        let mut files = Vec::new();
        find_rule_files(&root.join("rules"), &mut files).unwrap();
        assert_eq!(stats.rules + stats.selectors, files.len());
        assert_eq!(stats.rules, stats.experimental + stats.test + stats.stable);
        assert!(stats.selectors > 0);
    }

    #[test]
    fn placeholders_are_filled_and_typos_fail() {
        let values = BTreeMap::from([("rongroi.version", "0.8.1".to_owned())]);
        assert_eq!(
            fill(
                "รุ่น {{rongroi.version}} · {{ rongroi.version }}",
                &values,
                "t"
            )
            .unwrap(),
            "รุ่น 0.8.1 · 0.8.1"
        );
        assert!(fill("{{rongroi.release}}", &values, "t").is_err());
        assert!(fill("{{rongroi.version", &values, "t").is_err());
    }

    /// The questions and answers of a page's `<details>` FAQ, in page order.
    fn faq_on_page(page: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut rest = page;
        while let Some(start) = rest.find("<details><summary>") {
            rest = &rest[start + "<details><summary>".len()..];
            let (question, after) = rest.split_once("</summary><p>").unwrap();
            let (answer, after) = after.split_once("</p></details>").unwrap();
            found.push((question.to_owned(), answer.to_owned()));
            rest = after;
        }
        found
    }

    /// The questions and answers of the page's `FAQPage` JSON-LD, in order.
    fn faq_in_json_ld(page: &str) -> Vec<(String, String)> {
        let (_, after) = page
            .split_once("<script type=\"application/ld+json\">")
            .unwrap();
        let (json, _) = after.split_once("</script>").unwrap();
        let data: serde_json::Value = serde_json::from_str(json).unwrap();
        let faq = data["@graph"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["@type"] == "FAQPage")
            .expect("a FAQPage node");
        faq["mainEntity"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                (
                    q["name"].as_str().unwrap().to_owned(),
                    q["acceptedAnswer"]["text"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn the_faq_structured_data_says_what_the_page_says() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for page in ["site/index.html", "site/en/index.html"] {
            let text = std::fs::read_to_string(root.join(page)).unwrap();
            let shown = faq_on_page(&text);
            assert!(!shown.is_empty(), "{page}: no FAQ found");
            assert_eq!(
                shown,
                faq_in_json_ld(&text),
                "{page}: FAQ and FAQPage differ"
            );
        }
    }

    #[test]
    fn the_shipped_site_builds_from_a_release() {
        let list = [release(
            "v2026.10.09-0.8.1",
            "0.8.1",
            Some("2026-10-09T07:34:16Z"),
            false,
        )];
        let manifest = build_manifest(&list, &sums("0.8.1")).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let out = std::env::temp_dir().join(format!("rongroi-site-{}", uuid::Uuid::new_v4()));
        build(&root.join("site"), &out, &manifest).unwrap();
        let page = std::fs::read_to_string(out.join("index.html")).unwrap();
        assert!(page.contains("0.8.1"));
        assert!(!page.contains("{{"));
        assert!(out.join("release.json").is_file());
        assert!(out.join("en/index.html").is_file());
        let llms = std::fs::read_to_string(out.join("llms.txt")).unwrap();
        assert!(llms.starts_with("# aeterna-rongroi\n"));
        assert!(llms.contains("Latest release: 0.8.1 (2026-10-09)"));
        assert!(!llms.contains("{{"));
        std::fs::remove_dir_all(&out).unwrap();
    }

    const SCENE_LAST_TH: &str = "จบตรงนี้ ไม่มีคะแนน ไม่มีคำว่าผ่านหรือไม่ผ่าน คนเป็นผู้ตัดสิน";
    const SCENE_LAST_EN: &str = "It ends here: no score, no pass or fail. A person decides.";
    // REUSE-IgnoreStart
    const SCENE_SCRIPT_HEADER: &str = concat!(
        "// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors\n",
        "// SPDX-License-Identifier: GPL-3.0-or-later\n",
        "// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.\n",
    );
    // REUSE-IgnoreEnd

    fn site_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
    }

    /// Where the attribute `name` starts in one opening tag, if the tag carries it.
    fn find_attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
        let mut rest = tag;
        while let Some(at) = rest.find(name) {
            let before = rest[..at]
                .chars()
                .next_back()
                .is_none_or(char::is_whitespace);
            let after = &rest[at + name.len()..];
            let boundary = after.is_empty()
                || after.starts_with('=')
                || after.starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/');
            if before && boundary {
                return Some(after);
            }
            rest = after;
        }
        None
    }

    fn has_attribute(tag: &str, name: &str) -> bool {
        find_attribute(tag, name).is_some()
    }
    fn attribute_value(tag: &str, name: &str) -> Option<String> {
        let rest = find_attribute(tag, name)?.trim_start();
        let rest = rest.strip_prefix('=')?.trim_start();
        if let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') {
            let value = &rest[1..];
            value.find(quote).map(|end| value[..end].to_owned())
        } else {
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .unwrap_or(rest.len());
            Some(rest[..end].to_owned())
        }
    }

    fn data_msg_names(root: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut rest = root;
        while let Some(at) = rest.find("data-msg-") {
            let after = &rest[at..];
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                .unwrap_or(after.len());
            names.push(after[..end].to_owned());
            rest = &after[end..];
        }
        names.sort();
        names.dedup();
        names
    }

    /// Every opening tag in `text`; closing tags, comments and declarations are skipped.
    fn opening_tags(text: &str) -> Vec<&str> {
        let mut tags = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find('<') {
            let after = &rest[start..];
            if after.starts_with("</") || after.starts_with("<!") || after.starts_with("<?") {
                let Some(end) = after.find('>') else {
                    break;
                };
                rest = &after[end + 1..];
                continue;
            }
            let Some(end) = after.find('>') else {
                break;
            };
            tags.push(&after[..=end]);
            rest = &after[end + 1..];
        }
        tags
    }

    fn tag_with<'a>(text: &'a str, name: &str) -> Result<&'a str, String> {
        let mut found = opening_tags(text)
            .into_iter()
            .filter(|tag| has_attribute(tag, name));
        let tag = found
            .next()
            .ok_or_else(|| format!("no element has `{name}`"))?;
        if found.next().is_some() {
            return Err(format!("more than one element has `{name}`"));
        }
        Ok(tag)
    }

    fn scene_root_tag(page: &str) -> Result<&str, String> {
        let mut marks = page.match_indices("data-scan-scene");
        let Some((at, _)) = marks.next() else {
            return Err("no `data-scan-scene` root".to_owned());
        };
        if marks.next().is_some() {
            return Err("more than one `data-scan-scene` root".to_owned());
        }
        let start = page[..at]
            .rfind('<')
            .ok_or_else(|| "the scene root is not a tag".to_owned())?;
        let end = page[at..]
            .find('>')
            .ok_or_else(|| "the scene root never closes".to_owned())?
            + at;
        Ok(&page[start..=end])
    }

    fn scene_markup(page: &str) -> Result<&str, String> {
        let root = scene_root_tag(page)?;
        let start = page
            .find(root)
            .ok_or_else(|| "the scene root is missing".to_owned())?;
        let end = page[start..]
            .find("</figure>")
            .ok_or_else(|| "the scene never closes its `<figure>`".to_owned())?
            + start
            + "</figure>".len();
        Ok(&page[start..end])
    }

    fn attr_values(text: &str, name: &str) -> Vec<String> {
        opening_tags(text)
            .into_iter()
            .filter_map(|tag| attribute_value(tag, name))
            .collect()
    }

    fn squash(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// p1: one scene, after the three-states section, with the three rows and jumps, the tag, the closing
    /// line, and a script tag for `scan.js`.
    fn check_scene(page: &str, states_heading: &str) -> Result<(), String> {
        let scene = scene_markup(page)?;
        let heading = page
            .find(states_heading)
            .ok_or_else(|| format!("no `{states_heading}` section"))?;
        let states_end = page[heading..]
            .find("</section>")
            .ok_or_else(|| format!("the `{states_heading}` section never closes"))?
            + heading
            + "</section>".len();
        let scene_start = page
            .find(scene)
            .ok_or_else(|| "the scene is not in the page".to_owned())?;
        if scene_start < states_end {
            return Err("the scene comes before the three-states section".to_owned());
        }
        if page[states_end..scene_start].contains("</section>") {
            return Err(
                "another section sits between the three-states section and the scene".to_owned(),
            );
        }
        let mut rows = attr_values(scene, "data-scan-row");
        rows.sort();
        if rows
            .iter()
            .map(String::as_str)
            .ne(["found", "not_found", "unmeasured"])
        {
            return Err("the scene does not have the three result rows".to_owned());
        }
        let jump_tags: Vec<&str> = opening_tags(scene)
            .into_iter()
            .filter(|tag| has_attribute(tag, "data-scan-jump"))
            .collect();
        let mut jumps: Vec<String> = jump_tags
            .iter()
            .filter_map(|tag| attribute_value(tag, "data-scan-jump"))
            .collect();
        jumps.sort();
        if jumps
            .iter()
            .map(String::as_str)
            .ne(["found", "not_found", "unmeasured"])
            || !jump_tags.iter().all(|tag| tag.starts_with("<button"))
        {
            return Err("the scene does not have the three jump buttons".to_owned());
        }
        let (tag, last_line) = if states_heading.contains("ผลมี") {
            ("ตัวอย่าง", SCENE_LAST_TH)
        } else {
            ("Example", SCENE_LAST_EN)
        };
        if !scene.contains(tag) {
            return Err(format!("the scene has no `{tag}` tag"));
        }
        let aria = attribute_value(scene_root_tag(page)?, "aria-label")
            .ok_or_else(|| "the scene root has no `aria-label`".to_owned())?;
        if !aria.contains(tag) {
            return Err(format!(
                "the scene's `aria-label` does not carry the `{tag}` tag"
            ));
        }
        if !squash(scene).contains(last_line) {
            return Err("the scene has no closing line".to_owned());
        }
        let script = opening_tags(page).into_iter().any(|tag| {
            tag.starts_with("<script")
                && attribute_value(tag, "src").is_some_and(|src| src.ends_with("scan.js"))
        });
        if !script {
            return Err("the page has no script tag for `scan.js`".to_owned());
        }
        Ok(())
    }

    /// p2: play, slider and output are `hidden` in the HTML, and the slider carries the contract's
    /// `type`, `min`, `max`, `value` and `data-reach`.
    fn check_scene_controls(page: &str) -> Result<(), String> {
        let play = tag_with(page, "data-scan-play")?;
        let slider = tag_with(page, "data-scan-window")?;
        let out = tag_with(page, "data-scan-window-out")?;
        if !play.starts_with("<button")
            || !slider.starts_with("<input")
            || !out.starts_with("<output")
        {
            return Err("the scene controls are not a button, an input and an output".to_owned());
        }
        for (tag, hook) in [
            (play, "data-scan-play"),
            (slider, "data-scan-window"),
            (out, "data-scan-window-out"),
        ] {
            if !has_attribute(tag, "hidden") {
                return Err(format!("`{hook}` is not `hidden` in the HTML"));
            }
        }
        for (name, expected) in [
            ("type", "range"),
            ("min", "0"),
            ("max", "29"),
            ("value", "23"),
            ("data-reach", "16"),
        ] {
            if attribute_value(slider, name).as_deref() != Some(expected) {
                return Err(format!("the scan slider's `{name}` is not `{expected}`"));
            }
        }
        Ok(())
    }

    /// p3: the `data-msg-*` names on the scene root, all of the contract's five included.
    fn scene_messages(page: &str) -> Result<Vec<String>, String> {
        let names = data_msg_names(scene_root_tag(page)?);
        for required in [
            "data-msg-in",
            "data-msg-out",
            "data-msg-play",
            "data-msg-pause",
            "data-msg-replay",
        ] {
            if !names.iter().any(|name| name == required) {
                return Err(format!("the scene root has no `{required}`"));
            }
        }
        Ok(names)
    }

    /// p4: no "clean", "safe" or "trusted" in any script, and "ผ่าน" / "pass" only in the closing line.
    fn check_scene_words(scene: &str) -> Result<(), String> {
        let text = squash(scene);
        let lower = text.to_lowercase();
        for word in ["clean", "safe", "trusted", "สะอาด", "ปลอดภัย", "✓", "✔"]
        {
            if lower.contains(word) {
                return Err(format!("the scene says `{word}`"));
            }
        }
        let last_line = if text.contains(SCENE_LAST_TH) {
            SCENE_LAST_TH
        } else if text.contains(SCENE_LAST_EN) {
            SCENE_LAST_EN
        } else {
            return Err("the scene has no closing line".to_owned());
        };
        let rest = text.replacen(last_line, "", 1).to_lowercase();
        for word in ["ผ่าน", "pass"] {
            if rest.contains(word) {
                return Err(format!("the scene says `{word}` outside its closing line"));
            }
        }
        Ok(())
    }

    /// j1: the script starts with the neighbours' three header lines, has no Thai, and uses each of the
    /// motion hooks the contract names.
    fn check_scan_script(js: &str) -> Result<(), String> {
        if !js.starts_with(SCENE_SCRIPT_HEADER) {
            return Err("site/scan.js does not start with the three SPDX lines".to_owned());
        }
        if let Some((at, _)) = js
            .char_indices()
            .find(|(_, c)| ('\u{0E00}'..='\u{0E7F}').contains(c))
        {
            let line = js[..at].matches('\n').count() + 1;
            return Err(format!("site/scan.js has Thai text on line {line}"));
        }
        for name in [
            "prefers-reduced-motion",
            "IntersectionObserver",
            "visibilitychange",
            "requestAnimationFrame",
        ] {
            if !js.contains(name) {
                return Err(format!("site/scan.js never uses `{name}`"));
            }
        }
        Ok(())
    }

    /// j2: no network, no randomness, and no markup or code built from strings.
    fn check_scan_script_safety(js: &str) -> Result<(), String> {
        for name in [
            "fetch",
            "XMLHttpRequest",
            "WebSocket",
            "EventSource",
            "sendBeacon",
            "Math.random",
            "innerHTML",
            "insertAdjacentHTML",
            "eval",
            "Function(",
        ] {
            if let Some(at) = js.find(name) {
                let line = js[..at].matches('\n').count() + 1;
                return Err(format!("site/scan.js uses `{name}` on line {line}"));
            }
        }
        Ok(())
    }

    #[test]
    fn each_page_has_one_scene_after_the_three_states() {
        for (page, heading) in [
            ("site/index.html", "ผลมี 3 แบบ"),
            ("site/en/index.html", "Every result is one of three"),
        ] {
            let text = std::fs::read_to_string(site_root().join(page)).unwrap();
            check_scene(&text, heading).unwrap_or_else(|reason| panic!("{page}: {reason}"));
        }
    }

    #[test]
    fn the_scene_controls_start_hidden_and_the_slider_matches_the_contract() {
        for page in ["site/index.html", "site/en/index.html"] {
            let text = std::fs::read_to_string(site_root().join(page)).unwrap();
            check_scene_controls(&text).unwrap_or_else(|reason| panic!("{page}: {reason}"));
        }
    }

    #[test]
    fn both_pages_declare_the_same_scan_messages() {
        let thai = std::fs::read_to_string(site_root().join("site/index.html")).unwrap();
        let english = std::fs::read_to_string(site_root().join("site/en/index.html")).unwrap();
        let thai =
            scene_messages(&thai).unwrap_or_else(|reason| panic!("site/index.html: {reason}"));
        let english = scene_messages(&english)
            .unwrap_or_else(|reason| panic!("site/en/index.html: {reason}"));
        assert_eq!(
            thai, english,
            "the two pages declare different data-msg-* names"
        );
    }

    #[test]
    fn the_scene_does_not_call_a_pc_clean_or_safe() {
        for page in ["site/index.html", "site/en/index.html"] {
            let text = std::fs::read_to_string(site_root().join(page)).unwrap();
            let scene = scene_markup(&text).unwrap_or_else(|reason| panic!("{page}: {reason}"));
            check_scene_words(scene).unwrap_or_else(|reason| panic!("{page}: {reason}"));
        }
    }

    #[test]
    fn the_scan_script_has_its_header_and_motion_hooks() {
        let js = std::fs::read_to_string(site_root().join("site/scan.js"))
            .expect("site/scan.js is missing");
        check_scan_script(&js).unwrap_or_else(|reason| panic!("{reason}"));
    }

    #[test]
    fn the_scan_script_has_no_network_or_injected_markup() {
        let js = std::fs::read_to_string(site_root().join("site/scan.js"))
            .expect("site/scan.js is missing");
        check_scan_script_safety(&js).unwrap_or_else(|reason| panic!("{reason}"));
    }

    #[test]
    fn a_scan_script_that_fetches_fails_the_safety_check() {
        assert!(
            check_scan_script_safety("fetch('/x')")
                .unwrap_err()
                .contains("fetch")
        );
    }

    #[test]
    fn a_scene_that_says_a_pc_is_clean_fails_the_word_check() {
        assert!(check_scene_words("สะอาด").unwrap_err().contains("สะอาด"));
    }
}
