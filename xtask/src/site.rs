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
    let (Some(sums), Some(out)) = (&args.sums, &args.out) else {
        bail!("site: --sums and --out are required");
    };
    let sums =
        std::fs::read_to_string(sums).with_context(|| format!("reading {}", sums.display()))?;
    let manifest = manifest(&published, &sums, &args.repo)?;
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

/// The values `{{rongroi.*}}` placeholders in `site/` are replaced with.
fn placeholders(manifest: &Manifest) -> BTreeMap<&'static str, String> {
    let latest = &manifest.latest;
    BTreeMap::from([
        ("rongroi.version", latest.version.clone()),
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

/// Copies `site/` to `out`, filling placeholders in HTML and XML, and writes `release.json` beside it.
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
            Some("html" | "xml")
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
        std::fs::remove_dir_all(&out).unwrap();
    }
}
