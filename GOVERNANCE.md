# Governance

## Maintainers

| Role | Who |
|---|---|
| Lead maintainer | [@tanakon8529](https://github.com/tanakon8529) |
| Rule reviewer | **open** |
| Thai-language reviewer | **open** |
| Release approver (second person) | **open** |

## How decisions are made

- Day-to-day changes: pull request, green CI, merged by a maintainer.
- Changes to the architecture, the rule format, the license terms or the purpose boundary in
  [AGENTS.md](AGENTS.md): an ADR in `docs/adr/`, open for comment before merge.

## Releases

Releases are built only by the GitHub release workflow; that workflow is the only place the official-build
marker is set. While there is a single maintainer, releases are not code-signed. Code signing through the
SignPath Foundation requires separate author, reviewer and approver roles, so it will be requested once a
second maintainer can act as release approver.

### How to release

The design and its reasons are in [ADR 0008](docs/adr/0008-release-pipeline.md).

Before the first release, enable **immutable releases** in the repository settings, and run a rehearsal
(`vYYYY.MM.DD-X.Y.Z-rc.N`) as described in ADR 0008, including the desktop-app gate failure test.

1. Open a pull request `chore(release): X.Y.Z` against `dev`. It renames `## [Unreleased]` in `CHANGELOG.md` to
   `## [X.Y.Z] - YYYY-MM-DD` and sets version `X.Y.Z` in `Cargo.toml`, `apps/desktop/src-tauri/tauri.conf.json`
   and `apps/desktop/package.json`. Squash-merge it when CI is green.
2. Open a pull request from `dev` to `main`, also titled `chore(release): X.Y.Z`, and merge it with a **merge
   commit** when CI is green.
3. Tag that merge commit on `main` with the date from the changelog heading and push the tag:
   `git tag -a vYYYY.MM.DD-X.Y.Z -m "aeterna-rongroi X.Y.Z" <commit>`, then `git push origin vYYYY.MM.DD-X.Y.Z`.
   A rehearsal uses `vYYYY.MM.DD-X.Y.Z-rc.N`.
4. Wait for the `release` workflow. It creates a **draft** release with both executables, `SHA256SUMS`, the SBOMs
   and the notes. It never publishes. Do not re-run its `draft release` job: a re-run creates a second draft for
   the same tag; delete a stray draft instead.
5. Download the draft's files and check them on a real Windows machine (hash, no **UNOFFICIAL BUILD** banner,
   version). Builds are not byte-for-byte reproducible, so a check of an earlier `-rc.N` build does not carry over.
6. Open the draft, read the notes and the file list, and publish it. With immutable releases enabled, a published
   release cannot have its tag or files changed; a wrong file needs a new version.

## Becoming a maintainer

Sustained, good-quality contributions in an area (rules, a language, a collector) lead to an invitation for
that role.
