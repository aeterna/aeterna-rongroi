# ADR 0008 — Release pipeline and release page

- Status: proposed
- Date: 2026-09-11

## Context

ADR 0007 and the README promise two things that only a release can provide: executables built with the
official-build marker, and a `SHA256SUMS` file on the GitHub release page that staff compare against during a
screenshare. No release workflow exists yet, and the repository has no tags or releases.

The people who download a release are server staff and players on Windows 10 22H2 or Windows 11. They need to
get the right file, check that it is the published one, and understand why Windows may warn about it. Releases
are not code-signed while there is a single maintainer (GOVERNANCE.md).

Release pages of comparable projects were reviewed on 2026-09-11 (uv, ripgrep, hayabusa, chainsaw, PowerToys,
KeePassXC, clash-verge-rev, Jan, txAdmin, ox_lib, qbx_core). The useful patterns: one file per platform with a
predictable name, a checksum for every file, build attestations with a short "how to verify" section, notes
grouped by kind of change, and — for security tools — a note about antivirus or SmartScreen warnings.

Considered and rejected:

- **An NSIS installer.** Tauri's NSIS installer installs into `%LOCALAPPDATA%` (or `Program Files`) by default
  (Tauri docs, *Windows Installer*). A tool that looks for traces on a PC should not leave its own install
  folder behind, and a second file type makes "which hash do I check" harder to explain.
- **tauri-action or cargo-dist.** tauri-action centres on installers and the updater; cargo-dist does not build
  Tauri apps. Neither checks the official-build marker, so the checks below would still be custom.
- **Release notes generated from pull requests.** The M0 work predates the pull-request rule, so generated
  notes for 0.1.0 would be nearly empty. `CHANGELOG.md` already follows Keep a Changelog.
- **One job that builds and publishes.** Build scripts of every crate and npm package would run in a job that
  holds a token able to change releases.

## Decision

### How a release is made

1. A pull request titled `chore(release): X.Y.Z` into `dev` renames `## [Unreleased]` in `CHANGELOG.md` to
   `## [X.Y.Z] - YYYY-MM-DD` and bumps the version wherever it is not already `X.Y.Z` (workspace `Cargo.toml`,
   `apps/desktop/src-tauri/tauri.conf.json`, `apps/desktop/package.json`).
2. A release pull request from `dev` to `main` is merged with a merge commit (CONVENTIONS.md, section 7).
3. A maintainer pushes the tag `vYYYY.MM.DD-X.Y.Z` on that merge commit on `main`, where `YYYY.MM.DD` is the date
   in the changelog heading (for example `v2026.09.06-0.1.0`).
4. `.github/workflows/release.yml` builds, checks and attests the files and creates a **draft** release.
5. A maintainer reviews the draft and publishes it. The workflow never publishes.

Immutable releases are enabled for the repository before the first tag: once published, the tag and the files
cannot be changed or deleted (the title and notes still can). A mistake in a published file is fixed with a new
version.

### Files on the release page

| File | Contents |
|---|---|
| `aeterna-rongroi-X.Y.Z-windows-x64.exe` | Desktop app (uses Microsoft WebView2). No installer. |
| `aeterna-rongroi-cli-X.Y.Z-windows-x64.exe` | Command-line app (no WebView2). |
| `SHA256SUMS` | SHA-256 of both executables, in `sha256sum` format. |
| `aeterna-rongroi-X.Y.Z-windows-x64.cdx.json` | CycloneDX SBOM of the desktop app's Rust crates (`cargo cyclonedx --describe binaries`). |
| `aeterna-rongroi-cli-X.Y.Z-windows-x64.cdx.json` | CycloneDX SBOM of the CLI's Rust crates. |
| `aeterna-rongroi-X.Y.Z-ui.cdx.json` | CycloneDX SBOM of the npm packages built into the desktop app (`pnpm sbom --prod`). |

GitHub adds source-code archives on its own.

### Tags and versions

- Tags are `vYYYY.MM.DD-X.Y.Z`, or `vYYYY.MM.DD-X.Y.Z-rc.N` for a rehearsal. The date is the release date and
  must equal the date in the changelog heading `## [X.Y.Z] - YYYY-MM-DD`. `X.Y.Z` is the SemVer version and must
  equal the version in all three manifests; the manifests carry only `X.Y.Z`, because Cargo versions must be
  SemVer.
- A release is marked **pre-release** while the major version is `0` and always for `-rc.N` tags.
- An `-rc.N` tag uses the `## [X.Y.Z]` section of the changelog, so the changelog pull request merges before a
  rehearsal.

### Workflow

Trigger: a pushed tag matching `v[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]-*`; `release-check` then enforces
the exact format. Concurrency group `release-<tag ref>`, never cancelled in progress, so runs for different tags
never cancel each other. Every action is pinned by commit SHA, like the other workflows.

**Job `build`** — `windows-latest`; permissions `contents: read` only.

1. Check out the tag with full history, without persisted credentials.
2. Install the pinned toolchain.
3. `cargo run --locked -p xtask -- release-check <tag>` (gates below).
4. `pnpm install --frozen-lockfile`. **No build caches** (`rust-cache`, `setup-node` cache): a cache written by
   another workflow must not reach an official build. Every cargo command in the job uses `--locked`.
5. Build with `RONGROI_OFFICIAL_BUILD=1` and `RONGROI_COMMIT=<tag commit SHA>` set for the whole step:
   `cargo build --release --locked -p rongroi-cli` and `pnpm -C apps/desktop tauri build --no-bundle -- --locked`.
6. Copy the two executables to their release names.
7. Run the CLI `scan --json` into `report.json`, then
   `cargo run --locked -p xtask -- release-verify <tag> --report report.json --cli <exe> --desktop <exe> --commit <sha> --sums SHA256SUMS`
   checks the built files (gates below) and, only if they pass, writes `SHA256SUMS`.
8. Write the three SBOM files.
9. `cargo run --locked -p xtask -- release-notes <tag> --report report.json --sums SHA256SUMS --commit <sha> --run-url <url> --out notes.md`
   writes the release notes.
10. Upload the executables, `SHA256SUMS`, the SBOM files and `notes.md` as one workflow artifact, kept for one
    day.

**Job `attest`** — `ubuntu-latest`; needs `build`; permissions `contents: read`, `id-token: write`,
`attestations: write`. It does not check out or compile anything, so no dependency build script runs in a job
that can sign.

1. Download the artifact.
2. `sha256sum -c --strict SHA256SUMS`.
3. `actions/attest`: one build-provenance attestation with `subject-checksums: SHA256SUMS`, and one SBOM
   attestation per SBOM file (`subject-path` + `sbom-path`); both desktop SBOMs — Rust and UI — are attested
   against the desktop executable.

**Job `publish`** — `ubuntu-latest`; needs `build` and `attest`; permission `contents: write` only. It does not
check out or compile anything.

1. Download the artifact.
2. `sha256sum -c --strict SHA256SUMS`, and every attached executable must be listed in `SHA256SUMS`.
3. `gh release create <tag> --draft --verify-tag --title "aeterna-rongroi X.Y.Z" --notes-file notes.md`, plus
   `--prerelease` when the rule above applies, with the executables, `SHA256SUMS` and the SBOM files attached.

### Gates

Each gate stops the workflow; no release is created.

| Gate | Fails when |
|---|---|
| `xtask release-check` | the tag is not `vYYYY.MM.DD-X.Y.Z` or `vYYYY.MM.DD-X.Y.Z-rc.N`, or its date is not a real calendar date; `X.Y.Z` differs from any of the three manifests; `CHANGELOG.md` has no `## [X.Y.Z] - YYYY-MM-DD` section, the section is empty, or its date differs from the tag's date; the tag commit is not on `main` |
| Build | `Cargo.lock` or `pnpm-lock.yaml` would change (every cargo command uses `--locked`, `pnpm install` uses `--frozen-lockfile`) |
| CLI check (`xtask release-verify`) | `aeterna-rongroi-cli … scan --json` reports `provenance.official` not `true`, a version other than `X.Y.Z`, a commit other than the tag commit, or an `exe_sha256` different from `Get-FileHash` of the file |
| Desktop app check (`xtask release-verify`) | the desktop executable does not contain the build marker `aeterna-rongroi build marker: official=1;commit=<tag commit SHA>;` (ADR 0007) — the text its report header is read from, so a desktop build that lacks either variable fails. The app cannot be started headless on the runner. This check must be shown to fail for desktop builds without `RONGROI_OFFICIAL_BUILD` and without `RONGROI_COMMIT` before the first real release. |
| Publish | `sha256sum -c --strict` fails, an attached executable is not listed in `SHA256SUMS`, or the tag does not exist on the remote |

The logic of `release-check` and `release-notes` is unit- and snapshot-tested, and those tests run in the
existing required `rust (ubuntu)` check. Before merge, each gate is shown to fail on purpose: a version mismatch,
a missing changelog section, and the CLI check against an unofficial build.

### Release notes

`cargo xtask release-notes` renders one template. English first, then a short Thai section for staff.

1. A one-line pre-alpha notice: results are evidence for a person to judge and never prove a PC is clean.
2. **Changes** — the `## [X.Y.Z]` changelog section, unchanged.
3. **Downloads** — supported Windows versions, "no installer", and a table of file, what it is and SHA-256.
4. **Rules bundle** — schema version, rule count and SHA-256, taken from the report header, which shows the
   same values when the program runs.
5. **Verify before you trust a result** — `Get-FileHash` against `SHA256SUMS`;
   `gh attestation verify <file> --repo aeterna/aeterna-rongroi --signer-workflow aeterna/aeterna-rongroi/.github/workflows/release.yml`;
   the program shows version `X.Y.Z` and no **UNOFFICIAL BUILD** banner. If any check fails, do not rely on the
   result.
6. **Windows SmartScreen** — the files are not code-signed yet (GOVERNANCE.md), so Windows may warn; check the
   hash before running.
7. **ภาษาไทย** — the same download, verification and SmartScreen points, and that a result is evidence for a
   person to judge, not a verdict. Wording follows README.th.md.
8. The commit and a link to the workflow run.

### Rehearsal before the first release

Before the first release: merge the changelog pull request, push `vYYYY.MM.DD-0.1.0-rc.1`, inspect the draft,
verify the downloaded files with
`gh attestation verify <file> --repo aeterna/aeterna-rongroi --signer-workflow aeterna/aeterna-rongroi/.github/workflows/release.yml`,
run both executables on a real Windows machine (hash matches, no UNOFFICIAL BUILD banner, desktop app starts
under a standard-user token), and show that the desktop-app gate fails for desktop builds without
`RONGROI_OFFICIAL_BUILD` and without `RONGROI_COMMIT` (build the desktop app for Windows without each variable
and run `release-verify` against it).
Then delete the draft and the rehearsal tag, and push `vYYYY.MM.DD-0.1.0` on the same commit.

## Consequences

- Official executables exist only as files of a GitHub release built by this workflow (and, during a
  rehearsal, in a draft that is deleted afterwards).
- Attestations are public: the Sigstore Public Good Instance keeps them in its transparency log, including
  those for `-rc.N` files.
- No installer means no Start-menu entry and no automatic updates; users download each version.
- README.md and README.th.md show `Get-FileHash` with the versioned file names.
- GOVERNANCE.md gains a "How to release" list that points here.
- Windows will keep warning about unsigned files until code signing through SignPath is in place.
- Results of the 0.1.0 rehearsal (2026-09-11, `v2026.09.11-0.1.0-rc.1`, then `v2026.09.11-0.1.0` on the same
  commit):
  - The SBOM step found the files `cargo cyclonedx` writes and `pnpm sbom` produced the UI SBOM on the Windows
    runner; all three SBOM attestations verify with `--predicate-type https://cyclonedx.org/bom`.
  - The desktop-app gate passes the official build and fails desktop builds made without
    `RONGROI_OFFICIAL_BUILD` and without `RONGROI_COMMIT` (built for `x86_64-pc-windows-msvc` with
    `cargo-xwin`, then checked with `release-verify`).
  - Builds are not byte-for-byte reproducible: the `-rc.1` and final executables from the same commit have
    different SHA-256 values, so the checks on a real Windows machine are repeated on the final files before
    publishing.
  - Re-running the `draft release` job creates a second draft for the same tag.
  - Checked on Windows 11 (build 26220) only. The exact SmartScreen wording is still unverified: files copied
    for the check carried no Mark of the Web, so SmartScreen did not prompt.
