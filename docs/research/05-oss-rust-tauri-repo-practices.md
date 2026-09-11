# 05 — Rust and Tauri repository practices (2026-09-11)

## Workspace layout

| Project | Layout | Notes |
|---|---|---|
| [astral-sh/uv](https://github.com/astral-sh/uv) | `crates/*`, `uv-*` prefix | workspace dependencies and lints; nextest profiles; Windows-only crate `uv-windows` with a Windows CI job |
| [astral-sh/ruff](https://github.com/astral-sh/ruff) | `crates/*`, `ruff_*` | pedantic clippy with a curated allow list; thousands of insta snapshots |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) | root package + `crates/` | integration tests in `tests/` |
| [bevyengine/bevy](https://github.com/bevyengine/bevy) | `crates/bevy_*`, `tools/ci` | `unsafe_code = "deny"`, CI tasks as a Rust program |
| [helix-editor/helix](https://github.com/helix-editor/helix) | flat `helix-*`, `xtask/` | `cargo xtask` alias |

Common ground: one naming prefix, dependencies and lints declared once in the root, crates opting in with
`[lints] workspace = true`, and a task runner (xtask).

## Tauri 2 applications

Checked in `Cargo.lock`: spacedrive, gitbutler, clash-verge-rev and jan use Tauri 2; pot-desktop is still
Tauri 1 and archived.

| App | Useful pattern | Caution |
|---|---|---|
| [gitbutler](https://github.com/gitbutlerapp/gitbutler) | thin `src-tauri`, logic in crates; explicitly declines a CLA | not OSI-licensed |
| [clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev) | i18next with `locales/<lang>/<ns>.json` and generated key types | `"csp": null` and HTTP capabilities — an anti-example for us |
| [jan](https://github.com/janhq/jan) | updater behind an optional Cargo feature | CSP allows any HTTPS |
| [spacedrive](https://github.com/spacedriveapp/spacedrive) | the tightest CSP of the four | |

**None of the four is network-free**; all bundle the updater plugin. Tauri core only depends on an HTTP client
for mobile targets, so banning HTTP crates works for desktop builds.

## Quality gates seen in practice

| Gate | Tool |
|---|---|
| format / lint | `cargo fmt --check`, `cargo clippy -D warnings` on Linux and Windows |
| dependency policy | `cargo deny` — crate bans apply to transitive dependencies too ([docs](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html)) |
| tests | cargo-nextest, insta with `--unreferenced reject` |
| hygiene | typos, actionlint, zizmor, actions pinned by commit SHA |
| PR titles | `amannn/action-semantic-pull-request` |
| releases | cargo-dist or release-please; GitHub artifact attestations |

## Release integrity

- GitHub artifact attestations: `actions/attest-build-provenance`, verified with `gh attestation verify`
  ([docs](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)).
- **SignPath Foundation** signs OSI-licensed projects for free, but requires MFA, a prior release, a public
  code-signing policy and **separate author, reviewer and approver roles** ([terms](https://signpath.org/terms)).
  Used by starship, sniffnet and Seelen-UI among others.
- Since August 2024, EV certificates no longer give instant SmartScreen reputation
  ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)).
- Bit-for-bit reproducible MSVC builds are not currently achievable
  ([rust#88982](https://github.com/rust-lang/rust/issues/88982)); promise verifiable provenance instead.
- Tauri's default WebView2 install mode downloads a bootstrapper; `offlineInstaller` and `fixedVersion` do not
  ([docs](https://v2.tauri.app/distribute/windows-installer/)).

## Internationalisation

i18next + react-i18next is the most widely used option among the Tauri apps studied. A language is one folder
plus registration; CI checks key parity. Hosted Weblate is free for open-source projects once contributors
arrive ([hosting](https://weblate.org/en/hosting/)).

## What this meant for aeterna-rongroi

- `crates/rongroi-*`, workspace lints, xtask, nextest, insta.
- `cargo deny` bans network crates and Tauri network plugins; strict CSP; no updater.
- Squash merges with Conventional Commit titles; no CLA.
- Releases unsigned but attested until a second maintainer allows SignPath's role separation.
