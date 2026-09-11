# Conventions

How code, rules and docs look in this repository. [CONTRIBUTING.md](CONTRIBUTING.md) covers *how to
contribute*; this file covers *what the result should look like*. Each rule names what enforces it — when
nothing enforces it, reviewers do.

## 1. Glossary — one name per idea

Use exactly these words in code, UI text keys, docs, issues and PRs. Before naming something new, grep the
repository; if the idea already has a name, use it. A new term is a PR to this table.

| Term | Meaning | In code |
|---|---|---|
| **Host** | Where artifacts are read from. `LiveHost` = the real Windows machine; `FixtureHost` = a fake `C:\` folder used by tests | `rongroi_host::Host` |
| **Collector** | Reads one kind of artifact from a Host and produces Observations | `rongroi_collectors::Collector` |
| **Observation** | One typed fact a Collector saw (e.g. "Secure Boot is off") | `rongroi_core::model::Observation` |
| **Rule** | Data file that says which Observations are worth showing and how strong they are | `rules/**/rule.yaml` |
| **Evidence** | The result of one Rule: `Found`, `NotFound` or `Unmeasured` | `rongroi_core::model::Evidence` |
| **Found** | The Rule matched; the matching Observations are attached | `EvidenceState::Found` |
| **NotFound** | The Collector ran and nothing matched; carries the **retention window** | `EvidenceState::NotFound` |
| **Unmeasured** | The Collector could not look; carries a **reason** | `EvidenceState::Unmeasured` |
| **strength** | What the evidence can show: `execution`, `presence`, `tamper`, `posture`, `context` | `Strength` |
| **retention window** | How far back a source can see, in words shown to the user | `Rule::retention` |
| **Self mode / SS mode** | Full local view / screenshare view with consent, matches only, redacted paths | `Mode::SelfCheck`, `Mode::Ss` |
| **rules bundle** | All rules compiled and embedded in the executable, identified by its SHA-256 | `rongroi_core::bundle` |
| **official build** | A binary built by the upstream release workflow; anything else is **unofficial** | `rongroi_core::provenance` |

Never introduce a score, a "clean" flag, a pass/fail total, or synonyms such as "detection result",
"hit", "finding" for Evidence.

## 2. Rust

| Convention | Enforced by |
|---|---|
| Edition 2024, toolchain pinned in `rust-toolchain.toml` | cargo |
| Libraries return typed errors with `thiserror`; `anyhow` only in binaries and `xtask` | review |
| No `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` outside tests | clippy workspace lints |
| A machine problem (no admin rights, missing log, unsupported OS) is `Unmeasured { reason }`, never an `Err` that reaches the UI | tests per collector |
| `unsafe` only in `rongroi-host-windows`, each block with a `// SAFETY:` comment | workspace `unsafe_code = "deny"`, allowed locally only there · clippy `undocumented_unsafe_blocks` |
| Public items have doc comments | `missing_docs` lint |
| No global mutable state; no `std::net` | clippy `disallowed-types` · cargo-deny |
| Timestamps are UTC, RFC 3339 in reports | review · snapshot tests |
| Formatting | `rustfmt.toml` · `cargo fmt --check` |

## 3. Layout

- One collector per file: `crates/rongroi-collectors/src/<collector_id>.rs`.
- Unit tests live in the same file (`#[cfg(test)] mod tests`); cross-crate tests live in `tests/`.
- Parsers (`rongroi-parsers`, from M2) are pure: bytes in, structs out, no OS calls — so they can be
  fuzzed and tested on any platform.
- Only `rongroi-host-windows` calls Windows APIs.

## 4. Privacy in code

- Never print or log a raw user path outside Self mode. Redaction goes through `rongroi_core::view`.
- Logging (when added) goes to local stderr only. No telemetry, no crash upload, no network.
- Test fixtures never contain a real person's user name, host name or SID (`cargo xtask scrub-check`, from M1).

## 5. TypeScript / React (`apps/desktop`)

| Convention | Enforced by |
|---|---|
| Function components, strict TypeScript | `tsc --noEmit` |
| No user-visible literal strings; everything goes through i18n keys `namespace.section.item` in `snake_case` | review · `cargo xtask check-locales` |
| Files in `src/generated/` are produced from Rust types and never edited by hand | review |
| No `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource` | ESLint `no-restricted-globals` · CSP |

## 6. Rules

| Convention | Enforced by |
|---|---|
| Path `rules/<collector>/<category>/<slug>/rule.yaml`, `slug` in kebab-case | `cargo xtask check-rules` |
| `id` is a UUIDv4 and is never reused, even after deletion | `check-rules` |
| English `title`, `description`, `falsepositives` live in the rule; translations in `rules/i18n/<lang>.yaml` | `check-rules` · `check-locales` |
| `status: test` or `stable` requires at least one positive and one negative fixture in `tests/` | `check-rules` |
| `allow` entries identify software by `sha256` or `signer`, never by file name | `check-rules` |
| `falsepositives` is never empty — write what legitimately produces this evidence | `check-rules` |

## 7. Git

- Conventional Commits for PR titles: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `rules`, `i18n`, `ci`.
- Scope is the crate or area: `feat(collectors): …`, `rules(posture): …`, `i18n(th): …`.
- Branch names: `<type>/<short-description>`.
- One concern per PR; squash-merged.

## 8. Docs and comments

- Source docs are written in English. `README` and the screenshare guide also exist in Thai.
- Comments explain *why*, not *what*.
- Changing the architecture, the rule format or adding a new kind of source needs an ADR in `docs/adr/`.

## 9. File headers

Every source file starts with an SPDX header and one purpose line:

```rust
// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
```

Rule files use `#` comments and `CC-BY-SA-4.0`. Files that cannot carry comments are covered by
`REUSE.toml`. Enforced by `reuse lint`. Zero-width and bidi control characters are forbidden everywhere
(`cargo xtask check-unicode`).

## 10. Versions

- The application follows SemVer.
- The rules bundle and the report carry `schema_version`. A breaking change to the report format is a major
  version.
