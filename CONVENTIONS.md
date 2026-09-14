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
| **Unmeasured** | The Collector could not look; carries a **reason** and whether the Rule **expected** it | `EvidenceState::Unmeasured` |
| **expected unmeasured** | An Unmeasured result whose reason the Rule named in `unmeasured_when`; SS mode counts it. One whose reason it did not name is **unexpected** and SS mode lists it (ADR 0027) | `EvidenceState::Unmeasured::expected` |
| **source absent** / **source empty** | Opposite Unmeasured reasons: the place the artifact is kept is not on this PC, versus it is there and holds nothing. One word until ADR 0030 | `UnmeasuredReason::SourceAbsent`, `::SourceEmpty` |
| **scope statement** | An Unmeasured reason that is one fact about the **scan** — `not_admin`, `not_attempted` — stated once above the evidence and never as a row per Rule | `UnmeasuredReason::is_scope_statement`, `view::ScopeNotes` |
| **scope statement** | A fact about the **scan** rather than about the machine, said once above the evidence in both modes. Today: how many Rules missing administrator rights left unanswered | `rongroi_core::view::ScopeNotes` |
| **unmatched observation** | Something a Collector saw that no Rule matched; shown in Self mode only, counted in SS mode | `rongroi_core::model::UnmatchedGroup` |
| **strength** | What the evidence can show: `execution`, `presence`, `tamper`, `posture`, `context` | `Strength` |
| **retention window** | How far back a source can see, in words shown to the user | `Rule::retention` |
| **cased** | A `match` field a Rule compares byte for byte; every other string folds ASCII case (ADR 0025) | `Rule::cased` |
| **operator** | How one `match` entry compares its value, written `field\|operator`: `gt`, `gte`, `lt`, `lte`, `startswith`, `endswith`, `contains`, `exists`. A key with no `\|` compares for equality, and a list value means **or** (ADR 0029) | `rongroi_core::rules::Operator` |
| **field kind** | What a Collector declares one of its observation fields holds — text, a number, a boolean or a timestamp — so that `check-rules` can refuse an operator the field cannot take | `rongroi_collectors::FieldKind` |
| **boot time** | Report-header context: when the running Windows kernel started counting — the scan's clock minus `GetTickCount64` — or why there is no value. Never evidence and never read by a rule. Not "when the PC was last turned on": a "Shut down" with Fast Startup, sleep and hibernation do not reset it (ADR 0039) | `rongroi_core::model::BootTime`, `rongroi_host::BootTimeSource`, header field `boot_time` |
| **Self mode / SS mode** | Full local view / screenshare view with consent, matches only, redacted paths | `Mode::SelfCheck`, `Mode::Ss` |
| **rules bundle** | All rules compiled and embedded in the executable, identified by its SHA-256 | `rongroi_core::bundle` |
| **listed counts** | How many pieces of the evidence a view lists are in each state — found, not found, unmeasured. Three numbers, never added into one: not a pass/fail total (ADR 0045) | `rongroi_core::view::ListedCounts` |
| **rule files** | Where a Rule's `rule.yaml`, its fixtures folder and its Collector's file are in the repository, with its references | `rongroi_core::rules::RuleFiles` |
| **code link** | Where to read this binary's code: the commit of an official build, the repository otherwise | `Provenance::code_url`, `REPOSITORY_URL` |
| **official build** | A binary built by the upstream release workflow; anything else is **unofficial** | `rongroi_core::provenance` |
| **build marker** | The text `aeterna-rongroi build marker: official=<flag>;commit=<sha>;` embedded in every binary; the report's provenance is read from it | `rongroi_core::provenance::build_marker` |
| **path** | Observation field: the full path of the file the observation is about, as it was read. Redacted to `%USERPROFILE%` in SS mode | observation field `path` |
| **sha256** | Observation field: SHA-256 of that file, 64 lowercase hex characters. The only file hash, and one of the two things `allow` may compare | observation field `sha256` |
| **signature** | Observation field: what Windows says about the Authenticode signature **embedded** in that file — `valid`, `no_embedded_signature`, `invalid` or `unverifiable_offline` — checked without the network. Never "unsigned": a catalog signature is not looked at (ADR 0035) | `rongroi_host::SignatureCheck`, observation field `signature` |
| **discriminator** | The observation field a collector that reads several places uses to say which one an observation is about — today only `fivem_dir`'s `location`. A place that could not be read is a gap for that place's observations only, and a baseline observation that differs from a rule in the discriminator alone does not confront it (ADR 0044, ADR 0033) | `rongroi_collectors::Collector::discriminator`, `rongroi_core::model::DiscriminatorGaps` |
| **read_only** | Observation field: whether the file the observation is about carries the read-only attribute — the one attribute bit this program reads (ADR 0037) | `rongroi_host::FilesystemSource::is_read_only`, observation field `read_only` |
| **configured_path** / **at_configured_path** | Observation fields of an `evtx` log account: the file the Windows Event Log service states it writes that log's channel to, as the service spells it, and whether that is the file that was read (ADR 0042) | `rongroi_host::EventLogConfigSource`, observation fields `configured_path`, `at_configured_path` |
| **signer** / **signer_cert_sha256** | Observation fields of a `valid` signature: the signing certificate's display name, for the reader, and the SHA-256 of the certificate, the other thing `allow` may compare. A name is never compared: stolen certificates carry the real publisher's (ADR 0035) | observation fields `signer`, `signer_cert_sha256` |

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
- Test fixtures never contain a real person's user name, host name or SID. Nothing checks this
  automatically: `cargo xtask scrub-check` has been named here since M1 and was never written, so what
  holds the rule up is this sentence and the person who reviews a new fixture, together with the
  provenance document every vendored fixture has to come with.

> **An open gap, as of 2026-09-12.** An automated scrub check does not exist and no ADR has decided to
> write one. The provenance document of each vendored fixture set records the same absence
> (`fixtures/evtx/PROVENANCE.md`, `fixtures/prefetch/PROVENANCE.md`), and ADR 0016 counts
> `cargo xtask scrub-check` among the promises this repository has made with no code behind them.
> Review by hand is what there is, and it has already failed once: a vendored Event Log fixture was
> committed carrying a real machine SID that a byte scan had missed, and was removed again
> (`CHANGELOG.md`). A vendored artifact cannot be cleaned in place either: its records are checksummed
> inside their container, so editing a string breaks the container. The choice is to vendor a file
> whole or not at all.

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
| `collector` is a collector in this build, and every `match` field name one it declares it can emit | `check-rules` |
| English `title`, `description`, `falsepositives` live in the rule; translations in `rules/i18n/<lang>.yaml` | `check-rules` · `check-locales` |
| `status: test` or `stable` requires at least one positive and one negative fixture in `tests/` | `check-rules` |
| `match` strings compare without regard to ASCII case; `cased` names the fields compared exactly | `check-rules` · engine tests |
| A `match` key is a field name, optionally `\|` and one of the eight operators; a list value means **or** | `check-rules` · engine tests |
| An operator the field's declared kind cannot take, an empty list, and a `cased` entry `match` compares no text of are rejected | `check-rules` |
| `allow` entries identify software by `sha256` or `signer_cert_sha256` — exactly one, 64 hex characters — never by a file's or a signer's name (ADR 0035) | `check-rules` |
| No rule on `prefetch`, `bam` or `pca` identifies a program by `name` or `path`: nothing they emit identifies software, so such a rule can neither `allow` a legitimate program nor survive a rename (ADR 0034). `check-rules` and `check-baseline` both accept one today | review |
| `docs/rules-reference.md` and `docs/rules-reference.th.md` are generated from the bundle and never edited by hand; a change to a rule, `rules/i18n/` or a report label reruns `cargo xtask rules-reference` in the same pull request | `cargo xtask rules-reference --check` |
| `falsepositives` is never empty — write what legitimately produces this evidence; it is shown to the reader beside every `found` row | `check-rules` |
| `unmeasured_when` names only reasons the rule's collector can report, each once, and never `partial`, `budget_spent` or `read_failed` — a view lists those whatever a rule declares, so naming one is a failure rather than a line that changes nothing (ADR 0030, ADR 0032) | `check-rules` |
| The rule is quiet on every `fixtures/hosts/baseline-*` host, or a `rules/known-fps.csv` row accepts the match with a reason; an unused row fails too (ADR 0017) | `cargo xtask check-baseline` |
| The rule is **confronted** by some baseline observation — one carrying every field its `match` names and one unsatisfied condition away from firing, that condition not being the collector's discriminator — or a `rules/unconfronted.csv` row gives a reason and a `resolved_when`; a row for a rule that is confronted fails too. Quiet on a machine that was never put the question is not a measurement (ADR 0033, ADR 0044) | `check-baseline` |

## 7. Git

- Conventional Commits for PR titles: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `rules`, `i18n`, `ci`.
- Scope is the crate or area: `feat(collectors): …`, `rules(posture): …`, `i18n(th): …`.
- Permanent branches: `main` holds released code and carries the release tags; `dev` is where work is
  integrated and is the default branch.
- Work branches are named `<type>/<short-description>`, start from `dev`, and return to `dev` through a pull
  request that is squash-merged. One concern per PR.
- `dev` reaches `main` only through a release pull request from `dev` to `main`, merged with a merge commit
  (GOVERNANCE.md, "How to release").
- Repository rulesets enforce this: `main` and `dev` accept changes only through pull requests with the
  required checks green, and cannot be deleted or force-pushed.

## 8. Docs and comments

- Source docs are written in English. `README` and the screenshare guide (`docs/screenshare-guide.md`)
  also exist in Thai, and a change to either language's copy changes the other in the same pull request.
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
