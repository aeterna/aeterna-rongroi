# Contributing

Thanks for helping. Please read [AGENTS.md](AGENTS.md) (purpose boundary) and
[CONVENTIONS.md](CONVENTIONS.md) (how things should look) first.

## Setup

- Rust via [rustup](https://rustup.rs) — the toolchain is pinned in `rust-toolchain.toml`.
- Node 22+ and [pnpm](https://pnpm.io) for the desktop app.
- Optional quality tools: `cargo install --locked cargo-nextest cargo-deny cargo-insta typos-cli`,
  and [uv](https://docs.astral.sh/uv/) for `uvx --with chardet reuse lint`. REUSE needs an encoding
  detector; with `charset-normalizer` it misreads UTF-8 files whose first 2 KiB end inside a Thai character.

Most of the code builds and tests on macOS and Linux: collectors are tested against fake `C:\` folders.
Anything that reads a real Windows machine is exercised in the Windows CI job.

## Three ways to contribute

| You want to add | Run | Then |
|---|---|---|
| A detection rule | `cargo xtask new-rule <collector> <category>/<slug>` | Fill in `rule.yaml`, a positive and a negative fixture, and optional translations |
| A language | `cargo xtask new-locale <bcp47>` (e.g. `vi`, `pt-BR`) | Translate the generated files; missing keys fall back to English |
| A collector | `cargo xtask new-collector <id>` (from M1) | Implement the `Collector` trait; write an ADR if it reads a new kind of source |

Each one is a single pull request. Branch from `dev` and open the pull request against `dev`, the default
branch; `main` only receives release pull requests (CONVENTIONS.md, section 7).

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo nextest run
cargo xtask check-rules && cargo xtask check-locales && cargo xtask check-unicode
uvx --with chardet reuse lint
pnpm -C apps/desktop typecheck && pnpm -C apps/desktop lint && pnpm -C apps/desktop test
```

The PR title must be a Conventional Commit (`rules(posture): add …`). The template asks whether the change
adds network access (it must not) and whether it weakens a detection (explain why).

## False positives

If a rule flags legitimate software, open a **false-positive** issue with the tool version, the executable
hash, the rule id and an SS-mode export. Fixes should allow the software by `sha256` or `signer`, never by
file name.

## What we close

- Issues or PRs that publish techniques for evading this or any other anti-cheat. Report bypasses
  privately instead — see [SECURITY.md](SECURITY.md).
- Changes that add network access, telemetry, or writes to the scanned machine.

## Licensing of contributions

By contributing you agree that your contribution is licensed under the license of the files you change:
GPL-3.0-or-later for code, CC-BY-SA-4.0 for `rules/`.
