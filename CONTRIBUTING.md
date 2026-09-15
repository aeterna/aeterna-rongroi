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

### Running a fuzz target

The pinned toolchain does not provide this and neither does `cargo` by itself: `cargo-fuzz` drives libFuzzer
through `-Z sanitizer`, which is nightly-only. You need both of these once:

```bash
rustup toolchain install nightly --profile minimal --component rust-src
cargo +nightly install --locked cargo-fuzz
```

Then, from the repository root:

```bash
cargo +nightly fuzz build                     # all six targets
cargo +nightly fuzz run fuzz_bam fuzz/corpus/fuzz_bam fixtures/parsers/bam -- -max_total_time=60
```

The targets are `fuzz_bam`, `fuzz_pca_app_launch`, `fuzz_pca_general`, `fuzz_filetime`, `fuzz_prefetch`
(which seeds from `fixtures/prefetch/`) and `fuzz_evtx` (from `fixtures/evtx/`). The seed corpus is the fixture directory the L0 tests read, and it
comes **second** because libFuzzer writes what it finds to the first directory — the fixtures are an input,
never an output. A crashing input is saved under
`fuzz/artifacts/`; reproduce it with `cargo +nightly fuzz run <target> <that file>`.

`fuzz/` is its own workspace, excluded from the root one, so none of the commands above changes what
`cargo build`, `cargo clippy`, `cargo nextest run` or `cargo deny check` do (ADR 0016). CI runs each target
for 30 seconds on every pull request, which is a smoke gate; a real campaign is a local run of minutes or
hours when you change a parser.

Being a separate workspace has one consequence that is easy to miss: a `[patch.crates-io]` entry in the
root `Cargo.toml` does **not** reach `fuzz/`. `fuzz/Cargo.toml` repeats the `evtx` patch for that reason.
A patch added in one place and not the other would leave the fuzz targets exercising a different
dependency from the one the product ships — a green gate over code nobody runs.

### Re-syncing the vendored `evtx`

`third_party/evtx/` is the `evtx` crate's source with four patches applied: an allocation sized from a
record's substitution count, bounded against the bytes actually remaining; a `u16` multiplication
on a name length that overflowed before being widened; a walk of the chunk string table that had no
guard against a chain closed into a cycle, so it never returned; and a `SYSTEMTIME`'s milliseconds
multiplied in `u32`, which overflowed above 4294. The reasoning, the measured
allocation, and a command that proves the rest of the directory is byte-identical to the published crate
are in `third_party/evtx/PROVENANCE.md`; the decision is ADR 0018.

It is meant to be temporary. When an upstream release carries the fix, delete the directory, delete both
`[patch.crates-io]` stanzas, and bump the registry dependency. Until then, do not reformat it, do not
apply this project's lints to it, and do not fix its spelling — `Cargo.toml`'s `exclude`, `_typos.toml`
and `REUSE.toml` all hold it apart on purpose, so that the next person can verify it against upstream
with a single `diff`.

## Three ways to contribute

| You want to add | Run | Then |
|---|---|---|
| A detection rule | `cargo xtask new-rule <collector> <category>/<slug>` | Fill in `rule.yaml`, a positive and a negative fixture, and optional translations, then run `cargo xtask rules-reference` and commit the pages it rewrites |
| A language | `cargo xtask new-locale <bcp47>` (e.g. `vi`, `pt-BR`) | Translate the generated files; missing keys fall back to English |
| A collector | No scaffold — start from `crates/rongroi-collectors/src/process.rs` or `fivem_dir.rs` | Implement the `Collector` trait; write an ADR if it reads a new kind of source |

Each one is a single pull request. Branch from `dev` and open the pull request against `dev`, the default
branch; `main` only receives release pull requests (CONVENTIONS.md, section 7).

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo nextest run
cargo xtask check-rules && cargo xtask check-baseline
cargo xtask rules-reference --check
cargo xtask check-locales && cargo xtask check-unicode
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
