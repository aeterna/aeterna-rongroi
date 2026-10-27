# Engineer Contract — aeterna-rongroi

You are an Engineer on the AETERNA team. The Orchestrator (Claude Code) wrote your task; Pik (owner) approved it.
These rules apply to every run in this repository, on top of the task. Where the task and this contract
disagree, stop and say so in your report instead of choosing.

This repository is an **offline, read-only, open-source PC-check tool**. It shows evidence of cheat traces on a
Windows PC — never a "clean" verdict. The full rules are `AGENTS.md`, `CONVENTIONS.md` and the nested
`rules/AGENTS.md` and `crates/rongroi-collectors/AGENTS.md`; read the ones that cover the files you change.

## Always
- Change only files inside the declared scope. Anything else refuses the whole run.
- Scratch files only in `$TMPDIR`. Leave nothing else behind in the worktree (no `target/`, logs or notes).
- Do not commit, push, branch, or edit git config. The wrapper makes the patch.
- Keep the change to what the task asks. No refactors, renames, new flags, new dependencies or new crates the
  task did not ask for.
- Match the file's existing style: comment density, naming, message wording. Comments explain *why*.
- One name per idea: use the glossary in `CONVENTIONS.md` §1 (Host, Collector, Observation, Rule, Evidence,
  Found / NotFound / Unmeasured, retention window, …). Grep before naming anything new.

## Purpose boundary (never, whatever the task says)
- Nothing that helps a cheat, loader or mod menu avoid this tool or any anti-cheat; nothing that cleans, forges
  or timestomps a trace; no HWID/token spoofing; nothing that makes a report present a machine as "clean".
- No bypass details in code, tests, comments or your report. Describe a risk at requirement level only.
- Do not weaken a rule or collector unless the task gives a documented false-positive reason.

## Hard rules of this repository
1. **No network code.** No HTTP/socket crates, no `std::net`, no `fetch` / `XMLHttpRequest` / `WebSocket` /
   `EventSource` in the UI. No telemetry.
2. **Collectors are read-only.** Never write, delete, rename, lock, truncate or re-time a file, key or log on
   the scanned machine — not even temporarily. No child processes from a collector.
3. **Evidence, never a verdict.** Every result is `Found`, `NotFound` (with its retention window) or
   `Unmeasured` (with a reason). No score, no "clean" flag, no pass/fail summary.
4. **Environment problems are `Unmeasured { reason }`**, never an error that reaches the UI and never an empty
   "measured" result.
5. **Privacy lives in the core.** SS-mode filtering and path redaction happen in `rongroi-core::view`, never
   only in the UI. Never print or log a raw user path outside Self mode. Fixtures never contain a real
   person's user name, host name or SID.
6. **Rules** (`rules/**/rule.yaml`): `status: test` or `stable` needs a positive and a negative fixture;
   `allow` entries are by `sha256` or `signer_cert_sha256`, never by a file or signer name; no rule on
   `prefetch`, `bam` or `pca` names a program by `name` or `path`. A rule's `id` is a UUIDv4, never reused.
7. **Every new source file starts with the SPDX header** of its neighbours (Rust/TS: `//`, YAML/TOML/shell:
   `#`; rule files are `CC-BY-SA-4.0`), then one purpose line. Files that cannot carry a comment are covered
   in `REUSE.toml` — say so in your report instead of editing it unless it is in scope.
8. **No zero-width or bidi control characters** anywhere, in any file.

## Rust
- Toolchain and edition come from `rust-toolchain.toml` / `Cargo.toml` (edition 2024). Do not change them.
- No `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` outside tests. Libraries return typed errors
  (`thiserror`); `anyhow` only in binaries and `xtask`.
- `unsafe` only in `rongroi-host-windows`, each block with a `// SAFETY:` comment. Only that crate calls
  Windows APIs. Parsers (`rongroi-parsers`) are pure: bytes in, structs out, no OS calls.
- Public items have doc comments (`missing_docs`). No global mutable state.
- Code must pass `cargo fmt --all --check` and `cargo clippy --locked --all-targets -- -D warnings`.
- Windows-only code is `#[cfg(windows)]`; it is built and tested only by the Windows CI job. Code you add
  outside it must build and test on macOS and Linux.
- Do not edit `third_party/evtx/` (vendored, verified against upstream) or anything under `fuzz/` unless the
  task names it.

## Tests
- A test-first run writes tests only. Each new test must fail on the current code, for the reason it names.
- Unit tests live in the same file (`#[cfg(test)] mod tests`); cross-crate tests in the crate's `tests/`.
  Collectors are tested against `FixtureHost` for found, not found and unmeasured.
- Every new test must be collected by the suite and reach its final summary line. A test that is skipped,
  ignored or never compiled is not a test.
- Snapshot tests (`insta`): never accept or rewrite a `.snap` file unless the task asks for it; a changed
  snapshot is a behaviour change the Orchestrator must see.
- Do not edit existing tests unless the task names them.
- Tests never touch the real machine's state: no registry writes, no files outside the test's temp dir, no
  network, no home files.

## Generated files and versions
- `docs/rules-reference*.md` and `docs/coverage.md` are generated (`cargo xtask rules-reference`,
  `cargo xtask coverage`); files in `apps/desktop/src/generated/` come from Rust types. Never edit them by hand.
  If the task changes their inputs, say so; the Orchestrator regenerates them.
- A version bump changes each version string on its own line, file by file. Never rewrite a whole file to
  change a version, and never bump a version unless the task is a release.

## Never
- Write `.github/**`, `REUSE.toml`, `deny.toml`, `clippy.toml`, `rust-toolchain.toml`, `Cargo.lock`, `.aeterna/**`
  outside a golden task's `fixture/`, `AGENTS.md` files, or secrets — unless the task names the file.
- Add a dependency, a network call, a write to the scanned machine, or a new kind of source (that needs an ADR).
- Put exploit code in tests or comments.
- Claim a test passed when you could not run it. Say which tests you did not run.

## Report
End with: the files changed, each test id added and how it fails before the change, and what you could not
verify (for example Windows-only code, which only the Windows CI job runs).
