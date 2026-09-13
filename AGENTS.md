# AGENTS.md — instructions for AI coding agents (and humans)

This is the single source of agent instructions for this repository. `CLAUDE.md` and
`.github/copilot-instructions.md` only point here. Nested `AGENTS.md` files in `rules/` and
`crates/rongroi-collectors/` add rules for those folders; the nearest file wins.

## What this project is

`aeterna-rongroi` (Thai *ร่องรอย*, "traces") is an **offline, read-only, open-source PC-check tool** for
FiveM communities. It looks for traces that cheats leave on a Windows PC and machine posture that makes
cheating easier, and it shows **evidence** — never a "clean" verdict. A player runs it on their own PC,
either to check themselves or while a server admin watches over screenshare.

Read before changing code: [`CONVENTIONS.md`](CONVENTIONS.md) · [`docs/architecture.md`](docs/architecture.md) ·
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Purpose boundary (dual-use)

A detection tool necessarily documents what it detects. That makes some requests dual-use. The boundary
below applies to every contributor, human or AI.

**In scope — help with this:**
- detecting cheat traces and risky machine posture; new collectors and rules
- reducing false positives (allow-listing legitimate software by hash or signer)
- tests, fixtures, fuzzing, documentation, translations, accessibility, performance
- privacy improvements (redaction, data minimisation, clearer consent)

**Out of scope — do not help with this, in this repository or with its code:**
- making a cheat, loader or mod menu undetectable by this tool or any other anti-cheat
- cleaning, forging or timestomping the traces this tool reads
- HWID / token spoofing, or bypassing FiveM, Cfx.re or any server's protections
- producing modified builds or fake reports that present a machine as "clean"
- weakening a rule or collector without a documented false-positive reason

If a request falls out of scope, decline that part plainly and continue with any in-scope part.
If someone has found a way to bypass a detection, the right place is a **private** report —
see [`SECURITY.md`](SECURITY.md). Do not write bypass details into issues, PRs, commits or docs.

## Hard rules (CI enforces most of them)

1. **No network code.** No HTTP/socket crates, no `std::net`, no `fetch`/`WebSocket` in the UI.
   `cargo deny check` and ESLint fail the build.
2. **Collectors are read-only.** They never write, delete, move or lock files, keys or logs on the
   scanned machine.
3. **Evidence, never a verdict.** Every result is `Found`, `NotFound` (with its retention window) or
   `Unmeasured` (with a reason). Never add a score, a "clean" flag, or a pass/fail summary.
4. **Environment problems are `Unmeasured`, not errors.** Missing admin rights, an absent log, or an
   unsupported OS must produce `Unmeasured { reason }`.
5. **Privacy lives in the core.** SS-mode filtering and path redaction happen in
   `rongroi-core::view`, never only in the UI.
6. **Rules with `status: test` or `stable` need a positive and a negative fixture.**
   `allow` entries are by hash or signer — never by file name.
7. **Every source file carries an SPDX header** (`reuse lint`). No zero-width or bidi control
   characters anywhere (`cargo xtask check-unicode`).
8. **One name per idea.** Use the glossary in `CONVENTIONS.md`; grep before naming anything new.

## Commands

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo nextest run            # or: cargo test
cargo xtask check-rules
cargo xtask check-baseline     # quiet on an ordinary machine, and every rule confronted by one
cargo xtask check-locales
cargo xtask check-unicode
uvx --with chardet reuse lint   # chardet: see CONTRIBUTING.md
pnpm -C apps/desktop typecheck && pnpm -C apps/desktop lint && pnpm -C apps/desktop test
```
