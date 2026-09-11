# Testing

## Layers

| Layer | What it proves | Where | Runs on |
|---|---|---|---|
| L0 parsers (M2) | artifact formats decode correctly, including corrupt input | `crates/rongroi-parsers` | macOS · Linux · Windows |
| L1 collectors | every outcome — found, not found, unmeasured — against `FixtureHost` | `crates/rongroi-collectors/src/*.rs` | macOS · Linux · Windows |
| L2 rules | each rule's positive fixture is `found`, negative is `not_found` | `rules/**/tests/` via `cargo xtask check-rules` | macOS · Linux · Windows |
| L3 report | the full pipeline, as JSON snapshots; SS view never contains the fixture user name | `crates/rongroi-collectors/tests/`, `rongroi-core::view` | macOS · Linux · Windows |
| L4 UI | the GUI renders the L3 report JSON through mocked IPC; WebView hardening settings | `apps/desktop` (vitest) | macOS · Linux |
| L5 live | real Windows: no panic, non-admin gives `unmeasured(not_admin)`, scanned folders unchanged, no files left outside the run's temp folder | Windows CI job and a Windows test machine | Windows |
| Fuzz (M2) | parsers never panic on arbitrary bytes | `fuzz/` | Linux |

GitHub's Windows runners disable the SysMain and PCA services, so Prefetch and PCA collectors are expected to
be `unmeasured` there. Those collectors are verified on a real Windows 11 machine.

## Commands

```bash
cargo nextest run                       # L0, L1, L3 (or: cargo test)
cargo xtask check-rules                 # L2
cargo insta review                      # after an intended change to a report snapshot
pnpm -C apps/desktop test               # L4
cargo check --target x86_64-pc-windows-msvc -p rongroi-host-windows   # type-check Windows code from any OS
```

## Snapshots

Snapshots live next to the tests in `snapshots/`. The rules bundle hash is redacted so that adding a rule does
not rewrite every snapshot. Review every snapshot diff as carefully as code: it *is* the output users see.
CI runs `cargo insta test --unreferenced reject`, so a stale snapshot fails.

## Fixture hosts

`fixtures/hosts/<name>/host.yaml` describes a fake machine: platform, build, elevation, registry values and
keys that deny access. All of them are synthetic; see `fixtures/hosts/PROVENANCE.md`. Never copy files from
a real player's PC into this repository.

## Prove that a check can fail

A gate that has never failed has not been tested. When adding or changing a gate, break it on purpose once and
confirm it fails:

| Gate | Break it by |
|---|---|
| `cargo deny check` | adding `reqwest` to a crate |
| `check-rules` | duplicating a rule id, deleting a negative fixture, or allowing by `name:` |
| `check-locales` | adding a key to a translation that English does not have |
| `check-unicode` | inserting U+200B into any file |
| `reuse lint` | deleting a file's SPDX header |
| unofficial-build banner | building without `RONGROI_OFFICIAL_BUILD` |
