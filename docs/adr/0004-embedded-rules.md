# ADR 0004 — Rules are embedded in the executable only

- Status: accepted
- Date: 2026-09-11

## Context

Rules are open data files. They could be loaded from disk so that new rules ship without a new release, but
during a screenshare a player could then load an empty or edited rule set and show a harmless report.

## Decision

- `rongroi-core/build.rs` compiles every rule and rule translation into the binary.
- Shipped binaries contain no code path that loads rules from a file. Loading from the source tree exists only
  behind the `source-tree` feature, which only `xtask` enables.
- The report header shows the bundle's SHA-256, and the executable's own hash is published in `SHA256SUMS`,
  so one hash identifies both the program and its rules.
- One `rule.yaml` per folder, co-located with its fixtures: `rules/<collector>/<category>/<slug>/`.
- Files are collected in sorted order with line endings normalised to LF, so the bundle hash is identical on
  every platform.

## Consequences

- A new or fixed rule requires a new release. CI makes releases cheap.
- A rule PR touches one folder (plus an optional translation line), which keeps review simple.
