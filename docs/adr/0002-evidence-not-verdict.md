# ADR 0002 — Evidence, never a verdict

- Status: accepted
- Date: 2026-09-11

## Context

The tool runs offline on the player's own PC. The player controls the machine and the screen, cheats can
run from hardware or a second PC, and many traces age out after days. A "clean" result would claim more than
the tool can know, and a score invites people to treat a number as proof.

## Decision

- Every rule yields exactly one of `found`, `not_found` (with the source's retention window) or `unmeasured`
  (with a reason).
- A field that a collector could not read makes dependent rules `unmeasured`, never `not_found`.
- Evidence carries a `strength` (`execution`, `presence`, `tamper`, `posture`, `context`) instead of a level.
- There is no score, no pass/fail total and no "clean" state anywhere: model, UI, CLI, docs.
- Every output ends with the statement that the report cannot prove a PC is clean.

## Consequences

- Reviewers must read evidence rather than a number. That is the intent.
- Contributions that add a score or a summary verdict are rejected (AGENTS.md hard rule 3).
