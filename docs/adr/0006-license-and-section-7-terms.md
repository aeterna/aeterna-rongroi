# ADR 0006 — GPL-3.0-or-later with section 7 terms; CC-BY-SA-4.0 for rules

- Status: accepted
- Date: 2026-09-11

## Context

Free anti-cheat code in this market is often repackaged and sold closed. Research also found that most
existing PC-check repositories have no licence at all. The owner wants to warn people who would clone the
code to build evasion tools.

A licence cannot forbid a use. GPL-3.0 section 7 lists the additional terms it allows and says any other
restriction is a "further restriction" that the recipient "may remove" (text read from the GitHub licenses
API on 2026-09-11).

## Decision

- Code: **GPL-3.0-or-later**. Rules, rule translations and rule fixtures: **CC-BY-SA-4.0**.
- `NOTICE` adds the section 7 terms that are allowed:
  - (b) preserve notices and author attributions
  - (c) mark modified versions as different — they must not present themselves as official builds
  - (e) no trademark rights to the names "aeterna-rongroi" and "rongroi"
- `NOTICE` says plainly that these terms do not restrict use, and states the intended use separately as
  information rather than as a licence term.
- Per-file licensing follows REUSE (`reuse lint` in CI).

## Consequences

- A fork can remove detections, but it cannot pass itself off as the tool staff trust.
- The project stays OSI-compatible, which the SignPath Foundation requires for free code signing.
