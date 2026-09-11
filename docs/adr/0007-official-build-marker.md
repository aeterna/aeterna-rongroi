# ADR 0007 — Official-build marker

- Status: accepted
- Date: 2026-09-11

## Context

During a screenshare, staff need a quick way to tell the released program from a rebuilt or modified one.
Releases are not code-signed yet (GOVERNANCE.md).

## Decision

- `rongroi-core`'s build script writes `RONGROI_OFFICIAL_BUILD` and `RONGROI_COMMIT` into one text, the build
  marker `aeterna-rongroi build marker: official=<flag>;commit=<sha>;`, which is embedded in every binary.
  `Provenance::current()` reads the flag and the commit back from that text, so the marker in the file and the
  report header cannot disagree. Only the exact value `1` marks a build as official. Only the release workflow
  sets it. The release workflow checks the desktop app, which cannot run headless, by searching it for the
  marker (ADR 0008).
- Every other build shows **UNOFFICIAL BUILD** in the CLI header, the GUI and the report. The token stays in
  English in every language so it is recognisable and searchable.
- The report also carries the executable's SHA-256 and, for releases, the commit.
- The screenshare guide tells staff to stop if the banner appears or if `Get-FileHash` does not match
  `SHA256SUMS`.

## Consequences

- Casual rebuilds and honest forks are identified immediately.
- A malicious fork can remove the banner; the hash comparison against the release page still exposes it.
  This is a visible marker, not a security boundary.
