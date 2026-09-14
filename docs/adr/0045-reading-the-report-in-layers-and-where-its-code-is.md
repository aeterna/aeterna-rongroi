# ADR 0045 — Reading the report in layers, and where its code is

- Status: proposed
- Date: 2026-09-14
- Amends: ADR 0027 (where a rule's description and false positives are shown)

## Context

The desktop report of 0.3.0 is one list. It opens with the version, the rules bundle SHA-256 and the
executable's SHA-256, then shows every piece of evidence the view lists in bundle order, each with its
description and its observations written as one `field=value, field=value` line. Every row is always
fully open, and a `not_found` row takes the same space as a `found` one.

Two readers use that screen and it serves neither:

- A player or a server admin without a technical background has to read every row to learn how many
  rules matched, and meets hashes before any sentence about the machine.
- A technical reader can see the observation fields but cannot see where a rule is written, which
  fixtures back it, or which code produced the observation. Nothing in the GUI or the CLI output names
  the repository at all, although this is an open-source tool whose claim to trust is that anyone can
  read it (ADR 0003, ADR 0007).

What the change must not do:

- produce a score, a pass/fail total or a "clean" state (ADR 0002);
- add network code, a Tauri plugin, or a way for the window to open a web page (ADR 0003; the
  capability `main` says "No plugins, no network, no file system access from the UI");
- move SS-mode filtering or redaction out of `rongroi-core::view` (AGENTS.md hard rule 5);
- change which evidence a view lists (ADR 0014, ADR 0027, ADR 0030).

## Decision

### 1. Listed counts, above the evidence

`ReportView` gains `listed: ListedCounts { found, not_found, unmeasured }`: how many pieces of the
evidence **this view lists** are in each state. It is computed in `view::for_mode`, next to
`HiddenCounts`, so the GUI and the CLI state the same numbers. The field is additive with
`#[serde(default)]` and `REPORT_SCHEMA_VERSION` stays at 1, as with `ScopeNotes::not_attempted`
(ADR 0030).

The GUI shows the three numbers as three separate items, each with the words for its state, and one
item filters the list to that state. They are never added into one number and there is no fourth
item. Directly under them, not in a footer, stands the sentence the footer already carries: the report
is evidence for a person to judge and cannot prove that a PC is clean.

This is not the "pass/fail total" ADR 0002 rules out. A pass/fail total collapses the report into one
figure a reader can act on without reading; three counts of states that each still need their rows read
do not, and SS mode has shown counts per state since ADR 0014 (`HiddenCounts`). `CONVENTIONS.md` gains
**listed counts** in the glossary.

SS mode shows the same three listed counts — its view lists every match, posture results that looked,
and unmeasured results the rule did not expect — and keeps the `HiddenCounts` line as it is today.

### 2. Three layers per row

Each row of evidence has three layers:

1. **The row.** A state mark, the state in words, the rule title, and the rule description cut to two
   lines by CSS (`line-clamp`). No text is written or extracted for it: a first sentence cannot be cut
   out mechanically, because the Thai translations separate sentences with a space only.
2. **What it means**, opened by clicking the row. The whole description, then the false positives
   beside a `found` row, the retention window beside a `not_found` row, and the reason — with whether the
   rule expected it — beside an `unmeasured` row.
3. **For technical readers**, a closed section inside layer 2. The observation fields as a table of
   field and value, the rule id, `status`, collector, `strength`, the reason code and `expected`; and
   **where this is in the code** (§4).

A `found` row starts with layer 2 open. The sentence that says a rule does not prove cheating usually
ends its description, which is the part the two-line cut hides; a match is where that sentence matters
most and where there are few rows. `not_found` and `unmeasured` rows start closed.

A switch above the list opens layer 3 of every row at once, for a reader who wants everything.

This amends ADR 0027, which put the description and the false positives beside every row in full: the
description stays beside every row, cut to two lines until it is opened, and the false positives stay
open beside every match.

### 3. Groups by collector

Rows are grouped by the rule's collector, in a fixed order — `posture`, `fivem_dir`, `process`, `evtx`,
`prefetch`, `bam`, `pca` — and a collector with no listed evidence has no group. Each group has a plain
name in the locale files (`report.collector.<id>`, checked by `cargo xtask check-locales`) and shows its
own counts per state. Inside a group, `found` rows come first, then `unmeasured`, then `not_found`; the
`not_found` rows of a group are folded into one line that says how many there are and opens them.

Grouping and ordering are presentation of what the view already lists. They change nothing about what
is listed, so they live in the UI.

### 4. Rule files and the code link

`RuleText` gains `files: RuleFiles`, filled by `Bundle::text` from the `SourcedRule` path and the rule:

| Field | Value |
|---|---|
| `rule` | `rules/<path>` — the `rule.yaml` |
| `fixtures` | `rules/<dir of path>/tests` |
| `collector` | `crates/rongroi-collectors/src/<collector>.rs` |
| `references` | the rule's `references`, unchanged |

A test in `rongroi-core` walks the embedded bundle and fails if any of the first three paths does not
exist in the workspace, so a moved collector file or fixture folder fails CI instead of producing a
dead link.

`rongroi_core::provenance` gains `REPOSITORY_URL` (`https://github.com/aeterna/aeterna-rongroi`) and
`Provenance::code_url()`:

- an official build with a commit: `REPOSITORY_URL/tree/<commit>` — the code this binary was built from;
- anything else: `REPOSITORY_URL`, with the UI saying that the code of this build is not known.

A link to a file is `REPOSITORY_URL/blob/<commit>/<path>` for an official build and is not shown for an
unofficial one, because a path at `dev` may not be the code that ran.

`CONVENTIONS.md` gains **rule files** and **code link** in the glossary. Neither uses the word *source*,
which the glossary gives to where an artifact is kept on the PC (*source absent*, *source empty*).

### 5. Getting to the code without a plugin

The window cannot open a browser (§Context). A link is shown as selectable text with a **Copy** button
(`navigator.clipboard.writeText`) and, for the repository and the code link, a QR code for a phone:

- The QR code is drawn in Rust by the desktop app — a new command `code_link_qr(url) -> String` returning
  an SVG string — and shown as an `<img>` with a `data:image/svg+xml` URL, which the CSP already allows
  (`img-src 'self' data:`). No JavaScript dependency is added. The crate is chosen in the plan and must
  pass `cargo deny`.
- If the clipboard call is refused, the button says so and the text stays selectable.

A screen **About & code** is reachable from every screen. It shows: official build or not, version,
commit, the executable's SHA-256, the rules bundle's count and SHA-256, the licence, the repository and
the code link with Copy and QR, how to check a downloaded file against `SHA256SUMS` and with
`gh attestation verify aeterna-rongroi-<version>-windows-x64.exe -R aeterna/aeterna-rongroi`, and why
there is no button that opens a web page — using the ADR 0003 wording verbatim.

### 6. The CLI

The human output gains one line with the listed counts above the evidence and one line with the code
link above the footer. `--json` carries `listed` through `ReportView`. The CLI's row layout does not
change in this ADR.

### 7. What stays as it is

The start screen's choices and the consent text, the administrator-restart offer and when it is shown,
the unofficial-build banner, the own-traces and unmatched sections (each folded, after the evidence,
in the order they have today), the boot time line, and the dark and gold look of the window. SS mode's
filter and redaction are untouched; a technical reader in SS mode sees `%USERPROFILE%` in layer 3
because the view already carries it.

A state is never shown by colour alone: `found` is a filled square, `not_found` an open circle,
`unmeasured` a dashed circle with a dashed row border, and every row says its state in words.
`not_found` is grey, never green.

## What is unverified

- Whether WebView2 inside the Tauri window grants `navigator.clipboard.writeText` without a permission
  prompt. To be checked by hand on Windows before release; the selectable text is the fallback either
  way.
- The QR crate, its licence under `cargo deny`, and the size it adds to the desktop binary.
- Whether a phone camera reads the QR code off a screenshare at ordinary stream resolutions.

## Consequences

- `docs/rules-reference*.md` do not change. The report snapshots the UI tests read change (the new
  `listed` field), and so do the CLI output tests.
- Two pull requests: the core and CLI part with this ADR, then the desktop UI on top of it.
- A future rule whose collector has no file of its own name fails the rule-files test and must extend
  `RuleFiles` rather than link to a guess.
- The M3 collectors (vulnerable drivers, USN journal) land in this layout: their hashes, signers and
  journal fields go in layer 3, not in the row.
