# ADR 0073 — A saved report, its case code, and the digest staff see on screen

- Status: proposed — the owner asked for a save button (DMA plan Q-R2, 2026-10-15) and for this ADR (2026-10-16);
  the questions at the end are open
- Date: 2026-10-16
- Takes up: ADR 0040 "Not decided here" (a short digest on screen); ADR 0070's deferral of "the case code and the
  button that saves a report"

## Context

A server that checks a player over a screenshare wants to keep what it saw: in the DMA plan, staff open a case, give
the player a short case code, watch the scan, and file the report against the case. Three facts in this repository
decide how that can work.

**The window cannot save anything today.** The capability `main` grants `core:default` only, no plugin is enabled, and
the UI has no file or dialog API (`apps/desktop/src-tauri/capabilities/main.json:6`; no `tauri-plugin-*` in
`Cargo.lock`). PRIVACY.md says "The window version has no export or save button" (PRIVACY.md:480), and so do both
screenshare guides (§9) and ADR 0040 (0040:26).

**A file made afterwards is a different report.** The CLI's `scan --json` scans again: a file a player produces after
the session has other times in it and is not what staff watched (DMA plan, scrutinize round 3). The only way a file
can be the report staff saw is for the window that showed it to write it.

**Nothing in a report identifies it.** The header carries the program's version, commit and `exe_sha256`, the rules
bundle's SHA-256 and `generated_at` (`crates/rongroi-core/src/provenance.rs:22-30`, `bundle.rs:156`, `scan.rs:67`);
there is no report id, case id or report hash anywhere (searched 2026-10-16). And reports are not signed: a file
proves nothing about where it came from (ADR 0040), which this ADR does not change.

ADR 0040 left one thing open in so many words: "Showing a short digest of the report on screen during the session,
for staff to compare with a file sent afterwards, is not signing. It would tie a file to what staff saw on screen and
say nothing more than the screen did." (0040:119-121). This ADR proposes it.

**When the window's scan runs.** The desktop app scans before it creates its window (`apps/desktop/src-tauri/src/
main.rs:87-95`), so nothing typed into the window can be part of the scan. A case code has to be part of the file
that is saved, not of the scan.

## Decision (proposed)

### 1. A saved record, built once, in the core

`rongroi-core::view` gains a **saved record**: one JSON document that holds

- `kind: "rongroi-saved-report"` and `schema: 1`;
- `case_code`: the code the player typed, in canonical form (section 2), or absent;
- `rongroi_version` and `official_build`: copied from the header's provenance (ADR 0007), so a server reads them
  without walking the view;
- `scan_started_at`: the header's `generated_at`, which both front ends take just before the scan starts
  (`crates/rongroi-cli/src/main.rs:161-167`, `apps/desktop/src-tauri/src/main.rs:80-87`);
- `scan_finished_at`: a new time, taken when `scan::run` returns;
- `saved_at`: when the record was built;
- `view`: the **SS view** exactly as the window shows it, with the consent options the player chose — never the
  Self view, which holds unredacted paths and the profiles folder (`view.rs:420`);
- `devices`: every `pci_device` and `hid_device` observation (question 3). SS mode counts unmatched devices rather
  than listing them; a server comparing two checks of one player needs the whole list. Device rows hold model ids
  and times, no names (ADR 0069), and the consent question says they are saved.

The record is serialised **once**, as compact UTF-8 JSON with no byte-order mark, when the player confirms the case
code, and those bytes are kept in the app's state. Everything after that — the digest on screen and the file — comes from those bytes, so they cannot differ.
Building it in `rongroi-core::view` keeps the rule that what an SS audience sees is decided in the core (AGENTS.md
hard rule 5).

### 2. The case code

- Typed by the player at the SS consent screen, in a field labelled "Case code from the server (optional)"; the CLI
  takes `--case-code`.
- Format (question 2): 6 characters from Crockford's base32 alphabet (`0-9 A-H J K M N P-T V-Z`, no `I L O U`),
  shown as `XXX-XXX`. Input is made canonical as Crockford's specification says, in the window and in the CLI
  alike: upper case, `I` and `L` read as `1`, `O` as `0`, hyphens and spaces removed. What is left must be 6
  characters of the alphabet, or it is refused with a message. The record holds the 6 canonical characters, no
  hyphen; the server keeps their SHA-256 (nakara-city#2708, `case_code_sha256`). The
  program checks the format only. It cannot check that a code is real, unused or unexpired — it has no network — and
  says so; the server checks that when the file arrives.
- A code is not a secret and not a proof. It tells the server which case a file was meant for.

### 3. The digest on screen

While the SS view is shown, the window's header shows the SHA-256 of the saved record's bytes: **the first 16 hex
characters, large, in four groups** (question 4), and the full 64 under it in small type. The CLI prints the same line
to standard error before the JSON. Staff note it from the screenshare. When the file arrives, the server hashes it
and compares.

The server compares what staff noted (at least 16 characters, nakara-city#2708 `staff_noted_hash`) as a prefix of the
SHA-256 of the uploaded bytes, before parsing them.

Why 16 and not 8: 8 hex characters are 32 bits, and a changed file can be padded until its first 8 characters
match in about 2³² tries (estimated, not timed). 16 characters are 64 bits. What the comparison shows is only that
the file is the one that was on screen — not that the screen was honest (ADR 0040).

### 4. The save button, and what it writes

- Shown in SS mode only, after the SS view is on screen: "Save this report". Self mode has none (question 5).
- It opens Windows' own Save dialog from Rust, through a new `rongroi-host-windows` function over
  `IFileSaveDialog` — no Tauri plugin, and the UI still has no file access (capability unchanged). The default name is
  `rongroi-<case code or date>-<first 8 of the digest>.json`, in the player's Documents folder.
- It writes the kept bytes, nothing else, to the path the player chose, and reports success or the error. It never
  overwrites without Windows' own "replace?" prompt.
- This is the program's own output, written where the player chose, as a CLI redirect already is. Collectors stay
  read-only (hard rule 2 is about what a scan reads, and nothing here is part of a scan). The `CreateFileW` ban in
  `clippy.toml` stays for collectors; the writer uses `std::fs::write` in the desktop crate only, which a test pins.

### 5. Text that changes

The SS consent question says what the file would hold if saved: the SS view plus the device list, and the case code.
PRIVACY.md "What is stored" changes from "Nothing" to "Nothing, unless you press Save in SS mode — then exactly what
was on screen plus the device list, where you choose, and only there". Both screenshare guides' §9 replace "no export
or save button" with the button and the digest. ADR 0040 gets a note that its open question is taken up here.

### 6. Size

Measured on the development PC on 2026-10-16 with the 0.9.0 CLI: the SS view was 235 KB as printed (pretty JSON)
and 163 KB compact, with 458 timeline entries and 26 evidence rows. Its 40 PCI and 25 HID devices add roughly
20 KB (estimated). A saved record is expected well under 1 MiB, the upload limit the nakara session plans; a
record over it is still saved, and the window says how large it is.

## What this does not do

- It does not sign a report or make one tamper-evident beyond the comparison with what staff wrote down.
- It does not send anything anywhere. Uploading is the server's page (nakara `/pc-check/upload`, still closed).
- It does not save a Self-mode report.
- It does not let a CLI run produce the window's file; the CLI's `--json` output is its own record with its own digest.

## Alternatives weighed

- **A Tauri dialog and fs plugin.** Gives the UI file access the capability now denies, and adds two plugins where one
  Rust function does.
- **Save the full report.** Holds what SS mode hides (paths with the user's name, server identities).
- **Serialise when Save is pressed.** The digest staff noted could differ from the file if anything serialises
  differently between the two moments; one serialisation removes that.
- **A random code made by the program.** The point of a case code is that the server issued it.

## What is unverified

- `IFileSaveDialog` from the WebView2 host process on Windows 10 and 11: expected to work, not built yet.
- The time to forge an 8-character prefix: estimated, not measured.

## Decisions for the owner

| # | Question | Recommended |
|---|---|---|
| 1 | A save button in the window, SS mode only, writing a saved record built once in the core? | **Yes** |
| 2 | Case code: 6 characters of Crockford base32 shown as `XXX-XXX`, canonicalised as Crockford says, optional, format-checked only? | **Yes** — the nakara session agreed on 2026-10-16 and stores the SHA-256 of the canonical 6 |
| 3 | The saved record holds the SS view **plus every PCI and HID device** (model ids and times, no names)? | **Yes** — the server needs the full device list; the consent question says so |
| 4 | Digest on screen: first 16 hex of the SHA-256, large, with the full 64 small? | **Yes** |
| 5 | No save in Self mode? | **Yes** — Self mode holds what SS hides |
| 6 | The CLI gets `--case-code` and prints the digest to standard error? | **Yes** |

## Consequences

- `rongroi-core::view`: the saved record and its serialisation, with tests that the bytes are stable and hold no
  Self-mode field.
- `rongroi-host-windows`: a save dialog function; the desktop crate: two commands (build the record with a code,
  save the kept bytes).
- UI: the case code field on the consent screen, the digest in the header, the button.
- Consent text, PRIVACY.md, both guides, ADR 0040's note, the changelog.
- A new kind of file people will pass around. Its `schema` is 1 and additive changes keep it 1 (DMA plan Q-R3). The
  nakara parser ignores fields it does not know and refuses another `kind` or an unknown `schema`.
- The release that adds the button also carries `hid_device` (ADR 0072, merged), so the file holds HID devices from
  its first version, and the server's consent text names mice and keyboards.
