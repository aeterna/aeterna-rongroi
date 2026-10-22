# ADR 0081 — Three event fields read near a game session

- Status: proposed — four owner questions below; nothing is built
- Date: 2026-10-22
- Related: ADR 0018 (Event Log parsing; the payload is dropped), ADR 0031 (events identified by provider,
  channel and id together), ADR 0044 (gaps for one place), ADR 0048 (`driver_service` path resolution),
  ADR 0059 (Code Integrity and Defender as timeline selectors), ADR 0060 (`autostart` command-line
  resolution), ADR 0061 (trace ages), ADR 0064 and ADR 0071 (the two earlier payload widenings), ADR 0078
  (programs recorded near a game session, sections 4, 5 and 7, step P4)
- Amends: ADR 0018 (a fourth, fifth and sixth kind of event whose payload is read), ADR 0059 (3033's file
  name is read, as a digest), ADR 0078 section 4 (a service install that matches no candidate is counted,
  not made a candidate), section 5 "Clock trust" (changes under a threshold are counted, not drawn), and
  section 7 item 2 (how each field is emitted)

## Context

ADR 0078 section 7 item 2 asks for three payload fields, each read by a named function with a fixture and
none emitted as text: a service install's `ImagePath` (System 7045), the old and new time of a clock
change (Security 4616 and `Microsoft-Windows-Kernel-General` 1), and the file name Code Integrity refused
(3033). ADR 0018 drops every payload; ADR 0064 and ADR 0071 each widened it for named (provider, channel,
id) triples, through a separate `pub fn` in `rongroi_parsers::evtx` that reads only named fields, plus a
fuzz call and a test that a record's other fields and its `Computer` name do not survive. ADR 0071's type
holds no text at all; ADR 0064's holds text only after classifying it (`download_host`). This ADR follows
that pattern: the readers return the named fields, and the collector turns every text field into a digest
or a category before anything is emitted.

What the code holds today (`dev` at `6d10791`):

- `evtx` reads every `.evtx` file and emits, per (channel, provider, id, level), a count and the first and
  last time. 7045 and Kernel-General 1 are counted in `System.evtx` that way; 4616 in `Security.evtx` when
  the token can read it; 3033 in `CodeIntegrity/Operational`, which ADR 0059's timeline selector shows.
- `windows_start` (ADR 0071) is a separate collector that parses `System.evtx` a second time on its own
  thread with its own 30-second limit, through `evtx::windows_starts`, which builds its own parser.
- `driver_service::resolve(image_path, service, system_root)` resolves a driver's `ImagePath` and builds
  the default path from the service's name when `ImagePath` is empty. `autostart` resolves a quoted
  command line with arguments and `%variables%` in a private method that checks files exist through the
  host.
- `failure::reason_for` gives `not_admin` only for access denied on a token known not to be elevated.
- Only a full-tier collector may mark a field sensitive; `SS_WITHHELD_FIELDS` lists three fields.
- `view::game_windows` joins candidates by path ignoring ASCII case. It has no clock line and no
  service-install source yet (ADR 0078 section 5, "Clock trust", is unbuilt).

### Measured (2026-10-22, one Windows 11 PC, build 26220, an elevated token)

- **7045:** 52 events over 51 days. Fields `ServiceName`, `ImagePath`, `ServiceType`, `StartType`,
  `AccountName`. `ImagePath` shapes: 43 a drive-letter path, 6 a drive-letter path with arguments, 3
  `System32\…`. None empty.
- **4616:** none in the Security log. Its audit policy was not read, so whether it is off is inferred.
- **Kernel-General 1:** 126 events over 49 days. Fields `NewTime`, `OldTime`, `TimeDeltaInMs`, `Reason`,
  `ProcessName` (a `\Device\HarddiskVolumeN\…` path or empty), `ProcessID`, `CmosTime`, `TimeZoneBias`,
  `RealTimeIsUniversal`, `SystemInCmosMode`. By size of change: 65 under 1 s, 28 from 1 s to 1 min, 2 from
  1 min to 1 h, 31 of 1 h or more. Reason 1 with `svchost.exe` made 96; Reason 2 with no process made 28,
  25 of them 1 h or more (this PC keeps its hardware clock in local time, 7 h from UTC); `powershell.exe`
  made 2, one of them 1 h or more.
- **3033:** 507 events in 3 days, all for **one** file. Fields `FileNameLength`, `FileNameBuffer`,
  `ProcessNameLength`, `ProcessNameBuffer`, `RequestedPolicy`, `ValidatedPolicy`, `Status`.
  `FileNameBuffer` is `\Device\HarddiskVolumeN\…`, never a drive letter. This answers ADR 0078's open
  question: a 3033 file name and a candidate's path are **not** spelled the same way.

## Decision

### 1. One collector, `event_fields`, with named readers (amends ADR 0018)

The payload is read by named functions in `rongroi_parsers::evtx`, each matching its (provider, channel,
id) triples and nothing else (ADR 0031), each reading only the fields named here. `records` stays
payload-free. A new collector, `event_fields`, reads three logs, each parsed **once**:

- `system_fields(bytes)` on `System.evtx`: `Service Control Manager` 7045 → when, `ImagePath`,
  `ServiceType`; and `Microsoft-Windows-Kernel-General` 1 → when, `OldTime`, `NewTime`, `Reason`,
  `ProcessName`. `ServiceName`, `StartType` and `AccountName` are not read.
- `security_fields(bytes)` on `Security.evtx`: `Microsoft-Windows-Security-Auditing` 4616 → when, the
  previous and new time. Nothing else of the event.
- `refused_images(bytes)` on `Microsoft-Windows-CodeIntegrity%4Operational.evtx`: 3033 → when,
  `FileNameBuffer`. `ProcessNameBuffer` and the policy fields are not read.

The readers' types hold `ImagePath`, `ProcessName` and `FileNameBuffer` as text, because the collector
must transform them; no text field leaves the collector (sections 2 and 3). Each reader gets synthetic
record fixtures, a call in `fuzz_evtx`, and a test that a record's other fields and its `Computer` name do
not reach the result.

**Budget and order.** One thread, `System.evtx` first, then `CodeIntegrity/Operational`, then
`Security.evtx`, each with its own 20-second limit, so one slow log cannot take the others' time. A log
the limit stopped is `budget_spent` for its place.

**Gaps (ADR 0044).** The collector declares `log` as its discriminator; each log that could not be read
is a gap for that place, with the reason `failure::reason_for` gives (`not_admin` for a refused Security
log on a token known not to be elevated, `access_denied` when that is unknown, `source_absent` for a
missing file). One summary observation per log carries `read` and the counts in section 3.

### 2. Paths are joined as digests, never emitted (owner question 1)

A path has to reach the view to be compared with a candidate's, and collectors cannot see each other's
output. So each path is emitted as a **digest**, the hex SHA-256 of the path ASCII-lower-cased. There are
two forms, under two names, because the two events spell paths differently:

- **`path_digest` (7045):** of the resolved drive-letter path, `x:\…`. `ImagePath` is resolved by
  `driver_service::resolve` for a kernel or file-system driver (`ServiceType` 1 or 2), and otherwise by
  `autostart`'s command-line resolution, moved to a `pub(crate)` function in `rongroi-collectors` that
  takes `&dyn Host`. An empty `ImagePath` is not resolved, because the default path is built from the
  service's name, which this ADR does not read; it is counted as unresolved, with every other path that
  does not resolve.
- **`volume_path_digest` (3033):** of the path after its volume, `\…`, with the
  `\Device\HarddiskVolumeN` prefix removed, because the event names the volume by device and a candidate
  by drive letter. Two volumes can hold the same path, so a match says "a file at the same path on some
  volume".

The view computes both digests of each candidate's path, `x:\…` and `\…`, and joins each on its own name.

Emitted per 7045: `installed_at` (on the timeline), `kind` (`driver` or `program`), and `path_digest`
when the path resolved. Emitted per distinct 3033 file, not per event: `volume_path_digest`, `events`,
`first_seen`, `last_seen`; the 507 measured events become one observation.

A digest is not a secret: anyone who has the path can compute it, and the same file gives the same digest
in every report, so two reports can be linked by it. It keeps the path's text out of the report. SS mode
shows the digests; they are not withheld.

### 3. Clock changes (amends ADR 0078 section 5)

Kernel-General 1 is the clock line's source; the kernel writes it for every change, and the measured PC
held 126. A 4616, when the Security log holds one and could be read, is listed the same way; its absence
says nothing, because the audit policy that writes it is not read.

Each change of at least **60 seconds** either way is an observation: `changed_at` (on the timeline),
`old_time` and `new_time` (off the timeline: they are what the clock said, not when anything happened),
`reason` (Kernel-General's number, undocumented) and `by` (owner question 2). Each log's summary
observation carries `small_clock_changes`, the count of changes under 60 seconds, and their first and last
time. The view's clock line (ADR 0078 section 5) is drawn for every listed change inside the span it
compares; changes under 60 seconds do not draw it, because no comparison in the view is finer than a
minute. ADR 0078 section 5's "not known" line applies when `System.evtx` was not read or does not reach
back to the span (its trace age, ADR 0061).

`by` is a category, never a name: `windows` when `ProcessName`, after its volume, is under
`\Windows\System32\` or `\Windows\SysWOW64\`; `none` when it is empty; `other` otherwise. On the measured
PC, time sync is `windows` with Reason 1, the 25 start-up corrections are `none` with Reason 2, and
`powershell.exe` is `windows` too — so `by` does not separate a person typing `Set-Date` from time sync;
the size of the change, the reason and the time do. This ADR takes Reason 2 with no process to be Windows
setting its clock from a hardware clock kept in local time at start-up — an inference from
`TimeZoneBias` and `RealTimeIsUniversal`, not documented by Microsoft. The clock line says "the clock was
changed at …", never why.

### 4. Service installs and refused images in the view (amends ADR 0078 section 4)

A 7045 whose `path_digest` matches a candidate adds `installed_at` to that candidate's times, so the
install is placed in the windows. A 7045 that matches no candidate, or did not resolve, is **counted** per
window ("a driver was installed 4 minutes before the session; its path is not among the programs
recorded"), not made a candidate: with no path and no name there is nothing to list. A 3033 match is
shown on the candidate as "Code Integrity refused a file at the same path on some volume". Neither is a
fact on ADR 0078's ladder in this ADR; the view shows them as notes, and ordering by them waits for the
lab baseline (P7).

### 5. Consent and `PRIVACY.md`

`PRIVACY.md`'s event-log paragraph says today that nothing of any event other than `BootType` is read; it
names these exceptions in the change that adds them, with what a digest does and does not hide. The
consent text (CLI and desktop, both languages) says: "from four kinds of event, when a service or driver
was installed, when the clock was changed, from what time to what time, with Windows' reason number and
whether a Windows program made the change, and, for a service's file and each file Code Integrity
refused, a fingerprint of its path that matches only the same path — never a path or a name".

## Owner questions

1. **Paths as digests** (section 2). Recommended: **yes** — it keeps ADR 0078's "none emitted as text"
   and still joins; the cost is that a digest links two reports of the same file and is shown in SS mode.
   Alternative: emit 7045's resolved path as text, redacted in SS mode like `driver_service`'s, which a
   reviewer can read but which puts every installed service's path into the report.
2. **Who changed the clock** (`by`). Recommended: **the category** in section 3 (`windows`, `none`,
   `other`), no name. Alternative: no `by` at all, the two times and the reason only, as ADR 0078 wrote it.
   Emitting the process's file name is not offered: it would be a name in SS mode, and a standard-tier
   collector cannot mark a field sensitive.
3. **Tier of `event_fields`.** Recommended: **standard** — the clock line matters to every comparison the
   view makes, and nothing it emits is a path or a name. A standard scan then parses `System.evtx` three
   times (`evtx`, `windows_start`, `event_fields`). Alternative: full only.
4. **The 60-second threshold** (section 3, amends ADR 0078 section 5). Recommended: **60 seconds**, a core
   constant changed by a release, like ADR 0078's windows. Alternative: list every change and draw the line
   for each; on the measured PC that is 126 lines, 65 of them under a second.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Add the fields to `evtx`'s `records` | `records` is the payload-free reader every other event goes through; ADR 0018 and ADR 0071 keep it so |
| Map `\Device\HarddiskVolumeN` to a drive letter with `QueryDosDevice` | A new host call for a small gain; the volume-relative digest joins without it, and a mount point can map one volume to several paths anyway |
| One digest form for both events | A candidate has one path, and the two events spell it two ways; one form would make one of the two joins never match |
| One observation per 3033 event | 507 events for one file on the measured PC |
| Read `ServiceName` to resolve an empty `ImagePath` | None of the 52 measured installs had one; reading a name chosen by whoever installed the service for a case not seen is not worth the name in the report's inputs |
| The changing process's file name as `by` | A name in SS mode, which a standard-tier collector cannot withhold |
| One 30-second limit for all three logs | One slow log would cost the other two |

## What is unverified

- Whether 4616 is written on other PCs; none was on the measured one.
- What `Reason` values mean; Microsoft does not document them. Section 3 reads Reason 2 from one PC.
- Whether `ImagePath` in a 7045 is the same text the Services key holds afterwards, and whether it is ever
  empty.
- Whether a 3033's `FileNameBuffer` is ever a drive-letter path, or a short (8.3) name.
- How long `CodeIntegrity/Operational` reaches back: its default size is 1 MiB, and it held 3 days on the
  measured PC.

## Consequences

- `rongroi-parsers`: `evtx::{system_fields, security_fields, refused_images}` and their types; `fuzz_evtx`
  calls them.
- `rongroi-collectors`: `event_fields`, registered in `all()`, with its discriminator and ages
  declaration; `autostart`'s command-line resolution moved to a shared `pub(crate)` function taking
  `&dyn Host`; a digest helper shared with the view.
- `rongroi-core`: `view::game_windows` computes both digests per candidate, adds installs to candidates'
  times, counts unmatched installs per window, and gains the clock line; `COLLECTOR_ORDER` places
  `event_fields` after `windows_start`.
- CLI and desktop consent text, `CONSENT_WORDS`, `PRIVACY.md`, the locale name, `docs/architecture.md`.
- ADR 0059's selector for 3033 and 3077 is unchanged.
