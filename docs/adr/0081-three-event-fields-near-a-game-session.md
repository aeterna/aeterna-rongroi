# ADR 0081 — Three event fields read near a game session

- Status: proposed — four owner questions below; nothing is built
- Date: 2026-10-22
- Related: ADR 0018 (Event Log parsing; the payload is dropped), ADR 0031 (events identified by provider,
  channel and id together), ADR 0048 (`driver_service` path resolution), ADR 0059 (Code Integrity and
  Defender as timeline selectors), ADR 0060 (`autostart` command-line resolution), ADR 0061 (trace ages),
  ADR 0064 and ADR 0071 (the two earlier payload widenings), ADR 0078 (programs recorded near a game
  session, sections 5 and 7, step P4)
- Amends: ADR 0018 (a fourth, fifth and sixth kind of event whose payload is read), ADR 0059 (3033's file
  name is read, as a digest), ADR 0078 section 7 item 2 (how each field is emitted)

## Context

ADR 0078 section 7 item 2 asks for three payload fields, each read by a named function with a fixture and
none emitted as text: a service install's `ImagePath` (System 7045), the old and new time of a clock
change (Security 4616 and `Microsoft-Windows-Kernel-General` 1), and the file name Code Integrity refused
(3033). ADR 0018 drops every payload; ADR 0064 and ADR 0071 each widened it for named (provider, channel,
id) triples, through a separate `pub fn` in `rongroi_parsers::evtx` that returns a type with no field able
to hold text, plus a fuzz call and a test that no other text survives. This ADR follows that pattern.

What the code holds today (`dev` at `6d10791`):

- `evtx` reads every `.evtx` file and emits, per (channel, provider, id, level), a count and the first and
  last time. 7045 and Kernel-General 1 are counted in `System.evtx` that way; 4616 in `Security.evtx` when
  the token can read it; 3033 in `CodeIntegrity/Operational`, which ADR 0059's timeline selector shows.
- `windows_start` (ADR 0071) is a separate collector that parses `System.evtx` a second time on its own
  thread with its own 30-second limit.
- `driver_service::resolve` resolves a driver's `ImagePath` (`\SystemRoot\…`, `\??\X:\…`, `X:\…`,
  `System32\…`) and refuses the rest. `autostart` resolves a quoted command line with arguments and
  `%variables%`, privately.
- `view::game_windows` joins candidates by path ignoring ASCII case. It has no clock line and no
  service-install source yet (ADR 0078 section 5, "Clock trust", is unbuilt).

### Measured (2026-10-22, one Windows 11 PC, build 26220, an elevated token)

- **7045:** 52 events over 51 days. Fields `ServiceName`, `ImagePath`, `ServiceType`, `StartType`,
  `AccountName`. `ImagePath` shapes: 43 a drive-letter path, 6 a drive-letter path with arguments, 3
  `System32\…`.
- **4616:** none in the Security log, whose audit policy for this event is not on by default.
- **Kernel-General 1:** 126 events over 49 days. Fields `NewTime`, `OldTime`, `TimeDeltaInMs`, `Reason`,
  `ProcessName` (a `\Device\HarddiskVolumeN\…` path), `ProcessID`, `CmosTime`, `TimeZoneBias`,
  `RealTimeIsUniversal`, `SystemInCmosMode`. By size of change: 65 under 1 s, 28 from 1 s to 1 min, 2 from
  1 min to 1 h, 31 of 1 h or more. Reason 1 with `svchost.exe` (time sync) made 96 of them; Reason 2 with
  no process made 28, 25 of them 1 h or more (this PC keeps its hardware clock in local time, 7 h from
  UTC); `powershell.exe` made 2, one of them 1 h or more.
- **3033:** 507 events in 3 days, all for **one** file. Fields `FileNameLength`, `FileNameBuffer`,
  `ProcessNameLength`, `ProcessNameBuffer`, `RequestedPolicy`, `ValidatedPolicy`, `Status`.
  `FileNameBuffer` is `\Device\HarddiskVolumeN\…`, never a drive letter. This answers ADR 0078's open
  question: a 3033 file name and a candidate's path are **not** spelled the same way.

## Decision

### 1. One collector, `event_fields`, with three named readers (amends ADR 0018)

As ADR 0071 did for `BootType`, the payload is read by named functions in `rongroi_parsers::evtx`, each
matching its (provider, channel, id) triple and nothing else (ADR 0031), each returning a type that has
no field for any other part of the event. `records` stays payload-free. A new collector, `event_fields`,
calls them on `System.evtx`, `Security.evtx` and `Microsoft-Windows-CodeIntegrity%4Operational.evtx`, on
its own thread within one 30-second limit for all three, as `windows_start` does. The Security log needs
an elevated token; without one, that log is a gap for its place (`not_admin`, ADR 0044) and the other two
are still read.

- `service_installs(bytes)`: System, `Service Control Manager`, 7045 → when, `ImagePath`, `ServiceType`.
  `ServiceName` and `AccountName` are not read.
- `clock_changes(bytes)`: System, `Microsoft-Windows-Kernel-General`, 1, and Security,
  `Microsoft-Windows-Security-Auditing`, 4616 → when, old time, new time, `Reason` (Kernel-General only),
  and the changing process's file name (owner question 2).
- `refused_images(bytes)`: `Microsoft-Windows-CodeIntegrity/Operational`, 3033 → when, `FileNameBuffer`.
  `ProcessNameBuffer` and the policy fields are not read.

Each gets fixtures built from synthetic records, a call in `fuzz_evtx`, and a test that a record's other
fields and its `Computer` name do not reach the result.

### 2. Paths are joined as digests, never emitted (owner question 1)

ADR 0078 says none of these is emitted as text. A path still has to reach the view to be compared with a
candidate's, and collectors cannot see each other's output. So each path is emitted as a **digest**: the
SHA-256 of the path, ASCII-lower-cased, in one canonical form. The view computes the same digest of each
candidate's path and joins on it.

- **7045:** `ImagePath` is resolved to a drive-letter path — by `driver_service::resolve` for a kernel or
  file-system driver, and for a program service by the command-line resolution `autostart` already uses,
  made shared. An unresolved path is counted, not digested. Emitted per install: `installed_at` (on the
  timeline), `kind` (`driver` or `program`), and `path_digest` when it resolved.
- **3033:** the canonical form is the path **after** its volume, `\Device\HarddiskVolumeN` removed,
  because the event names the volume by device and a candidate by drive letter. The view digests a
  candidate's path without its `X:`. Two volumes can hold the same path, so a match says "a file at the
  same path on some volume". Emitted per distinct file, not per event: `path_digest`, `events`,
  `first_seen`, `last_seen`. The 507 measured events become one observation.

A digest of a path is not secret: anyone holding the path can compute it. It keeps the path out of the
report and out of SS mode, and it is enough for the join ADR 0078 asks for.

### 3. Clock changes, and the clock line (ADR 0078 section 5)

Each change of at least **60 seconds** either way is an observation: `changed_at` (on the timeline),
`old_time` and `new_time` (off the timeline: they are what the clock said, not when anything happened),
`reason` and, when owner question 2 says so, `by` (the process's file name). Smaller changes, time
synchronisation's ordinary corrections, are counted, not listed. The view's clock line (ADR 0078 section
5) uses every listed change inside the span it compares.

The measured PC shows why the threshold alone is not enough: 25 of its 31 changes of an hour or more were
Reason 2 with no process, which this ADR takes to be Windows setting its clock from a hardware clock kept
in local time at start-up — an inference from `TimeZoneBias` and `RealTimeIsUniversal`, not documented by
Microsoft. They are still listed; the clock line says "the clock was changed at …", never why. A manual
change by `powershell.exe` and a start-up correction look different only through `by` and `reason`.

### 4. Candidates (amends ADR 0078 sections 4 and 7)

A 7045 install with a path digest that matches a candidate adds `installed_at` to that candidate's times,
so the install is placed in the windows as ADR 0078 section 4 says. An install that matches no candidate
is counted per window: "a driver was installed 4 minutes before the session; its path is not among the
programs recorded". A 3033 match is shown on the candidate as "Code Integrity refused a file at the same
path". Neither is a fact on ADR 0078's ladder in this ADR; the view shows them as notes. Ranking by them
waits for the lab baseline (P7).

### 5. Consent and `PRIVACY.md`

`PRIVACY.md`'s event-log paragraph says today that nothing of any event other than `BootType` is read; it
names these three exceptions in the change that adds them, with the digest and what it does and does not
hide. The consent text (CLI and desktop, both languages) says: "from three kinds of event, when a service
was installed and a fingerprint of its file's path, when the clock was changed and by how much, and a
fingerprint of each file Code Integrity refused — never a path or a name".

## Owner questions

1. **Paths as digests** (section 2). Recommended: **yes**, it keeps ADR 0078's "none emitted as text" and
   still joins. Alternative: emit 7045's resolved path as text, redacted in SS mode like `driver_service`'s,
   which a reviewer can read but which puts every installed service's path into the report.
2. **The process that changed the clock** (`by`). Recommended: **emit its file name only**
   (`svchost.exe`, `powershell.exe`): it is what separates time sync from a person changing the clock, and
   it names a Windows program, not a person's file. Alternative: the two times and the reason only, as ADR
   0078 wrote it.
3. **Tier of `event_fields`.** Recommended: **standard** — the clock line matters to every comparison the
   report makes, and nothing it emits is text. Alternative: full only, which also keeps a standard scan
   from parsing `System.evtx` a third time.
4. **The 60-second threshold** (section 3). Recommended: **60 seconds**, a core constant changed by a
   release, like ADR 0078's windows. Alternative: list every change.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Add the fields to `evtx`'s `records` | `records` is the payload-free reader every other event goes through; ADR 0018 and ADR 0071 keep it so |
| Map `\Device\HarddiskVolumeN` to a drive letter with `QueryDosDevice` | A new host call for a small gain; the volume-relative digest joins without it, and a mount point can map one volume to several paths anyway |
| One observation per 3033 event | 507 events for one file on the measured PC |
| List every clock change | 65 of 126 measured were under a second, all time sync |
| Read `ServiceName` | A name chosen by whoever installed the service; it says nothing the path digest and the time do not, and it can name a person or a product |
| Keep 3033 as ADR 0059's timeline selector only | It shows that something was refused, not whether it was a candidate's file |

## What is unverified

- Whether 4616 is written on other PCs; none was on the measured one.
- What `Reason` values mean; Microsoft does not document them. Section 3 reads Reason 2 from one PC.
- Whether `ImagePath` in a 7045 is the same text the Services key holds afterwards.
- Whether a 3033's `FileNameBuffer` is ever a drive-letter path, or a short (8.3) name.
- How long `CodeIntegrity/Operational` reaches back: its default size is 1 MiB, and it held 3 days on the
  measured PC.

## Consequences

- `rongroi-parsers`: `evtx::{service_installs, clock_changes, refused_images}` and their types; `fuzz_evtx`
  calls them.
- `rongroi-collectors`: `event_fields`, its ages declaration; `autostart`'s command-line resolution made
  shared; a digest helper used by both the collector and the view.
- `rongroi-core`: `view::game_windows` joins digests, adds installs to candidates' times, counts unmatched
  installs per window, and gains the clock line.
- CLI and desktop consent text, `PRIVACY.md`, the locale name, `docs/architecture.md`.
- ADR 0059's selector for 3033 and 3077 is unchanged.
