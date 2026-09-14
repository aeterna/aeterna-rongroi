# ADR 0039 — A time anchor for the report: when Windows last started counting

- Status: accepted
- Date: 2026-09-13

## Context

A report carries times. The `evtx` collector reports each log's oldest and newest surviving record and
the first and last time an event of each kind was written (ADR 0028); the two log-clearing rules show
those times on a `found` row (ADR 0031); Prefetch, BAM and PCA carry the times programs ran. A reviewer
reading "this log's oldest record is 10:42" or "cleared at 10:40" cannot tell from the report whether that
was before or after the PC last started, which is one of the first questions anyone asks of a time.

The report header already carries `generated_at`, the scan's own clock. It carries nothing that places
the machine's current session on that clock.

This ADR adds that one fact, and it adds it as **context**. It is not evidence: no rule reads it, no
state depends on it, and nothing in this program concludes anything from it (ADR 0002). It is a read of
something this program did not read before, which is why it needs an ADR (AGENTS.md).

Two things make the fact easy to misread, and the decision is mostly about them:

- **"Started" in Windows is not "I turned the PC on".** Since Windows 8, "Shut down" hibernates the
  kernel instead of ending it unless Fast Startup is off, and Fast Startup is on by default. A player
  who shuts down every night can have a Windows that started days ago. Presented badly, "started 3 days
  ago" reads as "has not restarted since, why?".
- **Every time in the report is on some clock**, and a clock can be changed.

## Decision

### 1. The source: `GetTickCount64`

Microsoft, [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64):
*"Retrieves the number of milliseconds that have elapsed since the system was started."* The same page:
*"To obtain the time the system has spent in the working state since it was started, use the
QueryUnbiasedInterruptTime function."* And
[Interrupt Time](https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time): *"To retrieve
elapsed time that accounts for sleep or hibernation, use the GetTickCount or GetTickCount64 function, or
use the System Up Time performance counter."*

So the boot time is **the scan's clock minus `GetTickCount64`**, truncated to the second on both sides,
and "boot" means exactly what that count means: the moment the running kernel started counting, with
time spent asleep or hibernated counted as elapsed.

`LiveHost` calls it in `rongroi-host-windows/src/boot_time.rs`, gated on `Win32_System_SystemInformation`
alone (read from `windows` 0.62.2: `pub unsafe fn GetTickCount64() -> u64` in
`src/Windows/Win32/System/SystemInformation/mod.rs`). The function has no failure to report. `scan::run`
reads it **before** the collectors: `generated_at` is taken by the caller immediately before `run`, and
the `evtx` collector alone may run for 30 seconds, which would otherwise move the start that much earlier.

| Candidate | Verified | Why not |
|---|---|---|
| `QueryUnbiasedInterruptTime` | *"The unbiased interrupt-time count does not include time the system spends in sleep or hibernation."* ([doc](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime)) | Subtracting a count that leaves out sleep from the current clock gives a start **later** than the real one, by however long the PC slept. That is a wrong time, not a different definition |
| `NtQuerySystemInformation(SystemTimeOfDayInformation)` | *"Returns an opaque SYSTEM_TIMEOFDAY_INFORMATION structure that can be used to generate an unpredictable seed for a random number generator."* The layout is given as `BYTE Reserved1[48]` ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)) | A `BootTime` field in it is known only from outside Microsoft's documentation. ADR 0011 uses this function for a class whose structure **is** documented; this one is not |
| WMI `Win32_OperatingSystem.LastBootUpTime` | *"Date and time the operating system was last restarted."* ([doc](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem)) | COM and WMI initialisation, a service dependency and a much larger surface for one number. It is used below as the **comparison** for the measurement instead |
| The System log's own boot record | Measured below | A record payload, which the Event Log parser drops (ADR 0018), and stamped with the clock as it was at boot — on the test machine that was 7 hours off |
| `HiberbootEnabled` (whether Fast Startup is on) | Read on the test machine, read-only | A setting today, not how the last start happened: a machine with it on still cold-starts on every Restart. Reporting it would invite exactly the inference this ADR warns against, with no more information. Not read |

### 2. It lives in the report header, not in an observation

`ReportHeader.boot_time`, beside `generated_at`, `os_build` and `elevated`:

```json
"boot_time": { "state": "measured", "booted_at": "2025-12-28T21:56:56Z", "seconds_since_boot": 266584 }
"boot_time": { "state": "unmeasured", "reason": "not_windows" }
```

`seconds_since_boot` is what was measured; `booted_at` is derived from it and `generated_at`.

| Alternative | Why not |
|---|---|
| An observation from a new collector | No rule reads it, so it would be an unmatched observation: listed at the bottom of Self mode and **counted, never shown**, in SS mode (ADR 0014) — far from the rows it explains and absent from the view where staff read those rows. And a rule could then match it, which is what this ADR refuses: "started recently" and "has not restarted" are both ordinary, so a rule on either is a verdict about an innocent fact |
| `booted_at: Option<String>` like `os_build` | `None` would not say why. `unmeasured` with one of the twelve reasons (ADR 0030) says it the way every other result does, and the CLI and the app render it with the same sentence |

**Unmeasured, never a guessed time.** A host that is not Windows is `not_windows`. A Windows host whose
read fails is `read_failed`, the mapping `posture` uses for a failed platform read; on a live host
`GetTickCount64` cannot fail, so it is reached only by a fixture that did not describe the count. A
`generated_at` that does not parse, or a count that reaches before the start of the clock, is
`read_failed` rather than a made-up time.

**Schema.** Additive, and `REPORT_SCHEMA_VERSION` stays at 1, as for `own_traces`, `unmatched` and
`expected`: the field is `#[serde(default)]`, and a report written before it existed reads back
`unmeasured` / `not_attempted` — nothing was tried, which is what that report did.

**Snapshots.** Every one of the 15 report snapshots moves by exactly the new header field and nothing
else, reviewed diff by diff. `secure-boot-off` now describes `milliseconds_since_boot: 266584000`, an
invented value, so its two snapshots — the ones the desktop tests render — carry the measured shape;
the other 13 carry `unmeasured` / `read_failed` because their fixtures describe no count.
`FixtureHost` answers `Unsupported` when the field is absent, as it does for code integrity and the TPM.

No baseline host changes and `check-baseline` is unaffected: no rule can name a header field.

### 3. Shown in both modes, and named in the consent question

The boot time names no one and says nothing about who used the PC. SS mode's filter is about evidence
(ADR 0027), and this is context for the times on exactly the rows SS mode lists, so hiding it from staff
would remove it from the one view that needs it.

It is still a new read, and it is a small fact about a person's day — roughly when the PC was last
restarted — and two reports taken before the next restart carry the same value. So the consent question
says it, in the CLI and the app, in both languages: *"when Windows last started, which is shown to staff
as one time at the top of the report"*. `consent_names_every_kind_of_source` checks it beside the
collectors, and `PRIVACY.md` says what it is and what it is not.

**Accepted by the owner on 2026-09-13**, with this weighed: a `found` Event Log row that SS mode lists already
carries `first_seen` and `last_seen`, and `rongroi_core::view` redacts user paths, not times, so two reports could already be
matched through those rows. The boot time adds one more such value; rounding it would blur the
before-or-after comparison it exists for.

### 4. One line, with its caveat on the same line

CLI (English):

```
Windows start: 2025-12-28T21:56:56Z, 3d 2h 3m before this scan. Not reset by "Shut down" with Fast Startup (the Windows default), sleep or hibernation; reset by a restart.
```

In the app it is one `Windows start` entry in the header list, the same sentence in two parts. An
unmeasured value is `Windows start: not measured — <reason>`. Times stay UTC, like every other time in
the report (CONVENTIONS §2), so that a reviewer compares like with like.

The caveat is on the line itself rather than in a guide, because a reviewer who has not read the guide is
the one who would read "3d" as a finding. The screenshare guide's header section explains it at more
length, in English and Thai, and its "what not to conclude" table gains both directions: a start days ago
does not mean the player avoided restarting, and a start minutes ago does not mean they restarted to hide
something.

### What "boot" does not mean — written down

- **Fast Startup.** Microsoft,
  [System power states](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states):
  *"Fast startup logs off user sessions, but the contents of kernel (session 0) are written to hard
  disk."* *"In Windows, fast startup is the default transition when a system shutdown is requested. A
  full shutdown (S5) occurs when a system restart is requested or when an application calls a shutdown
  API."* And, in the same page's note to driver authors: *"the up time between kernel reboots may be
  significantly longer than on previous versions of the OS because the kernel, drivers, and services are
  preserved and restored, not re-started, on user-initiated sleeps and shutdowns."* The driver
  documentation says the same from the other side: a fast startup loads the hibernation file into
  memory, where a cold startup builds the kernel image from the kernel file
  ([Distinguishing Fast Startup from Wake-from-Hibernation](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation)).
- **Sleep and hibernation** do not reset the count, and the time spent in them is counted (the Interrupt
  Time sentence above).
- **A clock change.** `booted_at` is the scan's clock minus an elapsed count. Microsoft says the
  interrupt-time count *"is not subject to adjustments by users or the Windows time service"*; the
  `GetTickCount64` page does not say it of that function in those words, and the measurement below is
  what shows it for this one: a 7-hour clock change after the start did not move the count. So
  `booted_at` is expressed on the clock as it is **now**, and a record written before a clock change
  carries a time on the old clock and does not line up with it.
- **A modified operating system can report anything.** ADR 0002's premise applies unchanged: the player
  controls the machine, and this value is what Windows told the program.

## Measured

On one Windows 11 machine (build 26220), 2026-09-13, read-only — nothing was changed, and no event
content left the machine. The scan used a cross-built CLI from this branch.

| | Elevated | Limited token (`schtasks /rl LIMITED`) |
|---|---|---|
| `boot_time.booted_at` | `…T01:24:12Z` | `…T01:24:12Z` |
| `Win32_OperatingSystem.LastBootUpTime`, read before and after | `…T01:24:12.12Z` | `…T01:24:12.12Z` |

The two agree to the second, with and without administrator rights. `GetTickCount64` needs none.

**The System log disagreed by 7 hours, and the log itself says why.** The most recent
`Microsoft-Windows-Kernel-General` event 12 (the kernel's start record) was stamped, and gave its own
`StartTime`, 7 hours **earlier** than both values above. The same log holds a Kernel-General event 1 —
a system time change — whose `OldTime` and `NewTime` are 7 hours apart, written after that start. The
clock was changed after Windows started; the record written before the change carries the old clock,
and a boot time worked out from today's clock does not. This is the case the guide warns about, and it
happened on the first machine looked at. Why the clock was 7 hours off is **not established**.

**Fast Startup is on there and is the common case.** `HiberbootEnabled` under
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power` is `1`. Of the 48
`Microsoft-Windows-Kernel-Boot` event 27 records in the System log (the log reaches back a month), 27
carry boot type `1` and 21 carry `0`. That `1` means a Fast Startup and `0` a cold start is published by
third parties (Winaero, TheWindowsClub), **not by Microsoft**. On this machine it is consistent with the
log around it: from 2026-08-30 on, every type-0 record has a Kernel-General event 12 in the same second
and no type-1 record has one, and each of the four most recent type-1 records has a
`Power-Troubleshooter` event 1 — "the system has returned from a low power state" — within a second.

## What is not established

- ~~That `GetTickCount64` keeps counting across a Fast Startup on a real machine was not measured.~~
  **Amended 2026-09-14 — measured, without shutting anything down for the test.** The same Windows 11
  machine (build 26220) was shut down by its owner in the ordinary way the evening before and powered on
  the next morning. Read-only, from its System log and two clocks: `User32` event 1074 recorded a
  shutdown of type "power off"; `Kernel-Power` event 42 followed; the next morning `Kernel-Boot` event
  27 recorded boot type `1`, and no `Kernel-General` event 12 (operating system start) was written in
  between. After that start, the boot time derived from `GetTickCount64` and
  `Win32_OperatingSystem.LastBootUpTime` still agreed to the second and both still named the previous
  morning, about 26 hours before the reading. A "Shut down" with Fast Startup on did not reset the count,
  as the Microsoft sentences quoted above say. Still reading rather than measurement: what the numeric
  `TargetState`/`EffectiveState` values in event 42 name. Original text:
  *The last start on the test machine was a cold one, and producing a Fast Startup there means shutting the
  owner's PC down, which is a change this project does not make on it. The claim rests on the Microsoft
  sentences quoted above.* The EventLog service's daily uptime record (event 6013) on the same machine
  did **not** return to near zero after the type-1 starts and did after every type-0 one — but which
  counter event 6013 reads is not documented, and the clock changes above make its day-to-day
  differences unusable for deciding whether hibernated time is included.
- **Whether the hibernated interval of a Fast Startup is counted as elapsed** is covered by
  Microsoft's "accounts for sleep or hibernation" sentence and not by a measurement.
- **Modern Standby (S0 low-power idle)** was not examined. Microsoft describes it as part of the working
  state, so it would not reset the count either; that is reading, not measurement.
- **One machine, one build.** Another build, a virtual machine or a machine with a different clock
  source may answer differently.

## Consequences

- `rongroi_host::BootTimeSource` is a new source trait and `Host` requires it. `NonWindowsHost` answers
  `Unsupported`; `FixtureHost` reads `milliseconds_since_boot` and answers `Unsupported` without it.
- `rongroi-host-windows` gains the `Win32_System_SystemInformation` feature and one `unsafe` call with a
  `SAFETY` comment.
- `ReportHeader` gains `boot_time`; `apps/desktop/src/types.ts` mirrors it. The CLI prints one line
  above the evidence; the app adds one entry to the header list. `docs/architecture.md`, `PRIVACY.md`,
  `CONVENTIONS.md` (glossary: **boot time**), both consent texts and both screenshare guides say what it
  is.
- A future rule cannot use it, by construction. A future change that wants to reason about starts —
  "the log was cleared after the last start" — has to argue for that in its own ADR, against the Fast
  Startup and clock-change rows above.
