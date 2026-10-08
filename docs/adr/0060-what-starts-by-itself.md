# ADR 0060 — What starts by itself, and what Defender is told not to scan

- Status: accepted — the owner decided the nine questions below on 2026-09-30
- Date: 2026-09-30
- Amended: 2026-09-30, with a measurement on a Windows 11 PC ("Measured on a Windows 11 PC (2026-09-30)")
- Amended: 2026-10-08, by ADR 0064: section 4 holds for this collector; a full scan's `powershell_text`
  is the one place a program's arguments are read, and only into kinds of words

## Context

`driver_service` (ADR 0048) lists the kernel and file-system drivers registered under
`HKLM\SYSTEM\CurrentControlSet\Services`, with each driver file's SHA-256. It deliberately stops at `Type` 1
and 2. A program that Windows starts **by itself** — when the PC boots, when a person signs in, or on a
schedule — is registered in other places, and nothing in this program reads them:

1. **Services** that are programs rather than drivers: `Type` `0x10` (own process) and `0x20` (shared
   process), with the per-user variants built on them. Same registry key as `driver_service`.
2. **`Run` and `RunOnce`** under `HKLM`, under `HKLM\SOFTWARE\WOW6432Node` (32-bit programs) and under
   `HKCU`: a command line Windows runs at sign-in.
3. **Scheduled tasks**: a program the Task Scheduler starts on a trigger — boot, sign-in, a time, an event.
4. **Microsoft Defender exclusions**: not a program that starts, but the setting that tells the antivirus
   not to look at a folder, a process or a file extension. The plan groups it here because the same
   guides that set a program to start by itself set it, and because P0 (2026-09-16) measured that it can be
   read.

A registration is a standing configuration, not a record that something ran: the evidence it gives is
`posture`, like `driver_service`'s. Every registration on an ordinary PC belongs to something the person
installed, and a reviewer needs two things to tell those apart from the rest: **what file** would start
(its path, SHA-256 and embedded signature, as `fivem_dir` reports them under ADR 0035) and **whether it
starts by itself**.

This ADR decides how to read the four places, what reaches a report, and the two rules; the owner's
decisions are at the end. It records what a GitHub-hosted runner and a Windows 11 PC (build 26220) showed.

## Measured on a runner

**Where and how.** A GitHub-hosted runner, image `windows-2025-vs2026` version `20260925.250.1`, Windows
Server 2025 Datacenter build 26100, on 2026-09-30, from a throwaway branch that was deleted afterwards:
workflow runs [`36699375619`](https://github.com/aeterna/aeterna-rongroi/actions/runs/36699375619),
[`36699639698`](https://github.com/aeterna/aeterna-rongroi/actions/runs/36699639698) and
[`36700048738`](https://github.com/aeterna/aeterna-rongroi/actions/runs/36700048738), three passes of the
same probe with counters added. The probe was a Windows PowerShell 5.1 script with a small C# part for
SHA-256 and for `WinVerifyTrust` with the offline settings and result classes of
`rongroi_host_windows::signature` (ADR 0035). It printed counts, forms, classes of path and timings. On the
runner only, it also printed the paths the proposed rule would match and the Defender exclusions: they
belong to a published image and to no person. It is not kept in this repository. It ran under two tokens,
as ADR 0046's runner measurement did:

- **elevated**: the runner's own token (administrator, UAC off);
- **standard user**: a local account created for the run, not in Administrators, running the probe
  through a scheduled task.

The runner and the account were discarded with it. A path is classed against the runner's own
`%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%` and `ProfilesDirectory`.

### Rights

| Read | Elevated | Standard user |
|---|---|---|
| Keys under `...\Services`, and `Type`, `Start`, `ImagePath` in each | 764 of 764 | 764 of 764 |
| `Parameters\ServiceDll` of the program services | 205 | 201 — 4 `Parameters` keys refused |
| `Run` / `RunOnce` under `HKLM`, `HKLM\...\WOW6432Node`, `HKCU` | read | read |
| Listing `%SystemRoot%\System32\Tasks` and reading its XML files | 116 folders, 211 files, all parsed | **refused** at the top folder |
| Task Scheduler COM API (`Schedule.Service`, hidden tasks included) | 209 tasks | **148 tasks**, no error |
| `HKLM\...\Schedule\TaskCache\{Tree,Tasks,Boot,Logon,Plain}` | read | refused |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,Processes,IpAddresses,TemporaryPaths}` | read | **refused**, all five |
| The same under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` | absent | absent |
| Every resolved file, hashed and its signature checked | yes | yes |

The COM API answered a standard user with fewer tasks and no error. One of its 148 was the probe's own
task, registered for that account after the elevated pass had run. A reader of that API cannot tell "these
are all the tasks" from "these are the ones this account may see", which is the collapse ADR 0002 and
ADR 0030 exist to prevent. The files answer the same account with a refusal.

### Services

Of 764 keys: 422 drivers (`Type` 1, 2), 63 with no `Type`, and **278 program services** — `0x10` 76,
`0x20` 167, `0x110` 1, `0x120` 1, `0x50` 1, `0x60` 18, `0xd0` 1, `0xe0` 13. `Start`: automatic (2) 72–73,
on demand (3) 181, disabled (4) 24–25, the same image in different passes. 96 have a `TriggerInfo` key and
18 `DelayedAutostart`.

| `ImagePath` form | Services |
|---|---|
| a drive letter, a space, then arguments; the file is the first word | 217 |
| a drive letter, no space | 40 |
| quoted, with or without arguments | 21 |
| with a `%…%` variable (almost all `%SystemRoot%`/`%windir%`) | 243 of the above |
| `REG_EXPAND_SZ` / `REG_SZ` | 274 / 4 |

213 run in `svchost.exe`; 205 name a `ServiceDll`, all under `%SystemRoot%`. 225 have arguments. Every
`ImagePath` resolved to a file that existed, except 2 whose file is missing.

### Run and RunOnce

`HKLM\...\Run` held 2 values, both `REG_EXPAND_SZ` with a variable, both files under `%SystemRoot%` (one
with a valid embedded signature, one with none). `RunOnce`, both `WOW6432Node` keys and both `HKCU` keys
held nothing. Explorer's `StartupApproved\Run` held one binary value per `Run` value, 12 bytes, first byte
`0x04`; what the bytes mean has no Microsoft-documented source, and this ADR does not read them.

### Scheduled tasks

211 task files. 87 `Exec` actions (a program) and 126 `ComHandler` actions (a COM class). Triggers:
WNF state change 82, logon 34, boot 24, time 24, calendar 13, event 8, session change 7, registration 3,
idle 2, none 54. 83 disabled, 59 hidden. 59 of the 87 `Exec` actions have an `Arguments` element.
Principals: 139 service SIDs, 64 groups, 5 account SIDs, 7 account names. **4 task file names carry an
account SID.**

`Exec` commands: 72 a drive-letter path with no space, 9 an unquoted path with spaces resolved at a longer
prefix, 2 quoted, 2 relative, 2 an unquoted path with spaces that named no existing file; 71 of them through
a `%…%` variable. 3 files were missing. 15 start a Windows program that runs
a script or a library named in its arguments (`rundll32` 11, `cmd` 3, `cscript` 1); 10 of those name a
drive-letter file in their arguments, all under `%SystemRoot%`.

### Microsoft Defender exclusions

Elevated: `Paths` held 2 values, `C:\` and `D:\` — the runner image excludes both of its drives.
`Extensions`, `Processes`, `IpAddresses`, `TemporaryPaths` held none. `Get-MpPreference` listed 2 paths
elevated (whether the same two was not compared), and answered the standard user with its withheld marker instead of a list.

### What the proposed rules would match on the runner

**Starts by itself, no valid embedded signature, outside `%SystemRoot%` and `%ProgramFiles%`**: every
matching file had no embedded signature (none was `invalid`).

| Place | Files | What they are |
|---|---|---|
| services (any `Start`) | 2 | `C:\tools\Apache24\bin\httpd.exe`, `C:\ProgramData\Chocolatey\lib\NSSM\tools\nssm.exe` — both on demand, so neither starts by itself |
| tasks, any trigger | 2 | `C:\ProgramData\GitHub\Primer\primer.exe`, `C:\ProgramData\GitHub\HostedComputeAgent\hosted-compute-agent` |
| tasks, enabled with a boot or logon trigger | 1 | `primer.exe` |
| `Run` | 0 | — |

**A Defender exclusion covers a FiveM folder**: the `C:\` root covers `%LOCALAPPDATA%\FiveM`, which the
runner does not have; the `D:\` root does not (corrected on 2026-10-01 from "both drive roots", after the
collector's first reading of the runner in #121).

So **both proposed rules would read `found` on a baseline rebuilt from this runner**: the first on
GitHub's own provisioning agent, the second on the image's whole-drive exclusions. Both are ordinary
causes the rules' `falsepositives` name (section 8).

### Cost

The first (elevated) pass read the files cold; the standard-user pass read files the system had cached,
so only the first says anything about a scan.

| Pass | Distinct files | Bytes | Hashing | Signature checks |
|---|---|---|---|---|
| run 1 | 300 | 420 MB | 49.4 s | 0.43 s |
| run 2 | 300 | 420 MB | 49.6 s | 0.42 s |
| run 3 | 300 | 420 MB | 104.0 s | 0.35 s |
| run 3, files under `%SystemRoot%` | 271 | 281 MB | 77.5 s | — |
| run 3, files outside it | 29 | 140 MB | 26.5 s | — |

The signature checks ran straight after each file was hashed, so they read cached files; their cold cost is
not measured. Listing and parsing the 211 task files took 4.0–4.9 s in PowerShell, and the COM API 0.5–0.9 s.

## Measured on a Windows 11 PC (2026-09-30)

**Where and how.** A Windows 11 PC (build 26220), with the owner's permission, running the same probe as
the runner's third pass in Windows PowerShell 5.1: once elevated, and once as the signed-in account's
**limited** token through a scheduled task at run level `LIMITED`. The probe printed counts, forms,
classes of path and timings only — no value name, task name, path, signer, user name, SID or argument.
Its last line reported the task and its work folder deleted. The output is not kept in this repository.
In P0 (2026-09-16) the same PC's Defender `Exclusions\Paths` had been read elevated (6 values) and refused
to a limited token.

### Rights: elevated against limited

| Read | Elevated | Limited |
|---|---|---|
| Keys under `...\Services`, and `Type`, `Start`, `ImagePath` in each | 872 of 872 | 872 of 872 |
| `ServiceDll` of the program services | 230 | 227 — 3 `Parameters` keys refused |
| `Run` / `RunOnce` under `HKLM`, `HKLM\...\WOW6432Node`, `HKCU` | read | read, the same counts |
| Listing `%SystemRoot%\System32\Tasks` | 153 folders, 296 files; **1 file refused**, 295 parsed | **refused** at the top folder |
| Task Scheduler COM API, hidden tasks included | 289 tasks | **214 tasks**, no error |
| `TaskCache` keys | read (`Tasks`: 289 subkeys) | refused |
| Defender `Exclusions\*` (all five) | read | **refused**, all five |
| Defender's policy keys | absent | absent |
| Resolved files, hashed and signature checked | 410 distinct | 393 distinct (fewer tasks seen) |

So the runner's findings hold for an administrator's limited token on a PC, not only for a standard
account: tasks read from files are `not_admin`, the COM API gives a quarter fewer tasks with no error, and
Defender's exclusions are `not_admin`. One more fact only the PC showed: **an elevated read was refused
one task file** of 296 on an ordinary PC.

### Counts

- **Services**: 343 program services (`0x10` 111, `0x20` 171, `0x110` 7, `0x120` 1, `0x210` 3, `0x50` 1,
  `0x60` 24, `0xd0` 1, `0xe0` 24). `Start` automatic 99, on demand 239, disabled 5; 122 with `TriggerInfo`,
  21 delayed. All 343 `ImagePath` values `REG_EXPAND_SZ`; 267 with a variable; 264 with arguments; 249 in
  `svchost.exe`. Forms: first word then arguments 254, quoted 47, no space 39, **unquoted with a space
  resolved at a longer prefix 2**, unresolved 1 (1 file missing). 230 `ServiceDll`, all under
  `%SystemRoot%`, **201 of them with no embedded signature**. Of the 99 that start automatically, the image
  file is under `%SystemRoot%` for 76, `%ProgramFiles%` 20, `%ProgramData%` 3; the 4 with no embedded
  signature are all under `%SystemRoot%`.
- **Run**: `HKLM` 9 values, `WOW6432Node` 2, `HKCU` 13; every `RunOnce` key present and empty. `HKCU`'s 13:
  7 under `%ProgramFiles%`, 6 under the profile's `AppData\Local`, **every one with a valid embedded
  signature**; `HKLM`'s: 7 under `%ProgramFiles%`, 2 under `%SystemRoot%` (one with no embedded
  signature); `WOW6432Node`: 1 `%ProgramFiles%`, 1 `%ProgramData%`, both valid. 11 of the 24 have
  arguments. `StartupApproved` first bytes: `HKCU\...\Run` `0x02` 8, `0x03` 18, `0x00` 1 (27 values for 13
  `Run` values); `HKLM\...\Run` `0x02` 4, `0x03` 9, `0x06` 1; `Run32` `0x02` 2, `0x03` 7 — not the runner's
  `0x04`. What the bytes mean is still not documented.
- **Tasks** (files, elevated): 138 `Exec` and 159 `ComHandler` actions; 94 `Arguments` elements. Triggers:
  WNF 111, logon 47, time 43, calendar 28, boot 23, event 12, registration 10, session change 8, idle 6,
  none 64; 49 disabled, 62 hidden. Principals: 176 service SIDs, 89 groups, 20 account SIDs, 13 account
  names. **3 task file names carry an account SID.** `Exec` files: `%SystemRoot%` 100, `%ProgramFiles%` 23,
  other folders on the system drive 7, `%ProgramData%` 4, the profile outside `AppData` 2, `AppData\Local`
  1, `AppData\Roaming` 1; 19 missing, 1 unreadable. 13 start a Windows script or library host (`rundll32`
  11, `cmd` 1, `wscript` 1); 7 of those name a file in their arguments, 6 under `%SystemRoot%` and 1 in
  another folder on the system drive.
- **Defender**: `Paths` 6 values (under a profile outside `AppData` 3, `%SystemRoot%` 2, another folder on
  the system drive 1), no wildcard and no variable; `Extensions`, `Processes`, `IpAddresses`,
  `TemporaryPaths` empty; `Get-MpPreference` listed 6. **None of the 6 is, contains or lies inside a FiveM
  folder**, and all three FiveM folders exist on this PC. The probe also counted 3 non-empty
  `InstallFolder*` values under the subkeys of `HKLM\SOFTWARE\Rockstar Games` and its `WOW6432Node` twin;
  none of the 6 exclusions covers any of them.

### What the proposed rules would match

- **Autostart: 1 row.** A scheduled task, enabled, with a boot or logon trigger, whose file is under the
  profile outside `AppData` and has no embedded signature. The same one task is the only match with any
  trigger. No service and no `Run` value would match. What the program is was not printed.
- **Defender: `not_found`** — no exclusion covers a FiveM folder.

### Cost

| Pass | Distinct files | Bytes | Hashing | Signature checks | Whole probe |
|---|---|---|---|---|---|
| elevated | 410 | 857 MB | 3.0 s | 2.3 s | 15.9 s |
| of which under `%SystemRoot%` | 322 | 233 MB | 1.2 s | — | — |
| of which outside it | 88 | 624 MB | 1.9 s | — | — |
| limited | 393 | 854 MB | 1.4 s | 2.1 s | 7.5 s |

The PC was in use, and whether the files were in the cache was not controlled, so these times are not a
cold scan; the runner's cold passes took 49–104 s for half the bytes. Listing and parsing 296 task files
took 6.5 s in PowerShell, the COM API 1.9 s.

## Decision

### 1. A new collector, `autostart`, not a wider `driver_service`

`driver_service` is not widened to program services:

- **Its rule would change meaning.** The LOLDrivers rule compares every `driver_service` observation's
  `sha256`; its `not_found` says "no registered driver is on the list". With programs in the collector that
  sentence would describe something else.
- **Its budget would be spent on something else.** Its 30 s already covers 8.7–15.5 s of driver hashing
  (ADR 0048). The runner's program services and their service DLLs took most of the 49–104 s above. A
  budget spent on them would leave drivers unhashed, and `budget_spent` is always listed in SS mode.
- **Its resolver refuses most of these forms.** ADR 0048 treats `%…%`, a quoted path and a path followed by
  arguments as unknown forms. 243 of 278 program services have a variable and 225 have arguments.

`autostart` is a new collector with the discriminator `location` (ADR 0044): `service`, `run`, `task`.
A place that cannot be read is a gap for that place only, so a scan without administrator rights still
answers for services and `Run` while tasks are `not_admin`. The resolver's refusals of `.`, `..`, empty
segments, trailing dots and spaces, alternate data streams and `Documents and Settings` (ADR 0048) move to
a module both collectors use, with `driver_service`'s behaviour unchanged.

### 2. The three places

- **`service`**: every key directly under `HKLM\SYSTEM\CurrentControlSet\Services` whose `Type` has bit
  `0x10` or `0x20` and neither driver bit. Read: `Type`, `Start`, `ImagePath`, whether a `TriggerInfo` key
  exists, and `ServiceDll` in `Parameters` or in the key. Nothing else in the key.
- **`run`**: the values of `Run` and `RunOnce` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`,
  `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion` and
  `HKCU\Software\Microsoft\Windows\CurrentVersion`. `HKCU` is the account this program runs as, with the
  caveat ADR 0038 states: a scan restarted with another administrator's password reads that
  administrator's. Other accounts' hives are not read.
- **`task`**: the XML files under `%SystemRoot%\System32\Tasks`, recursively. Read: the task's path (its
  file's path below that folder), `Settings/Enabled`, the kinds of its triggers, and each `Exec` action's
  `Command`. **Never read into a report**: `Arguments`, `WorkingDirectory`, the principal's user id,
  `Author`, `Description`, or any other element. A refused top folder makes the place `not_admin`
  without administrator rights and `access_denied` with them. A single refused file — which an elevated
  read met on the PC, 1 of 296 — is a gap `access_denied` confined to `task` (ADR 0044), not a place
  that could not be read (owner decision 9). The XML is parsed in `rongroi-parsers`, pure
  and fuzzed like every parser (ADR 0013); the files' encoding was not recorded by the probe.

The COM API is not used: it answers a standard user with a subset and no error (measured), it is a call
into another process like the Event Log service's (ADR 0042), and it would need COM and the Task Scheduler
bindings as new `windows` features. The `TaskCache` registry keys are not used either: their layout has no
Microsoft-documented source, and a standard user was refused them as well.

### 3. From a command line to a file

| Form | File | Measured |
|---|---|---|
| `"<path>"` followed by anything | the quoted path | 21 services, 2 tasks |
| `\SystemRoot\…`, `\??\X:\…`, `X:\…` with no space, relative | as ADR 0048 resolves it | 40 services |
| `X:\…` with a space, unquoted | the shortest prefix ending at a space that names an existing file, with `.exe` added when it has no extension — the order `CreateProcessW`'s documentation gives for an unquoted command line | 217 services at the first word; 9 tasks at a longer prefix |
| a `%…%` variable | expanded, then as above, for a fixed list of machine variables (`SystemRoot`, `windir`, `SystemDrive`, `ProgramFiles`, `ProgramFiles(x86)`, `ProgramW6432`, `ProgramData`, `CommonProgramFiles`), and for `HKCU` values and tasks whose principal is this account, that account's own profile variables | 243 services, 71 tasks, 2 `Run` |
| anything else | none: a `read_failed` gap on `sha256` and `signature`, as ADR 0048 | 0 |

For a service with a `ServiceDll`, the file described is the DLL — the code that runs — and a field says
so. For a task, `Command` is a program alone, so the quoted-path reading applies to it whole.

### 4. Arguments are never reported

Arguments are where secrets live: a token, a password or an address passed to a program at start. The
collector reads a command line only to find where the program's path ends, and **nothing after it reaches
an observation**, not even whether there was anything. Task `Arguments` elements are not read.

*Amended 2026-10-08 by ADR 0064.* This section is unchanged for `autostart`. A full scan's
`powershell_text` reads the command lines Windows PowerShell was started with, as its own log keeps them,
and sorts their words into a fixed list of kinds; no substring reaches an observation except a download's
host, behind its own SS-mode question. It is the one exception, and it reads no task's or service's
arguments.

This has a cost, weighed in owner decision 4. Dropping arguments means the report describes the
program that starts, not what that program is given to run. When that program is one Windows ships for
running a script or a library (`cmd`, `powershell`, `wscript`, `cscript`, `rundll32`, `mshta`,
`regsvr32`), the row names that Windows program, under `%SystemRoot%` with its signature. On the runner,
15 task actions were of that kind, and the 10 that named a file named one under `%SystemRoot%`.

### 5. The observation

| Field | Kind | Places | Value |
|---|---|---|---|
| `location` | text | all | `service`, `run` or `task` |
| `service` | text | `service` | the key's name, as `driver_service` reports it |
| `entry` | text | `run`, `task` | the `Run` value's name, or the task's path (`\Folder\Name`), as read |
| `hive` | text | `run` | `machine`, `machine_32` (`WOW6432Node`) or `user` |
| `run_once` | boolean | `run` | whether the value is in `RunOnce` |
| `start` | number | `service` | `Start` as stored, as `driver_service` reports it |
| `trigger_start` | boolean | `service` | whether a `TriggerInfo` key exists |
| `service_dll` | boolean | `service` | whether `path` is the service's `ServiceDll` rather than its `ImagePath` |
| `enabled` | boolean | `task` | `Settings/Enabled`; an absent element reads as the Task Scheduler schema's default, true (not re-read for this ADR) |
| `triggers` | text | `task` | the kinds of its triggers, sorted and joined with `,`: `boot`, `logon`, `time`, `calendar`, `event`, `idle`, `registration`, `session_change`, `wnf`, `other`; empty when it has none |
| `starts_by_itself` | boolean | all | section 6 |
| `path` | text | all | the resolved file, drive-letter form; absent when section 3 finds none |
| `path_kind` | text | all | `windows` (under `%SystemRoot%`, except its `Temp` folder), `program_files`, `program_data`, `user_profile` (under a profile root, ADR 0049) or `other` |
| `sha256`, `signature`, `signer`, `signer_cert_sha256` | text | all | as `fivem_dir` reports them (ADR 0035); section 7 says when they are absent |

One observation per service, per `Run` value, and per `Exec` action of a task. A task whose actions are
all COM handlers (126 of 213 actions on the runner) is not reported in this change:
a handler is a class id, and the file behind it is another registry read this ADR does not propose.

### 6. What "starts by itself" means

- `service`: `Start` is 0, 1 or 2, or `Start` is 3 and `trigger_start` is true. Disabled (4) never does.
- `run`: always. Explorer's own "disabled" state is in `StartupApproved`, which is not read (above), so an
  entry the person switched off in Task Manager still reads true. The rule's `falsepositives` say so.
- `task`: `enabled` is true and it has at least one trigger.

It is a field rather than three rules because a rule has no `or` between fields (ADR 0029), and one rule
is one row for a reviewer to read.

### 7. Hashing, signatures and the budget

Two options were weighed; the owner chose B (owner decision 5):

- **A — hash and check every file.** 300 files, 420 MB, 49–104 s cold on the runner. A budget of its own
  would be spent on nearly every scan, and a spent budget is a `budget_spent` gap on `signature` that makes
  the rule `unmeasured` and listed in SS mode.
- **B — do not hash or check files whose `path_kind` is `windows`** (chosen). They are reported with
  `path` and `path_kind`, and `sha256` and `signature` are absent with no gap: not read by design, as a
  missing file is not a gap in ADR 0048. The embedded check says little there anyway — 178 of 205 service
  DLLs under `%SystemRoot%` carry **no embedded signature**, because Windows signs its own files through a
  catalog this program does not read (ADR 0035). Every other file is hashed and checked under a 30 s budget
  of its own, checked before each file as `driver_service` does, visiting the files of `starts_by_itself`
  entries first and hashing a path once however many entries name it. On the runner that is 29 files,
  140 MB, 26.5 s in the slowest pass.

Under B, a file under `%SystemRoot%` that is not Microsoft's is described by its path alone. `windows`
excludes `%SystemRoot%\Temp`, a temporary folder rather than where Windows keeps its own programs.

### 8. The rule on autostart

`rules/autostart/outside-windows/no-valid-embedded-signature/rule.yaml`, `posture`, `experimental`:

```yaml
match:
  starts_by_itself: true
  signature: [no_embedded_signature, invalid]
  path_kind: [program_data, user_profile, other]
```

- **Title**: a program that starts by itself has no valid embedded signature and is outside the Windows and
  Program Files folders. Never "unsigned" (CONVENTIONS.md, `signature`).
- **`falsepositives`**: programs installed per user into AppData — launchers, chat and voice apps, cloud
  sync clients, and above all their updaters and helpers; peripheral, RGB, fan and overclocking
  utilities; service wrappers and servers from a package manager (the runner's NSSM from Chocolatey and an
  Apache web server); management and provisioning agents (the runner's own GitHub agent); open-source and
  self-built tools, which are often not signed; a file signed through a catalog, which this check does not
  read; an entry switched off in Task Manager, which this program cannot tell from one that is on. A
  `found` row says a program not signed the way this checks is set to start without being asked; it does
  not say what the program does.
- **`unmeasured_when`**: `not_windows` and `access_denied` (owner decision 9): an ordinary PC produced it
  with administrator rights. `not_admin` is a scope statement already.
- `unverifiable_offline` is not matched: it is a fact about the check, not the file (ADR 0035).

### 9. A second collector, `defender_exclusion`

Defender's exclusions are a setting, not a program, and a limited token is refused the whole read
(measured on the runner and the PC), so they are a collector of their own rather than a fourth
`location`:

- It reads the value **names** of `Exclusions\Paths`, `Exclusions\Processes` and `Exclusions\Extensions`
  under `HKLM\SOFTWARE\Microsoft\Windows Defender` and under
  `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, and the number of values in `IpAddresses`. The
  addresses themselves are not read: an address can name a person's or a company's network.
  `TemporaryPaths` is not read; what writes it has no Microsoft-documented source here.
- One observation per exclusion: `kind` (`path`, `process`, `extension`), `set_by` (`settings` or
  `policy`), `exclusion` as written, and for a path or a process `covers_fivem` (below). One observation
  per key with `ip_addresses`, the count.
- Refused without administrator rights: the run is `Unmeasured { not_admin }`. Refused with them:
  `access_denied`, which a rule does not declare, so SS mode lists it. Microsoft documents a policy that
  limits who may see the list (not re-read for this ADR); how the registry answers an elevated read under
  it is not measured.
- **`covers_fivem`**: whether the exclusion, with `%…%` expanded as this account's, is one of FiveM's
  folders, a folder above one (a drive root included), or a folder inside one. FiveM's folders are the
  ones `fivem_dir` already names: `%LOCALAPPDATA%\FiveM`, `%LOCALAPPDATA%\FiveM for GTAV Enhanced` and
  `%APPDATA%\FiveM for GTAV Enhanced`, whether or not they exist on this PC. An exclusion containing `*` or
  `?` has no `covers_fivem`: how Defender reads a wildcard in a folder exclusion is not established here.
- The game's own folder is not compared yet. P0 found no install folder for GTA V Legacy in Rockstar's
  registry keys and only a Steam install value for Enhanced. The PC probe counted 3 non-empty
  `InstallFolder*` values under Rockstar's keys, but did not print which products' keys hold them, so which
  of them is the game FiveM starts is not established.

The rule: `rules/defender_exclusion/fivem/fivem-folder-excluded/rule.yaml`, `posture`, `experimental`,
`match: { covers_fivem: true }`. **`falsepositives`**: performance and FPS guides that tell players to
exclude the game or FiveM folder to reduce stutter; game and mod installers and launchers that add their
own exclusion; developers and build machines that exclude a whole drive for build speed (the runner image
excludes `C:\` and `D:\`); another security product or an administrator managing Defender. A `found` row
says Defender was told not to scan where FiveM keeps its files; it does not say what was put there.
`unmeasured_when: [not_windows]`.

### 10. Privacy and the scan tier

- **Both collectors are `standard`** (ADR 0052). They carry no server identity and, with arguments never
  read and `entry` withheld as below, no account identifier; they list software installed on the PC, as
  `driver_service` and `process` do.
- **`entry` is withheld in SS mode** (`view::SS_WITHHELD_FIELDS`, as `net_config`'s `address`): a task's
  path can carry an account SID (4 of 211 task files on the runner), and a `Run` value's name is whatever
  the program chose. `service` is shown, as `driver_service`'s is.
- `path` and `exclusion` go through SS-mode redaction like every string (ADR 0049). A command resolved
  from `%USERPROFILE%` or `%LOCALAPPDATA%` becomes a profile path, which redaction reaches; an exclusion
  kept as written with a variable carries no user name.
- `PRIVACY.md`, the CLI consent text and the desktop consent text name both collectors in the pull request
  that registers them: programs set to start by themselves, with their paths, hashes and signers, and
  Defender's exclusions.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Widen `driver_service` | Changes what the LOLDrivers rule's `not_found` says, shares a budget the drivers already use, and its resolver refuses most program-service forms (section 1) |
| Task Scheduler COM API | A standard user gets a subset with no error (148 of 209), which would read as measured; it is a call into another process and needs new `windows` features |
| The `TaskCache` registry keys | Undocumented layout; refused to a standard user as well |
| Report arguments, or whether there were any | Arguments carry secrets; presence alone tells a reviewer nothing a rule uses |
| Resolve the file a Windows script host is given | Needs argument text to be read and parsed; left for a later change (owner decision 4) |
| Hash every file under `%SystemRoot%` | 271 files, 77.5 s cold in one pass; the embedded check reads most of them as `no_embedded_signature` anyway (section 7) |
| Read `StartupApproved` | Its bytes have no Microsoft-documented meaning; on the runner every first byte was `0x04`, on the PC `0x02` and `0x03` with `0x00` and `0x06` once each |
| Read every account's `Run` key (`HKEY_USERS`) | Other people's settings; `LiveHost` refuses every root but `HKLM` and `HKCU` |
| Defender exclusions as a fourth `location` | A different rights profile and a different kind of fact; a limited token is refused all of it |
| Compare exclusions with the game's folder | The game's folder is not known on a measured PC |

## What is unverified

- How often each rule reads `found` on gaming PCs other than the one measured, and what the one program
  it matched there is.
- Which file the elevated read was refused on the PC, and why.
- The cold cost of the signature checks, and of hashing a PC's autostart files; the PC's times were not
  controlled for the cache.
- Which Rockstar products the 3 `InstallFolder*` values on the PC belong to.
- Whether Windows starts a service's `ServiceDll` from exactly the value read here in every case, and
  whether the Service Control Manager and Explorer split an unquoted command line exactly as
  `CreateProcessW`'s documentation describes (the runner's 217 services resolved at the first word, which
  every reading agrees on).
- How Defender expands a variable, or reads a wildcard, in an exclusion; whether exclusions set through
  device management appear under these keys (on the runner the registry and `Get-MpPreference` agreed).
- Whether the task files and the Task Scheduler's own registration can disagree; the files held 211 tasks
  and the COM API listed 209 elevated on the runner, and 296 against 289 on the PC (`TaskCache\Tasks`
  also 289).
- What `TemporaryPaths` holds, and what `StartupApproved`'s bytes mean.

## Before any code

1. ~~The PC measurement~~ — done, "Measured on a Windows 11 PC (2026-09-30)".
2. ~~The owner's decisions~~ — taken on 2026-09-30, below.
3. Baselines: the `autostart` and `defender_exclusion` observations of `baseline-*` hosts are rebuilt from
   the collectors' own output on a runner, as `driver_service`'s were (ADR 0048), and
   `fixtures/hosts/PROVENANCE.md` says what that does not show.

## Owner decisions (2026-09-30)

1. A new collector, `autostart`, reads program services, `Run`/`RunOnce` and scheduled tasks;
   `driver_service` is not widened (section 1).
2. Tasks are read from the XML files under `%SystemRoot%\System32\Tasks`, `not_admin` without
   administrator rights; the Task Scheduler COM API is not used (section 2).
3. `entry` is withheld in SS mode (section 10).
4. Arguments are never read into a report (section 4). Describing the file a Windows script or library host
   is given is not part of this change; on the PC it would have added one described file.
5. Files under `%SystemRoot%` are not hashed and their signature is not checked; they are reported by path,
   and every other file is hashed and checked under a 30 s budget of its own (section 7, option B). What
   decides it is that 201 of the PC's 230 service DLLs there have no embedded signature; the runner's cold
   77.5 s is the case the budget is for.
6. Both rules ship `experimental`, and a baseline rebuilt from a runner carries a `rules/known-fps.csv` row
   for each: GitHub's provisioning agent for the first, the image's whole-drive exclusions for the second.
   Those observations stay in the baseline (sections 8 and 9).
7. `defender_exclusion` is a collector of its own, reading paths, processes and extensions and counting IP
   addresses, with `covers_fivem` against FiveM's three folders only. The game's folder waits until a
   measurement says which Rockstar product keys hold the `InstallFolder*` values (section 9).
8. Both collectors are in the `standard` tier (section 10).
9. A task file refused to an elevated read is a gap `access_denied` confined to `task`, and the autostart
   rule declares `access_denied` in `unmeasured_when` (sections 2 and 8).

The points under "What is unverified" stay open; the changes that add the collectors say which they
measured.

## Choices made in the implementation (2026-10-01)

The pull requests that shipped this ADR (#120, #121) met four cases the sections above do not settle. The
owner had asked that such cases follow the recommendation or the more conservative reading; these are the
readings taken, recorded here so the ADR matches the code:

1. An unquoted command line with a space, where no prefix names an existing file, is reported without
   `path` and with no gap: the program is missing, as ADR 0048 treats a missing file (section 3).
2. A `Parameters` key refused to the token gives that service a `sha256` and `signature` gap, `not_admin`
   or `access_denied` through `failure::reason_for`, and no `path` (sections 3 and 7).
3. A Defender exclusion that is not a drive-letter path once expanded, such as a bare process name, or that
   uses a variable this account does not have, gets no `covers_fivem`, as a wildcard does (section 9).
4. When neither `%LOCALAPPDATA%` nor `%APPDATA%` is set, a path or process exclusion's `covers_fivem` is a
   `read_failed` gap (section 9).

## Consequences

- Two collectors, `autostart` and `defender_exclusion`, two `posture` rules, a task-XML parser in
  `rongroi-parsers` with a fuzz target, and the resolver's refusals shared with `driver_service`.
- `budget_spent` gains a fourth producer, `autostart`; `rules/AGENTS.md`, ADR 0030's table and `xtask`'s
  owner check name it.
- `location` gains a fourth collector and the glossary gains `entry`, `hive`, `run_once`,
  `trigger_start`, `service_dll`, `triggers`, `starts_by_itself`, `path_kind`, `set_by`, `exclusion`,
  `covers_fivem` and `ip_addresses`; `kind`, `enabled`, `service` and `start` are reused with their
  meanings.
- `view::SS_WITHHELD_FIELDS` gains `autostart`'s `entry`.
- `PRIVACY.md`, both consent texts, `docs/architecture.md`, README (both languages) and CHANGELOG change
  in the pull requests that ship it. No network code, and no new crate outside what the XML parser needs.
