# ADR 0060 — What starts by itself, and what Defender is told not to scan

- Status: proposed — the questions under "Owner decisions" are open
- Date: 2026-09-30

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

This ADR proposes how to read the four places, what reaches a report, the two rules, and what the owner has
to decide. It records what a GitHub-hosted runner showed; the Windows 11 PC is not measured yet for
anything but the Defender read (section "Before any code").

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

**A Defender exclusion covers a FiveM folder**: both drive roots cover `%LOCALAPPDATA%\FiveM`, which the
runner does not have.

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

## Measured on a PC

Only the Defender read, in P0 (2026-09-16), on a Windows 11 PC (build 26220): an elevated token read
`Exclusions\Paths` (6 values); a limited token from a scheduled task at `LIMITED` was refused with a
security exception. Nothing else in this ADR has been measured on a PC.

## Decision (proposed)

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
  `Author`, `Description`, or any other element. A refused folder or file makes the place `not_admin`
  without administrator rights and `access_denied` with them. The XML is parsed in `rongroi-parsers`, pure
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

This has a cost the owner should weigh (question 4). Dropping arguments means the report describes the
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

Two options, for the owner (question 5):

- **A — hash and check every file.** 300 files, 420 MB, 49–104 s cold on the runner. A budget of its own
  would be spent on nearly every scan, and a spent budget is a `budget_spent` gap on `signature` that makes
  the rule `unmeasured` and listed in SS mode.
- **B — do not hash or check files whose `path_kind` is `windows`** (recommended). They are reported with
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
- **`unmeasured_when`**: `not_windows`; `not_admin` is a scope statement already.
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
- The game's own folder is not compared: where the game is installed is still unknown on a measured PC
  (P0 found no install folder for GTA V Legacy in Rockstar's registry keys, only a Steam install value for
  Enhanced, and the folders it could read did not settle it).

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
| Resolve the file a Windows script host is given | Needs argument text to be read and parsed; question 4 |
| Hash every file under `%SystemRoot%` | 271 files, 77.5 s cold in one pass; the embedded check reads most of them as `no_embedded_signature` anyway (section 7) |
| Read `StartupApproved` | Its bytes have no Microsoft-documented meaning; on the runner every first byte was `0x04` |
| Read every account's `Run` key (`HKEY_USERS`) | Other people's settings; `LiveHost` refuses every root but `HKLM` and `HKCU` |
| Defender exclusions as a fourth `location` | A different rights profile and a different kind of fact; a limited token is refused all of it |
| Compare exclusions with the game's folder | The game's folder is not known on a measured PC |

## What is unverified

- **Everything on a Windows 11 PC** except the Defender read in P0: rights for the task files under a
  limited token of an administrator account (the runner measured a standard account), how many entries an
  ordinary gaming PC has in each place, their forms, and how often each rule would read `found`.
- The cold cost of the signature checks, and of hashing a gaming PC's autostart files.
- Whether Windows starts a service's `ServiceDll` from exactly the value read here in every case, and
  whether the Service Control Manager and Explorer split an unquoted command line exactly as
  `CreateProcessW`'s documentation describes (the runner's 217 services resolved at the first word, which
  every reading agrees on).
- How Defender expands a variable, or reads a wildcard, in an exclusion; whether exclusions set through
  device management appear under these keys (on the runner the registry and `Get-MpPreference` agreed).
- Whether the task files and the Task Scheduler's own registration can disagree; on the runner the files
  held 211 tasks and the COM API listed 209 elevated.
- What `TemporaryPaths` holds, and what `StartupApproved`'s bytes mean.

## Before any code

1. **The PC measurement.** A read-only probe that prints only counts, forms and classes of path — no
   value name, task name, path, signer, user name or argument — is prepared for the Windows 11 PC. It runs
   the runner's measurement once elevated and once as the signed-in account's limited token, through a
   scheduled task at `LIMITED` that it deletes, with its copied script and output, before it ends. It was
   exercised on the runner above. Its results are added to this ADR.
2. The owner's decisions below.
3. Baselines: the `autostart` and `defender_exclusion` observations of `baseline-*` hosts are rebuilt from
   the collectors' own output on a runner, as `driver_service`'s were (ADR 0048), and
   `fixtures/hosts/PROVENANCE.md` says what that does not show.

## Owner decisions (open)

1. **A new collector `autostart` for services, `Run`/`RunOnce` and tasks, rather than a wider
   `driver_service`.** Recommended: yes (section 1).
2. **Tasks read from the XML files, `not_admin` without administrator rights**, rather than the COM API's
   silent subset. Recommended: the files (section 2).
3. **`entry` withheld in SS mode.** Recommended: yes (section 10).
4. **Arguments.** (a) Never read into a report, as section 4 proposes; or (b) additionally, for the seven
   Windows script and library hosts only, resolve the first argument that is a drive-letter path to an
   existing file and describe that file — its path, hash and signature, never the argument text.
   Recommended: (a) now, and (b) as its own change after the PC measurement shows how often it occurs on a
   gaming PC.
5. **Files under `%SystemRoot%`.** Option B of section 7 — not hashed or checked, reported by path — with a
   30 s budget for the rest. Recommended: B.
6. **The two rules, both `experimental`,** and a `rules/known-fps.csv` row for each on a baseline rebuilt
   from a runner: GitHub's provisioning agent for the first, the image's whole-drive exclusions for the
   second. The alternative is to leave those observations out of the baseline, which would describe a
   machine that no one measured. Recommended: the rows.
7. **`defender_exclusion` as a second collector, reading paths, processes and extensions and counting IP
   addresses, with `covers_fivem` against FiveM's three folders only.** Recommended: yes; the game folder
   waits until where the game is installed is measured.
8. **Both collectors in the `standard` tier.** Recommended: yes (section 10).

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
