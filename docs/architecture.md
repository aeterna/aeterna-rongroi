# Architecture

aeterna-rongroi reads a Windows PC, turns what it sees into evidence, and shows that evidence to one of two
audiences. This page describes how the pieces fit; the reasons behind the big choices are in `docs/adr/`.

## Pipeline

```
Host ─► Collectors ─► CollectorRun ─► Engine (+ embedded rules bundle) ─► Report ─► View(mode) ─► CLI / GUI
```

1. **Host** — where artifacts are read from. `LiveHost` reads the real machine (Windows only);
   `FixtureHost` is a fake machine described in YAML so tests run on any OS.
2. **Collectors** — each reads one kind of artifact and returns a `CollectorRun`:
   - `Measured { observations, gaps, discriminator_gaps }` — what it saw, plus fields it could not read
     and why: for the whole run, or for the observations about one place when a collector that reads
     several places could read only some of them (ADR 0044)
   - `Unmeasured { reason }` — it could not look at all
3. **Engine** — evaluates every rule in the embedded bundle against the runs. Pure: no I/O, no clock.
4. **Report** — header (provenance, bundle hash, platform, elevation, time, boot time), one `Evidence` per rule,
   the `own_traces` the engine separated out, and the `unmatched` observations no rule matched. The
   report is frozen before any UI starts.
5. **View** — `view::for_mode` decides what an audience may see. The UI only renders a view.

Before any rule runs, the engine moves every observation that describes **this program** — its own path or
its own SHA-256 — out of the runs and into `own_traces`. aeterna-rongroi is running while it scans, so a
collector that enumerates the machine sees it; separating that visibly, rather than deleting it, keeps the
evidence about the PC and the trace of the tool apart without hiding either (ADR 0010). What "this program"
is arrives in `ScanContext` from each binary's `main`, so a fixture can exercise the whole path.

After the rules have run, every observation that **no** rule matched is kept as an *unmatched
observation*, grouped by collector. Evidence carries observations only where a rule matched, so without
this a collector that ships with no rule — `process` does, and `fivem_dir` did until ADR 0036 — would read the machine on
every scan and have its reading discarded. It is the complement of "matched at least one rule": an
observation one rule matched is evidence under that rule and is not repeated here because a second rule
did not match it. Own traces are taken out first, so one is never also an unmatched observation (ADR 0014).

The header's **boot time** is when the running Windows kernel started counting: the scan's clock minus
`GetTickCount64`, read before any collector runs. It is context for reading the times other rows carry,
it is in the header rather than an observation so that no rule can match it and so that SS mode shows it
with the rows it explains, and it is `unmeasured` with a reason rather than a guessed time. It is not when
the PC was last turned on: a "Shut down" with Fast Startup, sleep and hibernation do not reset it
(ADR 0039).

The CLI and the desktop app both call `rongroi_collectors::scan::run`, so they cannot disagree about a result.

## Crates

| Crate | Purpose | Depends on |
|---|---|---|
| `rongroi-core` | model, rule format and validation, embedded bundle, engine, views, provenance | — |
| `rongroi-host` | `Host` and source traits (including `SignatureSource`, ADR 0035, `BootTimeSource`, ADR 0039, and `EventLogConfigSource`, ADR 0042), `NonWindowsHost`, `FixtureHost` (feature `fixture`) | — |
| `rongroi-host-windows` | `LiveHost`: the only crate that calls Windows APIs or uses `unsafe` | `rongroi-host` |
| `rongroi-parsers` | artifact formats decoded from bytes into plain structs (BAM, PCA, Prefetch, EVTX): no OS calls, no `Host`, no clock (ADR 0013, ADR 0015, ADR 0018) | — |
| `rongroi-collectors` | `Collector` trait, collectors, `scan::run` | core, host |
| `rongroi-cli` | `aeterna-rongroi-cli` binary, no WebView | core, host, collectors, host-windows (Windows) |
| `xtask` | scaffolding and project checks | core (feature `source-tree`) |
| `apps/desktop` | Tauri 2 GUI | core, host, collectors, host-windows (Windows) |

Dependencies point one way. Parsers (from M2) are pure and depend on nothing platform-specific.

## Evidence model

Every rule produces exactly one of:

| State | Meaning | Carries |
|---|---|---|
| `found` | the rule matched | the matching observations |
| `not_found` | the collector looked and nothing matched | the rule's `retention` text — how far back the source can see |
| `unmeasured` | the collector could not look, or could not read a field the rule needs | a reason code, and whether the rule named that reason in `unmeasured_when` |

A rule whose field is listed in `gaps` is `unmeasured`, never `not_found`: saying "not found" about something
that was never read would be false. There is no score and no overall verdict (ADR 0002).

A collector that reads several places may declare a **discriminator**, the field saying which place an
observation is about — `fivem_dir`'s `location` is the only one. A place it could not read is then a gap
for that place's observations only: it makes `unmeasured` the rules that could match there, and leaves a
rule whose `match` rules that place out with the answer the places that were read give it (ADR 0044).

An `unmeasured` result carries `expected`: whether the reason is one the rule named in its
`unmeasured_when`. A declared reason is one the author said happens on ordinary machines; an undeclared
one means something they did not anticipate stopped the measurement, and it is the unmeasured result
SS mode lists (ADR 0027).

There are twelve reasons, and the split between them is how the report separates "we checked and there
was nothing" from "we could not check" (ADR 0030). Four describe a machine behaving exactly as Windows
ships it, so none of them may be read as a finding:

| Reason | Says |
|---|---|
| `not_windows` | the scan is not on Windows |
| `not_on_this_os` | this Windows version does not keep the artifact at all — PCA's files arrived in 22H2 |
| `not_admin` | Windows would not show it without administrator rights |
| `not_attempted` | the collector never looked; nothing was tried |
| `access_denied` | denied with the rights already held |
| `service_disabled` | the Windows service that writes the record is switched off |
| `source_absent` | the place the artifact is kept is not on this PC |
| `source_empty` | the place is on this PC and holds nothing |
| `partial` | some of it was read and some of it was not |
| `budget_spent` | a limit **this program** chose ended the read |
| `read_failed` | it is there and could not be read or understood |
| `collector_unavailable` | this build has no collector for the rule |

`source_absent` and `source_empty` mean opposite things and were one word until ADR 0030. A
content-level reason — `source_empty`, `service_disabled`, `partial` — gaps only the fields that
describe a record, because the folder or key itself **was** read and what it held is still measured.

Each row is shown with the rule's `description` — what the check means and what it does not prove —
and a `found` row also with its `falsepositives`, the ordinary things that produce the same evidence.
Both are mandatory in every rule and translated with the rest of its text (ADR 0027).

`strength` says what evidence can show: `execution`, `presence`, `tamper`, `posture`, `context`.

## Modes

| | Self | SS |
|---|---|---|
| Shows | every piece of evidence | `found` evidence, `posture` evidence that looked, and `unmeasured` evidence for a reason its rule did not name |
| Other evidence | shown | counted in `hidden.not_found` / `hidden.unmeasured_expected` / `hidden.unmeasured_unexpected` |
| `unmeasured` with reason `partial`, `budget_spent` or `read_failed` | shown | **always** a row, declared or not: each says the artifact was reachable and the read of it did not finish, which is not a rule author's to declare away. `check-rules` refuses the declaration outright (ADR 0030, ADR 0032) |
| `unmeasured` with reason `not_admin` or `not_attempted` | shown, and in the scope statement | **not** a row — one fact about the scan, said once above the evidence in `scope.not_admin` / `scope.not_attempted` (ADR 0012, ADR 0027, ADR 0030) |
| Own traces | shown | shown — they are transparency about the tool, not evidence about the PC (ADR 0010) |
| Boot time (header) | shown | shown — context for the times on the rows SS mode lists, and named in the consent question (ADR 0039) |
| Unmatched observations | shown | **not** shown — counted in `hidden.unmatched`, because a raw listing of what a collector saw is what this mode promises not to show (ADR 0014) |
| Paths | as read | `X:\Users\<name>` → `%USERPROFILE%`, in evidence and own traces alike |

The `scope` numbers are not hidden counts: in SS mode those rules are counted in `hidden.unmeasured_*`
as well, so the hidden counts keep accounting for everything the view leaves out.

Redaction is implemented and tested in `rongroi-core::view` (AGENTS.md hard rule 5).

## Rules bundle

`rongroi-core/build.rs` collects `rules/**/rule.yaml` and `rules/i18n/*.yaml` into one JSON document that is
compiled into the binary. At start-up `Bundle::embedded()` parses and validates it. The report header carries
the bundle's SHA-256. Shipped binaries have no way to load rules from disk (ADR 0004).

## Provenance

Only the upstream release workflow sets `RONGROI_OFFICIAL_BUILD=1` at compile time. Every other build shows
**UNOFFICIAL BUILD** in the CLI header, the GUI and the report (ADR 0007, NOTICE section 7(c)).

## What each collector reads

| Collector | Reads | Needs admin | Since |
|---|---|---|---|
| `posture` | `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State` → `UEFISecureBootEnabled`; `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` → `Enabled`, the *configured* memory-integrity policy rather than the running state; the kernel's code-integrity options, including test signing, via `NtQuerySystemInformation`; whether a TPM is present and which specification family it implements, via `Tbsi_GetDeviceInfo`; the firmware's own UEFI `SecureBoot` variable, via `GetFirmwareType` and `GetFirmwareEnvironmentVariableExW`, with `SeSystemEnvironmentPrivilege` enabled in this program's own token for the read and put back afterwards (`secure_boot_firmware`, ADR 0038); `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` → `EnableScriptBlockLogging`, the Windows PowerShell machine policy, reported as `enabled`, `disabled` or `not_configured` — not the per-user policy and not PowerShell 7's (ADR 0038). Kernel DMA Protection is **not** read: Microsoft documents no programmatic interface for its state (ADR 0038). One observation per run (ADR 0011) | no, except the firmware variable — measured 2026-09-13 on one real Windows 11 machine: `not_admin` under a limited token, read elevated (ADR 0038) | M0, M1 · firmware and script block logging: ADR 0038 |
| `fivem_dir` | FiveM's plugin folders for both editions: Legacy's `%LOCALAPPDATA%\FiveM\FiveM.app\plugins` (`location: plugins`) and Enhanced's `%APPDATA%\FiveM for GTAV Enhanced\gta5enhanced\asi` (`location: enhanced_asi`; that the Enhanced client loads from it is not established). Of each folder, whether it is there and how many files it holds; of each file directly inside, its path and, when readable, its SHA-256 and what `WinVerifyTrust` says about the signature **embedded** in it — `valid` with the signer's name and the signing certificate's SHA-256, `no_embedded_signature`, `invalid` or `unverifiable_offline` — checked with no revocation and URL retrieval from the local cache only, so it never reaches the network (ADR 0035). The same four facts of `FiveM.exe` in each edition's program folder, `%LOCALAPPDATA%\FiveM` (`location: legacy_exe`) and `%LOCALAPPDATA%\FiveM for GTAV Enhanced` (`location: enhanced_exe`); of those folders only the entry names are listed, to find that file, and nothing else in them is reported (ADR 0036). `location` is the collector's discriminator: a place that could not be listed is a gap for its own observations, unless no place could be (ADR 0044). No recursion, no timestamps, no ACLs (ADR 0009) | no, measured 2026-09-13 on one real Windows 11 machine: a limited-token scan read both plugin folders and both editions' `FiveM.exe` with the same signatures as an elevated one (ADR 0036) | M1 · signatures and Enhanced: ADR 0035 · `FiveM.exe` and the first rules: ADR 0036 |
| `pca` | The three Program Compatibility Assistant files under `%WinDir%\appcompat\pca` — `PcaAppLaunchDic.txt`, `PcaGeneralDb0.txt` and `PcaGeneralDb1.txt` — parsed by `rongroi_parsers::pca`. Of a launch record it reports the program's name, when PCA saw it run, and its path only when the path begins with a drive letter, which is the one shape SS-mode redaction can reach. The general databases contribute only how many records they held and whether every line parsed: no position in them has an established meaning (ADR 0020) | no, measured 2026-09-13 on one real Windows 11 machine: a limited-token scan read all three files and produced the same 3 observations as an elevated one. ADR 0020 left this unestablished; one machine now answers it (ADR 0033) | M2 |
| `prefetch` | The `.pf` files directly inside `%SystemRoot%\Prefetch`, parsed by `rongroi_parsers::prefetch`. Of each one it reports the program's base name, how many times Prefetch recorded it running, how many run times the file still held and the newest of them. **The files the program loaded and the volumes it touched are read and never reported**: Prefetch writes loaded-file paths as `\VOLUME{…}\USERS\<account>\…`, which SS-mode redaction cannot reach, a list of them is what SS mode promises not to show, and a volume serial number identifies one machine across two reports (ADR 0021). Of each `.pf` file, also whether it carries the read-only attribute, and no other attribute. Of Prefetch's setup, one observation per run: whether the folder is `listed`, `absent` or `unreadable`, and the `EnablePrefetcher` value under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`, left out when the registry holds none (ADR 0037) | yes, measured 2026-09-13 on one real Windows 11 machine: 627 observations elevated, 1 under a limited token. ADR 0015 said an elevated token is needed and one machine now agrees (ADR 0033) | M2 |
| `bam` | The Background Activity Moderator's registry state — one key per user account under `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`, whose value *names* are executable paths and whose value *data* `rongroi_parsers::bam` decodes. Of each value it reports the program's name, when BAM last saw it run, the parser's moderation state and how many bytes the value held, plus one account of how many user keys and values there were and how many decoded, with each key's own undocumented `Version` and `SequenceNumber` counted apart from the records (ADR 0023, amended). **No part of the SID goes out** — not hashed, not shortened, not indexed: it identifies one account and one installation, and the report says how many accounts had records instead. A path is reported only when it begins with a drive letter, the one shape SS-mode redaction can reach (ADR 0023) | yes, measured 2026-09-13 on one real Windows 11 machine: 83 observations elevated, 1 under a limited token. ADR 0023 left this unestablished; one machine now answers it (ADR 0033) | M2 |
| `evtx` | Every `.evtx` file directly inside `%SystemRoot%\System32\winevt\Logs`, parsed by `rongroi_parsers::evtx`. Records are **counted**, never listed: one observation per `(log, channel, provider, event id, level)` with how many there were and the first and last time one was written, plus one account per log of how much of it decoded, **the log's own state** — the oldest and newest surviving record, their times and their record ids, and the size of the file — and one for the folder, which adds how many of the logs read held no record at all and how many distinct channels the surviving records name. Those last two are the shape a one-click PC-optimiser script leaves, and a high count of empty logs is evidence **for** that benign explanation rather than corroboration of a clearing; none of these facts is a conclusion and each carries its innocent explanation in ADR 0028. **No record payload reaches the collector** — the parser drops it, and with it the user names, host names, addresses, SIDs and command lines an event carries (ADR 0018). A log that was denied, is larger than a host reads in one piece, or was not reached inside the collector's 30-second budget is named in the report as one, because an Event Log nobody could read is what a person who wants it unexamined would arrange (ADR 0024, ADR 0028). Of each log file, whether it carries the read-only attribute (ADR 0037). Of each log whose records name exactly one channel, what the Event Log service states about that channel through `EvtOpenChannelConfig` and `EvtGetChannelConfigProperty` — the file it writes the channel to, whether that is this file, and its maximum size — asked once per channel, never changed, on a thread of its own under a 5-second bound of its own that is not taken from the 30 seconds, so a service that never answers leaves those three fields `budget_spent` and costs no log and no other rule (ADR 0042, amended 2026-09-14) | yes for the `Security` channel — measured 2026-09-13 on one real Windows 11 machine: under a limited token both `evtx` rules came out `unmeasured / not_admin`, and elevated they read every channel. The CI runner cannot answer it, being always elevated (ADR 0018, ADR 0033) | M2 |
| `process` | The list of running processes through a ToolHelp snapshot: each process's image name and, when `QueryFullProcessImageNameW` answers, its path. No hashing, no process memory, no handle kept beyond the one query (ADR 0010) | no | M1 |

Every new collector adds a row here in the same PR.

## Desktop app

The GUI is a Tauri 2 shell around the same scan. It scans before creating its window, keeps the WebView2
profile in a temporary folder that is deleted on exit, keeps SmartScreen off inside the WebView, and has a
content-security policy that allows no network connections. WebView2's own Windows diagnostics are outside
the app's control and are disclosed in the consent screen (ADR 0001, PRIVACY.md).

Because the scan happens first, a collector that does not return is not a stalled progress bar — it is an
app that never appears. That is why the `evtx` collector, the only one whose input is both large and
attacker-chosen, bounds its own wall-clock and reports the logs it did not reach (ADR 0024).

## Known limits

- An offline tool shown on the player's own screen cannot prove innocence; a tampered OS can fake the display.
- Hardware (DMA) cheats and capture-proof overlays are invisible to a user-mode program.
- Traces age out: each `not_found` carries the retention window of its source for this reason.
