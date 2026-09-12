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
   - `Measured { observations, gaps }` — what it saw, plus fields it could not read and why
   - `Unmeasured { reason }` — it could not look at all
3. **Engine** — evaluates every rule in the embedded bundle against the runs. Pure: no I/O, no clock.
4. **Report** — header (provenance, bundle hash, platform, elevation, time), one `Evidence` per rule, and
   the `own_traces` the engine separated out. The report is frozen before any UI starts.
5. **View** — `view::for_mode` decides what an audience may see. The UI only renders a view.

Before any rule runs, the engine moves every observation that describes **this program** — its own path or
its own SHA-256 — out of the runs and into `own_traces`. aeterna-rongroi is running while it scans, so a
collector that enumerates the machine sees it; separating that visibly, rather than deleting it, keeps the
evidence about the PC and the trace of the tool apart without hiding either (ADR 0010). What "this program"
is arrives in `ScanContext` from each binary's `main`, so a fixture can exercise the whole path.

The CLI and the desktop app both call `rongroi_collectors::scan::run`, so they cannot disagree about a result.

## Crates

| Crate | Purpose | Depends on |
|---|---|---|
| `rongroi-core` | model, rule format and validation, embedded bundle, engine, views, provenance | — |
| `rongroi-host` | `Host` and source traits, `NonWindowsHost`, `FixtureHost` (feature `fixture`) | — |
| `rongroi-host-windows` | `LiveHost`: the only crate that calls Windows APIs or uses `unsafe` | `rongroi-host` |
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
| `unmeasured` | the collector could not look, or could not read a field the rule needs | a reason code |

A rule whose field is listed in `gaps` is `unmeasured`, never `not_found`: saying "not found" about something
that was never read would be false. There is no score and no overall verdict (ADR 0002).

`strength` says what evidence can show: `execution`, `presence`, `tamper`, `posture`, `context`.

## Modes

| | Self | SS |
|---|---|---|
| Shows | every piece of evidence | `found` evidence and all `posture` evidence |
| Other evidence | shown | counted in `hidden.not_found` / `hidden.unmeasured` |
| Own traces | shown | shown — they are transparency about the tool, not evidence about the PC (ADR 0010) |
| Paths | as read | `X:\Users\<name>` → `%USERPROFILE%`, in evidence and own traces alike |

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
| `posture` | `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State` → `UEFISecureBootEnabled`; `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` → `Enabled`, the *configured* memory-integrity policy rather than the running state; the kernel's code-integrity options, including test signing, via `NtQuerySystemInformation`; whether a TPM is present and which specification family it implements, via `Tbsi_GetDeviceInfo`. One observation per run (ADR 0011) | no | M0, M1 |
| `fivem_dir` | `%LOCALAPPDATA%\FiveM\FiveM.app\plugins` — the names of the files directly inside it and, when readable, each file's SHA-256. No recursion, no timestamps, no ACLs (ADR 0009) | no | M1 |
| `process` | The list of running processes through a ToolHelp snapshot: each process's image name and, when `QueryFullProcessImageNameW` answers, its path. No hashing, no process memory, no handle kept beyond the one query (ADR 0010) | no | M1 |

Every new collector adds a row here in the same PR.

## Desktop app

The GUI is a Tauri 2 shell around the same scan. It scans before creating its window, keeps the WebView2
profile in a temporary folder that is deleted on exit, keeps SmartScreen off inside the WebView, and has a
content-security policy that allows no network connections. WebView2's own Windows diagnostics are outside
the app's control and are disclosed in the consent screen (ADR 0001, PRIVACY.md).

## Known limits

- An offline tool shown on the player's own screen cannot prove innocence; a tampered OS can fake the display.
- Hardware (DMA) cheats and capture-proof overlays are invisible to a user-mode program.
- Traces age out: each `not_found` carries the retention window of its source for this reason.
