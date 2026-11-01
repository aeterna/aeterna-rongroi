# ADR 0089 — A native splash while the scan runs

- Status: accepted — the owner chose decisions 1, 4 and 5 below on 2026-11-01, each as recommended; built in
  the pull request that adds this file, and not yet seen on a Windows screen (see "What is unverified")
- Date: 2026-11-01
- Related: ADR 0001 (scan before the WebView exists), ADR 0010 (the program's own traces), ADR 0012 (a
  relaunch scans from the start), ADR 0052 (the full-scan question in a native dialog), AGENTS.md hard rules
  1, 3 and 4

## Context

The desktop app runs `scan::run` before it creates any window (ADR 0001), so that nothing a WebView does can
change what was measured. `scan::run` is synchronous and takes from a few seconds to, on a full scan, up to
90 seconds for the files of recorded programs (the text of the full-scan question, `main.rs`). In that time
the program shows nothing. A player who double-clicks it, or who pressed "Full scan" or "Run as
administrator" (the old window closes at once, ADR 0012 and ADR 0052), sees the program vanish and cannot tell
a scan from a hang.

The gap is not specific to a relaunch: it is there on every start. A splash tied to a `--splash` flag would
leave the ordinary start without one.

## Decision

### 1. One small native window on every start, from the process that scans (owner, 2026-11-01)

`rongroi_host_windows::splash::Splash::show` opens a Win32 window drawn by Windows. It uses no WebView and no
Edge component, so the property ADR 0001 protects holds. `main()` opens it after the tier is chosen
(`chosen_tier`, which may show the ADR 0052 dialog) and closes it before `remove_stale_data_dirs` and
`build_main_window`. There is no flag: `commands.rs` and `forwarded_args` do not change.

### 2. The window has its own thread

`scan::run` blocks the thread that calls it, so the window runs its message loop on a thread of its own and
is closed by posting a private message (`WM_APP + 1`) and joining. The window ignores `WM_CLOSE`, so the
person cannot close it and a handle Windows has reused is never posted to. `Splash` closes on `Drop`, so a
panic during the scan does not leave a window behind. A splash that cannot be created does nothing; it never stops a scan (hard rule 4).

### 3. It says that a scan is running, and nothing it does not know (owner, 2026-11-01)

`scan::run` reports no progress, so the window shows a moving strip with no percentage and no collector
names. Text is fixed, in Thai and English together, because no language has been chosen yet (as the
full-scan dialog). A full scan may add that it can take up to 90 seconds, the figure the full-scan dialog
already states; a standard scan states no duration, because none was measured. Showing real progress needs a
callback in `rongroi-collectors::scan::run` and is a separate decision with its own ADR (owner, 2026-11-01).

### 4. The strip is painted, not a common control

A progress bar with `PBM_SETMARQUEE` needs Common Controls version 6 and `InitCommonControlsEx`. Tauri's
default manifest declares version 6 (`tauri-build` 2.6.3, `windows-app-manifest.xml`), read from the source and
not run. The strip is `FillRect` on a `SetTimer` tick instead, so the splash does not depend on how the
program is packaged.

### 5. The program's own traces

A window on a second thread of the same process adds no entry to the process snapshot, and the program's own
process is already separated by `SelfIdentity` (ADR 0010). No collector enumerates windows (a search of
`crates` and `apps` for `EnumWindows`, `GetWindow`, `GetForegroundWindow` and `FindWindow` found none).
This is read from the code on 2026-11-01 and has not been run on Windows.

## Alternatives weighed

- **Do nothing; explain in the start screen.** Rejected: the gap is before any screen exists.
- **A splash in the WebView.** Rejected: it creates the WebView before the scan, which is what ADR 0001
  forbids.
- **A `--splash` flag on relaunch only.** Rejected: leaves the ordinary start silent, and forwards a flag
  through `forwarded_args`.
- **A progress bar with real phases.** Deferred (section 3).

## What is unverified

- That the splash behaves on Windows 10 22H2 and Windows 11 at 100 %, 150 % and 200 % scaling. The Windows
  code is checked by `rust (windows)` in CI for compiling and by the owner on `pik-windows` for how it looks.
- That the strip stays smooth while a collector holds the disk. The timer runs on the splash's own thread.

## Consequences

- `rongroi-host-windows` gains `splash.rs` and two `windows` features, `Win32_Graphics_Gdi` and
  `Win32_System_LibraryLoader`.
- `apps/desktop/src-tauri/src/main.rs` gains the open and close calls and a bilingual text constant, tested
  like `FULL_TEXT`.
- The CLI is unchanged: it has a terminal.
