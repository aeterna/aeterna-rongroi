# ADR 0012 — Restarting with administrator rights

- Status: accepted
- Date: 2026-09-12

## Context

Some checks can only be measured by a process whose token carries administrator rights. Without them the
honest result is `Unmeasured { reason: not_admin }` (AGENTS.md hard rule 4) — correct, but a report full of
"not measured" is worth little to the player or to the staff member watching the screenshare. The remedy so
far was spoken instructions: close the program, right-click it, choose *Run as administrator*. That is easy
to describe wrongly over a screenshare and easy to skip.

Elevation on Windows is a property of a process token, fixed when the process starts. A running process
cannot add it to itself. So the question is not *whether* to relaunch, but what the relaunch hands over.

The desktop app also scans and freezes the report **before** its window is created (ADR 0001,
`docs/architecture.md`), so that nothing the WebView does can change what was measured. There is no code
path that re-runs a scan inside a live window.

## Decision

### A relaunch of the whole program, not an in-place re-scan

"Scan as administrator" starts a fresh copy of the program with an elevated token and ends the current one.
Adding a "re-scan now" path inside the live window was rejected: it would undo the property ADR 0001 buys —
that the report was produced before any WebView existed — for every scan, in order to serve one case.

### The relauncher is not a `Host` method and not a Collector

It lives in `rongroi_host_windows::elevate` as a free function module.

- Not a `Host` method: a `Host` is "where artifacts are read from" (CONVENTIONS.md, section 1). Every method
  on it reads. This one starts a process and reads nothing, so it would be the only member of that trait
  that is not about reading.
- Not a Collector: `crates/rongroi-collectors/AGENTS.md` forbids child processes, and that rule stands
  unchanged. Starting the program again is application lifecycle, not collection — a note in that file
  records the distinction so the two are not read as contradicting each other.

It stays in `rongroi-host-windows` because that is the only crate allowed to call Windows APIs and the only
one allowed `unsafe` (CONVENTIONS.md, section 2).

### Nothing is handed over between the two processes

The new process runs its normal startup path and scans from scratch. There is no state file, no IPC, no
temporary report, and nothing is written to the scanned machine. A hand-over would mean the elevated
process publishing a report it did not itself measure, and would be the first thing this program ever wrote
to disk during a check.

### The current process exits as soon as the request is accepted

Only one instance runs, so there is no second window showing a different report. The desktop app exits
through `AppHandle::exit`, not `std::process::exit`, so its `RunEvent::Exit` handler still deletes the
per-run WebView2 profile folder.

### `--elevate` is removed from the forwarded arguments

The new process therefore cannot ask to elevate again. This matters because `is_elevated()` is false for a
restricted (SAFER) token in which Administrators is deny-only, even though such a token was derived from an
elevated one (`live.rs`). Forwarding the flag would let that case relaunch in a loop.

### Declining the prompt is a normal outcome

`ShellExecuteExW` reports `ERROR_CANCELLED` (1223) when the person dismisses the Windows consent dialog.
It maps to its own error variant, `ElevateError::Declined`, so the interface can say that the prompt was
declined instead of reporting a generic failure. It is shown as a plain sentence, is not an error dialog,
and is not recorded as a failure. Refusing rights on your own PC is a choice the tool has to accept, the
same way SS mode accepts a refusal to share.

### What the user sees

| | Asks for it | Declines the prompt | Windows refuses |
|---|---|---|---|
| CLI | `aeterna-rongroi-cli scan --elevate` | one line: the prompt was declined, exit 0 | the error, non-zero exit |
| Desktop | a button on the start screen, shown only while the report header says `elevated: false` | a plain sentence on the start screen | a short failure notice on the start screen |

On anything other than Windows the CLI says that elevation is Windows-only and exits cleanly, rather than
accepting the flag and silently doing nothing.

## Consequences

- Argument quoting is the one part of this that is testable off Windows, so it is a free function with unit
  tests (`CommandLineToArgvW` rules) rather than code inside the `unsafe` block.
- The `windows` crate gains the `Win32_UI_Shell` and `Win32_System_Registry` features: `ShellExecuteExW` is
  declared under the first, but its `SHELLEXECUTEINFOW` carries an `HKEY` and the generated function is
  gated on the second as well.
- The consent dialog is requested without an owner window, so it is not modal to the app's own window.
  Passing the Tauri window handle would need a second Windows API and is left until someone reports that
  the dialog is hard to find.
- The elevated run is a second scan, so its report has a later `generated_at` and may legitimately differ
  from the first. The program never shows both at once.
- The prompt itself can only be exercised on Windows: it cannot be produced on a build machine, and the
  Windows CI runner already runs as administrator with UAC off, so a real prompt is checked by hand.
