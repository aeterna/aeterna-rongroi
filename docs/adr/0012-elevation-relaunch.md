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
| CLI | `aeterna-rongroi-cli scan --elevate` — the scan runs in a new window, which waits for Enter (amendment below) | one line: the prompt was declined, exit 0 | the error, non-zero exit |
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

## Amendment (2026-09-13) — the elevated CLI copy's window closes on its report

### What was measured

The table above says what the CLI prints when the relaunch is **requested**. It said nothing about
what happens to the copy's output, and nobody had looked. `ShellExecuteExW` is called without
`SEE_MASK_NO_CONSOLE`, which is the flag that lets a new process inherit the caller's console, so the
copy gets a console window of its own. Whether that window stays open once the copy exits was the
open question. It was measured on one real Windows 11 machine (build 26220; no `DelegationConsole`
set and Windows Terminal not installed, so the console host is conhost):

| Run | What was seen |
|---|---|
| `scan` started the way `relaunch_elevated` starts the copy: verb `runas`, `SW_SHOWNORMAL`, `SEE_MASK_NOASYNC \| SEE_MASK_FLAG_NO_UI` | one new `ConsoleWindowClass` window while the scan ran (6.3 s, exit 0); **none left open 1 s after it exited**, and none after 6 s |
| the same, with `scan --pause-at-exit` (this amendment) | the prompt reached the window after 6.0 s; 5 s later the process was still running, its window open and the report's footer on screen; after Enter was written to its console input, it exited with 0 within 10 s and the window closed |

So before this amendment, `aeterna-rongroi-cli scan --elevate` printed "The new window does the scan"
and the new window closed as soon as the scan finished. The report was on screen for as long as the
scan took to print.

**What the measurement did not cover.** The launching process was already elevated, because a
scheduled task can start one on the desktop without a person, and a UAC prompt cannot be answered by
a program. From an elevated caller, `runas` shows no prompt. The product's real path is a
**non-elevated** caller, a prompt, and a copy started by the consent service. Both give the copy a new
console for the same reason: the flag that would share one is not set. The prompt path itself was
not run here. It needs a person to click, as the last Consequence above already says.

### Decision

- **The copy waits for Enter before it exits.** `--elevate` forwards a hidden `--pause-at-exit`, which
  prints "Press Enter to close this window." to standard error and reads one line. End of input
  counts as Enter, so a copy with no keyboard behind it exits instead of hanging. The flag is added
  once, however many times it is forwarded.
- **An error is printed before the pause, not after.** Returning the error from `main` prints it
  after everything else, which is into a window that has already closed. `main` prints it, pauses,
  and returns a failing exit code.
- **The relaunching process writes its messages to standard error.** "Starting again…" and "the
  prompt was declined" are not a report, for the reason the SS consent question moved to standard
  error at the same time: with `--json`, standard output is a file someone redirected.

### What was rejected

**Pausing whenever this process is the only one attached to its console** (`GetConsoleProcessList`
returning 1). That would also catch a double-click from Explorer. It is a guess about how the program
was started, where the flag states it, and it would change what an ordinary run does in cases no one
measured.

**Setting `SEE_MASK_NO_CONSOLE`** so the copy writes into the window it was started from. Not
measured. Whether an elevated process can share a console created by a non-elevated one was not
tested, and a change to how the process is created is a larger question than keeping a window open.

### What this does not fix

- **`--elevate` does not carry redirection.** `SHELLEXECUTEINFOW` has no standard-handle fields, so
  `scan --elevate --json > report.json` leaves the file empty and prints the copy's JSON into the
  copy's own window. To save an elevated report, run the scan from an administrator PowerShell.
- **A long report can outgrow the window's scrollback.** A Self-mode scan on the same machine printed
  more than the probe read back (it read the last 400 rows), and conhost keeps a limited number of
  rows. SS mode lists far less.
- **Windows Terminal as the default console host was not measured.** It has its own setting for
  closing a tab when a process exits. The pause keeps the process alive either way, so the tab has
  no exit to react to.
