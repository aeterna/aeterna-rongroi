# Unsigned program set to start at sign-in from the user's profile

## What the trace stands for

A Run value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, named `rongroi-lab`, whose data is the
quoted path of `%LOCALAPPDATA%\rongroi-lab\lab-tool.exe`. That file is a copy of this repository's own unsigned
build with a few bytes added at the end, so that it is not the running program
([ADR 0010](../../../../docs/adr/0010-process-source-and-own-traces.md)). Windows starts a program named by a Run value when the account signs in. The file is outside the Windows
folder and Program Files, and carries no embedded signature Windows trusts. The build does nothing on its own;
what the trace shows is the entry and the file, not what the program does.

## What the scenario shows

The autostart collector reads the `HKCU` Run value, resolves its quoted command line to the file, hashes the
file and checks its embedded signature. The file's folder is read as `user_profile`, and
`autostart/outside-windows/no-valid-embedded-signature` reads `found`. The scenario names no neighbour that must
stay `not_found`; the rule's own match is the only thing the expectation checks.

On the lab machine the control scan (ADR 0076 §1) reads this rule `unmeasured`, because some task files are
refused even to an elevated read. The control therefore cannot show that the rule reads `not_found` with no
scenario, and the `found` here is the scenario's, from the Run value.

## What the scenario does not show

- Whether the program runs, what it does, or who installed it. The rule says the same of every row it writes.
- Arguments. The collector never reports them, and this Run value has none.
- Per-user installers, launchers, updaters and chat or sync clients in AppData. The rule's `falsepositives` list
  them, and this scenario shows only a self-built tool, which the same list names.
- A file signed through a Windows catalog. The check does not read catalogs, and this file is not catalog-signed.
- Whether Task Manager's switch for a Run entry is on or off. The collector cannot tell, and this scenario does
  not set it.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0060](../../../../docs/adr/0060-what-starts-by-itself.md).
