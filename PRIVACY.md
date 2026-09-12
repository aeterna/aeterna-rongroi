# Privacy

## What the tool reads

Only local artifacts needed by its collectors, for example machine security settings (Secure Boot),
FiveM's own folders, the list of running processes and, in later versions, Prefetch, BAM, PCA and
Windows event logs. Each collector is listed with what it reads in
[docs/architecture.md](docs/architecture.md).

Of a running process it reads the name of the program and, when Windows will say, where that program
is on disk. It does not read what a program is doing, what is in its memory, or what you typed into it.

The tool does **not** take screenshots, read browser history, access files unrelated to its collectors,
or allow remote access.

## What leaves the machine

- **aeterna-rongroi's own code sends nothing.** There is no network code; CI rejects dependencies and APIs
  that could add it.
- **The GUI uses Microsoft WebView2**, a Windows component. Microsoft documents that WebView2 collects
  some required diagnostic data regardless of settings and follows the Windows *Diagnostic data* setting
  for optional data; crash reports may be sent to Microsoft. aeterna-rongroi turns off SmartScreen inside
  its WebView and keeps the WebView profile in a temporary folder that is deleted on exit, but it cannot
  switch off Windows' own diagnostics.
- **The CLI version does not use WebView2.** Use it if you want no WebView component involved.

## What is shown

| | Self mode | SS mode (screenshare) |
|---|---|---|
| Consent screen | no | yes — you may refuse |
| Evidence shown | everything | only rule matches, plus counts of what was not found or not measured |
| Paths | full | your user-profile folder is replaced with `%USERPROFILE%` |

### Program names are not redacted, and that can matter

SS mode replaces your user-profile folder inside **paths**: `C:\Users\<your name>\…` is shown as
`%USERPROFILE%\…`. A program's **name** is not a path and is not changed. Some installers and tools
produce an executable named after the account that installed it, so the name of a running program can
carry a real person's name to whoever is watching the screenshare.

There is no reliable way to recognise an account name inside an arbitrary name, and a guess that looks
like a guarantee would be worse than none — so aeterna-rongroi does not guess, and tells you instead.
If that matters to you, look at the report in Self mode first: you see exactly what SS mode would show,
before anyone else does.

### aeterna-rongroi's own traces

aeterna-rongroi is running while it scans, so it is in the list of running programs it reads. The report
keeps what it saw of **itself** in a separate "own traces" section instead of deleting it, and shows that
section in both modes: it is not evidence about your PC, and hiding it would tell you less about what the
tool did, not more. Paths in it are redacted in SS mode like any other.

## What is stored

Nothing, unless you click **Export**. An export is a file you save yourself; it contains the view you were
looking at (SS-mode exports are redacted). If you send an export to a server's staff, that server becomes
responsible for how it keeps it.
