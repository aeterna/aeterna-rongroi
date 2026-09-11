# Privacy

## What the tool reads

Only local artifacts needed by its collectors, for example machine security settings (Secure Boot) and,
in later versions, FiveM folders, running processes, Prefetch, BAM, PCA and Windows event logs.
Each collector is listed with what it reads in [docs/architecture.md](docs/architecture.md).

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

## What is stored

Nothing, unless you click **Export**. An export is a file you save yourself; it contains the view you were
looking at (SS-mode exports are redacted). If you send an export to a server's staff, that server becomes
responsible for how it keeps it.
