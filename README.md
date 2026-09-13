# aeterna-rongroi

> ⚠️ **Pre-alpha.** The scanner currently checks only a handful of things. Do not use it for real
> decisions yet.

**An offline, open-source PC-check tool for FiveM communities.** It looks for traces that cheats leave
on a Windows PC and for machine settings that make cheating easier, then shows you the evidence.
It never tells you a PC is "clean".

*rongroi* (ร่องรอย) is Thai for "traces". · อ่านภาษาไทย: [README.th.md](README.th.md)

## What it is — and what it is not

| It is | It is not |
|---|---|
| An evidence aid for a player checking their own PC, or for staff reviewing with the player's consent | Proof that someone is innocent or guilty |
| A user-mode program that only **reads** local artifacts | A kernel driver, a service, or anything that runs in the background |
| Open: every rule and every check is in this repository | Able to see hardware (DMA) cheats or menus hidden from screen capture |
| Offline: our code sends nothing anywhere | An online service or a ban list |

Every result is one of three things:

- **Found** — the evidence is shown, with where it came from
- **Not found** — shown together with how far back that source can see (for example, "this log only
  keeps the last few days")
- **Not measured** — with the reason (for example, "needs administrator rights")

## Privacy

- **aeterna-rongroi's own code sends nothing.** Continuous-integration checks fail the build if network
  code is added.
- **The GUI uses Microsoft WebView2**, a Windows component that may send Windows diagnostic data according
  to your Windows settings. **The CLI version does not use WebView2.**
- No screenshots, no browser history, no remote access.
- **SS mode** (for screenshare) asks for consent first, shows only what matched a rule, and hides your
  user name in paths. You may refuse.

Details: [PRIVACY.md](PRIVACY.md).

## Verifying a download

Releases are not code-signed yet, so Windows SmartScreen will warn when you run them. To check that you
have the real file, open PowerShell in the download folder:

```powershell
Get-FileHash .\aeterna-rongroi-*-windows-x64.exe
```

This prints the hash of each aeterna-rongroi executable in the folder. Compare each hash with the line for the
same file name in `SHA256SUMS` on the GitHub release page; upper or lower case does not matter. Files from older
versions in the folder are not listed there. Builds that did not come from the official
release pipeline show **UNOFFICIAL BUILD** in the window, in the CLI header and in every report.
If you see that banner, or the hash does not match, do not rely on the result.

An offline tool shown on the player's own screen cannot prove anything on its own: a modified operating
system could fake what is displayed. Treat results as evidence for a person to judge.

## Status

| Milestone | Scope | State |
|---|---|---|
| M0 | Repository, rule format, engine, Secure Boot posture check, CLI and GUI shell, release pipeline | released in 0.1.0 |
| M1 | FiveM folder checks, running processes, more posture checks, admin re-launch | released in 0.2.0 |
| M2 | Prefetch, BAM, PCA, event-log tamper signals | released in 0.2.0: the four collectors and two event-log rules, both `experimental`. No Prefetch, BAM or PCA rule is planned. What those three record names a program only by its file name or path, so a rule on them cannot exclude legitimate software and renaming the file defeats it ([ADR 0034](docs/adr/0034-prefetch-bam-and-pca-carry-no-identity.md)). Self mode lists what they saw, and SS mode counts it |
| M3 | Vulnerable-driver list, USN journal, Amcache, screenshare guide | the [screenshare guide](docs/screenshare-guide.md) is merged, not released yet; the rest is planned |

"Merged" means the work is on the `dev` branch and is not in a release. The releases so far are 0.1.0 and
0.2.0. The release pipeline shipped with 0.1.0 ([ADR 0008](docs/adr/0008-release-pipeline.md)), which is
why it is listed under M0.

Checking someone's PC over a screenshare? Read the [screenshare guide](docs/screenshare-guide.md) first.

## Contributing

Rules, translations and collectors are all added by pull request — see [CONTRIBUTING.md](CONTRIBUTING.md)
and [CONVENTIONS.md](CONVENTIONS.md). Found a way around a detection? Please report it privately:
[SECURITY.md](SECURITY.md).

## Intended use

This project helps people look at evidence of cheating with the player's consent. Contributions that make
cheats harder to detect, clean or forge traces, or produce misleading reports are not accepted.
See [AGENTS.md](AGENTS.md).

## License

- Code: **GPL-3.0-or-later**, with additional terms under GPL section 7 (keep notices, mark modified
  versions as unofficial, no rights to the name). See [NOTICE](NOTICE).
- Rules, rule translations and rule fixtures: **CC-BY-SA-4.0**.
