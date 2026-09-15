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
| M1 | FiveM folder checks, running processes, more posture checks, admin re-launch | released in 0.2.0. Released in 0.3.0: Authenticode signature checking without the network (a chain ending at a root this PC does not trust reads as unverifiable offline, not invalid), FiveM for GTA V Enhanced, the first rules on FiveM's plugin folders and on the signer of `FiveM.exe` ([ADR 0035](docs/adr/0035-signature-checking-offline-and-fivem-enhanced.md), [ADR 0036](docs/adr/0036-the-first-fivem-dir-rules-and-fivem-exes-signer.md)) with a monthly check on when that pinned certificate expires, a FiveM folder that cannot be read no longer leaving every FiveM rule unmeasured ([ADR 0044](docs/adr/0044-a-gap-confined-to-one-place-a-collector-reads.md)), Secure Boot as the firmware reports it and the script block logging policy of Windows PowerShell and PowerShell 7, per machine and per user ([ADR 0038](docs/adr/0038-firmware-secure-boot-and-script-block-logging-policy.md)), and when Windows last started, in the report header ([ADR 0039](docs/adr/0039-a-time-anchor-for-the-report.md)) |
| M2 | Prefetch, BAM, PCA, event-log tamper signals | released in 0.2.0: the four collectors and two event-log rules, both `experimental`. No rule on what Prefetch, BAM or PCA record is planned. What those three record names a program only by its file name or path, so a rule on them cannot exclude legitimate software and renaming the file defeats it ([ADR 0034](docs/adr/0034-prefetch-bam-and-pca-carry-no-identity.md)). Self mode lists what they saw, and SS mode counts it. Released in 0.3.0: three rules on the state of a Prefetch or event log file — read-only, or not the file its channel writes to ([ADR 0037](docs/adr/0037-prefetch-configuration-and-the-read-only-attribute.md), [ADR 0042](docs/adr/0042-what-the-event-log-service-says-a-channel-writes.md)) — and BAM no longer reporting two unreadable values per account on every PC |
| M3 | Vulnerable-driver list, USN journal, Amcache, screenshare guide | the [screenshare guide](docs/screenshare-guide.md) is released in 0.3.0. Amcache is decided against for now: no collector and no hash rules until the conditions in [ADR 0041](docs/adr/0041-amcache-feasibility.md) are met. The vulnerable-driver list is designed in [ADR 0046](docs/adr/0046-vulnerable-drivers-feasibility.md) and measured on a GitHub-hosted runner and a Windows 11 PC, with the LOLDrivers list counted; the `driver_service` collector lists registered driver services with each file's SHA-256 ([ADR 0048](docs/adr/0048-the-driver-service-collector.md)); the rule that compares them with the list is next. The USN journal collector reads the Windows drive's change journal without write access and counts records per watched folder, with no file names ([ADR 0047](docs/adr/0047-usn-journal-feasibility.md)); no rule reads it yet |

The releases so far are 0.1.0, 0.2.0 and 0.3.0. The release pipeline shipped with 0.1.0
([ADR 0008](docs/adr/0008-release-pipeline.md)), which is why it is listed under M0.

Checking someone's PC over a screenshare? Read the [screenshare guide](docs/screenshare-guide.md) first.
What each rule looks for, and what else produces it: the [rule reference](docs/rules-reference.md).

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
