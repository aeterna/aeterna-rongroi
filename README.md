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
- No screenshots, no browser history, no remote access, and no record of where your PC connected: of the
  network it reads only the settings that decide where traffic goes (hosts file, proxy, firewall rules).
- Of the programs Windows starts by itself (services, `Run`, scheduled tasks) it reads which file each one
  starts, never the arguments it is given. Of Microsoft Defender's exclusions it reads the folders,
  programs and file types, and only counts the network addresses.
- **A full scan reads more, and only if you say yes before it starts**: today, the names of FiveM for GTA V
  Enhanced's server cache folders. A flag or a script cannot say yes for you, and in SS mode a server's
  name stays hidden unless you agree to show it separately.
- **SS mode** (for screenshare) asks for consent first, shows what matched a rule, a timeline of the times its consent screen lists, and how far back
  each source reaches beside when parts of the PC were set up ([ADR 0061](docs/adr/0061-how-old-the-traces-are.md)), and hides your
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

**Latest release: [0.6.0](https://github.com/aeterna/aeterna-rongroi/releases/tag/v2026.10.02-0.6.0)**, 2 October 2026 —
a pre-release. It has 44 rules, and almost all of them are still `experimental`: they have not yet been
checked against enough real PCs, so read every result with care.
Earlier versions: [CHANGELOG.md](CHANGELOG.md).

| What it looks at, in plain words | Technical detail |
|---|---|
| **FiveM itself** — whether FiveM's files are the real, signed ones, and what add-on files sit in its folders. **New in 0.6.0:** when FiveM was last played, beside when its folders were last written | Legacy and GTA V Enhanced editions; Authenticode signatures checked offline; `plugins` and Enhanced's `asi` folder; Enhanced's per-server cache folders (full scan only, with consent); last session per edition from process start, Prefetch and BAM ([ADR 0062](docs/adr/0062-fivem-s-folders-beside-its-last-session.md)) |
| **Programs that ran** — what Windows remembers running recently | Prefetch, BAM, PCA, running processes. Listed in self mode, counted in SS mode. No rule judges what they record, because they name a program only by its file name ([ADR 0034](docs/adr/0034-prefetch-bam-and-pca-carry-no-identity.md)) |
| **Signs that records were wiped** — Windows' own logs cleared or blocked | An event log cleared; an event log or Prefetch file set read-only, or not the file Windows writes to |
| **Protection switched off** — antivirus and Windows security settings | Microsoft Defender's real-time protection switched off, its service disabled, its exclusions (administrator only); Secure Boot, TPM, memory integrity (HVCI), test signing, exploit mitigations, PowerShell logging |
| **Risky drivers** — drivers with known security holes, which a cheat can abuse to get deep into Windows | Each registered driver's SHA-256 compared with 1,847 verified [LOLDrivers](https://www.loldrivers.io/) hashes |
| **Deleted or renamed files** — in FiveM's add-on folders | The NTFS change journal (USN) for FiveM's `plugins` and `asi` folders, with the time span it covers |
| **Modified Windows** — Windows versions that come with protections removed | Atlas, ReviOS and similar builds, from install markers and what Windows reports about itself; the services such builds turn off |
| **Other settings** — things that start by themselves, and network redirects | Unsigned programs that start by themselves outside Windows and Program Files; a FiveM or Rockstar name in the hosts file |
| **How far back it can see** — so "not found" is never mistaken for "never happened" | The oldest time each source still holds, beside what it ordinarily keeps |

Not planned for now: Amcache ([ADR 0041](docs/adr/0041-amcache-feasibility.md)).

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
