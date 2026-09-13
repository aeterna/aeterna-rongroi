# Screenshare guide

For server staff checking a player's PC over a screenshare, and for the player. It covers
aeterna-rongroi **0.2.0**. อ่านภาษาไทย: [screenshare-guide.th.md](screenshare-guide.th.md)

> ⚠️ **Pre-alpha.** Six rules ship today, and five of them are `experimental`. Do not ban anyone
> because of what this tool shows, or clear anyone because of it.

## 1. What it can and cannot show

| It can show | It cannot show |
|---|---|
| Machine settings that make kernel-level cheats easier to load: Secure Boot, test signing, memory integrity (HVCI), TPM | Cheats running on a **second PC** (DMA). They leave nothing on the checked PC |
| That the Security log or an event log file recorded being cleared | Overlays hidden from screen capture |
| For each check, whether it was answered and, if not, why | Anything, if Windows on that PC was modified to lie to the programs that run on it |
| | That a PC is clean. **No result means that** |

Every row is one of three states. **Found** shows the evidence. **Not found** shows how far back that
source can see. **Not measured** shows the reason. A person decides what a row means. The tool
never does.

## 2. Get the real file

1. The player downloads it from the project's GitHub **Releases** page. Send the player the page,
   not a copy of the file.
   - `aeterna-rongroi-cli-0.2.0-windows-x64.exe` is the command-line version. It does not use
     WebView2.
   - `aeterna-rongroi-0.2.0-windows-x64.exe` is the version with a window.
2. Do not open it from the browser. Windows SmartScreen will warn, because releases are not
   code-signed yet, and the hash check comes first.
3. Before running it, the player opens PowerShell in the download folder and runs:

   ```powershell
   Get-FileHash .\aeterna-rongroi-*-windows-x64.exe
   ```

   Compare the hash with the line for the same file name in `SHA256SUMS` on the release page. Upper
   or lower case does not matter.
4. Only when the hash matches: `Unblock-File .\<file name>` removes the "downloaded from the internet"
   mark from that one file. If SmartScreen still shows **Windows protected your PC**, click **More
   info**, check the app name, and click **Run anyway**. The publisher shows as unknown until
   releases are signed. Do not turn SmartScreen off for the whole PC.
5. When it runs, the header must say **official build**. If it says **UNOFFICIAL BUILD**, or the
   hash does not match, **stop**. The result means nothing.

The report header also prints the program's own `exe sha256`. It should match `SHA256SUMS`. A
match shows the running file is consistent with the release. It cannot prove it: a modified program
could print any value.

## 3. Administrator rights

Some checks need administrator rights. The report says how many, once, above the evidence:

> Scope: N check(s) could not be answered because this scan does not have administrator rights.
> Running it again as administrator answers them.

That line is not a finding. It says this scan could not answer those checks. Measured on one
Windows 11 machine without administrator rights: Prefetch and BAM gave almost nothing, both
log-clearing rules came out *not measured*, and the four posture rules and PCA worked normally.

- **Window version:** on the start screen, click **Scan as administrator** and accept the Windows
  prompt. The program closes, starts again with those rights and scans from the beginning. The
  button only appears when the current scan ran without administrator rights.
- **CLI:** open **PowerShell as administrator** and run the scan in that window (§4).
  With 0.2.0, do not use `--elevate`. It runs the scan in a **new** console window, and Windows
  closes that window the moment the scan finishes, taking the report with it (measured on a real
  Windows 11 machine, [ADR 0012](adr/0012-elevation-relaunch.md)). Releases after 0.2.0 keep the
  window open until Enter is pressed. Either way, the report from `--elevate` stays in that window
  and never reaches a file redirected with `>`.

The player may decline administrator rights. The scan still runs, with more checks in the scope
line.

## 4. Run SS mode

SS mode is the screenshare view. It asks the player for consent first. It lists only what matched a
rule, and it replaces the player's user folder in paths with `%USERPROFILE%`.

**Window version:** **Screenshare check (SS mode)** → read the consent screen → **I agree — show the
SS view**. The window version scans when it starts, **before** its window opens, so the window cannot
change the results. The consent screen decides what is shown.

**CLI:**

```powershell
.\aeterna-rongroi-cli-0.2.0-windows-x64.exe scan --mode ss
```

Add `--lang th` for Thai. The program asks `Continue? [y/N]`, and **the player** answers it.

- **Do not use `--yes` to skip a question the player has not answered.** The flag exists for a
  player who has already agreed (§9).
- If the player refuses, the program prints `Scan cancelled. Nothing was read.` and reads nothing.
  What your server does after a refusal is your server's rule. The tool does not measure it.

## 5. Read the report

### The header

```
aeterna-rongroi 0.2.0
official build
mode: ss · windows <build> · administrator · rules: 6 (<bundle hash>)
exe sha256: <hash>
```

Check four things: `official build`, `mode: ss`, whether it says `administrator` or `standard user`,
and the rule count.

### Each row

```
[FOUND] check: <rule title>  (<strength>, <collector>)
    <evidence>
    About this check: <what it means and what it does not prove>
    Ordinary things that also produce this:
      - …
```

- **`check:`** comes before the title because the title says what the rule looks for, not what was
  seen.
- **Strength** says what kind of evidence the rule gives. `tamper`: traces were removed or altered.
  `posture`: a machine setting that makes cheating easier. `context`: background for the reviewer.
  (`execution` and `presence` exist, but no rule uses them yet.)
- **Ordinary things that also produce this** appears beside every `FOUND` row. **Read it out loud.**
  Every rule has to have it, and it is the part most likely to be skipped.
- **`NOT MEASURED (expected here)`** means the rule's author said this machine state is ordinary.
  **`NOT MEASURED (not expected)`** means it was not anticipated. Neither one is a finding.

### The line at the bottom

```
Hidden in SS mode: NOT FOUND <n> · NOT MEASURED (expected here) <n> · NOT MEASURED (not expected) <n> · unmatched observations <n>
```

These are counts of what SS mode does not list. §7 says why.

## 6. The six rules, and what else produces them

| Rule | Strength | Status | Ordinary causes (from the rule itself) |
|---|---|---|---|
| Secure Boot is turned off | posture | `test` | legacy BIOS/CSM boot, dual-boot, turned off for hardware or overclocking tools |
| Windows test signing is turned on | posture | `experimental` | people who write or test drivers, hardware engineers, software whose install asks for it |
| Memory integrity (HVCI) is configured off | posture | `experimental` | hardware that cannot support it, switched off to fix a driver conflict, off by default on many PCs |
| No TPM is present | context | `experimental` | older or self-built PCs, TPM off in firmware, virtual machines |
| The Security log records that it was cleared | tamper | `experimental` | "optimiser" and "debloat" scripts, a prebuilt or repaired PC, troubleshooting in Event Viewer, Windows updates |
| An event log file was cleared | tamper | `experimental` | the same, plus software whose setup resets the local log |

Three things to know about the two log-clearing rules:

- **They can be one action, not two.** Clearing the Security log can be recorded in both logs.
- **A high count points to an optimiser, not to something worse.** Those scripts clear every log at
  once.
- **Both fired on a GitHub Actions Windows runner, an imaged machine nobody was accusing of
  anything.** Preparing a Windows image deletes the event logs. The rules did what they are written to do, and it shows
  what a `tamper` row on an ordinary PC looks like.

The four posture rules describe the **machine**, not the person. Each rule's own text says that on
its own, it is not evidence of cheating.

## 7. What SS mode does not show, and why

The program reads more than the six rules ask about. It reads what Windows recorded about programs
that ran (Prefetch, BAM, the Program Compatibility Assistant), the list of running programs, and the
files in FiveM's plugins folder. **No rule reads those today**, so they are *unmatched observations*:

- **Self mode** lists them, for the player.
- **SS mode** shows only how many there were.

This is deliberate. The consent screen promises "only what matches a rule". A list of every program
someone ran would show staff what else is on that PC. Replacing the user name in the paths would not
change that. [ADR 0034](adr/0034-prefetch-bam-and-pca-carry-no-identity.md) explains why there is no
rule for them: these records name a program only by its file name or path, so renaming the file
defeats such a rule, and it cannot tell a legitimate program with the same name apart.

Self mode is the player's view, and the player's consent covers SS mode. Asking to see Self mode is
asking for something the player did not agree to.

## 8. Own traces

The program is running while it scans, so it sees itself. The **own traces** section, shown in both
modes, lists what it saw of itself. It is not evidence about the PC.

## 9. Keeping a record

- **The window version has no export or save button** in 0.2.0.
- **The CLI** can write the SS view as JSON, redacted the same way as the screen:

  ```powershell
  .\aeterna-rongroi-cli-0.2.0-windows-x64.exe scan --mode ss --json > report.json
  ```

  **Releases after 0.2.0:** the consent question stays on screen, the player answers it there, and the
  file holds only the JSON.

  **0.2.0:** the consent question goes to the same output as the JSON. With `>`, the player does not
  see the question, the program waits for an answer with nothing on screen, and the question ends up
  at the top of the file. So with 0.2.0, first run the SS-mode scan from §4 without `--json`, so the
  player reads the question and answers it on screen. If they agree, run the command above with
  `--yes` added. That is what `--yes` is for. It is a second scan, so a running-program list can
  differ slightly from the one on screen.

  Either way, run it from an administrator PowerShell (§3), not with `--elevate`.
- A file the player sends to staff becomes the server's responsibility, including how long it is
  kept ([PRIVACY.md](../PRIVACY.md)).

## 10. What not to conclude

| The report shows | It does not mean |
|---|---|
| a `FOUND` row | the player cheated |
| no `FOUND` rows | the PC is clean |
| `NOT MEASURED` | the player is hiding something |
| the scope line about administrator rights | the player refused anything |
| both log-clearing rows | two separate clearings |
| a large number of cleared logs | a more serious clearing |
| a posture row | anything about the person |

Treat the report as one piece of evidence for a person to judge, next to everything else your
server knows.

## Found a mistake in this guide?

Open an issue or a pull request ([CONTRIBUTING.md](../CONTRIBUTING.md)). If you found a way around a
detection, report it privately ([SECURITY.md](../SECURITY.md)).
