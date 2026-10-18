# FiveM folder excluded from Microsoft Defender

## What the trace stands for

An exclusion in Microsoft Defender's own settings for `%LOCALAPPDATA%\FiveM`, the folder FiveM keeps its files
in. It is the change a performance guide tells a player to make to stop Defender scanning the game's folder.
Defender is told not to scan that folder; the scenario writes it the way an administrator would, under
`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`. The folder itself is not created.

## What the scenario shows

The defender_exclusion collector reads the path exclusion from Defender's settings, with `set_by` `settings`.
It is a folder above FiveM's own folders, so it covers them, and `defender_exclusion/fivem/fivem-folder-excluded`
reads `found`. The scenario lists no neighbours, so it shows nothing about other exclusions staying quiet.

## What the scenario does not show

- Who set the exclusion, or why. A game or mod installer, a launcher, another security product, or an
  administrator may set one; the exclusion alone says nothing about the person using the PC.
- Whether the folder exists, or what is or was in it. The scenario creates no file there.
- Exclusions set by Group Policy (`set_by` `policy`), exclusions written with a wildcard, and the game's own
  folder, which the collector does not compare yet.
- Whether a removed exclusion is seen. The rule reads only the exclusions present when the scan runs.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md) and
[ADR 0060](../../../../docs/adr/0060-what-starts-by-itself.md).
