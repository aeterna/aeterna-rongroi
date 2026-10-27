<!-- SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md. -->

# Downloaded program with its download zone, running before a session

## What the trace stands for

A program downloaded from a website and still running when a game session starts: a file in
`%USERPROFILE%\Downloads` with the `Zone.Identifier` stream a browser writes when it saves it. The stream says
the file came from the Internet (`ZoneId=3`) and names the site it came from. That is the ordinary shape of
anything downloaded and run, which fact I4 names (ADR 0078 section 5). The file is Windows' own `ping.exe`,
copied, so it is inert: it pings the loopback address and the machine has no network.

## What the scenario shows

The process list records `tool.exe` with a drive-rooted path, so the file can be read, and the candidate is in
the 30 minutes before the session: T1 is true. The scan is a full scan (`full: true`), so `recorded_files` reads
the file and its stream. The file is still there, so I1 is false, and Downloads is a folder the account can
write, so I4 is true. In a full scan the candidate's file details also show the download zone, `the Internet
(3)`, and the website's name, `downloads.example.invalid`; SS mode shows the website as `%DOWNLOAD_HOST%` until
the player agrees to show download hosts (ADR 0078, "P6b decisions"; ADR 0064). Reading the stream can move the
file's last-access time on a PC where last-access updates are enabled, as every read this program makes can
(ADR 0079, "Measured: the stream read"). The scenario names no rule that must read `found`.

## What the scenario does not show

- What the program does or who downloaded it. The file is a copy of `ping.exe`, and the stream is written by
  the scenario the way a browser writes it, not by a browser.
- That the site in the stream exists, or that anything was downloaded. The address is a documentation domain,
  the machine has no network, and the scenario copies a local Windows file.
- That a browser was used or that a download happened at this time. Only the stream's shape is reproduced.
- The windows during the session, after it, and before the scan. A session whose game is still running has no
  end, so those windows are "not known" (ADR 0078 section 3).
- What other files in Downloads hold. The collector reads only the paths a record points at, and this scenario
  makes one.

See [ADR 0076](../../../../docs/adr/0076-lab-replay.md),
[ADR 0078](../../../../docs/adr/0078-programs-recorded-near-a-game-session.md) and
[ADR 0079](../../../../docs/adr/0079-the-file-a-recorded-program-ran-from.md).
