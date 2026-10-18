# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what a log file set read-only looks like on disk, so that Windows can no longer write to it. The
# attribute is changed on the file itself and the file is left where the Event Log service keeps it.
$p = Join-Path $env:SystemRoot 'System32\winevt\Logs\Application.evtx'
(Get-Item $p).IsReadOnly = $true
(Get-Item $p).IsReadOnly
