# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what a hosts entry that redirects a FiveM name looks like on disk: one line in the hosts file, which
# gives fivem.net (one of the names in LISTED_NAMES, crates/rongroi-collectors/src/net_config.rs) an address of its own.
Add-Content -Path (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Value "`r`n127.0.0.1 fivem.net" -Encoding ascii
Get-Content -Path (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Tail 3
