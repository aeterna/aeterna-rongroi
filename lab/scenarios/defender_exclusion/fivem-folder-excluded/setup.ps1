# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

$ErrorActionPreference = 'Stop'

# This is what an administrator does when a FiveM performance guide says to exclude the game's folder from
# Defender scans: an exclusion in Defender's own settings. The folder need not exist; the exclusion is held either way.
Add-MpPreference -ExclusionPath (Join-Path $env:LOCALAPPDATA 'FiveM')
(Get-MpPreference).ExclusionPath
