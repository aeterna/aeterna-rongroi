# ADR 0053 — When FiveM's own folders last changed

- Status: proposed
- Date: 2026-09-17

## Context

A reviewer asks when a FiveM cache was cleared, when the game last wrote a log, when it last crashed, and
when the player first reached a server. FiveM keeps folders whose contents answer part of that, and
`fivem_dir` reads none of them: it reads the Legacy `plugins` folder, the Enhanced `asi` folder, and
`FiveM.exe` in each edition's program folder (ADR 0009, ADR 0035, ADR 0036).

ADR 0050 gave a directory listing each entry's size and its creation and last-write times, and said that the
first collector to emit them would do so under its own decision. This is that decision.

## Measured

On one Windows 11 PC (build 26220), 2026-09-16, with the owner's permission, read-only, printing counts,
shapes and times only. Paths below are relative to `%LOCALAPPDATA%` (local) or `%APPDATA%` (roaming).

| Place | What it held |
|---|---|
| local `FiveM\FiveM.app\logs` | `.log` files only, a few, written over the previous week |
| local `FiveM\FiveM.app\crashes` | `.dmp` files and `.gamelog` files side by side, flat |
| local `FiveM\FiveM.app\data\cache` | a few files and two subfolders (`servers`, `subprocess`) |
| local `FiveM\FiveM.app\data\server-cache` and `server-cache-priv` | each a `db` and an `unconfirmed` subfolder, and — in `server-cache-priv` — thousands of files directly inside, named `cache_` and a 40-character hash; no server name is in any file name |
| local `FiveM for GTAV Enhanced\servercache` | **one subfolder per server**, each named by 40 hex characters, holding one subfolder per resource; nothing else |
| roaming `FiveM for GTAV Enhanced\logs` | `.log` files only, dozens |
| roaming `FiveM for GTAV Enhanced\gta5enhanced\crashes` and `...\launcher_crashes` | `.dmp` files |

FiveM's public source names the Legacy cache folders: `data/server-cache` with the launch mode as a suffix
(`code/components/rage-device-five/src/CitizenMount.Shared.cpp`), and the launcher pairs older
`cache/priv/` and `cache/fxdk/` folders with `data/server-cache-priv/` and `data/server-cache-fxdk/`
(`code/client/launcher/ViabilityChecks.cpp`). The
Enhanced client is not in the public repository; what its per-server folder names are derived from is not
known. Hashes of the endpoints and URLs its own logs named matched none of them.

A per-server folder's creation time and its last-write time both differed from its files' times.

## Decision

### 1. New places, reported as folders, never file by file

`fivem_dir` gains these `location` values:

| `location` | Folder | Reads |
|---|---|---|
| `legacy_logs` | local `FiveM\FiveM.app\logs` | folder activity |
| `legacy_crashes` | local `FiveM\FiveM.app\crashes` | folder activity |
| `legacy_cache` | local `FiveM\FiveM.app\data\cache` | folder activity |
| `legacy_server_cache` | local `FiveM\FiveM.app\data\server-cache`, `server-cache-priv`, `server-cache-fxdk` | folder activity, one observation per folder that exists, with `variant`: `default`, `priv` or `fxdk` |
| `enhanced_logs` | roaming `FiveM for GTAV Enhanced\logs` | folder activity |
| `enhanced_crashes` | roaming `FiveM for GTAV Enhanced\gta5enhanced\crashes` | folder activity |
| `enhanced_launcher_crashes` | roaming `FiveM for GTAV Enhanced\launcher_crashes` | folder activity |
| `enhanced_server_cache` | local `FiveM for GTAV Enhanced\servercache` | folder activity, and one observation per subfolder (section 3) |

`legacy_server_cache` names three fixed variants rather than matching `server-cache*`: a pattern would report
any folder someone creates beside them. The `variant` value is FiveM's own suffix, not anything of the
player's.

**Folder activity** is one observation per place, with what the listing of that folder — and nothing below
it — reports:

| Field | Kind | Value |
|---|---|---|
| `location`, `folder` | text | as today: `listed`, `absent` or `unreadable` |
| `files`, `folders` | number | entries that are files, and entries that are not |
| `size_bytes` | number | the sum of the files' sizes |
| `earliest_created_at`, `latest_created_at` | timestamp | the earliest and latest creation time among the files |
| `earliest_modified_at`, `latest_modified_at` | timestamp | the same for last-write times |
| `created_at`, `modified_at` | timestamp | the folder's own times, from its parent's listing |

A file whose size or time the listing did not provide is left out of that sum or that bound, and the
observation carries `files_without_times` with how many were left out, so a bound is never read as covering
files it did not see. An empty folder has `files: 0` and no bounds.

No file name, path or hash is emitted for these places. A crash dump's, a log's or a cache file's name says
nothing a reviewer needs that the count and the times do not, and some carry dates or hashes that match one
report with another. The files are not opened.

### 2. Names

`created` and the other `usn` counts already mean "how many journal records" (CONVENTIONS.md), so the times
here end in `_at`. `size_bytes` is the name `evtx` already uses for a size. `files` keeps its meaning.
CONVENTIONS.md's glossary gains **folder activity**, `folders`, `files_without_times`, the four bounds,
`created_at`, `modified_at` and `variant`.

### 3. Enhanced per-server folders: counted and dated, not named

For each subfolder of `enhanced_server_cache`, one observation with `location: enhanced_server_cache`,
`created_at`, `modified_at` and `entries` — how many entries its own listing holds, which is one listing
of that subfolder and nothing below it. No subfolder name and no path is emitted.

A subfolder's name identifies a server, whether or not anyone knows how it is derived, and a report that
carries it can be matched with another player's report of the same server. ADR 0052 (proposed) puts a
server identity behind the full scan and a separate SS-mode question; until that is accepted and built, the
name is not collected at all. When it is, the name is added under ADR 0052's terms without changing the
fields above.

The ordinary causes a reader needs beside these observations:

- a subfolder is one server's cache, not one visit: its creation time is the first time this cache was
  filled for that server, as far as this listing shows, and a cache that was cleared starts again;
- a subfolder whose name was changed by a person or a program is no longer named by 40 hex characters and
  is counted by the folder activity only;
- the count of subfolders is how many server caches are kept, not how many servers were joined.

### 4. What these observations are for, and what they are not

No rule reads them in this change. They are unmatched observations (ADR 0014): listed in Self mode, counted
in SS mode. They carry `Timestamp` fields, so the timeline in ADR 0051, once built, can place them, and a
timeline selector there can bring them into SS mode under that ADR's terms.

None of them says a folder was emptied by a person. A small or recent cache is what a new installation, a
cleared cache in FiveM's own settings, an update, disk-cleaning software or a moved profile folder also
leave. The text shown with them says so, in the words of ADR 0050 section 3.

### 5. Privacy

The consent question and `PRIVACY.md` gain, in the same change: for FiveM's log, crash and cache folders,
how many files and subfolders they hold, their total size, and the earliest and latest file times; for each
Enhanced server cache folder, when it was created and last changed and how many entries it holds — never a
file name. They also say that these times can match two reports of the same PC (ADR 0050 section 4).

## Alternatives weighed

| Alternative | Why not |
|---|---|
| One observation per file, as for `plugins` | Thousands of rows for `server-cache-priv`, names that carry dates and hashes, and nothing a reviewer reads that the bounds do not give. |
| Recurse into the cache folders | ADR 0009 rules out recursion; the bounds of the top level answer "when did this cache last change". |
| Emit the per-server folder name now | A server identity before ADR 0052's consent exists. |
| Match `server-cache*` | Reports whatever folder anyone creates beside FiveM's own. |
| A rule "cache folder is empty" | An empty cache is what a fresh install and FiveM's own "clear cache" leave; as a `found` row it would be the sea of red flags ADR 0027 rules out. |

## What is unverified

- How long FiveM keeps logs and crash dumps before it deletes them, in either edition.
- Whether FiveM's "clear cache" removes the folders themselves or only their contents, which decides what a
  folder's `created_at` means after it.
- What the Enhanced per-server folder name is derived from.
- Whether `server-cache-fxdk` appears outside FxDK.
- Whether the Enhanced `gta5enhanced` folder name is the same on every install.

## Consequences

- `fivem_dir`: eight `location` values, a third kind of observation (folder activity) and a fourth (a
  server cache folder); the `Reads` enum gains `FolderActivity` and `FolderActivityAndSubfolders`; eleven new
  fields; a fixture host per new place, including an unreadable one to show that its gap stays with its own
  observations (ADR 0044).
- `check-baseline` hosts gain the new folders where a runner or PC measurement supports them; the runner has
  no FiveM, so its baseline is unchanged.
- Consent text (CLI and desktop), `PRIVACY.md`, `docs/architecture.md`'s collector row and the glossary
  change with the code.
- Report snapshots change: Self mode lists the new observations, SS mode's unmatched count grows.
