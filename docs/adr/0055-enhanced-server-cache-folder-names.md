# ADR 0055 — The names of Enhanced's server cache folders, in a full scan

- Status: accepted — the owner chose this source as the first `full` collector on 2026-09-18 and asked
  for the implementation the same day
- Date: 2026-09-18

## Context

ADR 0052 made two scan tiers and said the tier ships with its first `full` collector, either "an Enhanced
server cache folder's name, or the endpoints in FiveM's logs". The owner chose the folder names on
2026-09-18: they are one listing away, while the log endpoints need a parser for a format FiveM does not
document and changes when it updates.

What is known about the folders, measured read-only on one Windows 11 PC (build 26220) on 2026-09-16 with
the owner's permission, printing counts and shapes only (ADR 0053 records the same folders):

- `%LOCALAPPDATA%\FiveM for GTAV Enhanced\servercache` held one folder per server the game joined, three
  of them, each named with 40 hexadecimal characters, beside one renamed `<name>.bak-<date>` folder.
- Inside each were 134 to 168 folders named with hashes, and no index file.
- What the 40-character name is computed from was **not found**. The public FiveM source does not hold
  the Enhanced client, and none of 84 forms built from the six endpoints and 34 URLs in that PC's logs —
  SHA-1 and a 40-character SHA-256 prefix, of UTF-8 and UTF-16, in both cases — matched any of the three
  names.

`fivem_dir` already reports each server folder's creation and last-write times and entry count, without
its name (ADR 0053). The name is what ADR 0052 section 6 assigns to the full tier, as a **server
identity**.

## Decision

### 1. A collector, `fivem_servers`, in the full tier

It lists `%LOCALAPPDATA%\FiveM for GTAV Enhanced\servercache` once and nothing below it. One observation
about the folder: `folder` (`listed`, `absent` or `unreadable`, as `fivem_dir` spells them) and, when
listed, `server_folders`, how many server folders it holds. One observation per folder whose name has the
shape `fivem_dir` counts as a server's — 40 hexadecimal characters: `server_folder`, the name as the
listing spells it, and `created_at` and `modified_at` from the listing (ADR 0050). A folder with any other
name is not reported. Nothing inside a server folder is listed or opened.

Its tier is `full`. `server_folder` is declared sensitive, of kind `server_identity`.

A folder that is not there is `folder: absent`, not a gap: Enhanced is not installed for this user, or
has joined no server. A folder that cannot be listed is `folder: unreadable` and a gap in every field,
`access_denied` or `read_failed`. Without `%LOCALAPPDATA%` the collector is `read_failed`.

### 2. What the name can and cannot say

It is the same for the same server on the same PC, so the same name in two reports of one PC is one
server. Whether another PC gets the same name for that server is not established, so a report does not
say it can be compared with anything outside that PC. It does not say what anyone did on the server.

### 3. One rule

`fivem_servers/enhanced/server-cache-folder` (`context`, `experimental`) matches every server folder, so
that SS mode lists them after a full scan with the player's agreement, each name replaced with
`%SERVER_IDENTITY%` unless the player also agreed to show server identities (ADR 0052 section 4). Its
`falsepositives` say what is ordinary about it: joining any server leaves one.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Endpoints from FiveM's logs first | A parser for an undocumented format that changes with FiveM's updates, with its own fuzzing; a second `full` collector, not the first. |
| Add the name to `fivem_dir` | A collector has one tier. Putting a full-tier field in a standard collector would make the standard scan read it. |
| Report every folder name in the cache | A renamed folder's name is whatever someone typed; only the shape FiveM writes is reported. |
| Hash the name before reporting it | A hash of a stable identifier is a stable identifier; it hides nothing. |

## Measured after it shipped (2026-09-20)

The binary built from `dev` at `d6e1246` ran `scan --full` on the same Windows 11 PC, with the owner's
permission, from two scheduled tasks on the signed-in desktop — one with an elevated token, one with a
limited one. Both read the folder: `folder: listed`, `server_folders: 3`, and one observation per server
folder, each name 40 hexadecimal characters, with the same creation and last-write times in both reports.
Listing `servercache` and reading those times needs no administrator rights, so `fivem_servers` has no
`not_admin` case to declare. The task, the script, the binary and the output were deleted afterwards, and
no folder name was written down.

## What is unverified

- What the name is computed from, and whether it is the same on another PC.
- Whether FiveM removes a server's folder itself, and when.
- Whether Legacy keeps anything that names a server: its `server-cache-priv` held content-addressed files, and its
  `db` folder did not read as the leveldb index the public FiveM source describes.

## Consequences

- `rongroi-collectors`: `fivem_servers`, registered in `all()` and after `fivem_dir` in `COLLECTOR_ORDER`.
- `rules/fivem_servers/enhanced/server-cache-folder` with fixtures and Thai text, and an `unconfronted.csv`
  row: no baseline describes Enhanced, and every observation carrying `server_folder` fires the rule.
- The full-scan question (CLI and desktop), the SS consent question after a full scan, `PRIVACY.md`,
  `docs/architecture.md`, the glossary, both READMEs and both screenshare guides name the read.
