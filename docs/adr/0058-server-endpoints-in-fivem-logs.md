# ADR 0058 — Server endpoints in FiveM's own logs, in a full scan

- Status: parked — the owner decided on 2026-09-30 to build nothing until a measurement on a PC shows a log
  line that names a joined server: a read-only probe of the kind used here, run on a PC that joined a server within the span its FiveM logs cover, prints the template of a line that names the joined server by an address, or by a name with a port (owner decision 1). Two measurements on 2026-09-30 found no
  such line on the PC measured (section "What the measurements mean").
- Date: 2026-09-30

## Context

A reviewer asks which servers a PC's FiveM connected to, and when. ADR 0054 recorded the owner's decision
that no record of where traffic went is read — not SRUM, the DNS cache, the live TCP table, the firewall log
or a packet capture — and named FiveM's own logs as the one source of *where* that is within this program's
limits. ADR 0052 put "endpoints and plugin names in FiveM's logs" in the full tier, with endpoints as a
**server identity**, and the owner decided on 2026-09-16 that FiveM's logs are read in full under the full
scan's consent. ADR 0055 made the first `full` collector, the Enhanced server cache folder names, and named
this source as the second: "a parser for an undocumented format that changes with FiveM's updates, with its
own fuzzing".

The two folders are already reported, as folder activity only — how many files, their total size and the
earliest and latest file times, never a file name and never a file's contents (ADR 0053):

| `fivem_dir` `location` | Folder |
|---|---|
| `legacy_logs` | `%LOCALAPPDATA%\FiveM\FiveM.app\logs` |
| `enhanced_logs` | `%APPDATA%\FiveM for GTAV Enhanced\logs` |

What is known about their contents was measured read-only on one Windows 11 PC (build 26220) on
2026-09-16, with the owner's permission, printing counts only; the script and its output were deleted:

- 3 Legacy and 34 Enhanced `.log` files, written between 2026-09-06 and 2026-09-16.
- Across them: 6 distinct `host:port` values, 35 distinct URLs, 3 distinct IPv4 addresses, and the word
  "discord" 22 times (one distinct value). Which edition's files held the endpoints was not recorded.
- No `license:`, `discord:<id>`, `steam:` or `cfx.re/join` text at all. **The logs carry no account
  identifier** on that PC, so this source gives server identities only.
- Enhanced's logs have lines of the form "Downloading … for `<host>`".
- The six endpoints and 34 of the URLs, hashed in 84 ways, matched none of the Enhanced server cache folder
  names (ADR 0055): an endpoint from a log cannot be joined to a `fivem_servers` folder.

FiveM does not document its log format, the Enhanced client is not in FiveM's public source (ADR 0055),
and the format can change with any FiveM update. This ADR therefore decides the boundaries — which files,
what leaves the parser, what SS mode shows — and takes the line templates from measurement (section 8).

## Measured 2026-09-30 on a Windows 11 PC (build 26220)

Read-only, with the owner's permission, from a PowerShell probe that printed counts, masked file-name shapes
and masked line shapes only — no host, address, URL, path, user name or line text. It ran once with an
elevated token and once with a limited one, and **both printed the same results**, so reading these folders
needs no administrator rights. No FiveM process was running. The probe and its output are not in this
repository.

| | Legacy `logs` | Enhanced `logs` |
|---|---|---|
| Files | 3, all `.log` | 37, all `.log`, no archives |
| File names (digits masked) | `CitizenFX_log_9999-99-99T999999.log` | four families: `fivem-launcher-<date>_<time>.log` (11), `fivem-for-gtav-enhanced.log-<date>_<time>.log` (11), `cef-<date>_<time>.log` (11), `installer-<date>_<time>.log` (4) |
| Written | 2026-09-07 to 2026-09-13 | 2026-09-06 to 2026-09-30, a span of 24 days |
| Sizes | 76,154 to 76,873 bytes; 229,188 in total | 122 to 174,204 bytes, median 25,778; 1,286,926 in total |
| Lines, longest line | 945; 2,198 characters | 13,747; 277 characters |
| Line endings | CRLF on every line | CRLF on 11,818 lines, LF alone on 1,929 |
| Line prefix | every line begins with a bracketed tick count and a bracketed process tag, `[     99999] [a9999_aaaaaaaa]` in shape; 31 lines also hold a `9999-99-99` date | 11,818 lines begin with a bracketed clock time and a bracketed level, `[99-99-9999 99:99:99] [    aaaa]` in shape; 88 lines have a Chromium-style prefix, `[9999/999999.999:aaaa:...`; the rest have none |
| Time in the file name | 7 hours (25,200 to 25,204 s) from the file's creation time | within 1 s of the file's creation time |

In every file read: no byte-order mark, no NUL byte, no invalid UTF-8; no file above 64 MiB, the largest
174,204 bytes. No text in the shape of an account identifier (`license:`, `license2:`, `steam:`,
`discord:`, `fivem:`, `xbl:`, `live:` or `ip:` followed by an identifier) and no e-mail address in any log;
the Windows user name in no line. Lines holding a drive path: 64 Legacy (24 under `\Users\`) and 81 Enhanced
(all 81 under `\Users\`). Lines naming a `.dll`: 3 Legacy, 8 Enhanced; naming an `.asi`: none. The newest
log, last written 12 minutes before, opened for reading while sharing read, write and delete.

Beside the log folders: Legacy's `FiveM.app` folder holds `cef_console.txt` (6 lines, LF, Chromium-style
prefix), the Legacy `crashes` folder 5 `.gamelog` files, and `%APPDATA%\CitizenFX`'s `kvs` folders a `.log`
file each; this collector reads none of them (section 1).

## Measured 2026-09-30, second probe

The same PC, the same day, as the signed-in user; the probe printed counts and masked templates only, and
finished. It read Legacy's three `CitizenFX_log_…` files and `cef_console.txt`, and Enhanced's four families.
In every template below, a host is replaced by its class, a path by `<PATH>`, a dotted name by its class, a
quoted string by `"*"`, a number by `9`, and any word outside a fixed vocabulary by `*`.

- **`host:port` outside a URL: none**, in every family.
- **Hosts inside URLs: none with a port.** By family: `cef-` 88 URLs, all to 4 single-label hosts (the
  game's own interface pages, `https` and `nui`); `fivem-for-gtav-enhanced.log-` 11, all `nui` to one
  single-label host, on a "Failed to … for …" line; `fivem-launcher-` 1, to one DNS name not on the probe's
  list of service domains, on an "install" line; `installer-` 12, to one such name, on "download" lines;
  `cef_console.txt` 7, to one single-label host and to `fivem.net`; Legacy 3, to one such name, on a line of
  the form "… a request for … URI `<https://name/5 segments>`".
- **IPv4 without a port: only in Legacy** — 3 lines, 6 occurrences, 2 distinct values, all in the public
  class, each inside a quoted value of a `9 * -> { "*" : "*" , "*" : "*" }` line: a JSON object logged
  after an arrow. Which key they sit under is masked, so whether they are a server's address, the player's
  own public address, or a dotted version number of that shape (the probe checked the shape, not that each
  part is at most 255) is **not known**.
- **"Downloading" lines** (3,704, all in `fivem-launcher-`): `Downloading file 9 <file name>` (1,836),
  `… Downloading resource 9 *` (1,826), `… Downloading file <file name> to <PATH> for *` (22) and two
  smaller forms. None holds a host, a URL or a port; the word after "for" is not a dotted name.
- **Lines about joining**, none holding a host: `Requesting handshake...` (11), `HTTP Handshake * game.
  client * 9` (10), `* session status to ok, response: 9 / {}` (10), `Requesting handshake error: * handshake
  failed.` (2) in Enhanced's launcher log; `Received * with net * 9 * to * to * from *` (6) in the game log;
  one Legacy line `* Requesting server *` whose remainder is neither an address, a dotted name nor a URL.
- **Times:** of the 11,818 Enhanced lines with a clock time, 11,805 have a first date field above 12 and none
  a second field above 12, so the date is **day first, `dd-mm-yyyy`**. The PC's offset
  from UTC was +7 hours, which matches the 7 hours between a Legacy file name's time and its creation time:
  the **Legacy file name's time is UTC**, Enhanced's local.
- **Paths under `\Users\`**: every one (105) is the signed-in user's profile folder, although the Windows user
  name matched none of them; the profile folder name and the user name differ on this PC.

## What the measurements mean

**On the PC measured, FiveM's logs do not name the servers the game joined.** The joins happened — the
launcher log holds handshake and session lines, and ADR 0055 found three Enhanced server cache folders on the
same PC — but no join line carries an address, a name or a port. What address-shaped text there is belongs
to the game's own interface, FiveM's download hosts and one Legacy request URI, and two IPv4-shaped values
whose meaning is masked.

The P0 note of 2026-09-16 — six distinct `host:port`, three IPv4 addresses, in 37 files — is less credible
than these counts:

- the files are the same ones: the three Legacy files span 2026-09-07 to 2026-09-13 in both measurements,
  and Enhanced's oldest file is from 2026-09-06 in both; the second measurement read 5 more files, not fewer;
- the 2026-09-16 pattern was not recorded, and its result was not broken down by line; the 2026-09-30
  patterns are in probes that printed their templates;
- no URL host on this PC has a port, so the six values were not URL endpoints either;
- what the looser pattern most plausibly caught is text of the same shape that is not a server: a clock time
  or a `name:line` reference next to a dotted name, a dotted version number (the IPv4 count is of the same
  kind), or a JSON value. That is unverified: the 2026-09-16 output is gone.

**What remains** is one Legacy line, `* Requesting server *`, whose remainder is not an address, and two
IPv4-shaped values in a JSON line whose key is unknown. Neither supports a collector: the first holds no
endpoint in any shape the parser could name, and the second could be the player's own public address, which
is an identifier of the player's connection rather than of a server (ADR 0021's reasoning), and which this
program must not read without knowing that it is not.

**One PC is one sample.** Another FiveM version, a PC that joins by typing an address, or a server that
refuses the connection may log differently. The design below is kept for that case, not built now.

## Decision

**If this source is reopened** (owner decision 1). Sections 1 to 9 are the design the measurements above
would have fed; they stand as the terms any later collector of this source is held to, and none of it is
built while the ADR is parked.

### 1. A collector, `fivem_logs`, in the full tier

It reads the two folders above and nothing else: one listing of each, then each `.log` file directly inside
it whose name has a measured family's shape (Legacy `CitizenFX_log_…`; an Enhanced family only when a
measurement shows it naming servers, which on the PC measured none of the four did — and a `cef-` log names
the pages the game's interface opened). No subfolder, no other extension, no other FiveM folder. Not the `.gamelog` files beside the crash dumps
(ADR 0053 measured them to name no `.dll`; they are not logs of connections), not `%APPDATA%\CitizenFX`'s
`kvs` (it held no host or URL), and never the NUI or CEF storage, which held text in the shape of a token
and which `crates/rongroi-collectors/AGENTS.md` and ADR 0052 section 5 put out of reach whatever the player
agrees to.

Its tier is `full`: in a standard scan it is not called and its run is `not_consented` (ADR 0052). A
`location` discriminator names the edition — `legacy` or `enhanced` — so a gap in one folder stays with that
folder's observations (ADR 0044).

A file is read with `FilesystemSource::read_file` (ADR 0019), which opens it for reading only and never
truncates. FiveM may hold the newest log open for writing while the scan runs; the standard library opens a
file sharing read, write and delete by default, so the read neither blocks FiveM nor is blocked by it —
per the standard library's source, to be re-read for the pinned toolchain when this is built. The newest log
opened that way on the PC measured, but with no FiveM process running; a read while FiveM writes is not
measured. The last line of a file being written may be cut short; the parser treats it as
any other line.

### 2. Limits

Every log lives on the machine under examination, so its size and number are chosen by whoever put them
there.

- **Per file:** `read_file`'s 64 MiB bound; the largest log measured was 174,204 bytes. A larger file is not truncated and not range-read; it is
  counted in `files_too_large` and makes its place `partial` (section 4). A range read is ADR 0052's open
  question for crash dumps and would be its own ADR; logs get one only if a measurement shows ordinary
  logs above the bound.
- **Per place:** files are read newest first, by last-write time from the listing (ADR 0050), and at most
  **200 files and 256 MiB** in total per place (owner decision 3). Files left over are counted in
  `files_not_read` and the place's gap is `budget_spent`, which names this program's limit rather than the
  machine (ADR 0030). Newest first means a budget spends itself on the span a reviewer asks about first.
- A wall-clock budget, as `evtx` has (ADR 0024), applies to the whole collector; the number is set in the
  implementation from a measurement of the largest folder, not guessed here.

### 3. What leaves the parser, and what the collector emits

The parser is `rongroi_parsers::fivem_log`: pure, `fn parse(&[u8]) -> Result<FiveMLog, ParseError>`, no
panic on any input, no clock, no path (ADR 0013). Bytes are split on `\n`, a trailing `\r` is dropped, and
each line is decoded lossily as UTF-8, so a byte-order mark, a NUL or an invalid sequence costs that line's
readability and nothing else.

It recognises a line only when the line matches one of a **closed list of templates**, each measured on a
real PC and each naming the server the game connected to or downloaded from (section 8). From such a line
it takes one endpoint: a host — an IPv4 address, a bracketed IPv6 address or a DNS name — and a port when
the line gives one. It returns, per file:

| Value | Meaning |
|---|---|
| `lines` | lines in the file |
| `lines_recognised` | lines whose prefix has the measured shape |
| endpoint records | per endpoint named by a recognised template: how many lines named it |
| `endpoint_shaped_unrecognised` | text in the shape of `host:port` on lines no template recognises — **counted, never returned** |

Text in the shape of `host:port` on any other line is not an endpoint for this collector: it can be a web
service FiveM called, a script's `file.lua:12`, or a player's chat. Counting it lets a reviewer see that the
format may have moved on without the program reporting what it did not understand.

The collector emits, per place:

| Field | Kind | Value |
|---|---|---|
| `location`, `folder` | text | `legacy` or `enhanced`; `listed`, `absent` or `unreadable`, as `fivem_dir` spells them |
| `files` | number | `.log` files in the folder |
| `files_read`, `files_not_read`, `files_too_large` | number | section 2 |
| `files_unrecognised` | number | files read in which no line had the measured prefix |
| `endpoints` | number | distinct endpoints named by recognised lines |
| `earliest_created_at`, `latest_modified_at` | timestamp | the bounds among the files read — the span the endpoints could have come from |

and one observation per distinct endpoint per place:

| Field | Kind | Value |
|---|---|---|
| `location` | text | as above |
| `endpoint` | text | `host:port` or `host`, the host lower-cased, as the recognised line gave it — **sensitive, `server_identity`** |
| `address_kind` | text | `loopback`, `unspecified`, `private`, `public` or `not_an_address` (a DNS name), as `net_config` spells them (ADR 0054) |
| `files`, `lines` | number | how many files read, and how many recognised lines, named it |
| `earliest_created_at`, `latest_modified_at` | timestamp | the earliest creation time and the latest last-write time among the files that named it |

The times are **the files' times from the listing** (ADR 0050), not a time taken from a line. Legacy lines
carry a tick count, not a clock time, and a Legacy file name's time is UTC. Enhanced lines carry a local clock
time with the date day first; which time zone the reader of a report is in is another matter, and no line
that names a server was found to carry it. A time computed from an unmeasured format would be a claim this program cannot support; if the
second probe settles those points, a per-endpoint time from Enhanced lines is an amendment to this ADR, not
an implementation choice. The bounds say "a log file created no earlier than this and last written
no later than this named the endpoint", which ADR 0050 section 3's text already frames as times the file
system reports.

No line text, no URL path, no player name, no resource name and no other field of a line leaves the parser.

### 4. What `partial` means here

The format is undocumented and changes with FiveM's updates, so "no endpoint found" is only a statement
about files the parser understood. A place is `partial` when any file in it was not read in full or not
understood: `files_too_large > 0` or `files_unrecognised > 0`, or a file that could not be read. The
endpoints that were read are still reported; the gap says the list may be short. `partial` is always
listed (ADR 0030), so a reviewer sees it whatever a rule declares. `files_not_read > 0` alone is
`budget_spent`, and a folder that cannot be listed is `unreadable` with `access_denied` or `read_failed`, as
in `fivem_dir`. A folder that is not there is `folder: absent`, not a gap: the edition is not installed for
this user, or has never written a log.

### 5. SS mode

`endpoint` is declared sensitive, of kind `server_identity`, so ADR 0052 section 4 applies unchanged: in SS
mode its value is `%SERVER_IDENTITY%` unless the player also agreed to show server identities, default no.
Self mode shows everything.

What an endpoint says about people, weighed for this ADR:

- **About the player:** which communities they play in, including a reviewer's rivals (the concern that made
  server identities a separate question). The set of endpoints with their times is also a profile of when
  the player plays.
- **About third parties:** a public address can be a hosting provider's, but a small server run from home
  has the host's home address, and an IP address can be personal data of whoever it belongs to. A DNS name
  can carry a community's or a person's name.
- **About the player's own network:** a `loopback` or `private` address is a server on the player's own PC
  or LAN — a developer's own FXServer, most often — and a public address the player controls looks the same
  as any other.

So the recommendation (owner decision 2) goes one step past ADR 0052 for this source: `address_kind` is
**not** sensitive and SS mode always shows it, so a reviewer can see "four public servers and one on this
PC" with identities hidden; and an endpoint whose `address_kind` is `loopback`, `unspecified` or `private` is
shown in SS mode as its kind only **even when the player agreed to show server identities**, as a hosts
line's address is (ADR 0054 section 4). It names the player's own network, not a community.

A report saved with `--json` holds the endpoints in full, as it holds everything a full scan read; the full
scan's question names this read (section 9).

### 6. Plugin names: not collected

ADR 0052's row says "endpoints and plugin names". This ADR proposes endpoints only (owner decision 4):

- whether the logs name plugins at all was not measured; the `.gamelog` files named no `.dll`;
- a name from a log carries no hash and no signer, so no rule could use it without naming a program, which
  ADR 0034 rules out for name-only records, and no `allow` could clear it (`rules/AGENTS.md`);
- a log that lists loaded modules lists every overlay, capture tool and driver helper the player runs,
  which is a list of installed software and not a list of plugins;
- `fivem_dir` already reads the Legacy `plugins` and Enhanced `asi` folders with a hash and a signer per
  file (ADR 0009, ADR 0035, ADR 0036), which is the better source for the same question.

If the measurement shows lines naming ASI plugins loaded from a folder `fivem_dir` does not read, that is a
separate ADR, and the place belongs in `fivem_dir` first.

### 7. Rules

- `fivem_logs/<edition>/server-endpoint` (`context`, `experimental`) matches every endpoint observation, so
  that SS mode lists them after a full scan with the player's agreement, as
  `fivem_servers/enhanced/server-cache-folder` does. Its `falsepositives` are the ordinary causes below. It
  gets an `unconfronted.csv` row: no baseline describes FiveM's logs, and every endpoint observation fires
  it.
- A timeline selector (`role: timeline`, ADR 0051) on the per-place observations, so the span the logs cover
  sits on the timeline beside the server cache folders' times.
- **No rule reads an endpoint's value.** There is no list of servers this project could keep that is not a
  list of third parties, and "this player joined server X" is a fact for the reviewer, not a finding.
- **No rule on an empty or missing log folder**, for the reason ADR 0053 gives for caches: an empty folder is
  what a fresh install, FiveM's own cleanup, a disk cleaner and a person all leave, and as a `found` row it
  would be the sea of red flags ADR 0027 rules out. The folder activity and the timeline already show it.
- The comparisons a reviewer might want — fewer log days than server cache folders, logs that start after
  the newest cache folder — are across observations, which the engine does not join. They belong to the
  timeline, not to a rule.

Ordinary causes the rule text and the view state beside these observations:

- an endpoint is a server the game connected to or downloaded from, as far as a recognised line says; it is
  not how long the player stayed or what they did there;
- a `loopback` or `private` endpoint is most often the player's own development server;
- no endpoint in a folder is what a player who has not joined a server, a FiveM update that changed the log
  format (then `partial` says so), FiveM deleting old logs, a reinstall, a disk cleaner or a person deleting
  logs all leave;
- the same server can appear under a DNS name and an address, and under more than one port, so the count of
  endpoints is not the count of servers;
- the logs cover a shorter span than the server cache folders, so a server with a cache folder and no
  endpoint is ordinary.

### 8. Testing, and the measurement that comes first

Nothing is implemented until the format is measured. The measurement, read-only on a real PC with the
owner's permission, prints counts and shapes only, never a host, an address, a URL, a user name or a line's
text. The first probe (2026-09-30, "Measured" above) covered the files, the encoding, the prefixes and the
counts; the second covers the endpoint templates, hosts inside URLs by scheme and host class, IPv4 addresses
without a port, the "Downloading" lines, the Enhanced date order and the time zone. Together they measure:

- the log file names' shapes, counts, sizes and age range, per edition, and whether FiveM keeps a fixed
  number of files or deletes them by age;
- the encoding: byte-order marks, NUL bytes, invalid UTF-8, line endings, the longest line;
- the line prefix's shape, with letters and digits masked, and whether lines carry a clock time or a tick
  count;
- for every line in the shape of `host:port`, the line's template with the endpoint replaced by a marker and
  every word outside a fixed vocabulary masked, and how many lines have each template;
- how many distinct endpoints there are, by `address_kind`, and how many look like a service domain or a
  source file rather than a server;
- counts of lines naming `.asi` or `.dll` files, drive paths, paths under `\Users\`, the Windows user name,
  and account-identifier prefixes;
- whether the newest log opens for reading while FiveM may be writing it.

The closed list of templates in section 3 is taken from that measurement, one entry per template, each with
the FiveM version it was measured on. Then:

- **Parser fixtures** in `fixtures/parsers/fivem_log/`, written by hand in the measured shapes, with
  addresses from the documentation ranges (RFC 5737's `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  RFC 3849's `2001:db8::/32`) and names under `.test` or `example.` (RFC 2606). No measured line, host or
  address is vendored, and `fixtures/PROVENANCE.md` says which measurement each shape comes from.
- **Parser tests** for each template; CRLF and LF; a byte-order mark; NUL bytes; invalid UTF-8; a last line
  cut short; a line far longer than any measured one; `file.lua:12`-shaped text on an unrecognised line
  (counted, not returned); an IPv6 endpoint; a file in a shape the parser does not know
  (`lines_recognised: 0`).
- **A fuzz target** `fuzz_fivem_log`, seeded from those fixtures (ADR 0016).
- **Collector tests** against `FixtureHost`: both folders absent; one unreadable; a file above the bound; a
  place over the file budget; an unrecognised file (`partial`); a standard scan (`not_consented`); and the
  cross-collector test that every emitted field is declared and that `endpoint` is the only sensitive one.
- **View tests:** SS mode replaces `endpoint` with `%SERVER_IDENTITY%` without the switch, shows it with the
  switch, and shows a `private` or `loopback` endpoint as its kind either way.
- **Baseline:** the runner has no FiveM, so `check-baseline` sees both folders `absent`; the rule's
  `unconfronted.csv` row says so.
- **After it is built:** `scan --full` on a real PC with the owner's permission, elevated and limited, reports
  compared as ADR 0055 did, with nothing measured written down beyond counts.

### 9. Privacy text

The full scan's question (CLI and desktop, both languages), the SS consent question after a full scan and
`PRIVACY.md` gain, in the change that adds the collector: FiveM's log files are read in full; the program
keeps from them only the servers the game connected to — address or name and port — how many files and
lines named each, and the times of those files; nothing else in a line is kept; in SS mode a server is shown
only when the player agrees to show server identities, and a server on the player's own PC or network never.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Report every `host:port` in the logs | Web services, CDNs, script line numbers and chat text would be reported as servers; the reviewer could not tell which is which. |
| Report the URLs too | A URL path can carry a token, a player name or a resource name; the host of a connect line is what the question needs. |
| Compute each connection's time from the line | The line's time format is not measured; the files' own times are known and honestly bounded. |
| Hash the endpoint before reporting it | A hash of a stable identifier is a stable identifier (ADR 0055); it hides nothing and makes the value useless to the reviewer. |
| Show private and loopback endpoints like public ones when the switch is on | They name the player's own network, as a hosts line's address can (ADR 0054). |
| Add plugin names from the logs | Section 6. |
| Range-read files above 64 MiB | A capability of its own ADR, justified only if ordinary logs are measured above the bound. |
| A standard-tier count of endpoints without the values | The owner's decision puts reading the logs in the full tier; a count still needs every line read. |
| A rule for an empty log folder | ADR 0053 and ADR 0027: what a fresh install and a cleaner leave. |

## What is unverified

- Whether FiveM's logs name a joined server on any other PC, FiveM version or way of joining.
- What the two IPv4-shaped values in Legacy's JSON line are, and what the Legacy `Requesting server` line's
  remainder is.
- What the 2026-09-16 pattern counted as six `host:port` values. The Enhanced "Downloading … for `<host>`" line is known to exist;
  whether its host is the server joined is not.
- Whether a server only browsed in the server list, not joined, leaves an endpoint in the logs.
- How many log files FiveM keeps and when it deletes them, in either edition (also ADR 0053): the PC measured
  held 11 of each main Enhanced family over 24 days and 3 Legacy files over 6 days, which is one sample.
- Which programs the 11 lines naming a `.dll` name; no plugin name is collected (section 6).
- Whether the newest log opens for reading while FiveM is running and writing it.
- Whether any of this holds on another FiveM version; the format is expected to change with updates, and
  `files_unrecognised` is how a report says it did.

## Owner decisions

1. **What to do with this source — decided 2026-09-30: park it.** The options weighed were:
   - **park it** — keep this ADR `proposed`, marked parked, with the measurements and the design; build
     nothing; reopen when a measurement on a PC shows a log line that names a joined server;
   - narrow it to Legacy's IPv4 line — a parser and a fuzz target for three lines whose values may be the
     player's own address;
   - withdraw it — and amend ADR 0052 section 6's row "Endpoints and plugin names in FiveM's logs";
   - keep it proposed with the question open.

   The owner chose to park it, as recommended: the premise is not supported on the one PC measured,
   narrowing would read a value that may identify the player's connection, and withdrawing would discard a
   design and a measurement method that a second PC could still need. Nothing is built. **The parking ends
   when** a read-only probe of the kind used here, run on a PC that joined a server within the span its FiveM logs cover, prints the template of a line that names the joined server by an address, or by a name with a port. Reopening is a change to this ADR that records that measurement and takes
   decisions 2 to 8. ADR 0052 section 6's row stays, with a note that the source is parked.

**Decisions 2 to 8 are not decided.** They are the recommendations that would be put to the owner if the
source is reopened, and no one has agreed to them.

2. **If reopened, which lines are read for endpoints.** Only a closed list of measured templates that name the
   server the game connected to; every other `host:port`-shaped text counted, not reported (section 3).
3. **If reopened, SS mode.** `endpoint` a server identity behind ADR 0052's switch; `address_kind` always
   shown; a `loopback`, `unspecified` or `private` endpoint shown as its kind only, even with the switch on
   (section 5).
4. **If reopened, limits.** The 64 MiB per-file bound with no range read — the largest log measured was
   174,204 bytes — newest files first, 200 files and 256 MiB per place, and a wall-clock budget set from a
   measurement (section 2).
5. **Plugin names.** Not collected (section 6); the logs name no `.asi` and 11 lines name a `.dll`.
6. **If reopened, times.** The files' creation and last-write bounds per endpoint (section 3).
7. **If reopened, rules.** One `context`/`experimental` rule listing endpoints and one timeline selector; no
   rule on an endpoint's value and none on an empty folder (section 7).
8. **If reopened, which files.** Legacy's `CitizenFX_log_…` files and only those Enhanced families a
   measurement shows naming a server; on the PC measured that is none of the four (section 1).

## Consequences

While parked: none in code. ADR 0052 section 6's row for FiveM's logs carries a note pointing here. If
reopened:

- `rongroi-parsers`: `fivem_log`, with fixtures under `fixtures/parsers/fivem_log/` and a fuzz target.
- `rongroi-collectors`: `fivem_logs`, tier `full`, registered in `all()` and after `fivem_servers` in
  `COLLECTOR_ORDER`; `endpoint` declared `Field::text("endpoint").sensitive(SensitiveKind::ServerIdentity)`.
- `rongroi-core::view`: the SS-mode kind-only display of a non-public endpoint, if decision 2 is taken.
- `rules/fivem_logs/…` with fixtures and Thai text, a timeline selector, and an `unconfronted.csv` row.
- The consent questions, `PRIVACY.md`, `docs/architecture.md`, the glossary (`fivem_logs`, `endpoint`,
  `files_read`, `files_not_read`, `files_too_large`, `files_unrecognised`, `lines_recognised`), both READMEs
  and both screenshare guides name the read, in the change that adds the collector.
- Every FiveM update can make `files_unrecognised` non-zero; keeping the template list current is ongoing
  work, each new template added with the measurement it came from.
