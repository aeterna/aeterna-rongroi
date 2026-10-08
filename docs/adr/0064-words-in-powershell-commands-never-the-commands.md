# ADR 0064 — Which kinds of words PowerShell's commands held, never the commands

- Status: accepted — the owner decided the seven questions below on 2026-10-08, each as recommended;
  "Before any code" items 1 and 3 measured on 2026-10-08 ("Measured before code"), item 2 (a runner) open
- Date: 2026-10-08

## Context

ADR 0063 put on the timeline what Windows records about PowerShell without reading what it says: the first
and last block PowerShell flagged as suspicious, and deletions in its history folder. Its own measurement
shows where that stops:

- **The loader line is not flagged.** `iex (New-Object Net.WebClient).DownloadString(…)` and
  `Get-Content … | iex` wrote no 4104 on Windows PowerShell 5.1; the script they ran did. PowerShell's list
  of suspicious words has no `Invoke-Expression`, `iex`, `DownloadString` or `Net.WebClient` (ADR 0063,
  "What PowerShell's source says").
- **Flagged blocks are ordinary.** 369 in a day and a half on the one PC measured, a Windows Forms dialog
  among them, so the two times say "PowerShell flagged something then", not what.

A reviewer who wants to know whether a command *downloaded something and ran it*, or *told Microsoft
Defender to look away*, or *cleared a log*, needs words from inside the commands. Three places on the PC
hold them:

| Source | What it holds | Reach on the PC measured |
|---|---|---|
| `ConsoleHost_history.txt` (PSReadLine) | each command typed into a PowerShell window, one per line, **no time** | 2 347 lines, last written 11 days before |
| `Microsoft-Windows-PowerShell/Operational` 4104 at level 3 | the text of each block PowerShell flagged, **with a time** | 1.29 days |
| `Windows PowerShell` 400 | the command line PowerShell was started with (`HostApplication`), **with a time**, the base64 of `-EncodedCommand` included — measured for starts from cmd and from PowerShell; from Win+R or a shortcut expected, not measured | 5.9 days |

The three are complementary and none is enough alone. Measured on the PC (ADR 0063 probes, 2026-10-08):

- `-Command` and `-EncodedCommand` leave **no** history line; their command line is in 400.
- PSReadLine 2.0.0, the version Windows ships, keeps **out of the file** any line containing `password`,
  `asplaintext`, `token`, `key` or `secret` (its source at `v2.0.0`; measured with a scratch history file
  through an interactive session: `HKEY_CURRENT_USER`, `apikey`, `password` and `token` lines were not
  written). The history is therefore incomplete by construction.
- A line pasted into a PowerShell window, the shape a seller of these cheats hands out, **is** written to
  the history.

### Where this meets this project's own rules

This is the first source whose contents are things a person typed. Three standing texts say no to it:

1. `crates/rongroi-collectors/AGENTS.md`: "Collect only what a rule needs. No browser history, screenshots,
   documents, credentials, tokens or unrelated personal files."
2. ADR 0052 §5: no `full` collector may read "any store that holds a credential or a token, whatever the
   player agrees to".
3. PRIVACY.md and ADR 0060: "**It never reads the arguments a program is given** … because arguments are
   where a token, a password or an address is passed to a program."

A command history is not a credential store, but it can hold a credential — PSReadLine's own filter exists
because people type them — and a 400 command line is exactly "the arguments a program is given". So the
question this ADR puts first is not how to read these sources but **whether this project reads them at all**
(owner question 1). Everything after it is the design that would make the answer "yes" as narrow as possible.

## Decision

### 1. A `full` collector, `powershell_text`, that keeps no text

A new collector, `tier: full` (ADR 0052), named `powershell_text`. It reads, in this order and each under its
own size cap:

- every history file PSReadLine keeps under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine` for the
  account running the scan (`ConsoleHost_history.txt`, and any other `*_history.txt` there);
- the text of every 4104 record at level 3 in `Microsoft-Windows-PowerShell/Operational`;
- `HostApplication` of every 400 record in `Windows PowerShell`.

A 4104 block longer than one record is split across records that share a `ScriptBlockId` (`MessageNumber`
of `MessageTotal`); the parser joins the parts of one block before classifying it, so a word split at a part
boundary is still read — on the PC measured, 324 of 367 flagged records were parts of a longer block. Each
line, block or command line is held in memory only long enough to be classified, and then dropped. **No
substring of it reaches an observation**, with one exception, the host in section 4. The parser that
classifies lives in `rongroi-parsers` (pure, fuzzed, ADR 0013, ADR 0016); the collector never sees text it
did not hand straight to it.

ADR 0018's rule — the event payload is not kept — stays for every other event. This widens it for exactly
two (channel, provider, id) triples, and the parser keeps them apart by those three fields, never by id alone
(ADR 0031).

### 2. A fixed list of kinds, as booleans

The parser normalises a text — case folded, PowerShell's backtick escape and `^` removed, adjacent string
literals joined, whitespace collapsed — decodes an `-EncodedCommand` / `-e` / `-enc` argument and a
`FromBase64String('…')` literal as UTF-16LE base64, at most two levels deep and 64 KiB each, and then says,
for each kind below, whether the text holds it:

| Field | Holds |
|---|---|
| `invoke_expression` | `Invoke-Expression`, `iex`, `[scriptblock]::Create`, `.Invoke()` on a script block |
| `remote_download` | `DownloadString`, `DownloadData`, `DownloadFile`, `Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`, `irm`, `Net.WebClient`, `Start-BitsTransfer`, `curl`/`wget` aliases |
| `download_then_execute` | `remote_download` and `invoke_expression` in the same line, block or command line |
| `encoded_command` | an encoded command or a base64 literal, and `decoded` says whether it decoded |
| `execution_policy_bypass` | `-ExecutionPolicy Bypass` / `Unrestricted`, `-ep bypass`, `Set-ExecutionPolicy` |
| `hidden_window` | `-WindowStyle Hidden`, `-w h` |
| `native_interop` | `Add-Type`, `DllImport`, `VirtualAlloc`, `OpenProcess`, `WriteProcessMemory`, `ReadProcessMemory` |
| `defender_tamper` | `Add-MpPreference … -Exclusion…`, `Set-MpPreference … -Disable…` |
| `trace_cleanup` | `Clear-History`, removing a `*_history.txt`, `wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, removing files under `Prefetch` |
| `game_process` | `FiveM`, `GTA5`, `GTA5_Enhanced`, `FiveM_b…_GTAProcess` |

The list is in the parser, not the rules bundle: a rule matches the booleans, and a word added to the list is
a change to the parser, its tests and this ADR. **No word names a cheat or a seller.** Such names change
weekly and turn the list into an advertisement; they are a separate question (section 6).

### 3. Observations: counts and times per source and kind

One observation per `(source, combination of kinds)` with at least one kind true — `source` is `history`,
`script_block` or `engine_start` — carrying the booleans, `count`, and:

- for `script_block` and `engine_start`, `first_seen` and `last_seen`;
- for `history`, no time (the file has none) and `newest_from_end`: how many lines from the end of the file
  the newest such line is — 1 is the last command typed. It says how recent, in commands, without a clock.

Plus one observation per source with `read` (`ok`, `absent`, `partial`, `budget_spent`), the number of lines,
blocks or records examined, and for `history` the file's size and last-write time — so a `not_found` can be
told from an empty or absent source, as everywhere else (ADR 0030).

### 4. The download host, the one piece of text kept, behind its own question

When `remote_download` is true, the host part of the first URL in the text — **only the host**: no scheme,
user name, password, port, path or query, which is where a seller's per-customer key would be. A host that
is an address is reported as its kind only — `loopback`, `private`, `public`, `unspecified` — as
`net_config` does for a hosts line (ADR 0054). A name is lower-cased and kept.

It is a new `SensitiveKind`, `download_host`, with its own SS-mode question, default no; until the player
answers yes, SS mode shows `%DOWNLOAD_HOST%` (ADR 0052 §4). Self mode shows it, as it shows everything.

### 5. Rules

All `experimental`, all with `falsepositives` that name what an ordinary PC does with PowerShell:

- `powershell_text/history/download-then-execute` — `source: history`, `download_then_execute: true`;
  `presence` (a line was typed, not that it succeeded).
- `powershell_text/engine-start/download-then-execute` — the same for 400; `presence`.
- `powershell_text/any/defender-tamper` — `defender_tamper: true`; `tamper`.
- `powershell_text/any/trace-cleanup` — `trace_cleanup: true`; `tamper`.
- A timeline selector on `script_block` and `engine_start` observations with any kind true.

`native_interop`, `game_process`, `hidden_window` and `execution_policy_bypass` get no rule of their own;
they are context on the rows above and in Self mode. A rule pairing `native_interop` with `game_process` is a
later question, once the baseline below says how often ordinary scripts produce it.

### 6. What this ADR does not do

- No list of known loader hosts. A later ADR may add one as a data file in the bundle, matched against
  `download_host`, with its source for each entry.
- No other account's history. The account running the scan only; a scan elevated with another
  administrator's password reads that administrator's folder, and the `read` observation says so, by
  comparing that folder's account with the one running the scan as ADR 0060 does for a task's account.
- No Run dialog history (`RunMRU`): 400 is expected to hold a PowerShell started from it (measured from cmd
  only, ADR 0063 probe), and `RunMRU` holds every other program's command line too.
- No PowerShell 7 log: not registered on the one PC measured (ADR 0063 §3).

## Before any code

Measured on the development PC with a read-only probe that prints counts only, run by the owner's leave:

1. How many of the PC's history lines, flagged blocks and 400 command lines turn each kind true —
   **counts per kind and per source, nothing else** — so that the rules' falsepositives come from a PC, not
   from memory. That PC is the owner's; the probe prints no text, and its output is read before anything is
   written down.
2. The same classification over a GitHub-hosted runner's logs, which this project may publish, as the
   baseline this collector needs (`crates/rongroi-collectors/AGENTS.md`).
3. The time to read and classify the three sources at their sizes on that PC, for the budget.

The outcome is an amendment to this ADR before the change that adds the collector.

## Measured before code (2026-10-08, the development PC)

Items 1 and 3 of "Before any code", by a read-only probe that approximates section 2's kinds with PowerShell
regular expressions and prints counts only (`.claude/probes/`, not in the repository). It left out what this
project's own earlier probes wrote: 0 history lines, 9 flagged blocks, 19 starts. Windows 11 build 26220,
elevated, the account that owns the history.

| Source | Examined | Any kind | By kind |
|---|---|---|---|
| history (1 file, 86 KB) | 2 347 lines | 13 | `execution_policy_bypass` 10 · `remote_download` 5 · `invoke_expression` 4 · **`download_then_execute` 3** (the newest 1 493 commands from the end) · 1 distinct host name, 4 of 5 downloads with a URL |
| 4104 level 3 | 367 records, 123 blocks | **0** | — |
| 400 | 1 517 starts | 1 333 | **`execution_policy_bypass` 1 293** · `encoded_command` 40 (80 of 80 decoded) |

What it changes:

- **`execution_policy_bypass` and `encoded_command` cannot be rules**, which section 5 already says: on this PC
  85 % of PowerShell's starts carry `-ExecutionPolicy Bypass` — tools and scheduled tasks start it that way —
  and 40 starts are encoded. They stay context.
- **`download_then_execute` is found on the owner's own PC**, in three old history lines, from installing
  software. The history rule's `falsepositives` leads with installers that are installed with one line
  (`… | iex`), and its description says the row shows how many commands ago, not when.
- **No flagged block on this PC holds any kind.** What PowerShell flags here is ordinary: 125 of the 379
  records hold the word `Properties`, which is on its list. A block that holds a kind is therefore not
  common, on this PC; one PC is not a population.
- **Time:** reading and classifying the history took 1.5 s, the flagged blocks 8.5 s and the 400 records 41 s —
  through `Get-WinEvent`, which renders every message; the collector reads the `.evtx` file the `evtx`
  collector already parses, so these are an upper bound for the logs, not the budget. The budget is set
  after the parser exists.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| Stop at ADR 0063 | The loader line, the shape the cheat in the reviewed clip uses, stays invisible |
| Show the matching lines in SS mode, or let the player choose to | The line is personal data and may hold a credential; this program has never shown what a person typed |
| A hash of each line, to compare across reports | Two players typing the same seller's line would match; a hash of a short line is guessable; it is an identifier |
| The indicator list in the rules bundle | A bundle file would decide what the collector keeps, so a bundle change would change what is read from a PC without an ADR |
| Reading every 4104 level, not only level 3 | With script block logging on, every block — every script the player ran — is in the log at level 5 |
| History only, or logs only | Each misses what the other holds: `-Command` leaves no history line; a pasted line leaves no 400; history has no time |

## What is unverified

- **Every count of how often the kinds occur.** Nothing has been classified yet ("Before any code").
- **Whether 400 is written for every start**, or only for some hosts; measured for `powershell.exe` started
  with `-Command` and `-EncodedCommand` from cmd and from PowerShell.
- **The normalisation's reach.** Obfuscation can split any word this list holds; the parser undoes the
  common escapes and nothing more, and a text it cannot read as one of the kinds is `false`, not unknown.
  That limit is written into every rule's description.
- **PSReadLine versions other than 2.0.0**, whose filter may differ.

## Owner decisions (2026-10-08)

The owner answered "as recommended" to all seven, question 1 included: this project reads what a person typed,
under the conditions above and nowhere else.

1. **Whether this project reads what a person typed at all**, under the conditions in this ADR, which means
   amending three texts: `crates/rongroi-collectors/AGENTS.md` ("credentials, tokens or unrelated personal
   files"), ADR 0052 §5 and the "never reads the arguments" sentence in PRIVACY.md and ADR 0060 — each to name
   this collector as the one exception, and why. Recommended: **yes, narrowly** — full tier, kinds and counts
   only, one host behind its own question — because the alternative leaves the loader line invisible and the
   design keeps no text. This is the decision; the rest follows from it.
2. Three sources, history + 4104 level 3 + 400 (section 1). Recommended.
3. The kinds of section 2, in the parser, no seller names. Recommended.
4. Observations of section 3, including `newest_from_end` for history. Recommended.
5. `download_host` as a new sensitive kind with its own question, addresses by kind only (section 4).
   Recommended.
6. The rules of section 5: three `presence`/`tamper` rules and a selector, all `experimental`.
   Recommended.
7. "Before any code" measured on the development PC (counts only) and on a runner before the code change.
   Recommended.

## Consequences (if accepted)

- `rongroi-parsers::powershell_text` (pure, with a fuzz target) and `rongroi-collectors::powershell_text`
  (`full`); `SensitiveKind::DownloadHost` and its placeholder, question and translations; amendments to the
  three texts in question 1, to ADR 0018 (two triples) and to ADR 0052 §6's table.
- The full-scan question (CLI and desktop dialog), the SS consent text and PRIVACY.md name the three sources,
  that no text is kept, and the host question.
- A test, beside `a_records_payload_and_computer_name_are_not_kept` in the evtx parser, that runs the
  collector over fixture text holding a password, a token and a URL with a path, and asserts none of them is
  in any observation, the host excepted.
- A `baseline-*` host from the runner measurement, and rules with fixtures.
