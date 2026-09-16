# ADR 0050 — Times and sizes of the entries a listing returns

- Status: proposed
- Date: 2026-09-16

## Context

A reviewer reading a report asks *when* as often as *what*: when a folder's contents were last written, when
a folder a program keeps per server was created, whether a cache is days old or minutes old. Today no
collector can answer, because `FilesystemSource::list_dir` returns a name and whether the entry is a file,
and nothing else. ADR 0009 said so in one line — "No timestamps, no size, no owner or ACL, no attributes" —
and the amendments by ADR 0019 and ADR 0037 kept that line while changing the rest. None of the three gives a reason for
leaving times and sizes out; the source then had one consumer, the plugin folder, whose rules needed a hash.

The times a report already carries come from artifacts that record an event themselves — `last_run` from
Prefetch, BAM and PCA, `first_seen`/`last_seen` from the Event Log and the USN journal — and from the
report's own anchors (`generated_at`, `boot_time`, ADR 0039). A folder whose files are the evidence has no
such artifact: its own entries are the only record.

Adding what a source returns is an ADR (CONVENTIONS.md §8), and this one changes what ADR 0009 declined.

## What the listing already holds

`LiveHost::list_dir` uses `std::fs::read_dir`. On Windows, Rust 1.98.1 — the pinned toolchain — builds each
entry from the `WIN32_FIND_DATAW` that `FindFirstFileExW`/`FindNextFileW` fill in, and `DirEntry::metadata`
converts that same structure without another system call and without opening the entry
(`library/std/src/sys/fs/windows.rs`, `impl DirEntry`, tag `1.98.1`). The structure carries the creation,
last-access and last-write times and the size. So nothing new is opened to get them, and nothing about the
files is touched that `list_dir` does not touch today.

Microsoft documents what those values are, and what they are not:

- [File Times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times): NTFS stores times in
  UTC; "The only guarantee about a file time stamp is that the file time is correctly reflected when the
  handle that makes the change is closed"; `SetFileTime` "lets you modify creation, last access, and last
  write times without changing the content of the file"; NTFS "delays updates to the last access time for
  a file by up to 1 hour"; FAT's write time has a resolution of 2 seconds and its access time of one day.
- [FindFirstFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew):
  "In rare cases or on a heavily loaded system, file attribute information on NTFS file systems may not be
  current at the time this function is called."

## Measured

On one Windows 11 PC (build 26220), with the owner's permission, read-only, printing counts and times only —
no file names and no values from the files. The same `FindFirstFile` data, read through PowerShell's
`Get-ChildItem`, over FiveM's own folders:

- Every listed file and folder had a creation time, a last-write time and a size.
- A folder's own times were readable from its parent's listing, and they differed from the times of the
  files inside it: a per-server cache folder's creation time is not its newest file's.
- **Last-write times earlier than creation times were ordinary.** FiveM's `citizen` folder held files
  written in 2022 and created in 2026; a browser profile under FiveM's roaming folder held files written
  `2001-01-01T00:00Z`. Files that arrive from an archive or an installer carrying their original write
  time would explain both; that explanation was not traced here. Either way, neither value on its own says
  when anything happened on this machine.

The GitHub-hosted runner was not needed for this ADR's question: what the listing returns is a property of
the standard library and the file system, and the PC read it the same way.

## Decision

### 1. `DirEntryInfo` gains three optional values

```text
DirEntryInfo { name, is_file, size: Option<u64>, created: Option<Timestamp>, modified: Option<Timestamp> }
```

- `size`: the entry's size in bytes as the listing reports it. `None` for a directory.
- `created`, `modified`: the entry's creation and last-write times, converted from `FILETIME` with
  `rongroi_parsers::filetime::to_timestamp`, and **truncated to whole seconds**. A reviewer reads a folder's
  times against events minutes or days apart; the 100-nanosecond part adds nothing to that reading and makes
  two reports of the same machine easier to link (section 4).
- `None` when the listing did not provide the value, or when the value is outside the range `to_timestamp`
  represents. `None` is never a zero, and a zero `FILETIME` converts to 1601 like any other value.
- **The last-access time is not read.** NTFS delays it by up to an hour, and a listing like this one is
  itself an access to the folder.

`LiveHost` fills the values from `DirEntry::metadata`, which reads the listing's own data. It does not call
`std::fs::metadata` or open any entry. An entry whose metadata cannot be converted keeps its name and
`is_file`, and its three values are `None` — one entry's times are never a reason to fail the listing.

`NonWindowsHost` is unchanged: its `list_dir` is `Unsupported`.

### 2. Fixtures say it or say nothing

`FixtureFile` gains `size`, `created` and `modified`, each optional, times in RFC 3339 UTC. A fixture that
does not write one returns `None` for it, never a default: a fixture written before this ADR describes
entries whose times were not modelled, not entries created at the epoch.

### 3. What the values mean, written where they are shown

Every place that shows one of these values says, in its own words, that:

- they are what the file system recorded, which programs update as they create, copy, extract and write
  files, and which any program able to write a file can set;
- a last-write time earlier than a creation time is ordinary (section "Measured");
- a folder's own times are not its files' times;
- no value orders two events on its own, and none says who or what wrote it.

This repository does not document how times are set by hand beyond the sentence above (AGENTS.md, purpose
boundary).

### 4. What the values reveal

A report that carries a folder's creation time to the second can be matched with another report of the same
machine, as a Prefetch `last_run` already can. The times are not a machine identifier in the sense of
ADR 0021 — a volume serial and a Prefetch creation time together name one Windows installation, and a
folder's times change when the folder is recreated — but they are specific. Each collector that emits them
says so in the consent question and in `PRIVACY.md` in the same change.

### 5. No collector emits them yet

This ADR changes what the source returns. A collector that emits a size or a time does so through its own
field declarations (ADR 0026), with its own ADR or amendment naming the places and the reason, and with the
consent text and `PRIVACY.md` updated in the same change. The first intended consumer is `fivem_dir`, for
FiveM's cache, log and crash folders and the Enhanced per-server cache folders; that is a separate ADR.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| `std::fs::metadata` or `GetFileInformationByHandle` per entry | Opens every entry, which the listing does not, and adds a system call per file. It would answer the currency note above, at that cost; the note names a rare case, and no reading here needs the difference. |
| Keep the full 100-nanosecond value | No reading needs it, and it makes two reports easier to link (section 4). |
| Read the last-access time | Delayed by up to an hour, and moved by reading. |
| A separate `file_times(path)` call | A second pass over names already listed, with a window in which the entry can change between the two. |
| Read NTFS's `$FILE_NAME` times beside the listed ones | Needs the raw volume or the MFT, set aside in ADR 0041 and ADR 0047. |

## What is unverified

- Whether the listing's values lag on a busy PC by an amount a reviewer would notice. Microsoft names the
  case and gives no bound. It is not measured here.
- Folders on FAT or exFAT volumes, and on network shares. Only NTFS was read.
- Which operations move a folder's own last-write time. NTFS is commonly described as updating it when an
  entry inside is created, removed or renamed and not when a file inside is written; the PC reading fits
  that (a per-server folder's last write was older than its newest file), but no Microsoft page read here
  states it, and the text shown to a reviewer does not rely on it.
- Whether Windows or FiveM keeps a folder's creation time when a folder is replaced by a rename. A folder
  created under another name and renamed into place carries its original creation time on NTFS; that was
  not tested here.

## Consequences

- `rongroi-host`: `DirEntryInfo` gains `size`, `created` and `modified`. Every construction site and test
  that builds one changes.
- `rongroi-host-windows`: `list_dir` fills them from `DirEntry::metadata`, with a live test on the Windows
  CI runner that creates a file in its own temporary folder and checks that `size` matches and that
  `created`/`modified` fall between two readings of the clock.
- `rongroi-host` fixture: `FixtureFile` gains the three optional keys; a fixture test pins that an absent
  key reads as `None`.
- No collector, rule, report snapshot, consent text or `PRIVACY.md` line changes with this ADR (section 5).
- ADR 0009's "No timestamps, no size", and its restatement in the paragraph ADR 0019 added, are amended for
  these three values.
  Owner, ACL, other attributes and the last-access time remain unread.
