# ADR 0047 — The USN change journal: what can be read, and what it may say

- Status: accepted — the recommendation below; no code until measurement 1 under "Before any code" passes
- Date: 2026-09-14
- Amended: 2026-09-14, with measurements on a GitHub-hosted runner ("Measured on a runner"): measurement 1 passed

## Context

README's milestone table lists the USN journal under M3 as planned. ADR 0013 said it "will need the
same decoding" as the M2 artifacts when it comes. Nothing reads it today. No collector, parser, rule or
fixture mentions it.

### What the journal is

Microsoft, [Change Journals](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals): "When
any change is made to a file or directory in a volume, the USN change journal for that volume is updated
with a description of the change and the name of the file or directory."

What a record holds, and what it does not
([Change Journal Records](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records)):

- "The change journal logs only the fact of a change to a file and the reason for the change (for
  example, write operations, truncation, lengthening, deletion, and so on). It does not record enough
  information to allow reversing the change."
- "multiple changes to the same file may result in only one reason flag being added to the current
  record. If the same kind of change occurs more than once, the NTFS file system does not write a new
  record for the changes after the first."
- "The NTFS file system may delete old records to conserve space."

`docs/research/03-pc-check-screenshare-tools.md` already rates it: file create, delete and rename,
retention "circular; days to weeks", cleanable, false-positive risk "high (normal activity)".

### Why it is on M3

The journal is the one source on a Windows PC that records **deletions and renames** of files other
collectors can only see while they exist. A Prefetch file, an Event Log file or a file in FiveM's plugin
folder that is gone at scan time leaves no trace in `prefetch`, `evtx` or `fivem_dir`. The journal may
still hold the record of it going, for as long as the journal's size keeps it.

Every such record has ordinary causes too. Prefetch keeps a bounded number of files (research note 03
records up to 1,024, from a secondary source), the Event Log service writes to its own folder whenever it
records anything, and a player removes a ReShade preset from the plugins folder. That is why this ADR
proposes observations and no rule (Question 3).

### The questions

1. Can this program read the journal without changing anything, and with what rights?
2. What is in a record, and can it be parsed to this repository's bar?
3. What should reach the report, given that the journal names every file changed on the volume?
4. What would a scan cost, and what does the scan itself add to the journal?

This ADR answers from Microsoft's documentation and this repository's code. **Nothing was measured on a
Windows machine for it.** The measurements a collector needs first are under "Before any code". No
collector code, parser, rule, fixture or dependency is part of it.

Every Microsoft page cited was read on 2026-09-14.

## Question 1 — reading the journal without changing anything

### The documented way in

- **A volume handle.** [Obtaining a Volume Handle for Change Journal Operations](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-volume-handle-for-change-journal-operations):
  "call the **CreateFile** function with the *lpFileName* parameter set to a string of the following
  form: \\\\.\\*X*:".
- **Administrator rights.** [Using the Change Journal Identifier](https://learn.microsoft.com/en-us/windows/win32/fileio/using-the-change-journal-identifier):
  "To perform this and all other change journal operations, you must have system administrator
  privileges. That is, you must be a member of the Administrators group." CreateFileW says the same of
  any volume handle: "The caller must have administrative privileges", and "When opening a volume or
  floppy disk, the *dwShareMode* parameter must have the **FILE_SHARE_WRITE** flag"
  ([CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)).
- **Two read operations.** `FSCTL_QUERY_USN_JOURNAL` "Queries for information on the current update
  sequence number (USN) change journal, its records, and its capacity"
  ([page](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_query_usn_journal)).
  `FSCTL_READ_USN_JOURNAL` "Retrieves the set of update sequence number (USN) change journal records
  between two specified USN values"
  ([page](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_read_usn_journal)).
  Neither page describes an effect on the volume.

So a collector reports `not_admin` without an elevated token, like `prefetch` and `bam`. That is
documented. It is not yet measured here, and this project states rights after measuring them (ADR 0033).

### What makes this different from every read so far

**A volume handle is not a file handle.** CreateFileW: it "returns a direct access storage device (DASD)
handle", and "this type of access also exposes the disk drive or volume to potential data loss, because
an incorrect write to a disk using this mechanism could make its contents inaccessible to the operating
system." `crates/rongroi-collectors/AGENTS.md` says collectors open things "for reading only".

- **Access asked for.** Microsoft's own example
  ([Walking a Buffer of Change Journal Records](https://learn.microsoft.com/en-us/windows/win32/fileio/walking-a-buffer-of-change-journal-records))
  opens the volume with `GENERIC_READ | GENERIC_WRITE`. A collector would ask for `GENERIC_READ` only.
  **Whether both read operations succeed on a handle opened without `GENERIC_WRITE` is not stated on any
  page read.** If they do not, the collector cannot be built under this repository's rules, and this ADR
  ends there. That is the first measurement.
- **The share mode is required to include `FILE_SHARE_WRITE`.** That does not ask for write access. It
  lets this handle coexist with the handles Windows holds on the volume for writing.
- **The control codes that change the journal share the call that reads it.** `FSCTL_CREATE_USN_JOURNAL`
  and `FSCTL_DELETE_USN_JOURNAL` go through `DeviceIoControl` like the two reads.
  [Creating, Modifying, and Deleting a Change Journal](https://learn.microsoft.com/en-us/windows/win32/fileio/creating-modifying-and-deleting-a-change-journal):
  deleting "walks through all of the files on the volume and resets the USN for each file to zero". A
  wrong constant would be the most destructive call this program could make. `clippy.toml` cannot ban a
  constant. It can ban a function: `DeviceIoControl` would be banned in `clippy.toml` for the whole
  workspace, and called in one wrapper in `rongroi-host-windows` that takes only an enum of the two read
  codes, with the one `#[allow]` a reviewer can find by grep. That is ADR 0038's pattern, which banned the
  firmware write calls a privilege would permit.

### Not proposed

| Way | Why not |
|---|---|
| `FSCTL_READ_UNPRIVILEGED_USN_JOURNAL` | The `windows` 0.62.2 sources define the constant (`src/Windows/Win32/System/Ioctl/mod.rs`). Microsoft Learn has no page for it; the URL in the pattern of the others returns 404. A third-party project describes it as reading without administrator rights. An undocumented contract is not built on, for the reason ADR 0038 gave for Kernel DMA Protection and ADR 0046 for `SystemModuleInformation` |
| Reading `$Extend\$UsnJrnl:$J` through the raw volume | A second parser over NTFS metadata, ruled out for Amcache in ADR 0041 for the same reasons |
| `FSCTL_ENUM_USN_DATA` | It "Enumerates … to obtain master file table (MFT) records": a listing of the files on the volume, not of changes. Not needed for this idea, and a full file listing is more than any rule needs |

### The journal's own state is documented

`USN_JOURNAL_DATA_V0` ([page](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_journal_data_v0)):

- `UsnJournalID`: "A journal is assigned a new identifier on creation and can be stamped with a new
  identifier in the course of its existence."
- `FirstUsn`: "The number of first record that can be read from the journal."
- `NextUsn`: "The number of next record to be written to the journal."
- `LowestValidUsn`: "The first record that was written into the journal for this journal instance."
- `MaximumSize`: "The target maximum size for the change journal, in bytes. The change journal can grow
  larger than this value, but it is then truncated at the next NTFS file system checkpoint to less than
  this value."

When the identifier changes is also documented. It changes when the journal is deleted and created again,
and also without that: "the NTFS file system restamps a change journal with a new identifier when a volume
is moved from one version of NTFS to another and then back. Such a move can happen in a dual-boot
environment or when working with removable media" (Using the Change Journal Identifier). And "Change
journals are not necessarily created at startup. To create a change journal, an administrator may do so
explicitly or start another service that requires a change journal" (Creating, Modifying, and Deleting).

**No Microsoft page read states that the journal is on by default on a Windows 10 or 11 system volume, or
its default size.** A forensics blog gives "usually 0x2000000 (32 MB)". A collector therefore has to
expect a volume with no journal. The error that operation returns then is not established here, and it
would map to `source_absent` only once measured.

### Answer to Question 1

**Documented as feasible for an administrator, and not yet shown to be feasible read-only.** It turns on
one measurement: both read operations on a volume handle opened with `GENERIC_READ` alone.

## Question 2 — records, and parsing them

### The layout

`FSCTL_READ_USN_JOURNAL` "return[s] a USN followed by zero or more change journal records, each in a
**USN_RECORD_V2** or **USN_RECORD_V3** structure" (Walking a Buffer). Per record
([USN_RECORD_V2](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2),
[USN_RECORD_V3](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v3)):

- `RecordLength`, `MajorVersion`, `MinorVersion`;
- `FileReferenceNumber` and `ParentFileReferenceNumber`, 64-bit in version 2 and 128-bit in version 3,
  each "an arbitrarily assigned value that associates a journal record with" the file or its parent
  directory;
- `Usn`; `TimeStamp`, "The standard UTC time stamp (FILETIME) of this record";
- `Reason`, flags such as `USN_REASON_FILE_CREATE` `0x00000100`, `USN_REASON_FILE_DELETE` `0x00000200`,
  `USN_REASON_RENAME_OLD_NAME` `0x00001000`, `USN_REASON_RENAME_NEW_NAME` `0x00002000` and
  `USN_REASON_CLOSE` `0x80000000`;
- `SourceInfo`, `SecurityId`, `FileAttributes`;
- `FileNameLength`, `FileNameOffset`, and the name.

**A record names a file. It does not give its path.** The only location it carries is the parent's
reference number. "A rename or move operation generates two USN records, one that records the old parent
directory for the item, and one that records a new parent."

Version 4 records carry extents and no name. They are "only output when range tracking is turned on"
([USN_RECORD_V4](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v4)).
A read would ask for versions 2 to 3 through `READ_USN_JOURNAL_DATA_V1`'s `MinMajorVersion` and
`MaxMajorVersion`. Those two fields have no description on Microsoft's page, so what the call returns when
they are set is a measurement too.

On versions: "If your code detects a change in the major version number of the change journal software, it
should not work with the change journal." A parser stops at a major version it does not know, and the
collector reports it rather than guessing.

### The bar

The bar is ADR 0013, 0015, 0016 and 0018: pure bytes in, never a panic or hang, allocations bounded by the
bytes available, a fuzz target in `fuzz smoke (ubuntu)`, seeds that are the L0 fixtures.

The kernel writes this buffer, not a file an attacker hands over. It is still decoded to that bar, for
two reasons: the parser is tested on bytes a test writes, and a defect found in `evtx` showed what an
unguarded length does. The hazards are concrete:

- **`RecordLength` of 0.** Microsoft's own sample advances by `RecordLength` with no check, so a zero
  never advances and the loop never ends. A parser refuses a length shorter than the fixed part of a
  record.
- `RecordLength` past the end of the buffer; `FileNameOffset + FileNameLength` past the end of the record;
  an odd `FileNameLength` for UTF-16.
- Alignment: "all records are aligned on 64-bit boundaries from the start of the buffer."

No crate was searched for this ADR. The format is small next to binary XML, and `rongroi-parsers` has
written parsers of this size before (`bam`, `pca`, `prefetch`).

**Fixtures.** `fixtures/parsers/PROVENANCE.md` already takes fixtures that are "synthetic and
hand-written" from a documented layout, and says "Never copy files from a real player's PC into this
repository." A USN buffer from anyone's PC lists that person's file names, so it is not publishable. The
seeds would be written from the layout above.

### Answer to Question 2

**Feasible to this repository's bar**, as a new parser module with its own fuzz target.

## Question 3 — what reaches the report

### The privacy problem

The journal names every file created, changed, renamed or deleted on the volume while it retains: document
names, browser cache entries, the user's own folder name, the names of other programs. That is further from
"Collect only what a rule needs" (`crates/rongroi-collectors/AGENTS.md`) than anything this program reads,
Prefetch included. ADR 0021 read Prefetch's loaded-file list and reported none of it.

Two more fields identify the machine rather than an event. `UsnJournalID` stays the same across scans of
one journal. File reference numbers are stable per file. ADR 0021 declined to emit a volume serial number
as "A stable identifier of one machine". The same reasoning keeps both out of the report.

### Folders this program already reads, by reference number

A record carries `ParentFileReferenceNumber`. A collector could learn the file identifiers of the folders
other collectors already read, by opening each folder, and keep only records whose parent is one of them:

| Folder | Read today by |
|---|---|
| `%SystemRoot%\Prefetch` | `prefetch` |
| `%SystemRoot%\System32\winevt\Logs` | `evtx` |
| `%WinDir%\appcompat\pca` | `pca` |
| FiveM's `plugins` folder and Enhanced's `gta5enhanced\asi` | `fivem_dir` |

Everything else the journal holds is dropped. If the parser returns no name at all, the collector never
holds one.

Two things about this are not established:

- **That a record's parent reference equals what opening the folder returns** as its file identifier, in
  both the 64-bit and the 128-bit forms. The documentation calls both "arbitrarily assigned", and whether
  the two APIs agree is a measurement.
- **A folder that was itself deleted and made again** has a new identifier. Records about the old folder
  are not attributed to the new one. That loses evidence, and it cannot invent any.

### What an observation would carry

This is the shape to argue about, not a decision. Records are **counted, never listed**, as `evtx` counts
events (ADR 0018, ADR 0024).

- **One account of the journal,** for the system volume: whether a journal was there and read; how many
  records were read and of which major versions; the time of the oldest and newest record read; whether
  the journal still holds its first record (`FirstUsn` equal to `LowestValidUsn`); and `MaximumSize`.
  **Not** `UsnJournalID`, and no USN values that would identify one journal across reports.
- **Per watched folder,** discriminated by folder (ADR 0044): how many records carried a create, a delete,
  a rename, or a data change, and the first and last time of each. No names.

The oldest record's time is this source's retention window, measured on each scan rather than written into
a rule.

### What it may not be read as

- **A delete or rename count is not evidence of cleaning.** Prefetch's own bound, the Event Log service and
  ordinary software all produce them. Each has to be measured on an ordinary machine before any rule
  reads it, the way ADR 0028 read `logs_without_records` as evidence for the benign explanation.
- **A journal that still holds its first record is not evidence it was deleted.** It is also a journal that
  has not filled yet, a new installation, a volume moved between NTFS versions, or a journal a service
  created. "Nothing trimmed since creation" is context for the retention window. It is not tamper.
- **No record of a file is not evidence the file never changed.** Records age out, and repeated changes
  collapse into one record.

### Rules

**None proposed.** Each candidate needs a measured ordinary baseline for the count it reads, a
`falsepositives` list for that folder, and its own ADR. Candidate strengths: `context` for the journal
account; `tamper` only for a shape a baseline shows ordinary machines do not have.

## Question 4 — cost, and what the scan itself adds

- **Size.** The journal is bounded by `MaximumSize` plus `AllocationDelta` and can be larger between
  checkpoints. `fsutil usn` says "The change journal can grow to more than the sum of the values of
  **maxsize** and **allocationdelta** before being trimmed." An administrator can raise it. Time to read an
  ordinary journal was not measured.
- **Direction.** "To obtain the records in which you are interested, you must start at the oldest record
  (that is, with the lowest USN) and scan forward" (Using the Change Journal Identifier). **A budget that
  stops a read early loses the newest records**, the ones most likely to matter. A collector either reads
  to `NextUsn` as the query found it, or reports `budget_spent`, which SS mode always lists
  (ADR 0030, ADR 0032). `budget_spent` is `evtx`'s alone today and would gain a second producer.
- **The journal moves while it is read.** Records older than `FirstUsn` can be trimmed during the read; the
  read then fails with `ERROR_JOURNAL_ENTRY_DELETED` ([READ_USN_JOURNAL_DATA_V1](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v1)).
  The identifier can change, and the call "fails and returns an appropriate error code". Both are a read
  that did not finish: `partial` or `read_failed`, never `source_empty`.
- **The scan writes to the journal.** Launching this program creates or updates its own Prefetch file where Prefetch is on, and
  the desktop app's WebView2 writes its profile. Both add records. The first lands in a watched folder, so
  counts include this program's own launch unless the collector separates it. How to do that without
  holding names is a question for the collector's ADR (ADR 0010 separates own traces by path and SHA-256,
  and a count has neither). Research note 04 records that writing many files "can overwrite USN evidence";
  this program writes few, and how few was not measured.

## Recommendation

1. **Build nothing until measurement 1 passes.** If both read operations fail on a volume handle without
   `GENERIC_WRITE`, record that here and close the M3 item as decided against.
2. If it passes: a `usn` collector for the system volume. A journal account, plus counts per folder that
   other collectors already read. Names dropped in the parser. No `UsnJournalID`. No rule.
3. `DeviceIoControl` banned in `clippy.toml` outside one wrapper that accepts only the two read codes.
4. A pure parser in `rongroi-parsers` with a fuzz target, seeded from hand-written fixtures.
5. `PRIVACY.md` and the consent question name the journal in the same pull request as the collector.

## Before any code

1. **Read-only access.** On a GitHub-hosted Windows runner, elevated: `FSCTL_QUERY_USN_JOURNAL` and
   `FSCTL_READ_USN_JOURNAL` on `\\.\C:` opened with `GENERIC_READ` and
   `FILE_SHARE_READ | FILE_SHARE_WRITE`. Record only success or the error code.
2. **Rights.** The same under a limited token on the runner, which is thrown away afterwards (the CAPI2
   step in `.github/workflows/windows.yml` already changes a runner on that basis). Expected `not_admin` by
   Microsoft's documentation, to be measured.
3. **Folder identifiers.** Whether records under `%SystemRoot%\Prefetch` carry a parent reference equal to
   the folder's identifier as a folder handle reports it, in both widths.
4. **Versions.** What `READ_USN_JOURNAL_DATA_V1` with major versions 2 to 3 returns, and what a query
   returns on a volume with no journal.
5. **Cost.** The journal's `MaximumSize`, bytes read and time taken on the runner.
6. **A baseline.** Counts per watched folder from the runner, with no names, in a `baseline-*` host whose
   `fixtures/hosts/PROVENANCE.md` row says it is a runner image and not a gaming PC.

## Measured on a runner

**Where and how.** One GitHub-hosted runner, image `windows-2025-vs2026`, Windows Server 2025 Datacenter
build 26100, on 2026-09-14: workflow run [`34868203532`](https://github.com/aeterna/aeterna-rongroi/actions/runs/34868203532), commit `077a7e0` on a throwaway branch that was deleted afterwards. The
probe was a PowerShell script compiling C# at run time. It printed counts, forms and error codes and
nothing else, and it is not kept in this repository. It ran under three tokens:

- **elevated:** the runner's own token. GitHub's runners run as administrator with UAC off
  (`.github/workflows/windows.yml`);
- **restricted:** a token made from that one with `CreateRestrictedToken`, Administrators and
  `S-1-5-114` deny-only and privileges removed with `DISABLE_MAX_PRIVILEGE`, used by impersonation. It keeps the
  elevated token's integrity level, so it is not a UAC limited token;
- **standard user:** a local account created for the run, not a member of Administrators, running the
  probe through a scheduled task. That is the closest the runner comes to an ordinary account.

The runner and the account were discarded with it.

The same run carried ADR 0046's measurements. Every volume handle below was opened with `GENERIC_READ` and
`FILE_SHARE_READ | FILE_SHARE_WRITE`, `OPEN_EXISTING`. The probe had a control that opens with
`GENERIC_WRITE` as well, and it runs only if the read-only attempt fails. **It never ran.**

| | Elevated | Restricted | Standard user |
|---|---|---|---|
| Open `\\.\C:` (NTFS, system volume) | ok | failed, 5 (`ERROR_ACCESS_DENIED`) | failed, 5 |
| Open `\\.\D:` (NTFS) | ok | failed, 5 | failed, 5 |
| `FSCTL_QUERY_USN_JOURNAL` on C: | ok, 80 bytes back | — | — |
| `FSCTL_QUERY_USN_JOURNAL` on D: | failed, 1179 (`ERROR_JOURNAL_NOT_ACTIVE`) | — | — |
| `FSCTL_READ_USN_JOURNAL` on C:, from `FirstUsn` to the query's `NextUsn` | ok | — | — |

**The journal on C:.** `MaximumSize` 33 554 432 bytes (32 MiB), `AllocationDelta` 8 388 608. `NextUsn` minus
`FirstUsn` was 35 781 184 bytes. `FirstUsn` was not equal to `LowestValidUsn`, so records had been trimmed
since the journal was made. Supported major versions 2 to 4.

**The read.** `READ_USN_JOURNAL_DATA_V1` was accepted at 48 bytes, asking for major versions 2 to 3. With a
1 MiB output buffer it took 40 calls and 1.04 seconds, and returned 371 278 records in 41 321 568 bytes.
**Every record was major version 3**; none was version 2, and none was malformed. The oldest record was
from 2026-09-08T01:11Z and the newest from the moment of the read: about six and a half days on a runner
image, which is not a measurement of a PC.

**Folder identifiers.** Before the read, the probe made a folder on C:, created a file in it, renamed the
file and deleted it. The folder's 128-bit identifier from `GetFileInformationByHandleEx` with `FileIdInfo`
was compared with each version 3 record's `ParentFileReferenceNumber`:

| Folder | Records whose parent matched | With a create | Rename | Delete | Data change |
|---|---|---|---|---|---|
| the probe's own folder | 7 | 3 | 3 | 1 | 2 |
| `%SystemRoot%\System32\winevt\Logs` | 723 | 3 | 0 | 0 | 722 |
| `%SystemRoot%\Prefetch` | 0 | | | | |
| `%WinDir%\appcompat\pca` | 0 | | | | |

A record can carry several reasons, so a row's columns do not add up to its total. The probe's folder got
exactly the create, rename and delete it made. The runner's Prefetch and PCA folders got none in six and a
half days, which is consistent with a runner image and says nothing about a PC. Without Administrators the
Prefetch folder itself could not be opened (5); the Event Log and PCA folders could.

### What that settles, and what it does not

1. **Measurement 1 passed.** Both read operations work on a volume handle opened without `GENERIC_WRITE`.
   The M3 item stays open, and Recommendation 2 onward applies.
2. **Rights:** without Administrators the volume cannot be opened, with error 5, under a restricted token
   and under a standard account. A collector reports `not_admin`.
3. **Folder identifiers:** the 128-bit identifier matches, shown by a folder with known changes in it.
   The 64-bit comparison for version 2 records was not exercised, because none arrived.
4. **Versions:** this image returned version 3 when asked for 2 to 3. Whether a Windows 11 PC returns
   version 2 is not known. A collector that asks for 3 to 3 would need only the 128-bit comparison, if a PC
   honours that request, which is also not known.
5. **No journal:** a volume without one answers the query with 1179, `ERROR_JOURNAL_NOT_ACTIVE`. That is
   `source_absent`. Whether any other error means the same is not known.
6. **Cost:** about 39 MiB of records in about a second, for a journal whose `MaximumSize` is 32 MiB. A read to `NextUsn` fits inside a
   scan without cutting off the newest records.
7. **A baseline** (measurement 6): the per-folder counts above are the runner's. The fixture is made from a
   run of the collector itself.

## What is not established

- Every rights and behaviour statement on a Windows 10 or 11 PC. The runner is Windows Server 2025.
- Whether the journal is on by default on Windows 10 and 11, and its default size there.
- Whether a PC returns version 2 records, whether it honours a request for version 3 only, and the 64-bit
  parent comparison.
- How long an ordinary journal retains on a PC, and how many records a scan of one reads.
- Records in a Prefetch folder on a machine where Prefetch is on.
- The contract of `FSCTL_READ_UNPRIVILEGED_USN_JOURNAL`.

## Consequences

- No code, no rule, no fixture, no dependency. `Cargo.lock`, `deny.toml`, `clippy.toml` and the report are
  unchanged.
- Accepted by the owner on 2026-09-14, with the five points of the recommendation as written.
- README's M3 row, in both languages, links here: the USN journal is designed, and waits on the
  measurements under "Before any code".
