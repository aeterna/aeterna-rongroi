# ADR 0047 — The USN change journal: what can be read, and what it may say

- Status: accepted — the recommendation below; measurement 1 under "Before any code" passed, and the `usn` collector is implemented (see Consequences)
- Date: 2026-09-14
- Amended: 2026-09-14, with measurements on a GitHub-hosted runner ("Measured on a runner"): measurement 1 passed
- Amended: 2026-09-30, accepted: a folder on another volume, and the first rules that read a count
  ("Amendment (2026-09-30, accepted)"), with two readings of the journal on a Windows 11 PC;
  implemented (see Consequences)
- Amended: 2026-09-30, by ADR 0061 (owner decision 6): the journal observation gains
  `journal_created_on` ("Amendment for ADR 0061: `journal_created_on`"); "Not `UsnJournalID`" still holds
  for the identifier itself

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

## Amendment (2026-09-30, accepted — the owner decided the six questions below on 2026-09-30): a folder on another volume, and the first rules that read a count

The owner accepted this amendment on 2026-09-30, with the six decisions listed at its end, and it is
implemented (see Consequences). It answers the open question under "What is not established" about a watched folder on another
volume, and decides the first rules that read a watched folder's counts.

### Measured on a PC

One Windows 11 PC (build 26220), on 2026-09-15, at its owner's request: the command-line scan built from
`dev` at `ab26a88`, run once elevated and once under the same account's limited token. Nothing from the
scan was committed. What it showed of `usn`:

| | Elevated | Limited |
|---|---|---|
| `\\.\C:` opened with `GENERIC_READ` | yes | no, error 5, so the collector reported `not_admin` |
| Observations from `usn` | 6: the journal and five folders | none |
| Journal records read | 387 660, all version 3 (`records_version_2` 0) | — |
| `maximum_size` | 33 554 432 (32 MiB) | — |
| `trimmed` | true | — |
| The journal's span, oldest to newest record | **about 39 minutes** (06:35 to 07:14 UTC) | — |
| `prefetch` records | 242 | — |
| `winevt_logs` records | 56 | — |
| `appcompat_pca` records | 2 | — |
| `plugins`, `enhanced_asi` | `identified`, 0 records each | — |

The runner's journal had the same maximum size and covered six and a half days. This PC's covered 39
minutes. A PC in use writes far more records than an idle runner image, and the journal keeps a size, not
a time. **On this PC, a count the journal gives is a count for the last 39 minutes before the scan, and
nothing older.** One PC is not a distribution. How long the journal reaches on other PCs is not known.

#### The probe, on the same PC (2026-09-30)

The probe described under "Before any code: a probe on the PC" ran on the same Windows 11 PC (build 26220)
on 2026-09-30, once elevated and once under the limited token through a scheduled task with the limited run
level. It printed only the counts and forms listed there. Its output was not committed, and the script was
removed from the PC.

**The journal**, elevated:

| | |
|---|---|
| `MaximumSize` / `AllocationDelta` | 33 554 432 / 8 388 608 bytes |
| Trimmed since it was made | yes |
| Records read | 376 781, all version 3; none damaged |
| Bytes, calls, time | 43 991 800 bytes in 42 calls, 0.24 s |
| **Span, oldest to newest record** | **39 minutes** (10:24 to 11:03 UTC) |
| Records per minute | about 9 650 |
| Records anywhere on the volume carrying a delete / a rename's old name | 70 315 / 570 |

Two readings of the same PC, fifteen days apart, gave the same 39 minutes. It is still one PC.

**Where the folders are.** All five watched folders and ten of the eleven FiveM folders the probe also looked
at exist (FiveM Legacy's `mods` does not). Every one that exists has its base variable on the system drive
letter, no reparse point on the way down, the system volume's serial, and NTFS. **`other_volume` does not
occur on this PC.**

**Per folder**, of the records whose parent is the folder:

| Folder | Records | Create | Delete | Rename (old / new) | Data change | Close |
|---|---|---|---|---|---|---|
| `prefetch` | 409 | 9 | 0 | 0 / 0 | 406 | 136 |
| `winevt_logs` | 65 | 0 | 0 | 0 / 0 | 65 | 23 |
| `appcompat_pca` | 2 | 0 | 0 | 0 / 0 | 2 | 1 |
| `plugins`, `enhanced_asi` | 0 | | | | | |
| FiveM's own root, `FiveM.app`, `citizen`, `logs`, `crashes`, `data\cache`, `data\server-cache-priv`, Enhanced's roaming folder, its `mods` and its `servercache` | 0 each | | | | | |

No watched folder had a deletion or a rename in the span. So the probe could not measure how many records
one deleted or renamed file leaves on a PC. Nothing in FiveM's folders changed in those 39 minutes either.
That says nothing about a span in which FiveM ran or updated.

**Under the limited token:**

- `\\.\C:` was refused with error 5, as on 2026-09-15. The collector reports `not_admin` for the whole run.
- **Opening the Prefetch folder to read its identifier was also refused, with error 5.** Every other folder
  could be identified. The runner showed the same for Prefetch without Administrators (above).

What the collector does with that, read from `usn.rs`: `locate` runs first and would record Prefetch as
`Unreadable(not_admin)`, since `reason_for` maps a denial without elevation to `not_admin`. Then the journal
read is refused, and `collect` returns `Unmeasured { not_admin }` for the whole run, discarding every
place's result. So the Prefetch refusal never reaches a report on its own. It is inside the run-level
`not_admin`, which the timeline shows once and which each rule on `usn` would add to `ScopeNotes`. A
per-place gap for Prefetch (ADR 0044) would only appear if the volume could be opened without
Administrators, which neither the runner nor this PC allows. In an elevated scan, `access_denied` on
Prefetch alone would be a per-place gap confined to `prefetch`, and none of the rules decided here reads that place.
Nothing in ADR 0044 or in the proposals below needs to change for this. The collector's test for a refused
volume already covers the path.

### What happens today to a folder on another volume

Read from `crates/rongroi-collectors/src/usn.rs` at `0746990`. The journal read is always the system
volume's, the drive letter of `%SystemRoot%`. Before the read, `locate` classifies each watched folder, and
a folder is `other_volume` in two cases:

1. **Its base variable names another drive letter.** `%LOCALAPPDATA%` or `%APPDATA%` on `D:` is caught
   before any file is opened.
2. **Its path is on the system drive letter, but its identifier names another volume.** The folder's
   `FileIdInfo` carries a `VolumeSerialNumber` different from the one read from the root of the system
   volume. That is what a junction to another drive produces (the `usn-folder-on-other-volume` fixture).

For such a folder the collector emits an observation with `location` and `folder: other_volume` and no
count, and a `DiscriminatorGaps` entry that marks every other field `read_failed` for that `location`
alone (ADR 0044). The code comment says why it is not `not_attempted`: that reason's words say the scan
stopped before reaching the source. Its records are never compared, so a record is never credited to a
folder the journal read never reached.

Where that shows today:

- **No evidence row.** No rule makes evidence from `usn`. The one file that reads it,
  `usn/timeline/watched-folder-record-times`, is a timeline selector (ADR 0051) and makes none.
- **The timeline.** `scan.rs` turns the gap on `first_seen` into an unmeasured source: `usn`, that place,
  `read_failed`. The timeline shows it in both modes, where the folder's times would be.

The problem is the next step. **Once any rule makes evidence from a watched folder's counts, `read_failed`
becomes a row that SS mode always lists and no rule can declare** (ADR 0032). A PC whose FiveM folder is on
a game drive would show "this could not be read" on every scan. Nothing failed: this build reads one
journal by design, and the folder was never within it.

Which folders this can happen to: the three under `%SystemRoot%` are on the system volume by definition,
because the journal read is chosen from `%SystemRoot%`. The two FiveM folders are under the user's profile,
which a player can move to another drive, by moving the profile folders or by a junction made to free space
on `C:`. How common that is on players' PCs was not measured.

### The options

| Option | What a row would say | Against it |
|---|---|---|
| Keep `read_failed` | "this could not be read", always listed | A statement of failure where nothing failed, on every scan of such a PC |
| `source_absent` | "this PC has no such record to read" | The folder is there. ADR 0030 split `source_absent` from `source_empty` because one word for two situations told a reader something false |
| `not_attempted` | "the scan stopped before reaching it" | Already rejected: the scan did not stop. It is also a scope statement and never a row |
| **A new reason, `other_volume`** | "this is on another drive, and this program reads only the system drive's change journal" | A fourteenth reason, with the cost of any reason: the enum, the `types.ts` mirror, both locales, ADR 0030's table |
| Read that volume's journal too | the counts, from the other volume's journal | See below |

**Reading the other volume's journal** would give the counts rather than a reason. It does not remove the
need for a reason, and it adds cost:

- That volume may have no journal. The runner's `D:`, an NTFS volume, answered 1179
  (`ERROR_JOURNAL_NOT_ACTIVE`). A volume that is not NTFS has none at all. Each of those is still a place
  this program cannot count.
- It is a second volume handle and a second full read inside the same 30-second budget, and a second
  journal span, which the report would have to show beside the first. A reader who compares two counts over
  two different spans can be misled by the difference.
- It reads the journal of a drive the player may not think of as part of the check, a game or data drive.
  The collector would still keep no name, but the consent question and `PRIVACY.md` would have to say it.

**`other_volume` has not been seen on a real PC.** The one PC measured has every watched folder on the
system volume, and the case is known only from the code and the `usn-folder-on-other-volume` fixture. How
common it is, and whether such a volume has a journal, is not known. The new reason was chosen on weaker
grounds than a measurement: it costs little before the first rule ships. Without it, the first PC that does
have the case would show a row saying a read failed when none did. No measured case justified reading a
second journal, so none is read (owner decision 2).

### Decision 1: `other_volume`, a fourteenth reason

- **Code:** `other_volume`, the same word as the `folder` value it goes with (CONVENTIONS.md, one name per
  idea). `UnmeasuredReason::OtherVolume`.
- **Words:** "this is on another drive, and this program reads only the system drive's change journal".
  Thai: "ส่วนนี้อยู่บนไดรฟ์อื่น และโปรแกรมนี้อ่าน change journal ของไดรฟ์ระบบเท่านั้น".
- **Producer:** `usn` alone. `check-rules` then accepts it in `unmeasured_when` only for rules on `usn`.
- **Declarable.** It is on the same side of ADR 0032's line as `access_denied` and `source_absent`: the
  program never reached the source, and the reason is how the machine is set up. It is not a read that
  began and did not finish, so it is not always listed.
- **Not a scope statement.** It is about one place on one machine, not about the whole scan, so it does not
  go in `ScopeNotes`.
- **Where a reviewer still sees it:** the timeline's unmeasured sources carry the place and the reason in
  both modes, as they do today. A rule that declares `other_volume` is counted in SS mode rather than listed,
  and the timeline still says, once, that this place was on another drive.
- **What changes with it:** ADR 0030's table gains a row, `rules/AGENTS.md`'s list of which collector
  produces which reason, `crates/rongroi-cli/src/output.rs`, `apps/desktop/src/locales/*/report.json` and the
  `types.ts` mirror. `REPORT_SCHEMA_VERSION` stays at 1. A report written earlier carries no such reason.
  A reader built before it would refuse a report that has one, as it would any unknown reason.

### Decision 2: the first rules, deletions and renames in FiveM's plugin folders

**Which folders.** Only `plugins` (FiveM for GTA V Legacy) and `enhanced_asi` (FiveM for GTA V Enhanced).
Both were `identified` with no record in 39 minutes, in both readings of the PC above. Prefetch and the Event
Log folder change every few minutes (409 and 65 records in 39 minutes), though neither had a deletion in
that span. Their deletions come from Windows itself (Prefetch keeps a bounded number of files) and from
optimisers, and ADR 0047 already says a delete count there is not evidence of cleaning. How often they occur
on an ordinary PC was not measured, and a rule found on most scans is the "sea of red flags" ADR 0027
forbids. FiveM's cache, log and crash folders are not watched by `usn`, and none is added (owner decision 6).
FiveM writes and removes files there itself.

**Why four files and not one.** `match` is a conjunction (ADR 0029), so "a deletion or a rename" is two
rules. A rule over both places would make a player with only one edition `unmeasured`. The absent folder's
gap (`source_absent`) reaches any rule whose `location` could match there, and it would cover the other
place's answer (ADR 0044). So there is one rule per place per reason:

| Path | `match` |
|---|---|
| `rules/usn/plugins/files-deleted` | `location: plugins`, `folder: identified`, `deleted\|gte: 1` |
| `rules/usn/plugins/files-renamed` | `location: plugins`, `folder: identified`, `renamed\|gte: 1` |
| `rules/usn/enhanced-asi/files-deleted` | `location: enhanced_asi`, `folder: identified`, `deleted\|gte: 1` |
| `rules/usn/enhanced-asi/files-renamed` | `location: enhanced_asi`, `folder: identified`, `renamed\|gte: 1` |

Renames are included because moving a file out of the folder is a rename, with the old name's record under
this folder as its parent. Whether Windows' Recycle Bin shows up this way in the journal is not measured
here. A file moved elsewhere on the same volume is renamed, not deleted.

**The shape of one of them**, as the starting point for the change that adds them:

```yaml
title: The change journal holds a deletion in FiveM's plugin folder
description: >-
  The NTFS change journal holds at least one record of a file deleted directly inside FiveM for GTA V
  Legacy's plugin folder. The row gives how many records, and the first and last time. It shows the span
  the journal covered: on an ordinary PC in use that can be well under an hour. Nothing before that span is
  seen. If this rule finds nothing, it means only that nothing was deleted there within that span. The
  journal does not record which program deleted a file, so this does not say who did it, or that anything
  was hidden.
status: experimental
collector: usn
strength: context
match:
  location: plugins
  folder: identified
  deleted|gte: 1
retention: >-
  Only the span the change journal still held when the scan read it, shown beside this row. The journal
  keeps a fixed size and drops its oldest records first; on one Windows 11 PC it held about 39 minutes.
unmeasured_when: [not_windows, source_absent, other_volume]
falsepositives:
  - The player removed or replaced a graphics mod, ReShade, an ENB or another plugin they had installed
  - FiveM or its updater replaced or removed a file in the folder (not measured for this folder)
  - A clean-up, "clear FiveM cache" or optimiser tool that empties FiveM's folders
  - Antivirus software quarantining or removing a file
  - FiveM reinstalled, or its folder deleted and made again. Records about the old folder are not counted
    at all, so this can also remove a row that would otherwise be here
```

Its `renamed` sibling differs in `match` and in two lines: a rename is also what an update that writes a
new copy and swaps it in by renaming does, and a rename inside the folder yields two records, one for the
old name and one for the new.

**Counts are records, not files.** A file changed once can leave several records. On the runner the probe's
one deletion left one record carrying the delete reason, and one file created left three with the create
reason. The row says "records". The probe below measures, per folder, how many distinct files the records
were about, without reporting any of them.

**Strength and status.** `context`: a `not_found` from it is counted in SS mode, never listed, because
"nothing deleted in the last 39 minutes" is not a statement a reviewer should read as a clean result
(ADR 0031's reasoning for a log-clearing rule). **Status `experimental`**, for three reasons: no ordinary
baseline of deletions or renames in these folders over a useful span exists (the PC above had no record in
39 minutes, which says nothing about a day); whether FiveM's updater writes in `plugins` was not measured;
and how the Recycle Bin shows in the journal was not measured. It still carries a positive and a negative
fixture. `baseline-elevated-win11`'s `plugins` observation (`identified`, `deleted: 0`, `renamed: 0`)
confronts the two `plugins` rules. No baseline carries `enhanced_asi` as `identified`, so the two
`enhanced_asi` rules need a `rules/unconfronted.csv` row until one does.

**`unmeasured_when`.** `not_windows`; `source_absent`, because a player with one edition has no folder for
the other, and because this is also the reason when the volume has no journal at all (both PCs measured had
one; the timeline names `usn`'s reason for the whole collector either way); `other_volume` (Decision 1).
`not_admin` is not declared: it is a scope statement and never a row whether declared or not. `access_denied`
is not declared, because the folders are in the player's own profile and a denial there is unexpected.
`partial`, `budget_spent` and `read_failed` cannot be declared (ADR 0032).

### How this differs from `usn/timeline/watched-folder-record-times`

| | The timeline selector (ADR 0051) | The four rules |
|---|---|---|
| Kind | `role: timeline`. It makes no evidence | Evidence rules, `strength: context` |
| What it reads | every watched folder that is `identified` | two FiveM folders, one reason each |
| Condition | any record | at least one record carrying a delete, or a rename |
| What reaches a reader | the folder's first and last record time, as timeline entries, in both modes | a `found` row with the counts, always listed in SS mode; `not_found` counted in SS mode |
| Effect on scope lines | none | each adds to `ScopeNotes.not_admin` in a scan without Administrators |
| Its gaps | the timeline's unmeasured sources | the row's state, and the timeline's unmeasured sources as today |

The selector answers "when did anything change in this folder". A rule answers "did the journal see a file
leave this folder", as a row a reviewer can point at, with its ordinary causes beside it.

### Decision 3: every `usn` row states the journal's span

The journal's span is measured on each scan. ADR 0051 already reads it as `usn`'s coverage band: the
`first_seen` and `last_seen` of the observation whose `location` is `journal`. Today it is shown only on
the timeline. A row whose count is for the last 39 minutes, shown without those 39 minutes, is the
reading this amendment must prevent.

- `rongroi-core::view` pairs every evidence row of a collector whose `Coverage` names a `place` with that
  place's band: for `usn`, the journal's span. It is done in the core, where the bands are already built,
  so that the CLI and the desktop cannot disagree, and in both modes.
- On a `found` row it is shown beside the folder's own `first_seen` and `last_seen`, which are the times
  of that folder's records, not the span.
- On a `not_found` row it is shown with `retention`: "nothing within this span". Self mode lists that row;
  SS mode counts it, because the rules are `context`.
- An `unmeasured` row has no band. When the read did not finish (`partial`, `budget_spent`, `read_failed`)
  the span is not what the counts cover, and when it never started there is none.
- When the journal's observation has no times, because it held no record, the row says there is no span
  rather than showing none.

`evtx`'s coverage declares no single place (a band per log), so it is untouched by this.

### Without Administrators

Today a scan without Administrators gets `not_admin` from `usn` as a whole. It shows in one place: the
timeline's unmeasured sources, since ADR 0051. `ScopeNotes` counts rule evidence, and no rule makes evidence
from `usn`, so the scope line above the evidence does not count it, and the restart-as-administrator offer
does not mention it.

With the four rules, each is `unmeasured` with `not_admin` in such a scan. `ScopeNotes.not_admin` grows by
four, in both modes, and none of them is a row (ADR 0027, ADR 0030). No new kind of line appears. The
existing line's count grows, and the four rules become part of what restarting as administrator gets back.
Rules on `prefetch`, `bam`, `pca` and `evtx` already put the line there on an ordinary non-elevated scan.

### Who deleted it

The journal does not say. A record carries the file's reference number, its parent's, a time, the reason
flags and `SourceInfo`, which says only whether the change came from certain classes of system activity
([USN_RECORD_V3](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v3)).
It names no process and no user. A deletion by the player, by FiveM's updater, by an antivirus and by
Windows look alike in it. Every row these rules make says so in its `description`, and no future rule may
claim otherwise from the journal alone.

### Before any code: a probe on the PC

A read-only PowerShell probe, kept out of the repository, measures on the same PC, elevated and not. It ran
on 2026-09-30, and its results are under "The probe, on the same PC" above:

- whether `\\.\C:` opens with `GENERIC_READ` alone;
- for each watched folder and for FiveM folders `usn` does not watch: whether it exists, whether its base
  variable is on the system drive letter, whether any folder on the way is a reparse point, whether it is
  on the system volume, and that volume's file system. Volume serials are compared in memory and never
  printed;
- the journal's size, whether it is trimmed, its record count and versions, **its span in minutes**, and
  records per minute;
- per folder: records, and how many carried a create, delete, rename (old and new name), data change or
  close, how many distinct files were deleted or renamed away, and how long before the scan the first and
  last record were;
- for a folder on another volume: whether that volume has an active journal, and the same numbers from it.

It prints no file name, user name, journal identifier, USN, file reference number, volume serial or volume
GUID. It sends only the two read control codes.

### Owner decisions (2026-09-30)

1. A folder on another volume is reported with a new, declarable reason, `other_volume` (Decision 1), and
   ADR 0030's table is amended in the change that adds it. No PC measured so far has the case.
2. No second volume's journal is read.
3. The first rules are four `context` rules: deletions and renames, one per FiveM plugin folder, `plugins`
   and `enhanced_asi` (Decision 2).
4. They are `experimental`, with a positive and a negative fixture each, and a `rules/unconfronted.csv` row
   for the `enhanced_asi` pair.
5. `rongroi-core::view` pairs every `usn` row with the journal's coverage band, in both modes (Decision 3).
6. No rule reads the `prefetch`, `winevt_logs` or `appcompat_pca` counts, and no FiveM cache, log or crash
   folder is added to `usn`, until a measured baseline shows how often they change on an ordinary PC.

### What the amendment does not establish

- How long the journal reaches on PCs other than the one above (39 minutes there, twice).
- Whether any player's FiveM folders are on another volume, and whether such volumes have a journal. The
  one PC measured has none.
- Whether FiveM's updater writes in `plugins` or `gta5enhanced\asi`.
- How the Recycle Bin, and how an update that swaps a file in, show in the journal.
- How many records one deleted or renamed file leaves on a PC. The probe saw no deletion or rename in any
  watched folder.
- How often Prefetch and the Event Log folder see deletions on an ordinary PC. None in 39 minutes on one PC.

## What is not established

- Every rights and behaviour statement on a Windows 10 or 11 PC. The runner is Windows Server 2025.
- Whether the journal is on by default on Windows 10 and 11, and its default size there.
- Whether a PC returns version 2 records, whether it honours a request for version 3 only, and the 64-bit
  parent comparison.
- How long an ordinary journal retains on a PC, and how many records a scan of one reads.
- Records in a Prefetch folder on a machine where Prefetch is on.
- The contract of `FSCTL_READ_UNPRIVILEGED_USN_JOURNAL`.
- Which reason a watched folder on another volume (a junction to a game drive) should carry. The first rule
  that reads a per-folder count must settle it. Today it is `read_failed`, which SS mode always lists and no
  rule can declare; `not_attempted` was rejected because it says the scan stopped early. Settled by the
  amendment of 2026-09-30: a new reason, `other_volume`, which amends ADR 0030 in the change that adds it.
- Attribution relies on the NTFS `VolumeSerialNumber`. Whether a cloned volume attached to the same PC keeps
  the serial is not verified.

## Consequences

- Implemented as the `usn` collector (`crates/rongroi-collectors/src/usn.rs`), with `rongroi_parsers::usn`,
  `UsnJournalSource` and a `fuzz_usn` target. No rule. The implementation plan's rulings — per-folder times
  rather than per-reason, version 2 matched by the 64-bit index, a 30-second budget, absent folders as
  `source_absent` gaps and folders on another volume (checked by volume serial) as `read_failed` gaps, and
  the program's own Prefetch record counted — are in `docs/architecture.md`'s `usn` row.
- Accepted by the owner on 2026-09-14, with the five points of the recommendation as written.
- The amendment of 2026-09-30 was accepted by the owner the same day, with its six decisions, and is
  implemented in one change: `UnmeasuredReason::OtherVolume` (`other_volume`), which `usn` alone reports, for
  a watched folder on another volume, where it reported `read_failed` before, with ADR 0030's table amended
  and the words in both languages in the CLI and the desktop; the four `context`, `experimental` rules
  `rules/usn/plugins/files-deleted`, `rules/usn/plugins/files-renamed`,
  `rules/usn/enhanced-asi/files-deleted` and `rules/usn/enhanced-asi/files-renamed`, each with a positive
  and a negative fixture, `baseline-elevated-win11` confronting the `plugins` pair and a
  `rules/unconfronted.csv` row for each of the `enhanced_asi` pair; and `rongroi_core::view::RowBand`,
  which pairs each `found` and `not_found` row of a collector whose coverage names a place — `usn`, the
  journal — with that place's span, or says the journal held no record, in both modes
  (`ReportView::row_bands`). No second volume's journal is read, and nothing was added to the folders `usn`
  watches.
- README's M3 row, in both languages, links here: the collector reads the change journal without write
  access and counts records per watched folder with no file names, and four `context` rules read the
  deletions and renames in FiveM's two plugin folders.

## Amendment for ADR 0061: `journal_created_on` (2026-09-30, accepted with ADR 0061)

ADR 0061's owner decision 6 amends this ADR's "Not `UsnJournalID`" in the change that builds it.

- **What is added.** The journal's own observation (`location: journal`) gains one text field,
  `journal_created_on`: the UTC date, `YYYY-MM-DD`, that `UsnJournalID` gives when it is read as a
  `FILETIME`. The host computes the date and hands over nothing else (`UsnJournalState::created_on`,
  `rongroi_host::journal_created_on`); the identifier never leaves `rongroi-host-windows`, and the report
  carries no finer time than a day.
- **What it is, and is not.** Microsoft documents the identifier only as assigned when the journal is
  created and possibly restamped ([Using the Change Journal
  Identifier](https://learn.microsoft.com/en-us/windows/win32/fileio/using-the-change-journal-identifier)).
  That it encodes a time is **not documented**: the report labels it "the identifier read as a time; not
  documented". On one Windows 11 PC it read, twice, as a date within a day of the oldest installation date
  Windows Setup kept (ADR 0061, "Measured on a Windows 11 PC").
- **When it is left out.** An identifier that does not read as a date from 2000-01-01 up to 2100-01-01 gives
  no date, and the field is absent — a field left out for one item, not a gap. The report header's
  `usn_journal_created` anchor also refuses a date after the scan's own (`read_failed`).
- **Rights.** Administrators only, like the rest of `usn` (limited token: error 5, measured). Without them
  the anchor is `not_admin`.
- **What still holds.** No identifier, USN or file reference number is reported, and no rule reads
  `journal_created_on`: it is context for the trace-ages section's anchors (ADR 0061).
