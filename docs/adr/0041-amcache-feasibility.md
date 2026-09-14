# ADR 0041 — Amcache: whether it can be read, and what a hash rule would cost

- Status: accepted — no Amcache collector and no hash rules for now (option B)
- Date: 2026-09-13

## Context

README's milestone table lists Amcache under M3. ADR 0013 left it to be argued on its own, because
"Amcache needs a registry-hive reader" and each such reader "carries a dependency and a licence
question". Nothing reads it today. No collector, parser, rule or fixture mentions it.

### What Amcache is

`%SystemRoot%\AppCompat\Programs\Amcache.hve` is a registry hive file, with `Amcache.hve.LOG1` and
`Amcache.hve.LOG2` beside it. None of the entries in `HKLM\SYSTEM\CurrentControlSet\Control\hivelist`
named it when it was probed (below), so no registry key path was found that reaches it, and this ADR
treats it as a file. Its `InventoryApplicationFile` key holds one subkey per
executable Windows has catalogued. Kaspersky's analysis of the artifact
([Securelist, 2025-10-01](https://securelist.com/amcache-forensic-artifact/117622/)) lists the values
of each entry. They include `LowerCaseLongPath` ("the full lowercase path to the executable"), `Name`,
`OriginalFileName`, `Publisher`, `Version`, `ProductName`, `LinkDate`, `Size`, and `FileId`, which
it describes as "the SHA-1 hash of the file, with four zeroes appended to the beginning of the hash".

**An entry shows that a file was present. It does not show that the file ran.**
`docs/research/03-pc-check-screenshare-tools.md` already records this: Amcache means "a file was
**present**, with SHA-1 — **not** proof of execution". The same document concludes: "Label ShimCache
/ Amcache as presence; require agreement between artifacts before calling something executed." The
Securelist analysis agrees: "Amcache.hve is not a true execution log: it records files in directories
scanned by the Microsoft Compatibility Appraiser, executables and drivers copied during program
execution, and GUI applications that required compatibility shimming. Only the last category reliably
indicates actual execution."

### The idea this ADR examines

A rule could list the `FileId` hashes of known cheat builds. The list would be reviewed in a pull
request and embedded in the binary like every other rule (ADR 0004). It would never be pushed from a
server (ADR 0003). A match would be evidence of strength `presence`. A second, separate fact would be
that the hashed file is no longer at the path Amcache recorded.

Three questions decide whether that collector should exist at all:

1. Can this program read `Amcache.hve` without changing anything on the machine?
2. Can the hive be parsed safely, to this repository's standard for hostile input?
3. What does a list of cheat hashes in a public repository cost, and who decides?

This ADR answers the first two with measurements and sources. It lays out the third for the owner.
**No collector code is part of it.**

## Question 1 — reading the hive without changing anything

### What was measured

**Where:** one real Windows 11 machine, build 26220 (`ver`: 10.0.26220.9472), on 2026-09-13, with a
throwaway probe cross-built from macOS. The probe printed only whether each call succeeded, the error
code when it did not, and for the hive file whether its first four bytes were the `regf` signature.
It printed no hive content and nothing was copied off the machine. It ran twice: once with an elevated
administrator token over SSH, and once with a limited token, from a scheduled task created with
`/rl LIMITED`. The probe, its folder and both tasks were deleted afterwards.

**Against the real `Amcache.hve` and its logs.** Every open asked for `GENERIC_READ` with
`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, `OPEN_EXISTING`.

| Call | Elevated | Limited token |
|---|---|---|
| `GetFileAttributesW` on `Amcache.hve`, `.LOG1`, `.LOG2` | all three present | all three `INVALID_FILE_ATTRIBUTES` |
| `CreateFileW` with `FILE_READ_ATTRIBUTES` only | succeeded, all three | failed, 5 (`ERROR_ACCESS_DENIED`), all three |
| `CreateFileW` with `GENERIC_READ` | succeeded, all three; `ReadFile` of 4 bytes on the hive returned `regf` | failed, 5, all three |
| The same with `FILE_FLAG_BACKUP_SEMANTICS`, `SeBackupPrivilege` not enabled | succeeded, all three | failed, 5, all three |
| `AdjustTokenPrivileges` to enable `SeBackupPrivilege` in the probe's own token | enabled | not held: `ERROR_NOT_ALL_ASSIGNED` (1300) |
| `GENERIC_READ` with `FILE_FLAG_BACKUP_SEMANTICS` after that attempt | succeeded, all three | failed, 5, all three |

**A control: a hive Windows is holding.** `%SystemRoot%\System32\config\SOFTWARE` is the file behind
`HKLM\SOFTWARE`, a hive the running system has loaded. The sharing violation below is itself the
evidence that it was held.

| Call | Elevated | Limited token |
|---|---|---|
| `GENERIC_READ`, all sharing flags | failed, **32** (`ERROR_SHARING_VIOLATION`) | failed, 5 |
| The same with `FILE_FLAG_BACKUP_SEMANTICS` and `SeBackupPrivilege` enabled | failed, **32** | failed, 5 |

**`RegLoadAppKeyW`, on a hive the probe created in its own folder.** It was not called on the real
`Amcache.hve`. The reason is under "`RegLoadAppKey`" below.

| Step | Elevated | Limited token |
|---|---|---|
| `RegLoadAppKeyW` on a path with no file, `KEY_ALL_ACCESS`, then one subkey and one `REG_BINARY` value, then `RegCloseKey` | created `t.hve`, `t.hve.LOG1` and `t.hve.LOG2`, 8 192 bytes each | same |
| Load again with `KEY_READ`, `dwOptions` 0: then `CreateFileW` `GENERIC_READ` with all sharing flags on `t.hve` and on `t.hve.LOG1` | both failed, **32** | both failed, **32** |
| While loaded, a second process calls `RegLoadAppKeyW` on the same path with `KEY_READ` | succeeded, and opened the subkey | same |
| After the `KEY_READ` load was closed: bytes and last-write time of `t.hve`, `.LOG1`, `.LOG2` compared with before | unchanged | unchanged |
| A copy of `t.hve` with `FILE_ATTRIBUTE_READONLY` set, loaded with `KEY_READ` | failed, **5** | failed, **5** |

Also measured, and not load-bearing: at the time of the probe, `HKLM\SYSTEM\CurrentControlSet\Control\hivelist`
held 38 entries, and none began `\REGISTRY\A\`. Microsoft documents that hives loaded by
`RegLoadAppKey` cannot be enumerated (quoted below), so an empty result there does not say whether
Amcache was loaded. The scheduled task `\Microsoft\Windows\Application Experience\Microsoft
Compatibility Appraiser Exp` was in state `Ready`.

### What the measurements establish

- **Reading the hive needs an elevated token on this machine.** With a limited token the file cannot
  even be stat'ed. A collector would report `not_admin` the way `prefetch` and `bam` already do: an
  access denial without an elevated token (`crates/rongroi-collectors/src/failure.rs`).
- **When Windows is not holding the hive, a plain read works.** An elevated open for reading, with the
  sharing flags that `std::fs::File::open` also uses, read the file's signature. Rust's documentation:
  "By default `share_mode` is set to `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`"
  ([`OpenOptionsExt`](https://doc.rust-lang.org/std/os/windows/fs/trait.OpenOptionsExt.html)).
  `LiveHost::read_file` opens files that way (ADR 0019).
- **When Windows is holding a hive, a plain read fails with 32, and backup semantics with
  `SeBackupPrivilege` enabled does not change that.** The `SOFTWARE` control and the synthetic hive
  both show it. Microsoft documents the sharing rule: "You cannot request a sharing mode that conflicts with the access mode that is specified in an
  existing request that has an open handle. **CreateFile** would fail and the GetLastError function
  would return **ERROR\_SHARING\_VIOLATION**"
  ([CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)).
- **When and for how long Windows holds `Amcache.hve` was not measured.** It was not held at the one
  moment it was probed. A collector therefore has to expect 32 on some scans. The error means "the
  read did not happen", not "nothing is there". `SourceError::from_io` maps only `PermissionDenied` to
  `AccessDenied` and everything else to `Failed`, so a collector would have to recognise the raw OS
  error 32 itself. How the standard library classifies 32 was not checked.

### The four ways in

#### A plain read — feasible, administrator only, and only while the hive is not held

This is the only path the measurements support. It is the same read `LiveHost::read_file` already does,
under the same 64 MiB limit (ADR 0019). Whether a real `Amcache.hve` fits under that limit was not
measured. The owner's file size was deliberately not recorded.

#### `FILE_FLAG_BACKUP_SEMANTICS` with `SeBackupPrivilege` — not adopted

Microsoft describes the flag: "The system ensures that the calling process overrides file security
checks when the process has **SE\_BACKUP\_NAME** and **SE\_RESTORE\_NAME** privileges." It describes
the privilege: it "causes the system to grant all read access control to any file, regardless of the
access control list (ACL) specified for the file"
([Privilege Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)).

On the measured machine it bought nothing:

- the elevated token already had read access to `Amcache.hve` through its ACL;
- the flag did not get past a sharing violation, which is the obstacle that actually varies;
- a limited token does not hold the privilege at all.

It also sits badly with this project's rules. ADR 0012 asks Windows for an elevated token and
nothing more. It never adjusts a privilege. Enabling `SeBackupPrivilege` would be the first change
this program makes to its own token, and it would widen every later read in the process, not only
this one: any file on the machine becomes readable whatever its ACL says. That is still a read, but
"what this program can see" would no longer be what an administrator's ACLs allow. A machine where an
elevated token is denied `Amcache.hve` by ACL would be the evidence to reopen this, in its own ADR.

#### `RegLoadAppKey` — ruled out

`RegLoadAppKey` hands back a registry handle to the hive, so no hive parser would be needed, and it
would see what the kernel sees, including changes still sitting in the transaction logs. It is ruled
out because it cannot be shown not to write, and in two measured respects it acts like a writer.

What Microsoft documents
([RegLoadAppKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw)):

- "If the file does not exist, an empty hive file is created with the specified name." A call aimed
  at a machine that has no Amcache would create one.
- "During the **RegLoadAppKey** operation, the registry will verify if the file has already been
  loaded. If it has been loaded, the registry will return a handle to the previously loaded hive
  rather than re-loading the hive." Whether a call attaches or loads therefore depends on the state
  of the machine at that instant.
- "there is no way to enumerate hives currently loaded by **RegLoadAppKey**". A program cannot check
  beforehand which of the two it will get.
- The only documented option is `REG_PROCESS_APPKEY`. The page documents no read-only load, and says
  nothing about flushing, transaction logs or recovery.

What the synthetic hive showed:

- A `KEY_READ` load of a copy marked read-only failed with `ERROR_ACCESS_DENIED`. **The file is opened
  for writing whatever access the caller asks for.**
- While loaded with `KEY_READ`, the hive and its `.LOG1` refused a read open with 32. **Loading it
  holds it.** A Windows component that later opened `Amcache.hve` as a file, rather than through
  `RegLoadAppKey`, would be refused for as long as this program held it. Whether any component does
  that was not established.
- A clean hive's bytes and write time did not change across a `KEY_READ` load. **This does not show
  that a load never writes.** The dirty case, a hive whose recent changes are still in its logs, was
  not constructed. Maxim Suhanov's specification says a hive in that state requires recovery (see
  Question 2). Whether the kernel writes that recovery back to the file when the hive is loaded by
  `RegLoadAppKey` is established neither by Microsoft's page nor by this probe.

A call that creates a missing file, opens an existing one for writing, and may write a recovered
state back to it is not a read-only collector (`crates/rongroi-collectors/AGENTS.md`: "Never write,
delete, rename, lock, truncate or change timestamps").

#### Volume Shadow Copy — ruled out

Creating a snapshot is a change to the machine. It allocates shadow storage on the volume, and it
leaves a snapshot that persists until something deletes it. Deleting it afterwards is the "restore it
afterwards" that `crates/rongroi-collectors/AGENTS.md` forbids. It also destroys part of the evidence
this collector would want. Suhanov, on exporting hives from a live system
([dfir.ru, 2020-10-03](https://dfir.ru/2020/10/03/exporting-registry-hives-from-a-live-system/)),
describes the freeze step: "transaction log files are applied to corresponding hive files. Then, an
applied transaction log file can be emptied". Not run.

#### Reading the raw volume — not in scope here, noted for completeness

Forensic tools read locked files by opening `\\.\C:` and parsing NTFS themselves. Microsoft requires
that "The caller must have administrative privileges" and that "When opening a volume or floppy disk,
the *dwShareMode* parameter must have the **FILE\_SHARE\_WRITE** flag" (CreateFileW, above). It would
mean a second parser, an NTFS reader over metadata an attacker controls, with its own ADR. It is not
free of side effects either. Suhanov, in the same article: "the NTFS driver can (and, actually, will)
flush pending changes to file system metadata". Not run.

### Answer to Question 1

**Partly feasible.** Only a plain elevated read, and only at moments Windows is not holding the file.
How often that is was not measured. A collector built on it reports `not_admin` without elevation. It
also needs a way to say that the hive was held at that moment. The nearest existing reason is
`read_failed`, "it is there and could not be read or understood" (ADR 0030). Whether that is precise
enough is a question for the collector's own ADR.

## Question 2 — parsing the hive safely

### This repository's bar for a parser

It is set by ADR 0013, ADR 0015, ADR 0016 and ADR 0018. A parser is pure: bytes in, structs out, no
OS call, no `Host`, no clock. It never panics, aborts or hangs on any input. An allocation sized by
the file is bounded by what the bytes could hold; `evtx`'s unbounded `Vec::with_capacity` cost a
7.7 GB reservation and a vendored patch. A walk over a structure the file describes cannot loop
forever; `evtx`'s string-table cycle was a hang. The parser has a fuzz target in `fuzz smoke (ubuntu)`
with seeds that are the L0 fixtures. A dependency passes `cargo deny check` with its reason written
down for any exception. A regf hive has every one of those hazards: cell sizes, value lengths, subkey
counts, big-data segment counts and name lengths are all read from the file, and subkey lists and
index roots are offsets into it.

### Candidate crates

Eleven crates were examined on 2026-09-13, at the newest published version of each. `cargo deny check`
ran in a scratch crate per candidate, outside this repository, with this repository's `deny.toml`
minus its ignore list. The rows marked † were re-checked by hand for this ADR: the licence field, the
`cargo deny` summary line, and the `file:line` named. The rest come from a reading of each crate's
source that was not repeated.

| Crate | Licence | `cargo deny` | `unsafe` | Input | Dirty hive | Logs applied | Hostile-input findings |
|---|---|---|---|---|---|---|---|
| `nt-hive` 0.3.0 † | GPL-2.0-or-later | `licenses FAILED`, rest ok: not on the allow-list | `#![forbid(unsafe_code)]` (`lib.rs:17`) | `&[u8]`, zero-copy | `Hive::new` fails with `SequenceNumberMismatch`; `Hive::without_validation` skips every check | no | Returns `Result` throughout. Segment counts checked against the list cell; nested index roots rejected. A cell size of 0 reaches a subtraction that would overflow in a debug build (`hive.rs:158`, read, not run). No fuzz target |
| `notatin` 1.0.1 † | Apache-2.0 | `advisories FAILED`: RUSTSEC-2024-0436 (`paste`, unmaintained) | none, not forbidden | a path, or `Read + Seek` copied whole into a `Vec` | recorded in its parse log | yes, `.LOG1`/`.LOG2` with hash and sequence checks | **An `ri` subkey list pointing at itself recurses without limit** (`sub_key_list_ri.rs` `parse_offsets` → `cell_key_node.rs` `parse_sub_key_list`): a stack overflow on crafted input. 22 `expect`. A log-supplied size grows the buffer without a bound against the file. Optional recovery of deleted keys and values |
| `nt_hive2` 4.2.4 | `GPL-3.0` (deprecated SPDX id), and two GPL dependencies | `licenses FAILED` | none, not forbidden | `Read + Seek` (binrw) | `is_dirty`; the caller may declare the hive clean | yes, new format only | `unwrap` on the base block panics on a malformed header (`hive/mod.rs:112`). `Vec::with_capacity(segments.len() * 16344)` up to about 1 GiB (`db.rs:36`). `panic!` on a failed patch |
| `regf-rs` 0.1.1 † | MIT OR Apache-2.0 | all ok | `#![forbid(unsafe_code)]` | `Vec<u8>` | `is_dirty()` | no | `Vec::with_capacity(count as usize)` on a `u32` value count from the file (`cell.rs:259`), unbounded. Indexing by a file-supplied segment count without a length check (`cell.rs:286`). Unguarded `ri` recursion. First published 2026-09-01 |
| `winreg-core` 0.2.1 | Apache-2.0, **no licence file in the package** | all ok | forbidden | `Vec<u8>` | `is_clean()` | partly: no hash or sequence validation | Unbounded `with_capacity` on counts and big-data sizes. A log record size of 0 never advances (`txlog.rs:168`). Unguarded recursion, and iterators without a visited set. Upstream repository returned 404 |
| `regf` 0.1.0 | MIT | all ok | none | `Read` into a `Vec` | `is_dirty()` only | parses, never applies | `vec![0u8; bin_size]` before reading (`parser.rs:70`). Unguarded recursion over `ri` and over the key tree |
| `frnsc-hive` 0.13.4 | MIT | all ok | 7 sites | forensic-rs virtual files | sequence numbers never compared | no ("LOG files are not currently implemented") | `todo!()` in the reader. Unbounded allocations. `continue` that skips the position increment (`reader.rs:1327`) |
| `hivex` 0.2.1 | EUPL-1.2, over a bundled LGPL-2.1 C library | `licenses FAILED` | FFI | C | — | — | Out on licence and on `unsafe` outside `rongroi-host-windows` |

Three more search results were not regf parsers of this kind or were not examined in depth
(`viva-uefi-regf`, `adhammer-secrets`, and `winreg-recover`, whose source is a placeholder comment).
**No crate ships an `Amcache.hve` sample**, so a test corpus would have to be written here, synthetic,
from a documented layout.

What the table says:

- **No candidate meets this repository's bar as published.** The two with the best shape each fail
  on a different axis. `nt-hive` has the safety properties ADR 0013 asks for: pure bytes in, `forbid`,
  `Result`, zero-copy. But its licence is not on `deny.toml`'s allow-list, and it does not read
  transaction logs. `notatin` reads the logs, but it fails `cargo deny` today and recurses without
  limit on a self-referencing subkey list, which is the class of defect `fuzz_evtx` found in `evtx`.
- **Adding `GPL-2.0-or-later` to the allow-list is its own decision.** The "or later" grant permits
  use under GPL-3.0-or-later. The allow-list's own comments call it "the set we accept, not the set we
  currently use" and "Licenses compatible with distributing the whole program under
  GPL-3.0-or-later". Today it holds no licence with stronger copyleft than MPL-2.0. This ADR does not
  know why, so it does not treat the absence as either a policy or an oversight.
- **Every route is a vendoring or a writing job.** Taking `notatin` means an advisory ignore with its
  reason, a recursion guard patched in, and an allocation bound, exactly as ADR 0018 did for `evtx`.
  Taking `nt-hive` means a licence decision and a separate log replayer. Writing a reader for the one
  key and one value this idea needs (`InventoryApplicationFile` subkeys, `FileId`,
  `LowerCaseLongPath`) is a smaller format than binary XML. Its hazards are the same as every hive
  reader's: offsets, counts and lists supplied by the file.

### A hive that is not reconciled

A file read straight from a running machine can be **dirty**. Suhanov's regf specification
([Windows registry file format specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md),
CC BY 4.0) defines it: "A hive is considered to be dirty (i.e. requiring recovery) when a base block
in a primary file contains a wrong checksum, or its *primary sequence number* doesn't match its
*secondary sequence number*." It also says what that costs a reader of the primary file alone: "When
the new format of transaction log files is used, a flush operation on a hive will succeed after dirty
data was stored in a transaction log file (but not yet in a primary file); a hive writer may delay
writing to a primary file (up to an hour)." The new format was "introduced in Windows 8.1 and
Windows Server 2012 R2". His measurements of flushing
([Flush strategies in the Windows registry](https://github.com/msuhanov/regf-samples/blob/master/8.1-unreconciled/Flush%20strategies%20in%20the%20Windows%20registry.md))
conclude: "Without looking at transaction log files, an examiner may not see the latest changes
happened to the registry."

For this idea that gap sits in the worst place. The entries most likely to matter are the most
recent ones, and those are the ones a parser of the primary file alone may not see. So a collector
has three options:

| Option | Cost |
|---|---|
| Parse the primary file only, and say nothing about dirtiness | A `not_found` over a dirty hive may be false for up to the last hour of writes. `docs/architecture.md`: saying "not found" about something that was never read "would be false". Not acceptable |
| Parse the primary file only, detect a dirty base block, and report `partial` | Honest. SS mode lists `partial` whatever the rule declares, so a hive that is often dirty makes the rule often unanswered |
| Read `.LOG1`/`.LOG2` as well and replay them in memory, as a pure function over three byte buffers | Answers the most. It is a second parser over attacker-controlled input with its own bounds and fuzz target. The three files are read by three separate opens, so they can come from different moments, which the replay has to detect rather than assume away |

How often a real `Amcache.hve` is dirty was not measured. That would need its base block's sequence
numbers, which is content of the owner's file.

### How `FileId` is computed

Securelist again: "The AmCache computes the SHA-1 hash over only the first 31,457,280 bytes (≈31 MB)
of each executable". The authors checked it against a binary larger than that: they "found that it
indeed stored the SHA-1 hash calculated only for the first 31,457,280 bytes of the binary". ANSSI's
white paper *Analysis of the AmCache v2* (Blanche Lagny, CERT-FR, 2019), as cited by
[Qazeer's notes](https://github.com/Qazeer/InfoSec-Notes/blob/master/DFIR/Windows/Artefacts/Amcache.md),
gives the same limit as "the first 30MB". 31,457,280 bytes is exactly 30 MiB. The ANSSI PDF itself was
not read for this ADR; the figure rests on the Securelist experiment and is corroborated second-hand.

What that means for someone writing a rule:

- **A rule author can compute it from a cheat file.** For a file of at most 31,457,280 bytes it is the
  SHA-1 of the whole file. For a larger one it is the SHA-1 of its first 31,457,280 bytes.
- **It is not `sha256`.** `CONVENTIONS.md` calls `sha256` "The only file hash", and `allow` compares
  only `sha256` and `signer_cert_sha256` (ADR 0035). An Amcache hash would be a second hash under
  its own glossary row and field name. `allow` could not compare it, and "the same file" would mean
  "the same first 30 MiB".
- **SHA-1 collisions can be computed on purpose.** Leurent and Peyrin computed "the very first
  chosen-prefix collision for SHA-1" ([SHA-1 is a Shambles](https://sha-mbles.github.io/)). The page, from
  2020, puts the cost at 45k USD at its prices and projects under 10k USD by 2025. A file that is not
  a cheat can therefore be made to carry a listed cheat's SHA-1, at that cost. That belongs in the rule's `falsepositives`, next to the reason Amcache is `presence`
  at all: a file can be on a disk without its owner running it or putting it there.

### Answer to Question 2

**Not feasible with any crate as published.** It is feasible as vendoring or writing work of the size
ADR 0018 already did once, and it needs a decision on transaction logs. A rule author can compute the
hash a rule needs.

## Question 3 — a list of cheat hashes in a public repository

**Decided by the owner on 2026-09-13: option B now, and option C if hash rules are ever wanted.**
The options below were laid out before that decision and are kept as the reasoning.

One fact constrains every option. **Whatever list this program matches against ships inside the
executable.** The rules bundle is compiled in (ADR 0004) and the program runs offline on the player's
own PC (ADR 0003), so anyone who holds the binary holds the list. Keeping the list out of the
repository does not keep it from a cheat author. Publishing a hash of each hash does not hide it
either: an author computes the same function over their own build and looks it up.

A second fact limits the benefit. **One changed byte in the first 30 MiB is a different `FileId`.** A
hash rule can only match a build nobody changed after the hash was listed.

| Option | What it costs |
|---|---|
| **A. Publish hash rules in `rules/`**, reviewed like any rule | Anyone can see which builds are known from the moment the rule is merged, and a rebuilt binary no longer matches. Needs a source per hash that a reviewer can check without running the file. Adds a maintenance stream that ages quickly |
| **B. No hash rules.** No Amcache collector, or one that reports only the hive's own state (read or not, dirty or not, how many entries) | Amcache's one distinctive property, a content hash beside a presence record, goes unused. The M3 item becomes "decided against" rather than "done" |
| **C. Publish only hashes that are already public**, each with its public source cited in the rule | Discloses little that is not already known, and covers only builds someone has already published. Depends on the source's licence permitting reuse under CC-BY-SA-4.0. Still a list to maintain |
| **D. A list kept outside this repository**, compiled into a separate build | The list still ships in that build's binary, so it is not secret from its users. That build is not the official build (ADR 0007, NOTICE section 7), so its reports say **UNOFFICIAL BUILD**. Its rules are not reviewable in public. It is a fork, not a configuration |
| **E. The program shows Amcache hashes and staff compare them against their own list** | Shows the player's whole inventory of programs to another person. That is what SS mode promises not to do (ADR 0014) |

**Recommendation, accepted by the owner on 2026-09-13:** **B** until a collector is otherwise
acceptable, then **C** if hash rules are wanted at all. A and C disclose the same kind of thing, and C
discloses only what is already out. D and E each break a property this project has already decided to
keep.

## What a collector would emit, if one is built

This is the shape to argue about, not a decision.

- **`amcache`**, reading `%SystemRoot%\AppCompat\Programs\Amcache.hve` through `FilesystemSource::read_file`,
  and the two logs if replay is taken on.
- **One account of the hive:** whether it was read, whether its base block was dirty, whether logs
  were applied, how many `InventoryApplicationFile` entries it held and how many decoded.
- **Per matching entry:** the `FileId` digest as 40 lowercase hex characters without the `0000`
  prefix, under a new field name (for example `amcache_sha1`; the name is a glossary change, grep
  first). The path only when it begins with a drive letter, the one shape SS-mode redaction reaches
  (ADR 0023). And **whether a file is at that path now**, with its `sha256` when it is: the "no longer
  on disk" fact, kept separate because a deleted file is not evidence it was a cheat.
- **Strength `presence`**, and never `execution`.
- **Unmeasured:** a limited token is `not_admin`; no hive is `source_absent`; a sharing violation is a
  read that did not happen and is not `source_absent`; a dirty hive without replay is `partial`.

### Privacy: collect only what a rule needs

`InventoryApplicationFile` is an inventory of executables on the PC: games, work software, anything
installed or downloaded, each with its full path, and the path carries the Windows user name. Its
sibling keys add installed applications, shortcuts and drivers. None of that is needed to ask "is one
of these hashes here".

Three ways to hold to `crates/rongroi-collectors/AGENTS.md` ("Collect only what a rule needs"):

| Way | Cost |
|---|---|
| Emit every entry, with path and name | Self mode lists the whole inventory as unmatched observations (ADR 0014). SS mode counts it. The consent text must say so. Too much |
| Emit every entry's digest only, no path or name | The unmatched list is a column of hashes, which says little to a reader. The "no longer on disk" fact needs the path, so it could not be computed for anything |
| **The collector keeps only entries whose digest a rule in the bundle names** | Nothing else leaves the parser. But a collector would have to learn the bundle's hashes, a new seam from rules to collectors that `docs/architecture.md`'s pipeline does not have. That needs its own decision |

Only `InventoryApplicationFile` would be read. The consent question and `PRIVACY.md` would name
Amcache in the same pull request as the collector.

## What would reopen this

All of these, each with its evidence written in a follow-up ADR that supersedes this one:

1. **Hash rules wanted, in the form Question 3 allows:** only hashes already published elsewhere, each
   rule citing its public source, under a licence that permits reuse under CC-BY-SA-4.0. Without hash
   rules there is little reason for a collector.
2. **A parser that meets the bar above.** A crate from the table or a vendored and patched one, with
   `cargo deny check` passing on this workspace (not a scratch crate), allocations bounded by the
   bytes available, cycle-safe traversal, a fuzz target in `fuzz smoke`, and seeds that are
   redistributable synthetic hives, never a real person's Amcache.
3. **A decision on transaction logs.** Detect-and-report `partial`, or replay in memory. If replay,
   its own fuzz target.
4. **A measurement of how often Windows holds `Amcache.hve`,** on more than one machine and at more
   than one moment, so that the rate of scans unable to read it is known before a rule depends on it.
5. **A decision on the privacy seam:** how the collector learns which digests to keep, or an argued
   alternative.
6. **A `baseline-*` host that confronts the rule** (ADR 0033), built from a documented or measured
   hive and not from invented data.

## What is not established

- **One machine, one moment, one Windows build.** Windows 10 was not probed. That the hive was not
  held at the moment it was probed says nothing about the rest of the day.
- **Whether a `RegLoadAppKey` load writes a dirty hive back.** Only a clean synthetic hive was tried.
- **Whether a real `Amcache.hve` is usually dirty,** or fits under the 64 MiB read limit.
- **Whether an Amcache entry outlives the file it describes,** which the "no longer on disk" fact
  depends on. No source for it was read for this ADR.
- **The ANSSI paper was not read directly.** The 31,457,280-byte figure rests on Securelist's
  experiment and a secondary citation of ANSSI.
- **How the Rust standard library classifies error 32** as an `io::ErrorKind`.

## Consequences

- No code, no rule, no fixture, no dependency. `Cargo.lock`, `deny.toml` and the report are unchanged.
- README's milestone table records Amcache in M3 as decided against for now, with a link here. `docs/architecture.md` does not describe Amcache, so nothing there is wrong.
- The probe used for Question 1 is not in this repository. Its results are recorded above, and it
  printed nothing from the owner's hive but the four-byte `regf` signature check.
