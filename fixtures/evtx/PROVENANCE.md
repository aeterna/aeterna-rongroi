# EVTX fixtures — provenance

Every file here is **vendored from the `evtx` crate's own test corpus**, which
`docs/research/06-testing-windows-forensic-code.md` vetted as Apache-2.0 and vendor-eligible. None was
captured from a real player's machine, and none may be.

**Event Log is the highest-PII artifact this repository has vendored.** One record can carry a user
name, a host name, a source IP address, a SID and a full command line — `Security` channel records
routinely carry all five. That is why the selection below rejected five of the seven candidate files,
and why a sixth was removed after vendoring when a second reading found a machine SID in it. There is no scrubbing tool in this repository — `cargo xtask scrub-check` is named in
`CONVENTIONS.md` §4 and does not exist — and a record may not be redacted in place in any case: each
record is checksummed within its chunk, so editing a string breaks the chunk exactly as it does for
Prefetch. The choice is to vendor a file whole or not at all. See `docs/adr/0018-evtx-parsing.md`.

| Field | Value |
|---|---|
| Source | [github.com/omerbenamram/evtx](https://github.com/omerbenamram/evtx), `samples/` |
| Licence | Apache-2.0 (the crate is dual MIT/Apache-2.0; Apache-2.0 is taken here, matching `docs/research/06`) |
| Copyright | the upstream `LICENSE-MIT` reads "Copyright (c) 2019 Omer Ben-Amram"; recorded as `2019 Omer Ben-Amram` in `REUSE.toml` |
| Commit | `9c7d0b5429e86200d9e449bbdd2679cbe54b54ea` (2026-06-13) |
| Retrieved | 2026-09-12 |
| Licence text | `LICENSES/Apache-2.0.txt` |

The file is bytes and cannot carry an SPDX header, so `REUSE.toml` annotates `fixtures/evtx/*.evtx`
with the Apache-2.0 licence and the upstream copyright.

## The file

Renamed on vendoring so the name says what it is; the upstream name is recoverable from the table.

| File | Upstream path | Bytes | Records | What it tests |
|---|---|---|---|---|
| `languagepacksetup-operational.evtx` | `samples/Microsoft-Windows-LanguagePackSetup%4Operational.evtx` | 69 632 | 17, no errors | a provider-specific channel name (`Microsoft-Windows-LanguagePackSetup/Operational`); a **damaged trailing record** whose provider GUID is truncated to `…-4A0000000000`, whose `Channel` is absent and whose payload element is malformed — a record that parses without being well formed |

SHA-256:

```
cad1968ff938ad005a5e67170a95d4e72c4f3091d3199de7210ad6a65ce6a7e2  languagepacksetup-operational.evtx
```

It is one 64 KiB chunk behind a 4 KiB file header, which is the smallest an `.evtx` file comes. 68 KiB,
against the 144 MB the whole upstream `samples/` folder would cost a public repository people clone. The multi-chunk cases — including the corrupt chunk that must not lose the file — are
**built in the tests from these bytes** rather than vendored, exactly as `fixtures/prefetch/`'s corrupt
cases are: the upstream file that carries a bad chunk magic is 1 MB and carries a machine's real logs
with it.

These same bytes are the seed corpus `ci.yml` hands `fuzz_evtx` (ADR 0016), so the directory is read by
the L0 tests and by the fuzzer and may not be emptied or renamed at one end alone:
`crates/rongroi-parsers/tests/fixtures.rs` fails if it holds no `.evtx` file or if `ci.yml` stops
naming it.

## What is in them — read this before adding another

**Both scans have to be run, because each one is blind where the other sees.** A rendered record is not
the file: binary XML stores values in a per-chunk string table and substitutes them into templates, so a
string can sit in the file and in no record, or in a record and be hard to find in the bytes.

- The removed `application-no-crc32.evtx` carried, in the chunk's slack past its last live record,
  strings that appeared in **no** rendered record: two `\\?\C:\ProgramData\Microsoft\Windows\WER\…`
  Windows Error Reporting paths, `AppHang_NcbService_…`, `ncbservice.dll`, `ServiceHang`, and a 32-hex
  token. Those are remnants of records that were overwritten or never flushed — which is itself the
  reason this artifact matters, and the reason slack has to be read and not only records.
- Conversely `EventID` renders as a bare JSON number in all 17 records here (`4000` nine times, `4001`
  eight times, counted), yet the attribute name `Qualifiers` **is** in the chunk's string table. A name
  in the string table is the binary-XML schema, not a value any record used. Reasoning from the presence
  of a string to the shape of a record is how the wrong conclusion gets drawn in this direction.

**A scanner can be blind to alignment, and mine was.** An earlier draft of this file claimed
`DESKTOP-1N4R894` "does not appear in a raw UTF-16 or ASCII scan". It does: once, UTF-16LE, at byte
offset **5733**, which is **odd**. The scan that missed it walked `range(0, len, 2)` and so only ever
looked at even offsets. Nothing requires a UTF-16 string inside an `.evtx` chunk to begin on an even
boundary. Scan both alignments, or use a plain substring count over the raw bytes, which has no
alignment to be wrong about.

What the kept file contains, in full:

- **Host name**: `DESKTOP-1N4R894`, once, as UTF-16 inside the chunk's string table. It is the name
  Windows generates at install time from a fixed prefix and random characters and contains no person's
  name. This is still a host name, and `CONVENTIONS.md` §4 says a fixture never contains one, so it is
  written down here rather than left to be found — the same way `fixtures/prefetch/PROVENANCE.md`
  records its account name. It was **not avoidable**: every `.evtx` record carries a `Computer` field
  by format, so a file with no host name in it is not an Event Log.
- **SIDs**: none, in any form. Neither `S-1-5-21-…` nor even the well-known `S-1-5-18` appears — zero
  occurrences, ASCII and UTF-16, by raw byte count. An earlier version of this document asserted the
  opposite in both directions and was wrong; see "A correction" below.
- **User names**: none. No `TargetUserName`, `SubjectUserName`, `AccountName` or `LogonType` field
  appears — each counted, each zero. The element name `UserID` is in the string table, with no SID
  behind it.
- **IP addresses**: none. Searched as a dotted-quad pattern over the raw bytes and over both UTF-16
  alignments: no match.
- **Credential material**: none. `password`, `passwd`, `Credential`, `NTLM`, `Kerberos`, `Hash` and
  `token` are each zero in both encodings.
- **Paths**: none at all. `C:\` does not occur in this file in either encoding, and neither does
  `\Users\`. (The system paths an earlier draft listed here belonged to the removed file.)
- **Everything else it holds, in full** — these are all of the printable runs, at both alignments:
  binary-XML schema names (`Event`, `System`, `Provider`, `EventID`, `EventRecordID`, `TimeCreated`,
  `SystemTime`, `Execution`, `ProcessID`, `ThreadID`, `Channel`, `Computer`, `Security`, `UserID`,
  `Correlation`, `ActivityID`, `RelatedActivityID`, `Keywords`, `Opcode`, `Task`, `Version`,
  `Qualifiers`, `Guid`, `EventData`, `xmlns` and the `schemas.microsoft.com` event schema URL); the two
  provider names `Microsoft-Windows-LanguagePackSetup` and
  `Microsoft-Windows-PushNotifications-Platform` with their channels; four `MS-CV:` Windows Update
  correlation tokens and five `Context:` hex ids; `<ping-response><wait>NN</wait>` payload fragments;
  `PNG 149 CON 29`-style counters; and the `ElfFile`/`ElfChnk` magics. Nothing else.

## A correction — why one of the two kept files was removed after it had been vendored

`application-no-crc32.evtx` was vendored, committed, and then **removed** on 2026-09-12, before the
branch was ever pushed. Reading its bytes as UTF-16 found, twice, at offsets 38237 and 38529:

```
S-1-5-21-1100413981-69743188-641974803-1000
```

That is a real machine's SID, and `-1000` is the RID of the first user account created on it. It is the
same category of data that got `new-user-security.evtx` and
`Microsoft-Windows-HelloForBusiness%4Operational.evtx` rejected in the table below, so keeping it would
have been inconsistent with this document's own standard.

This document had stated the opposite — *"SIDs: `S-1-5-18` (LocalSystem) only … No `S-1-5-21-…` machine
or domain SID appears in either file"* — and was **wrong in both directions**: the machine SID was
present, and `S-1-5-18` was not there at all. The error is worth recording rather than quietly fixing,
because this same document is the one that says a raw scan of `.evtx` bytes is not a privacy check, and
then a raw scan is what was relied upon.

What was lost with it: a sample rendering `EventID` both as a bare number and as an object carrying a
`Qualifiers` attribute. That case is now asserted directly against `scalar` and `number` in
`evtx.rs` with JSON literals, which exercises the same branch without a sample. Two tests that listed
strings from that file and asserted their **absence** from parser output were also trimmed — a token the
corpus no longer contains makes such an assertion pass for the wrong reason.

**The lesson for the next file**, learned three times over in writing this one: a sentence of the form
"no X appears" is a measurement, not a recollection. Count each claim against the raw bytes *and* against
the decode, at both UTF-16 alignments, and write the counts down. Every negative claim above was produced
that way after three of them had already been found false.

## What was rejected, and why

Five other candidates of the same 68 KiB size were decoded and read before vendoring, and each was
dropped rather than redacted. Recorded so the next person does not re-litigate them:

| Rejected file | What reading it found |
|---|---|
| `MSExchange_Management_wec.evtx` | an Active Directory domain (`ave.local`, `DC.ave.local`), host `WEC.ave.local`, the account `Administrateur`, SID `S-1-5-21-186559946-…-500`, an address `test2@example.com`, and a full `Set-Mailbox` PowerShell command line |
| `issue_201.evtx` | byte-for-byte the same file as the above (identical SHA-256) under a second name |
| `Security_short_selected.evtx` | three real routable IP addresses (`23.94.153.202`, `169.46.6.101`, `169.46.118.42`), host `temporal`, and a **failed logon** for `Administrator` — an authentication failure against a real host |
| `new-user-security.evtx` | account names `IEUser` and `WIN-QALA5Q3KJ43$`, host `IE8Win7`, two `S-1-5-21-…` SIDs, and account-creation records carrying password-policy fields |
| `Microsoft-Windows-HelloForBusiness%4Operational.evtx` | machine SID `S-1-5-21-1769714682-2803786108-491265710-500` — the built-in Administrator account of a real machine. **Its raw bytes show no SID at all**: binary XML stores a SID as 28 binary bytes, so only the decode revealed it. This is the file that proves a grep over `.evtx` bytes is not a privacy check |

## What this corpus does not cover

- **No record with event id 1102 or 104 is in this file**, so the artifact that motivates this parser
  — a cleared log — is not exercised by a fixture. The corpora that do carry those events are
  `EVTX-ATTACK-SAMPLES` (real red-team capture) and `hayabusa-sample-evtx` (no licence at all), and
  `docs/research/06` ruled both out for vendoring here. This does not affect the parser, which assigns
  no meaning to an event id, but it will matter to the rule that reads one: that PR needs a fixture
  built by clearing a log on a machine whose owner consents, or a synthetic record.
- **No `Security` channel file at all**, because every `Security` sample in the corpus carries logon
  records with user names or addresses. The channel is a string to this parser, so nothing in the code
  is untested by that absence.
- **No multi-chunk file, and no file with more than 17 records.** Both properties are constructed in
  the tests from these bytes.
- **No sample rendering `EventID` as an object.** The file that did was removed (see "A correction");
  that shape is covered by a unit test over `scalar`/`number` instead of by a fixture.
- **One file, not two.** Every Event Log test in the repository now reads this single sample or bytes
  built from it, so a defect specific to it would not be caught by a second opinion.

Adding a fixture generated from a real Windows install means recording here, as
`fixtures/hosts/PROVENANCE.md` requires: the generator, the Windows build, that networking was
disabled, and that the scrub check passed — which first means writing that check. Never copy an
`.evtx` file from a real player's PC into this repository.
