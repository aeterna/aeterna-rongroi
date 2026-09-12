# EVTX fixtures — provenance

Every file here is **vendored from the `evtx` crate's own test corpus**, which
`docs/research/06-testing-windows-forensic-code.md` vetted as Apache-2.0 and vendor-eligible. None was
captured from a real player's machine, and none may be.

**Event Log is the highest-PII artifact this repository has vendored.** One record can carry a user
name, a host name, a source IP address, a SID and a full command line — `Security` channel records
routinely carry all five. That is why the selection below rejected five of the seven candidate files
and kept two. There is no scrubbing tool in this repository — `cargo xtask scrub-check` is named in
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

The files are bytes and cannot carry an SPDX header, so `REUSE.toml` annotates `fixtures/evtx/*.evtx`
with the Apache-2.0 licence and the upstream copyright.

## The files

Renamed on vendoring so the name says what each one is; the upstream name is recoverable from the table.

| File | Upstream path | Bytes | Records | What it tests |
|---|---|---|---|---|
| `application-no-crc32.evtx` | `samples/Application_no_crc32.evtx` | 69 632 | 17, no errors | the parse that succeeds; the `Application` channel; **`EventID` rendered as an object** (`{"#attributes":{"Qualifiers":0},"#text":1}`) alongside `EventID` rendered as a bare number, in one file; a provider with no GUID |
| `languagepacksetup-operational.evtx` | `samples/Microsoft-Windows-LanguagePackSetup%4Operational.evtx` | 69 632 | 17, no errors | a provider-specific channel name (`Microsoft-Windows-LanguagePackSetup/Operational`); a **damaged trailing record** whose provider GUID is truncated to `…-4A0000000000`, whose `Channel` is absent and whose payload element is malformed — a record that parses without being well formed |

SHA-256:

```
2b128dc61812123a34ab2808502c6d48a0db6018e6b21bfb4f0be12d6dad2596  application-no-crc32.evtx
cad1968ff938ad005a5e67170a95d4e72c4f3091d3199de7210ad6a65ce6a7e2  languagepacksetup-operational.evtx
```

Both are one 64 KiB chunk behind a 4 KiB file header, which is the smallest an `.evtx` file comes.
136 KiB total, against the 144 MB the whole upstream `samples/` folder would cost a public repository
people clone. The multi-chunk cases — including the corrupt chunk that must not lose the file — are
**built in the tests from these bytes** rather than vendored, exactly as `fixtures/prefetch/`'s corrupt
cases are: the upstream file that carries a bad chunk magic is 1 MB and carries a machine's real logs
with it.

These same bytes are the seed corpus `ci.yml` hands `fuzz_evtx` (ADR 0016), so the directory is read by
the L0 tests and by the fuzzer and may not be emptied or renamed at one end alone:
`crates/rongroi-parsers/tests/fixtures.rs` fails if it holds no `.evtx` file or if `ci.yml` stops
naming it.

## What is in them — read this before adding another

**Both scans were run on every candidate, because each one is blind where the other sees.** A rendered
record is not the file: binary XML stores values in a per-chunk string table and substitutes them into
templates, so a string can be in the file and not in any record, or in a record and not recognisable in
the bytes. Two concrete cases from these two files:

- `languagepacksetup-operational.evtx` renders `Computer: DESKTOP-1N4R894`, and the string
  `DESKTOP-1N4R894` **does not appear** in a raw UTF-16 or ASCII scan of the file.
- `application-no-crc32.evtx` carries, in the chunk's slack past its last live record, strings that
  appear in **no** rendered record: two `\\?\C:\ProgramData\Microsoft\Windows\WER\…` Windows Error
  Reporting paths, `AppHang_NcbService_…`, `ncbservice.dll`, `ServiceHang`, and the 32-hex token
  `c9a00ec972c9369f89b240a6b9b272f4`. These are remnants of records that were overwritten or never
  flushed — which is itself the reason this artifact matters.

What the two kept files contain, in full:

- **Host names**: `DESKTOP-0HIJB49` and `DESKTOP-1N4R894`. Both are the name Windows generates at
  install time from a fixed prefix and random characters; neither contains a person's name. This is
  a host name, and `CONVENTIONS.md` §4 says a fixture never contains one, so it is written down here
  rather than left to be found — the same way `fixtures/prefetch/PROVENANCE.md` records its account
  name. It was **not avoidable**: every `.evtx` record carries a `Computer` field by format, so a file
  with no host name in it is not an Event Log.
- **SIDs**: `S-1-5-18` (LocalSystem) only. That is a well-known constant, identical on every Windows
  machine, and identifies nobody. No `S-1-5-21-…` machine or domain SID appears in either file.
- **User names**: none.
- **IP addresses**: none.
- **Credential material**: none. No password, hash, token or key field appears.
- **Paths**: system paths only — `C:\Windows\system32\…`, `C:\ProgramData\Microsoft\…`. No user profile
  path (`\Users\…`) in either file.
- Otherwise: Windows Update correlation ids (`MS-CV: …`, `Context: …`), product-SKU GUIDs, ESENT and
  Search indexer diagnostics, and Software Protection Platform state — all machine-generated, none
  identifying.

## What was rejected, and why

Five other candidates of the same 68 KiB size were decoded and read, and each was dropped rather than
redacted. Recorded so the next person does not re-litigate them:

| Rejected file | What reading it found |
|---|---|
| `MSExchange_Management_wec.evtx` | an Active Directory domain (`ave.local`, `DC.ave.local`), host `WEC.ave.local`, the account `Administrateur`, SID `S-1-5-21-186559946-…-500`, an address `test2@example.com`, and a full `Set-Mailbox` PowerShell command line |
| `issue_201.evtx` | byte-for-byte the same file as the above (identical SHA-256) under a second name |
| `Security_short_selected.evtx` | three real routable IP addresses (`23.94.153.202`, `169.46.6.101`, `169.46.118.42`), host `temporal`, and a **failed logon** for `Administrator` — an authentication failure against a real host |
| `new-user-security.evtx` | account names `IEUser` and `WIN-QALA5Q3KJ43$`, host `IE8Win7`, two `S-1-5-21-…` SIDs, and account-creation records carrying password-policy fields |
| `Microsoft-Windows-HelloForBusiness%4Operational.evtx` | machine SID `S-1-5-21-1769714682-2803786108-491265710-500` — the built-in Administrator account of a real machine. **Its raw bytes show no SID at all**: binary XML stores a SID as 28 binary bytes, so only the decode revealed it. This is the file that proves a grep over `.evtx` bytes is not a privacy check |

## What this corpus does not cover

- **No record with event id 1102 or 104 is in either file**, so the artifact that motivates this parser
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

Adding a fixture generated from a real Windows install means recording here, as
`fixtures/hosts/PROVENANCE.md` requires: the generator, the Windows build, that networking was
disabled, and that the scrub check passed — which first means writing that check. Never copy an
`.evtx` file from a real player's PC into this repository.
