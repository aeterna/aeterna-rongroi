# Prefetch fixtures — provenance

Every file here is **vendored from a third-party corpus that `docs/research/06-testing-windows-forensic-code.md`
vetted as MIT and vendor-eligible**. None was captured from a real player's machine, and none may be:
a real `.pf` file's string table holds the full path of every file the program loaded, which includes
`\USERS\<name>\…` paths repeated once per file, and this is a public repository. There is no scrubbing
tool in this repository — `cargo xtask scrub-check` is named in `CONVENTIONS.md` §4 but does not exist
yet. See `docs/adr/0015-prefetch-parsing.md`.

| Field | Value |
|---|---|
| Source | [github.com/EricZimmerman/Prefetch](https://github.com/EricZimmerman/Prefetch), `Prefetch.Test/TestFiles/` |
| Licence | MIT — the upstream file `license` reads "The MIT License (MIT) / Copyright (c) 2016 Eric"; recorded as `2016 Eric Zimmerman` in `REUSE.toml`, since the repository is his |
| Commit | `27d87a095fe0bd4b07726aec867e1c0f1aef08f9` (2026-04-27) |
| Retrieved | 2026-09-12 |
| Licence text | `LICENSES/MIT.txt` |

The files are bytes and cannot carry an SPDX header, so `REUSE.toml` annotates `fixtures/prefetch/*.pf`
with the MIT licence and the upstream copyright.

## The files

Renamed on vendoring so the name says what each one is for; the original name is kept as its suffix.

| File | Upstream path | Bytes | Container | SCCA version | What it tests |
|---|---|---|---|---|---|
| `win10-compressed-v30-CMD.EXE-D269B812.pf` | `Win10/CMD.EXE-D269B812.pf` | 6 298 | `MAM\x04`, declares 25 138 bytes | 30 | the parse that succeeds, and — decompressed by the test — that an uncompressed payload parses identically |
| `win81-raw-v26-CMD.EXE-4A81B364.pf` | `Win2012R2/CMD.EXE-4A81B364.pf` | 6 318 | uncompressed | 26 | an unsupported version is a typed error |
| `vista-raw-v23-CMD.EXE-89305D47.pf` | `Vista/CMD.EXE-89305D47.pf` | 6 026 | uncompressed | 23 | an unsupported version is a typed error |
| `winxp-raw-v17-CMD.EXE-087B4001.pf` | `Win2k3/CMD.EXE-087B4001.pf` | 6 002 | uncompressed | 17 | an unsupported version is a typed error |
| `bad-notAPrefetch.pf` | `Bad/notAPrefetch.pf` | 13 | neither | — | the corpus's deliberately bad file: 13 bytes whose offset-4 signature is `SDCA` |

SHA-256:

```
0ef6ce683365dac64191608b47a74665ddec28eaae530ce2622900130c404077  win10-compressed-v30-CMD.EXE-D269B812.pf
c9706f88240a1e1e6b3f84d13de0946640c06ec0b82a4b91aa82d3e865c970ae  win81-raw-v26-CMD.EXE-4A81B364.pf
6127d820b031cac7f5fb1e6d45e244aa48cbb7fa62910ad0317eacb71a0edcd0  vista-raw-v23-CMD.EXE-89305D47.pf
1ad8768dc22d960b935657f2019e8ae0027c5367e06b0eec2554a98ab80347e9  winxp-raw-v17-CMD.EXE-087B4001.pf
ce6664ab57e09ec71ec63f60e2917d7825185cf53fb9dcc9de19a63a3793c865  bad-notAPrefetch.pf
```

The smallest file of each version was taken, so the corpus costs 24 KiB rather than the 1.7 MB the
whole `TestFiles/` folder would.

## What is in them — read this before adding another

These are prefetch files from the upstream author's own test machines, so their string tables are that
machine's file paths. Every one of the five was scanned (decompressed first, where it is compressed):

- **The four older-version files carry system paths only** — `\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\NTDLL.DLL`
  and similar — plus a volume device path and serial number. No user profile path.
- **The Windows 10 file carries user profile paths**: its loaded-file list includes
  `\VOLUME{…}\USERS\<account>\APPDATA\LOCAL\…`, where `<account>` is a single letter — the upstream
  author's account on the machine he captured it from in 2016.

That last point is a known tension with `CONVENTIONS.md` §4, "Test fixtures never contain a real
person's user name, host name or SID", and it is recorded here rather than left for someone to find.
**It was not avoidable by picking a different file**: all six Windows 10 files in the corpus were
checked and every one contains the same account's paths, and the other corpus folders hold no SCCA
v30 or v31 file at all. The choice was between this file and having no fixture that exercises real
MAM/Xpress-Huffman decompression — the one thing the dependency exists to do — and the file was kept
because the corpus is MIT-licensed and has been public since 2016, so vendoring it publishes nothing
that was not already published. **This is an owner's call to reverse**: replacing it with a synthetic
v30 payload built in the test would remove the account name and remove the decompression coverage with
it.

`prefetch.rs` pins the fact rather than assuming it away: `the_windows_10_fixture_carries_user_profile_paths`
asserts those paths are there, because they are the reason `PrefetchRecord::loaded_files` is documented
as content a collector must redact through `rongroi_core::view` before it reaches a report.

## What this corpus does not cover

**There is no Windows 11 (SCCA v31) file in it**, so v31 — a version this parser accepts — is not
exercised by any fixture. The corpus predates Windows 11. When a v31 file can be obtained from a
machine whose owner can consent, it still may not be committed here unless it is free of user profile
paths; the alternative is a synthetic payload built in a test.

Adding a fixture generated from a real Windows install means recording here, as
`fixtures/hosts/PROVENANCE.md` requires: the generator, the Windows build, that networking was
disabled, and that the scrub check passed — which first means writing that check.
