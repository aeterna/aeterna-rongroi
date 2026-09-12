# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Vendored `evtx`: a `u16` multiplication in `binxml/name.rs` that overflows on a name length above
  32767. Under overflow checks it panics; in an ordinary release build it wraps silently, leaving
  `data_size` short and the cursor in the wrong place with nothing reporting it. The patch widens
  before multiplying, so an implausible length becomes an out-of-range seek and the chunk is refused
  like any other damaged chunk. `fuzz_evtx` found it on `dev` minutes after the pull request that
  introduced the parser had merged with that same job green — the fuzzer takes a random seed, so the
  regression test added for it is deterministic rather than a saved crash input.
- Vendored `evtx`: a crafted `.evtx` input made the Event Log parser **not return** — past 300 s under
  the sanitizer, past 600 s without. A chunk's string table is a set of linked chains, and the walk of
  them guarded only against an entry pointing at itself, so a chain closed into a cycle of two or more
  was walked forever, overwriting the same cache keys each time round — which is why memory never grew
  and no allocator alarm fired. The walk now stops at a position it has already cached, and that loses
  no string. This defect was recorded here as open with its location not found; both saved reproducing
  inputs now parse, and `docs/testing.md` records the exception as closed rather than open. One fixed
  defect is not a proof that this parser cannot hang, and neither document claims it is.

### Removed
- The `application-no-crc32.evtx` Event Log fixture, on finding that it carried a real machine SID
  (`S-1-5-21-…-1000`, the first user account of a real computer) in its chunk string table. It had been
  vendored and committed on the strength of a byte scan that missed it, under a provenance document
  asserting no such SID was present — an assertion that was wrong in both directions, since the
  well-known `S-1-5-18` it did claim was not there either. `fixtures/evtx/PROVENANCE.md` records the
  correction rather than quietly dropping the file. The `EventID`-as-object case it covered is now a
  unit test over `scalar`/`number`, and two tests that asserted the absence of strings only that file
  contained were trimmed, since such an assertion passes whether or not the parser works.

### Added
- The `bam` collector: it enumerates the Background Activity Moderator's per-account keys under
  `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings` and reports, per registry value,
  the program's name, when BAM last saw it run, the parser's moderation state and how many bytes the
  value held — that last one because whether a value is still the documented 24 is the first sign of a
  layout this repository has never confirmed on Windows 11. **No part of the account's SID goes out**,
  hashed or otherwise: it identifies one account and one Windows installation, and the report says how
  many accounts had records instead. A path is emitted only when it begins with a drive letter, the one
  shape SS-mode redaction can reach. An absent BAM key is `source_missing`; a key that is there and
  holds nothing is `values: 0`, a cleared execution history. No rule reads it yet (ADR 0023).
- Hosts can enumerate the registry and read a value's bytes: `RegistrySource` gains `subkeys`,
  `value_names` and `read_bytes`, which is what BAM needs and what no other artifact does — its value
  *names* are executable paths and its value *data* is the artifact. A key or value that is not there
  is an answer rather than a failure, as it already is for a file. Each value is bounded at 64 KiB and
  a larger one is refused whole rather than truncated; the count of subkeys and of values is
  deliberately not bounded, because a partial enumeration would read as "there was nothing else". A
  fixture writes a binary value as a map with `content:` or `from:`, the pair a file entry already uses
  (ADR 0022).
- The `prefetch` collector: it lists `%SystemRoot%\Prefetch` and reports, per `.pf` file, the
  program's name, how many times Windows recorded it running, how many run times the file still held
  and the newest of them, plus one account of how many files the folder held and how many decoded —
  an emptied Prefetch folder is `files: 0`. **The files each program loaded and the volumes it touched
  are read and never reported**: Prefetch writes loaded-file paths as `\VOLUME{…}\USERS\<account>\…`,
  which SS-mode redaction cannot reach, a raw listing of them is what SS mode promises not to show
  whether or not a name is replaced in it, and a volume serial number identifies one machine across
  two reports with no rule able to ask anything of it. Reading the folder needs an elevated token, so
  a scan without one reports `not_admin` and says in the report that it could not read the artifact.
  No rule reads it yet (ADR 0021).
- The `pca` collector, the first thing in the product to call `rongroi-parsers`: it reads the three
  Program Compatibility Assistant files under `%WinDir%\appcompat\pca` and reports, per launch record,
  the program's name, when PCA saw it run, and its path — the last of these only when the path begins
  with a drive letter, which is the one shape SS-mode redaction can reach, so that a UNC or device path
  carrying an account name is withheld rather than shown unredacted. The general databases contribute
  only how many records they held and whether every line parsed, because no position in them has an
  established meaning and one of them is a user path. A file that is there and could not be read says so
  in the report rather than being counted away. No rule reads it yet, so what it sees is listed in Self
  mode and counted in SS mode (ADR 0020).
- Hosts can read a file's bytes: `FilesystemSource::read_file` returns the contents of a file a
  collector names, which is what the four parsers in `rongroi-parsers` have been waiting for — their
  whole API is bytes in, structs out, and until now nothing on a `Host` returned bytes. A file that is
  not there is an answer rather than a failure, as it already is for a directory. The read is bounded
  at 64 MiB and a larger file is refused whole rather than truncated: the file's size is chosen by
  whoever put it on the machine being examined, and a truncated artifact would be reported as a damaged
  one. A fixture describes a file's bytes inline with `content:` or points at a file under `fixtures/`
  with `from:`. Nothing consumes it yet; the collectors are the next pull requests (ADR 0019).
- Event Log parser: Windows `.evtx` files decode to a plain struct per record — the record id, the time
  it was written, the event id, the channel, the provider and the level — and a damaged chunk costs its
  own records and nothing else, the rest of the log being returned alongside an account of what failed.
  No event is interpreted: which id means a log was cleared is a rule's judgement, not a parser's. A
  record's payload is deliberately not kept, because that is where user names, host names, addresses and
  command lines live. The binary XML decoder is the `evtx` crate, whose error type stops inside the
  parser module; it brings the unmaintained `encoding` crate with it, and `deny.toml` now carries an
  ignore for RUSTSEC-2021-0153 that states the exposure rather than waving it away (ADR 0018).
- The `evtx` crate is **vendored under `third_party/evtx/` with one patch**, rather than taken from the
  registry. Its binary-XML reader sized a `Vec` from a record's substitution count without bounding it
  against the bytes remaining, so a **crafted** 68 KiB Event Log reached a 7.7 GB allocation — measured,
  not estimated. Crafted matters: the input came out of `fuzz_evtx`, mutated from a well-formed sample,
  and an unmodified Event Log does not do this. macOS survives it, since the reservation is lazy. Windows was not tested: there the
  commit is charged up front and a failed Rust allocation aborts uncatchably, so a machine without that
  much commit available would lose the process. Either way the size is chosen by the file and not by the
  program, which is what this crate's "never panics, never aborts" contract rules out. The patch bounds the reservation by the bytes the input could actually
  contain. Both fixes are now offered upstream as
  [omerbenamram/evtx#294](https://github.com/omerbenamram/evtx/pull/294), which credits the April 2026
  reports (#291, #292, #293) rather than claiming the finding, and discloses that it was written and
  opened by an AI assistant on the account owner's instruction. The directory goes away when an
  upstream release carries the fix. Everything else
  in it is byte-identical to the published crate and `third_party/evtx/PROVENANCE.md` says how to check
  that (ADR 0018).
- `fuzz_evtx`, the fuzz layer's sixth target, seeded from the same `fixtures/evtx/` file the parser tests
  read. It covers more third-party code than any other target, and the RUSTSEC ignore above names it as
  one of the things that bounds the risk of taking that dependency. It earned that billing immediately:
  it found the unbounded allocation above before the parser was ever pushed, and with the patch reverted
  it rediscovers it from the committed fixture alone in under 90 seconds.
- `cargo xtask check-baseline`: the whole rule set is run against fixture hosts described as ordinary
  machines, through the same `scan::run` pipeline the CLI uses, and any `Found` evidence that is not
  recorded in `rules/known-fps.csv` with a written reason fails the gate — as does a row whose rule no
  longer matches, because an unused exception is a claim about the rule set that is no longer true.
  Two baseline profiles ship, and both are silent today (ADR 0017).
- Prefetch parser: Windows `.pf` files — MAM-compressed or not — decode to a plain struct with the
  executable, run count, the last eight run times, the volumes and the loaded files, with every raw
  `FILETIME` kept beside its converted timestamp. SCCA versions 30 and 31 (Windows 10 and 11) are read;
  an older or unrecognised version is a typed error rather than a wrong parse. The decompressor is the
  `prefetch-core` crate, whose error type stops inside the parser module and never reaches the rest of
  the codebase (ADR 0015).
- The fuzz layer `docs/testing.md` has promised since M2: one cargo-fuzz target per parser entry point,
  seeded from the same fixtures the parser tests read, and a CI job that builds them and runs each for 30
  seconds as a smoke gate. `fuzz/` is its own workspace because cargo-fuzz needs nightly, so the pinned
  1.98.1 toolchain builds, lints and tests everything else exactly as before (ADR 0016).
- `fuzz_prefetch`, the fuzz layer's fifth target, seeded from the same `fixtures/prefetch/` files the parser
  tests read. Prefetch is the only parser that hands bytes read from the machine to a third-party
  decompressor, and a target pointed at it is half of why ADR 0015 accepted that dependency's immaturity.
- Unmatched observations: what a collector saw that no rule matched is kept, grouped by collector, and
  listed in Self mode — the files in FiveM's plugin folder and the running processes, which no rule reads.
  SS mode counts them and lists none, because a raw listing of every file and program name is what that
  mode promises not to show. `unmatched` is a new, additive field of the report format (ADR 0014).
- `process` collector: the processes running at scan time, each with its image name and, when Windows
  will name it, the path of its image. Nothing is hashed and no process memory is read; a process whose
  path cannot be resolved is still listed, without that field. No rule reads it yet (ADR 0010).
- Own traces: aeterna-rongroi is itself running while it scans, so the report now separates the
  observations that describe the tool from evidence about the machine, and shows them in an "own traces"
  section of its own — in both Self and SS mode, because hiding "this was us" from the person watching a
  screenshare would tell them less. The section is new in the CLI output and in the desktop report, and
  `own_traces` is a new, additive field of the report format (ADR 0010).
- `rongroi-parsers`: a new crate that turns Windows artifact bytes into plain Rust structs, with its
  first two parsers — BAM registry values and the PCA text files. Parsers are pure (no OS calls, no
  `Host`, no clock, no panic on any input), so they are tested on macOS and Linux as well as Windows.
  A PCA file with a malformed line returns the lines that parsed alongside an account of the ones that
  did not, and bytes whose meaning no public source establishes are kept rather than named or dropped
  (ADR 0013).
- `posture` collector: Windows test signing, memory integrity (HVCI) and whether a TPM is present, beside
  the Secure Boot state it already read. Memory integrity is read from the configured policy in the
  registry, which says what Windows was told to enforce and not that the hypervisor is enforcing it; a
  machine with no TPM is reported as a fact rather than as something that could not be measured (ADR 0011).
- Three rules, all `experimental`: test signing is on, memory integrity is configured off, and no TPM is
  present. The last is the first `context`-strength rule, so SS mode lists it only when it matches.
- `fivem_dir` collector: the files directly inside `%LOCALAPPDATA%\FiveM\FiveM.app\plugins`, each with its path and, when it can be read, its SHA-256. No rule reads it yet, so the files are shown in Self mode for a person to judge (ADR 0009).
- File-system and environment host sources, with `FixtureHost` describing directories and environment variables in YAML (ADR 0009).
- Restart with administrator rights on request: `aeterna-rongroi-cli scan --elevate` and a "Scan as
  administrator" button in the desktop app, so checks that need an elevated token can be measured instead of
  being reported as `Unmeasured`. The program starts again and scans from the beginning; declining the
  Windows prompt is a normal outcome, not an error (ADR 0012).

### Fixed
- ADR 0009 claimed the `fivem_dir` collector's observations were "still visible in Self mode". They were
  not: nothing carried an observation that no rule matched, so both collectors that ship without a rule
  read the machine on every scan and the result was discarded (ADR 0014).
- Desktop app: the report header shows the program version, which the release notes ask people to check.
- Documentation that had drifted from the code. `CONVENTIONS.md` §4 named `cargo xtask scrub-check` as
  what keeps a real user name, host name or SID out of a fixture; that command has never existed, review by
  hand is all there is, and the section now says so and records the gap. ADR 0008 and ADRs 0010–0018 were
  still `proposed` for decisions that are built and merged, and ADR 0008's Context still said no release
  workflow existed. `CONTRIBUTING.md` told a contributor to run `cargo xtask new-collector`, which does not
  exist either. README's Status table called M0 "in progress" and everything after it "planned", and put
  the release pipeline in M3 although it shipped with 0.1.0; it now says which milestones are released,
  which are merged but unreleased, and that nothing reads the M2 parsers yet. `GOVERNANCE.md` still framed
  the pre-first-release steps as outstanding, ADR 0013 placed USN and Amcache in M2 against README's M3,
  and `CONVENTIONS.md` §8 said a screenshare guide exists in Thai when it exists in no language.

## [0.1.0] - 2026-09-11

### Added
- Repository foundation: licenses, NOTICE with GPL section 7 terms, AGENTS.md, CONVENTIONS.md, policies.
- Rule format v1, rules bundle embedded in the executable, evidence engine with Found / NotFound / Unmeasured.
- Secure Boot posture collector with Live and Fixture hosts.
- CLI with Self and SS modes, and an unofficial-build banner.
- Desktop app shell (Tauri 2) with consent screen and English / Thai.
- Release workflow: official Windows executables with `SHA256SUMS`, SBOMs and build attestations in a draft GitHub release (ADR 0008).
