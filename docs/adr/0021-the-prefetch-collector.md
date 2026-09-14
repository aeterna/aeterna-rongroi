# ADR 0021 — The Prefetch collector

- Status: proposed
- Date: 2026-09-12

## Context

ADR 0015 called Prefetch "the strongest execution artifact M2 reads" and wrote the parser for it, then
left the collector to a later pull request — one that "needs an elevated token, and reports
`Unmeasured` without one". ADR 0019 gave a host a way to hand a collector a file's bytes, and ADR 0020
spent them on the Program Compatibility Assistant. This is the Prefetch half.

Two things make it a different shape from the PCA collector rather than a copy of it:

- **It enumerates.** PCA has three file names that are known in advance, so it reads by name and never
  lists a folder. Prefetch is a folder of up to about a thousand `.pf` files whose names are not known
  until they are read, so this collector lists first and reads second — the `fivem_dir` shape, with
  `read_file` added.
- **A `.pf` file holds the sharpest personal data this program has yet touched.** Its string table is
  the full path of every file the program loaded, normally hundreds of them and some under a user's
  profile, plus the volumes it touched and their serial numbers. That is the decision this ADR mostly
  exists to record.

It is also the first time `prefetch-core` — the third-party MAM/Xpress-Huffman decompressor ADR 0015
took on, published two months before that decision with one maintainer — is reachable from a real
scan. Until this pull request it ran only under `cargo nextest` on five vendored files and under
`fuzz_prefetch` on mutations of them. From here it runs on whatever bytes sit in a player's Prefetch
folder.

## Decision

### No rule ships with it

The same argument ADR 0020 made for PCA, and ADR 0009 made for `fivem_dir`, and it is if anything
stronger here. Prefetch records a **name and no hash** — `PrefetchRecord` has no digest and the
artifact has no path for the executable at all — while a rule's `allow` may identify legitimate
software only by `sha256` or by `signer` (CONVENTIONS.md §6, `rules/AGENTS.md`). A rule saying
"`cheat.exe` ran" would therefore have no way to exclude a legitimate program of that name, on the
artifact that proves execution most strongly. Writing that rule is a separate decision with a separate
false-positive argument, and this pull request does not make it.

**Decided in ADR 0034.** The separate decision this section defers was made: no rule on `prefetch`, `bam`
or `pca` identifies a program by `name` or `path`.

The observations land in the unmatched bucket: listed in Self mode, counted and never listed in SS
mode (ADR 0014). That settles the privacy question for *this* pull request by construction — nothing
this collector emits reaches an SS viewer at all today — but it is not what the withholding below
rests on, because a rule would change it and the withholding must survive that.

### What is emitted

`rongroi_core::engine::matches` compares field values for exact JSON equality and takes a rule's
`match` block as a conjunction. No regex, no substring, no numeric comparison, no disjunction. Three
kinds of observation, as `pca` has:

**A program Prefetch recorded**, one per `.pf` file that decoded:

```json
{
  "collector": "prefetch",
  "fields": {
    "name": "cmd.exe",
    "path": "C:\\Windows\\Prefetch\\CMD.EXE-D269B812.pf",
    "run_count": 55,
    "recorded_runs": 8,
    "last_run": "2016-01-12T20:07:03.9810694Z",
    "scca_version": 30
  }
}
```

- `name` is the base name Prefetch stored, **lower-cased**. This is the field a rule can use, and it
  is deliberately the same field name and the same normalisation `pca` gives a launch record, so a
  rule author learns one spelling for "which program" rather than two. Windows upper-cases what it
  stores, and a rule matching `CMD.EXE` under exact equality would miss a record written any other
  way, so the normalisation happens once, here.
  The raw `executable` is **not** emitted beside it: it is the same string in a different case, and a
  second field carrying it would be a second thing to match on that no rule should choose.
- `path` is the `.pf` file, not the program. Prefetch does not record where the executable lives —
  only its base name and the volume-relative paths this collector withholds — so there is no
  executable path to emit. The `.pf` path is emitted unconditionally, without the drive-letter test
  `pca` applies, and the difference is the point: `pca`'s test guards a path **the artifact spelled**,
  which may be a UNC or device path with an account name in it, while this path is built by the
  collector from `%SystemRoot%` and the file's own name and contains no user profile segment.
- `run_count` is Prefetch's own total. `recorded_runs` is how many run times the file still held, at
  most eight; `recorded_runs: 8` says the window is full and older runs have aged out, which is
  something a reader needs before concluding anything from `last_run`.
- `last_run` is the newest of those, RFC 3339 UTC. A raw `FILETIME` that names no representable
  instant omits the field rather than inventing one; the rest of the record still stands.
- The **older seven run times are not emitted.** An array cannot be matched by exact equality, and
  seven fields no rule can use on up to a thousand observations is noise in a report a person reads.
  `recorded_runs` says how many there were. Emitting them is a deliberate widening for a rule that
  needs them, which is the standard ADR 0014 set for this bucket.

**An account of the folder**, one per run that listed it:

```json
{
  "collector": "prefetch",
  "fields": {
    "files": 1,
    "entries": 1,
    "rejected": 0,
    "intact": true,
    "loaded_files_withheld": "user_file_list",
    "volumes_withheld": "machine_identifier"
  }
}
```

`files` is how many `.pf` files the folder held, `entries` how many decoded, `rejected` how many were
there and yielded nothing. `intact` is `rejected == 0` — the same field and the same meaning `pca`
gives it, "everything this collector read yielded a record" — and it exists for the same reason: the
question a rule wants to ask is `rejected > 0`, which exact equality cannot express.

`files` is the one genuinely useful matchable number on this artifact. **`files: 0` on a folder that
exists is a Prefetch folder that was emptied**, which is a machine whose execution history was
removed — and unlike every other question here it is the same string on every machine.
`files >= entries + rejected`, because a file that was listed and gone by the time it was read counts
in neither: Windows rewrites this folder while a scan runs, and ADR 0019 made that an answer rather
than a failure.

The two `_withheld` fields are on this observation and not on every record, because they are a
statement about the run rather than about one file, and because a constant field repeated a thousand
times is noise. They mirror `pca`'s `path_withheld: "unredactable_form"`: a field name naming what is
absent, and a token naming why.

**Something that yielded nothing**, one per `.pf` file that could not be read or decoded, and one for
the whole folder when the folder itself could not be listed:

```json
{ "collector": "prefetch", "fields": { "path": "C:\\Windows\\Prefetch\\CMD.EXE-4A81B364.pf", "read": "unsupported_version" } }
```

`read` is one of `access_denied`, `too_large`, `failed` (from a `SourceError`, through
`crate::failure::read_failure`) and `truncated`, `not_prefetch`, `not_decompressible`,
`implausible_size`, `unsupported_version`, `malformed` (from a `ParseError`). The parser collapses
those six into two variants and one `field` name; the collector spreads them out again, because they
are different machines to a reviewer. A `.pf` from an older Windows on a machine that was upgraded in
place is ordinary; a `MAM` container whose payload does not decompress is a file something has written
over. Telling a reviewer "malformed" about both would lose the only part of this that is evidence.

The folder-level refusal carries `read` and nothing else — there is no file to name, and the collector
id already names the folder.

A rule scopes itself with `name` (a program that ran), `read` (something that did not read) or `files`
(the account). Two of the three carry `path`, because a file is worth naming whether it decoded or
not; `path` alone is not a usable matcher on any of them, since it differs on every machine.

### The privacy boundary: `loaded_files` and `volumes` do not leave the parser

**`loaded_files` is withheld whole**, and redaction was not attempted. Three separate reasons, any one
of which would be enough:

1. **The redactor cannot reach these paths.** `rongroi_core::view::redact_user_paths` requires
   literally a drive letter, a colon, a separator, the segment `users`, a separator. Prefetch writes
   `\VOLUME{01d12173f395296c-66f451bc}\USERS\<account>\APPDATA\LOCAL\…` — verified by reading the
   vendored Windows 10 fixture, and pinned by `prefetch.rs`'s own
   `the_windows_10_fixture_carries_user_profile_paths`. No drive letter, so no redaction. A report
   whose surrounding text says paths are redacted, showing a real account name, is worse than a report
   that does not show the path.
2. **Redaction would not rescue it even if it reached.** ADR 0014 settled this: "a redaction pass over
   a raw listing would look like a guarantee while changing almost nothing about what the listing
   reveals". Hundreds of file paths per program, for every program on the machine, is a description of
   what a person has on their computer. Replacing one segment of each does not make it less of one.
3. **No rule could use it.** Under exact equality a rule would have to match a whole path string that
   differs on every machine. Even the shapes that might matter — "this program loaded a DLL from a
   temp folder" — are substring questions the matcher cannot ask.

**`volumes` is withheld whole too**, and this one deserves its own argument because the field is not a
person's name. A `PrefetchVolume` carries a device path (`\VOLUME{…}`), a 32-bit serial number and the
volume's creation time. The serial and the creation time together are a **stable identifier of one
Windows installation**: two reports from the same machine carry the same pair, two reports from
different machines do not.

The case *for* emitting them is real and was weighed. A `.pf` file whose volume serial does not match
the machine's own system volume was copied in from somewhere else, which is a genuine tamper signal
and exactly the kind of thing a forensic reviewer looks for. It is not emitted anyway:

- **Nothing could act on it today.** Making that comparison needs the scanned machine's own volume
  serial, which no `Host` method returns; it would be a new host capability and its own ADR. Emitting
  an identifier now against a rule that does not exist is how an identifier ends up in a report with
  nobody able to say what it is for.
- **A report is a file a player hands to a server's staff, who keep it** (PRIVACY.md). An identifier
  that links two such files across time is a linkage this program has no reason to create, and
  PRIVACY.md does not disclose one. The `not_found`/retention framing of this whole tool is about what
  a machine did, not about which machine it is.
- **The device path is the prefix of the withheld list.** Emitting `\VOLUME{…}` while withholding
  `\VOLUME{…}\USERS\<account>\…` publishes the machine identifier and withholds only the name, which
  is the half that is easier to guess anyway.

If a later pull request adds the system-volume comparison, the serial arrives with the rule that uses
it and with the PRIVACY.md sentence that discloses it. That is the same order ADR 0020 set: the
exposure arrives with the rule, never ahead of it.

What survives — a base name, three numbers and a timestamp — is what a rule could use, and is what
this collector emits.

### Failure classification

| What happened | Outcome |
|---|---|
| Not Windows | `Unmeasured { not_windows }` |
| `%SystemRoot%` unset or empty | `Unmeasured { read_failed }` — there was no folder to look in |
| the Prefetch folder is not there | `Unmeasured { source_missing }` — since ADR 0030, `source_absent`, or `service_disabled` when `EnablePrefetcher` says Windows records no application launch |
| the folder is there and could not be listed | a `read:` observation **and** every field in `gaps` |
| one `.pf` file could not be read or decoded | a `read:` observation naming it; `rejected` and `intact` say so; **no gap** |
| a `.pf` file was listed and is gone when read | nothing; counted as neither read nor refused |

**An absent Prefetch folder is `Unmeasured`, not an empty `Measured`.** Prefetch is off on some
machines by policy, and an absent folder is also what an installation that never had it looks like. In
neither case is "no `.pf` file is here" the statement "no program ran" — it is the absence of the
record that would have said either way. The engine turns an empty `Measured` into `NotFound`, and
`NotFound` on this collector would tell a server admin a program did not run, on evidence that was
never read. `fivem_dir` reports an absent plugin folder the other way round because there "FiveM is
not installed" genuinely is the answer.

**A folder that could not be listed is `not_admin` when this program was not elevated.** ADR 0015
records that reading `%SystemRoot%\Prefetch` needs an elevated token, so on an ordinary scan this is
the *expected* path and not an error. The read is attempted first and classified second, through the
same `crate::failure::reason_for` `pca` wrote, so a machine where the folder happens to be readable
without those rights is read rather than assumed shut. `not_admin` is the signal that makes the CLI's
and the app's restart-as-administrator offer (ADR 0012) worth taking, and this collector is the one
that will produce it most often.

The denial is **also** emitted as an observation, not only counted in `gaps`. With no rule reading
this collector a `gaps` entry reaches no screen at all — a `Report` carries evidence, own traces and
unmatched observations, never the runs — and an artifact this program could not read is precisely what
an evader would arrange. It is the part a reviewer most needs.

**One unreadable `.pf` file does not gap the run, which is where this differs from `pca`.** ADR 0020
gapped every field on one unreadable PCA file, because a PCA file is the whole record of a class of
launches and losing it loses an unknown number of entries. A `.pf` file is not that: it is one
program's record. Losing it loses that program and says nothing about the others, which is exactly the
per-item case ADR 0009 settled for `fivem_dir` — one unhashable plugin omits one field and is never a
gap. The alternative was weighed and rejected: gapping the whole collector on one transient failure
among eight hundred files would make this collector `Unmeasured` on most real machines, which says
less than what actually happened. The loss stays visible three ways — the file is named with `read`,
`rejected` counts it, and `intact` goes false — and a rule that needs the folder to have been read
whole can add `intact: true` to its matcher.

### The third-party decompressor, and the bound on it

This pull request is what makes `prefetch-core` reachable from a real scan for the first time. ADR
0015 accepted that crate's immaturity — two months old, one maintainer, few users — on two grounds:
that its blast radius is a wrong parse rather than memory corruption, and that `fuzz_prefetch` exists
to find such a defect. Both still hold, and neither is a claim that the risk is absent. What changes
today is the input distribution: five vendored files and their mutations become whatever is in a
player's Prefetch folder.

**The 16 MiB cap ADR 0015 mentions was verified in the code, not taken on trust.**
`rongroi_parsers::prefetch::MAX_DECOMPRESSED_LEN` is `16 * 1024 * 1024`, and
`reject_implausible_declared_size` runs **before** `prefetch_core::decompress`, which is what matters:
the decompressor reserves the declared size up front, so a header declaring 4 GiB has to be refused
before it is reached. Two limits of that check, read from the same function and worth writing down
here because a collector is what exposes them:

- It applies to a `MAM` container only. An **uncompressed** `.pf` declares no size and is not checked
  — it is bounded instead by ADR 0019's 64 MiB `read_file` limit, because an uncompressed payload is
  the file's own bytes. So the effective bound on an uncompressed Prefetch payload is 64 MiB, not
  16 MiB.
- The cap bounds the *declared* size, not the decompressor's behaviour on a stream that lies about it.
  That is `fuzz_prefetch`'s job, and `prefetch-corrupt-files` is now the one fixture in this repository
  that drives that branch end to end from a `Host`.

### Alternatives weighed

| Alternative | Why not |
|---|---|
| Emit `loaded_files` redacted through `view` | The redactor does not reach `\VOLUME{…}\USERS\<name>\…` at all — no drive letter. The report would say paths are redacted while showing an account name |
| Emit `loaded_files` after widening `redact_user_paths` to any `\Users\<name>\` | ADR 0020 already declined to widen it, and it would not help: the objection is the listing, not the name in it (ADR 0014) |
| Emit only a count of loaded files | A number no rule can match, on a field whose whole value was the paths. It buys nothing and invites the next person to ask for one more field |
| Emit the volume serial number | A stable identifier of one machine, which nothing today can compare against anything, in a file a player hands to someone who keeps it. It arrives with the rule that uses it or not at all |
| Emit `executable` raw as well as `name` | The same string in a different case. Two matchable fields for one idea, one of which fails on exact equality |
| Derive the program's name from the `.pf` file name for a file that did not decode | `<NAME>-<HASH>.pf` is a convention, and splitting on it is a guess. The path is emitted whole and a reader can see it; a guess in a field a rule matches is worse than no field |
| `Measured` with no observations when the folder is absent | The engine reads that as `NotFound`, i.e. "the program did not run", from a record that does not exist |
| `Unmeasured` for a folder that could not be listed | Nothing reaches the report at all while no rule reads this collector, and "could not read the artifact" is the part a reviewer most needs |
| Gap every field when one `.pf` file fails | One `.pf` is one program's record (ADR 0009). It would make the collector `Unmeasured` on most real machines over one transient failure |
| Read the folder with `read_file` on names known in advance | There are none: `.pf` names carry a hash of the executable's path and are not predictable |
| Cap how many `.pf` files are read | A number invented here, with no measurement behind it, that would silently drop part of the artifact. The honest answer is to read the folder and record that the volume is unmeasured |
| `WinDir` for the folder, as `pca` uses | `SystemRoot` is what `rongroi_parsers::prefetch` and ADR 0015 name this artifact's location under. Both are set by Windows and name the same directory; using the documented one keeps the code checkable against the document |

## What is unverified

**No real `.pf` file from a real machine has been read by any collector.** Every byte this collector
was tested against is either the 2016 upstream corpus (`fixtures/prefetch/PROVENANCE.md`) or bytes
constructed in a fixture. So: how many files a real Prefetch folder holds, how large they are, whether
any of them is an SCCA v31 file (the corpus has none, and v31 is a version this parser accepts on the
strength of reading `prefetch-core`'s source rather than of a parse), and whether the folder in
practice contains files that fail in ways this collector has not seen — none of that is established
here.

**CI's Windows runner cannot settle Prefetch behaviour.** It runs **as administrator with UAC off**
and it **disables SysMain**, so the live smoke there exercises neither the non-elevated branch — the
one this collector will take on almost every real scan — nor a machine that has a populated Prefetch
folder. `docs/testing.md` already says this collector is expected to be `unmeasured` there. What it
reports on that runner is therefore not evidence that it reports correctly anywhere.

**That reading `%SystemRoot%\Prefetch` needs an elevated token is asserted in prose and not measured.**
ADR 0015 states it and this collector is built around it; nothing in this repository measured it, and
neither did this pull request. The collector is correct either way, because it attempts the listing
and classifies the result. The check on a real Windows 11 machine with a standard user token is
whether `list_dir` on that path returns `AccessDenied`.

**The volume-serial decision rests on a use that does not exist.** The argument for emitting a serial
turns on comparing it with the scanned machine's own system volume, and no `Host` method returns that.
Whether such a comparison would in practice separate a copied-in `.pf` from an ordinary one — on a
machine with several volumes, or one that was cloned — is not established here either.

**`prefetch-core` on real-machine input is unmeasured.** Its five vendored files parse and
`fuzz_prefetch` has found nothing in a 30-second smoke, which is the whole of the evidence. A real
folder is a thousand files written by several Windows builds, and this pull request is what first
sends them through it.

**Volume in the report is not measured.** The largest unmatched group before this change was six PCA
observations. A real Prefetch folder holds up to about a thousand `.pf` files, so Self mode may list a
thousand observations — a behavioural change PRIVACY.md describes but that has never been exercised at
that scale, in either the CLI's renderer or the app's. Reading a thousand files through `read_file` is
also the most I/O this program has ever done in one scan, and how long that takes was not measured.

**The `LiveHost` path was not executed.** `list_dir` and `read_file` against a real
`%SystemRoot%\Prefetch` were compiled and linted for `x86_64-pc-windows-msvc` and run by nothing. In
particular, that Windows answers `PermissionDenied` — and therefore `AccessDenied` rather than some
other kind — for a denied Prefetch folder is assumed from `std`'s documented mapping.

## Consequences

- `all()` gains `prefetch::Prefetch`. `docs/architecture.md` gains its row and `PRIVACY.md` names the
  two fields this collector reads and does not report.
- `crate::failure` is new: `reason_for` and `read_failure` move out of `pca` unchanged, so the two
  collectors that classify a `SourceError` do it in one place and with one vocabulary. No behaviour
  changes and `pca`'s tests are untouched.
- **No existing snapshot moves.** None of the fixture hosts that predate this change sets
  `%SystemRoot%`, so the collector is `Unmeasured { read_failed }` on every one of them and
  contributes no observation. `cargo xtask check-baseline` is untouched for the same reason, and both
  baselines stay silent.
- Neither the CLI nor the desktop app changes: both render the unmatched bucket by collector id (ADR
  0014), and the desktop types an observation's `fields` as an open record. The two new L3 snapshots
  are read by name, so `pnpm test` is unaffected.
- No dependency enters `Cargo.lock`. `prefetch-core` and `xpress-huffman` arrived with ADR 0015;
  `rongroi-collectors` already depends on `rongroi-parsers` after ADR 0020.
- Seven fixture hosts are added, four of which point at `fixtures/prefetch/` with `from:` and copy
  nothing. `prefetch-corrupt-files` writes one file's bytes inline: they exist to exercise the
  collector's reporting rather than the parser, and `fixtures/prefetch/` is a fuzz seed corpus that
  must not gain inputs that are not artifacts.
- The Windows 10 fixture's account name and volume serial numbers now reach a collector test. They
  reach no observation, which is what the tests assert — by shape, because a one-letter account name
  cannot be asserted absent.
