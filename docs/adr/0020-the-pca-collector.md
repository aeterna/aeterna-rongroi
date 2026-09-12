# ADR 0020 — The PCA collector

- Status: proposed
- Date: 2026-09-12

## Context

ADR 0019 gave a host a way to hand a collector the bytes of a file. Nothing used it. `rongroi-parsers`
still held four parsers that no part of the product called, and `rongroi-collectors` still did not
depend on it. This is the pull request that joins them, and the artifact it joins them over is the
Program Compatibility Assistant.

PCA rather than Prefetch, BAM or the Event Log, for reasons this ADR is also the place to record so
that they can be checked rather than taken on faith:

- **It needs no capability beyond `read_file`.** Three fixed paths under `%WinDir%\appcompat\pca` and
  an environment variable that `EnvironmentSource` already supplies. BAM needs registry enumeration
  and a binary registry value, neither of which exists.
- **No ADR states an elevated-token requirement for it.** ADR 0015 states one for Prefetch and ADR
  0018 states one for the Event Log; nothing in this repository states one for PCA. If the folder is
  readable without an elevated token — which is **not verified**, see below — then this is the first
  collector whose wiring makes an ordinary, non-elevated scan read more than it did.
- **Its parser carries no third-party code and no known hang.** `rongroi_parsers::pca` depends on
  `jiff` and the in-repo CP-1252 table (ADR 0013). `prefetch` pulls `prefetch-core`; `evtx` pulls a
  vendored binary-XML decoder with an open non-termination defect (`docs/testing.md`).
- **Its shape is the one this codebase already has.** A `source` discriminator, a `path` and a
  timestamp is `fivem_dir`'s `location` + `path` + `sha256` with a different third field.

## Decision

### No rule ships with it

A rule that matched a PCA launch record would match it by name or by path, and `allow` may identify
legitimate software only by `sha256` or by `signer` (CONVENTIONS.md §6, `rules/AGENTS.md`). PCA
records neither: it records a path and a time. So a rule saying "this program ran" would have no way
to exclude a legitimate program of the same name, which is the objection that kept `fivem_dir`
rule-free (ADR 0009) and it applies here unchanged.

An observation no rule matched is an **unmatched observation**: listed in Self mode, counted and never
listed in SS mode (ADR 0014). That is a real destination, and it is the one this collector ships into.
It also settles the privacy question for this pull request by construction — nothing this collector
emits reaches an SS view at all today, because SS mode lists no unmatched observation. The exposure
arrives with the rule, not with the collector, and the rule is a separate decision.

### The observation shape, and what a matcher can do with it

`rongroi_core::engine::matches` compares field values for **exact JSON equality**, and a rule's
`match` block is a **conjunction of all its keys**. There is no regex, no substring, no numeric
comparison and no disjunction. Everything below follows from that: a field a rule should be able to
match on has to be emitted already normalised, and a question that needs "or" needs two rules.

Three kinds of observation, disjoint by which fields they carry, so that a rule written for one never
matches another:

**A launch record**, one per line of `PcaAppLaunchDic.txt`:

```json
{
  "collector": "pca",
  "fields": {
    "source": "app_launch_dic",
    "name": "game.exe",
    "path": "C:\\Users\\alex\\Downloads\\game.exe",
    "last_run": "2026-09-12T10:23:46Z"
  }
}
```

- `source` names which of the three files the record came from, as `fivem_dir`'s `location` names
  which folder a file was in. It is on every observation this collector emits, so a rule can scope
  itself to one file without having to know what else may appear later.
- `name` is the last path segment, **lower-cased**. This is the field a rule can actually use: a full
  path differs on every machine, so under exact equality it matches nothing, while `cheat.exe` is the
  same string everywhere. Windows does not care which case a program was launched with, so a record
  written `Cheat.exe` and one written `cheat.exe` have to arrive at a rule as one string or a rule
  matching either would miss the other. `path` is left exactly as the file spelled it, which is what
  CONVENTIONS.md defines that field as; `name` is a normalisation and says so here.
- `last_run` is RFC 3339 UTC, from the parser's `Timestamp`. No rule can usefully match an exact
  instant; it is there for the person reading Self mode and for a later rule that has something to
  compare it against.
- `path` is emitted **only for a path that begins with a drive letter** — see below.

**An account of one file**, one per file that was read:

```json
{ "collector": "pca", "fields": { "source": "app_launch_dic", "entries": 3, "rejected": 0, "intact": true } }
```

`rejected` being empty is the only thing that says a PCA file was intact — the parser's own
documentation makes that point, which is why it returns the lines that parsed alongside an account of
those that did not. `entries` and `rejected` are the counts a person reads. `intact` exists **because
of the matcher**: a rule wants to say "this file has lines that do not parse", which is
`rejected > 0`, and exact equality cannot express it. `rejected: 0` can be matched and is the useless
direction — it fires on every healthy machine. So the useful question is pre-normalised into a boolean
the engine can compare. A rule that later needs a different question answered gets a field added for
it deliberately, which is the same widening standard ADR 0014 set for the unmatched bucket.

A worked example of a rule this shape admits, to show the interface is real:

```yaml
collector: pca
strength: tamper
match:
  source: app_launch_dic
  intact: false
```

and its positive fixture:

```json
{
  "description": "PCA's launch dictionary has lines that do not parse",
  "observations": [
    { "collector": "pca", "fields": { "source": "app_launch_dic", "entries": 41, "rejected": 2, "intact": false } }
  ],
  "expect_matches": 1
}
```

That rule is not written here — its `falsepositives` list needs facts about how often Windows writes a
line PCA's own format does not accept, which this repository does not have.

**A file that yielded nothing**, one per file that is on the machine and could not be read or parsed:

```json
{ "collector": "pca", "fields": { "source": "app_launch_dic", "read": "access_denied" } }
```

`read` is one of `access_denied`, `too_large`, `failed`, `not_pca_text`, `truncated`. It is
deliberately finer than the `UnmeasuredReason` the same failure puts in `gaps`: "Windows would not let
me read it" and "it is not the format it should be" are different things to a reviewer, and only the
second is a machine with something odd in `appcompat\pca`. This observation carries no `name`, `path`
or `last_run`, so a rule written for a launch record never matches it, and it carries `read`, which no
other observation does, so a rule written for it never matches a launch record.

### The PII boundary: a path is emitted only in the shape redaction can reach

PCA records the paths of programs that ran. That is a list of what a person has on their computer, and
it is the sharpest constraint in this pull request.

`rongroi_core::view::redact_user_paths` replaces `X:\Users\<name>` — a drive letter, a colon, a
separator, the literal segment `users`, a separator. **A path with no drive letter in front of it is
not touched.** A UNC path such as `\\nas\home\<name>\tool.exe` and a device path such as
`\Device\HarddiskVolume3\Users\<name>\tool.exe` both carry an account name straight through the
redactor. The parser hands back whatever the line spelled, and nothing in this repository establishes
that PCA only ever writes drive-letter paths.

So the collector emits `path` only when the path begins `X:\` or `X:/`, and otherwise emits
`path_withheld: "unredactable_form"` and no path at all. Three things about that choice:

- **Withholding beats a redactor that silently fails.** A path shown to an SS viewer with a real
  account name in it, in a report whose surrounding text says paths are redacted, is worse than a
  path that is not there. ADR 0014 already refused to let redaction stand in for withholding, for the
  same reason.
- **The test is deliberately narrower than the redactor.** `redact_user_paths` scans the whole string,
  so it would in fact reach `\\?\C:\Users\<name>\…`. The collector refuses that shape anyway. Erring
  toward withholding is the direction that cannot leak a name.
- **The withholding is said out loud.** An absent `path` with nothing in its place would read as "PCA
  recorded no path", which is not what happened. `path_withheld` is also a matchable field: a rule
  that wants to know a program was launched from a share or a device path has one.

The alternative of widening `redact_user_paths` to the `\Users\<name>\` segment regardless of prefix
was not taken here. It is a change to `rongroi-core` with its own snapshot churn, it weakens a function
whose current precision is testable, and it would still not cover a profile folder that is not named
`Users`. If a later collector needs it, it is its own decision with its own ADR.

Also withheld, each for a reason of its own:

| | Emitted | Why |
|---|---|---|
| `PcaGeneralDb0/1` record fields | **no**, only the counts and `intact` | No position has an established meaning (`PcaGeneralEntry` names none, deliberately), and field 1 of the lines this repository has is a user path. A field name invented here would put a guess into a report a server admin is asked to trust |
| a rejected line's text | **no** | `RejectedLine::text` "normally contains a full user path" and says so where it is defined. The count carries the signal |
| a rejected line's number and reason | **no** | One observation per bad line, that no rule can use, on a file that may have many. The count is what a rule and a reader both want |
| `name` | **yes** | A program's name can itself carry a person's name — an installer that names an executable after the account that ran it. That is an already-disclosed, already-accepted limitation of this whole program (PRIVACY.md), not something PCA introduces |

### Failure classification

| What happened | Outcome |
|---|---|
| Not Windows | `Unmeasured { not_windows }` |
| `%WinDir%` unset | `Unmeasured { read_failed }` — there was no folder to look in |
| none of the three files is there | `Unmeasured { source_missing }` |
| a file is there and could not be read | a `read:` observation, **and** every field in `gaps` |
| a file is there and has a line that does not parse | an `intact: false` account; **not** a gap |

**None of the three files being there is `Unmeasured`, not an empty `Measured`.** This is where PCA
differs from `fivem_dir`, whose absent plugin folder is `Measured` with nothing in it because the
engine turns that into `NotFound` and "FiveM is not installed" is the honest answer. An absent PCA
store is not the statement "this program did not run" — it is the absence of the record that would
have said either way. A rule reading that as `NotFound` would be telling a server admin a program did
not run, on evidence that was never read.

**The reason is `source_missing`, not `not_on_this_os`.** The parser's module documentation instructs
a collector to report `not_on_this_os`, because these files do not exist on Windows 10 at all. Read
against what the collector can actually observe, that instruction cannot be followed honestly: an
absent folder is also what a Windows 11 machine looks like when PCA has written nothing, and the
collector cannot tell the two apart from the absence. `source_missing` — "the artifact is not present
or not reported on this machine" — is true in both cases; `not_on_this_os` is true in one and false in
the other. Where this repository cannot tell two states apart it says the thing that is true of both
(`posture` makes an absent registry value a gap rather than "off"), so that is what this does.
`not_on_this_os` stays unproduced. Producing it honestly needs the Windows version or PcaSvc's own
state read, which is a later decision and a different source.

**One unreadable file gaps every field, which is stricter than `fivem_dir`.** ADR 0009 established
that a per-item failure omits a field and is never a gap: one unhashable plugin says nothing about the
others. A PCA file is not one item in a listing. It is the whole record of a class of launches, so an
unreadable one loses an unknown number of entries, and a rule that then read "no match" as `NotFound`
would be making the same false statement as above. What *was* read is still emitted — the run stays
`Measured` — so a reader sees both halves.

**Denial is visible, not counted away.** An artifact this program could not read is exactly what an
evader would arrange, so it is emitted as an observation and reaches Self mode through the unmatched
bucket, rather than only existing as a `gaps` entry that no rule reads yet. Denial is classified
against `is_elevated()`: `Some(false)` makes it `not_admin`, which is this repository's first
production of that reason and the signal that makes the CLI's and the app's restart-as-administrator
offer (ADR 0012) worth taking. The read is attempted first and classified second, so a machine where
the folder happens to be readable without an elevated token is read.

### Alternatives weighed

| Alternative | Why not |
|---|---|
| List the folder with `list_dir`, then read what is in it | Three fixed names are already known. Listing adds a second failure mode that says the same thing and lets a fixture describe a folder whose listing and whose files disagree |
| One observation per file, carrying its entries as an array | An array cannot be matched by exact equality, so no rule could reach a single record. It would also make a per-record `path` invisible to `SelfIdentity`, which partitions own traces by `path` |
| Emit the general databases' fields as `field_0`, `field_1`, … | A field named on a guess in evidence a server admin is asked to trust. `PcaGeneralEntry` refuses to name them for that reason and the collector is not the place to overrule it |
| Emit `path` always and rely on SS redaction | The redactor does not reach a UNC or device path. The report would say paths are redacted while showing an account name |
| Withhold `path` entirely | It is the field `SelfIdentity` uses to move this program's own launch record into own traces, and the one thing that tells a reader *where* a program ran from. Withholding the shapes redaction cannot reach costs less and says more |
| `Measured` with no observations when no PCA file is there | The engine reads that as `NotFound`, i.e. "the program did not run", from a record that does not exist |
| Report a whole-folder denial as `Unmeasured` | Nothing then reaches the report at all while no rule reads this collector, and "could not read the artifact" is the part a reviewer most needs |

## What is unverified

**Whether `%WinDir%\appcompat\pca` is readable without an elevated token is not established, and
cannot be established on CI.** Nothing in this repository states it either way, and this pull request
does not claim it. The GitHub Windows runner cannot answer it: it runs **as administrator with UAC
off** and it **disables PcaSvc**, so the live smoke there exercises neither the non-elevated branch nor
a machine that has these files. It needs a real Windows 11 machine, with a standard user token, and
the thing to check is whether `read_file` on each of the three paths succeeds. If it turns out to need
an elevated token, the second reason in the Context section above falls away — the collector is
correct either way, because it attempts the read and classifies the result, and `not_admin` is the
answer it already produces.

**No real PCA file was read.** Every byte this collector was tested against is synthetic and
hand-written (`fixtures/parsers/PROVENANCE.md`). The `<path>|<timestamp>` shape and the timestamp
format come from public write-ups (ADR 0013), so what a real file holds — how many lines, which path
shapes, whether Windows ever writes a line its own format does not accept — is not known here. The
`intact` field's usefulness turns on that last one and is therefore unmeasured.

**Which path shapes PCA writes is not known.** The drive-letter test is a decision about what this
program is willing to print, taken because the repository cannot rule the other shapes out — not a
finding that PCA writes them. If a real machine shows that it only ever writes drive-letter paths,
`path_withheld` becomes dead and can be removed on that evidence.

**Volume on a real machine is not measured.** The largest unmatched group today is three processes.
A real `PcaAppLaunchDic.txt` may hold far more lines than that, and Self mode listing all of them is a
behavioural change to the report that PRIVACY.md describes but that has never been exercised at scale.

## Consequences

- `rongroi-collectors` depends on `rongroi-parsers` for the first time. No external crate enters
  `Cargo.lock`: the dependency is a workspace edge.
- `all()` gains `pca::Pca`, which is the whole of registering a collector. `docs/architecture.md`
  gains its row.
- **No existing snapshot moves.** A `Report` carries evidence, own traces and unmatched observations,
  never the runs, and none of the fixture hosts that predate this change sets `%WinDir%`, so the
  collector is `Unmeasured` on every one of them and contributes nothing. `cargo xtask check-baseline`
  is untouched for the same reason, and both baselines stay silent.
- Neither the CLI nor the desktop app changes. Both render the unmatched bucket by collector id
  (ADR 0014) and the desktop types `fields` as an open record, so a new collector reaches both screens
  without an edit. The two new L3 snapshots are read by name, so `pnpm test` is unaffected.
- `not_admin` becomes producible for the first time. Its translations in the CLI and both locale files
  have existed and been unreachable since M1.
- Seven fixture hosts are added and each one points at the parser corpora rather than copying them,
  except `pca-unredactable-path`, whose bytes are inline because they exercise the collector's
  withholding rather than the parser and must not become a fuzz seed.
- `rongroi_parsers::pca::parse_general_db` is now called by the product and its result is deliberately
  almost entirely discarded. That is not waste: `rejected` is a tamper signal and costs one read, and
  the day a field there is established the collector is the only place that changes.
