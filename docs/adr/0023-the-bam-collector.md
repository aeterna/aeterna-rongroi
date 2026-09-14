# ADR 0023 — The BAM collector

- Status: proposed
- Date: 2026-09-12

## Context

ADR 0013 wrote the BAM parser and left the collector to a later pull request. ADR 0019 gave a host a
way to hand a collector a file's bytes, ADR 0020 spent them on the Program Compatibility Assistant and
ADR 0021 on Prefetch. BAM was the one artifact those two capabilities did not reach, because it is not
a file: ADR 0022 added the registry enumeration and the binary value read it needs, and this is what
they are for. It is the fourth and last collector of M2's parsers except the Event Log, which is held
behind the non-termination defect `docs/testing.md` records.

BAM's shape is unlike the other three in two ways that decide most of what follows.

**The artifact is split between the name of a registry value and its data.** A value under
`…\Services\bam\State\UserSettings\{SID}` is named with an executable's path and holds a timestamp;
neither half means much without the other. So the collector cannot avoid handling a path the artifact
spelled — the problem ADR 0020 met in PCA — while `rongroi_parsers::bam` handles the bytes.

**The artifact is partitioned by user account.** Prefetch, PCA and `fivem_dir` read one folder and say
nothing about whose it is. BAM's keys *are* accounts, named by SID, and a collector has to decide what
to say about that. Nothing else in this program has had to.

## Decision

### No rule ships with it

The argument ADR 0020 made for PCA and ADR 0021 for Prefetch, unchanged. BAM records a path and a
timestamp and **no hash**, while a rule's `allow` may identify legitimate software only by `sha256` or
by `signer` (CONVENTIONS.md §6, `rules/AGENTS.md`). A rule saying "`cheat.exe` ran" would have no way
to exclude a legitimate program of that name. Writing it is a separate decision with its own
false-positive argument, and this pull request does not make it.

**Decided in ADR 0034.** The separate decision this section defers was made: no rule on `prefetch`, `bam`
or `pca` identifies a program by `name` or `path`.

The observations land in the unmatched bucket: listed in Self mode, counted and never listed in SS
mode (ADR 0014). That settles the privacy question for *this* pull request by construction, and it is
not what the withholding below rests on, because a rule would change it and the withholding has to
survive that.

### The SID does not go out, in any form

**Decision: no part of an account's SID reaches a report. Not the SID, not a hash of it, not its last
segment, not a per-run index. What is reported is how many accounts had records.**

The case for emitting something was weighed rather than waved away. A reviewer reading a report might
reasonably want to know whether a program ran under the account being checked or under another one on
the same machine, and a well-known SID such as `S-1-5-18` would say "this ran as the system" — a real
distinction between a service and a person's own session.

It is declined anyway, and the reasons stack:

- **A SID is two identifiers in one.** `S-1-5-21-X-Y-Z-<RID>` carries a per-account relative
  identifier *and*, in `X-Y-Z`, an identifier of the machine or domain that issued it. The second half
  is exactly what ADR 0021 refused to publish when it withheld a volume serial number: a value that is
  the same in two reports from one machine and different in reports from two machines. A report is a
  file a player hands to a server's staff, who keep it (PRIVACY.md); this program has no reason to
  hand them a way to link two of those files.
- **CONVENTIONS.md §4 names a SID beside a user name and a host name** as the things a fixture must
  never contain. A field that must not be in a test fixture is a strange thing to put in a report about
  a real person's machine.
- **Hashing is worse than withholding.** A hash of a SID is still a stable per-account identifier —
  the linkage survives the hash, which is the whole point of a hash — and it would be the first hashed
  identifier in this codebase, in a report whose only other `sha256` is a file's. No rule could use it
  either: `allow` compares the `sha256` of a *file*.
- **A per-run index buys nothing.** `user_index: 0` is not an identifier, and it is also not an answer:
  no rule can match a number that means a different account on every run, and a reader cannot tell
  which account `0` is. What it would do is partition a person's programs by account inside the report,
  which is a distinction with no consumer.
- **The well-known-SID idea is a judgement, and a table.** Recognising `S-1-5-18` means shipping a list
  of well-known SIDs and deciding which of them are safe to name — an interpretation in a collector,
  which ADR 0002 keeps out of this program, and one nothing in this repository could check. If a rule
  ever needs "ran as the system", it arrives with that rule and with the PRIVACY.md sentence that
  discloses it, which is the order ADR 0020 and ADR 0021 both set.

What *is* reported is `users`, the number of account keys that were enumerated. A count is not an
identifier; it does not distinguish two machines with two accounts each; and it carries the one fact a
reviewer genuinely needs — whether the records they are reading are all of them, or one account's
worth of several. The account observation also says the rest was withheld, rather than leaving a reader
who knows BAM is keyed by SID to guess whether this program read the accounts and dropped them or never
read them.

A consequence worth stating: **a refusal to read one account's key is reported in the same shape as a
refusal to read the whole BAM key**, because the only thing that would tell them apart is the account.
That is a real loss of detail and it is the price of the decision above.

### What is emitted

`rongroi_core::engine::matches` compares field values for exact JSON equality and takes a rule's
`match` block as a conjunction: no regex, no substring, no numeric comparison, no disjunction. Three
kinds of observation, as `pca` and `prefetch` have.

**A program BAM recorded**, one per registry value that decoded:

```json
{
  "collector": "bam",
  "fields": {
    "name": "example.exe",
    "path": "C:\\Users\\fixtureuser\\Downloads\\example.exe",
    "last_run": "2020-01-01T00:00:00Z",
    "moderation_state": 0,
    "value_bytes": 24
  }
}
```

- `name` is the last segment of the value's name, **lower-cased** — the same field name and the same
  normalisation `pca` and `prefetch` give it, so a rule author learns one spelling for "which
  program". It is the field a rule can actually use: a full path differs on every machine.
- `path` is the value's name, exactly as BAM spelled it, and **only when it begins with a drive
  letter**; otherwise `path_withheld: "unredactable_form"`. See below.
- `last_run` is the instant BAM stored, RFC 3339 UTC. A raw `FILETIME` naming no representable instant
  omits the field rather than inventing one. **A `FILETIME` of zero is reported as 1601-01-01**, not as
  an absence: whether a zero means "never ran" is a judgement for a rule, and a collector that turned
  it into a missing field would take that judgement away (ADR 0013). Under exact equality a rule can
  match that instant if it ever wants to.
- `moderation_state` is the parser's own name for bytes 8..12. The collector is not naming a byte
  range here — `rongroi_parsers::bam` did, on the strength of two public write-ups, and this passes it
  through. What the number means on Windows 11 is unverified; see below. A value too short to hold it
  omits the field rather than reporting a zero nobody read.
- `value_bytes` is how long the value was. ADR 0013 names it as the first thing to check on a current
  build — "whether a BAM value is still 24 bytes" — and it is the one number here that means the same
  thing on every machine, so a rule or a reader can see at a glance that a machine's BAM is not the
  shape the write-ups describe.
- **The undecoded tail is not emitted, under any name, not even as a length of its own.**
  `BamEntry::unparsed_tail` is bytes with no established meaning; `value_bytes` says how many there
  were without pretending to know what they are.

**An account of what BAM held**, one per run that enumerated the key:

```json
{
  "collector": "bam",
  "fields": {
    "users": 1,
    "values": 2,
    "entries": 2,
    "rejected": 0,
    "intact": true,
    "sid_withheld": "per_user_identifier"
  }
}
```

`values` is how many registry values were enumerated, `entries` how many decoded, `rejected` how many
were there and yielded nothing. `intact` is `rejected == 0`, the same field and the same meaning `pca`
and `prefetch` give it, pre-normalised because the question a rule wants is `rejected > 0` and exact
equality cannot express it.

**`values: 0` under a key that exists is the matchable question on this artifact**: a machine whose BAM
state was cleared, which is `prefetch`'s `files: 0` one source over. It is also why an empty key is
`Measured` and an absent key is not — see the table below.

**Something that yielded nothing**, one per value that could not be read or decoded, and one for the
BAM key or an account key that could not be enumerated:

```json
{ "collector": "bam", "fields": { "path_withheld": "unredactable_form", "read": "truncated" } }
```

`read` is one of `access_denied`, `too_large`, `failed` (from a `SourceError`, through
`crate::failure::read_failure`) and `truncated`, `malformed` (from a `ParseError`). The parser accepts
any length of at least eight bytes, so `truncated` is the only decode failure it has today;
`malformed` is there for whatever a later version of it adds, and a finer word invented here for a
failure this collector has not seen would be a guess in evidence. A key-level refusal carries `read`
and nothing else.

A rule scopes itself with `name`, `read` or `values`. A `read` observation carries no `name` and no
`value_bytes`, and every other observation carries no `read`, so a rule written for one never matches
another.

### The path is withheld unless it is drive-rooted

The rule `pca` set (ADR 0020), applied unchanged, and BAM is the artifact it matters most for.
`rongroi_core::view::redact_user_paths` requires literally a drive letter, a colon, a separator, the
segment `users`, a separator. A path of the form `\Device\HarddiskVolume3\Users\<account>\…` has no
drive letter, so redaction does not touch it, and an SS viewer would see a real account name while the
code around it says paths are redacted. Withholding is the direction that cannot leak a name, and the
omission is *stated* — `path_withheld` — because silently dropping the field would read as "BAM
recorded no path", which is never true: the path is the value's name.

Whether BAM in fact writes device paths is **unverified** (below). The test costs nothing either way:
if a machine spells them with a drive letter they are emitted, and if it does not they are not.

Widening `redact_user_paths` to any `\Users\<name>\` segment was considered and declined for the third
time here, for the reasons ADR 0020 gave: it is a change to `rongroi-core` with its own snapshot churn,
it weakens a function whose current precision is testable, and it would still miss a profile folder not
named `Users`.

### Failure classification

| What happened | Outcome |
|---|---|
| Not Windows | `Unmeasured { not_windows }` |
| the BAM key is not there | `Unmeasured { source_missing }` — since ADR 0030, `source_absent`; a key that is there and holds no record is `source_empty` |
| the BAM key is there and could not be enumerated | a `read:` observation **and** every field in `gaps` |
| the BAM key is there and holds no account | `Measured`, one account observation, `users: 0` |
| one account's key could not be enumerated | a `read:` observation **and** every field in `gaps` |
| one value could not be read or decoded | a `read:` observation naming it; `rejected` and `intact` say so; **no gap** |
| a value was enumerated and is gone when read | nothing; counted as neither read nor refused |

**An absent BAM key is `Unmeasured`, not an empty `Measured`.** The engine turns an empty `Measured`
into `NotFound`, and `NotFound` on this collector would tell a server admin a program did not run, on
evidence that was never read. An absent key is the absence of the record, not a statement about what
ran. The same reasoning ADR 0020 and ADR 0021 applied to their artifacts, and the same reason
`not_on_this_os` stays unproduced here as it did there: a collector cannot tell "this Windows has no
BAM" from "BAM has recorded nothing on this machine" by the absence alone.

**A key that is there and holds nothing is a different answer, and it is `Measured`.** That is the
cleared-state case, and it is the one a rule could ask about.

**Denial is classified against `is_elevated()` through `crate::failure::reason_for`**, so a scan
without administrator rights reports `not_admin` and one with them reports `access_denied` — the pair
that makes the restart-as-administrator offer (ADR 0012) worth taking or not worth taking. The read is
attempted first and classified second, so a machine where the key happens to be readable is read.

**Whether reading this key needs an elevated token is not established in this repository, and the brief
this pull request followed asserted it.** ADR 0015 states the requirement for Prefetch and ADR 0018 for
the Event Log; nothing anywhere states it for BAM, and an exhaustive search of the repository for it
found nothing. The collector is correct either way, because it attempts and classifies rather than
short-circuiting on `is_elevated()`. `not_admin` is treated as an ordinary outcome rather than a fault
— which is right whether the requirement is real or not — but this ADR does not assert the requirement.

**A denial partway through gaps the run; a single bad value does not.** Those are the two precedents
this repository already has, and BAM needs both: an account key that cannot be enumerated loses an
unknown number of records, which is ADR 0020's case for a PCA file, while one value that will not
decode loses one program's record and says nothing about the others, which is ADR 0009's per-item case
that ADR 0021 applied to a `.pf` file. The loss stays visible either way — the thing is named with
`read`, `rejected` counts it, `intact` goes false.

### Alternatives weighed

| Alternative | Why not |
|---|---|
| Emit the SID | A per-account and per-installation identifier, in a file a player hands to someone who keeps it, that no rule can use |
| Emit a hash of the SID | The linkage survives the hash. It would be the first hashed identifier here, and `allow` compares the hash of a file |
| Emit the RID, or a per-run `user_index` | Not an identifier and not an answer either: no rule can match it, no reader can resolve it, and it partitions the report by account for nobody |
| Recognise well-known SIDs and name them | A table and a judgement in a collector (ADR 0002). It arrives with the rule that needs it |
| Emit one observation per account instead of one per run | The same partition by another route, with the SID's information content restored by ordering |
| Emit `path` whatever its shape | A device path carries `\Users\<account>\` past a redactor that cannot see it, in a report whose text says paths are redacted |
| Widen `redact_user_paths` instead | Declined by ADR 0020 and ADR 0021 already; the objection here is the same and the churn is real |
| Emit `unparsed_tail`, or its length | Bytes with no established meaning (ADR 0013). `value_bytes` says how many there were without naming them |
| Omit `moderation_state` because its meaning is unverified | The parser named it, not this collector, and dropping a decoded field would hide the very thing a current-build check needs to see |
| Treat a zero `FILETIME` as "never ran" | A judgement for a rule. The parser deliberately refuses to make it, and a collector that made it would be deciding for every future rule |
| `Measured` with nothing in it when the key is absent | The engine reads that as `NotFound`, i.e. "the program did not run", from a record that does not exist |
| Gap the run for one undecodable value | It would make the collector `Unmeasured` on any machine with one odd value among hundreds, which says less than what happened |

## What is unverified

**BAM's value-name path form on Windows 11.** `rongroi_parsers::bam` says only "the value name is the
executable's path". Whether that is `\Device\HarddiskVolumeN\…`, a drive-rooted path, or something else
on a current build is not established anywhere in this repository, and this pull request did not
establish it. The collector handles both, and which branch a real machine takes decides whether `path`
is ever emitted at all. The check on a real Windows 11 machine is to read one value name under
`…\bam\State\UserSettings\{SID}` and look at its first characters.

**BAM's 24-byte value layout on Windows 11.** ADR 0013 records that both public write-ups tested only
Windows 10 builds 18363 and 19592, from 2019–2020, and that nothing confirms the layout on Windows 11.
This collector inherits that uncertainty rather than resolving it: `moderation_state` may name
something that is no longer a power-throttling DWORD, and `last_run` rests on the first eight bytes
still being a `FILETIME`. `value_bytes` exists so that the first sign of a changed layout is visible in
a report rather than silently decoded as if it were the old one. **No fixture in this repository is a
real BAM value** — `fixtures/parsers/PROVENANCE.md` says every file there is synthetic and
hand-written — so no test here can confirm any of it.

**CI's Windows runner cannot settle either of those, or the permission question.** It runs as
administrator with UAC off, so the `not_admin` branch — the one an ordinary scan may take — is never
exercised there, and whatever its BAM key contains is a GitHub runner's rather than a player's.

**No real BAM value has been read by anything.** Every byte this collector was tested against is a
synthetic fixture. So: how many values a real account key holds, how many accounts a real machine has
under `UserSettings`, whether real value names are always paths, and whether a real machine holds
values this collector has not seen fail — none of it is established.

**Volume in the report is not measured.** A real BAM key may hold a few hundred values across several
accounts, and Self mode lists every unmatched observation. That is the same unmeasured behavioural
change ADR 0021 recorded for Prefetch, at a smaller scale. No cap is applied on the number of values
read, for the reason ADR 0022 gives for not bounding an enumeration.

**The live registry path was not executed.** `LiveHost::subkeys`, `value_names` and `read_bytes` are
compiled and linted for `x86_64-pc-windows-msvc` and run by nothing here. That Windows answers
`ERROR_ACCESS_DENIED` — and therefore `SourceError::AccessDenied` rather than some other code — for a
denied BAM key is assumed from the classification `LiveHost` already applies to every registry read.

## Consequences

- `all()` gains `bam::Bam`. `docs/architecture.md` gains its row and `PRIVACY.md` says what this
  collector reads and what it does not report.
- `crate::paths` is new: `file_name`, `is_drive_rooted` and `UNREDACTABLE_FORM` move out of `pca`
  unchanged, so the two collectors that handle a path an artifact spelled answer the same two
  questions in one wording. No behaviour changes and `pca`'s tests are untouched apart from the two
  that move with the functions.
- **No existing snapshot moves.** No fixture host written before this change describes a BAM key, so
  the collector is `Unmeasured { source_missing }` on every one of them and contributes no
  observation. `cargo xtask check-baseline` is untouched for the same reason, and both baselines stay
  silent.
- Neither the CLI nor the desktop app changes: both render the unmatched bucket by collector id
  (ADR 0014), and the desktop types an observation's `fields` as an open record.
- No dependency enters `Cargo.lock`. `rongroi-collectors` has depended on `rongroi-parsers` since
  ADR 0020, and `bam` is the last of the four parsers to have a caller — `evtx` still has none, and is
  held behind the non-termination defect in `docs/testing.md`.
- Ten fixture hosts are added. All are synthetic; all reference `fixtures/parsers/bam/` with `from:`
  and copy nothing. Their SIDs and account names are invented and are written out in full so that a
  test asserting no part of one reaches an observation has something to assert against.

## Amendment (2026-09-14) — each account key's own `Version` and `SequenceNumber`

**What was wrong.** This ADR and ADR 0022 describe an account key as holding one value per program and
nothing else. It does not. Every account key measured also holds two values named `Version` and
`SequenceNumber`, both `REG_DWORD`. The collector read them as candidate records: `read_bytes` refuses a
value that is not `REG_BINARY` (ADR 0022), `LiveHost` passes that on as a failure (`windows-registry`
0.100's `Key::get_bytes` answers `ERROR_INVALID_DATA` for any other type), and the collector counted
each as a value that was there and yielded nothing. So **every ordinary PC reported `intact: false`**,
the run was gapped `partial`, and Self mode listed two rows `{ path_withheld: unredactable_form, read:
failed }` per account — `path_withheld` because a name like `Version` does not begin with a drive letter.
No rule reads this collector (ADR 0034), so no evidence changed; what was misleading was the account a
reviewer reads and the noise in Self mode.

**Measured, read-only, on two Windows 11 machines** (the first read through this program's own report,
the second directly):

| Build | Source | What it showed |
|---|---|---|
| 26200 | a Self-mode report from release 0.2.0 | the account observation `users: 8, values: 63, entries: 47, rejected: 16, intact: false`, and 16 observations `path_withheld: unredactable_form, read: failed`. Sixteen is two per account; the report attributes no row to an account and names no value, so it is consistent with the pair on every key rather than a reading of it |
| 26220 | PowerShell's `RegistryKey.GetValueKind` and `GetValue` over every account key, elevated, 2026-09-14 | 7 account keys; every one holds `Version` and `SequenceNumber` as `REG_DWORD`; `Version` is 1 in all 7 and `SequenceNumber` between 59 and 170; every other value (74 of them) is `REG_BINARY` of exactly 24 bytes; 2 of the 7 keys hold the two values and nothing else |

The second measurement printed counts, types, lengths and the two numbers only — no SID and no value
name other than these two. Nothing on either machine was changed.

**Microsoft documents neither value.** A search of Microsoft Learn on 2026-09-14 found no description of
either; the only pages mentioning this key are community answers about the program entries. So this
program gives them no meaning — not "the layout version of the records", not "a write counter" — and
does not report their numbers.

**Decision.**

- A value is set aside as the account key's own only when its name is `Version` or `SequenceNumber`,
  compared without case as the registry compares value names, **and** `read_u32` reads it as a number.
  A value of one of those names and any other type is read like every other value and, when it does not
  decode, is counted in `rejected` with its `read:` row, so a damaged or unexpected value stays visible.
  On `LiveHost`, `read_u32` also accepts a `REG_QWORD` whose number fits in 32 bits (`Key::get_u32`
  in `windows-registry` 0.100), so such a value with one of those names would be set aside too; none was
  seen.
- The two are neither `entries` nor `rejected`, emit no observation of their own, and **are counted in a
  new account field, `metadata_values`**, rather than dropped silently — the same reason the account says
  `sid_withheld` out loud.
- **`values` now counts only the values read as candidate records**, so `values == entries + rejected`
  apart from a value that disappears between listing and reading. The alternative, keeping the pair in
  `values`, was declined: `values: 0` is this ADR's one matchable question (a key holding no record) and
  the `source_empty` gap rests on it, and on every measured machine the pair would make that answer
  `values: 2 × users` for a key that holds no record — which is what 2 of the 7 keys measured on build
  26220 were.

**Fixtures.** `bam-account-metadata` is new: two accounts, both holding the pair with measured numbers,
one of them also a record. `bam-entries-present` and `baseline-elevated-win11` gain the pair, because
both describe an ordinary machine and an ordinary machine's key holds it
(`fixtures/hosts/PROVENANCE.md`). The one snapshot that moves is
`report_snapshot__bam_entries_present_self_view`, which gains `metadata_values: 2`; the SS-mode snapshot
counts the account and does not change.

**What this does not establish.** Whether every Windows build that has BAM writes these two values, or
only the builds measured; what either number means; whether an account key can hold other non-record
values on other machines. Such a value would be counted in `rejected` and turn `intact` false, which is
the direction that stays visible. Two machines are two machines.

**Also learned, and not a decision.** Every one of the 74 `REG_BINARY` values on build 26220 was 24 bytes
long. That is the length ADR 0013 asked about, on one machine; it says nothing about whether the bytes
are still laid out the way `rongroi_parsers::bam` decodes them.
