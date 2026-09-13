# ADR 0037 — Prefetch's configuration as an observation, and the read-only attribute

- Status: proposed
- Date: 2026-09-13

## Context

Three facts about Prefetch, and one about an event log file, reached this program without any rule
being able to ask about them.

**`EnablePrefetcher` present, absent, or off.** The `prefetch` collector already read the value
(ADR 0030), and used it only to choose between two `Unmeasured` reasons: `service_disabled` when the
low bit is clear, and otherwise whatever the folder said. A reason is not an observation. Nothing
could match "the value is absent", and absence and `0` became the same thing in the report — the
collector's `application_launches_recorded` answered `None` for both an absent value and one it could
not read.

**The Prefetch folder is not there.** That returned `CollectorRun::Unmeasured { source_absent }`, with
no observation at all. The absence was measured — `list_dir` answered `Ok(None)` — and was reported
only as the reason every Prefetch rule could not be answered.

**A `.pf` or `.evtx` file carries the read-only attribute.** ADR 0009 said of the file-system source
that no attributes are read, and ADR 0019 repeated it when it added `read_file`: "still no recursion,
no timestamps, no size, no owner or ACL, no attributes". This ADR amends that sentence for one
attribute.

The question for each is the one `rules/AGENTS.md` asks of every tamper-shaped signal: what ordinary
machine produces it, and does it arrive together with the others for an innocent reason. A popular
optimiser script clears every event log **and** empties Prefetch in one click (ADR 0028), so a signal
that is only ever seen beside those is evidence for that script, not against the player.

## What was measured, and where

On 2026-09-13, on one Windows 11 machine (build 26220), read-only throughout — nothing on it was
changed:

| Question | Answer on that machine |
|---|---|
| `EnablePrefetcher` | present, `REG_DWORD` `3`, beside `BootId` and `BaseTime` and nothing else in the key. Readable **without** elevation |
| `.pf` files in `%SystemRoot%\Prefetch` | 239, **none** read-only (`Archive` and `NotContentIndexed` on all of them) |
| `.evtx` files in `%SystemRoot%\System32\winevt\Logs` | 413, **none** read-only (`Archive` and `Compressed` on all of them) |
| A file's attributes under a limited token | readable for `Security.evtx` and `Application.evtx`, whose contents that token cannot read |
| The Prefetch folder under a limited token | listing denied, as ADR 0015 says |

Then this pull request's CLI, cross-built, was run there:

| | Elevated | Limited token |
|---|---|---|
| Prefetch configuration | `folder: listed`, `enable_prefetcher: 3` | `folder: unreadable`, `enable_prefetcher: 3` |
| `.pf` observations carrying `read_only` | 243, all `false` | none — the folder was not listed |
| `.evtx` observations carrying `read_only` | 413 log accounts, all `false` | 413 refusals (`access_denied`), all `false` |
| `prefetch-file-read-only` | `not_found` | `unmeasured / not_admin` |
| `event-log-file-read-only` | `not_found` | `unmeasured / not_admin` |

Microsoft's own documentation of the switch is an archived Windows Embedded page: `EnablePrefetcher`,
`REG_DWORD`, under `…\Memory Management\PrefetchParameters`, "0 = Disabled, 1 = Application start
prefetching enabled, 2 = Boot prefetching enabled, 3 = Application start and boot enabled"
([Disable Prefetch, Standard 7 SP1](https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ff794503(v=winembedded.60))).
**No Microsoft page found says what the value is by default, or what Windows does when it is absent.**

Of the attribute, Microsoft says: "A file that is read-only. Applications can read the file, but
cannot write to it or delete it. This attribute is not honored on directories."
([File Attribute Constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)).

## Decision

### 1. Prefetch's configuration is an observation, beside the records

Every `prefetch` run that could look — that is, every run on Windows with `%SystemRoot%` set — now
emits one observation of the collector's configuration:

```json
{ "collector": "prefetch", "fields": { "folder": "listed", "enable_prefetcher": 3 } }
```

- `folder` is `listed`, `absent` or `unreadable` — the field name and the three words `fivem_dir`
  already uses for its folders, so one idea keeps one name. It is the only observation of this
  collector carrying `folder`, so a rule scopes itself to it with `folder|exists: true`.
- `enable_prefetcher` is the value as the registry holds it. **When the registry holds no value, the
  field is left out** — not `null`, not a default. `enable_prefetcher|exists: false` is then the one
  question "the value is absent", and it is a different question from `enable_prefetcher: 0`.
- A value that could not be read — denied, or of a type that is not a number — is neither: the field
  is left out **and** gapped with that read's reason, so `exists: false` answers `unmeasured`, never
  `found` (ADR 0029's ordering in `engine::evaluate_rule`).

### 2. An absent folder is `Measured`, and what was not read stays a gap

The folder being absent now returns `Measured` with the configuration observation and **every other
field gapped** with the reason it used to return — `source_absent`, or `service_disabled` when the
switch is off. A folder that could not be listed gaps the same fields, with the listing's reason.

This keeps what every existing and future rule on a Prefetch *record* means. Before, such a rule was
`unmeasured` because the run was; now it is `unmeasured` because the field it names is gapped, with
the same reason and the same `expected`. No rule's `not_found` can arise from a folder nobody read.
The only fields left ungapped are `folder` and `enable_prefetcher`, because those two were measured:
`list_dir` answered, and the registry answered.

The one visible change is in the report: a host with no Prefetch folder now contributes an unmatched
observation `{ folder: absent }`, which Self mode lists and SS mode counts (ADR 0014).

### 3. One attribute bit, on `FilesystemSource`

```rust
fn is_read_only(&self, path: &str) -> Result<Option<bool>, SourceError>;
```

`Ok(None)` is a file that is not there, as `read_file` reports it. Nothing else about a file's
attributes crosses the trait: not hidden, not system, not compressed, no timestamps, no size. A rule
needs one bit and the source hands back one bit.

**On the file-system source, not a new trait**, for the reason ADR 0019 put `read_file` there and ADR
0022 put enumeration on `RegistrySource`: the codebase splits sources by what is touched, and this
touches the same file `read_file` opens, with no additional permission.

**`LiveHost` uses `std::fs::symlink_metadata(path)?.permissions().readonly()`**, and no `unsafe`. Read
from the standard library's Windows implementation (`library/std/src/sys/fs/windows.rs`, in the 1.90
source installed locally — the pinned 1.98.1 toolchain ships no source, so the same code in that
release is **assumed**, not read): `readonly()` is `attrs & FILE_ATTRIBUTE_READONLY != 0`, and
`symlink_metadata` opens the entry with an access mode of `0`, every share mode and
`FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, falling back to `FindFirstFileExW` when
that open is refused. So the query reads no content, holds nothing open, and cannot stand in the way
of the Event Log service writing the file. `symlink_metadata` rather than `metadata`: the attribute of
the entry the collector listed, never of whatever a link points to. `GetFileAttributesW` was the
alternative — one call, no handle — and would have needed `unsafe`, a `windows` feature, and a wide
string for an answer the standard library already gives.

**`FixtureHost` models it per file entry**, as `read_only: true` or `false`. An entry that does not
say is `Unsupported`, never `false`: a fixture written before this change has not claimed its files
are writable, and silence is not a value — the rule the `code_integrity:` and `tpm:` blocks follow.

### 4. How a collector reports it

- `prefetch`: `read_only` on each `.pf` file's observation, whether the file decoded or was refused.
  An attribute that could not be read omits the field on that file **and gaps `read_only` for the
  run** with that failure's reason: one file whose attribute is unknown makes "no `.pf` file here is
  read-only" a claim nobody measured about it. `read_only` is not in `RECORD_FIELDS`, so an empty
  folder does not gap it — an empty folder holds no read-only file, and saying so is true.
- `evtx`: `read_only` on each log's account, and on the refusal of a log that could not be read — the
  attribute is asked before the bytes, and under a limited token it is the one thing about
  `Security.evtx` that can be read. An unread attribute gaps the field for the run, as above. It is in
  `RECORD_FIELDS`, beside every other per-log field.

### 5. Two rules read the attribute; nothing reads the configuration

| Rule | `match` | Why it is written |
|---|---|---|
| `prefetch-file-read-only` (`7d493537`) | `read_only: true` | Windows writes and rewrites these files itself; 0 of 239 carried the attribute on the one machine measured |
| `event-log-file-read-only` (`9b318bfa`) | `read_only: true` | The Event Log service writes these files itself; 0 of 413 carried it |

Both are `experimental` and `tamper`. `tamper` because the attribute is a change to the artifact's
file from how Windows' own writer leaves it; it is a class of evidence, not a severity (ADR 0031), and
under `tamper` a `not_found` is counted rather than listed in SS mode. Neither names a program
(ADR 0034): the question is about a file's attribute, whichever program a `.pf` file is about. Their
`falsepositives` are the two ways this ADR can support from a primary or a reproducible source:

- Read-only chosen in a folder's Properties, which Windows applies to the files inside. That the
  checkbox sets the attribute on the files and not on the folder is stated in Microsoft Q&A answers
  by community contributors, not in a Microsoft document found here; Microsoft's own page says only
  that the attribute "is not honored on directories". **Unverified by a Microsoft source.**
- Files copied or restored by software that keeps attributes. Microsoft's robocopy documentation:
  "The default value for the **/COPY** option is **DAT** (data, attributes, and time stamps)"
  ([robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)).

**Nothing reads `enable_prefetcher` or `folder`.** Three rules were considered and none is written:

- **"`EnablePrefetcher` is absent."** No ordinary cause could be written down: no Microsoft page
  states the default or the behaviour without the value, and the one machine measured has it. A rule
  whose `falsepositives` cannot be filled honestly is a rule `rules/AGENTS.md` does not allow, and one
  measured machine is not a population in which absence is unusual. It stays an observation: a person
  reading Self mode sees it.
- **"`EnablePrefetcher` is `0` or `2`."** A performance setting, recommended by tweak guides and set by
  optimiser scripts (ADR 0028), and already what `service_disabled` says. As a finding it would be
  the optimiser's shape presented as a fact about a person.
- **"The Prefetch folder does not exist."** An archived Microsoft TechNet forum answer by Microsoft
  support staff says application prefetching is disabled by default on Windows Server 2003 and later
  and the folder is not present there — a forum reply, not documentation. On a desktop, the ordinary
  causes named in ADR 0030 for an emptied folder apply to a deleted one, and nothing measured
  separates the two. Not written.

A rule on any of them is now *expressible*, which is what this ADR had to settle; whether one is
*defensible* is a question for the pull request that brings a population, not one machine.

### 6. Baselines

`baseline-elevated-win11` carries `EnablePrefetcher: 3` and `read_only: false` on its `.pf` file and
its log, each a value measured on the machine above and recorded in `fixtures/hosts/PROVENANCE.md`.
Both rules are therefore **confronted**: the baseline's observation carries `read_only` and is one
condition from firing (ADR 0033). The other two baselines set no `%SystemRoot%`, so both collectors
stay `Unmeasured` there, as before.

## What was rejected

| Alternative | Why not |
|---|---|
| A new `Unmeasured` reason for "the switch is absent" | A reason is not matchable, and a reason that names a configuration state is a finding in the vocabulary (ADR 0030 refused `bam_pruned_at_boot` for this) |
| `enable_prefetcher: null` when absent | `null` is its own JSON type and equality cannot stand in for absence; `exists: false` is the operator ADR 0029 added for exactly this |
| Put `folder` and `enable_prefetcher` on the account observation | The account exists only when the folder was listed, so an absent folder would still have nowhere to say so |
| Keep `Unmeasured { source_absent }` for an absent folder and add the observation elsewhere | A `CollectorRun::Unmeasured` carries no observations |
| Emit the whole attribute word, or `hidden` and `system` as well | Collect only what a rule needs (`crates/rongroi-collectors/AGENTS.md`); no rule asks about them |
| Count read-only files on the account instead of a bit per file | A reviewer needs to know which file; a count is a second field for one idea, and `read_only` on the file observation already answers `exists` and equality |
| `GetFileAttributesW` | `unsafe` and a new `windows` feature for the bit `std` returns |
| Treat an unread attribute as `false` | A value nobody read, in a field a rule matches |

## What is unverified

- **One machine.** 0 of 239 and 0 of 413 are counts on one Windows 11 installation, not a
  distribution. Whether a Windows build, an edition, an OEM image or a common application leaves `.pf`
  or `.evtx` files read-only is not established.
- **Whether Windows' Prefetch writer or the Event Log service honours the attribute on its own files**
  was not tested and is not claimed — no file on the test machine was changed. Neither rule's text
  says what the attribute does to the artifact.
- **What Windows does with no `EnablePrefetcher` value.** No primary source found.
- **The standard library's implementation in 1.98.1.** Read in the 1.90 source; the pinned toolchain
  has no source installed.
- **`GetFileAttributes`-level behaviour on a file the Event Log service holds open** was exercised on
  the test machine through PowerShell and through this program's CLI (413 accounts, no failure), which
  is evidence for that machine and that build only.
- **The folder-Properties false positive** rests on community answers, as said above.

## Consequences

- `FilesystemSource` gains `is_read_only`; `LiveHost`, `NonWindowsHost` and `FixtureHost` implement it,
  and a live test in `rongroi-host-windows` sets and reads the attribute on a file in its own temporary
  folder on the Windows CI runner.
- `prefetch` declares three more fields (`enable_prefetcher`, `folder`, `read_only`) and `evtx` one
  (`read_only`). An absent Prefetch folder is a `Measured` run whose non-configuration fields are all
  gapped; `prefetch`'s tests that expected `Unmeasured` now expect that.
- Every report snapshot gains the two rule rows. On hosts with no `%SystemRoot%` they are `unmeasured /
  read_failed`, listed in SS mode, as the log-clearing rules' rows already are (ADR 0031).
- The consent question, the desktop consent screen, `PRIVACY.md` and `docs/architecture.md` say that
  these files' read-only attribute and Prefetch's switch are read.
- ADR 0009's "no attributes" and ADR 0019's restatement of it are amended for this one bit.
