# ADR 0044 — A gap confined to one place a collector reads

- Status: proposed
- Date: 2026-09-14
- Amends: ADR 0009 (a folder that could not be listed is a gap in every field), ADR 0036 ("Recorded, not
  fixed"), ADR 0029 (when `exists: false` consults a gap)

## Context

A `CollectorRun::Measured` carries `gaps`: field → reason, "no rule may read this field as *not
found*, because it was never read" (ADR 0009). The map covers every observation of the run. For a
collector that reads one thing that is exactly right. `fivem_dir` reads four places, and each of its
observations says which one with `location`: Legacy's `plugins`, Enhanced's `enhanced_asi`, and the
two program folders `legacy_exe` and `enhanced_exe` (ADR 0035, ADR 0036). When one of the four could
not be listed, the collector wrote a gap in every field for the whole run, and ADR 0036 recorded what
that costs without fixing it:

> Gaps being run-wide has a cost these rules make visible: an unreadable Enhanced program folder makes
> the Legacy plugins rules `unmeasured` too, though that folder was read.

Measured on the two fixture hosts that describe it, before this change:

| Fixture host | What could not be read | `fivem_dir` rules `unmeasured / access_denied` |
|---|---|---|
| `fivem-dir-access-denied` | Legacy's `plugins` folder; the other three places are absent | all 7 |
| `fivem-dir-client-folder-denied` | Legacy's program folder; `plugins` listed and empty, Enhanced absent | all 7 |

On the second host, four of those seven rules — both plugin rules and both `asi` rules — ask only
about folders that were read and found empty or absent. `unmeasured` there is not false the way
`not_found` about an unread field would be, but it withholds an answer the scan had, and SS mode lists
each of them as a row, because none declares `access_denied` (ADR 0036). A reviewer is shown four
"could not check" rows about folders that were checked.

## Decision

### 1. A collector may declare a discriminator

`Collector::discriminator() -> Option<&'static str>`, `None` by default. It names the observation field
whose value says which of the places the collector reads an observation is about. `fivem_dir` declares
`location`; no other collector declares one.

Declaring it is a promise that **every** observation the collector emits carries that field. The engine
cannot check the promise, so `every_observation_carries_its_collectors_discriminator` runs every
collector over every fixture host and fails on an observation without it; a second test,
`discriminator_gaps_name_the_declared_discriminator`, fails if a run scopes gaps by any other field and
requires that some fixture host produce such gaps at all.

### 2. `DiscriminatorGaps`: gaps for one value of it

`CollectorRun::Measured` gains `discriminator_gaps: Vec<DiscriminatorGaps>`, each
`{ discriminator, value, gaps }` — "these fields could not be read for the observations whose
`discriminator` is `value`". It is serialised only when non-empty, so every other collector's run is
byte-for-byte what it was.

### 3. What the engine does with them

`evaluate_rule`, in order. Rows 1, 3 and 5 are what it did before; rows 2 and 4 are new.

| Step | Run-wide `gaps` | `discriminator_gaps` |
|---|---|---|
| 1 | a field of an `exists: false` condition is a gap → `unmeasured` **before** matching (ADR 0029) | — |
| 2 | — | while matching, an observation **carrying the place's value** does not satisfy `<field>\|exists: false` for a field that place's gaps list |
| 3 | any observation matched → `found` | the same |
| 4 | — | nothing matched, and a place **the rule could match in** has a gap in a field the rule names → `unmeasured`, with the first such place's reason |
| 5 | nothing matched and a field the rule names is a gap → `unmeasured`; otherwise `not_found` | the same |

(In the code step 5's gap check comes before step 4's; neither can turn the other's `unmeasured` into
`not_found`, so the order decides only which reason is shown when both apply, and a run-wide gap wins.)

**"A place the rule could match in"** is `could_match_there`: every one of the rule's conditions on the
discriminator holds for the place's value, compared by the same `condition_matches` that `match` uses —
the ASCII fold, `cased`, value lists and every operator included. A rule with no condition on the
discriminator could match anywhere, so every place reaches it. A rule whose `location: plugins` cannot
hold for `enhanced_exe` is not reached by what `enhanced_exe` did not yield. One function answers both
"does it match" and "could it match there", so the two cannot disagree.

**Why step 2 instead of step 1's early return.** A run-wide gap may explain the absence of a field on
any observation, so ADR 0029 answers `unmeasured` before looking. A place's gap can explain it only on
observations about that place. An observation from a place that was read lacks a field because the
field is not there, which is a measurement: the could-not-be-checked rule matching a locked plugin in a
listed folder is `found`, and that row names the file. With the early return it would have been
`unmeasured` and, because `matches` still counted it as matched for the unmatched bucket, shown nowhere.
Step 2 is ADR 0029's guarantee applied to exactly the observations the gap is about: an observation
from the unreadable place cannot be `found` by an absence nobody read. The same exclusion is applied
when the unmatched bucket is computed, so an observation step 2 refused is an unmatched observation
rather than dropped (ADR 0014).

### 4. `fivem_dir` reports each unreadable place for itself

- **Some places read, some not:** each place that could not be listed, or whose environment variable is
  unset, is one `DiscriminatorGaps` with every declared field and its reason. Run-wide `gaps` is empty.
- **No place read:** a gap in every field for the whole run with the worst reason, exactly as before. No
  place answered anything, so there is nothing for a discriminator to keep apart, and a rule naming a
  `location` this collector never emits stays `unmeasured` rather than becoming `not_found`.
- **Order.** Places with `access_denied` come first, the rest in the order the collector reads them. The
  engine takes the first place that reaches a rule, so this is ADR 0035's ranking — `access_denied` is
  the reason a rule may declare, and a run that met both is not better than its denial — carried into
  the per-place form.

The same two fixture hosts, after:

| Fixture host | `unmeasured / access_denied` | `not_found` |
|---|---|---|
| `fivem-dir-access-denied` | both `plugins` rules, could-not-be-checked | both `asi` rules, both `FiveM.exe` rules |
| `fivem-dir-client-folder-denied` | both `FiveM.exe` rules, could-not-be-checked | both `plugins` rules, both `asi` rules |

`a_fivem_folder_that_could_not_be_listed_leaves_the_rules_that_could_match_there_unmeasured` asserts
every one of those fourteen states through the shipped pipeline and the embedded bundle.

## Alternatives weighed

| Alternative | Why not |
|---|---|
| **Split the collector's run into one run per location** | `evaluate_rule` takes the first run for a rule's collector, so the engine would need to choose among runs — by asking which runs a rule could match in, the same question with the same discriminator, in a worse shape. It would also split `fivem_dir`'s unmatched observations into four groups under one collector id, and leave nowhere to say "no place was read" |
| **One field name per location** (`plugins_signature`, `enhanced_exe_signature`, …) | Gaps would then be per field and need no engine change, at the price of four names per idea, eight fields becoming thirty-two, and every rule and fixture rewritten — the opposite of `CONVENTIONS.md`'s one name per idea |
| **Change `gaps` itself to carry an optional scope** | Every collector and every test builds a `gaps` map today; a new field that defaults to empty changes none of them and cannot change their results |
| **Early-return `unmeasured` for a place gap on an absence condition too**, like step 1 | Hides a genuine `found` from a place that was read (step 2 above), and the observation it hides reaches no bucket |
| **Pick the reason by rank in the engine** | The engine does not know which reasons a collector prefers; the collector already orders its places, and does |
| **Leave it** (ADR 0036's position) | Four rows per affected report telling a reviewer "could not check" about folders that were checked |

## What changes for other collectors

Nothing, and that was measured rather than argued: they declare no discriminator and emit no
`discriminator_gaps`, every construction of a run elsewhere passes an empty list, and after this change
every test passed — 562 at the time — with **no report snapshot changed** (`cargo insta test --unreferenced reject`).
`REPORT_SCHEMA_VERSION` and `RULES_SCHEMA_VERSION` are unchanged: a run is not part of a report, and no
rule is written differently.

That no snapshot moved is also a limit worth naming: none of the snapshot hosts has a place that could
not be read, so the new states are held by the integration test above and by unit tests, not by a
snapshot.

## What is not established

- **No real machine has shown one FiveM folder denied while another is readable.** Both hosts above are
  synthetic. ADR 0036's limited-token run read all four places on the one machine measured. What this
  change settles is what the report says if that happens, not how often it does.
- **The promise that every observation carries the discriminator is checked on fixture hosts only.** A
  code path no fixture host reaches could emit an observation without `location`; the collector builds
  every observation through two functions that both insert it, which is a reading of the code, not a
  proof.
- **A `found` row does not say that another place could not be read.** Evidence has one state; a rule
  that matched in a readable place while another place was unreadable is `found`, as a rule with a
  run-wide gap in a field some observation still carried already was. For plugin folders the folder
  observation `folder: unreadable` is in the report (Self mode lists it as unmatched, SS mode counts it);
  for a program folder nothing in the report names the place, as before this change.
- **One discriminator per collector.** Nothing here needs two. A collector that reads places along two
  axes would need this revisited.
- **No other collector was assessed for a discriminator.** `evtx`'s `channel`, for one, says which log
  an observation is about, and whether its gaps should be scoped by it was not examined.

## Consequences

- `rongroi_core::model::DiscriminatorGaps`; `CollectorRun::Measured::discriminator_gaps`;
  `rongroi_collectors::Collector::discriminator`. The glossary gains **discriminator**.
- The same declaration decides one more thing, recorded where the definition it changes lives: a
  baseline observation that differs from a rule in the discriminator alone does not confront it
  (ADR 0033, amendment of 2026-09-14).
- `engine::evaluate_rule` and the unmatched bucket use `matches_in_run`; `could_match_there` is private
  to the engine.
- ADR 0036's "Recorded, not fixed" paragraph and ADR 0009's per-run sentence carry a pointer here.
  `docs/architecture.md`, `docs/rules-authoring.md` and `rules/AGENTS.md` say gaps may be confined to a
  place.
