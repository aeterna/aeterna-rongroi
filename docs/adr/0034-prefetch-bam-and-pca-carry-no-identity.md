# ADR 0034 — Prefetch, BAM and PCA carry no identity

- Status: accepted
- Date: 2026-09-13

## Context

README's milestone table lists M2 as "Prefetch, BAM, PCA, event-log tamper signals". Since 0.2.0 all
four collectors ship, and so do two log-clearing rules for the Event Log. No rule reads `prefetch`,
`bam` or `pca`, and the table said so in words that read as work still to do: "no rule reads
Prefetch, BAM or PCA yet".

Each of the three collector ADRs deferred that rule in the same sentence. ADR 0020 for PCA, ADR 0021
for Prefetch and ADR 0023 for BAM each say *no rule ships with it* and call writing one "a separate
decision". Nobody has made that decision, so it stayed open by default. This ADR makes it.

### What these three observations can name

The fields each collector declares (`FIELDS` in `crates/rongroi-collectors/src/<collector>.rs`):

| Collector | Fields that say which program |
|---|---|
| `prefetch` | `name`, `path` (the `.pf` file's own path, not the program's) |
| `bam` | `name`, `path` when it begins with a drive letter |
| `pca` | `name`, `path` when it begins with a drive letter |

None of them emits `sha256` or `signer`. In these three a program is a name or a path, and that is
all. The artifacts are built that way. Prefetch names its file after the executable and records no
digest, and ADR 0021 notes it has no path for the executable at all. BAM keys its values by path. PCA
writes a path and a time.

### What `allow` can compare

`is_allowed` in `crates/rongroi-core/src/engine.rs` reads only the `sha256` and `signer` fields of an
observation. `CONVENTIONS.md` §6 and `rules/AGENTS.md` forbid an `allow` entry that names a file,
because anyone can rename a file to an allowed name. Of the seven collectors, only `fivem_dir` emits
`sha256`. No collector emits `signer`. No rule in the bundle has an `allow` entry.

So a rule on `prefetch`, `bam` or `pca` that names a program has **no way to exclude a legitimate
program with the same name**. It also names the one thing the person it is about can change: rename
the executable, and these artifacts record the new name.

### What the gates do with such a rule

This was measured with two throwaway rules on 2026-09-13, removed afterwards. It is not asserted from
reading the gates.

| Probe rule (`status: experimental`, no fixtures) | `check-rules` | `check-baseline` |
|---|---|---|
| `collector: pca`, `path\|contains: '\Downloads\'` | passes | **fails**: found on `baseline-elevated-win11`, matching `game.exe` under a Downloads folder, and no `known-fps.csv` row accepts it |
| `collector: prefetch`, `name: NOTAREALCHEAT.EXE` | passes | **passes**: the baseline's `CMD.EXE` record carries `name` and is one condition away, so the rule is confronted (ADR 0033) and quiet |

The baseline was built to catch the first shape. Its `host.yaml` holds "a game executable run out of
a Downloads folder" on purpose. It cannot catch the second shape, and nothing should: a rule naming
one program is quiet on an ordinary machine, which is correct. What makes that rule wrong is not
something a fixture can show. The rule cannot be allowed, and renaming a file defeats it. **The rule
most people would write passes every gate in this repository.**

### Where these observations go today

No rule matches them, so they are **unmatched observations** (ADR 0014). Self mode lists them. SS
mode shows only how many there were. On one real Windows 11 machine, scanned elevated (ADR 0033),
that was 627 Prefetch observations, 83 from BAM and 3 from PCA. They are a record of what ran
recently, for the person who opens Self mode. A reviewer watching an SS-mode screenshare sees three
numbers.

## Decision

### 1. No rule on `prefetch`, `bam` or `pca` identifies a program by `name` or `path`

That means no `name:` match, and no `path` match with any operator, that picks out a program. The
reasons are the Context above: the rule cannot exclude legitimate software, and a rename defeats it.
A rule of this kind would also move these observations into SS mode as `found` rows. ADR 0020 and
ADR 0021 said that choice reopens the privacy question they settled by having no rule.

**No gate enforces this.** The measurement above shows `check-rules` and `check-baseline` accept the
narrow form. Until a gate exists, review enforces it, and `CONVENTIONS.md` §6 says so in its
"Enforced by" column instead of implying a check that does not run.

### 2. These three collectors are for the reader of Self mode, by design

They are not waiting for rules. They show a person what Windows recorded about recent programs,
which ADR 0014 built unmatched observations to do. This ADR changes nothing about SS mode. SS mode
still counts them and does not list them, because that is what its consent screen promises.

### 3. M2 is complete as scoped

M2 shipped four collectors and two log-clearing rules in 0.2.0. README's milestone table says that,
and names this ADR as the reason no Prefetch, BAM or PCA rule is planned. It does not call them
unfinished work.

### What would reopen this

Each of these needs its own ADR. None of them undoes decision 1 for rules of the kind it forbids.

- **An observation that carries identity.** A collector reads the file at a recorded path, if it is
  still there, and emits its `sha256`, plus Authenticode `signer` once signer checking exists (the
  precondition ADR 0009 already set for a `fivem_dir` rule). Then `allow` has something to compare,
  and a rule about a program can exclude legitimate ones.
- **A fact that does not depend on a name.** An example is a program these artifacts say ran whose
  file is no longer at its path. ADR 0028 explains why the engine has no join across observations.
  A fact like this is computed in the collector, in Rust, where a test can contradict it, the same way
  ADR 0028 computes facts about a log.

## What was rejected

**Writing the name rules and accepting their matches in `rules/known-fps.csv`.** A `known-fps.csv`
row accepts a match on a *baseline*. It does nothing on a player's machine, where the legitimate
program with that name really is.

**Letting `allow` compare `name` for these three collectors.** An allow entry keyed on a name is an
instruction for how to avoid the rule: rename the file to the allowed name. `CONVENTIONS.md` forbids
it for that reason, and the reason does not depend on the collector.

**Listing unmatched Prefetch, BAM and PCA observations in SS mode**, so that staff get the execution
history. That breaks the consent screen's promise, "only what matches a rule", which ADR 0014 decided
deliberately. It is not this ADR's to change.

**Adding the `check-rules` gate in this change.** Refusing a `name` or `path` match on these three
collectors is a small check. It is a code change, and this is a documentation change. Until the gate
exists, the rule rests on review.

## What this does not fix

- **A reviewer watching SS mode gets nothing from these three but a count.** The execution history
  that the commercial PC-check tools in `docs/research/03-pc-check-screenshare-tools.md` read reaches a
  person only in Self mode. This ADR
  records that. It does not change it.
- **Only review enforces decision 1.** A rule of the forbidden kind passes every gate today, as the
  measurement shows.
- **The M3 driver list and a `fivem_dir` rule are still blocked** on the same missing thing: nothing
  emits `signer`.
- **The two log-clearing rules are still unconfronted** (`rules/unconfronted.csv`, ADR 0033). "M2 is
  complete as scoped" says what shipped. It does not say those rules have been measured against a
  baseline.

## Consequences

- `README.md` and `README.th.md` list M1 and M2 as released in 0.2.0, and say why no Prefetch, BAM or
  PCA rule is planned.
- `CONVENTIONS.md` §6, `rules/AGENTS.md` and `docs/rules-authoring.md` state decision 1. It is
  enforced by review.
- No code, rule, fixture or schema changes. `RULES_SCHEMA_VERSION` and `REPORT_SCHEMA_VERSION` are
  untouched.
