# Writing rules

A rule tells the engine which observations are worth showing and what they can show. It never decides that
someone cheated.

## Start

```bash
cargo xtask new-rule <collector> <category>/<slug>
# e.g. cargo xtask new-rule posture boot/secure-boot-disabled
```

This creates `rules/<collector>/<category>/<slug>/` with `rule.yaml`, a positive and a negative fixture, and
a fresh UUID. The placeholders fail `cargo xtask check-rules` until you fill them in.

## Fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | lowercase UUIDv4, never reused — not even after the rule is deleted |
| `title` | yes | short, English |
| `description` | yes | what it means, why it matters, and what it does **not** prove. Shown to the reader beside every row, whatever the state (ADR 0027) |
| `status` | yes | `experimental` · `test` · `stable` · `deprecated` |
| `collector` | yes | must equal the first folder name, and must be a collector in this build |
| `strength` | yes | `execution` · `presence` · `tamper` · `posture` · `context` |
| `match` | yes | map of `field` — or `field\|operator` — → value; **all** of them must hold to match. Strings compare without regard to ASCII case (ADR 0025). Every field name must be one the collector declares it can emit, and every operator one its kind can take — `check-rules` rejects the rest and names the one it meant (ADR 0026, ADR 0029). The whole vocabulary is in [How matching works](#how-matching-works) |
| `cased` | no | **field** names compared byte for byte instead; everything left out folds case. One entry covers every comparison the rule makes against that field |
| `allow` | no | legitimate software excluded by `sha256` (the file) or `signer_cert_sha256` (the certificate that signed it) — exactly one per entry, never a file's or a signer's name: certificates stolen from a real publisher carry its name (ADR 0035). Revocation is not checked, so an allowed certificate that is later stolen and revoked stays allowed until the entry is removed. `prefetch`, `bam` and `pca` emit neither, so a rule on them has nothing to allow by, and no rule on them names a program by `name` or `path` (ADR 0034). No gate refuses that rule; review does |
| `retention` | yes | how far back the source can see, in words for the user |
| `unmeasured_when` | no | reason codes you expect on some machines. A reason named here is **counted** in SS mode; one that is not is **listed**, because it means something you did not anticipate stopped the measurement (ADR 0027). Every entry must be a reason the collector can report — `check-rules` rejects the rest and names what it does report. `partial`, `budget_spent` and `read_failed` may not be named at all: a view lists them whatever you declare, so `check-rules` refuses the line (ADR 0030, ADR 0032) |
| `falsepositives` | yes | what legitimately produces this evidence; never empty. Shown to the reader beside every `found` row (ADR 0027), so write it for them |
| `references`, `tags`, `related`, `modified` | no | |
| `author`, `date` | yes | `date` is `YYYY-MM-DD` |

Unknown fields are errors. Use `#` comments for notes.

## How matching works

- The engine takes the run of the rule's `collector`.
- If the collector could not look, the rule is `unmeasured` with the collector's reason.
- Otherwise every observation that satisfies **all** `match` entries is attached as `found` (minus `allow`ed
  software). `match` is a conjunction; there is no `or` between entries, no grouping and no negation.
- If nothing matched but a field in `match` is listed in the run's `gaps`, the rule is `unmeasured` — never
  `not_found`. That is true of **every** operator; the table below says so one by one, and `exists: false`
  is checked against `gaps` before anything is matched at all (ADR 0029).
- A collector that reads several places may report a gap for **one place** only, keyed by its
  discriminator (`fivem_dir`: `location`). Such a gap makes the rule `unmeasured` only if the rule could
  match an observation from that place — every condition the rule puts on `location` holds for that
  place's value, which is true of a rule that puts none. An observation from that place never satisfies
  `exists: false` for a field the place could not read (ADR 0044).
- Otherwise the rule is `not_found`, and the report shows its `retention`.

### The operators

A key is a field name, or a field name, `|`, and one operator. A key with no `|` compares for equality,
which is what every rule written before ADR 0029 says and still means.

```yaml
match:
  event_id: 104                          # equality
  channel: [Security, System]            # a list means OR — any one of them
  run_count|gte: 2                       # gt · gte · lt · lte
  last_run|gt: "2026-01-01T00:00:00Z"    # ordered as instants, not as text
  path|startswith: 'C:\Users\'           # startswith · endswith · contains
  path|exists: true                      # exists: true or false
```

| Operator | Takes | Works on a field the collector emits as |
|---|---|---|
| none (equality) | one value, or a list meaning **or** | anything |
| `gt` `gte` `lt` `lte` | one number, or one RFC 3339 timestamp | a number or a timestamp |
| `startswith` `endswith` `contains` | one string, or a list meaning **or** | text |
| `exists` | `true` or `false` | anything |

- **Strings compare without regard to ASCII case** (ADR 0025), and that reaches every text operator:
  `path: "C:\\Windows\\Temp\\x.exe"` matches `C:\WINDOWS\Temp\X.EXE`, and so does
  `path|startswith: 'C:\Windows\'`. Non-ASCII letters are not folded — `Sömchai` does not match `SÖMCHAI`.
  Numbers, booleans and null are compared exactly and are never coerced: `event_id: 1102` does not match
  the text `"1102"`, nor `1102.0`.
- To compare one field byte for byte, name it in `cased`. It names a **field**, so one entry covers every
  comparison the rule makes against it, and the rest of `match` keeps folding. Naming a field `match` does
  not have — or one it uses only where no text is compared, such as `run_count|gte: 2` — is an error, so a
  `cased` line that does nothing cannot pass as an exact comparison that never happened.
- **Timestamps are parsed, not compared as text.** The collectors write them with `jiff`, which prints a
  fraction of a second only when there is one, so `2020-01-01T00:00:00.5Z` and `2020-01-01T00:00:00Z` are
  different shapes and comparing them as text puts the later instant first. Write an RFC 3339 value; an
  offset such as `2026-09-13T07:00:00+07:00` is fine.
- **`startswith` and `contains` are text, not paths.** Neither knows what `\` is, so
  `path|startswith: 'C:\Users\Public'` also matches `C:\Users\PublicRecords\x.exe`, and
  `path|contains: 'Temp'` matches `C:\Program Files\TempleOS\game.exe`. **Put the separators in the
  value** — `'C:\Users\'`, `'\AppData\Local\Temp\'`, `'.exe'` — and check by eye that the rule's `title`
  describes what you actually wrote.
- **`exists` is not equality.** It asks whether the field is in the observation at all, which is how a
  withheld path (`path_withheld` present), an absent one (`path` missing) and an unreadable one (`path` in
  `gaps`) are told apart. `null` is its own type and equality cannot stand in for any of the three.

### What a gap does, operator by operator

A field in the run's `gaps` means the collector could not read it. **Every operator answers `unmeasured`**,
never "no match" — ADR 0002 is what that protects, and ADR 0029 has the table in full.

| Operator | Field is in `gaps` |
|---|---|
| equality, and a value list | `unmeasured` |
| `gt` `gte` `lt` `lte` | `unmeasured` |
| `startswith` `endswith` `contains` | `unmeasured` |
| `exists: true` | `unmeasured` |
| `exists: false` | `unmeasured` — checked **before** matching, because a field nobody could read is also a field that is not there, and without that order the rule would be `found` and the report would say "we looked and it is not there" |

## What the reader sees

Every row carries the rule's `title` and its `description`, in the reader's language. A `found` row
also carries `falsepositives` — a finding shown without what else produces it is a finding shown as an
accusation (NIST SP 800-86 section 3.4). A `not_found` row does not: nothing was found, so there is
nothing to explain.

An `unmeasured` row says whether its reason was one this rule named in `unmeasured_when`. SS mode lists
the ones no rule expected and counts the rest, so `unmeasured_when` is the difference between a line a
reviewer should ask about and a number they can move past. There are exceptions in each direction
(ADR 0030, ADR 0032): `not_admin` and `not_attempted` are never a row at all — each is one fact about
the scan, said once above the evidence — and `partial`, `budget_spent` and `read_failed` are always a
row, declared or not, because each says the artifact was reachable and the read of it did not finish.
Naming one of those three in `unmeasured_when` is a `check-rules` failure: the line would decide
nothing, and a line that looks load-bearing and is not is worse than none.

The twelve reasons, and what each says to the reader, are in `docs/architecture.md`; ADR 0030 adds the
ordinary condition that produces each and how common it is. The two that most often need declaring:
`source_absent` ("this PC has no such record to read") and `source_empty` ("the place this is kept is
there and holds nothing"). They mean opposite things — write the one you mean.

No rule ships with `cased` today. The `fivem_dir` rules are the first to use a value list and an
operator, `exists` (ADR 0036). `cased` looks like this, and needs a `#`
comment saying why the field's own vocabulary distinguishes case:

```yaml
match:
  path: "C:\\Windows\\Temp\\x.exe"    # matches C:\WINDOWS\TEMP\X.EXE
  some_field: Exact Value
cased: [some_field]
```

## When a collector omits a field for one item

Some collectors report a failure on **one** item by leaving a field out of that item's observation,
not by a gap: `fivem_dir` omits `signature` for a file whose check failed, and `sha256` for one it could
not hash (ADR 0009). A gap covers the whole run, or since ADR 0044 one whole place, so a gap there would silence every rule on that
collector because of one file. The consequence for a rule author is that such an item satisfies **no**
equality on the omitted field, and a rule that lists every value the field can take still falls to
`not_found` for it. Nothing in the engine can tell you this happened.

The pattern ADR 0036 uses:

- **Partition the values.** Write one rule per group of values a reader should tell apart, and put
  every value the field can take in some rule. `match` has no negation, so "anything but `valid`" is the
  list of the other values.
- **Give the missing field its own rule**, with `<field>|exists: false` beside a condition only the
  items can meet (for `fivem_dir`, `path|exists: true`, which a folder observation does not carry). The
  engine checks gaps before an absence condition, so a run that could not read at all makes that rule
  `unmeasured`, not `found` (ADR 0029).
- **Say so in `description`** of every rule in the group: an item whose field is missing is shown under
  the other rule, and this row's `not_found` speaks only for the items that carried the field.

## An `allow` entry is a measurement

An `allow` entry names a file or a certificate by digest, and it is only as good as where the digest came
from. Add one only when it was measured from a file its publisher released, and say in a `#` comment when
and how — never from memory, a forum post or another tool's list. A certificate entry goes stale when the
publisher renews: the rule's `falsepositives` has to say what a reviewer sees then and what they should
do, and the entry for the new certificate is added **beside** the old one, which still signs the files
people have not updated (ADR 0036).

A certificate entry also takes a row in `rules/certificate-pins.csv`, measured with it: the rule's id, the
certificate's SHA-256, its subject, `not_before`, `not_after` and the date you read them. `check-rules`
fails on an entry without a row and on a row without an entry, and reads no clock. The monthly
`certificate-pins` workflow runs `cargo xtask check-pin-expiry`, which fails once a rule's newest pinned
certificate is within 90 days of `not_after`; `--today YYYY-MM-DD` shows what it will say on another day.

## Fixtures

`tests/positive/*.json` must make the rule `found`; `tests/negative/*.json` must make it `not_found`.
They are synthetic observations — never real player data, never cheat binaries.

```json
{
  "description": "Windows reports Secure Boot off",
  "observations": [
    { "collector": "posture", "fields": { "secure_boot": "disabled" } }
  ],
  "expect_matches": 1
}
```

Optional: `gaps` (field → reason) and `expect_matches`. `status: test` and `stable` require at least one of
each kind.

## Translations

Add the rule's text to `rules/i18n/<lang>.yaml`, keyed by id. Translatable fields: `title`, `description`,
`falsepositives` and `retention`. Any field you leave out is shown in English; an empty field is an error.
Report JSON always keeps the English `retention`, so a report reads the same whatever language produced it —
translations are applied only when the report is displayed.

```yaml
7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7:
  title: Secure Boot ถูกปิดอยู่
  retention: เป็นค่าที่ตั้งไว้ตอนนี้เท่านั้น บอกไม่ได้ว่าในอดีตเครื่องนี้เคยตั้งค่าไว้อย่างไร
```

## The baseline gate asks two questions

`cargo xtask check-baseline` runs the whole rule set against every `fixtures/hosts/baseline-*` host —
machines this project asserts are unremarkable. It asks:

1. **Is your rule quiet there?** A `found` needs a `rules/known-fps.csv` row with a reason, and a row
   whose rule no longer matches fails too.
2. **Was your rule ever asked anything?** A rule is *confronted* when some baseline observation carries
   every field your `match` names and comes within **one** unsatisfied condition of firing it — the
   baseline was put the rule's question and answered no. A rule nothing confronts is quiet for a reason
   that says nothing about it, and would stay quiet however it was written (ADR 0033). **The one
   condition may not be the collector's discriminator** (`fivem_dir`: `location`): an observation that
   differs from your rule only in the place it is about was asked about another place, and a misspelt
   `location:` would stay "confronted" by it (ADR 0033 as amended, ADR 0044).

The second is the one that will surprise you. If your rule reads values no baseline holds — a channel,
a folder, a registry key that no fixture describes — the gate fails and the fix is a baseline that holds
the shape your rule reads. If no such fixture can be added, `rules/unconfronted.csv` takes a row naming
your rule, **why** nothing confronts it, and **what would end the row**; the gate fails again once a
baseline does confront it, so the fixture that closes the hole also deletes the note.

**A row is not a pass.** It records that this gate is measuring nothing about your rule, which is a
worse position than a rule that fails. Say so in the pull request.

Fixtures are bound by their own rules — read `fixtures/hosts/PROVENANCE.md` before adding one, and
`fixtures/evtx/PROVENANCE.md` before adding any Event Log sample.

## The reference page

[`docs/rules-reference.md`](rules-reference.md) and [`docs/rules-reference.th.md`](rules-reference.th.md)
describe every rule in the bundle for a reader who will not open YAML: its title, what `match` asks in
words (operators and case included), its `retention`, `unmeasured_when`, `falsepositives`, `allow` and
references, grouped by collector and category. They are **generated** from the same bundle the program
embeds, the Thai one from `rules/i18n/th.yaml`, and the words for a strength or a reason from the desktop
app's `report.json`.

After changing a rule, a rule translation or one of those words, run:

```bash
cargo xtask rules-reference          # rewrites both pages; commit them with the rule
```

CI runs `cargo xtask rules-reference --check`, which fails on a page that does not match and names that
command. Two pull requests that both change rules each regenerate the pages; whichever merges second
reruns the command after rebasing instead of resolving the conflict by hand. Never edit the pages
themselves: the page renders rule text, so what it says is fixed in the rule.

## Check

```bash
cargo xtask check-rules
cargo xtask check-baseline          # quiet on an ordinary machine, and confronted by one
cargo xtask rules-reference --check # the reference pages match the rules
cargo nextest run -p rongroi-core   # the embedded bundle must parse
```

## Please do not

- Describe how to avoid a rule, in the rule, a comment, a fixture or the PR. Bypasses go to SECURITY.md.
- Weaken or delete a rule without a false-positive reason in the PR.
- Add scores, "clean" rules or anything that reads as a verdict.
