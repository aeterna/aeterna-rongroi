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
| `match` | yes | map of observation field → value; **all** must be equal to match. Strings compare without regard to ASCII case (ADR 0025). Every field name must be one the collector declares it can emit — `check-rules` rejects the rest and names the one it meant (ADR 0026) |
| `cased` | no | fields of `match` compared byte for byte instead; everything left out folds case |
| `allow` | no | legitimate software excluded by `sha256` or `signer` — never by file name |
| `retention` | yes | how far back the source can see, in words for the user |
| `unmeasured_when` | no | reason codes you expect on some machines. A reason named here is **counted** in SS mode; one that is not is **listed**, because it means something you did not anticipate stopped the measurement (ADR 0027). Every entry must be a reason the collector can report — `check-rules` rejects the rest |
| `falsepositives` | yes | what legitimately produces this evidence; never empty. Shown to the reader beside every `found` row (ADR 0027), so write it for them |
| `references`, `tags`, `related`, `modified` | no | |
| `author`, `date` | yes | `date` is `YYYY-MM-DD` |

Unknown fields are errors. Use `#` comments for notes.

## How matching works

- The engine takes the run of the rule's `collector`.
- If the collector could not look, the rule is `unmeasured` with the collector's reason.
- Otherwise every observation whose fields equal all `match` entries is attached as `found` (minus `allow`ed
  software).
- **Strings compare without regard to ASCII case** (ADR 0025): `path: "C:\\Windows\\Temp\\x.exe"` matches
  `C:\WINDOWS\Temp\X.EXE`, because Windows does not care which case a path was written in. Non-ASCII letters
  are not folded — `Sömchai` does not match `SÖMCHAI`. Numbers, booleans and null are compared exactly and
  are never coerced: `event_id: 1102` does not match the text `"1102"`, nor `1102.0`.
- To compare one field byte for byte, name it in `cased`. It is per field, so the rest of `match` keeps
  folding; a rule with no `cased` line is case-insensitive throughout. Naming a field `match` does not have
  is an error, so a typo there cannot pass as an exact comparison that never happened.
- If nothing matched but a field in `match` is listed in the run's `gaps`, the rule is `unmeasured` — never
  `not_found`. `cased` does not change that: `gaps` is keyed on the field names in `match`, not on values.
- Otherwise the rule is `not_found`, and the report shows its `retention`.

## What the reader sees

Every row carries the rule's `title` and its `description`, in the reader's language. A `found` row
also carries `falsepositives` — a finding shown without what else produces it is a finding shown as an
accusation (NIST SP 800-86 section 3.4). A `not_found` row does not: nothing was found, so there is
nothing to explain.

An `unmeasured` row says whether its reason was one this rule named in `unmeasured_when`. SS mode lists
only the ones no rule expected and counts the rest, so `unmeasured_when` is the difference between a
line a reviewer should ask about and a number they can move past. `not_admin` is never a row at all: it
is one fact about the scan, said once above the evidence, with the remedy (ADR 0027).

No rule ships with `cased` today. It looks like this, and needs a `#` comment saying why the field's own
vocabulary distinguishes case:

```yaml
match:
  path: "C:\\Windows\\Temp\\x.exe"    # matches C:\WINDOWS\TEMP\X.EXE
  some_field: Exact Value
cased: [some_field]
```

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

## Check

```bash
cargo xtask check-rules
cargo xtask check-baseline          # the rule must also be quiet on an ordinary machine
cargo nextest run -p rongroi-core   # the embedded bundle must parse
```

## Please do not

- Describe how to avoid a rule, in the rule, a comment, a fixture or the PR. Bypasses go to SECURITY.md.
- Weaken or delete a rule without a false-positive reason in the PR.
- Add scores, "clean" rules or anything that reads as a verdict.
