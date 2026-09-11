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
| `description` | yes | what it means, why it matters, and what it does **not** prove |
| `status` | yes | `experimental` · `test` · `stable` · `deprecated` |
| `collector` | yes | must equal the first folder name |
| `strength` | yes | `execution` · `presence` · `tamper` · `posture` · `context` |
| `match` | yes | map of observation field → value; **all** must be equal to match |
| `allow` | no | legitimate software excluded by `sha256` or `signer` — never by file name |
| `retention` | yes | how far back the source can see, in words for the user |
| `unmeasured_when` | no | reason codes you expect on some machines |
| `falsepositives` | yes | what legitimately produces this evidence; never empty |
| `references`, `tags`, `related`, `modified` | no | |
| `author`, `date` | yes | `date` is `YYYY-MM-DD` |

Unknown fields are errors. Use `#` comments for notes.

## How matching works

- The engine takes the run of the rule's `collector`.
- If the collector could not look, the rule is `unmeasured` with the collector's reason.
- Otherwise every observation whose fields equal all `match` entries is attached as `found` (minus `allow`ed
  software).
- If nothing matched but a field in `match` is listed in the run's `gaps`, the rule is `unmeasured` — never
  `not_found`.
- Otherwise the rule is `not_found`, and the report shows its `retention`.

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

Add the rule's text to `rules/i18n/<lang>.yaml`, keyed by id. Any field you leave out is shown in English.

```yaml
7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7:
  title: Secure Boot ถูกปิดอยู่
```

## Check

```bash
cargo xtask check-rules
cargo nextest run -p rongroi-core   # the embedded bundle must parse
```

## Please do not

- Describe how to avoid a rule, in the rule, a comment, a fixture or the PR. Bypasses go to SECURITY.md.
- Weaken or delete a rule without a false-positive reason in the PR.
- Add scores, "clean" rules or anything that reads as a verdict.
