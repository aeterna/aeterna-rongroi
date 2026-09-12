# AGENTS.md — rules

Adds to the root [`AGENTS.md`](../AGENTS.md); read that first. Authoring guide:
[`docs/rules-authoring.md`](../docs/rules-authoring.md).

- A rule describes **evidence to show**, never a verdict. No scores, no "clean" rules.
- `falsepositives` must honestly list what legitimately produces the evidence.
- `allow` identifies legitimate software by `sha256` or `signer` only — never by file name.
- **`match` compares strings without regard to ASCII case.** `path: "C:\\Windows\\Temp\\x.exe"` matches
  `C:\WINDOWS\Temp\X.EXE`, because Windows does not care which case a path was written in and a rule that
  missed one would report `not_found` — a thing looked for and not there. Non-ASCII letters are **not**
  folded: `Sömchai` does not match `SÖMCHAI`. Numbers, booleans and null are compared exactly, so
  `event_id: 1102` never matches the text `"1102"` (ADR 0025).
- To compare one field byte for byte, list its name in `cased`. It is per field, so the rest of `match`
  keeps folding, and every field left out of it folds. A rule with no `cased` line is case-insensitive —
  write one only when the field's own vocabulary distinguishes case, and say in a `#` comment why. A
  `cased` entry naming a field `match` does not have fails `cargo xtask check-rules`.
- `collector` must be a collector in this build and every `match` field name one that collector
  declares it can emit (`Collector::fields`, ADR 0026). A misspelling is not a quiet mistake: the rule
  becomes `not_found` on every machine, which this program shows a player as evidence that something
  was looked for and was not there. `check-rules` rejects it and names the field it meant.
- `status: test` or `stable` needs a positive and a negative fixture in `tests/`.
- A new rule must also be quiet on every `fixtures/hosts/baseline-*` host, or carry a
  `known-fps.csv` row with a reason (`cargo xtask check-baseline`, ADR 0017).
- Fixtures are synthetic observations. Never commit cheat binaries, loaders or real player data.
- **Out of scope:** rules, comments or fixtures that explain how to avoid a rule, and weakening a rule
  without a documented false-positive reason. Bypasses are reported privately via
  [`SECURITY.md`](../SECURITY.md).
- Rules, translations and fixtures in this folder are CC-BY-SA-4.0.
