# AGENTS.md — rules

Adds to the root [`AGENTS.md`](../AGENTS.md); read that first. Authoring guide:
[`docs/rules-authoring.md`](../docs/rules-authoring.md).

- A rule describes **evidence to show**, never a verdict. No scores, no "clean" rules.
- `falsepositives` must honestly list what legitimately produces the evidence.
- `allow` identifies legitimate software by `sha256` or `signer` only — never by file name.
- `status: test` or `stable` needs a positive and a negative fixture in `tests/`.
- Fixtures are synthetic observations. Never commit cheat binaries, loaders or real player data.
- **Out of scope:** rules, comments or fixtures that explain how to avoid a rule, and weakening a rule
  without a documented false-positive reason. Bypasses are reported privately via
  [`SECURITY.md`](../SECURITY.md).
- Rules, translations and fixtures in this folder are CC-BY-SA-4.0.
