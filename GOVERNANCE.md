# Governance

## Maintainers

| Role | Who |
|---|---|
| Lead maintainer | [@tanakon8529](https://github.com/tanakon8529) |
| Rule reviewer | **open** |
| Thai-language reviewer | **open** |
| Release approver (second person) | **open** |

## How decisions are made

- Day-to-day changes: pull request, green CI, merged by a maintainer.
- Changes to the architecture, the rule format, the license terms or the purpose boundary in
  [AGENTS.md](AGENTS.md): an ADR in `docs/adr/`, open for comment before merge.

## Releases

Releases are built only by the GitHub release workflow; that workflow is the only place the official-build
marker is set. While there is a single maintainer, releases are not code-signed. Code signing through the
SignPath Foundation requires separate author, reviewer and approver roles, so it will be requested once a
second maintainer can act as release approver.

## Becoming a maintainer

Sustained, good-quality contributions in an area (rules, a language, a collector) lead to an invitation for
that role.
