# ADR 0005 — YAML parser: serde-saphyr

- Status: accepted
- Date: 2026-09-11

## Context

Rules and fixture hosts are YAML, the format used by Sigma, Hayabusa, Velociraptor and LOLDrivers, so rule
authors already know it. `serde_yaml` is deprecated (`0.9.34+deprecated`).

Candidates checked on crates.io on 2026-09-11:

| Crate | Latest | Last update | License |
|---|---|---|---|
| `serde-saphyr` | 1.2.0 | 2026-08-30 | MIT OR Apache-2.0 |
| `saphyr` | 0.0.12 | 2026-08-18 | MIT OR Apache-2.0 |
| `serde_yaml_ng` | 0.10.0 | 2024-05-26 | MIT |
| `serde_norway` | 0.9.42 | 2024-12-21 | MIT OR Apache-2.0 |

## Decision

Use `serde-saphyr`: a stable 1.x release with serde support, actively maintained, licence compatible with
GPL-3.0-or-later.

## Consequences

- All YAML goes through `serde_saphyr::from_str` with `deny_unknown_fields`, so typos in rule fields fail
  loudly instead of being ignored.
- Revisit if the crate stops being maintained; the parser is used in only three places.
