## Summary

<!-- What changes and why. Link the issue if there is one. -->

## Test plan

<!-- Commands you ran and what you checked. For rules: which fixtures. For collectors: which Windows build. -->

## Checklist

- [ ] PR title is a Conventional Commit (`feat(collectors): …`, `rules(posture): …`, `i18n(th): …`)
- [ ] `cargo fmt`, `cargo clippy`, `cargo nextest run` and the relevant `cargo xtask check-*` pass
- [ ] New or changed rules have a positive and a negative fixture
- [ ] Tested on real Windows (say which build), or not applicable
- [ ] **Adds network access?** No — this project has no network code (ADR 0003)
- [ ] **Writes to the scanned machine?** No — collectors are read-only
- [ ] **Weakens or removes a detection?** No / Yes — the false-positive reason is: <!-- explain -->
- [ ] Contains no bypass details (those go to a private security report, see SECURITY.md)
