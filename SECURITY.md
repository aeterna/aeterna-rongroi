# Security policy

## Reporting

Use GitHub **private vulnerability reporting**: the "Report a vulnerability" button under the repository's
Security tab. Do not open a public issue.

Please report privately:

- **Detection bypasses** — a way for a cheat to avoid a rule or collector, or to make the tool show a
  misleading result
- Vulnerabilities in the tool itself (for example, a crafted artifact that crashes a parser or makes the
  tool write to disk)
- Any network access or data leaving the machine through our code

Include the version, the executable hash, and the smallest steps that reproduce the problem.
Please do not publish details until a fixed release is available.

## What happens next

A maintainer acknowledges the report, reproduces it and fixes it in a new release. Rules are embedded in
the executable, so a fixed detection always ships as a new release. Credit is given in the release notes
unless you ask otherwise.

## Scope notes

- The tool runs offline on the player's own PC. It cannot prove that a machine is clean, and a tampered
  operating system can fake what is shown on screen. Reports that restate this known limit are not
  vulnerabilities.
- Hardware (DMA) cheats and capture-proof overlays are outside what a user-mode tool can see.

## Supported versions

Only the latest release is supported during pre-alpha.
