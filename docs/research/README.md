# Research notes

Background research gathered on **2026-09-11** before the project started. It explains why the design looks
the way it does. It is a snapshot: products, prices and policies change, so re-check anything before relying
on it.

Conventions used in these notes:

- Claims made by a vendor about their own product are marked **(vendor claim)**.
- "Not found" means the research looked and found nothing — not that the thing does not exist.
- Links to cheat sellers, leaked source code, spoofers and bypass tutorials are deliberately left out.
  Where they mattered, the notes describe what was seen without linking to it.

| Note | Question it answers |
|---|---|
| [01 — FiveM anti-cheat landscape](01-fivem-anticheat-landscape.md) | What exists for FiveM today, and what does each kind of product actually see? |
| [02 — Machine-level anti-cheat techniques](02-machine-level-anticheat-techniques.md) | What can software on the player's PC detect, at what cost, and with what privacy duties? |
| [03 — PC-check / screenshare tools](03-pc-check-screenshare-tools.md) | How do staff check PCs today, which Windows artifacts matter, and what are the limits? |
| [04 — Open-source detection-rule projects](04-oss-detection-rule-projects.md) | How do large projects structure rules, IDs, validation and contribution? |
| [05 — Rust and Tauri repository practices](05-oss-rust-tauri-repo-practices.md) | How do large Rust/Tauri projects organise crates, quality gates, releases and signing? |
| [06 — Testing Windows forensic code](06-testing-windows-forensic-code.md) | How do real projects test Windows-only parsers and collectors, and which fixtures can we use? |
