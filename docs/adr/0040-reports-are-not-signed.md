# ADR 0040 — Reports are not signed

- Status: accepted
- Date: 2026-09-13

## Context

### The request

Server staff who receive a report after a screenshare, or instead of one, can reasonably ask for a
"signed report": a file they could check later to learn that the real program produced it and that
nobody edited it since. Some PC-check tools offer that. They sign the report with a key embedded in their
executable, verify the signature with the same executable, offline, and describe the result as a report
that cannot be forged. This ADR records why this project does not do that, in terms of what this
repository already says about itself. No other product is examined here.

### What a report is in this program

- It is produced on the player's own PC by a program the player starts. The README describes that
  program as "A user-mode program that only **reads** local artifacts", and ADR 0002 starts from "The
  player controls the machine and the screen".
- Its header carries provenance: whether the build is official, the version, the commit and the SHA-256
  of the running executable (`rongroi_core::provenance::Provenance`). The official flag and the commit are
  read back from the build marker embedded in the executable (ADR 0007); the hash is the program hashing
  its own file.
- The window version has no export. The CLI prints the view it was asked for, and `--json` redirected
  into a file is the only report file that exists (`docs/screenshare-guide.md` §9).

### Where a signing key would have to be

A signature is worth what its key is worth: a valid one says that something holding the key produced
these bytes, and nothing else.

1. **The source is public and anyone may build it.** The code is GPL-3.0-or-later (ADR 0006). A key
   written into the source is published with it.
2. **A key added only by the release workflow is still in the executable.** The program signs on the
   player's PC, so the key has to be there in a form the program can use, in every copy of every
   release, on the machine of the person whose report is being signed. That person owns the machine, and
   the program runs with that person's rights; nothing in this repository can keep a key in that
   executable from them. A key in a binary can be extracted from it, and after that anything can be
   signed with it.
3. **A verifier that is the same executable checks itself.** A copy of the program that was modified to
   sign anything can equally be modified to call anything valid, and ADR 0007 already records that a
   modified build can remove the one visible marker there is: "This is a visible marker, not a security
   boundary."
4. **An unextractable key would still sign what the program was told.** The README says, in its section
   on verifying a download: "An offline tool shown on the player's own screen cannot prove anything on its
   own: a modified operating system could fake what is displayed." The same holds for what is written to
   a file. An unmodified, official copy of this program running on a Windows that lies to it would sign
   the lie, and the signature on it would be valid. A signature covers the report's bytes; it cannot say
   that they reflect the machine.

### What this repository already proves, and about what

| Mechanism | What it establishes | What it does not |
|---|---|---|
| Official-build marker (ADR 0007) | A build that did not come from the release workflow and was not modified to hide it says **UNOFFICIAL BUILD** | Anything about a build modified to hide it |
| `SHA256SUMS` and the build-provenance attestation (ADR 0008) | Which executable files the release workflow built, checkable by anyone with `gh attestation verify` on their own copy | That the copy running on the player's PC is one of them, or anything about a report |
| `exe sha256` in the report header | The running program's statement about its own file | A proof of it: the screenshare guide says "A match shows the running file is consistent with the release. It cannot prove it: a modified program could print any value." |
| Code signing, planned once a second maintainer exists (GOVERNANCE.md) | Who published an executable | Anything about a report |

Every one of these is about where a **binary** came from. None is about whether a **report** reflects the
machine it describes, and a report signature would not be either: by points 2 to 4 it would establish at
most that a copy of the program, or anyone who had read the key out of one, produced the bytes.

### What the control is

The screenshare guide already describes the procedure that carries the weight: staff watch the player
download the file from the Releases page, compare its hash, start it, see the header, see the player
answer the consent question and see the rows appear (`docs/screenshare-guide.md` §2 to §5). It is subject
to the same README sentence — a Windows modified to lie can lie while someone watches — and the guide's
first table says so: the tool cannot show "Anything, if Windows on that PC was modified to lie to the
programs that run on it". What watching adds is that a person saw the session, which is what ADR 0002
asks for: evidence for a person to judge.

## Decision

1. **Reports are not signed.** No key, no signature field and no "verified", "authentic" or "unforgeable"
   state is added to the report, the CLI, the desktop app or the documentation.
2. **Nothing in this repository describes a report as tamper-proof.** A report file received after a
   session is text that anyone who held it could have changed, and the documentation says so where staff
   read it: a section in both screenshare guides and a sentence in PRIVACY.md.
3. **The provenance fields keep their present meaning.** `official`, `version`, `commit` and `exe_sha256`
   are what the running program says about itself, shown to make an unofficial build easy to notice
   (ADR 0007). They are not authentication and are not to be described as such.
4. **A request for signed reports is answered with this ADR**, not with a partial implementation.

### Rejected

- **An asymmetric key in the executable, verified by the executable.** Points 1 to 4 above.
- **A shared secret (a keyed hash) instead of a key pair.** The verifier needs the same secret, so it is
  in the executable twice over; points 1 to 4 apply unchanged.
- **Signing in the release workflow.** The workflow builds executables. Reports are produced on players'
  PCs, where the workflow's credentials are not and must not be.
- **A key per server, handed to that server's staff and loaded by the player's copy.** The player's copy
  still holds the key while it signs, on the player's PC; point 2 applies to each server's key instead of
  to one.

## What would reopen this

These are conditions under which the question is worth asking again. They are not a plan, nothing here has
been evaluated or measured, and whether any mechanism on the Windows PCs this program runs on meets them is
**not established** in this repository.

- **The key is not in the executable and cannot be used outside its purpose by the machine's owner** — for
  example a key generated and held inside security hardware on the PC rather than in software.
- **The verifier runs outside the scanned machine and does not trust it**: it checks the key against a
  root of trust the scanned machine does not supply, and checks that the signature is fresh against a
  challenge staff chose during the session, so an old report cannot be replayed.
- **What is signed says something about the software that produced the report**, and not only that the
  hardware exists — otherwise point 4 applies to it unchanged.
- **A new ADR reconciles it with ADR 0003 and with privacy.** A verifier that needs the network conflicts
  with ADR 0003; one that does not has to be distributed and trusted some other way. Hardware that can
  sign is also hardware that can identify a machine: this repository's own TPM rule says "A TPM is one of
  the stable pieces of hardware an identity can be tied to".

### Not decided here

Showing a short digest of the report on screen during the session, for staff to compare with a file sent
afterwards, is not signing. It would tie a file to what staff saw on screen and say nothing more than the
screen did. It is neither accepted nor rejected by this ADR and would need its own proposal.

## Consequences

- A report file is worth what the session it came from was worth. Staff who want more than that have to
  watch the scan run; this project offers no artifact that stands in for having watched.
- Servers that want to check players without a live session get nothing from this program that a
  signature would have appeared to give them. That is a real cost, and it is the honest one.
- There is no key to protect, rotate or revoke in the release process, and no verification screen whose
  "valid" could be read as a verdict (ADR 0002).
- A fork may add report signing and describe its reports as unforgeable. NOTICE section 7(c) requires such
  a fork to present itself as unofficial; nothing else in this repository can prevent the claim.
