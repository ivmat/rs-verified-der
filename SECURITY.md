# Security policy

`der-verified` parses DER/X.690 — an attacker-controlled input format on the certificate/PKI attack
surface. Parser-differential and malformed-input bugs here are security-relevant, so they are handled
as security issues even though this crate performs no cryptography itself.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately to **ivomatijasevic@gmail.com** with:

- a description of the issue and its impact (e.g. a non-canonical encoding accepted, a panic on
  crafted input, a claimed property that does not hold);
- a minimal reproducer — ideally a byte sequence plus the entry point (`decode_*` / `parse_*` /
  `validate_*`) and the observed vs. expected behaviour;
- if the bug contradicts a proof or the `PROOF_MANIFEST.md`, say which claim.

**Response window:** you will receive an acknowledgement within **7 days**, and an initial assessment
(accepted / needs-info / not-a-vuln) within **30 days**. If a fix is warranted, a coordinated
disclosure timeline will be agreed with the reporter.

You are welcome to encrypt sensitive reports; ask in your first email and a key will be provided.

## Scope

In scope: memory-safety, panic-on-input, and correctness/parser-differential defects in the published
`der-verified` crate (a decoder accepting an encoding it should reject, or rejecting a canonical one;
a proof or manifest claim that does not hold).

Out of scope: the deliberate profile narrowings documented in `DECISIONS.md` and `PROOF_MANIFEST.md`
(e.g. leap-second rejection, range caps, primitive-form-only rules) — these are intended behaviour,
not defects. If you believe a documented narrowing is itself exploitable in a way the docs miss, that
*is* in scope; explain the gap.

## A note on the proofs

The verification claims are bounded and assumption-scoped exactly as `PROOF_MANIFEST.md` states. A
report showing that a proof's stated bounds or assumptions are unsound, or that a harness proves less
than it appears to, is especially valuable and welcome.
