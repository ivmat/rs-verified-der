# The ten-minute replay

A bounded, laptop-sized companion to the full proof floor. Run it when you want to *watch* the
gates work — accept a real result, then reject a seeded fault and a tampered evidence record —
without provisioning the ~24 GB machine the full `./check.sh` Kani run needs.

## What this replays (and what it does not)

**It replays:** the crate's library unit tests (the doc-tests are left to `cargo test`), the
acceptance-manifest gate against the pinned vendored
validator, and exactly ONE Kani proof harness (`boolean::proofs::one_octet_is_canonical`, chosen
because BOOLEAN is the smallest module with a documented mutation control — see
`evidence/MUTATION-CONTROLS-2026-08-23-fivemodule.md`). Then it shows that same harness and that
same validator each REJECT a deliberately broken input: a one-line code mutation, and a
one-byte-flipped evidence record.

**It does not replay:** the full 203-harness Kani floor (`./check.sh`/`cargo kani -Z stubbing`,
which needs ~24 GB RAM — see the README's "Verify it yourself" §1), the L4/L5 Lean lids (unbounded
proofs over six codecs — README §2), or any claim about the X.509 layer or real-world certificate
correctness. One harness passing is evidence about one bounded property of one primitive codec,
not about the crate as a whole. For the actual scope of what is (and is not) proven, read
[`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) and [`ASSUMPTIONS.md`](ASSUMPTIONS.md) — this replay is a
demonstration of the *mechanism*, not a substitute for either.

## Prerequisites

- A stable Rust toolchain (`rust-toolchain.toml` pins the channel; `rustup` selects it
  automatically).
- Kani `0.67.0`, for the two Kani steps (S3/S4):
  ```sh
  cargo install --locked kani-verifier --version 0.67.0
  cargo kani setup
  ```
  If Kani is not installed, the script SKIPS those two steps loudly and exits non-zero — it never
  reports a pass it did not actually run.
- Python 3, stdlib only (no `pip install`).

## Run it

```sh
./replay.sh
```

The name is the budget, not the duration: on a warm laptop the whole script finishes in seconds
(the crate is small and dependency-free); a cold first build adds compile time.

## Expected output

Each step prints a `== step ==` header and ends with one line of the form
`RESULT: <step> ACCEPT|REJECT (expected <verdict>)`. On a clean checkout with Kani installed, all
five RESULT lines read, in order:

```
RESULT: S1 (cargo test) ACCEPT (expected ACCEPT)
RESULT: S2 (acceptance manifest, clean) ACCEPT (expected ACCEPT)
RESULT: S3 (kani, clean boolean) ACCEPT (expected ACCEPT)
RESULT: S4 (kani, mutated boolean) REJECT (expected REJECT)
RESULT: S5 (validator, tampered record) REJECT (expected REJECT)
```

followed by a summary table (step, expected, observed, wall time, peak RSS) and
`replay.sh: all six steps observed their expected verdict.`

## Negative controls

**S4 (seeded code fault).** In a throwaway `mktemp -d` copy of `der-verified/` — never a tracked
file — one line of `boolean.rs` is changed to also accept `0x01` as a canonical DER `TRUE` (the
BER-legal, DER-illegal encoding). Rerunning the same harness there must fail: the mutation is a
real defect, not a no-op, and `one_octet_is_canonical` is the harness documented to catch exactly
this class. If it did not fail, the script aborts loudly instead of reporting a pass — a control
that cannot fail is worthless.

**S5 (tampered evidence).** In a second throwaway copy, one byte is flipped inside a JSON evidence
record that `der-verified/acceptance.toml` cites. The manifest's `record_hash` no longer matches
the (now-changed) record content, so the strict vendored validator must refuse the manifest. Same
loud-abort rule if it does not.

## Boundary

This replays **one codec's one bounded property, plus the manifest check** — not the proof floor
(203 harnesses across 33 modules), not the L4/L5 Lean lids, and not X.509 or certificate-chain
correctness. It is a fast, honest demonstration that the gates are real gates: they accept a real
result and they reject a real fault. It is not a substitute for `./check.sh`, and it makes no claim
this document does not spell out. See `PROOF_MANIFEST.md` for the actual proof envelope and
`ASSUMPTIONS.md` for what all of it stands on.
