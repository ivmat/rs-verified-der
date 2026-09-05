# The ten-minute replay

A bounded, laptop-sized companion to the full proof floor. Run it when you want to *watch* the
gates work — accept a real result, then reject a seeded fault and a tampered evidence record —
without provisioning the ~24 GB machine the full `./check.sh` Kani run needs. Add `--with-lean`
when the pinned Lean/Aeneas toolchain is installed and you also want to re-execute the six Lean
lids that the acceptance manifest records.

## What this replays (and what it does not)

**It replays:** the crate's library unit tests (the doc-tests are left to `cargo test`), the
acceptance-manifest gate against the pinned vendored
validator, and exactly ONE Kani proof harness (`boolean::proofs::one_octet_is_canonical`, chosen
because BOOLEAN is the smallest module with a documented mutation control — see
`evidence/MUTATION-CONTROLS-2026-08-23-fivemodule.md`). Then it shows that same harness and that
same validator each REJECT a deliberately broken input: a one-line code mutation, and a
one-byte-flipped evidence record.

**With `--with-lean`:** it additionally runs `lean/check_lean.sh` with `DER_REQUIRE_LEAN=1`. That
re-extracts the shipped Rust through Charon and Aeneas and checks all six L4/L5 lids. An absent or
wrong toolchain is a failure, never a skip. This re-executes the current Lean baseline; it does not
rerun every historical Lean mutation-control record that the acceptance manifest validates. L1 is
accept-only: it seeds no Lean-side fault. The reject side is the six recorded controls under
`evidence/lid-mutation-controls-2026-08-29/`; S2 hash-validates their public projections but does not
re-execute them. A green Lean run can refresh tracked `lean/lid-source-state.txt` when its recorded
source hashes changed. Lean build state stays under ignored `lean/.lake/`.

**It does not replay:** the full 203-harness Kani floor (`./check.sh`/`cargo kani -Z stubbing`,
which needs ~24 GB RAM — see the README's "Verify it yourself" §1), any claim about the X.509 layer,
or real-world certificate correctness. In the default mode it also does not execute Lean. One Kani
harness passing is evidence about one bounded property of one primitive codec, not about the crate
as a whole. For the actual scope of what is (and is not) proven, read
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
- For `--with-lean`: Elan plus the pinned Aeneas and Charon checkouts described in README §2.
  `VERIFIED_RS_TOOLS` points at the directory containing the `aeneas/` checkout, with Charon at
  `aeneas/charon/`. The option fails if they are absent, at the wrong pinned revisions, or have
  tracked local changes.

## Run it

```sh
./replay.sh               # default laptop replay; validates Lean records but does not run Lean
./replay.sh --with-lean   # also re-extracts and checks all six Lean lids; fail-closed
```

The name is the default-mode budget, not a promise for the optional Lean mode. The measured
`--with-lean` path uses a warm `lean/.lake/`, where Lake validates reusable build traces and cached
artifacts. A cold `lean/.lake/` is not a laptop-sized operation: Lake must re-fetch the pinned
packages over the network and rebuild the Mathlib subset that Aeneas imports from source. No script
here fetches Mathlib's prebuilt cache, and this document makes no duration claim for that cold path.

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

With `--with-lean`, one additional result appears before the summary:

```
RESULT: L1 (Lean lids) ACCEPT (expected ACCEPT)
```

The final line then confirms the six base steps plus the requested Lean replay.

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

The default mode replays **one codec's one bounded property, plus the manifest check**. The
`--with-lean` mode adds the six current L4/L5 Lean lids. Neither mode runs the full proof floor
(203 Kani harnesses across 33 modules), proves X.509 or certificate-chain correctness, or reruns
every historical control record. S4 and S5 watch the Kani harness and manifest validator reject real
faults. L1 is accept-only; its six recorded Lean controls are validated by S2 rather than rerun. This
is not a substitute for `./check.sh`. See `PROOF_MANIFEST.md` for the actual proof envelope and
`ASSUMPTIONS.md` for what all of it stands on.
