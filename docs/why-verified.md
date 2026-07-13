# Why a formally verified DER decoder — and how it's built

## The problem: X.509's encoding layer is a bug goldmine

Almost every TLS connection, code signature, and PKI check rests on parsing X.509 certificates, which
are encoded in DER — a canonical subset of ASN.1's BER. That encoding layer has a long, ugly track
record: memory-safety bugs in C parsers, and — more insidiously — **parser differentials**, where two
implementations disagree on whether the same bytes are a valid certificate. Differential-testing work
like *Frankencerts* showed how routinely real stacks diverge. A byte string one library rejects as
malformed, another accepts; a non-canonical length encoding one decoder normalizes, another treats as
a different value. Those disagreements are where certificate-confusion and bypass bugs live.

DER is *supposed* to make this tractable: every value has exactly one valid encoding. So a decoder has
a crisp, checkable contract — **accept a byte string if and only if it is the unique canonical DER
encoding, and never panic doing so.** That contract is small enough to *prove*.

## The idea: the proofs are the product

`der-verified` is a DER/X.690 encoding/decoding core in Rust where every public codec carries
machine-checkable evidence, and that evidence **re-runs from a fresh clone** — no trust in a badge, no
"we tested it a lot." `./check.sh` reproduces the whole thing.

It's deliberately narrow. This is the *encoding* brick — tags, lengths, and the canonical content
codecs (BOOLEAN, INTEGER, OID, BIT STRING, OCTET STRING, the string types, times, SEQUENCE, SET OF
ordering). The `x509_*` modules compose those verified codecs into structural framing for RFC 5280
objects, but interpret **no** semantics: no signature or key checks, no path or trust validation, no
cross-field profile rules. That boundary is the whole honesty story (below).

## Two layers of proof

**L3 — bounded, with Kani (CBMC under the hood).** 161 proof harnesses across 25 modules. Each proves,
for all inputs up to a stated size, the default safety properties (no panic, no overflow, no
out-of-bounds) *plus* the functional ones: decode/encode round-trips, canonicality/minimality, and
that malformed or non-canonical encodings are rejected with the right error. Bounded model checking is
exhaustive within its bound — it doesn't sample inputs, it considers all of them symbolically.

**L4 — unbounded, with Aeneas → Lean 4.** Bounded proofs leave a nagging question: what about inputs
bigger than the bound? For three codecs — `length`, `big_integer`, and `oid` — the Rust is translated
(via Charon → Aeneas) into a pure functional model and the properties are proven in Lean 4 for inputs
of *any* length, `sorry`-free. The lid re-extracts from the shipped source and fails on drift, so it
provably concerns the code you actually ship.

Plus 294 concrete and regression tests (including seeded-bad specimens), `#![forbid(unsafe_code)]`,
zero dependencies, and allocation-free decode paths.

## The honesty envelope

[`PROOF_MANIFEST.md`](../PROOF_MANIFEST.md) states exactly what is proven, under what bounds, with what
assumptions and stubs — and **what is not**. The short version of "not proven": any cryptography, any
certificate-path or trust decision, and the full RFC 5280 profile semantics. If you want those, you
build them *on top of* this verified core, inside the same discipline. Calling this "a verified X.509
parser" would be a lie; it's a verified encoding layer, and the manifest keeps that honest.

## A war story: the proof that needed 100 GB

The most interesting failure was the harness proving that validating an X.509 `Name` never panics. A
`Name` is a `SEQUENCE OF SET OF AttributeTypeAndValue` — doubly nested, variable-count — and DER
requires the `SET OF` members to be in canonical order. Proving "never panics" over fully symbolic
bytes meant CBMC re-derived that pairwise ordering comparison across every possible partition of the
input, inside a three-deep loop nest. The formula didn't just get big; it blew past **100 GB during
symbolic execution**, before the SAT solver even ran. Shrinking the input buffer and the unwind bound
barely helped — the cost was the ordering machinery, not the loop depth.

The fix is the standard modular-verification move, and it's a nice illustration of the technique:
prove the heavy inner layer (`validate_rdn`, one `RelativeDistinguishedName`) panic-free *once* at its
natural scale (~17 GB), establishing a postcondition; then in the outer "never panics" proof, replace
that inner call with a stub that returns a nondeterministic result constrained to the proven
postcondition. CBMC then only has to reason about the outer framing (~510 MB). Same theorem, split into
two tractable pieces that both fit on a normal machine. (The full rationale is `DECISIONS.md` D26.)

Doing that surfaced a second, subtler issue worth mentioning: the stub's contract has to be discharged
at *every input length the composition actually uses*, not just the full buffer — parser control flow
is length-dependent, so a fixed-length lemma leaves a gap. Making the discharging proofs range over a
symbolic input length closed it (and closed the same latent gap in the other modular proofs).

## Reproduce it

```sh
git clone https://github.com/ivmat/rs-verified-der && cd rs-verified-der
cargo test                       # 294 tests
cargo install --locked kani-verifier && cargo kani setup
cargo kani -Z stubbing           # the 161-harness proof floor
./check.sh                       # everything, incl. the Lean lids if the toolchain is present
```

The Lean L4 layer needs the pinned Aeneas/Charon/Lean toolchain; without it, `check.sh` runs the Kani
floor and skips the lids (they're a local-milestone check). CI runs the memory-tractable share of the
floor on every push; the heaviest harnesses are documented as local checks.

## Takeaway

You can't (yet) formally verify "X.509 is safe." But you *can* carve off the encoding layer — the part
with a crisp canonical-form contract and a bad CVE history — and prove that brick doesn't panic and
accepts only canonical bytes, with evidence anyone can re-run. That's a real, honest reduction of
attack surface, and a template for doing the same to the layers above it.
