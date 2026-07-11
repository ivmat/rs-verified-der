# TODO / open issues

Tracked roadmap for `der-verified`. Grouped by theme; check items off as they land. See
`PROOF_MANIFEST.md` for what is currently proven and `DECISIONS.md` for the rationale behind each
scope boundary referenced below.

## Known limitations (verification)

- [ ] **`x509_name::validate_never_panics` is CBMC-intractable at the current bound.** The harness
      inlines `set_of::cmp_padded` (the SET-OF §11.6 padded comparison) and the SAT instance blows up
      (no verdict after a long run at `[u8; N]` / `unwind 20`). Consequence: `./check.sh` may not
      complete end-to-end on modest hardware, even though every *other* harness verifies green and the
      X.509 composition harnesses pass (they stub `validate_name` away — see `PROOF_MANIFEST.md`).
      Candidate fixes:
  - reduce the harness buffer/unwind to the smallest bound that still exercises a multi-RDN,
    multi-ATV path (the technique already used for `x509_extension::validate_extensions_never_panics`),
    with the residual covered compositionally;
  - or decompose/stub `cmp_padded` (proven independently) inside this harness;
  - or run it on a machine with more solver headroom.
- [ ] Record, per harness, the wall-clock/solver cost so the intractable ones are visible up front.

## Verification breadth

- [ ] A 4th L4 (Aeneas→Lean) lid — either another codec, or a **correctness** lid on a consumer slice
      (the current 3 lids cover `length`, `big_integer`, `oid`; the X.509 slices are Kani-only).
- [ ] Add the L4 Lean job to CI if a hosted runner can provision the pinned Aeneas/Charon/Lean stack
      (currently a local-milestone check — see the README).

## API / scope

- [ ] A typed / profile API layer enforcing the cross-field RFC 5280 rules currently left to the
      caller (deliberately out of the verified core): `signatureAlgorithm == tbsCertificate.signature`;
      `version` v3-required-if-extensions; UTCTime `≤ 2049` / GeneralizedTime `≥ 2050`; name
      constraints. Keep it a separate layer on top of the verified codecs.
- [ ] `oid`: optionally materialize arcs (allocation-aware) — currently validate-only.

## Publishing

- [ ] Decide crates.io publication: remove `publish = false`, set a real `version` (currently
      `0.0.0`), fill remaining package metadata, and confirm the crate name (`der-verified` is
      available on crates.io).
- [ ] Confirm the `repository` URL in `der-verified/Cargo.toml` matches the final repo.
- [ ] Fresh-clone verification on a clean machine/container: follow the README verbatim, confirm
      `cargo test` + `cargo kani -Z stubbing` are green (the end-to-end reproducibility check).

## Good first issues

- [ ] More reject-differential test vectors (non-canonical encodings a lax parser would accept).
- [ ] Rustdoc usage examples per module (they double as doctests).
- [ ] A short "threat model / what a verified decoder buys you" section in the README or a `docs/`
      page.
