# TODO / open issues

Tracked roadmap for `der-verified`. Grouped by theme; check items off as they land. See
`PROOF_MANIFEST.md` for what is currently proven and `DECISIONS.md` for the rationale behind each
scope boundary referenced below.

## Known limitations (verification)

- [x] **`x509_name::validate_never_panics` — RESOLVED via a modular proof (DECISIONS.md D26).** The
      monolithic harness blew up (>100 GB in CBMC symbolic execution: `set_of::cmp_padded` re-derived
      over symbolic content). Split into `validate_rdn_never_panics` (the heavy SET-OF/ATV layer at
      one-RDN scale, ~17 GB) + `validate_never_panics` stubbing `validate_rdn` with its proven
      postcondition (~510 MB). Same theorem, now compositional; `./check.sh` completes end-to-end
      (161/161 Kani + the L4 lids). The same review also fixed a pre-existing fixed-vs-symbolic input
      length gap across all modular harnesses.
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

- [x] crates.io prep done: `publish = false` removed, package metadata filled (`authors`, `readme`,
      description, license, keywords, categories), crate README added, crate name `der-verified`
      confirmed available. Version deliberately kept at `0.0.0` (name-reservation / initial release
      per owner) — bump for the first real release.
- [x] `repository` URL confirmed = `https://github.com/ivmat/rs-verified-der`.
- [ ] `cargo publish` (needs a crates.io token via `cargo login`) — owner runs it manually.
- [x] Reproducibility: the full L3+L4 toolchain (Kani + Aeneas/Charon/Lean) was rebuilt from scratch
      and `./check.sh` is green end-to-end (2026-07-12). A pristine-container run is still nice-to-have
      before a tagged release.

## Good first issues

- [ ] More reject-differential test vectors (non-canonical encodings a lax parser would accept).
- [ ] Rustdoc usage examples per module (they double as doctests).
- [ ] A short "threat model / what a verified decoder buys you" section in the README or a `docs/`
      page.
