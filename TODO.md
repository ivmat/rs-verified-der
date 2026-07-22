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
- [x] Record, per harness, the wall-clock/solver cost so the intractable ones are visible up front —
      [`docs/verification-cost.md`](docs/verification-cost.md) (cost tiers, the heavy `set_of` §11.6
      family, the two harnesses that need a >16 GB box, and a measured solver-selection note).

## Verification breadth

- [x] **A 4th L4 (Aeneas→Lean) lid — landed on `tlv` (DECISIONS.md D27).** The first L4 lid on the
      crate's structural *composition* layer (composing `tag` + `length`), not another leaf codec:
      `decode_tlv`'s structural/no-over-read correctness, ∀-length (`lean/TlvProofs.lean`). Required a
      one-line behavior-preserving source fix (`tlv.rs`'s point-free `map_err` → explicit closures, to
      unblock an Aeneas naming clash) — re-verified by Kani + tests. 7 disclosed assumed specs (2 of
      which restate an already-proved `LengthProofs.lean` fact, worked around a duplicate-extraction
      namespace collision, not new trust). `check_lean.sh` extended + confirmed non-vacuous
      (sorry-injection test). The lids now cover `length`, `big_integer`, `oid`, `tlv`; the larger
      `sequence`/consumer-walk lid (a loop over an unbounded child count) and a `tag.rs` D25-style
      refactor to fully de-opaque `decode_tag` remain open, larger, separate items.
- [x] **A 5th L4/L5 (Aeneas→Lean) lid — landed on `sequence` (DECISIONS.md D28).** The larger
      `sequence`/consumer-walk lid flagged above: `decode_sequence`'s structural/no-over-read
      correctness, ∀-length AND ∀-children (`lean/SequenceProofs.lean`) — the crate's first
      **unbounded-LOOP** lid (`tlv::decode_tlv` is itself loop-free). Required the SAME map_err
      name-clash fix as D27, this time in `sequence.rs`, plus a documented `check_lean.sh` patch step
      working around a genuine Aeneas codegen gap (the `Iterator` trait's `step_by`/`enumerate`/`take`
      defaults aren't filled for a user-defined `impl Iterator` that only defines `next`) — filled with
      Aeneas's own generic default-method combinators, inert for this lid's scope. Same 7 disclosed
      assumed specs as `tlv`'s lid (restated for the new extraction pass's namespace). `check_lean.sh`
      extended + confirmed non-vacuous (sorry-injection test, both at the `lake build` and full-gate
      level). The lids now cover `length`, `big_integer`, `oid`, `tlv`, `sequence`; a `tag.rs`
      D25-style refactor to fully de-opaque `decode_tag` remains open, a separate item.
- [ ] Add the L4/L5 Lean job to CI if a hosted runner can provision the pinned Aeneas/Charon/Lean
      stack (currently a local-milestone check — see the README).

## API / scope

- [ ] A typed / profile API layer enforcing the cross-field RFC 5280 rules currently left to the
      caller (deliberately out of the verified core): `signatureAlgorithm == tbsCertificate.signature`;
      `version` v3-required-if-extensions; UTCTime `≤ 2049` / GeneralizedTime `≥ 2050`; name
      constraints. Keep it a separate layer on top of the verified codecs.
- [ ] `oid`: optionally materialize arcs (allocation-aware) — currently validate-only.
- [ ] **`no_std` support (later).** The crate is already `#![forbid(unsafe_code)]`, allocation-free on
      decode paths, and near-`core`-only (one `std::` use). Making it `#![no_std]` (gated on a `std`
      feature) would make a zero-dep, formally-verified DER core usable in embedded / bootloader /
      kernel contexts. Low priority; a strong differentiator when done.

## 0.1.0 release checklist

`0.0.0` is published (name reservation). For the first *real* release:

- [ ] Bump `version` to `0.1.0` in `der-verified/Cargo.toml`.
- [ ] **Fix rustdoc intra-doc links** — `cargo doc` (with `-D warnings`) currently errors on broken /
      private-item links, incl. `validate_name` → private `validate_rdn`/`validate_atv` (from the D26
      modular-proof docs), plus `minimality_is_local`, `decode_extn_id_tlv`, `decode_time_tlv`. These
      render broken on docs.rs.
- [ ] `#![deny(missing_docs)]` + a top-level crate-doc example (parse a cert end-to-end) so docs.rs
      reads well and the public API is fully documented.
- [ ] Add `CHANGELOG.md` (Keep-a-Changelog) with the 0.1.0 entry.
- [ ] Declare an MSRV (`rust-version` in Cargo.toml) and CI-check it.
- [ ] Confirm CI is green on the public repo and that docs.rs builds cleanly.
- [ ] Final public-API review (0.1.0 is the API you're committing to; breaking changes still allowed
      pre-1.0 but keep it coherent).
- [ ] `cargo publish` the 0.1.0.

## Publishing

- [x] crates.io prep done: `publish = false` removed, package metadata filled (`authors`, `readme`,
      description, license, keywords, categories), crate README added, crate name `der-verified`
      confirmed available. Version deliberately kept at `0.0.0` (name-reservation / initial release
      per owner) — bump for the first real release.
- [x] `repository` URL confirmed = `https://github.com/ivmat/rs-verified-der`.
- [x] Published `der-verified` to crates.io — 0.0.0 (name reservation) then 0.1.0 (2026-07-13).
- [x] Reproducibility: the full L3+L4 toolchain (Kani + Aeneas/Charon/Lean) was rebuilt from scratch
      and `./check.sh` is green end-to-end (2026-07-12). A pristine-container run is still nice-to-have
      before a tagged release.

## Good first issues

- [ ] More reject-differential test vectors (non-canonical encodings a lax parser would accept).
- [ ] Rustdoc usage examples per module (they double as doctests).
- [x] A "why / threat-model" writeup covering what a verified decoder buys you —
      [`docs/why-verified.md`](docs/why-verified.md).
