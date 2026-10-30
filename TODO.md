# Open work

This is the single active backlog, reconciled on 2026-10-28. Items below are proposals,
not commitments or evidence of completed verification. Current claims belong in
[PROOF_MANIFEST.md](PROOF_MANIFEST.md), [the requirements inventory](docs/requirements/der.inventory.toml)
and [acceptance.toml](der-verified/acceptance.toml). The
[proof-floor declaration](docs/proof-floor.json) identifies the recorded run;
[the evidence policy](evidence/README.md) explains how to request its logs.

The acceptance 0.4.0 migration, requirement-level mapping, full recorded floor, and
`set_of` shared-walk refactor are complete. Earlier status and scoping notes are in
[the archive index](docs/archive/README.md).

## Proofs and tests

- [ ] Discharge `has_repeated_leading_oid` totality and helper comparison obligations.
  Profile totality and precedence proofs remain conditional on the helper's totality;
  concrete tests do not discharge it. See [the helper-proof plan](docs/proof-work/s5-profile-helper-harnesses.md).
- [ ] **R2 — structural reachability:** add appropriate accept-path covers to
  `tlv::decode_tlv_structure`, both OCTET STRING structural/identifier harnesses,
  `sequence::accepted_identifier_is_canonical_0x30`, and
  `set_of::accepted_identifier_is_canonical_0x31`. For a harness that exercises a child
  walk, witness a second iteration as well; the TLV structural harness has no loop.
  Investigate each unsatisfied cover;
  Kani success alone does not show it was reached. See [COVERAGE.md §6.3](COVERAGE.md#63-three-harnesses-cannot-witness-their-own-happy-path).
- [ ] Add observed-red controls for `x509_certificate` and `x509_tbs_certificate`;
  the current projected record store has none for these modules. Preserve the existing
  controls for the other X.509 and key-container modules and assess remaining gaps
  per requirement in [acceptance.toml](der-verified/acceptance.toml).
- [ ] Explore an unbounded Lean proof for `profile` and for an X.509 structural module.
  These are separate projects; neither is covered by the existing codec lids.
- [ ] Add external vectors and differential tests, including relevant x509-limbo and
  Wycheproof DER/ECDSA cases. Refresh mutation testing for changed code, retaining the
  [existing survivor dispositions](COVERAGE.md). Add a proof or suitable large-input test
  for `encode_tlv_into` at `value.len() == u32::MAX` (~4 GiB): the `>` guard differs
  from `>=` or `==` there. A fast unit test cannot allocate the required value; see
  [the disclosed boundary residual](COVERAGE.md).
- [ ] Refresh per-harness cost measurements where source changes have invalidated old
  figures, including `x509_name::validate_rdn_never_panics`. Keep historical measurements dated.
- [ ] Run the documented replay in a pristine environment as a release-readiness check.

## Scope and API decisions

- [ ] **R3 — identifier-form checking:** decide whether the base strict TLV API should
  enforce the checks currently available through the opt-in `identifier_form` API.
  This changes accepted input and requires call-site review and proof work.
- [ ] **R4/R5 — nested input:** decide whether to add tree-wide validation and explicit
  depth/work limits. They are distinct changes; current APIs leave input-size and
  nesting limits to callers.
- [ ] Decide whether PKCS#8 attribute members should be decoded and validated rather
  than returned as opaque content.
- [ ] Resolve UTF8String CSI-introduced control sequences against X.690 §8.23.9 e.
- [ ] Decide whether the public EXPLICIT-context primitive should require exactly one
  inner TLV. Current in-crate callers perform their own inner-value checks.
- [ ] Consider basic constraints, key usage, name constraints and validity-against-clock
  as separate profile extensions. They are outside the current profile coverage.
- [ ] Review `no_std` support together with optional OID-arc materialization: the latter
  needs an allocation policy. Any chosen configuration needs its own build/proof checks.
  Guard against Kani selecting the test/std configuration: consider a
  `#[cfg(all(kani, test))] compile_error!(...)` check rather than assuming it never does.
- [ ] Review public API coherence before the next release that changes the API.

## Verification workflow — separate approval required

- [ ] Exercise the new CI workflow's hosted pass/fail paths and adopt `CI result` as
  a required check before publication. Local fixture tests do not establish hosted behavior.
- [ ] Capture a real completed run with the committed recorder before relying on the new
  push/release gate. Historical declarations and legacy receipts cannot register that run.
  Review the explicit producer bundle through [the release workflow](docs/release.md).
- [ ] Provision and test Lean CI separately if pursued. The bounded CI change selection
  and fast-check parity are described in [CI selection and limits](docs/ci.md);
  the public release producer and future Lean CI remain separate work.

## Documentation and inventory

- [ ] Reconcile the legacy `DER-*` coverage ledger with the requirements inventory before
  deciding whether a generated view can replace it. Preserve rule-level scope and caveats.
- [ ] Check inventory completeness beyond the earlier selected standards/“shall” census;
  do not reuse its old `slice = true` status as a description of the current inventory.
- [ ] Correct X.690 clause citations in `context_tag.rs`, `bit_string.rs` and crate docs
  during an approved source change. Record corrections to historical decisions explicitly.
- [ ] Make delegated RSASSA-PSS parameters, PKCS#8 attributes and ECPrivateKey parameter
  semantics clear in the coverage ledger where its summary omits them.
