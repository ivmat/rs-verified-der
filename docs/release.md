# Recorded acceptance and release preparation

`der-verified/acceptance.toml`, its inventory mirror and its evidence records are
snapshots of an issued verification record. Ordinary commits and CI validate those
files; they do not regenerate them. The producer of new evidence is external to
this repository. Release preparation imports its reviewed bundle and does not
invent claims, run proofs or turn old evidence into evidence for changed code.
The producer's claim-to-evidence mapping remains a reviewed trust boundary.

## Development checks

Run `python3 gates/check_acceptance_manifest.py` or `./check_fast.sh`. Snapshot
integrity remains mandatory: the pinned validator closure, claim and record hashes,
record pointers, inventory digest, assumption IDs and absence of orphan records
are checked. Current-source applicability is reported separately:

- **APPLICABLE:** the recorded subject's inputs match, allowing only safe prose and
  validated acceptance artifacts. Recorded compiler/tool assumptions still apply;
  this does not prove a newly installed toolchain or create a consumer acceptance.
- **CHANGED:** proof, build, tool, policy, requirements or other unapproved inputs
  changed. The historical record is valid only for its recorded subject.
- **UNKNOWN:** subject history or identity cannot be established, for example in a
  shallow clone. Obtain the missing history before release validation.

A valid historical snapshot may pass development checks with CHANGED or UNKNOWN.
Corrupt or inconsistent artifacts still fail. The package test prints the same
applicability distinction; unpacked-crate validation checks record integrity, not
whether its source equals a Git commit. `--require-current` on either check refuses
CHANGED and UNKNOWN. The README map uses the snapshot's own inventory; the current
requirements and source inventories remain separate development checks.

## Explicit release workflow

Set the intended package version before the full proof run. No command below changes
a version, creates a tag or publishes a crate.

1. Commit the intended source as **S**. Capture a real complete run with
   `python3 gates/proof_runs.py record`. This local receipt is required; a historical
   prose summary or an imported log cannot substitute for it.
2. Obtain the producer's reviewed bundle for S: `acceptance.toml`,
   `der.inventory.toml.vendored-copy` and `evidence/acceptance-records/*.json`.
   Its subject must be S. Its version is the package version already committed at S.
3. Stage it outside the checkout:

   ```sh
   python3 gates/release_evidence.py prepare --release 0.3.0 \
     --bundle /path/to/producer-bundle --output /path/to/new-staging-directory
   ```

   Use the intended version in place of `0.3.0`. Preparation checks snapshot
   integrity, current requirements, source equivalence and the trusted run. It
   writes only the new staging directory. `release-preparation.json` is a review
   summary, not proof evidence or release authorization.
4. Review the staged files. Copy only the three artifact groups into `der-verified/`.
   Copy any files under `proof-generated/` to their exact repository paths:
   `lean/lid-source-state.txt`, `docs/proof-floor.json` and `PROOF_MANIFEST.md` only. These are exact
   recorder-captured outputs; do not fill in missing measurements. Refresh the README map with
   `python3 gates/gen_verification_map.py --write` and review the release prose.
   The recorder supplies these bytes after a real complete run; arbitrary metadata
   edits do not qualify. For the proof manifest, only the designated generated
   floor-summary regions may differ; all other text must match S. Commit the result as **T**.
5. Until the open tag decision below is settled, capture a fresh complete run at clean T using the
   capped, sequential procedure in [CI selection and limits](ci.md). Then run:

   ```sh
   python3 gates/release_evidence.py validate --release 0.3.0 --source FULL_S_COMMIT
   ```

   Validation requires the package version to match, strict snapshot validation,
   current applicability and a successful offline package check. The complete S→T
   diff may contain only approved prose, exact acceptance artifacts and exact
   recorder-captured source-state metadata. Code, build, tool and policy changes
   require a new full run. All three captured outputs must be present at T with their exact
   bytes, even if a path would otherwise appear unchanged relative to S. The tool writes a
   local **release-validation** receipt
   bound to T, S and `refs/tags/v0.3.0`; it does not claim a full run occurred at T.
6. Pending at T (prose, not generated): `COVERAGE.md` is not a protected input and is refreshed
   by hand at T from the recorded run, after the capture. Until then its floor-of-record text
   still describes the earlier floor and must not be read as describing S or T. Review it
   before any push of T.

The release validator avoids inventing a proof result merely to commit validated output. The tag
gate checks its separate receipt and the bound trusted run again. A branch proof-reuse result is
insufficient for a release tag. Release-validation receipts, when created, are stored under the Git
common directory; local owner control of that store is a trust assumption. They are not signed or
portable release attestations.

For a public tag, the independent publication receipt gate also applies. As the last act before
pushing the final tag object, write `evidence/push-receipts/<sha>.receipt` with
`full-suite: GREEN @ <sha>` for the exact pushed SHA, and ensure it is newer than the commit
that object resolves to (for an annotated tag, the tagged commit; an unreadable timestamp refuses). This
legacy text receipt is mandatory publication policy but is not a trusted proof registration and
cannot replace `record` or release validation.

## Open decision: proof source for a release tag

The maintainer has not yet decided whether a release tag may rely on the trusted run at S when T
differs from S only by the three exact recorder-generated outputs, or whether every tagged commit
requires a fresh full run. Until that decision is recorded, this procedure requires a fresh full
run at T before creating or pushing the tag. The tag-path code is unchanged and continues to bind
release validation to T, S, the release ref and the trusted S receipt.

Later branch commits may reuse a validated release ancestor T when T→U contains only approved
prose. The gate verifies T and its captured source S again and refuses any artifact change after T.
No further full proof run is needed merely for that prose update.

The artifact exception currently supports this dependency-free crate without build
scripts, external file/environment reads or Rust include macros. It refuses more
complex input arrangements until their dependencies can be checked. It never
blanket-excludes the evidence directory or Lean sources from change checks.
