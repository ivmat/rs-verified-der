# Updating documentation

A code, proof or feature change MUST include a docs-sync pass in the same change
(or the immediate next one). Use simple technical English,
keep each fact in one authoritative place, and link to detail instead of copying it.
Do not turn the active backlog into a run diary.

## Sources of truth

| Question | Source |
|---|---|
| What remains open? | [TODO.md](TODO.md) |
| What is proved, with which bounds and assumptions? | [PROOF_MANIFEST.md](PROOF_MANIFEST.md), [ASSUMPTIONS.md](ASSUMPTIONS.md) |
| Which requirements have evidence? | [Requirements inventory](docs/requirements/der.inventory.toml), [evidence maps](docs/requirements/evidence/README.md), [acceptance manifest](der-verified/acceptance.toml) |
| Which run is recorded? | [Proof-floor declaration](docs/proof-floor.json), [evidence policy](evidence/README.md) |
| Why was a scope or design decision made? | [DECISIONS.md](DECISIONS.md) |
| What shipped? | [CHANGELOG.md](CHANGELOG.md) |

## Counts and generated regions

Use the generator rather than hand-grepping Rust attributes or copying old prose counts:

```sh
python3 gates/gen_proof_manifest.py --json
python3 gates/gen_proof_manifest.py --check
python3 gates/gen_verification_map.py --check
```

When the corresponding inputs changed, regenerate with `--write`, then review the diff.
Never hand-edit generated regions. The proof manifest's `pins-observed` region records the
regenerating machine; `--check` deliberately excludes it. Do not treat that environmental
diff as new evidence or widen the exclusion to suppress a failure.

The count guard scans the explicit `GUARDED_DOCS` list in `gates/gen_proof_manifest.py`.
`docs/archive/` is outside that list, so historical counts are not checked against current
source. Preserve that distinction if the scan is broadened. The guard recognizes
specific prose patterns, not every possible assertion. Prefer
linking to the proof manifest over repeating counts. Keep measured runtime and memory
figures dated; source counts cannot refresh a measurement.

## Change checklist

| Change | Review/update |
|---|---|
| Harness, test, bound, stub, cover, tool pin or Lean lid | Generated proof manifest; affected requirement/evidence mappings; nearby scope prose |
| New capability or changed behavior | API docs, requirement scope, README summary, changelog, relevant decision |
| Changed assumption or known limitation | Assumptions, proof manifest, relevant coverage rows; security guidance if affected |
| CI or verification policy | Documented commands, tiers, replay behavior and cost claims |
| Work completed or new follow-up | Reconcile TODO; remove completed tasks rather than appending contradictory updates |
| Documents moved or archived | Update links and plain-text citations, including `gates/map_declared.txt`; regenerate its README projection |

Known-unsatisfiable covers retain their source registry entry:

```rust
// VACUITY-DISCLOSED: <finding harness> -> witness <positive-construction harness>
```

Kani can report success with an unsatisfied cover. Preserve the limitation and its witness;
do not infer accept-path reachability from success alone.

## History and evidence

Keep dated decisions and shipped changelog entries as history; add an explicit correction
when needed. Archive superseded status narratives with a clear date and a link to current
sources. [The archive](docs/archive/README.md) is not an additional work queue.

Acceptance records, inventory mirrors and vendored validator files have hash and packaging
contracts. Do not delete or rewrite them as documentation cleanup. Evidence regeneration
uses the explicit [release workflow](docs/release.md), not an ordinary push or docs edit.
Development checks report historical snapshot integrity and current applicability separately.

Run the relevant existing checks after editing and report what was actually run. Link and
projection checks establish documentation consistency, not Kani or Lean proof success.
