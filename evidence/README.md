# Evidence policy

Full run evidence is kept outside git, available on request. This includes logs, control campaigns, twins, predictions and historical run records.
The local files stay on disk. The removal from git does not edit history.

The acceptance manifest `der-verified/acceptance.toml` and its projected records under `der-verified/evidence/acceptance-records/` stay committed as the showcase.
The requirements maps under `docs/requirements/evidence/` also stay committed. They are source maps, not run logs.

The floor of record is `c7a2e26`: 302 successful harnesses, zero failures, exit 0, and Lean lid PASS in one pass.
The raw log SHA-256 is `d8ec85a0c7c072f49e51c072bc3d19739e93937ec6ce4a4f8e79b9509bbaddd0` (decompressed bytes).
See [`docs/proof-floor.json`](../docs/proof-floor.json) for the compact declaration and [`COVERAGE.md`](../COVERAGE.md) for the certification procedure.

Use the commit and hashes in the acceptance records to identify requested material.
