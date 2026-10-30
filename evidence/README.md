# Evidence policy

Full run evidence is kept outside git, available on request. This includes logs, control campaigns, twins, predictions and historical run records.
The local files stay on disk. The removal from git does not edit history.

The acceptance manifest `der-verified/acceptance.toml` and its projected records under `der-verified/evidence/acceptance-records/` stay committed as the showcase.
The requirements maps under `docs/requirements/evidence/` also stay committed. They are source maps, not run logs.

The [proof-floor declaration](../docs/proof-floor.json) records the run commit, result and raw-log
SHA-256 (decompressed bytes). Recorder-generated memory fields state when they were not measured.
See [COVERAGE.md](../COVERAGE.md) for the certification procedure.

Use the commit and hashes in the acceptance records to identify requested material.
