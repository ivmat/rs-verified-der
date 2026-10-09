# Vendored acceptance closure

`acceptance/` is a complete, byte-for-byte export of the acceptance 0.3.2
consumer closure. It is generated material. Do not edit any file below that
directory by hand.

- Source: public repository `https://github.com/ivmat/acceptance-format`
  (family version 0.3.2; this commit carries no git tag in that repository)
- Source commit: `455ca4f84ada3fc51eed30942696f34d118e1a59`
- Closure inventory: `acceptance/CLOSURE.json`

The inventory records the SHA-256 the exporter computed from the source checkout at `455ca4f`
(`source_dirty=false`). The closure verifier confirms the vendored tree still matches that
inventory; it does not by itself prove identity to the upstream commit. Identity to upstream is
established by comparing all 20 listed files against a fresh checkout of `455ca4f` at vendoring
time; repeat that comparison on every re-vendor.

The closure supplies its own verifier. It checks every listed file hash, the
source commit, export cleanliness, missing files, unexpected source files, and
bytecode caches. Run vendored Python with bytecode writing disabled.

## Re-vendoring

1. Clone the public repository `https://github.com/ivmat/acceptance-format` at
   the pinned commit, and export to a fresh `gates/vendor/acceptance/`
   destination with that checkout's
   `protocol_acceptance/tools/export_closure.py` tool.
2. Verify the copy:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 python3 -B gates/vendor/acceptance/export_closure.py verify \
     --dest gates/vendor/acceptance \
     --expect-commit 455ca4f84ada3fc51eed30942696f34d118e1a59 --require-clean
   ```

3. Re-emit `der-verified/acceptance.toml` and its projected evidence records
   with the same commit. Do not edit generated output to change a pin.
4. Run `./check.sh`.

The source commit must be publicly resolvable before this update is merged. A
release re-export may change only `CLOSURE.json` provenance when every listed
file hash remains byte-identical.
