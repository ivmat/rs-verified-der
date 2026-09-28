# Vendored acceptance closure

`acceptance/` is a complete, byte-for-byte export of the acceptance 0.3.2
consumer closure. It is generated material. Do not edit any file below that
directory by hand.

- Release tag: `acceptance-v0.3.2`
- Source commit: `d22080c8ad2efe858e9e6788d270eed92b3f6345`
- Closure inventory: `acceptance/CLOSURE.json`

The closure supplies its own verifier. It checks every listed file hash, the
source commit, export cleanliness, missing files, unexpected source files, and
bytecode caches. Run vendored Python with bytecode writing disabled.

## Re-vendoring

1. From a clean checkout of the pinned release, export to a fresh
   `gates/vendor/acceptance/` destination with the release's
   `protocol_acceptance/tools/export_closure.py` tool.
2. Verify the copy:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 python3 -B gates/vendor/acceptance/export_closure.py verify \
     --dest gates/vendor/acceptance \
     --expect-commit d22080c8ad2efe858e9e6788d270eed92b3f6345 --require-clean
   ```

3. Re-emit `der-verified/acceptance.toml` and its projected evidence records
   with the same commit. Do not edit generated output to change a pin.
4. Run `./check.sh`.

The source commit must be publicly resolvable before this update is merged. A
release re-export may change only `CLOSURE.json` provenance when every listed
file hash remains byte-identical.
