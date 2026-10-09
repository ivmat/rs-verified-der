# Vendored acceptance closure

`acceptance/` is a complete, byte-for-byte export of the acceptance 0.3.2
consumer closure. It is generated material. Do not edit any file below that
directory by hand.

- Source: public repository `https://github.com/ivmat/acceptance-format`
  (family version 0.3.2; this commit carries no git tag in that repository)
- Source commit: `455ca4f84ada3fc51eed30942696f34d118e1a59`
- Closure inventory: `acceptance/CLOSURE.json`

The inventory binds that source commit to SHA-256 digests for all 20 exported files. Verification
against those digests confirms that every vendored file is byte-for-byte identical to the pinned
source, including the complete `export_closure.py` and its cold-model-name regular expression; the
exporter has no local patch.

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
