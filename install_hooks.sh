#!/usr/bin/env bash
# Install this repo's git hooks:
#   pre-commit -> hooks/pre-commit   (the fast verification layer, check_fast.sh, on every commit)
#   pre-push   -> gates/pre-push     (the push boundary: destination trap + document gates at the
#                                     pushed sha + a full-suite receipt when the destination is
#                                     public — read that file's header before pushing)
# Hooks are machine-local and cannot travel in a commit; the tracked files above are the real ones
# and .git/hooks only symlinks to them, so editing either takes effect with no reinstall.
# Idempotent.
set -eu
cd "$(dirname "$0")"
[ -d .git/hooks ] || { echo "no .git/hooks — not a git repo?"; exit 2; }
chmod +x hooks/pre-commit check_fast.sh gates/pre-push
ln -sf ../../hooks/pre-commit .git/hooks/pre-commit
echo "installed: .git/hooks/pre-commit -> hooks/pre-commit  (check_fast.sh runs on every commit)"
ln -sf ../../gates/pre-push .git/hooks/pre-push
echo "installed: .git/hooks/pre-push   -> gates/pre-push    (destination + doc gates + receipt)"
