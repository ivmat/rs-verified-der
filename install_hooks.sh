#!/usr/bin/env bash
# Install this repo's git hooks so git runs the fast verification layer (check_fast.sh) on every
# commit. Idempotent; symlinks so the hook stays in sync with hooks/pre-commit.
set -eu
cd "$(dirname "$0")"
[ -d .git/hooks ] || { echo "no .git/hooks — not a git repo?"; exit 2; }
chmod +x hooks/pre-commit check_fast.sh
ln -sf ../../hooks/pre-commit .git/hooks/pre-commit
echo "installed: .git/hooks/pre-commit -> hooks/pre-commit  (check_fast.sh runs on every commit)"
