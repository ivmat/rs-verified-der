---
type: reference
---

# `evidence/push-receipts/` — what a receipt is, and why none of them is committed

`gates/pre-push` refuses a push to the (public) upstream unless this directory holds a file

```
<sha>.receipt        containing        full-suite: GREEN @ <sha>
```

for **every** sha the push carries, with an **mtime newer than that commit**.

## Why the receipts are untracked

A receipt certifies a sha. Committing it would produce a *different* sha, which would then have no
receipt — the certificate cannot live inside the thing it certifies. So `*.receipt` is git-ignored
here (`.gitignore` in this directory), and only this README and that ignore file are tracked. The
receipt is a **local, machine-side artifact**: it says "on this machine, at this moment, the full
suite was green at this sha, and I am about to push it".

That is deliberately a weaker object than the evidence in `../check-*.log`, which IS committed and
IS the crate's public claim. The receipt does not replace the log; it is the interlock that stops a
push from happening *before* the log exists.

## What writing one asserts

`./check.sh` — the doc-link gate, the manifest and verification-map gates, the workspace tests, the
doctest-count and tier-parity gates, the full Kani floor, and the Lean lids — ran **to completion,
green, at exactly that sha**, and its distilled log was committed the way `../check-*.log` headers
describe. The mtime rule is what makes "as the last act before pushing" enforceable rather than
aspirational: an amend or rebase after the run changes the sha, and the gate then finds no receipt
for the sha it is actually being asked to push.

## How to write one

```sh
sha=$(git rev-parse HEAD)
printf 'full-suite: GREEN @ %s\n' "$sha" > evidence/push-receipts/$sha.receipt
```

Anything else in the file is free-form and is ignored by the gate — a run date, the host, the
wall-clock, the log path it corresponds to. Only the `full-suite: GREEN @ <sha>` line is checked.

## `overrides.log`

If a push is forced with `FV_PUSH_GATE_OVERRIDE=1`, the gate appends a line here before letting it
through. That file is untracked too, and its existence is the point: an override is visible and
dated rather than silent. The session that produced the work is not the one that should use it.
