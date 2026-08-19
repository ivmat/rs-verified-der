---
type: reference
---

# Negative fixtures for `gates/pre-push` — 2026-08-19

**What this closes.** A push gate that has never been observed refusing anything is a gate nobody
has evidence for. `gates/pre-push` was installed on this clone on 2026-08-19; this file records it
being **driven into each of its refusal paths on purpose**, with the refusal text verbatim, plus one
positive control and one no-op control so "refuses everything" and "passes everything" are both
excluded.

**Method.** The hook was invoked directly the way git invokes it — `gates/pre-push <remote> <url>`
with the ref line `<local ref> <local sha> <remote ref> <remote sha>` on stdin — against the repo at
`a3e0c8932552a8c816d30a918b4c06d8c2022947` (HEAD at the time). No actual push was made, and none of
these runs contacted the upstream except through the gate's own `gh repo view` visibility query,
which answered `PUBLIC` in every run below. Exit status is the hook's, and git treats non-zero as
"refuse the push".

| # | Fixture | Exit | Outcome |
|---|---|---:|---|
| F1 | destination is not the declared slug | **1** | REFUSED — remote-verification trap |
| F2 | correct destination, **no receipt** for the pushed sha | **1** | REFUSED — missing full-suite receipt |
| F3 | receipt exists but names a **different sha** | **1** | REFUSED — receipt content |
| F4 | receipt is correct but **older than the commit** | **1** | REFUSED — stale receipt |
| F5 | receipt correct and newer than the commit | **0** | ALLOWED (positive control) |
| F6 | up-to-date push: args, zero ref lines on stdin | **0** | ALLOWED (no-op control) |

## F1 — wrong destination

`gates/pre-push evil https://github.com/someone-else/rs-verified-der.git`

```
==============================================================================
 PUSH REFUSED — der-verified push gate
==============================================================================
  BLOCKED: remote-verification trap: this repo may only push to ivmat/rs-verified-der
  BLOCKED: attempted destination: remote 'evil' -> https://github.com/someone-else/rs-verified-der.git (parsed as 'someone-else/rs-verified-der')

  TO CLEAR THIS: push to the declared destination. If a NEW destination is genuinely
  wanted, edit ALLOWED_SLUG in gates/pre-push deliberately — do not add a remote to
  get around this, and do not reach for the override.

  Visible, logged override (not for the session that produced the work):
    FV_PUSH_GATE_OVERRIDE=1 git push ...
==============================================================================
```

Note the ordering: the destination rule fires **before** the payload rules, so a push aimed at the
wrong place never even reaches the document gates. A payload gate that ignores the destination is
walked around by adding a remote.

## F2 — correct destination, no receipt

`gates/pre-push origin https://github.com/ivmat/rs-verified-der.git`

```
== der-verified push gate: document gates @ a3e0c8932552a8c816d30a918b4c06d8c2022947 ==
PASS check_links: 23 curated doc files, all relative links resolve
== proof-manifest gate: PASS (generated regions + 7 guarded count-claims current) ==
== verification-map gate: PASS (README.md verification map current) ==

==============================================================================
 PUSH REFUSED — der-verified push gate
==============================================================================
  BLOCKED: push to ivmat/rs-verified-der (visibility: public) does not clear the gate
  BLOCKED: a3e0c8932552a8c816d30a918b4c06d8c2022947: no full-suite receipt at evidence/push-receipts/a3e0c8932552a8c816d30a918b4c06d8c2022947.receipt

  TO CLEAR THIS:
    1. run ./check.sh at the exact sha you intend to push (Kani floor + Lean lids +
       gates), and commit its distilled log the way evidence/check-*.log headers do;
    2. as the LAST act before pushing, write the receipt for the FINAL sha:
         sha=$(git rev-parse HEAD)
         printf 'full-suite: GREEN @ %s\n' "$sha" > evidence/push-receipts/$sha.receipt
    3. push, and do NOT amend afterwards — an amend changes the sha and voids the receipt.

  Visible, logged override (not for the session that produced the work):
    FV_PUSH_GATE_OVERRIDE=1 git push ...
==============================================================================
```

Two things are visible here beyond the refusal: the visibility was resolved **live** (`gh` answered
`PUBLIC`, so the receipt rule engaged rather than being skipped), and the document gates ran inside a
detached worktree **at the pushed sha** — the `23 curated doc files` count is the corpus at that
commit, not the working tree's 25, which is the point of gating the sha rather than the tree.

## F3 — receipt names a different sha

Receipt written containing `full-suite: GREEN @ deadbeef`:

```
  BLOCKED: a3e0c8932552a8c816d30a918b4c06d8c2022947: evidence/push-receipts/a3e0c8932552a8c816d30a918b4c06d8c2022947.receipt does not contain the line 'full-suite: GREEN @ a3e0c8932552a8c816d30a918b4c06d8c2022947'
```

The filename alone does not satisfy the gate: the sha must appear **inside** the file, so a receipt
cannot be produced by renaming an older one.

## F4 — correct receipt, older than the commit

Same receipt, back-dated with `touch -d "2020-01-01"`:

```
  BLOCKED: a3e0c8932552a8c816d30a918b4c06d8c2022947: the receipt is OLDER than the commit — it must be the LAST act before the push; an amend or rebase voids it
```

This is the rule that makes "the receipt is the last act before the push" enforceable instead of
aspirational. It is also the rule that catches the realistic accident: run the suite, then amend or
rebase, then push — the sha the receipt certifies is no longer the sha being pushed.

## F5 — positive control

Receipt correct and freshly touched:

```
== der-verified push gate: document gates @ a3e0c8932552a8c816d30a918b4c06d8c2022947 ==
PASS check_links: 23 curated doc files, all relative links resolve
== proof-manifest gate: PASS (generated regions + 7 guarded count-claims current) ==
== verification-map gate: PASS (README.md verification map current) ==
der-verified push gate: OK — ivmat/rs-verified-der (public), document gates green at: a3e0c8932552a8c816d30a918b4c06d8c2022947
```

Exit 0. Without this run, F1-F4 would be equally consistent with a gate that refuses unconditionally.
The fixture receipt was **deleted afterwards**, so no receipt for that sha survives this campaign —
a fixture that leaves a live receipt behind would be a hole, not a control.

## F6 — no-op control

`gates/pre-push origin <url> < /dev/null` (git's shape for an already-up-to-date push: arguments
present, zero ref lines) exits **0** with no output. A gate that refused the no-op push would train
people to override it routinely.

---

## What this establishes, and what it does not

- **Establishes:** each of the gate's four refusal conditions was observed refusing, with the
  message a human would actually see; the allow path was observed allowing; the no-op path does not
  refuse. The visibility check was observed resolving live against the real upstream.
- **Does not establish** that the gate cannot be bypassed. It can, three ways, all deliberate:
  `FV_PUSH_GATE_OVERRIDE=1` (visible, logged to `evidence/push-receipts/overrides.log`),
  `git push --no-verify` (git's own escape, which no hook can close), and editing the tracked
  `gates/pre-push` itself. A hook is an interlock against *mistakes and momentum*, not a control
  against a determined operator on their own machine.
- **Does not establish anything about the proofs.** The document gates this hook runs are
  pure-stdlib text checks; they take no FV slot and run neither Kani nor CBMC. The Kani/Lean claim
  at a pushed sha rests entirely on the receipt — i.e. on someone having actually run `./check.sh`
  — and the gate checks that the receipt *exists and is timely*, never that the run happened. The
  committed `evidence/check-<sha>.log` is what carries that claim; the receipt is only the
  interlock that stops a push from preceding it.
- **Not tested here:** a multi-ref push (several shas in one invocation, each needing its own
  receipt). The code path is a loop over the ref lines and is shared with the single-ref case
  exercised above, but "shared code path" is an argument, not a fixture.
