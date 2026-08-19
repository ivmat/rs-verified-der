#!/usr/bin/env python3
"""Negative control for the new length_decode_total corollaries (TlvProofs, SequenceProofs).

Plants ONE statement mutation per lid: the totality conclusion `∃ r, decode_length s = ok r`
(the Result-monad succeeds) is strengthened into `∃ v used, decode_length s = ok (.Ok (v, used))`
(the decode always ACCEPTS). That is the natural overclaim one step past the true statement, and
it is FALSE -- the empty slice decodes to `ok (.Err Truncated)`, so no `(v, used)` witnesses it.

Same protocol as driver-used-le.py: run `lake build DerVerified` from lean/, record the log,
revert with `git checkout --`, confirm byte-identical sha256, re-build.
"""
import hashlib, json, os, subprocess, time

ROOT = "/home/ivo/repo/rs-verified-der"
OUT = os.path.join(ROOT, "evidence/lid-mutation-controls-2026-08-19")
LEAN = os.path.join(ROOT, "lean")

MUT = [
    ("M10-tlv-total", "TlvProofs.lean",
     "strengthen length_decode_total from totality (the Result monad succeeds) to acceptance "
     "(the decode always returns Ok) -- false for the empty slice, which returns Err Truncated"),
    ("M11-sequence-total", "SequenceProofs.lean",
     "same strengthening in this pass's copy"),
]

OLD = ("    ∃ r : core.result.Result (U32 × Usize) length.LengthError, "
       "length.decode_length s = ok r := by")
NEW = ("    ∃ (v : U32) (used : Usize), "
       "length.decode_length s = ok (core.result.Result.Ok (v, used)) := by")


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def build(logpath):
    t = time.time()
    r = subprocess.run(["lake", "build", "DerVerified"], cwd=LEAN,
                       capture_output=True, text=True)
    wall = round(time.time() - t, 1)
    with open(logpath, "w") as f:
        f.write(r.stdout + r.stderr)
    return r.returncode, wall


results = []
for mid, fname, desc in MUT:
    path = os.path.join(LEAN, fname)
    base = sha(path)
    src = open(path).read()
    assert src.count(OLD) == 1, fname
    open(path, "w").write(src.replace(OLD, NEW, 1))
    subprocess.run(["git", "diff", "--", "lean/" + fname], cwd=ROOT,
                   stdout=open(os.path.join(OUT, mid + ".diff"), "w"))
    rc_m, w_m = build(os.path.join(OUT, mid + "-mutated.log"))
    subprocess.run(["git", "checkout", "--", "lean/" + fname], cwd=ROOT, check=True)
    rest = sha(path)
    rc_r, w_r = build(os.path.join(OUT, mid + "-reverted.log"))
    results.append({
        "id": mid, "file": fname, "kind": "statement", "desc": desc,
        "baseline_sha256": base, "restored_sha256": rest,
        "byte_identical": base == rest,
        "mutated_rc": rc_m, "mutated_wall": w_m,
        "reverted_rc": rc_r, "reverted_wall": w_r,
        "observed": "RED" if rc_m != 0 else "GREEN (CONTROL FAILED)",
    })
    print(json.dumps(results[-1], indent=1))

json.dump(results, open(os.path.join(OUT, "results-total.json"), "w"), indent=1)
