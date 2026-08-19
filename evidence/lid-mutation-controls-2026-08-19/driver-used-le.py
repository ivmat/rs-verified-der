#!/usr/bin/env python3
"""Negative control for the new decode_length_used_le / length_decode_used_le theorems.

Plants ONE statement mutation per lid (the no-over-read comparison `≤` -> `<`, in both the
triple and the equation form so the mutation is a coherent, FALSE statement of the property
rather than a shape the derivation line alone rejects), runs `lake build DerVerified` from
lean/, records the log, reverts with `git checkout --`, confirms byte-identical sha256, and
re-builds.
"""
import hashlib, json, os, shutil, subprocess, time

ROOT = "/home/ivo/repo/rs-verified-der"
OUT = os.path.join(ROOT, "evidence/lid-mutation-controls-2026-08-19")
LEAN = os.path.join(ROOT, "lean")

MUT = [
    ("M7-length-used-le", "LengthProofs.lean",
     "flip the no-over-read comparison in decode_length_used_le(_spec) from <= to < "
     "(false whenever a decode consumes the whole input, e.g. the 1-byte short form)"),
    ("M8-tlv-used-le", "TlvProofs.lean",
     "same flip in this pass's length_decode_used_le / decode_length_used_le_spec"),
    ("M9-sequence-used-le", "SequenceProofs.lean",
     "same flip in this pass's length_decode_used_le / decode_length_used_le_spec"),
]

OLD_SPEC = "        r = core.result.Result.Ok (v, used) → used.val ≤ s.val.length ⦄ := by"
NEW_SPEC = "        r = core.result.Result.Ok (v, used) → used.val < s.val.length ⦄ := by"
OLD_EQ = "      l_used.val ≤ s.val.length := by"
NEW_EQ = "      l_used.val < s.val.length := by"


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
    assert OLD_SPEC in src and OLD_EQ in src, fname
    mutated = src.replace(OLD_SPEC, NEW_SPEC, 1).replace(OLD_EQ, NEW_EQ, 1)
    open(path, "w").write(mutated)
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

json.dump(results, open(os.path.join(OUT, "results-used-le.json"), "w"), indent=1)
