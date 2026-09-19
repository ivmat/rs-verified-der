#!/usr/bin/env python3
"""Re-witness campaign driver: the three Kani mutation-control legs (big_integer, integer, tlv)
whose source files gained unrelated EOF `#[test]` additions between the campaigns that last
witnessed them (402719a) and the current HEAD (d05d3f2) -- the P3 stale-control policy is
per-WHOLE-FILE, so those additions void the carry-over even though the mutated function itself
is untouched. This campaign re-applies the SAME documented mutation, verbatim, against the
current source and records the fresh result. It does NOT touch length/tag/oid (unaffected --
still carry over) or sequence/set_of (unaffected).

Mutation text re-applied verbatim from the ORIGINAL campaign specs:
  - BIG-A (big_integer): mutation-controls-2026-08-30-five-modules/run_campaign.py
  - INT-A (integer):      mutation-controls-2026-08-30-five-modules/run_campaign.py
  - tlv off-by-one:       mutation-controls-2026-08-29-seq-tlv-setof (README-documented; no
                          committed driver script existed for that campaign, so the anchor is
                          re-derived here directly from tlv.rs's own decode_tlv, and is the
                          production `Ok((..., end))` return line the README's prose names).

Protocol (identical to the 2026-08-29/08-30 campaigns): baseline sha256 of all three files
recorded before anything is touched; predictions preregistered to disk before any harness runs;
every mutation is an exact-string replacement that HARD-FAILS unless its anchor occurs exactly
once; each mutation applied to a pristine file, observed, then reverted and confirmed
byte-identical by sha256 before the next is applied.

Command shape per leg (matching check-d05d3f2's own convention, the 2026-09-18 Law-1 relaxation):
  systemd-run --user --unit=<name> -p MemoryMax=24G -p MemorySwapMax=0 --wait --pipe --collect -- \\
      cargo kani --manifest-path der-verified/Cargo.toml --harness <fq> --exact -Z stubbing
one leg at a time, sequentially, no other box work concurrent.
"""
import hashlib
import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent  # rs-verified-der/
SRC = ROOT / "der-verified" / "src"
OUT = pathlib.Path(__file__).resolve().parent
LOGS = OUT / "logs"


def sha256(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


BIG_A_OLD = "        let c1 = content[1];"
BIG_A_NEW = "        let c1 = content[0];"

INT_A_OLD = """    if content.len() >= 2 {
        let c0 = content[0];
        let c1 = content[1];
        if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
            return Err(IntError::NonMinimal);
        }
    }"""
INT_A_NEW = """    // if content.len() >= 2 {
    //     let c0 = content[0];
    //     let c1 = content[1];
    //     if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
    //         return Err(IntError::NonMinimal);
    //     }
    // }"""

TLV_OLD = "    Ok((Tlv { tag, value: &input[header..end] }, end))"
TLV_NEW = "    Ok((Tlv { tag, value: &input[header..end] }, end + 1))"

MUTATIONS = [
    {
        "id": "R4", "defect": "BIG-A", "module": "big_integer", "file": "big_integer.rs",
        "fn": "validate_integer_content",
        "old": BIG_A_OLD, "new": BIG_A_NEW,
        "description": "BIG-A: big_integer::validate_integer_content wrong index -- `c1` is "
                       "bound to content[0] a second time instead of content[1], so the "
                       "minimality check no longer inspects the byte X.690 8.3.2 keys on "
                       "(re-witness of mutation-controls-2026-08-30-five-modules' R4, verbatim)",
        "red": [("R4-bigint-mutated-oracle", "big_integer::proofs::validate_iff_minimal_oracle")],
        "reverted": ("R4-bigint-reverted-oracle",
                     "big_integer::proofs::validate_iff_minimal_oracle"),
    },
    {
        "id": "R3", "defect": "INT-A", "module": "integer", "file": "integer.rs",
        "fn": "decode_integer",
        "old": INT_A_OLD, "new": INT_A_NEW,
        "description": "INT-A: integer::decode_integer redundant-padding minimality check "
                       "removed (the two-octet 0x00/0xFF padding rejection commented out), so "
                       "non-minimal integer encodings are wrongly accepted (re-witness of "
                       "mutation-controls-2026-08-30-five-modules' R3, verbatim)",
        "red": [
            ("R3-integer-mutated-minimal", "integer::proofs::decode_accepts_only_minimal"),
            ("R3-integer-mutated-positive-padding",
             "integer::proofs::redundant_positive_padding_is_non_minimal"),
            ("R3-integer-mutated-negative-padding",
             "integer::proofs::redundant_negative_padding_is_non_minimal"),
        ],
        "reverted": ("R3-integer-reverted-minimal", "integer::proofs::decode_accepts_only_minimal"),
    },
    {
        "id": "R7", "defect": "TLV-A", "module": "tlv", "file": "tlv.rs",
        "fn": "decode_tlv",
        "old": TLV_OLD, "new": TLV_NEW,
        "description": "TLV-A: tlv::decode_tlv reports its consumed count off by one "
                       "(`end` -> `end + 1` in the returned tuple; the value borrow itself "
                       "still uses the correct `end`), so a structurally-correct decode "
                       "misreports how much input it consumed (re-witness of "
                       "mutation-controls-2026-08-29-seq-tlv-setof's tlv leg, verbatim defect, "
                       "re-derived anchor since that campaign shipped no committed driver script)",
        "red": [
            ("R7-tlv-mutated-structure", "tlv::proofs::decode_tlv_structure"),
            ("R7-tlv-mutated-roundtrip", "tlv::proofs::tlv_roundtrip_small"),
        ],
        "reverted": ("R7-tlv-reverted-structure", "tlv::proofs::decode_tlv_structure"),
    },
]


def apply_exact(path, old, new):
    text = path.read_text(encoding="utf-8")
    n = text.count(old)
    if n != 1:
        sys.exit(f"FATAL: anchor occurs {n} times (expected exactly 1) in {path.name}")
    path.write_text(text.replace(old, new), encoding="utf-8")


import os

_CORRECTED_PATH = os.pathsep.join([
    str(pathlib.Path.home() / ".cargo" / "bin"),
    str(pathlib.Path.home() / ".elan" / "bin"),
    str(pathlib.Path.home() / ".local" / "bin"),
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
    "/usr/games", "/usr/local/games",
])


def run_harness(name, fq):
    log = LOGS / f"{name}.log"
    unit = f"der-control-refresh-{name}-{int(time.time())}"
    cmd = [
        "systemd-run", "--user", f"--unit={unit}", "--quiet",
        "-p", "MemoryMax=24G", "-p", "MemorySwapMax=0",
        "-p", f"Environment=PATH={_CORRECTED_PATH}",
        "-p", f"WorkingDirectory={ROOT}",
        "--wait", "--pipe", "--collect", "--",
        "cargo", "kani", "--manifest-path", "der-verified/Cargo.toml",
        "--harness", fq, "--exact", "-Z", "stubbing",
    ]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    log.write_text(r.stdout + r.stderr, encoding="utf-8")
    body = r.stdout + r.stderr
    if "VERIFICATION:- SUCCESSFUL" in body:
        return "SUCCESSFUL"
    if "VERIFICATION:- FAILED" in body:
        return "FAILED"
    return "INDETERMINATE"


def main():
    LOGS.mkdir(parents=True, exist_ok=True)

    files = sorted({m["file"] for m in MUTATIONS})
    baseline = {f: sha256(SRC / f) for f in files}
    (OUT / "baseline-sha256.txt").write_text(
        "".join(f"{h}  der-verified/src/{f}\n" for f, h in sorted(baseline.items())), encoding="utf-8")

    pre = []
    for m in MUTATIONS:
        for name, fq in m["red"]:
            pre.append((name, m["module"], fq, "mutated", "RED"))
        rn, rfq = m["reverted"]
        pre.append((rn, m["module"], rfq, "reverted", "GREEN"))
    (OUT / "predictions.tsv").write_text(
        "run\tmodule\tharness\tleg\tpredicted\n"
        + "".join("\t".join(r) + "\n" for r in pre), encoding="utf-8")
    print(f"preregistered {len(pre)} predictions")

    results = []
    for m in MUTATIONS:
        path = SRC / m["file"]
        assert sha256(path) == baseline[m["file"]], f"{m['file']} not pristine before {m['id']}"
        apply_exact(path, m["old"], m["new"])
        mutated_sha = sha256(path)
        assert mutated_sha != baseline[m["file"]], "mutation was a no-op"
        print(f"{m['id']} {m['defect']}: mutation applied to {m['file']}")

        for name, fq in m["red"]:
            v = run_harness(name, fq)
            print(f"  {name}: predicted RED, observed {v}")
            results.append({"run": name, "module": m["module"], "harness": fq, "leg": "mutated",
                            "predicted": "RED", "observed": v, "file": m["file"],
                            "defect": m["description"]})

        subprocess.run(["git", "checkout", "--", f"der-verified/src/{m['file']}"],
                       cwd=ROOT, check=True)
        assert sha256(path) == baseline[m["file"]], f"revert of {m['file']} not byte-identical"
        print(f"  reverted {m['file']}: sha256 byte-identical to baseline")

        rn, rfq = m["reverted"]
        v = run_harness(rn, rfq)
        print(f"  {rn}: predicted GREEN, observed {v}")
        results.append({"run": rn, "module": m["module"], "harness": rfq, "leg": "reverted",
                        "predicted": "GREEN", "observed": v, "file": m["file"],
                        "defect": m["description"]})

    final = {f: sha256(SRC / f) for f in files}
    (OUT / "final-sha256.txt").write_text(
        "".join(f"{h}  der-verified/src/{f}\n" for f, h in sorted(final.items())), encoding="utf-8")
    assert final == baseline, "tree not restored to baseline"

    (OUT / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    with (OUT / "verdicts.tsv").open("w", encoding="utf-8") as fh:
        fh.write("run\tmodule\tharness\tleg\tpredicted\tobserved\n")
        for r in results:
            fh.write(f"{r['run']}\t{r['module']}\t{r['harness']}\t{r['leg']}\t"
                     f"{r['predicted']}\t{r['observed']}\n")

    ok = all((r["predicted"] == "RED") == (r["observed"] == "FAILED") for r in results)
    print(f"\nALL {len(results)} legs matched prediction: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
