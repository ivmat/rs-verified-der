#!/usr/bin/env python3
"""Re-witness campaign driver: the five modules whose red mutation-control legs could not be
carried across 69bbc9f -> 402719a.

Why this campaign exists. The stale-control policy refuses to DERIVE which file a mutated
(red-expectation) leg touched -- a red leg must name its own mutated dependency, and no campaign
before 2026-08-29 ever recorded that field. So every pre-08-29 red leg is unimportable, and five
contract-grade claims (length, tag, integer, big_integer, oid) were left with only their GREEN
reverted legs: a check nobody watched fail. Their sources are byte-identical across that range,
so the documented mutations re-apply verbatim and re-witness the same result. This run produces
that evidence FRESH at 402719a, with the dependency recorded explicitly.

Protocol (follows the 2026-08-19 campaign, the most mechanically reproducible of the three):
every mutation is an exact-string replacement that HARD-FAILS unless its anchor occurs exactly
once; predictions are written BEFORE any harness runs; each mutation is applied to a pristine
file, observed, then reverted and confirmed byte-identical by sha256 before the next one.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "der-verified" / "src"
OUT = ROOT / "campaign-out"
LOGS = OUT / "logs"


def sha256(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def comment_out(block):
    """Comment out every line, preserving each line's own indentation."""
    lines = block.split("\n")
    out = []
    for ln in lines:
        if ln.strip() == "":
            out.append(ln)
            continue
        indent = ln[: len(ln) - len(ln.lstrip())]
        out.append(f"{indent}// {ln.lstrip()}")
    return "\n".join(out)


LEN_A_OLD = """    if val < 0x80 {
        return Err(LengthError::NonMinimal); // long form for a short-form value
    }"""

TAG_A_OLD = """    if number <= 30 {
        return Err(TagError::NonMinimal); // high-tag form for a low-tag-representable number
    }"""

INT_A_OLD = """    if content.len() >= 2 {
        let c0 = content[0];
        let c1 = content[1];
        if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
            return Err(IntError::NonMinimal);
        }
    }"""

OID_A_OLD = """        if at_subid_start && b == 0x80 {
            return Err(OidError::NonMinimalSubid);
        }"""

# defect ids mirror the original campaigns' own labels (LEN-A, TAG-A, INT-A, BIG-A, OID-A, OID-B)
MUTATIONS = [
    {
        "id": "R1", "defect": "LEN-A", "module": "length", "file": "length.rs",
        "fn": "decode_length",
        "old": LEN_A_OLD, "new": comment_out(LEN_A_OLD),
        "description": "LEN-A: length::decode_length long-form minimality check removed "
                       "(the `val < 0x80` rejection commented out), so a long-form encoding of a "
                       "short-form-representable value is wrongly accepted",
        "red": [
            ("R1-length-mutated-classify", "length::proofs::long_form_of_short_value_is_non_minimal"),
            ("R1-length-mutated-canonical", "length::proofs::decode_accepts_only_canonical"),
        ],
        "reverted": ("R1-length-reverted-classify",
                     "length::proofs::long_form_of_short_value_is_non_minimal"),
    },
    {
        "id": "R2", "defect": "TAG-A", "module": "tag", "file": "tag.rs",
        "fn": "decode_tag",
        "old": TAG_A_OLD, "new": comment_out(TAG_A_OLD),
        "description": "TAG-A: tag::decode_tag high-tag minimality check removed (the "
                       "`number <= 30` rejection commented out), so a high-tag form of a "
                       "low-tag-representable number is wrongly accepted",
        "red": [
            ("R2-tag-mutated-classify", "tag::proofs::high_tag_of_small_number_is_non_minimal"),
            ("R2-tag-mutated-canonical", "tag::proofs::decode_tag_accepts_only_canonical"),
        ],
        "reverted": ("R2-tag-reverted-classify",
                     "tag::proofs::high_tag_of_small_number_is_non_minimal"),
    },
    {
        "id": "R3", "defect": "INT-A", "module": "integer", "file": "integer.rs",
        "fn": "decode_integer",
        "old": INT_A_OLD, "new": comment_out(INT_A_OLD),
        "description": "INT-A: integer::decode_integer redundant-padding minimality check "
                       "removed (the two-octet 0x00/0xFF padding rejection commented out), so "
                       "non-minimal integer encodings are wrongly accepted",
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
        "id": "R4", "defect": "BIG-A", "module": "big_integer", "file": "big_integer.rs",
        "fn": "validate_integer_content",
        "old": "        let c1 = content[1];", "new": "        let c1 = content[0];",
        "description": "BIG-A: big_integer::validate_integer_content wrong index -- `c1` is bound "
                       "to content[0] a second time instead of content[1], so the minimality "
                       "check no longer inspects the byte X.690 8.3.2 keys on",
        "red": [("R4-bigint-mutated-oracle", "big_integer::proofs::validate_iff_minimal_oracle")],
        "reverted": ("R4-bigint-reverted-oracle",
                     "big_integer::proofs::validate_iff_minimal_oracle"),
    },
    {
        "id": "R5", "defect": "OID-A", "module": "oid", "file": "oid.rs",
        "fn": "validate_oid",
        "old": OID_A_OLD, "new": comment_out(OID_A_OLD),
        "description": "OID-A: oid::validate_oid subidentifier minimality check removed (the "
                       "redundant leading 0x80 rejection commented out), so non-minimal "
                       "subidentifiers are wrongly accepted",
        "red": [
            ("R5-oidA-leading", "oid::proofs::leading_0x80_is_non_minimal"),
            ("R5-oidA-later", "oid::proofs::later_0x80_is_non_minimal"),
        ],
        "reverted": ("R5-oidA-reverted", "oid::proofs::leading_0x80_is_non_minimal"),
    },
    {
        "id": "R6", "defect": "OID-B", "module": "oid", "file": "oid.rs",
        "fn": "validate_oid",
        "old": "        if at_subid_start && b == 0x80 {",
        "new": "        if at_subid_start && i == 0 && b == 0x80 {",
        "description": "OID-B: oid::validate_oid subidentifier minimality NARROWED to the first "
                       "octet only (`i == 0` conjunct added), so a redundant 0x80 opening a LATER "
                       "subidentifier is wrongly accepted while the leading case still rejects",
        "red": [("R6-oidB-later", "oid::proofs::later_0x80_is_non_minimal")],
        "reverted": ("R6-oidB-reverted", "oid::proofs::later_0x80_is_non_minimal"),
    },
]


def apply_exact(path, old, new):
    text = path.read_text(encoding="utf-8")
    n = text.count(old)
    if n != 1:
        sys.exit(f"FATAL: anchor occurs {n} times (expected exactly 1) in {path.name}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def run_harness(name, fq):
    log = LOGS / f"{name}.log"
    cmd = ["cargo", "kani", "--manifest-path", "der-verified/Cargo.toml",
           "--harness", fq, "--exact", "-Z", "stubbing"]
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

    # 1. Baselines, recorded before anything is touched.
    files = sorted({m["file"] for m in MUTATIONS})
    baseline = {f: sha256(SRC / f) for f in files}
    (OUT / "baseline-sha256.txt").write_text(
        "".join(f"{h}  der-verified/src/{f}\n" for f, h in sorted(baseline.items())), encoding="utf-8")

    # 2. PREREGISTER predictions -- written to disk before a single harness runs, so the
    #    prediction cannot be edited to match what was observed.
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

        # revert from git and PROVE the revert byte-identical before continuing
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
