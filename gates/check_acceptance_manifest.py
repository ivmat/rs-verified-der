#!/usr/bin/env python3
"""check_acceptance_manifest.py — validate this repo's acceptance manifest against the PINNED,
vendored validator. Pure stdlib apart from the vendored tool it invokes.

`der-verified/acceptance.toml` — inside the PACKAGE root, so it ships to registry consumers — is
this crate's machine-readable certificate: what is claimed, at what grade, on what evidence, and
— the part that matters — what is NOT weighted and why. It is
GENERATED. Nothing in this repo should ever hand-edit it, and this gate is one half of why that
rule holds: if the file is edited into a shape the validator refuses, the gate fails closed.

Two things are deliberately pinned rather than resolved at runtime:

  * The VALIDATOR is vendored under `gates/vendor/acceptance-format/` at a recorded commit
    (see that directory's VENDOR.md). A gate that fetched the validator, or imported whatever
    version happened to be installed, would silently change what "valid" means underneath a
    published crate. The whole point of a certificate is that its checker does not drift.
  * The manifest's own `validator_sha` must MATCH that pin. A manifest generated against one
    revision of the format and checked against another is not a checked manifest, and this gate
    refuses that combination rather than reporting a green it cannot justify.

`--strict --strict-weight` are not optional here. `--strict` turns transitional allowances into
errors; `--strict-weight` makes the weighted count answer to the evidence rules rather than to the
manifest's own say-so. Running the validator without them would check a weaker thing than the
number this crate publishes.

Usage:
    python3 gates/check_acceptance_manifest.py           (the gate; wired into check_fast.sh + check.sh)
"""
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# The manifest and its evidence store live inside the PACKAGE root, not the repo root (owner
# ruling R-8, 2026-08-30). A crate published to a registry must carry its own checkable surface:
# placed at the repo root they would reach people reading GitHub but NOT the consumer who
# installed the crate from crates.io — who is exactly the audience the exposure exists for.
# `record` pointers are therefore package-root-relative, and Cargo.toml's `include` ships both.
PACKAGE = ROOT / "der-verified"
MANIFEST = PACKAGE / "acceptance.toml"
VENDOR = ROOT / "gates" / "vendor" / "acceptance-format"
VALIDATOR = VENDOR / "check_acceptance.py"
VENDOR_DOC = VENDOR / "VENDOR.md"
# The projected public evidence store: neutral, generated views of the internal verification
# records, committed so a public reader can resolve and re-hash what the manifest cites.
STORE = PACKAGE / "evidence" / "acceptance-records"

# The commit of the format repo this validator was vendored from. Kept here as well as in
# VENDOR.md so the gate can CHECK the manifest against it rather than trust a prose note.
#
# It must be a PUBLICLY RESOLVABLE commit. A manifest pinning a commit that exists only in a
# private working repo cannot be reproduced by the people it is published for, and leaks a private
# identifier besides. The binding that matters is CONTENT, not the commit id -- so re-pinning to a
# public commit carrying byte-identical files is a provenance correction and does not invalidate
# any evidence.
PINNED_SPEC_SHA = "c8c00bb"

# Content hashes of the vendored files. Pinning by COMMIT alone is a promise; this is the check.
# Without it the gate's whole rationale is defeatable by editing the vendored validator to return
# 0 -- the gate would then faithfully report the green of a tool nobody pinned.
VENDORED_SHA256 = {
    "check_acceptance.py": "d3dfd2069dabec7e7020e9ffec68ecac7058f896ded37a080c5a34dbb77e8be3",
    "m11.py": "501a5116b63f06d396d45e578e885db041f06a0e54068015d0fd0d7a87ff989d",
    "acceptance_grammar.py": "c6529560feac9cd8c4202e61b9740d0e529553ecc06aa53a25205e9702b201ac",
}

# A short git sha is ambiguous below ~7 hex; anything shorter is not an identification. The
# prefix relation is intentionally two-way (the manifest may record a longer sha than we pin),
# but BOTH sides must be hex and at least this long, or "b" would satisfy "bd1c995".
_MIN_SHA = 7
_SHA_RE = re.compile(r"\A[0-9a-f]{%d,40}\Z" % _MIN_SHA)


def fail(msg):
    print(f"FAIL check_acceptance_manifest: {msg}", file=sys.stderr)
    return 1


def main():
    for path, what in ((MANIFEST, "manifest"), (VALIDATOR, "vendored validator"),
                       (VENDOR_DOC, "vendor pin note")):
        if not path.exists():
            return fail(f"{what} missing at {path.relative_to(ROOT)}")

    # The pin is duplicated in VENDOR.md for a human to read. Duplication is where drift lives, so
    # check the two agree rather than trusting whoever last re-vendored to have updated both. The
    # constants in THIS file stay authoritative -- prose is not parsed for identity anywhere else
    # in this repo, and it is not made authoritative here either.
    doc = VENDOR_DOC.read_text(encoding="utf-8")
    if PINNED_SPEC_SHA not in doc:
        return fail(f"gates/vendor/acceptance-format/VENDOR.md does not record the pinned commit "
                    f"{PINNED_SPEC_SHA!r} this gate enforces — the note and the gate disagree "
                    f"about which validator this crate is checked by")
    for name, expected in sorted(VENDORED_SHA256.items()):
        if expected not in doc:
            return fail(f"VENDOR.md does not record the sha256 this gate enforces for {name} — "
                        f"the note and the gate disagree about what was vendored")

    # The vendored tool must be the tool that was vendored. Check before trusting its verdict.
    for name, expected in sorted(VENDORED_SHA256.items()):
        path = VENDOR / name
        if not path.exists():
            return fail(f"vendored file missing: gates/vendor/acceptance-format/{name}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            return fail(
                f"vendored gates/vendor/acceptance-format/{name} does not match its recorded "
                f"sha256 (expected {expected}, got {actual}). Either it was edited in place -- "
                f"which VENDOR.md forbids -- or it was re-vendored without updating the pin. "
                f"Do not 'fix' this by pasting the new hash in: re-vendor deliberately, re-emit "
                f"acceptance.toml, and record why."
            )

    text = MANIFEST.read_text(encoding="utf-8")

    # The manifest must have been generated against the SAME revision this gate checks it with.
    m = re.search(r'^\s*validator_sha\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        return fail("acceptance.toml declares no validator_sha — cannot confirm it was generated "
                    "against the vendored validator")
    declared = m.group(1).strip().lower()
    if not _SHA_RE.match(declared):
        return fail(
            f"acceptance.toml declares validator_sha {declared!r}, which is not a hex sha of at "
            f"least {_MIN_SHA} characters. A prefix shorter than that identifies nothing -- under "
            f"a bare two-way prefix test even 'b' would satisfy the pin."
        )
    if not (declared.startswith(PINNED_SPEC_SHA) or PINNED_SPEC_SHA.startswith(declared)):
        return fail(
            f"acceptance.toml was generated against validator_sha {declared!r} but this repo "
            f"vendors {PINNED_SPEC_SHA!r} (gates/vendor/acceptance-format/VENDOR.md). Re-emit the "
            f"manifest, or re-vendor the validator — do not edit either to agree with the other."
        )

    # The generated-file banner must be the FIRST thing in the file, not merely present somewhere
    # in it: a substring search over the whole text is satisfied by the phrase appearing inside
    # any claim's free-text description, which is exactly the case where it would be doing no
    # work. This is a readability guarantee for whoever opens the file next, not a tamper check —
    # the validator run below is what actually decides whether the content is sound.
    first_line = next((ln for ln in text.splitlines() if ln.strip()), "")
    if "DO NOT HAND-EDIT" not in first_line.upper():
        return fail(
            f"acceptance.toml does not open with its generated-file banner (first non-empty line "
            f"is {first_line[:60]!r}). It is emitted, never hand-written, and must say so on the "
            f"line a reader sees first."
        )

    # The evidence store is GENERATED and COMMITTED, which makes drift between it and the manifest
    # a real failure mode with two directions — and the validator closes only one. It resolves and
    # re-hashes the records a claim CITES (re-hashing only on weighted claims), so it cannot see a
    # projection that no claim cites any more. An orphan is not harmless: it sits in the published
    # tree looking exactly like evidence for a claim nobody makes. Both directions checked here.
    cited = set()
    for m_rec in re.finditer(r'^\s*record\s*=\s*"([^"]+)"', text, re.MULTILINE):
        rel = m_rec.group(1)
        # Resolved against the MANIFEST's own directory, which is what a relative `record` means
        # to the validator and to any consumer who unpacked the crate — not against the repo root,
        # which a crates.io consumer does not even have.
        path = (MANIFEST.parent / rel).resolve()
        if not path.is_file():
            return fail(f"acceptance.toml cites a record that does not resolve: {rel!r}. A public "
                        f"manifest whose records cannot be fetched cannot be checked by the people "
                        f"it is published for.")
        try:
            path.relative_to(STORE.resolve())
        except ValueError:
            return fail(f"acceptance.toml cites a record OUTSIDE the published evidence store: "
                        f"{rel!r}. Records must resolve within "
                        f"{STORE.relative_to(ROOT).as_posix()}/ — a pointer out of the tree is "
                        f"either a private-store leak or a link no reader can follow.")
        cited.add(path)

    if not cited:
        return fail("acceptance.toml cites no evidence records at all — a manifest with no "
                    "resolvable evidence is not a certificate")

    orphans = sorted(p.name for p in {q.resolve() for q in STORE.glob("*.json")} - cited)
    if orphans:
        return fail(
            f"{len(orphans)} projected record(s) in {STORE.relative_to(ROOT).as_posix()}/ are not "
            f"cited by acceptance.toml: {orphans[:5]}{' ...' if len(orphans) > 5 else ''}. Re-emit "
            f"the manifest and the store together — the emitter deletes records that stop being "
            f"cited, so an orphan means the two came from different runs."
        )

    r = subprocess.run(
        [sys.executable, str(VALIDATOR), "--strict", "--strict-weight", str(MANIFEST)],
        capture_output=True, text=True,
    )
    out = (r.stdout + r.stderr).strip()
    if r.returncode != 0:
        return fail(f"vendored validator rejected acceptance.toml:\n{out}")

    summary = out.splitlines()[-1] if out else "(no output)"
    print(f"PASS check_acceptance_manifest: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
