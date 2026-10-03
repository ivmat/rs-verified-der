# Planted-satisfied twins, re-run at the final bytes — 2026-10-03

This directory holds six single-harness Kani runs. They re-witness, at the bytes this repository now ships, the three
covers that `PROOF_MANIFEST.md` §8.2 discloses as **known-unsatisfiable at their bound**, each next to the companion
harness that witnesses the same path on a concrete input. They are the **planted-satisfied twin** evidence for the
claims `PM/x509_validity`, `PM/x509_extension` and `PM/x509_tbs_certificate`: the method is described in
[`../PLANTED-SATISFIED-TWINS-2026-08-18.md`](../PLANTED-SATISFIED-TWINS-2026-08-18.md). The logs are under `logs/`.

An unsatisfiable cover proves nothing until something has been seen to satisfy it. Each pair therefore holds one log
where the disclosed cover is **not** satisfied (the baseline) and one where the companion's cover **is** satisfied
(the twin).

## 1. Prediction, committed before any run

The prediction is `PROOF_MANIFEST.md` §8.2, the generated table "Harness whose `cover` is UNSATISFIABLE at its
bound / Companion witness harness", as committed at the capture commit `42c8165`. That commit was made at
`2026-10-03T13:52:02+02:00` (11:52:02Z), before every run recorded here (the earliest started at `2026-10-03T21:54:29Z`).
The capture commit is a pre-squash commit and is not part of the published history. The published squash head
`17ee51e` has exactly the same tree (`git rev-parse 17ee51e^{tree}` prints `1f938d215b692ad117191f1add9418771be82169`,
the tree of the capture commit), so §8.2 of `PROOF_MANIFEST.md` at the squash head holds the same table. The squash
commit itself is dated after the runs, because it was created after them; the order "prediction, then observation"
rests on the capture commit's date, which a reader can not check in the published history.
The pairing itself is older: all three companion names have been in the manifest since 2026-07-30. The table reads:

| Harness whose cover is unsatisfiable at its bound | Companion witness harness | Companion uses `#[kani::stub]`? |
|---|---|---|
| `x509_extension::validate_extensions_never_panics` | `x509_extension::validate_extensions_ok_path_witnessed` | no |
| `x509_tbs_certificate::parse_tbs_certificate_never_panics` | `x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed` | **yes** — read it as glue reachability only |
| `x509_validity::parse_never_panics` | `x509_validity::parse_validity_ok_path_witnessed` | no |

So the prediction for each pair is: baseline `0 of 1 cover properties satisfied` (cover status `vacuous`), twin
`1 of 1 cover properties satisfied` (cover status `held`), and `VERIFICATION:- SUCCESSFUL` in both.

## 2. The six runs

All six ran at the capture commit `42c8165`, with Kani `0.67.0`, CBMC `6.8.0`, CaDiCaL `2.0.0`, one harness per run
(`cargo kani -Z stubbing --manifest-path der-verified/Cargo.toml --harness <h> --exact`), sequentially, each inside a
detached, memory-capped `systemd --user` service (`MemorySwapMax=0`). Each log is the complete tool output of one
run, unedited (it is not a distillation; the two `x509_extension` logs additionally start with a short `#` header,
see §5), and ends with the tool's own `Complete - 1 successfully verified
harnesses, 0 failures, 1 total.`

| log (under `logs/`) | harness | role | observed cover | cap | unit | peak | sha256 of the log |
|---|---|---|---|---|---|---|---|
| `x509_validity-unsat-16B-42c8165.log` | `x509_validity::proofs::parse_never_panics` | baseline | `0 of 1` | 20G | `kani1-x509-validity--proofs--parse-never-panics--737966` | `967.1M` | `72684492af4d17c8aaea2d369c6fdd162d5b7e147b2dbc6bf9a5c1b5e372e422` |
| `x509_validity-sat-32B-concrete-witness-42c8165.log` | `x509_validity::proofs::parse_validity_ok_path_witnessed` | twin | `1 of 1` | 20G | `kani1-x509-validity--proofs--parse-validity-ok-path-witnessed--738057` | `717.9M` | `f7a9374ec59a3cda85c2b98ca18fadcbf664471f926b9fd641f0c9f51498baca` |
| `x509_extension-unsat-13B-42c8165.log` | `x509_extension::proofs::validate_extensions_never_panics` | baseline | `0 of 1` | 24G | `kani1-x509-extension--proofs--validate-extensions-never-panics--736649` | `20G` | `ed4451c79307e7d3ce9a16e2f1388c49fad7990ba3e2b30e436970788f41d1ac` |
| `x509_extension-sat-16B-concrete-witness-42c8165.log` | `x509_extension::proofs::validate_extensions_ok_path_witnessed` | twin | `1 of 1` | 24G | `kani1-x509-extension--proofs--validate-extensions-ok-path-witnesse-737283` | `16.7G` | `3a82f7f0db733234b73a9c0a3c2b8dbf34ad2e20a67e126535e3c10af7318c2c` |
| `x509_tbs_certificate-unsat-10B-42c8165.log` | `x509_tbs_certificate::proofs::parse_tbs_certificate_never_panics` | baseline | `0 of 1` | 20G | `kani1-x509-tbs-certificate--proofs--parse-tbs-certificate-never-pa-738133` | `5.5G` | `4a76bc3ffe3e7d1c84ac0f54b5c58a6722dc303a7efcfb5018aea5cfafc518b5` |
| `x509_tbs_certificate-sat-135B-concrete-witness-42c8165.log` | `x509_tbs_certificate::proofs::parse_tbs_certificate_ok_path_witnessed` | twin | `1 of 1` | 20G | `kani1-x509-tbs-certificate--proofs--parse-tbs-certificate-ok-path--738270` | `11.6G` | `f200e209e69659f4588550b5a06af7f3cdbccf121a3e2168b598e3de9d87e6c5` |

The "observed cover" column quotes the `** N of 1 cover properties satisfied` summary line of the log. The "peak"
column is the memory peak journald printed when the unit ended; where a run's peak was not read, the cell says
`NOT CAPTURED` and that is a disclosed gap, not a value.

What the twins are, in one line each:

- **x509_validity**: a concrete 32-octet specimen with two `UTCTime` fields, run through the real, unstubbed
  `parse_validity`.
- **x509_extension**: a concrete 16-octet specimen holding two `Extension` members, run through the real, unstubbed
  `validate_extensions`.
- **x509_tbs_certificate**: a concrete 135-octet v1 `TBSCertificate` specimen under **three** stubs. The third stub
  (`parse_validity`) is what makes the `Ok` tail reachable at all, so this twin witnesses glue reachability under
  stub semantics. It is not evidence that the real sub-parsers accept the specimen.

## 3. Capture commit versus attribution commit

The runs were captured on the source tree of commit `42c8165` (the "capture commit"; the header of each distilled log
and every run record names it). The capture commit is a pre-squash commit and is not part of the published history.
The published squash head `17ee51e` has the same tree: `git rev-parse 17ee51e^{tree}` prints
`1f938d215b692ad117191f1add9418771be82169`, which is the tree of the capture commit. This directory is committed by the
commit that adds this file (the "attribution commit"). That commit differs from the squash head only in documentation
and evidence files: the compile-input closure is byte-identical. The closure is `check.sh`, `der-verified/src`,
`der-verified/Cargo.toml`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, and the paths `.cargo` and
`der-verified/build.rs` (neither exists). The git object ids of those paths at the capture commit, and so at the
squash head, were:

| path | git object id at the capture commit |
|---|---|
| `check.sh` | `89e49de4c5ea3a1499d0e279e03b3132e2a5ff11` |
| `der-verified/src` | `e07961f52fe2db39dccea6cbe5eb494a6cef34f0` |
| `der-verified/Cargo.toml` | `ef29dba8fa0ec513f0b44e4399cf05d6e5d3ccf2` |
| `Cargo.toml` | `43b527831f0bf4ea16d1845384020b73a5da17df` |
| `Cargo.lock` | `f353059756bee00ff680de554177c3a39cc17160` |
| `rust-toolchain.toml` | `4cc3bc3dad8330360248c8dc95471eebdd788a8b` |

Check it at the attribution commit, in any clone, with no access to the capture commit:

```sh
for p in check.sh der-verified/src der-verified/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml; do
  printf '%s %s\n' "$(git rev-parse HEAD:$p)" "$p"
done
git rev-parse 17ee51e^{tree}
git diff 17ee51e HEAD -- check.sh der-verified/src der-verified/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml .cargo der-verified/build.rs
```

With the attribution commit checked out as `HEAD`, the six ids must be printed in the same order as in the table, the
tree id must be the one above, and the `git diff` must print nothing.

## 4. How the checkout was known to be clean

- **x509_validity and x509_tbs_certificate (four runs):** each was run in a checkout of the capture commit. The
  checkout's `git status --short --untracked-files=no` printed nothing before the first run and printed
  nothing after the last (operator-attested).
- **x509_extension (two runs):** these are the logs of the two heavy split-floor companions (§5). A guard in the
  driver refused to start unless the checkout `HEAD` was the capture commit, and `git status --short
  --untracked-files=no` printed nothing after the control runs that preceded them (operator-attested).

## 5. The two x509_extension legs are the split-floor companions

Both `x509_extension` logs are **the same observation as the split-floor companions**
`evidence/check-42c8165-heavy-x509_extension-validate_extensions_never_panics.log` and
`evidence/check-42c8165-heavy-x509_extension-validate_extensions_ok_path_witnessed.log`. Each file in `logs/` is a
byte-for-byte copy of its companion (the `#` header of the companion included; the same single form is used for both legs, never the raw body alone): `cmp` prints nothing, so the file
sha256 recorded in §2 is also the sha256 of the companion file. The part of the file after the `#` header is the
raw tool output, whose own sha256 is pinned in the companion's header: `9bda38f05b0f5c2c435c5d93c8ae17840499b8a072f9614f25d92c81ca8f5b57` for the baseline and
`bf96ce9a9bf43e99896458bca93cfcf20fdfd62504ecc4e998a1608e6c214941` for the twin.

Why these two heavy harnesses ran only once: each peaks above 20 GB, so they cannot run inside the capped main
floor run (`evidence/check-42c8165.log`, 294 harnesses). They ran separately, one at a time, at `MemoryMax=24G`,
in a window reserved for them (`2026-10-03 21:34Z-21:54Z (box otherwise idle, owner-directed)`). The same deterministic observation then plays two roles: it is the
per-harness verification record of that harness in the split floor, and it is the baseline or twin leg here. A
second identical run would add cost and no independence. If this double use is ever judged unacceptable, the fix is
two separate 24G runs that replace these two files.

The other four logs were produced by targeted single-harness runs (§6), not by the floor run. The floor run
(`evidence/check-42c8165.log`) contains the `x509_validity` and `x509_tbs_certificate` blocks too, and they read the
same: `0 of 1` and `1 of 1` for validity, `0 of 1` and `1 of 1` for the TBS pair.

## 6. Exact commands

Run from a clean checkout of the capture commit (or of the squash head `17ee51e`, which has the same tree), one run at a time, each as a detached, memory-capped service
(`systemd-run --user --collect --wait`, `-p MemorySwapMax=0`, `-p MemoryMax=20G`; `24G` only for the two heavy
`x509_extension` harnesses). The command each service executed, with stdout and stderr written to the log, was:

```sh
cargo kani -Z stubbing --manifest-path der-verified/Cargo.toml --harness <harness> --exact
```

with `<harness>` one of the six names in §2 (the `x509_extension` pair came from the floor-companion runs,
same command). The units were `kani1-x509-validity--proofs--parse-never-panics--737966`, `kani1-x509-validity--proofs--parse-validity-ok-path-witnessed--738057`, `kani1-x509-extension--proofs--validate-extensions-never-panics--736649`, `kani1-x509-extension--proofs--validate-extensions-ok-path-witnesse-737283`, `kani1-x509-tbs-certificate--proofs--parse-tbs-certificate-never-pa-738133`, `kani1-x509-tbs-certificate--proofs--parse-tbs-certificate-ok-path--738270` (the table in §2 pairs each with its harness). Check each log, and the copies, with:

```sh
sha256sum logs/*.log
cmp logs/x509_extension-unsat-13B-42c8165.log ../check-42c8165-heavy-x509_extension-validate_extensions_never_panics.log
cmp logs/x509_extension-sat-16B-concrete-witness-42c8165.log ../check-42c8165-heavy-x509_extension-validate_extensions_ok_path_witnessed.log
grep -H 'cover properties satisfied' logs/*.log
```

The `grep` must print `0 of 1` for the three baselines and `1 of 1` for the three twins (§2).

## 7. Earlier twin runs: superseded, and one that still stands

- The 2026-08-18 pairs (`evidence/planted-satisfied-twins-2026-08-18/`) for `x509_validity` and `x509_extension`
  were captured at an earlier commit. `x509_validity.rs` and `x509_extension.rs` have changed since, so those
  logs no longer describe the shipped bytes. They are kept as history and are **superseded** by the four runs
  above. The 2026-08-18 "same harness, enlarged buffer" leg needed a source edit and is not repeated: one baseline
  and one twin per disclosed cover is what the claim needs.
- The 2026-09-18 pair for `x509_tbs_certificate` (`evidence/controls-refresh-2026-09-18/logs/`, captured at
  `d05d3f2`) is also kept. **Its sat twin no longer witnesses the final bytes**: `context_tag.rs`, a real,
  unstubbed callee of `parse_tbs_certificate`, changed between `d05d3f2` and `42c8165`. A file-level carry-over rule
  that compares only the module file and its harness file would still accept that twin; this directory does not
  rely on it. The 42c8165 pair in §2 is the one that witnesses the final bytes.

## 8. What this does not establish

A satisfied twin shows that the disclosed cover is satisfiable in principle: the harness body can reach the path the
cover names, once a buffer is large enough to hold a well-formed object. It does **not** show that the baseline's
bound is adequate, and for the TBS pair it shows glue reachability under stub semantics only. Nothing here grades any
harness's oracle.
