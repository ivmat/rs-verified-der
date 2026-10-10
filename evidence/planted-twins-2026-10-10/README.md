# Planted-satisfied twins, re-run at the integration head — 2026-10-10

This directory holds six single-harness Kani runs. They re-witness, at the bytes this repository now ships, the three
covers that `PROOF_MANIFEST.md` §8.2 discloses as **known-unsatisfiable at their bound**, each next to the companion
harness that witnesses the same path on a concrete input. They are the **planted-satisfied twin** evidence for the
claims `PM/x509_validity`, `PM/x509_extension` and `PM/x509_tbs_certificate`: the method is described in
[`../PLANTED-SATISFIED-TWINS-2026-08-18.md`](../PLANTED-SATISFIED-TWINS-2026-08-18.md). The logs are under `logs/`.
This directory replaces [`../planted-twins-2026-10-03/`](../planted-twins-2026-10-03/README.md) for the shipped bytes: that
directory was captured at `42c8165`, and `der-verified/src/x509_extension.rs` (a doc-comment edit), `sequence.rs` and
`set_of.rs` have changed since. Its logs stay as dated history.

An unsatisfiable cover proves nothing until something has been seen to satisfy it. Each pair therefore holds one log
where the disclosed cover is **not** satisfied (the baseline) and one where the companion's cover **is** satisfied
(the twin).

## 1. Prediction, committed before any run

The prediction is `PROOF_MANIFEST.md` §8.2, the generated table "Harness whose `cover` is UNSATISFIABLE at its
bound / Companion witness harness", as committed at the capture commit `d68eeca`. That commit was made at
`2026-10-09T13:38:54+02:00`, before every run recorded here: the four fresh twin runs ran from `2026-10-10T14:36:03Z`
to `2026-10-10T14:41:30Z`, and the two reused `x509_extension` observations ran in the window
`2026-10-10T14:08:54Z` to `2026-10-10T14:20:18Z` (§5). The pairing itself is older: all three companion names have been in
the manifest since 2026-07-30. The table reads:

| Harness whose cover is unsatisfiable at its bound | Companion witness harness | Companion uses `#[kani::stub]`? |
|---|---|---|
| `x509_extension::validate_extensions_never_panics` | `x509_extension::validate_extensions_ok_path_witnessed` | no |
| `x509_tbs_certificate::parse_tbs_certificate_never_panics` | `x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed` | **yes** — read it as glue reachability only |
| `x509_validity::parse_never_panics` | `x509_validity::parse_validity_ok_path_witnessed` | no |

So the prediction for each pair is: baseline `0 of 1 cover properties satisfied` (cover status `vacuous`), twin
`1 of 1 cover properties satisfied` (cover status `held`), and `VERIFICATION:- SUCCESSFUL` in both.
Observed: exactly that, for all three pairs.

## 2. The six runs

All six ran at the capture commit `d68eeca`, with Kani `0.67.0`, CBMC `6.8.0`, CaDiCaL `2.0.0`, one harness per run
(`cargo kani -Z stubbing --manifest-path der-verified/Cargo.toml --harness <h> --exact`), sequentially, each inside a
detached, memory-capped `systemd --user` service (`MemorySwapMax=0`). Each log is the complete tool output of one
run, unedited (it is not a distillation; the two `x509_extension` logs additionally start with a short `#` header,
see §5), and ends with the tool's own `Complete - 1 successfully verified harnesses, 0 failures, 1 total.`

| log (under `logs/`) | harness | role | observed cover | cap | unit | peak | sha256 of the log |
|---|---|---|---|---|---|---|---|
| `x509_validity-unsat-16B-d68eeca.log` | `x509_validity::proofs::parse_never_panics` | baseline | `0 of 1` | 20G | `kani1-x509-validity--proofs--parse-never-panics--1842297` | `900.1M` | `90c31ed1ca9d7a076165eff4f545e07769025a8e6142647a5d29adf239d595e4` |
| `x509_validity-sat-32B-concrete-witness-d68eeca.log` | `x509_validity::proofs::parse_validity_ok_path_witnessed` | twin | `1 of 1` | 20G | `kani1-x509-validity--proofs--parse-validity-ok-path-witnessed--1842416` | `717.3M` | `0b11e57e6437e0206b21ee3b4fb4778988a5aabaaad55631c6e2d5ad2c801783` |
| `x509_extension-unsat-13B-d68eeca.log` | `x509_extension::proofs::validate_extensions_never_panics` | baseline | `0 of 1` | 24G | `kani1-x509-extension--proofs--validate-extensions-never-panics--1841323` | `20.1G` | `5715408becf6977d7a7dec15bd95e4220c6db01d31ae1af63265abecc26dbace` |
| `x509_extension-sat-16B-concrete-witness-d68eeca.log` | `x509_extension::proofs::validate_extensions_ok_path_witnessed` | twin | `1 of 1` | 24G | `kani1-x509-extension--proofs--validate-extensions-ok-path-witnesse-1841617` | `16.5G` | `bacef8b9ade5ae87d9bfdabdf2a6fe2b7c70baf3c56e7c85a34d70cb61535abd` |
| `x509_tbs_certificate-unsat-10B-d68eeca.log` | `x509_tbs_certificate::proofs::parse_tbs_certificate_never_panics` | baseline | `0 of 1` | 20G | `kani1-x509-tbs-certificate--proofs--parse-tbs-certificate-never-pa-1842496` | `5.5G` | `cf278cb6063fc00a071610866e528b895b1c65c64c327fbfa009d082c8ae0889` |
| `x509_tbs_certificate-sat-135B-concrete-witness-d68eeca.log` | `x509_tbs_certificate::proofs::parse_tbs_certificate_ok_path_witnessed` | twin | `1 of 1` | 20G | `kani1-x509-tbs-certificate--proofs--parse-tbs-certificate-ok-path--1843006` | `11.7G` | `2361b398a1c2571e40adf993879e364e8a87453d6d1be34f139e0c74d3475dae` |

The "observed cover" column quotes the `** N of 1 cover properties satisfied` summary line of the log. The "peak"
column is the memory peak journald printed when the unit ended.

What the twins are, in one line each:

- **x509_validity**: a concrete 32-octet specimen with two `UTCTime` fields, run through the real, unstubbed
  `parse_validity`.
- **x509_extension**: a concrete 16-octet specimen holding two `Extension` members, run through the real, unstubbed
  `validate_extensions`.
- **x509_tbs_certificate**: a concrete 135-octet v1 `TBSCertificate` specimen under **three** stubs. The third stub
  (`parse_validity`) is what makes the `Ok` tail reachable at all, so this twin witnesses glue reachability under
  stub semantics. It is not evidence that the real sub-parsers accept the specimen.

## 3. Capture commit versus attribution commit

The runs were captured on the source tree of commit `d68eeca` (the "capture commit"; the header of each log and every
run record names it). This directory is committed by a later commit (the "attribution commit") that differs from the
capture commit only in documentation and evidence files: the compile-input closure is byte-identical. The closure is
`check.sh`, `der-verified/src`, `der-verified/Cargo.toml`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, and the
paths `.cargo` and `der-verified/build.rs` (neither exists). The git object ids of those paths at the capture commit were:

| path | git object id at the capture commit |
|---|---|
| `check.sh` | `89e49de4c5ea3a1499d0e279e03b3132e2a5ff11` |
| `der-verified/src` | `a4ff4747c168d4dfff6471142acd49e8b100a914` |
| `der-verified/Cargo.toml` | `ef29dba8fa0ec513f0b44e4399cf05d6e5d3ccf2` |
| `Cargo.toml` | `43b527831f0bf4ea16d1845384020b73a5da17df` |
| `Cargo.lock` | `f353059756bee00ff680de554177c3a39cc17160` |
| `rust-toolchain.toml` | `4cc3bc3dad8330360248c8dc95471eebdd788a8b` |

Check it at the attribution commit, in any clone:

```sh
for p in check.sh der-verified/src der-verified/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml; do
  printf '%s %s\n' "$(git rev-parse HEAD:$p)" "$p"
done
git diff d68eeca HEAD -- check.sh der-verified/src der-verified/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml .cargo der-verified/build.rs
```

With the attribution commit checked out as `HEAD`, the six ids must be printed in the same order as in the table, and
the `git diff` must print nothing.

## 4. How the checkout was known to be clean

- **x509_validity and x509_tbs_certificate (four runs):** each was run in the checkout of the capture commit. The
  driver refused to start unless `HEAD` was the capture commit and `git status --porcelain --untracked-files=no`
  printed nothing (operator-attested).
- **x509_extension (two runs):** these are the logs of the two heavy split-floor companions (§5), run under the same
  guard in the same checkout.

## 5. The two x509_extension legs are the split-floor companions

Both `x509_extension` logs are **the same observation as the split-floor companions**
`evidence/check-d68eeca-heavy-x509_extension-validate_extensions_never_panics.log` and
`evidence/check-d68eeca-heavy-x509_extension-validate_extensions_ok_path_witnessed.log`. Each file in `logs/` is a
byte-for-byte copy of its companion (the `#` header of the companion included): `cmp` prints nothing, so the file
sha256 recorded in §2 is also the sha256 of the companion file. The part of the file after the `#` header is the
raw tool output, whose own sha256 is pinned in the companion's header: `e36ad659748892344352aaaa79f41be06f7023bc426e29938266eca71191c248` for the baseline and
`b268d1367461d724c8346ad86927f04eb21de053cf8e21c1027d841a3f791f4d` for the twin.

Why these two heavy harnesses ran only once: earlier measurements approached or exceeded 20 GiB, so they were kept out of
the 20 GiB-capped main floor run (`evidence/check-d68eeca.log`, 295 harnesses). Their measured peaks in the 24G runs were
20.1G (baseline) and 16.5G (twin). The same deterministic observation then plays two roles: it is the per-harness
verification record of that harness in the split floor, and it is the baseline or twin leg here. A second identical run
would add cost and no independence. If this double use is ever judged unacceptable, the fix is two separate 24G runs
that replace these two files.

The other four logs were produced by targeted single-harness runs (§6), not by the floor run. The floor run
(`evidence/check-d68eeca.log`) contains the `x509_validity` and `x509_tbs_certificate` blocks too, and they read the
same: `0 of 1` and `1 of 1` for validity, `0 of 1` and `1 of 1` for the TBS pair.

## 6. Exact commands

Run from a clean checkout of the capture commit, one run at a time, each as a detached, memory-capped service
(`systemd-run --user --collect --wait`, `-p MemorySwapMax=0`, `-p MemoryMax=20G`; `24G` only for the two heavy
`x509_extension` harnesses). The command each service executed, with stdout and stderr written to the log, was:

```sh
cargo kani -Z stubbing --manifest-path der-verified/Cargo.toml --harness <harness> --exact
```

with `<harness>` one of the six names in §2 (the `x509_extension` pair came from the floor-companion runs, same
command). The table in §2 names the unit of each run. Check each log, and the copies, with:

```sh
sha256sum logs/*.log
cmp logs/x509_extension-unsat-13B-d68eeca.log ../check-d68eeca-heavy-x509_extension-validate_extensions_never_panics.log
cmp logs/x509_extension-sat-16B-concrete-witness-d68eeca.log ../check-d68eeca-heavy-x509_extension-validate_extensions_ok_path_witnessed.log
grep -H 'cover properties satisfied' logs/*.log
```

The `grep` must print `0 of 1` for the three baselines and `1 of 1` for the three twins (§2).

## 7. Earlier twin runs: superseded

- The 2026-10-03 directory ([`../planted-twins-2026-10-03/`](../planted-twins-2026-10-03/README.md)) holds the same six runs at
  `42c8165`. `x509_extension.rs` has changed since (doc comments only), and `sequence.rs` and `set_of.rs` changed in the
  verified source, so those logs are kept as history and are **superseded** by the six runs above.
- The 2026-08-18 pairs (`planted-satisfied-twins-2026-08-18`) and the 2026-09-18 `x509_tbs_certificate` pair
  ([`../controls-refresh-2026-09-18/`](../controls-refresh-2026-09-18/README.md)) are older history, superseded likewise.

## 8. What this does not establish

A satisfied twin shows that the disclosed cover is satisfiable in principle: the harness body can reach the path the
cover names, once a buffer is large enough to hold a well-formed object. It does **not** show that the baseline's
bound is adequate, and for the TBS pair it shows glue reachability under stub semantics only. Nothing here grades any
harness's oracle.
