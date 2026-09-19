# evidence/ — what is here, and the raw-log policy

This directory holds the crate's verification evidence: distilled full-gate run logs
(`check-<commit>.log`), observed-red mutation/ablation control bundles, Lean-lid control logs, and
the per-run write-ups the other documents cite.

## Raw gate logs are kept LOCAL, not committed (policy change 2026-09-18)

Each full-gate run produces two things: a **distilled** log (per-harness verdicts, cover
satisfaction, timings, stage banners — committed here as `check-<commit>.log`) and the **complete
raw** log (every solver line — hundreds of thousands of lines, tens of MB gzipped).

**As of 2026-09-18 (owner ruling: raw gate logs stay out of the repo — the repo is not the place for
tens of MB of raw solver output), the complete raw logs are kept LOCAL and are NOT committed.**
`evidence/raw/` is gitignored. Every distilled log's own header records the raw log's **byte count
and sha256**, so a raw log — **available on request** — can be verified byte-for-byte against the
distillation it produced. The distillation is therefore checkable rather than trusted, exactly as
before; only the storage location of the raw changed.

**Historic note.** Distilled log headers written **before 2026-09-18** state that the raw log is
"committed alongside it … at `evidence/raw/check-<commit>.log.gz`". That was true when those headers
were written (the raw logs were committed then). It is no longer true after this policy change: those
raw `.gz` files were untracked (kept on disk locally, still available on request) and `evidence/raw/`
was gitignored. The dated per-log headers are left as written rather than rewriting history; this note
is the standing disclosure that supersedes the "committed alongside" wording for every distilled log
in this directory. The `check-d05d3f2.log` header (2026-09-18 onward) already states the current
"kept LOCAL / available on request" wording directly.
