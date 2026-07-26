# Paper — der-verified artifact/experience report

`der-verified.tex` is the artifact/experience paper for this crate: the
dual-layer (Kani bounded floor + Aeneas→Lean unbounded lids) architecture, the
tractability techniques, the measured cost profile, the honest proof envelope,
and the toolchain gotchas.

It is self-contained (embedded `thebibliography`, no `.bib`/biber needed) and
builds with two `pdflatex` passes:

```sh
pdflatex der-verified.tex
pdflatex der-verified.tex
```

All content is drawn from artifacts already public in this repo
(`README.md`, `PROOF_MANIFEST.md`, `docs/why-verified.md`,
`docs/verification-cost.md`).
