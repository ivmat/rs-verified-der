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

**`der-verified.pdf` is STALE relative to `der-verified.tex`.** The `.tex`
was updated 2026-08-07 to match the current `PROOF_MANIFEST.md` (171 Kani
harnesses, 6 Aeneas→Lean lids, 320 tests); the checked-in `.pdf` was not
regenerated in that pass (no `pdflatex`/`tectonic`/`xelatex`/`latexmk` was
available on the machine that made the edit). Recompile with two
`pdflatex` passes (or `tectonic`) on a machine that has the toolchain — mac,
typically — and check the resulting PDF's content against the `.tex` before
any Zenodo upload or other publication.

**Review-driven fix round, 2026-08-07 (no `pdflatex` here either).** The L4
lid table's `p{4.4cm}` column carries long `\code{...}` theorem names
(e.g. `decode_accepts_only_canonical`); `\allowbreak` was inserted at every
`\_` boundary inside those names so LaTeX has break points instead of
overfull hboxes in the two-column layout. This is the conservative fix chosen
without a compiler to verify it against — eyeball the table's line-breaking
at the next mac recompile and adjust if it still overfills.
