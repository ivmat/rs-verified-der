# CI selection and limits

Every CI run builds the crate, runs `check_fast.sh`, checks tier parity, and builds/tests
on the declared MSRV. The fast entry point includes requirement inventory/maps, acceptance
and unpacked-package validation, generated summaries, source-state checks, tests and clippy.
It does not run Kani or Lean.

## Which changes run Kani?

- Every main-branch push runs the existing LIGHT-tier Kani matrix.
- A PR skips the Kani action only when its complete change from the event's base commit
  to the checked merge commit contains only known prose paths from `gates/ci_changes.py`.
  Each matrix job remains present and writes “Kani NOT RUN (docs-only PR)” to its job
  summary. The aggregate repeats that state rather than implying a proof ran.
- Source (including Rust doc comments), Lean, Cargo inputs, requirements, acceptance records,
  gates, workflow/configuration and unknown paths run Kani. Missing history, malformed event
  data, a non-ancestor base or an empty diff also run Kani.
- The workflow independently forces Kani when the selector or workflow changed, before
  invoking the PR's selector. This guards against accidental policy edits; a PR that edits
  the workflow itself still needs normal code review.
- Renames are compared as a deletion and addition. A source file renamed into a docs path
  therefore cannot skip proofs. New filenames are conservative unless explicitly allowed.

Changes to proof/build dependencies must also review the prose allowlist. Its entries must
remain documentation, not become files read by production code or proof builds.

Superseded PR runs are cancelled per workflow and Git ref. Main-branch runs are not
cancelled and use distinct run groups, preserving each pushed commit's status. Main pushes deliberately do not use
last-push path filtering: otherwise a docs-only push could cancel the previous code-changing
run and skip the proof that never finished. PR selection covers the whole PR, including code
changed before its latest docs commit.

The existing `test + clippy`, MSRV and named Kani matrix checks keep their names. `CI result`
is an additional always-evaluated aggregate: any failed, cancelled, skipped or missing dependency
fails it. Configure it as a required check when adopting this workflow; repository protection
settings are not changed by this patch. A passing docs-only PR is not a new proof result.

Heavy-tier Kani and Lean remain local milestones. The workflow has been checked locally;
its hosted pass/fail paths still need a real GitHub run after publication.

## Captured proof runs and branch pushes

The public push gate validates immutable pushed object IDs and the **remote** refs. For a
branch, it accepts a registered full run at that commit, named carry-over from an ancestor
with unchanged proof inputs, or an existing release validation followed only by approved prose
changes. That release commit is checked strictly before carrying its evidence to the prose commit;
changing or reverting its artifacts cannot use this carry-over.
Tags always require matching [release validation](release.md), including the tag version.
Pushing one commit to both a branch and a tag must satisfy both policies. A deletions-only push
(no object pushed) is still gated at the current HEAD, and a push with no ref lines is a no-op.
The public-only rules below do not run when GitHub reports the repository as private; the
hook's closing line says which rules ran.

For a public destination, two independent evidence gates apply to every pushed object. The
long-standing publication receipt at `evidence/push-receipts/<sha>.receipt` must contain
`full-suite: GREEN @ <sha>` and must not predate the commit. Trusted-run or release verification
must also pass for the pushed ref. A legacy text receipt is still not a proof registration, and a
registered proof run does not replace the publication receipt.

Capture a real run deliberately, sequentially, as the only heavy job on the machine (no other
Kani, Lean or large build running). A capture takes hours, so run it as a **detached**,
memory-capped user unit with swap disabled. Do not use `systemd-run --scope`: a scope belongs
to the calling terminal, so closing the terminal or a hangup kills the run and skips its cleanup.

1. Check for leftovers first. No capture unit may be active, and no stale capture checkout may exist:

   ```sh
   systemctl --user is-active der-proof-capture      # must NOT print "active"
   ls -d "$(git rev-parse --git-common-dir)"/der-proof-checkout-* 2>/dev/null   # must print nothing
   ```

   If the second command lists directories and no capture is running, a killed run left them
   (build products can be several GiB). `record` refuses to start until they are gone; remove
   them with `python3 gates/proof_runs.py clean-stale`. It deletes only those directories (and their
   worktree registrations), refuses to touch symlinks and refuses while a capture holds the lock.
2. Start the detached unit from the repository root. The unit does not inherit your shell
   environment, so pass the reviewed variables explicitly, and only those that are set
   (`systemd-run -E NAME` passes an unset variable as an empty string, which the recorder would
   misread):

   ```sh
   export TMPDIR=/var/tmp   # on disk: a tmpfs /tmp counts against RAM, not just the cap
   set --
   for v in PATH HOME LANG LC_ALL LC_CTYPE TMPDIR CARGO_HOME RUSTUP_HOME KANI_HOME ELAN_HOME VERIFIED_RS_TOOLS; do
     [ -n "$(printenv "$v")" ] && set -- "$@" -E "$v"
   done
   systemd-run --user --unit=der-proof-capture --collect \
     --working-directory="$PWD" \
     -p MemoryMax=24G -p MemorySwapMax=0 \
     "$@" "$(command -v python3)" gates/proof_runs.py record
   ```

   Follow it with `journalctl --user -u der-proof-capture -f`. The raw log is also written
   into the local store. If the unit is stopped, killed or hits its memory cap, its cleanup does
   not run: repeat step 1 before the next attempt. Keep the box's total memory use
   (the 24G cap plus everything else) below its RAM. Without user lingering
   (`loginctl show-user "$USER" -p Linger`), the unit stops when the last login session ends;
   keep a session open or enable lingering. A pressure-based OOM daemon such as `systemd-oomd`,
   if active, may also stop the unit before it reaches its cap.

This expensive command checks out committed HEAD in an isolated linked worktree and runs the
fixed full Kani+Lean gate. It never runs automatically in a push hook. A failed, incomplete or
tool-mismatched run leaves no trusted receipt. The recorder, its imported policy helpers and
the run's source must be committed versions. Caller changes and its Git index are untouched. The
capture checkout is created in a mode-0700 temporary directory under the Git common directory and
removed afterwards, so its build products do not consume `/tmp` tmpfs memory. Do not run concurrent
heavy captures.

After a successful `record`, the owner-only Git-local store pins the source commit, raw log and
completed-run receipt. A private `refs/der-proof-runs/<run-id>` ref keeps each recorded source
reachable across rebases and garbage collection. Never push these refs: the push hook refuses any
`refs/der-proof-runs/*` ref to every destination (public, private or not allowed), before any
other rule and with no override. **Do not use `git push --mirror`
or a `refs/*:refs/*` refspec, and do not configure a mirror fetch (`+refs/*:refs/*` with pruning)
in a clone that holds a proof store**: a mirror push is refused, and a pruning mirror fetch deletes
these local-only refs, after which the store refuses (see below). Legacy text
receipts, copied logs and `docs/proof-floor.json` cannot register a run. The local owner and
reviewed recorder/check scripts are trusted; this is not a signature or protection against a
compromised local account, OS or runtime loader. A new clone has no local run authority.

The whole store is verified together with the current verifier, and any failing entry refuses
all of them. This includes entries that an updated verifier no longer accepts, or whose source ref
was deleted. One bad entry therefore cannot be skipped silently, and it also would block new
captures. Resolve it explicitly and visibly:

```sh
python3 gates/proof_runs.py retire --run-id <32-hex run id> --reason "<one line>"
```

`retire` verifies nothing about the entry. It removes that one run from the active index, moves
its receipt and log into `quarantine/` inside the store, and appends the time, run id and reason
to `quarantine/retired.log`. A retired run is never accepted as evidence again, by a push, a
release receipt binding its digest or a restored index entry (the store refuses). An unknown id
or a missing reason refuses and changes nothing. It does not repair a corrupt `index.json` and
does not delete the `refs/der-proof-runs/<run-id>` ref. Retiring is not a proof: capture a new
run afterwards.

The pushed-commit verifier is also the commit's own gate code. A commit that changes `gates/`
is certified by its own changed gate, so review every `gates/` diff as policy.

Carry-over identifies the **historical captured tools and source commit**. It does not say
that the target commit was freshly proved, or that today's installed tools ran. Relevant
binaries, Kani's compiler/CBMC/bundle, tool pins and supported configuration are recorded and
compared before/after capture. The verifier authenticates the immutable receipt, required tool
identity fields and log integrity; it does not independently re-observe the historical tools or
rehash the host's current tool installation on each push. The push hook runs this verifier from a
detached checkout of the pushed object, not from mutable working-tree verifier code.

The supported input profile is deliberately narrow: this one-member, dependency-free source
crate, with no build scripts, compile-time file includes/path overrides, external file or
environment access, submodules, source symlinks, custom Cargo configuration or checkout filters.
Unsupported compiler/loader/Lean/Python overrides (including Python optimization) refuse
capture. Git replacement objects are disabled, legacy grafts refuse validation, and checkout
bytes/modes must match committed blobs. Direct system compilers and manager proxies are both
supported. This is not a general hermetic-build resolver.

The proof subprocess receives only the reviewed `PATH`, `HOME`, `TMPDIR`, locale,
`CARGO_HOME`, `RUSTUP_HOME`, `KANI_HOME`, `ELAN_HOME` and `VERIFIED_RS_TOOLS` inputs plus
recorder-owned controls. Their names and values are stored as environment provenance; arbitrary
caller variables and secrets are not forwarded or recorded. The `python3` launcher must resolve
to the recorder's Python, and the observed Lean version must exactly match its declared pin.

The reuse prose allowlist is narrower than CI's: proof-manifest and assumption changes remain
protected. Unknown paths and changes to source, harnesses, requirements, builds, toolchain,
gates or workflow policy require a new run. The narrowly validated metadata outputs below
are the only exceptions. Source-independent snapshot comparison in a fresh clone is advisory;
it is not local run authorization.

## Verification outputs without a second proof run

A successful isolated run may refresh `lean/lid-source-state.txt`. Only the recorder's valid
capture context may stage that file after Lean PASS, with its roster and source hashes checked.
Ordinary `check.sh` behavior is unchanged. Every other unexpected checkout change refuses capture.

The receipt binds exact generated bytes for the verified state cache, the log-derived floor
declaration, and the two floor-dependent generated regions of `PROOF_MANIFEST.md`. Other prose,
bounds, assumptions and generated regions remain unchanged. Counts and unsatisfied covers come
from the actual harness log; unmeasured memory fields say so. These outputs can be committed with
a release bundle without relabelling the source run or forcing another proof merely for metadata.
The manifest projection pins its source anchor to S. Later verification authenticates its stored
bytes and digest and checks that bytes outside the permitted generated bodies still match S;
it does not render historical evidence again with the current generator.
Changing the generated floor declaration without the corresponding proof-manifest projection is
refused. A change to the source-state cache alone is not refused: it has no manifest projection
and is accepted when its bytes equal the trusted run's output. Any other value is refused.

Release validation checks the exact artifact commit and its relationship to the trusted source
run. It produces a distinct release-validation receipt, never a fabricated “full-suite GREEN”
at another SHA. See [the release workflow](release.md).

Local tests cover source/input changes, renames/deletions, missing/unrelated history, tampered or
incomplete receipts, tool and configuration refusals, metadata exactness, caller-index isolation,
remote tag promotion and mixed branch/tag pushes. An integrated disposable fixture captures its
fixed test runner, validates a real snapshot bundle, commits the exact outputs, validates the
release and passes the tag hook; log, index and artifact mutations then refuse. These fixture
verdicts are not Kani or Lean proofs. Hosted CI pass/fail paths still need testing
before publication.

## Known limits

- Tool identity does not fingerprint the Aeneas Lean library or Mathlib build products under the
  external proof-tools checkout. Their committed pins and observed binaries remain assumptions.
- The public environment variable name `VERIFIED_RS_TOOLS` and its home-directory fallback are kept
  for operator compatibility. They are legacy interface names, not evidence of another repository
  being present, and an operator should set the variable explicitly for reproducible capture.
