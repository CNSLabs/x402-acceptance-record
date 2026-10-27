# Blind checker (Python) for the x402 acceptance record, version 0

**Build account.** This checker is blind. Its author, an AI agent (GPT-6.1 Sol) in an isolated context operated by Molt for CNS Labs on 2026-10-26, read SPEC.md, CASES.md, README.md and LICENSE of `CNSLabs/x402-acceptance-record` at tag `draft-2026-10-21` (commit `ad53b54a`) and the two upstream texts SPEC.md pins by commit, the offer and receipt extension at `faa1c694` and `execution_evidence.md` at `23b5c21`, and nothing else: no generator, no other checker, no vector, no part of this repository. `vectors.json` was not opened before the verifier was frozen at commit `bec16636` (2026-10-26T19:03:24Z, archive SHA-256 `98aa4293a8094aeeeaa76fc153ee97f8dde319a08d0cef301352b5c7a00b22eb`). The expected outputs were first seen after the freeze, before the first execution. The checker is AI-written. The unchanged frozen commit passed 127 of 127 vectors on its first run. The original tree remains in `checker/`; a separately recorded post-review correction is in `r1/`. Every file read is listed with a UTC timestamp in `READ-LOG.md`; the stage-one portion is frozen inside the checker as `checker/STAGE1-READ-LOG.md`, and the exact brief the author received is `BRIEF.md`.

**Post-review revision.** Vic's review of 2026-10-26 16:03 ET found two misses outside the corpus: a JWS offer with a non-CAIP-2 `network` qualified, and integral number spellings such as `1.0` and `1e2` in an EIP-712 offer were disregarded. Both are classified and corrected in `r1/` as a second commit (`68bb522`) on the frozen one, with 87 of 87 selftests and 127 of 127 vectors. The frozen tree, hash and first-run result above are unchanged.

## Layout

- `checker/`: the frozen verifier (`acceptance.py`), CLI (`cli.py verify <inputs.json>` prints the AR-36 output; `cli.py selftest` runs 84 synthetic tests with fresh keys), pinned dependencies (`requirements.lock`), the author's `README.md` and `IMPLEMENTATION-NOTES.md`.
- `runner/`: the post-freeze transport adapter. It decodes base64url fields and renames three transport names for the unpinned section 5 binding, never consults a vector's expected result, refuses to run if `checker/` has uncommitted changes, and records the commit and archive hash it ran at. `STAGE2-ANALYSIS.md` audits it.
- `provenance/`: `checker-freeze-bec16636.bundle`, the checker's own git repository at the freeze (clone it and run `git archive HEAD | shasum -a 256` to reproduce the hash; the files under `checker/` are the same tree, copied for review), `build-logs/`, and `verify-by-molt-2026-10-26.json`, an independent re-run by Molt on the same commit, also 127 of 127.
- `FREEZE.md`, `READ-LOG.md`, `REPORT.md`, `STAGE2-ANALYSIS.md`, `ENVIRONMENT-NOTES.md`, `DISAGREEMENTS.md`.
- `r1/`: the post-review revision (its tree under `r1/checker/`, `r1.patch`, `review-repro/`, `README.md`); `provenance/checker-r1.bundle` holds both commits. `v0/results/rerun-mike-r1-2026-10-26.json` is its rerun.

## Result

[original first-run result](../results/rerun-mike-2026-10-26.json): the vector file SHA-256 (`8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5`, bytes unchanged), one entry per vector id with expected and actual output (`result`, `conditions` compared as a set with absence asserted, and `disposition`, `reason`, `policy_refusal` where present), and totals: 127 vectors, 127 passed, 0 failed.

## Disagreements

None on the first run. `DISAGREEMENTS.md` records that, states this checker's readings on the three points where the authors' and the independent checkers already differ, and points to the ten places the author found the spec ambiguous or underspecified, all written down before the freeze in `checker/IMPLEMENTATION-NOTES.md`. Passing the vectors does not settle them.

## Reproduce

Run from this directory (under `conformance/checker-blind/` in the public package):

```sh
python3 -m venv .venv
.venv/bin/pip install -r checker/requirements.lock
.venv/bin/python -B checker/cli.py selftest
.venv/bin/python -B r1/checker/cli.py selftest
.venv/bin/python -B run_package.py --revision frozen --author "Your name" --output ../results/frozen-your-run.json
.venv/bin/python -B run_package.py --revision r1 --author "Your name" --output ../results/r1-your-run.json
```

The package runner clones the selected bundle into a temporary directory, verifies it against the copied source
and specification pins, then uses the original transport adapter. It writes a new report and never replaces
`checker/`, modifies the read log or overwrites an earlier result. `runner/run_vectors.py` remains the original
historical runner; its staged input directory is not required by this package runner.


## Environment disclosures

`ENVIRONMENT-NOTES.md`: the first two dependency installs used the host's default temporary directory before the agent confined `TMPDIR` to its task directory; no project source was involved. The stage-two folder handed to the author carried the results README and one sample result but not the vectors-layout README, so the author took the layout from `vectors.json` itself after the freeze.
