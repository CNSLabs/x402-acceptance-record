# Clean-room checker (Python) for the x402 acceptance record, version 0

A verifier written from the specification text alone, by an AI agent (GPT-6.1 Sol) in an isolated context operated by Molt for CNS Labs on 2026-10-26, and frozen before its author saw any vector. It is the "checker written from the specification alone, by someone who has not seen this package's code" that `v0/README.md` describes as a separate result.

## What the author could see

Stage one, before the freeze: `SPEC.md`, `CASES.md`, `README.md` and `LICENSE` of `CNSLabs/x402-acceptance-record` at tag `draft-2026-10-21` (commit `ad53b54a`), plus the two upstream texts SPEC.md pins by commit: the offer and receipt extension at `faa1c694` and `execution_evidence.md` from x402 PR #3682 at `23b5c21`. Nothing else: no generator, no other checker, no vectors, no part of this repository. Every file read is listed with a UTC timestamp in `READ-LOG.md`; the stage-one portion is also frozen inside the checker as `checker/STAGE1-READ-LOG.md`. The exact brief the agent received is `BRIEF.md`.

Stage two, after the freeze: `vectors.json`, the results README and one sample result file, used only to write the transport adapter in `runner/` and to run the frozen checker.

## Freeze

- Commit `bec16636ff3c2afa0b7ec7a0a32ab2179f96817c`, 2026-10-26T19:03:24Z, in the checker's own git repository.
- `git archive HEAD | shasum -a 256` = `98aa4293a8094aeeeaa76fc153ee97f8dde319a08d0cef301352b5c7a00b22eb`.
- `provenance/checker-freeze-bec16636.bundle` is that repository. `git clone` it and run the same command to reproduce the hash; the files under `checker/` here are the same tree, copied for review.
- Receipts: `FREEZE.md`, `provenance/build-logs/`.

## Result

First run on the frozen commit, no changes before or after: **127 of 127 vectors pass**. Recorded as `v0/results/rerun-cnslabs-cleanroom-sol-2026-10-26.json` in the results format (author, platform, checker name, version and commit, vector file SHA-256, specification pins, one outcome per vector, totals). An independent re-run by Molt on the same commit is `provenance/verify-by-molt-2026-10-26.json`, also 127 of 127. Synthetic self-test: 84 of 84 (`checker/cli.py selftest`, fresh keys, no vectors).

`STAGE2-ANALYSIS.md` records that no failure needed classifying and audits the adapter: it changes transport representation only (base64url decoding, three field renames for the unpinned section 5 binding) and never consults a vector's expected result.

## Spec findings

Ten points the author found ambiguous or underspecified while implementing, all written down before the freeze: `checker/IMPLEMENTATION-NOTES.md`, summarized in `REPORT.md`. Passing the vectors does not settle them.

## Reproduce

```sh
cd v0/checker-python-cleanroom
python3.13 -m venv .venv && .venv/bin/pip install -r checker/requirements.lock
.venv/bin/python -B checker/cli.py selftest
# restore the frozen repository so the runner's integrity checks can run
rm -rf checker && git clone provenance/checker-freeze-bec16636.bundle checker
mkdir -p inputs/stage2-vectors-after-freeze && cp ../vectors/vectors.json inputs/stage2-vectors-after-freeze/
.venv/bin/python -B runner/run_vectors.py --json rerun-yours.json
```

The runner refuses to run if `checker/` has uncommitted changes and records the commit and archive hash it ran at.

## Environment disclosures

`ENVIRONMENT-NOTES.md`: the first two dependency installs used the host's default temporary directory before the agent confined `TMPDIR` to its task directory; no project source was involved. The staged stage-two folder carried only the results README, so the vector layout was taken from `vectors.json` itself after the freeze.
