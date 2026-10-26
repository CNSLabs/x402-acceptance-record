> Publication copy: private locators were removed from metadata. The [export manifest](../PUBLICATION-METADATA.json) records original and public hashes; inputs, outputs, timestamps and source snapshots retain their original meaning.

# Clean-room checker for the x402 acceptance record v0 — brief (2026-10-26, Mike's decision, private authorization locator withheld)

Objective: build an independent verifier ("checker") for the x402 acceptance record, version 0, written from the specification text alone, then run it against the published vectors and record the result. The deliverable's value depends entirely on provenance discipline. Two stages, in order.

Working directory (write only inside it): <checker-workspace>

## Stage 1 — spec only
Allowed reading: `inputs/stage1-spec-only/` only: SPEC.md, CASES.md, README.md, LICENSE, and `upstream-pinned/*`, which are the two upstream texts SPEC.md pins by commit (offer-and-receipt extension at faa1c694; execution evidence `x402ev/1` at 23b5c21). Nothing else about this project: do not open `inputs/stage2-vectors-after-freeze/`; do not open any other directory under `<other-task-directories>` or `<other-workspace>`; do not use gh, git, curl or a browser to fetch anything from CNSLabs or x402-foundation beyond what is staged; do not search the web for implementations of this spec. Standard library and crypto-library documentation is fine. Keep `READ-LOG.md` listing every file you read, with UTC timestamps, in order.

Deliverable: `checker/` implementing `verify` per SPEC.md section 8 (the AR-* steps, in order), both signing forms (EIP-712 and JWS), the verifier inputs of section 5 and the output of AR-36. Language: TypeScript on Node 22+ or Python 3.12+, your choice. Pinned dependencies with a lockfile; well-known crypto libraries allowed (for example @noble/curves and @noble/hashes, or cryptography, pycryptodome, coincurve); no network at runtime. CLI: `verify <inputs.json>` prints the AR-36 output object as JSON; `selftest` uses only synthetic keys you generate plus the spec's own illustrative examples. `checker/README.md`: inputs read, design, how to run.

Freeze: when stage 1 is complete, `git init` inside `checker/`, commit everything, and write `FREEZE.md` at the root with the commit hash (`git rev-parse HEAD`), a SHA-256 over the committed tree (`git archive HEAD | shasum -a 256`), and the UTC timestamp. Do not touch stage 2 before this commit exists.

## Stage 2 — after the freeze commit only
Now read `inputs/stage2-vectors-after-freeze/`: `vectors.json` (127 vectors), the vectors `README.md` (layout), the results README and `sample-result-*.json` (format). Write `runner/` (separate from `checker/`, may import it) that maps each vector's `inputs` to your checker and compares against `expect`, producing a results JSON in the package's format named `rerun-cnslabs-cleanroom-sol-2026-10-26.json`: author "CNS Labs clean-context agent (GPT-6.1 Sol, operated by Molt)", platform (OS, runtime version), checker name, version and commit (the FREEZE commit), SHA-256 of vectors.json, the profile and specification pin carried by the vector file, one outcome per vector with expected and actual on failure, and totals.

Rule: do NOT modify `checker/` while producing this first result. Record it as-is, failures included. Then write `STAGE2-ANALYSIS.md`: for each failing vector, classify it as spec ambiguity, checker misreading, or suspected vector/spec disagreement, citing the exact spec clause. If you then fix the checker, do it as a separate commit in `checker/` with a `CHANGES.md` describing each change and why, and record a second result file for the new commit. The first result file stays untouched.

## Report
`REPORT.md` at the root, and the same in your final message: language and dependencies; files read in stage 1; freeze commit, tree hash and time; first-run totals (pass/fail of 127) and each failure with a one-line cause; v2 if any; everything in SPEC.md you found ambiguous or underspecified while implementing (valuable even if all vectors pass). State plainly that the checker was written entirely by an AI agent in a clean context. Run the selftest and the vector run yourself and include the exact commands and outputs. Never fabricate results; if something cannot run, say so.

## Boundaries
No pushes, no Slack, no GitHub writes, no messages to anyone, no reading of the private conformance repository. Time budget about three hours; if stage 2 cannot be finished, deliver stage 1 frozen plus a clear status.
