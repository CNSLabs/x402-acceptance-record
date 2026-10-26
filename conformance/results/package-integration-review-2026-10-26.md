<!-- human-doc: evidence -->
# Package integration verification — 26 October 2026

The assembled public package passes the checks below. The specification, corpus, original frozen checker and
first-run result are unchanged. This is an integration rerun, not another blind implementation.

| Check | Result |
| --- | --- |
| TypeScript corpus | 127/127 |
| Generator | Byte-identical regeneration of all 127 vectors |
| TypeScript typecheck and synthetic tests | Passed; 182/182 tests |
| Independent Python corpus and statement identities | 127/127 and 89/89 |
| Original frozen Python corpus | 127/127 |
| Corrected Python r1 corpus and synthetic tests | 127/127 and 87/87 |
| Original five signed review inputs against r1 | 5/5 expected outcomes |
| Copied frozen/r1 sources versus their Git bundles | Byte-identical |

Original checker commit: `bec16636ff3c2afa0b7ec7a0a32ab2179f96817c`.
Corrected checker commit: `68bb522d71aa5a0e4a65da28020bae474ec5dbc8`.
Vector SHA-256: `8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5`.
Package runner SHA-256: `e8bfc748a99219c55333ccf081148bac5b2857f36f9a713b0d9fedb3a8637c68`.

The two number-spelling mutations now return `verified`; the malformed-network mutation returns
`unknown / evidence_unavailable`. Both baseline forms still verify.

Reproduce from the package root: `npm ci --ignore-scripts`, `npm run check`, `npm test`, `npm run typecheck`,
`npm run selftest:checker`; then follow the [Python package instructions](../checker-blind/README.md#reproduce)
and [independent checker's instructions](../checker-python-independent/README.md).
From `review/2026-10-26-vic-repro/`, run `python reproduce.py --package ../../checker-blind --revision r1`.
Python checks used each checker's already-installed pinned dependencies; the TypeScript dependencies were freshly
installed from the lockfile. Checkers use caller-supplied chain evidence; no live chain or wallet was exercised.

The original implementation differences remain documented in the [package overview](../README.md).
The original first run remains the evidence for the pre-vector freeze; r1 is explicitly post-review.
No result here resolves the remaining spec interpretation questions or approves a normative wording change.
