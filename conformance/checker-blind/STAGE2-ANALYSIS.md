# Stage-two analysis — first frozen-checker result

## Provenance and outcome

- Checker freeze: `bec16636ff3c2afa0b7ec7a0a32ab2179f96817c`.
- Result: `rerun-cnslabs-cleanroom-sol-2026-10-26.json`.
- First run: **127 passed, 0 failed, 127 total**.
- Checker files were unchanged and Git-clean before and after the run.
- Staged SPEC.md and CASES.md SHA-256 values match the vector file's specification pins.
- Vector SHA-256: `8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5`.
- No v2 checker commit, CHANGES.md or second result file was needed or produced.

## Failing-vector classification

There are no failing vectors, so there are no per-vector classifications as spec
ambiguity, checker misreading or suspected vector/spec disagreement. Passing these
127 cases does not settle underspecified inputs they do not exercise. All noticed
ambiguities and chosen interpretations were recorded before the freeze in
`checker/IMPLEMENTATION-NOTES.md` and are summarized in REPORT.md.

## Adapter audit

The runner changes only transport representation, not verification semantics.
`record` remains exact decoded bytes, including the invalid UTF-8 cases AR-C25-k.
Subject and offer wrappers are decoded into their JSON objects. Outcome becomes
raw bytes. Caller trust/chain field renamings are `ed25519` -> `key`, `code` ->
`hasCode`, and `returns` -> `returnData`. The adapter has no vector-ID or expectation
input, and never alters signed members, signature bytes, trust identities or chain
facts. These mappings address SPEC §5's unpinned JSON binding (pre-freeze
IMPLEMENTATION-NOTES item 1), not fixes to the checker.

## Staged documentation

The only staged README is the results README. A separate vector-layout README was
not present; the vector file's own generator note says inputs are unpadded
base64url-encoded exact bytes, and the transport field inventory was inspected
post-freeze. The staged seeds.json was not opened. No reference implementation or
private conformance repository was read.
