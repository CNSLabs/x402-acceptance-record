# Post-freeze vector runner

This directory was created only after checker commit
`bec16636ff3c2afa0b7ec7a0a32ab2179f96817c` existed and FREEZE.md was written.
It never writes inside checker/, disables Python bytecode caches, verifies the
checker is clean before and after running, checks archive hashes and source pins,
and uses exclusive creation for result JSON so an earlier result cannot be replaced.

```sh
.venv313/bin/python -B runner/run_vectors.py --json rerun-cnslabs-cleanroom-sol-2026-10-26.json
```

The staged package contains `vectors.json`, one README (the results README), and
one sample result. A separate vectors-layout README was not staged. `seeds.json`
is also present but is not needed and is deliberately not opened.

Transport adaptation is deliberately separate from verification:

- base64url record -> exact bytes (not parsed/re-serialized)
- base64url subject and each offer -> parsed JSON evidence object
- base64url outcome -> exact bytes
- issuer key `ed25519` -> checker key `key`, preserving `kid`
- chain fact `code` -> checker fact `hasCode`
- call `returns` -> checker call `returnData`; `revert` remains unchanged

No vector ID, expected result, fixture digest, signer, signed field, trust meaning,
chain classification, or signature is consulted or changed by `adapt_inputs`.
It performs no result-dependent branching. The comparison projects the five AR-36
members and compares the condition set without order; absent optional fields must
stay absent. All expected and actual objects are recorded, including passes.
