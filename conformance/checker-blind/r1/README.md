# Post-review revision r1 (2026-10-26)

**What this is.** A second commit, `68bb522`, in the checker's own repository, directly on the frozen commit `bec16636`, made after the first run in response to Vic's review of 2026-10-26 16:03 ET. The frozen commit, its archive hash and the first-run result (`v0/results/rerun-mike-2026-10-26.json`) are unchanged, and `../checker/` is still the frozen tree. Here, `checker/` is the r1 tree, `r1.patch` is the full diff (3 files, 51 insertions, 1 deletion), and `../provenance/checker-r1.bundle` holds both commits.

## Findings and classification

1. **A JWS offer whose `network` is not CAIP-2 (`"base"`) qualified** when the subject's `payment.network` matched byte for byte, so the record verified. Classification: checker inconsistency plus a spec gap. The EIP-712 branch enforced `eip155:<chainId>` per extension §3.1.1; the JWS branch applied only AR-29's byte-equality. The extension's §4.2 field table, and its note that offer and receipt payloads MUST use CAIP-2, are production-side requirements; neither the verification steps in §4.5 nor SPEC.md AR-29 directs a verifier to enforce them. r1 disregards a JWS offer whose `network` does not match the CAIP-2 grammar `[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}`, so such a record is `unknown` with `evidence_unavailable`. Proposed spec text: AR-29 states that an offer whose `network` is not a CAIP-2 identifier is disregarded.
2. **An EIP-712 offer with `version` written `1.0` or `validUntil` written `1e2` was disregarded**, giving `unknown` with `evidence_unavailable`. Classification: checker binding stricter than the text. The extension's schema types both fields as JSON integers, which these spellings satisfy by value; EIP-712 signs the value, and the JCS digest does not depend on the spelling. The frozen binding required a Python `int` (pre-freeze implementation note 7 had recorded the missing numeric domain). r1 normalizes an integral JSON number in 0..2^53−1 to an integer in a local copy of the EIP-712 payload before hashing; the later type and range checks are unchanged. JWS payloads must still be byte-identical to their JCS form (extension §10), and the acceptance record's AR-6 plain-digit rule is unchanged. Proposed spec text: EIP-712 payload integers compare by value.

## Verification at `68bb522`

- `cli.py selftest`: 87 passed, 0 failed (84 before; three new synthetic regressions, fresh keys, no vector read).
- Staged vectors: 127 of 127, `v0/results/rerun-mike-r1-2026-10-26.json`, vector file SHA-256 unchanged (`8c20c905…`).
- `review-repro/`: five inputs rebuilt from the review's description with fresh synthetic keys by `repro.py` (the review's own fixtures were not opened). On the frozen commit they give verified, verified, verified, unknown, unknown (`results-frozen.json`); on r1 they give verified, unknown, verified, verified, verified (`results-r1.json`). `repro.py` expects the checker one directory up at `../checker`.

## Provenance

The r1 change was written by an AI agent (GPT-6.1 Sol) in an isolated context operated by Molt, from the review text and the pinned specification texts, reviewed by Molt, and amended once before publication to remove a "local and unpushed" sentence from the implementation notes (`4f65ce5` → `68bb522`, code identical). No other checker was consulted. The commit carries Mike Norman's git identity, as the rest of this branch does. The frozen checker was not modified; everything in r1 is additive.
