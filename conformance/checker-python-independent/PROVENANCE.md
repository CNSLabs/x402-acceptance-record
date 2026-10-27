<!-- human-doc: evidence -->
# Implementation provenance

Primary job: document what this verifier author could inspect, what was actually inspected, and the limits of the independence claim.

The initial implementation was written in a fresh agent context using the parent's inherited model and reasoning effort, unchanged. The author worked in the supplied isolated temporary workspace. Existing acceptance-record checkers and generators, repository implementation, previous review checkouts, parent implementation artifacts, Slack, and other agent histories were not opened. The author did not ask another agent for implementation guidance. No separate human author or organizational independence is claimed.

The permitted packet was read: `SPEC.md`, `CASES.md`, `VECTOR-FORMAT.md`, both pinned upstream specification texts, `SOURCE-MANIFEST.json`, and `vectors.json`. The expected results were visible and used by the separate assertion runner. The verifier only receives `vectors[*].inputs`, decoded to exact bytes; it never receives an ID or expected result. It does not open the corpus.

The specification pin is `ad53b54ad59df93bd5d3258963f27acccdcec23c`; the corpus pin is `b3bd7cb228cce98803cadcdfb75bc847e4455df8`. The upstream texts are execution evidence at `23b5c21125982961a2d4c13faf3cb5a6d6d7c03b` and offer/receipt at `faa1c694c66a3732aaabbce93bdae140e521a67d`.

The corpus SHA-256 was checked before and after runs and remains:

```text
8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5
```

During the work the packet preparer corrected one extra trailing LF in each upstream copy and added the authorized numeric probe data. Adding exactly one LF to each corrected text reproduced its original supplied hash, confirming the source change was only that byte. Both old and new hashes remain in [access-log.json](access-log.json); every run checks the current frozen manifest. The corpus bytes were never changed.

The first complete implementation, dependency lock, and source hashes were frozen in [attempts/first-implementation](attempts/first-implementation/) before the initial corpus run. Additional pre-correction snapshots and every initial failing report remain in `attempts/` and `results/`. Corrections were recorded in [disagreements.json](disagreements.json). No expected corpus output was changed.

After the first corpus run, the parent transmitted two candidates from a fresh-context read-only reviewer who had read this implementation and the permitted normative packet, without reference implementation access. The author checked the relevant texts, built fresh signed regressions, retained their failures, and corrected the demonstrated defects. The final implementation therefore includes disclosed post-first-run review, while the initial implementation remains independently derived from the packet and general libraries.

## General libraries and primary documents

The verifier uses Trail of Bits' `rfc8785` 0.1.4 for all JCS serialization, PyNaCl 1.6.0 for Ed25519 verification and point operations, `eth-keys` 0.7.0 with an explicitly selected `NativeECCBackend` for secp256k1 recovery, and PyCryptodome 3.23.0 for Ethereum Keccak. Every direct and transitive installed package is pinned in [requirements.lock](requirements.lock). Runtime versions and loaded file-backed modules are in each corpus report; [library-files.json](library-files.json) also records installed dependency metadata and binary hashes. The PyNaCl binary does not expose a queryable libsodium version here; its exact binary hash is recorded instead of guessing that version.

Official documentation consulted is logged by URL in [access-log.json](access-log.json): RFC 8785, RFC 8032, EIP-712, CAIP-2, libsodium point arithmetic, PyNaCl signing, eth-keys, PyCryptodome Keccak, and the rfc8785 package. Coincurve's general library documentation was opened during dependency selection, but Coincurve was not used. An initial sandboxed dependency fetch could not resolve DNS; the authorized retried installation succeeded except for Coincurve's Python 3.14 packaging failure. The implementation selected eth-keys' native backend instead. Package-manager subprocesses briefly used OS-managed temporary build directories; the installed environment and all author-created artifacts remained in this workspace. No unrelated project files were opened.

The libsodium documentation identifies an older subgroup-validation defect. This verifier requires canonical Ed25519 encodings and explicitly checks `[L-1]P + P = identity` in addition to the library point check, for both public keys and signature R points. It then uses the library signature verification operation. The published mixed-order and small-order corpus cases pass.

## Supplemental number evidence

The 26 cases from RFC 8785 Appendix B are encoded as their IEEE-754 bit strings, including two expected non-finite rejections. The additional frozen data came from `stillmarcus24/assurance-run` at `335ed5df8ca16658ec2c5b5e0cb34449bf1dc6f0` (11 probes) and `aos-standard/catalog` at `40b21297af1289dde5849da1ea6f1caa3ab8d140` (1,001 doubles). Only data and the supplied frozen manifest were opened; those projects' implementation and runner code were not supplied or opened. File hashes are in the packet manifest and numeric reports.

The runner parses each original `json_text` or TSV `json` spelling directly. It does not pre-convert through JavaScript strings, substitute expected values, or coerce integer-valued floats into strings before testing. It independently verifies the TSV's binary64 bit patterns. All 1,038 supplemental cases match. These finite test sets strengthen the numerical evidence; they do not exhaust the binary64 domain.

## Scope and remaining limits

Only `x402ev/1`, the two defined authority triples, acceptance EIP-712, acceptance Ed25519 JWS, and the specified offer forms are supported. Unknown offer payload fields are treated as unsupported according to the upstream forward-compatibility guidance. Offer JWS key resolution uses explicitly declared issuer key IDs; receipt key authorization uses the 32-byte key values.

Trust and chain facts are relying-party inputs. Contract validation uses the exact supplied `(chainId, account, digest, signature)` call declaration and retains the block diagnostic on success; it is not a live ERC-1271 integration. Settlement, content bytes when absent, resource identity between offer and receipt, and consequences of acceptance remain outside the draft's verified claim.

The upstream phrase “distinct non-null entities” does not explicitly classify a syntactically valid zero EVM address. An exploratory test expected rejection but the implementation accepted its authenticated receipt; this is retained as an unresolved textual ambiguity, with no normative expected result. The current verifier rejects empty payer/payee identifiers and equal addresses but does not add the acceptance signer's explicit zero-address ban to receipt parties by inference.
