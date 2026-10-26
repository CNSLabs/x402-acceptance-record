# Disagreements

## First run

127 of 127 vectors passed on the frozen commit `bec16636`. There is no miss to classify as a vector defect, a checker defect or a spec ambiguity. No other checker was opened at any point, and `vectors.json` was not modified (SHA-256 `8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5`).

## Post-review findings (Vic, 2026-10-26 16:03 ET)

Two misses outside the shared corpus, both reproduced independently with fresh synthetic keys. (1) A JWS offer with `network: "base"` qualified against a subject with the same spelling: checker inconsistency (the EIP-712 branch enforces `eip155:`, the JWS branch did not) plus a spec gap (neither extension §4.5 nor AR-29 directs a verifier to enforce §4.2's CAIP-2 requirement). (2) `version: 1.0` or `validUntil: 1e2` in an EIP-712 offer was disregarded: checker binding stricter than the text (the extension's schema types both as integers, satisfied by value). Corrected in `r1/` as a second commit on the frozen one; the frozen commit and first-run result are unchanged. Classification, proposed spec text and verification: `r1/README.md`.

## This checker's readings on the three points where the other two checkers already differ

All three are decided in the frozen `checker/acceptance.py`; none is exercised by a vector, so passing says nothing about them. The readings were chosen before any vector was seen.

1. **Which key may verify a JWS offer.** A key listed for the declaring issuer is tried if it carries no `kid`, or if its `kid` equals the JWS header's `kid`. A listed key with a different `kid` is not tried. So: neither "declared kid only" nor "any listed issuer key"; keys without a `kid` are treated as unscoped. (`_qualifying_terms`, candidate selection.)
2. **An offer payload with an unknown member.** It does not qualify. Unknown signed payload members are refused; see `checker/IMPLEMENTATION-NOTES.md` item 7, which also records that the upstream extension has only a SHOULD about unknown fields.
3. **A zero EVM address as the receipt payer.** Rejected. The subject's payment is refused when payer equals payee, or when either is the literal `null` or the all-zero 20-byte address, so a zero payer does not authenticate the subject and `payer/0` does not resolve. The author recorded the "distinct non-null payer and payee" requirement in item 5 of the implementation notes.

## RFC 8785 numbers

Canonicalization uses the `rfc8785` package (0.1.4), pinned. The 11 number probes and the 1,001-double catalog that travel with the independent checker were not run against this checker; they can be, post-freeze, without touching the verifier.

## Ambiguities recorded before the freeze

Ten, in `checker/IMPLEMENTATION-NOTES.md` and summarized in `REPORT.md`: the section 5 input binding; the parse-pass overlap between AR-6 and AR-35; dependency gating between AR-35 comparisons; chain freshness and block selection in AR-12 and AR-14; the partial x402ev schema in AR-27; `eip155` payer spelling in AR-27; offer payload fields and expiration bounds in AR-29; offer ECDSA versus the stricter acceptance ECDSA of AR-13; issuer account identity in AR-33 and section 5; absent versus explicit null in AR-18. Where the spec text is at fault, the fix belongs in the text, not in the vectors.
