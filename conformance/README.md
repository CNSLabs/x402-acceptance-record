# x402 acceptance record, version 0: vectors and checkers

Conformance material for the published specification (CNSLabs/x402-acceptance-record, tag `draft-2026-10-21`,
commit `ad53b54`):

| Path | What it is | Licence |
| --- | --- | --- |
| `vectors/vectors.json` | One vector per case variant per signing form, 127 in all: exact bytes in, asserted output out. Layout in `vectors/README.md`. | CC0 1.0 |
| `vectors/seeds.json` | The seeds every test key derives from. Throwaway keys, never funded. | CC0 1.0 |
| `generator/` | Deterministic generator. `npm run build` writes the vectors; `npm run check` rebuilds and compares bytes; `npm run selftest` checks the hand-built cases. | Apache-2.0 |
| `checker/` | The authors' checker, TypeScript. `npm test` runs it over the vectors; `npm run selftest:checker` runs its synthetic checks. | Apache-2.0 |
| `checker-python-independent/` | A Python checker implemented in a fresh agent context from the published texts, with the reference implementations unopened by its author. Its own README, provenance, disagreement ledger and reports are inside. | Apache-2.0 (code), CC0 1.0 (reports) |
| `checker-blind/` | A blind Python checker: written from the specification texts alone and frozen, in its own git repository, before its author saw any vector; 127 of 127 on the first run. Brief, read log, freeze receipt, the frozen repository as a bundle, and ten spec ambiguities logged before the freeze are inside. | Apache-2.0 (code), CC0 1.0 (reports) |
| `results/` | Pinned runs: `checker-ts-<commit>.json` for the TypeScript checker, `rerun-vic-2026-10-26.json` and its note for the fresh-context Python checker, `rerun-mike-2026-10-26.json` for the frozen blind one and `rerun-mike-r1-2026-10-26.json` for its corrected successor. | CC0 1.0 |

Everything runs offline; nothing is submitted to any chain. Setup for the TypeScript parts: Node 22, `npm install` in
this directory. Setup for the Python checker: Python 3.12 or newer and its `requirements.lock`, as its README says.
In the public repository this package lives under `conformance/`.

## How each checker was built

Each checker is described as it was built, no more. The thread this work answers distinguishes "independent, not
blind" (the expected outputs were visible to the implementer) from a blind implementation (frozen before its author
saw any vector), and both from a third party's clean-room run.

**`checker/`, TypeScript, the authors' checker.** Written with AI assistance in a working context separate from the
generator's. Its inputs were SPEC.md and CASES.md at the published tag, the vector layout in `vectors/README.md`, and
the two upstream texts the specification pins (x402 execution evidence at `23b5c21`, the offer and receipt extension
at `faa1c694`). It did not open the generator or the earlier checker's verification code; it copied two small helper
files from the earlier checker, the Ed25519 point-order and scalar rules and the base64url and JCS encodings, and
reviewed them against the specification. The vectors were produced in parallel and were run against it before it was
finished, so their expected objects were visible to its author. It passes 127 of 127; the run is
`results/checker-ts-0b35fdc.json`.

**`checker-python-independent/`, Python, Vic's fresh-context implementation.** Written by an agent in a fresh context
on Vic's side, from a frozen packet of SPEC.md, CASES.md, the vector layout, the two pinned upstream texts and the
vectors, with general libraries (`rfc8785`, PyNaCl, `eth-keys`, PyCryptodome). It did not open the TypeScript checker,
the generator or the earlier checker. The expected outputs were visible and are read only by its assertion runner;
the verifier itself receives decoded inputs only. Its first implementation was frozen before the first run and is
preserved; a second fresh-context reviewer's findings and the corrections that followed are in its disagreement
ledger. It passes 127 of 127 outputs and 89 of 89 statement identities, the 26 RFC 8785 Appendix B number cases,
stillmarcus24's 11 number probes and the 1,001 catalog doubles. Its runner verifies the digests of its frozen packet
and refuses any other corpus, so a changed vector file stops it rather than running; its own signed regression tests
are where its discrimination is shown. Full account: `checker-python-independent/PROVENANCE.md` and `PACKAGING.md`;
the run is `results/rerun-vic-2026-10-26.json`.

**`checker-blind/`, Python, the blind implementation.** Written by an AI agent (GPT-6.1 Sol) in an
isolated context operated by Molt for CNS Labs, from SPEC.md, CASES.md, the README and LICENSE at the published tag
and the two pinned upstream texts, and nothing else: no generator, no other checker, no vectors, nothing from this
package. Every file read is timestamped in its read log. The checker was committed in its own git repository
(`bec16636`, 2026-10-26T19:03:24Z) and its tree hash recorded before the first vector was read; the bundle of that
repository is in `provenance/`, and the files under `checker/` are that tree. A transport adapter written after the
freeze decodes the vector layout and renames three input fields; it never reads an expected result. First run, no
changes to the frozen verifier: 127 of 127, re-run by Molt on the same commit with the same result; 84 synthetic self-tests.
The separately preserved post-review revision r1 passes 127 of 127 and 87 synthetic self-tests; it incorporates
the two corrections below and is not described as an unchanged blind implementation.
Ten points it found ambiguous while implementing were written down before the freeze
(`checker/IMPLEMENTATION-NOTES.md`). The run is `results/rerun-mike-2026-10-26.json`.

## Where the checkers read the text differently

All three pass every vector, so these differences fall outside the corpus. They are candidates for sentences in the
specification, and a reason to keep more than one checker. The blind checker's ten pre-freeze notes
(`checker-blind/checker/IMPLEMENTATION-NOTES.md`) cover the same ground from a reader who had seen no code: the
section 5 input model is not a wire schema; the dependency graph of the malformed pass is not enumerated; chain-fact
precedence and block selection are unstated; the receipt schema is partial; the payer's chain-id spelling is looser
than AR-11; the offer extension's unknown members, expiration domain and ECDSA conventions are looser than AR-13;
issuer account identity has no stated representation or chain scope; absent versus null is undefined. Three points
where the checkers decided differently, each recorded in its own notes:

- **Which key may verify a JWS offer (AR-29).** The TypeScript checker treats the header `kid` as a lookup hint and
  accepts any Ed25519 key `trust.issuers` lists for `deliveryIssuer`. The fresh-context checker uses only a listed key
  whose declared key id equals the header's `kid`. The blind checker tries a listed key when it has no `kid` or its
  `kid` equals the header's. AR-29 says "a key or address `trust.issuers` lists" and does not mention `kid`.
- **Unknown members in an offer payload.** The TypeScript checker verifies and digests the payload as transmitted, so
  such an offer can qualify. The fresh-context and blind checkers refuse it, following the extension's
  forward-compatibility guidance. AR-29 is silent.
- **A zero EVM address as receipt payer or payee.** The TypeScript and fresh-context checkers accept it, reading the
  upstream rule's "distinct non-null entities" as present and distinct. The blind checker rejects it: a payment whose
  payer or payee is the zero address does not authenticate the subject. AR-11 bans the zero address for the
  acceptance signer only.

## Findings outside the corpus, 26 October

Vic ran five signed fixtures from his checker's regression suite, two baselines and three mutations, through the
blind checker, and the same five were then run here through all three checkers without changing any of them. The
baselines verify everywhere; the mutations split the checkers.

| Fixture | TypeScript (authors') | fresh-context Python | blind Python |
| --- | --- | --- | --- |
| EIP-712 offer with `version` written `1.0` | verified | verified | unknown, `evidence_unavailable` |
| EIP-712 offer with `validUntil` written `1e2` | verified | verified | unknown, `evidence_unavailable` |
| JWS offer and receipt both naming network `base` | verified | unknown, `evidence_unavailable` | verified |

- **Number spellings in an offer: a blind-checker defect.** The offer extension types `version` and `validUntil` as
  numbers; `1.0` is the number 1 and `1e2` is 100, the typed-data values and the JCS digest are unchanged, and AR-6's
  plain-digit rule applies to the acceptance body, not to the seller's offer. Mike's separate
  [r1 revision](checker-blind/r1/README.md) fixes these cases. The frozen implementation and first-run result
  remain unchanged; the successor and its rerun are recorded separately.
- **A network identifier that is not CAIP-2: a spec ambiguity.** AR-29 compares the offer's and the receipt's
  `network` byte for byte, and AR-27 makes the `eip155:<decimal>` form a condition for deriving the payer, not for the
  subject's availability; a record under `declared-evidence/0` needs no payer, so two checkers verify it. The
  extension's §4.2 describes `network` as CAIP-2, which the fresh-context checker enforces. The proposed clarification would state
  explicitly whether CAIP-2 syntax is required for an offer to qualify. This does not restrict valid networks to
  EVM networks. No vector in the 127-case corpus exercises this input; the signed supplemental fixtures do.

The table above records the original frozen implementations. In r1, both number-spelling cases verify and the
non-CAIP-2 offer yields `unknown / evidence_unavailable`. The TypeScript reading remains unchanged. Mike's
proposed clarifying sentences are not adopted spec changes.

The original five signed fixtures and observed outputs are in
[review/2026-10-26-vic-repro/](review/2026-10-26-vic-repro/); Mike's separately generated inputs and before/after
results are in [checker-blind/r1/review-repro/](checker-blind/r1/review-repro/). See the
[package rerun instructions](checker-blind/README.md#reproduce) for both the frozen and corrected revisions.

[Integration verification](results/package-integration-review-2026-10-26.md) records the assembled package checks.
