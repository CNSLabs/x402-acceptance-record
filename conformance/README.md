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
| `checker-python-cleanroom/` | A Python checker written from the specification texts alone and frozen, in its own git repository, before its author saw any vector; 127 of 127 on the first run. Brief, read log, freeze receipt, the frozen repository as a bundle, and ten spec ambiguities logged before the freeze are inside. | Apache-2.0 (code), CC0 1.0 (reports) |
| `results/` | Pinned runs: `checker-ts-<commit>.json` for the TypeScript checker, `rerun-vic-2026-10-26.json` and its note for the fresh-context Python checker, `rerun-cnslabs-cleanroom-sol-2026-10-26.json` for the clean-room one. | CC0 1.0 |

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

**`checker-python-cleanroom/`, Python, the clean-room implementation.** Written by an AI agent (GPT-6.1 Sol) in an
isolated context operated by Molt for CNS Labs, from SPEC.md, CASES.md, the README and LICENSE at the published tag
and the two pinned upstream texts, and nothing else: no generator, no other checker, no vectors, nothing from this
package. Every file read is timestamped in its read log. The checker was committed in its own git repository
(`bec16636`, 2026-10-26T19:03:24Z) and its tree hash recorded before the first vector was read; the bundle of that
repository is in `provenance/`, and the files under `checker/` are that tree. A transport adapter written after the
freeze decodes the vector layout and renames three input fields; it never reads an expected result. First run, no
changes before or after: 127 of 127, re-run by Molt on the same commit with the same result; 84 synthetic self-tests.
Ten points it found ambiguous while implementing were written down before the freeze
(`checker/IMPLEMENTATION-NOTES.md`). The run is `results/rerun-cnslabs-cleanroom-sol-2026-10-26.json`.

## Where the checkers read the text differently

All three pass every vector, so these differences fall outside the corpus. They are candidates for sentences in the
specification, and a reason to keep more than one checker. The clean-room checker's ten pre-freeze notes
(`checker-python-cleanroom/checker/IMPLEMENTATION-NOTES.md`) cover the same ground from a reader who had seen no
code: the section 5 input model is not a wire schema; the dependency graph of the malformed pass is not enumerated;
chain-fact precedence and block selection are unstated; the receipt schema is partial; the payer's chain-id spelling
is looser than AR-11; the offer extension's unknown members, expiration domain and ECDSA conventions are looser than
AR-13; issuer account identity has no stated representation or chain scope; absent versus null is undefined. The two
below are where the TypeScript and fresh-context Python checkers made opposite choices:

- **Which key verifies a JWS offer (AR-29).** The Python checker uses only a listed Ed25519 key whose declared key id
  equals the offer header's `kid`. The TypeScript checker treats `kid` as a lookup hint and accepts any Ed25519 key
  `trust.issuers` lists for `deliveryIssuer`. AR-29 says "a key or address `trust.issuers` lists" and does not
  mention `kid`.
- **Unknown members in an offer payload.** The Python checker disregards an offer whose payload carries a member the
  extension does not define, following the extension's forward-compatibility guidance. The TypeScript checker
  verifies and digests the payload as transmitted, so such an offer can qualify. AR-29 is silent.
- **A zero EVM address as receipt payer or payee.** Both accept it, reading the upstream rule's "distinct non-null
  entities" as present and distinct. Vic's ledger records the open question; neither checker bans the zero address
  there, while AR-11 bans it for the acceptance signer.
