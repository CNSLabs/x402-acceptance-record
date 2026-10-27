# x402 acceptance record

Shodai (CNS Labs). **Draft, not ratified.**

An acceptance record is the counterparty's signed answer, usually the buyer's, about one specific x402 delivery:
`accepted`, `rejected` or `disputed`. It is bound to that delivery through the seller's signed delivery record, which it
names by that record's own identifier and through which it reaches the delivery's payment. It checks its terms against
the seller's signed x402 offer on amount, asset, payee and network (this version does not bind the offer's resource to
the delivery), and establishes authority from the payer the delivery record names or from other declared evidence
about that delivery. A relying party verifies it from the
record, the delivery record it names, the seller's signed offer, chain facts for EIP-712 signers, and its own trust
inputs.

## What this adds

Shodai posted a set of acceptance conditions to
[x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4) on October 4–6, 2026
([condition table](https://github.com/x402-foundation/tsc/issues/4#issuecomment-5983983078),
[record binding and member conditions](https://github.com/x402-foundation/tsc/issues/4#issuecomment-5986215440),
[expected records and fingerprints](https://github.com/x402-foundation/tsc/issues/4#issuecomment-6018007147)).
The community built the
[`acceptance-record-v0`](https://github.com/babyblueviper1/preaction-governance-conformance/tree/3243d33077d75a13c07eea1e05901101acdb316b/examples/acceptance-record-cold)
profile and its vectors from them, and several independent implementations have been tested against it.

This record keeps those result tokens and conditions, and their evaluation order except where noted below, and adds:
- **an EIP-712 form with contract wallets**, beside JWS, with one body and one meaning. Contract accounts are
  checked with ERC-1271 on the chain the signed message names;
- **the delivery referenced by its existing x402 identifier**: for x402 execution evidence (`x402ev/1`,
  [x402 PR #3682](https://github.com/x402-foundation/x402/pull/3682), unmerged), the receipt's own identifier
  `evidenceRef`, byte for byte, rather than a new hash of the whole record;
- **timestamps in seconds**: integer Unix seconds, as x402 receipts use;
- **a closed record**: a fixed, versioned body in which unknown members are rejected.

It also differs from `acceptance-record-v0` in ways a checker will notice:
- the body is parsed before the key step, so a body or JWS payload that does not parse is `acceptance_member_invalid`
  even when its signature is also invalid, where `acceptance-record-v0` reports `signature_invalid` for a payload
  that decodes but is not an object;
- `unknown` may also carry no condition and a reason, `profile_unavailable` or `evidence_unavailable`, when the
  verifier lacks the subject profile or the subject or terms evidence; in `acceptance-record-v0` it always carries
  `acceptance_authority_unresolved`;
- the JWS header requires `typ`, the payload must be the JCS serialization of the body, and authority goes through a
  named profile;
- a `trust.keys` input that lists one `kid` twice is refused, rather than resolved to its first entry;
- every `key_unresolved` carries a `reason` (`key_missing`, `signer_mismatch`, `key_refused`,
  `chain_state_unavailable` or `contract_accounts_unsupported`), so a missing key and an impersonation attempt differ;
- a missing record reports `no_record` without a disposition, where `acceptance-record-v0` reports `not_responded`.

Two further points shape the meaning. The terms are checked against a record the delivery's issuer signed (for a
paid x402 call, the seller's signed offer), so a digest written only by the buyer is not enough. The match covers
amount, asset, payee and network, not the resource: the delivery record does not yet define how it names the resource.
A verified record does not establish settlement either; the delivery record's own rules cover that. Authority is
specific to the delivery: being the payer is one way to establish it, declared evidence such as a purchase or trust
record is another, and authority that does not resolve reports `unknown`.

The signing domain carries no chain. The signer's chain is named inside the signed message, and the verifier checks
the signature on that chain. An ordinary account's wallet can therefore sign while on any network, without switching. Verifying an EIP-712 record
needs chain facts for the signer's chain (whether the account has code), supplied or fetched; a JWS record needs none.
Accounts that bind signatures to their own chain must sign on the chain the message names (SPEC §11).

## Status

- Draft for review. It is not an x402 specification and has not been ratified.
- Identifiers (domain name, JWS `typ`, profile names, version) are draft identifiers and may change.
- Examples (SPEC §4.4) are illustrative and unrun.
- Vectors for every case and three checkers are published under [`conformance/`](conformance/) (27 October): 127 vectors in both signing forms, regenerating from published seeds; the authors' TypeScript checker; a Python checker implemented in a fresh agent context from the published texts, with the reference implementations unopened by its author and the expected outputs visible; and a blind Python checker, written from the specification texts alone and frozen before its author saw any vector, 127 of 127 on its first run. The blind checker’s original result is preserved beside its post-review r1 correction. Each is described as it was built in `conformance/README.md`. Independent reruns are invited and recorded there.
- Shodai intends to implement SDK support once the specification is accepted and ratified into x402.
- Response windows are coming in the next revision.

## Files

| File | What it is |
|---|---|
| [SPEC.md](SPEC.md) | The record, the two signing forms, subject and authority profiles, and the `verify` operation. |
| [CASES.md](CASES.md) | 25 requirement cases: inputs, expected result and the rule each tests, with a coverage table. |
| [NOTICE.md](NOTICE.md) | Licensing and credits. |
| [conformance/](conformance/) | Vectors over the 25 cases in both signing forms (CC0), the generator and the checkers, each described as built (Apache-2.0), and recorded runs. |
| [LICENSE](LICENSE) | Apache License, Version 2.0, covering the specification and documentation. |
| [LICENSE-CC0](LICENSE-CC0) | CC0 1.0 Universal dedication, covering the requirement cases and vectors. |

## How it relates to other records

| Record | Who signs what | Relation to this record |
|---|---|---|
| Delivery evidence (`x402ev/1`, [x402 PR #3682](https://github.com/x402-foundation/x402/pull/3682); the delivery-receipt proposal, [x402 PR #3783](https://github.com/x402-foundation/x402/pull/3783), is a future profile) | The seller's server signs what it delivered and for which payment. | `x402ev/1` is the subject this record decides about, not the decision. |
| Buyer delivery claim ([x402 PR #3604](https://github.com/x402-foundation/x402/pull/3604), holistis) | The paying buyer signs whether delivery happened. | Closest buyer-side prior work. This record adds binding to the seller's signed offer (amount, asset, payee and network, not the resource), outcome binding and delivery-specific authority. |
| Evaluator or judge verdicts | A third party signs its own judgment. | Not the counterparty's decision, and its authority comes from its own scheme. |
| Payment fingerprints | A participant computes a shared identifier for a payment. | Correlation only; not a signed decision. |

## Composition

An acceptance names its subject through a subject profile; the subject record and the acceptance keep their own
signers and claims. This release focuses on x402 delivery records and defines one profile, x402 execution evidence.
Composition with other records, including third-party findings such as Trilatic's work-acceptance record
([maximusrufus/work-acceptance-record](https://github.com/maximusrufus/work-acceptance-record)), proposed on
[x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4), is follow-up work while that record's
updated profile settles.

## Not in this version

Response windows and response obligations; delegation systems; subject profiles for delivery receipts and for
third-party records such as work-acceptance records; binding the offer's resource to the delivery; revocation;
partial or streamed deliveries; transport and storage; and any settlement or reputation consequence. The full list
is in SPEC §10. `not_responded` is reserved: it means "a response was due under the terms and none arrived", and this
version never produces it.

## Feedback

Comments are welcome on [x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4) or as issues on
this repository. Disagreement with a case's expected result is the most useful kind.
