# Requirement cases, version 0

Shodai (CNS Labs). Draft, not ratified.

These 25 cases state what a verifier built from [SPEC.md](SPEC.md) must return. Each case gives its inputs as a
change to the baseline fixture below, the operation it runs, the expected output, and the requirements it tests.
Exact input and output bytes for every case follow as separate vector files; nothing in this file is a signed
artifact, and no value here has been run.

**Reading a row.**
- **Form.** `EIP-712` or `JWS`: the case runs in that form only. `both`: the case runs in each form with the same
  expected output, except that a variant labeled `EIP-712` or `JWS` runs in that form only. A cell such as
  `EIP-712 (a)–(e); JWS (f)–(i)` says which variants run in which form. `none`: no record is supplied.
- **Variants.** Lettered variants (a), (b), … are separate inputs with the same expected output. Each variant, in
  each form it names, becomes its own vector.
- **Check.** `verify` is the operation of SPEC AR-35.
- **Expected.** The result token, then the condition set, then whichever of `disposition`, `reason` and
  `policy_refusal` the output carries (SPEC AR-36). Members not listed are absent. Condition sets compare without
  order. Where a cell says `except (b) …`, that variant alone carries the stated value.

## Baseline fixture

Unless a case says otherwise, every record in a case is validly signed, after its change is applied, by the key or
account its `signer` names, under its form's rules. Where a change makes the EIP-712 typed message unbuildable,
`signature` is the baseline record's signature unchanged. "t0" is 1791500000.

**Parties and keys.**
- **Seller and delivery issuer:** `did:web:seller.example`, with Ed25519 key KS.
- **Seller account:** SELLER, an ordinary account on chain 84532. `trust.issuers` lists it for
  `did:web:seller.example` only where a case says so.
- **Buyer, EIP-712 form:** ordinary account BUYER on chain 84532.
- **Buyer, JWS form:** Ed25519 key KB, `kid` `cp-1`, signer identifier `did:example:buyer`.
- **Other accounts:** OTHER, an ordinary account; WALLET, a contract account on chain 84532. PAYEE and ASSET are
  addresses.

The vectors publish test keys; this file describes them and publishes no private key.

**Seller records.**
- **Offer A:** an x402 signed offer in JWS form (`alg` `EdDSA`, `kid` `did:web:seller.example#ks`), signed with KS.
  Its payload is `{version: 1, resourceUrl: "https://seller.example/report", scheme: "exact", network:
  "eip155:84532", asset: ASSET, payTo: PAYEE, amount: "10000", validUntil: t0 + 3600}`. TA is `0x` + hex SHA-256 of
  JCS of that payload.
- **Receipt A:** an `x402ev/1` `info` object in the shape of that specification's example, signed with KS
  (`signer.keyType` `Ed25519`, `signer.publicKey` KS). It has payment `{network: "eip155:84532", payer: BUYER,
  payee: PAYEE, amount: "10000", asset: ASSET}`, a `request.clientNonce`, `delivery.contentDigest`
  `sha256:` + DA, and `delivery.timestamp` t0. It has no `txHash`, `fingerprint` or `transparency`. Its
  `evidenceRef` is EA = `x402ev/1:sha256:` + HA.
- **Receipt B:** Receipt A with a different `request.clientNonce`, signed with KS: a second paid call that returned
  the same bytes. `evidenceRef` EB = `x402ev/1:sha256:` + HB.
- **Receipt C:** Receipt A with `payment.payer` WALLET, signed with KS. `evidenceRef` EC = `x402ev/1:sha256:` + HC.

Offers write `asset` and `payTo`, and receipts write `payment.payer`, in EIP-55 mixed-case spelling. All other
addresses, including the receipts' `payment.payee` and `payment.asset`, are written in lowercase hex.

**Baseline records.**
- **EIP-712:** body `{version: 0, contextId: 0x+HA, deliveryIssuer: "did:web:seller.example", confirmingParty:
  "eip155:84532:"+BUYER, signer: "eip155:84532:"+BUYER, authority: {mode: "direct", profile: "payer/0", reference:
  ""}, termsDigest: TA, outcomeDigest: 0x+DA, subject: {profile: "x402ev/1", reference: EA}, disposition:
  "accepted", issuedAt: t0 + 600}`, signed by BUYER.
- **JWS:** the same body except `confirmingParty` and `signer` `"did:example:buyer"` and authority `{mode:
  "declared", profile: "declared-evidence/0", reference: ""}`. Protected header `{alg: "EdDSA", kid: "cp-1", typ:
  "x402-acceptance+jws"}`, signed with KB.

**Baseline inputs.**
- `record`: the baseline record of the case's form.
- `subject`: Receipt A.
- `terms`: Offer A.
- `trust.issuers`: `did:web:seller.example` → KS, key id `did:web:seller.example#ks`.
- `trust.keys`: `{kid: "cp-1", signer: "did:example:buyer", key: KB}`.
- `trust.authority`: `{confirmingParty: "did:example:buyer", signer: "did:example:buyer", subjectProfile:
  "x402ev/1", subjectReference: EA}`.
- `trust.complete`: absent.
- `chain`: on 84532 at block 1000, BUYER and OTHER have no code; WALLET has code, and for each record WALLET signs in
  a case, the listed `isValidSignature` call with that record's digest and signature returns `0x1626ba7e` followed by
  28 zero bytes. No other call is listed, and nothing is listed for other chains.
- `contractAccounts`: true.

## Cases

| ID | Title | Form | Given (change from baseline) | Check | Expected | Rules |
|---|---|---|---|---|---|---|
| AR-C01 | Baseline acceptance | both | (a) None. (b) `terms` holds Offer A2 and then Offer A, where Offer A2 is Offer A with `validUntil` t0 + 7200, signed with KS; the record is unchanged. (c) EIP-712 only: the baseline EIP-712 body with authority `{mode: "declared", profile: "declared-evidence/0", reference: ""}`, signed by BUYER, and `trust.authority` gains `{confirmingParty: "eip155:84532:"+BUYER, signer: "eip155:84532:"+BUYER, subjectProfile: "x402ev/1", subjectReference: EA}`. (d) `terms` holds only Offer A in EIP-712 form with `validUntil` 0, signed by SELLER, which the `trust.issuers` entry for `did:web:seller.example` also lists for this variant; `termsDigest` is `0x` + hex SHA-256 of JCS of that offer's payload. | verify | `verified`; {}; disposition `accepted` | AR-1, AR-4–AR-13, AR-15–AR-20, AR-23–AR-27, AR-29, AR-31 (EIP-712), AR-32 (JWS; EIP-712 (c)), AR-35, AR-36 |
| AR-C02 | A later dispute leaves an earlier acceptance as it was | EIP-712 | Two records by BUYER: the baseline record, and record D, the baseline body with `disposition` `disputed` and `issuedAt` t0 + 900. Each is verified on its own with the baseline inputs. | verify, once per record | Baseline record: `verified`; {}; `accepted`. Record D: `verified`; {}; `disputed`. | AR-3, AR-1 |
| AR-C03 | No record | none | `record` absent. | verify | `no_record`; {} | AR-35, AR-37 |
| AR-C04 | Signed `not_responded` | both | `disposition` `"not_responded"`. | verify | `malformed`; {`acceptance_member_invalid`} | AR-1 |
| AR-C05 | Record not closed or not in the stated shape | both | (a) extra body member `"reason": "late"`; (d) `subject` gains member `"uri"`; (e) the envelope gains member `"hint"`; (l) `version` 1. EIP-712 only: (f) `signer` with its address in mixed-case checksum spelling, `confirmingParty` unchanged; (g) `signer` `eip155:84532:0x` + 40 zeros, with any 65-byte signature; (o) `signer` and `confirmingParty` `eip155:084532:` + BUYER; (p) `signer` and `confirmingParty` `eip155:0:` + BUYER. | verify | `malformed`; {`acceptance_member_invalid`} | AR-4, AR-5, AR-7, AR-10, AR-11 |
| AR-C06 | Confirming party absent | both | `confirmingParty` `""`. | verify | `malformed`; {`confirming_party_absent`} | AR-34, AR-5 |
| AR-C07 | Signer is the delivery issuer | JWS (a)–(b); EIP-712 (c) | (a) `trust.keys` gains `{kid: "cp-9", signer: "did:example:buyer", key: KS}`; the record's header `kid` is `cp-9` and it is signed with KS. (b) Body `signer` and `confirmingParty` `"did:web:seller.example"`; the `cp-1` entry's `signer` is `"did:web:seller.example"`, and the `trust.authority` entry names that party and signer. (c) The `trust.issuers` entry for `did:web:seller.example` also lists BUYER's address. | verify | `malformed`; {`acceptance_signer_is_issuer`} | AR-33 |
| AR-C08 | Terms differ from the seller's offer | both | `termsDigest` is `0x` + hex SHA-256 of JCS of Offer A's payload with `amount` `"20000"`. That offer is not supplied. | verify | `malformed`; {`acceptance_terms_digest_mismatch`} | AR-29 |
| AR-C09 | Outcome differs from the receipt | both | (a) `outcomeDigest` is `0x` + the hex of a SHA-256 value other than DA; (b) the baseline record, with `outcome` supplied as bytes whose SHA-256 is not DA. | verify | `malformed`; {`acceptance_outcome_digest_mismatch`} | AR-25 |
| AR-C10 | Acceptance presented against another delivery | both | (a) `subject` input is Receipt B; the record still names EA and HA. (b) `contextId` is `0x` + HB; `subject.reference` stays EA; `subject` input is Receipt A. | verify | `malformed`; {`acceptance_record_digest_mismatch`} | AR-24 |
| AR-C11 | Acceptance before the outcome | both | `issuedAt` t0 − 1. | verify | `malformed`; {`acceptance_precedes_outcome`} | AR-26 |
| AR-C12 | Rejection in the same second as the outcome | EIP-712 | `issuedAt` t0; `disposition` `"rejected"`. | verify | `verified`; {}; disposition `rejected` | AR-26, AR-1, AR-2 |
| AR-C13 | All conditions reported; a dependent check skipped | JWS | `termsDigest` as in AR-C08; `outcomeDigest` `"0xabc"`. (JWS only: in EIP-712 an ill-formed `outcomeDigest` stops at preflight, AR-10.) | verify | `malformed`; {`acceptance_member_invalid`, `acceptance_terms_digest_mismatch`} | AR-35, AR-5, AR-29 |
| AR-C14 | Signature checked before bindings | EIP-712 | After signing, `termsDigest` is replaced as in AR-C08; the signature is unchanged. | verify | `malformed`; {`signature_invalid`} | AR-35, AR-13 |
| AR-C15 | Signed under another domain, type or chain | EIP-712 | Signed with: (a) domain `{name, version, chainId: 84532}` typed `EIP712Domain(string name,string version,uint256 chainId)`; (b) domain `version` `"1"`; (c) the `Acceptance` members in alphabetical order; (d) a body naming chain 84532 in `signer` and `confirmingParty`, presented with both changed to name chain 8453. For (d), `chain` also says BUYER has no code on 8453. (e) domain `{name, version, verifyingContract: PAYEE}` typed `EIP712Domain(string name,string version,address verifyingContract)`. | verify | `malformed`; {`signature_invalid`} | AR-8, AR-9, AR-12, AR-13 |
| AR-C16 | Signature encodings refused | EIP-712 (a)–(e), (j)–(m); JWS (f)–(i) | (a) `s` replaced by n − s and `v` switched between 27 and 28; (b) `v` replaced by `v` − 27; (c) the 64-byte compact form r ‖ (yParity · 2^255 + s); (d) the signature hex in uppercase; (e) AR-C17's inputs with the call returning `0xffffffff` followed by 28 zero bytes; (j) the baseline record unchanged, with `chain` saying BUYER has code on 84532 and the call for that record returning `0xffffffff` followed by 28 zero bytes (BUYER's 65-byte signature would recover); (k) AR-C17's inputs with the call giving `revert`; (l) AR-C17's inputs with the signature hex in uppercase, no call listed for it; (m) AR-C17's inputs with the call returning `0x1626ba7e` followed by 27 zero bytes (31 bytes of return data). (f) One byte of the signature flipped; (g) `S` replaced by `S` + L; (h) `R` = the identity point's encoding and `S` = k·a mod L, where a is KB's secret scalar and k = SHA-512(R ‖ A ‖ M) mod L, so the cofactorless equation accepts; (i) `R'` = rB + T, T a point of order 8, and `S'` = r + k'·a mod L with k' = SHA-512(R' ‖ A ‖ M) mod L, so the cofactored equation accepts and the cofactorless one fails. | verify | `malformed`; {`signature_invalid`} | AR-13, AR-14, AR-17, AR-20 |
| AR-C17 | Contract account | EIP-712 | `subject` input is Receipt C. Body: `contextId` `0x` + HC, `subject.reference` EC, `signer` and `confirmingParty` `eip155:84532:` + WALLET; signed by WALLET. (a) The listed call returns the baseline 32 bytes. (b) The listed call returns `0x1626ba7e` followed by 60 zero bytes: 64 bytes whose first word is the magic value. | verify | `verified`; {}; disposition `accepted` | AR-12, AR-14, AR-31 |
| AR-C18 | Contract account not resolvable | EIP-712 | AR-C17's inputs, with: (a) no `chain` entry for WALLET on 84532; (b) `contractAccounts` false; (c) `signer` and `confirmingParty` naming `eip155:8453:` + WALLET, signed by WALLET, and `chain` listing WALLET on 84532 with code and a valid call for this record, and nothing for chain 8453 (a verifier using 84532 would return `verified` or `unknown`); (d) as (a), with `trust.complete` true. | verify | `key_unresolved`; {}; `policy_refusal` false; reason `chain_state_unavailable`, except (b) `contract_accounts_unsupported` | AR-12, AR-14, AR-36 |
| AR-C19 | JWS key absent from a complete trust input | JWS | `trust.complete` true, and: (a) header `kid` `cp-2`, signed with a key that is not in `trust.keys`; (b) header `kid` `cp-1`, signed with KB, with body `signer` and `confirmingParty` `"did:example:other"`; (c) (a)'s input with an extra body member `"reason": "late"`. | verify | `key_unresolved`; {}; `policy_refusal` true; reason `key_missing`, except (b) `signer_mismatch` | AR-18, AR-22, AR-35, AR-36 |
| AR-C20 | Refused Ed25519 keys | JWS | `trust.complete` is the JSON string `"true"`. The `cp-1` entry's key is: (a) the identity point, with signature `R` = the identity point's encoding and `S` = 0; (b) KB + T, T a point of order 8, with a signature both RFC 8032 equations accept; (c) a non-canonical encoding with y ≥ p. | verify | `key_unresolved`; {}; `policy_refusal` false; reason `key_refused` | AR-19, AR-22 |
| AR-C21 | JWS header or payload not in the profile | JWS | (a) `typ` `"JWT"`; (b) the header gains `"cty": "json"`; (c) `alg` `"ES256K"` with a valid secp256k1 signature; (d) the payload is the body serialized with a space after each colon, validly signed over those bytes; (e) the payload decodes to a JSON array, and one signature byte is flipped; (f) the protected header names `alg` twice, both times `"EdDSA"`; (g) the signature segment's last character changed so that its unused bits are non-zero, decoding to the same bytes. | verify | `malformed`; {`acceptance_member_invalid`} | AR-6, AR-15, AR-16, AR-35 |
| AR-C22 | Valid signature, authority not established | EIP-712 (a)–(b), (e)–(h); JWS (c)–(d) | (a) `signer` and `confirmingParty` `eip155:84532:` + OTHER, signed by OTHER, who is not Receipt A's payer; (b) AR-C17's inputs with `confirmingParty` `"did:web:acme.example"`; (e) authority `{mode: "direct", profile: "payer/1", reference: ""}`; (f) authority `{mode: "declared", profile: "payer/0", reference: ""}`; (g) authority `{mode: "direct", profile: "payer/0", reference: "x"}`; (h) the baseline EIP-712 record with `confirmingParty` `"did:web:acme.example"`, still signed by BUYER, the payer, so a payer signing for another party does not resolve. (c) `trust.authority` empty; (d) the `trust.authority` entry's `subjectReference` is EB. | verify | `unknown`; {`acceptance_authority_unresolved`}; disposition `accepted` | AR-30, AR-31, AR-32 |
| AR-C23 | Unknown subject profile | both | `subject.profile` `"other/9"`. | verify | `unknown`; {}; reason `profile_unavailable`; disposition `accepted` | AR-23, AR-35 |
| AR-C24 | Evidence unavailable | both | (a) `terms` empty; (b) `subject` absent; (c) Receipt A with `delivery.latencyMs` changed after signing; (d) `terms` holds only Offer A with `amount` `"20000"`, signed with KS; (e) `deliveryIssuer` `"did:web:other.example"`, which `trust.issuers` does not list; (f) `terms` holds only Offer A re-signed with an Ed25519 key not listed in `trust.issuers`; (g) `terms` holds only Offer A in EIP-712 form, signed by an address not listed; (h) Receipt A re-signed with `delivery.contentDigest` `sha256:` + 64 uppercase hex digits, its new `evidenceRef` and digest carried into `subject.reference` and `contextId`; (i) Receipt A with its signature's `S` replaced by `S` + L; (j) Receipt A re-signed with an Ed25519 key that `trust.issuers` does not list for `deliveryIssuer`, with `signer.publicKey` set to that key, so that its `evidenceRef` and signature check under that key; its new `evidenceRef` and digest carried into `subject.reference` and `contextId`. | verify | `unknown`; {}; reason `evidence_unavailable`; disposition `accepted` | AR-23, AR-27, AR-29, AR-35 |
| AR-C25 | Numbers and text not in the stated encoding | both | Variant letters are kept from the earlier combined case, so AR-C05 and AR-C25 together use (a)–(p) once each. (b) `issuedAt` as the JSON string `"1791500600"`; (c) the member name `disposition` appears twice, both times `"accepted"`; (h) `issuedAt` written `1791500600.0`; (i) `issuedAt` written `1.7915006e9`; (j) `issuedAt` written `01791500600`; (k) a string member contains the byte 0xFF; (m) `issuedAt` 9007199254740992; (n) a string member contains the escape `\ud800`. | verify | `malformed`; {`acceptance_member_invalid`} | AR-5, AR-6, AR-10 |

### Composition

This version defines one subject profile, `x402ev/1`. Acceptances of other records, such as third-party findings,
are composed through subject profiles that later revisions may add (SPEC, Composition note); an unknown profile is
covered by AR-C23.

## Coverage

Every requirement maps to cases that violate it, or is marked positive-only, deferred to vectors, not
data-testable with the reason, or reserved.

| Rule | Cases | Note |
|---|---|---|
| AR-1 | AR-C04; positive AR-C01, AR-C02, AR-C12 | |
| AR-2 | AR-C12 (a verified rejection) | Otherwise not data-testable: governs consumers. |
| AR-3 | AR-C02 | |
| AR-4 | AR-C05 (a), (d) | |
| AR-5 | AR-C05 (l), AR-C25 (b), (m), AR-C13, AR-C06 | |
| AR-6 | AR-C25 (c), (h)–(k), (n); AR-C21 (f) | Conformant JCS is exercised by AR-C21 (d) and by the digests the vectors fix (AR-16, AR-21, AR-29). |
| AR-7 | AR-C05 (e) | |
| AR-8 | AR-C15 (a), (b), (e) | The signing-request rule is signer-side; its effect is AR-C15 (a). |
| AR-9 | AR-C15 (c) | |
| AR-10 | AR-C05 (f), (g), (l), (o), (p) and AR-C25 (b), (m) in EIP-712; positive AR-C01 | |
| AR-11 | AR-C05 (f), (g), (o), (p) | |
| AR-12 | AR-C18 (a), (c); AR-C15 (d) | AR-C18 (c) fails a verifier that uses the payment network's chain. |
| AR-13 | AR-C14, AR-C16 (a)–(d) | |
| AR-14 | AR-C16 (e), (j)–(m); AR-C18; positive AR-C17 (a), (b) | AR-C16 (j) fails a verifier that falls back to recovery. Recording the chain and block is not data-testable. |
| AR-15 | AR-C21 (a)–(c), (g) | |
| AR-16 | AR-C21 (d) | |
| AR-17 | AR-C16 (f) | |
| AR-18 | AR-C19 (a), (b) | Duplicate `kid` inputs are refused before `verify`; no case uses one. |
| AR-19 | AR-C20 | |
| AR-20 | AR-C16 (g)–(i) | |
| AR-21 | — | Deferred to vectors: not result-changing; identity values are fixed with the bytes. |
| AR-22 | AR-C19, AR-C20 | |
| AR-23 | AR-C23, AR-C24 (b), (c), (e), (h), (i), (j) | |
| AR-24 | AR-C10 | |
| AR-25 | AR-C09 (a), (b); bytes absent in every positive case | |
| AR-26 | AR-C11; boundary AR-C12; AR-C02 | |
| AR-27 | AR-C24 (c), (h), (j); positive AR-C01 (mixed-case payer) | |
| AR-28 | — | Reserved. |
| AR-29 | AR-C08, AR-C24 (a), (d), (f), (g); positive AR-C01 (b), (d) and mixed-case offer addresses | |
| AR-30 | AR-C22 (a)–(g) | (e)–(g): unsupported triples. |
| AR-31 | AR-C22 (a), (b), (h); positive AR-C01, AR-C17 | |
| AR-32 | AR-C22 (c), (d); positive AR-C01 (JWS, and EIP-712 (c)) | How the relying party weighs evidence is not data-testable. |
| AR-33 | AR-C07 (a)–(c) | (a) issuer key, (b) string equality, (c) listed account. |
| AR-34 | AR-C06 | |
| AR-35 | AR-C03, AR-C13, AR-C14, AR-C19 (c), AR-C21 (e), AR-C22, AR-C23, AR-C24 | Each step's stopping rule. |
| AR-36 | every case; `policy_refusal` AR-C18 (d), AR-C19, AR-C20; `reason` on `key_unresolved` AR-C18, AR-C19, AR-C20 | |
| AR-37 | AR-C03 | |
