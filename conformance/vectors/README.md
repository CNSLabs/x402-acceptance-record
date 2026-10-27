# Vectors for the x402 acceptance record, version 0

Exact input and output bytes for every case in `CASES.md` of the published specification
(CNSLabs/x402-acceptance-record, tag `draft-2026-10-21`, commit `ad53b54ad59df93bd5d3258963f27acccdcec23c`),
in both signing forms where the case says `both`. One vector per variant per form, as the case list's reading
rules define them. The expected outputs are typed by hand from the case rows; nothing in `expect` was read
back from a checker.

`vectors.json` and `seeds.json` are dedicated to the public domain under CC0 1.0 Universal, like the case list.
No key here was ever funded on any chain; every private key derives from a published seed.

## File layout

```
{
  "profile": "x402 acceptance record, version 0",
  "specification": { "repository", "tag", "commit", "files": { "SPEC.md": <sha256>, "CASES.md": <sha256> } },
  "generator": { "seedsDigest": <sha256 of JCS(seeds)>, "note": <string> },
  "fixture": { "t0": 1791500000, "keys": {...}, "addresses": {...}, "digests": {...} },
  "vectors": [ <vector>, ... ]
}
```

`fixture` publishes the public keys, addresses and digests the case list names (KS, KB, BUYER, OTHER, SELLER,
WALLET, PAYEE, ASSET, TA, DA, HA, HB, HC, EA, EB, EC) so a reader can follow a vector back to its row. It is
informative; the checker reads only `vectors[*].inputs`.

## A vector

```
{
  "id": "AR-C01-a-eip712",          // <case>-<variant>-<form>
  "case": "AR-C01",
  "variant": "a",                   // the row's variant letter, or a label where the row has none
  "form": "eip712" | "jws" | "none",
  "title": "Baseline acceptance",
  "note": "what this variant changes from the baseline",
  "inputs": { ... },                // the verifier's inputs of SPEC section 5, see below
  "expect": { ... },                // the asserted output members of SPEC AR-36, see below
  "statementId": "x402accept/0:sha256:..."   // AR-21, present when the body is well formed; informative
}
```

### `inputs`

Every byte-exact input is carried as **unpadded base64url of its exact bytes**, never as parsed JSON, because
several cases depend on the lexical form of the text (duplicate member names, number spellings, a byte that is
not UTF-8). Decode, then hand the bytes to the verifier unchanged.

| Member | Form | Meaning (SPEC section 5) |
|---|---|---|
| `record` | base64url string, or `null` | The envelope's JSON text. `null` means the `record` input is absent (AR-C03). |
| `subject` | base64url string, or `null` | The subject record as its profile transmits it: for `x402ev/1`, the `execution-evidence` `info` object's JSON text. `null` means absent. |
| `terms` | array of base64url strings | Zero or more terms artifacts. Each decodes to the JSON text of an x402 signed offer object in the offer and receipt extension's shape: `{"format":"jws","signature":"<compact JWS>"}` or `{"format":"eip712","payload":{...},"signature":"0x..."}`. |
| `outcome` | base64url string, optional | The delivered bytes. Absent in every case but AR-C09 (b). |
| `trust` | object | See below. |
| `chain` | array | Declared chain state. See below. |
| `contractAccounts` | boolean | Whether the verifier validates contract accounts. Absent means `true`. |

`trust`:

```
{
  "issuers":   [ { "issuer": "did:web:seller.example",
                   "keys": [ { "ed25519": "<base64url, 32 bytes>", "kid": "did:web:seller.example#ks" },
                             { "address": "0x<40 lowercase hex>" } ] } ],
  "keys":      [ { "kid": "cp-1", "signer": "did:example:buyer", "key": "<base64url, 32 bytes>" } ],
  "authority": [ { "confirmingParty": "...", "signer": "...", "subjectProfile": "x402ev/1", "subjectReference": "x402ev/1:sha256:..." } ],
  "complete":  <any JSON value>      // optional; absent means the input is absent (AR-22)
}
```

`issuers[*].keys[*]` is either an Ed25519 key (`ed25519`, with an optional `kid`) or an Ethereum address
(`address`). Addresses are written in lowercase here; the specification compares them case-insensitively.

`chain` is a list of declarations, each for one `(chainId, account)` at one block:

```
{ "chainId": 84532, "block": 1000, "account": "0x<40 lowercase hex>", "code": false }
{ "chainId": 84532, "block": 1000, "account": "0x<40 lowercase hex>", "code": true,
  "calls": [ { "digest": "0x<64 hex>", "signature": "0x<hex>", "returns": "0x<hex>" },
             { "digest": "0x<64 hex>", "signature": "0x<hex>", "revert": true } ] }
```

A listed account's `code` says whether it has code on that chain at that block. For an account with code, each
listed call is the result of `isValidSignature(digest, signature)` for that exact digest (the EIP-712 digest of
the record's typed message, 32 bytes) and that exact signature (the record's `signature` bytes): either the
return data or a revert. Accounts, chains and calls that are not listed are unavailable to the verifier
(AR-12, AR-14). `block` is informative.

### `expect`

```
{ "result": "verified" | "malformed" | "key_unresolved" | "unknown" | "no_record",
  "conditions": [ ... ],            // compared as a set; [] when none
  "disposition": "accepted",        // only where AR-36 says it is present
  "reason": "...",                  // only where AR-36 says it is present
  "policy_refusal": false }         // only where AR-36 says it is present
```

A checker passes a vector when its output has the same `result`, the same set of `conditions`, and, for each
of `disposition`, `reason` and `policy_refusal`, the same value when `expect` lists it and no value when it does
not. Other members of the checker's output are not compared (AR-36 allows them).

## Generator readings

Where the case list leaves a construction choice open, the generator made these. None changes an expected output;
they are listed so a checker author can see what the bytes assume.

- **Receipts** are the `x402ev/1` `info` object serialized as JCS, in the shape of that proposal's example without
  `txHash`, `fingerprint` or `transparency`; `signer.signature` carries the `base64url:` prefix the example uses.
  `request` has `method`, `urlHash`, `clientNonce` and `timestamp`.
- **Offers in JWS form** have the header `{"alg":"EdDSA","kid":"did:web:seller.example#ks"}` and a JCS payload;
  EIP-712 offers are signed under `{name: "x402 offer", version: "1", chainId: 1}` with the extension's `Offer` types.
- **"Validly signed after its change is applied"** for an EIP-712 record with an extra member (AR-C05 (a), (d)) means
  the signature covers the typed message built from the eleven known members; the extra member is not part of the
  typed data. Where the typed message cannot be built (AR-C05 (f), (g), (l), (o), (p), AR-C25 in EIP-712 form), the
  baseline record's signature is carried unchanged, as the fixture says.
- **AR-C24 (c)** changes `delivery.latencyMs` from 42 to 43 in the receipt text; **AR-C24 (i)** rewrites the receipt's
  `signer.signature` value with `S + L`; **AR-C25 (k)** places the byte 0xFF inside the `deliveryIssuer` value and
  **AR-C25 (n)** places the escape `\ud800` there.
- **AR-C16 (l)** lists no call for the uppercase signature, since AR-14 refuses it before any call.
- **Chain declarations** are all at block 1000; a call is matched by its exact `digest` and `signature` strings.
- **WALLET's signature** is a deterministic 65-byte blob; only the declared `isValidSignature` result gives it meaning.
- **Ed25519 forgeries** (AR-C16 (h), (i); AR-C20 (b)) are built from KB's secret scalar as the rows describe; the
  generator's self-test checks that the cofactorless and cofactored equations behave as each row states.

## Running

Three checkers consume this file. The TypeScript one below; the Python one in `../checker-python-independent/` has
its own README with a pinned environment and reads its frozen copy of this file, identical byte for byte; the
blind Python one in `../checker-blind/` reads it through a post-freeze adapter, as its README says.

From the package root, the directory above this one: `npm install`, then `npm test` runs the checker in `checker/` over this file and prints one line
per vector and the totals. `npm run check` regenerates the vectors from the seeds and fails if any byte differs
from the committed file. `SHA256SUMS` lists the digests of `vectors.json` and `seeds.json`.
