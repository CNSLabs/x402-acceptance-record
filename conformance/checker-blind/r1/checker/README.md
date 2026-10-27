# Clean-room Sol Python checker — x402 acceptance record v0

This checker was written entirely by an AI agent in a clean context, from the
specification texts below alone, before access to published vectors. It is not a
ratified standard or a production security audit. No private conformance repository,
reference checker, web implementation, or stage-two file informed this version.

## Stage-one inputs read

From `../inputs/stage1-spec-only/` only:

- `SPEC.md` (AR-1 through AR-37, especially AR-35 and AR-36)
- `CASES.md` (requirement cases, not signed vectors)
- `README.md`
- `LICENSE`
- `upstream-pinned/extension-offer-and-receipt.md@faa1c694.md`
- `upstream-pinned/execution_evidence.md@23b5c21.md`

The task `../BRIEF.md` is the provenance/workflow instruction, not an implementation
source. `../READ-LOG.md` records explicit file reads in UTC order. Standard runtime
and installed dependency imports are library operations, not project source reads.
`SOURCE-MANIFEST.json` records SHA-256 of the six source files. The complete
stage-one implementation, selftest and these design decisions are committed before
stage-two inputs are opened. `../FREEZE.md` will carry its immutable commit and tree
archive hash. Any later transport runner is outside this repository.

## Runtime and installation

Python 3.12+ (actually run with Python 3.13.14). Runtime dependencies:
`coincurve==21.0.0` (libsecp256k1 recovery), `cryptography==46.0.3` (Ed25519),
`pycryptodome==3.23.0` (Ethereum Keccak-256), `rfc8785==0.1.4` (JCS).
`requirements.lock` pins these and all resolved transitive runtime dependencies.

From the parent task directory, the built environment is `.venv313`:

```sh
.venv313/bin/python -B checker/cli.py selftest
.venv313/bin/python -B checker/cli.py verify path/to/inputs.json
```

For a separate installation, create a Python 3.12+ virtualenv, then install with
`python -m pip install -r checker/requirements.lock`. Package installation is a
build-time operation. Verification and selftest never access the network.

## API and JSON binding

`from acceptance import verify` accepts a Python dictionary and returns exactly the
normative AR-36 members (conditions serialized as a sorted array representing a set).
The CLI writes that object as JSON to stdout. Caller configuration errors such as
duplicate `trust.keys.kid` raise `InputRefused`; the CLI writes an error to stderr and
exits 2 without an AR-36 result. A verification result, including malformed, exits 0.

- `record`: JSON text (Python `str` or raw `bytes`), absent or null. For convenience,
  an already parsed envelope object is serialized with JCS. To test malformed
  lexical encodings use raw text/bytes, not a parsed object. The CLI outer JSON can
  carry ordinary malformed record text as a string; a runner can pass raw bytes
  to the API for invalid-UTF-8 records.
- `subject`: the `execution-evidence.info` object, or absent.
- `terms`: a list of issuer-signed offer artifacts; one artifact object is also
  accepted as a convenience. Both upstream signing formats are supported.
- `outcome`: optional raw Python bytes; CLI may use UTF-8 text, `{"hex":"0x..."}`
  or `{"base64url":"..."}`. Null is treated as unsupplied.
- `trust.issuers`: `[{"issuer":"did:web:...","keys":[...]}]`. Ed25519 key entries
  are unpadded base64url strings or objects `{"key":"<base64url>","kid":"optional"}`
  (a `publicKey` field can replace `key`). Address entries are `"0x<40 hex>"` or
  `{"address":"0x<40 hex>"}`. Explicit `{"hex":"..."}` or
  `{"base64url":"..."}` encoding objects are also accepted for Ed25519 bytes.
- `trust.keys`: `[{"kid":"...","signer":"...","key":"<base64url>"}]`.
- `trust.authority`: exact four-field declared-evidence entries from SPEC §5.
- `trust.complete`: only the JSON boolean true declares completeness.
- `chain`: `[{"chainId":"84532","account":"0x...","block":1000,
  "hasCode":false,"calls":[]}]`. A number or decimal string can carry chainId.
  For code-bearing accounts set `hasCode:true`; calls are
  `{"digest":"0x<64 hex>","signature":"0x...","returnData":"0x..."}` or
  `{"digest":"...","signature":"...","returnData":"revert"}`. Missing facts
  are unavailable, never inferred or fetched. The `revert:true` form is also
  accepted. Classification of EIP-7702 designators must be `hasCode:true`.
- `contractAccounts`: boolean, default true.

## Design

`acceptance.py` implements the nine AR-35 steps directly, in order: absence;
format-specific preflight; key/account resolution then signature verification;
aggregate independent malformed checks; malformed/profile/evidence/authority
terminal precedence; verified. It keeps no decision state between records.

I-JSON decoding refuses duplicate names, non-UTF-8 text, lone surrogates and
nonfinite constants. Acceptance-number parsing refuses signs, fractions, exponents
and leading zeroes before JSON object member validation. JWS's delayed JCS equality
check follows key/signature resolution. JCS is provided by the pinned RFC 8785
library, including UTF-16 property ordering and ECMAScript number formatting.

Ed25519 keys and signature R points are decompressed canonically and checked for
exact order L with independent extended-coordinate subgroup arithmetic; identity,
small-order, mixed-order and y >= p encodings are refused. S must be below L.
The cryptography library then performs RFC 8032 signature verification. These gates
apply equally to acceptance, subject, and terms evidence.

EIP-712 builds exact AR-8/9/10 types locally. EOA recovery enforces lowercase 65-byte
encoding, v=27/28, and low-s without normalization. Contract accounts are never
recovered; an exact caller-supplied chain/block/digest/signature fact must return
the ERC-1271 ABI first word, with at least 32 bytes. No RPC client is included.

The x402ev authenticator uses only pinned verification rule 1. It removes exactly
`evidenceRef`, `signer.signature`, and `transparency` from the canonical preimage.
Offer authentication uses issuer authorization, exact network/amount and
address-aware asset/payee matching, and validity at the delivery timestamp.
No settlement, delivery resource binding, response obligation or quality claim is
inferred. `IMPLEMENTATION-NOTES.md` records every ambiguity noticed during build.

## Selftest

`selftest.py` creates fresh synthetic Ed25519 and secp256k1 keys, subject records,
offers and acceptance records entirely in memory. It exercises both signing forms,
terms forms, independent malformed aggregation, precedence, strict encodings,
Ed25519 point/scalar rejection, chain facts, ERC-1271 ABI lengths, authority,
evidence absence, JCS ordering/numbers, timing boundaries and record independence.
No published vector file is imported by the selftest.
