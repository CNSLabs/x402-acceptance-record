# Checker

The authors' checker for the x402 acceptance record, version 0, in TypeScript. It implements `verify` as SPEC.md
AR-35 defines it and returns the output of AR-36; `run-vectors.ts` runs it over `../vectors/vectors.json`.

This is the authors' implementation, not a clean-room one. It was written with AI assistance in a working context
separate from the generator's, from SPEC.md, CASES.md, the vector layout and the two upstream texts the specification
pins, without opening the generator; two small helper files (Ed25519 order rules, encodings) were copied from the
earlier checker and reviewed, and the vectors' expected objects were visible before it was finished. The full account
is in `../README.md`. Independent reruns are recorded in `../results/` by their authors.

Run, from the package root, the directory above this one:

```
npm test                                   # all vectors
npx tsx checker/run-vectors.ts vectors/vectors.json --only AR-C18        # one case, or a comma-separated list of ids
npx tsx checker/run-vectors.ts vectors/vectors.json --json results/checker-ts.json
npx tsx checker/selftest.ts                # synthetic checks of the JSON reader, base64url, Ed25519 rules and scenarios
```

Layout: `verify.ts` (the AR-35 steps, in order), `json.ts` (a strict I-JSON reader over bytes that keeps each
number's lexeme, for AR-5 and AR-6), `jws.ts` and `eip712.ts` (the two signing forms), `ed25519.ts` (point-order
and scalar rules of AR-19 and AR-20), `subject.ts` (`x402ev/1`, AR-23 to AR-27), `terms.ts` (signed offers, AR-29),
`body.ts` (member forms), `inputs.ts` (the input types of SPEC section 5), `encoding.ts`.

It uses no clock and no network: every input comes from the vector, including declared chain state (AR-12, AR-14).
JCS is `canonicalize`, which serializes numbers with `JSON.stringify`, the ECMAScript rule RFC 8785 requires; a
JavaScript implementation inherits that rule rather than earning it, so the vectors' JCS digests, not this checker,
are the evidence of canonicalization. Licence: Apache-2.0.
