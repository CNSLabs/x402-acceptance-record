# Vic's review packet of 26 October, run through all three checkers

Source: `x402-checker-review-repro-2026-10-26.zip`, posted by Vic in the team channel on 2026-10-26 16:03 ET with his
review of the blind checker (frozen commit `bec16636`). The signed input bytes and recorded outputs are unchanged. The reproduction runner now selects either the original
frozen revision or r1; documentation describes that addition. The five fixtures are signed synthetic inputs in the vector layout; `our_result` is his checker's output,
`mike_result` the blind checker's output he observed.

Run here on the same day, each checker through its own entry point (the TypeScript runner; Vic's `cli.py`; the blind
checker's `acceptance.verify` behind its own `runner.adapt_inputs`), without changing any checker:

| Fixture | TypeScript (authors') | fresh-context Python | blind Python |
| --- | --- | --- | --- |
| `valid-jws-baseline` | verified | verified | verified |
| `valid-eip712-offer-baseline` | verified | verified | verified |
| `integral-float-offer-version` (`version: 1.0`) | verified | verified | unknown, evidence_unavailable |
| `integral-exponent-offer-expiry` (`validUntil: 1e2`) | verified | verified | unknown, evidence_unavailable |
| `invalid-caip2-offer-network` (`network: "base"`) | verified | unknown, evidence_unavailable | verified |

Classification is in `../../README.md`, "Findings outside the corpus". The separately recorded r1 correction makes the three mutated inputs match the fresh-context checker.
The table above remains the original observation; the frozen implementation and first-run result are unchanged.
