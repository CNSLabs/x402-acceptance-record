# Signed regression reproduction

Primary job: reproduce two checker findings using five synthetic signed inputs.

This packet supplements the original 127-vector corpus. It preserves the original freeze and first-run result. The full signed input envelopes and observed outputs are in `repro.json`; no real credentials or transaction funds are involved.

Use the dependencies pinned by Mike's checker, then run:

```sh
python reproduce.py --package ../../checker-blind --revision frozen
```

Run from this review directory. Repeat with `--revision r1` for the corrected successor. The package argument names the directory containing `checker/`, `r1/checker/` and `runner/`. The script only imports the existing transport adapter and verifier; it does not execute the corpus runner or append to the read log.

At the reviewed frozen version, all five cases match the recorded Mike result; the two baseline cases match the expected result, while the three mutations do not. The mutations represent two issues:

- A signed JWS offer and receipt using `base` rather than a CAIP-2 network identifier are accepted. The pinned offer specification section 4.2 requires CAIP-2 syntax.
- EIP-712 seller offer values `version: 1.0` and `validUntil: 1e2` are rejected despite having the same numeric values and canonical/signing meaning as `1` and `100`. The acceptance-record numeric spelling restriction does not apply to the seller offer.

The expected results here come from the cited specification rules and our existing independent-checker regression cases. Compare the listed normative result members, excluding the optional statementId. This packet removes an earlier raw-object equality flag that counted the optional statementId as a difference; input bytes and observed outputs are unchanged.

Source pins are included in `repro.json`. The public export uses a relative fixture-source link; all signed inputs and recorded outputs remain unchanged.
