# Notice

x402 acceptance record, version 0 (draft). Shodai (CNS Labs).

## Licensing

- The specification and documentation (README.md, SPEC.md, NOTICE.md) are licensed under the Apache License,
  Version 2.0 (LICENSE).
- The requirement cases (CASES.md), the vectors and seeds (conformance/vectors/) and the recorded runs
  (conformance/results/) are dedicated to the public domain under CC0 1.0 Universal (LICENSE-CC0).
- The generator and the checkers (conformance/generator/, conformance/checker/,
  conformance/checker-python-independent/, conformance/checker-python-cleanroom/) are licensed under the Apache
  License, Version 2.0 (LICENSE).

## Third-party material

The fresh-context Python checker's frozen input packet (conformance/checker-python-independent/inputs/) reproduces the two x402
extension texts it was built from (Apache-2.0), stillmarcus24's RFC 8785 number probes (MIT) and the aos-standard
catalog's number corpus (CC0), each credited with its licence in
conformance/checker-python-independent/THIRD-PARTY-NOTICES.md. Nothing else is reproduced; works named under Credits
are referenced, not copied.

## Credits

This record builds on public work by others. Credit does not imply endorsement.

- **Condition table.** The result tokens, dispositions and conditions follow Shodai's posts on
  [x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4) of October 4 and 5, 2026, including the
  October 5 additions `acceptance_member_invalid` and `acceptance_record_digest_mismatch`.
- **Key step.** draft-krausz-verification-state-03, §5.4.2: `key_unresolved` versus `signature_invalid`, with the
  completeness input.
- **babyblueviper1**: the `acceptance-record-v0` cold build of those conditions
  (`preaction-governance-conformance`, `examples/acceptance-record-cold`), its evaluation-order readings and its
  vectors.
- **Tetsurohhori**: the probes behind the header, timestamp-form and completeness-input rules of
  `acceptance-record-v0`.
- **actaseal**: the independent implementation that surfaced its evaluation-order readings, and the
  `key_unresolved` / `signature_invalid` vector pair.
- **stillmarcus24**: the mutation test that pinned the untrimmed, byte-exact confirming-party rule.
- **robertolocatelli81-dev (Noûs)** and **TKCollective**: the refusal of small-order and mixed-order Ed25519 keys and
  signature points.
- **maximusrufus (Trilatic)**: the work-acceptance record proposal on x402-foundation/tsc#4, which shaped the
  composition design.
- **magentixai**: the AXES requirements register, whose GAP-EXEC-002 (two-sided non-repudiation) motivated a
  counterparty-signed record.
- **x402 offer and receipt extension**: the signed offer used as the seller's terms commitment, and the precedent for
  the EIP-712 and JWS forms.
- **whawk46**: x402 execution evidence `x402ev/1` (x402 PR #3682), whose `evidenceRef` names the delivery.
- **johnInarti**: the x402 delivery receipt proposal (x402 PR #3783), noted as a future subject profile.
- **holistis**: the Buyer Delivery Claim proposal (x402 PR #3604), the closest buyer-side prior work.

The independent implementers of `acceptance-record-v0`, listed in its README, showed which rules a cold reader needs
stated; several rules here are written with their findings in mind.
