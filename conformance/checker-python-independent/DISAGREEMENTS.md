<!-- human-doc: evidence -->
# Disagreements and corrections

Primary job: preserve the initial results and explain every correction or unresolved interpretation.

The final corpus run matches 127/127 normative outputs and 89/89 statement identities. There are no remaining supplied-vector disagreements. The initial 127/127 normative result did not mean all checks were green: its separate identity result was 88/89. No corpus byte or expectation was changed.

| Finding | Classification | Disposition |
|---|---|---|
| `AR-C21-g-jws` identity extraction | Checker defect in supplemental runner | Fixed: derive identity from its valid body without requiring valid signature-segment encoding. Normative malformed verdict was already correct. |
| Invalid `subject.reference` suppressed independent outcome/time comparisons | Checker defect | Fixed after an independently signed selftest exposed the missing conditions. Skip only comparisons dependent on the invalid field. |
| RFC 8032 fixture omitted one hex digit | Checker defect in selftest | Corrected against the official RFC. The first test error remains preserved. |
| Zero EVM payer address and “non-null entities” | Spec ambiguity | Open. Removed the unsupported normative assertion from the selftest suite, retained its exact signed diagnostic and actual result separately. Verifier behavior was not changed to force the assertion green. |
| EIP-712 offer `version:1.0` / integral exponent timestamp | Checker defect | Fixed after post-first-run review and independently signed failing regressions. Numeric value and JCS digest survive lexical rewrites; acceptance body restrictions remain strict. |
| Signed offer with human-readable network `base` | Checker defect | Fixed after post-first-run review and independently signed failing regression. Offers must use CAIP-2 syntax even when the receipt matches byte-for-byte. |
| Public API required explicit `record=None` | Checker defect in API default | Fixed: omitted record now returns `no_record`; added independent selftest. Published vectors already supplied explicit null. |

The machine-readable reasons, classifications, corrections and dispositions are in [disagreements.json](disagreements.json). No supplied vector defect was found.

Preserved reports:

- [Initial corpus](results/first-run-2026-10-26.json): 127/127 verdicts, 88/89 identities.
- [Initial supplemental selftests](results/selftests-first-run-2026-10-26.json): one assertion failure and two test errors, each explained above.
- [Review probes before fixes](results/review-probes-before-fixes-2026-10-26.json): three reproduced failures, no changed corpus expectations.
- [Zero-address ambiguity diagnostic](results/zero-address-ambiguity.json): exact input, actual result, initial exploratory expectation, and no asserted normative expectation.
- [Final corpus](results/rerun-vic-2026-10-26.json), [final numeric probes](results/numeric-rerun-vic-2026-10-26.json), and [final selftests](results/selftests-rerun-vic-2026-10-26.json).

The corrected independent selftest suite has 14 tests. The zero-address diagnostic is excluded from that pass count because its expected normative outcome remains unresolved. The numeric suites pass 26 RFC cases, 11 requested probes and 1,001 catalog doubles, including original exponent and float spellings.
