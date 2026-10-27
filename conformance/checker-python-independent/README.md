<!-- human-doc: index -->
# Python acceptance-record verifier

Primary job: route a reviewer to the implementation, reproducible results, and limitations of this specification-derived verification run.

The final run matches **127/127 published normative outputs and 89/89 supplied statement identities**. The first run matched 127/127 outputs but only 88/89 identities; that runner defect and subsequent supplemental findings remain recorded in [disagreements](DISAGREEMENTS.md).

The verifier is in [verifier.py](verifier.py). Its API takes exact record, subject, terms, and optional outcome bytes with explicit trust and chain declarations. It has no corpus, case-ID, expected-result, filesystem, clock, or network dependency. [wire.py](wire.py) decodes the published base64url input transport. [cli.py](cli.py) verifies one input object. [run_vectors.py](run_vectors.py) alone reads the published expectations and compares results.

Create an environment and run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python cli.py path/to/one-input-object.json
.venv/bin/python run_vectors.py --output results/new-corpus-run.json
.venv/bin/python numeric_tests.py --output results/new-numeric-run.json
.venv/bin/python selftests.py --output results/new-selftests-run.json
```

Report writers deliberately refuse to overwrite an earlier report. The run was performed with CPython 3.14.3 on macOS arm64; all installed dependency versions, loaded module hashes, and checker source hashes are recorded in the reports. Dependencies are fully version-pinned in [requirements.lock](requirements.lock).

- [Final corpus report](results/rerun-vic-2026-10-26.json): every vector's actual and expected normative output, identity comparison, exact input pins, environment, and source hashes.
- [Final number report](results/numeric-rerun-vic-2026-10-26.json): 26/26 RFC 8785 Appendix B cases, 11/11 frozen requested probes, and 1,001/1,001 frozen catalog doubles. Original JSON number spellings are retained.
- [Final supplementary selftests](results/selftests-rerun-vic-2026-10-26.json): 14/14 tests, including newly signed evidence, independent RFC 8032 data, evaluation order, field-dependent checks, offer numeric spellings, CAIP-2 syntax, duplicate-key input refusal, and statelessness.
- [Provenance](PROVENANCE.md), [source access log](access-log.json), and [disagreement ledger](disagreements.json).
- [First-run report](results/first-run-2026-10-26.json) and [first complete source snapshot](attempts/first-implementation/), preserved before corrections.

This is a fresh-context agent implementation on Vic's side, using the same inherited model and reasoning effort. It is independent of the unopened reference acceptance implementations; it is not blind testing or organizational, human, or third-party independence. Expected outputs were visible. A second fresh-context reader reviewed the first implementation against the same allowed texts after the first run; the independently reproduced findings and corrections are explicit in the ledger.

The result applies to the pinned draft and corpus, not all possible inputs or a live deployment. Chain evidence is caller-declared; no deployed contract wallet or chain RPC was exercised. The draft leaves the zero-address meaning of “non-null entities” unclear; [the diagnostic](results/zero-address-ambiguity.json) preserves that unresolved interpretation without inventing a new corpus expectation. Supplemental numeric probes are diagnostics, not additional release commitments.
