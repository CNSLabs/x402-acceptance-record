# x402 clean-room checker report

The checker was written entirely by an AI agent in a clean context from the specification texts alone. Both stages are complete.

## Implementation and provenance

- **Language/runtime:** Python 3.13.14, macOS 27.0.1 arm64; supports Python 3.12+.
- **Pinned dependencies:** coincurve 21.0.0, cryptography 46.0.3, pycryptodome 3.23.0, rfc8785 0.1.4; transitives cffi 2.1.1 and pycparser 3.12. Complete pins are in `checker/requirements.lock`. No network is used at runtime.
- **Stage-one files read:** `BRIEF.md` for instructions; under `inputs/stage1-spec-only/`: `SPEC.md`, `CASES.md`, `README.md`, `LICENSE`, `upstream-pinned/extension-offer-and-receipt.md@faa1c694.md`, and `upstream-pinned/execution_evidence.md@23b5c21.md`. Own generated code/configuration was also read/executed. Ordered UTC receipts are in `READ-LOG.md`, with a pre-freeze snapshot committed inside the checker.
- **Freeze commit:** `bec16636ff3c2afa0b7ec7a0a32ab2179f96817c`.
- **Frozen tree SHA-256** (`git archive HEAD | shasum -a 256`): `98aa4293a8094aeeeaa76fc153ee97f8dde319a08d0cef301352b5c7a00b22eb`.
- **Freeze time:** `2026-10-26T19:03:24Z`. No stage-two file was opened before this commit and freeze receipt existed. The checker remains Git-clean at that exact commit and archive hash.
- **Vector SHA-256:** `8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5`. Its profile is “x402 acceptance record, version 0”; specification pin is `ad53b54ad59df93bd5d3258963f27acccdcec23c` (`draft-2026-10-21`). Its SPEC.md and CASES.md hashes match the stage-one sources.

## First result

**127 passed / 0 failed / 127 vectors.** There are no failures to classify. No checker changes, v2 commit or second result were needed. The separate runner only decodes transport and renames documented input-binding fields; it never changes verification logic or signed data. The first result is preserved unchanged.

Result: [rerun-cnslabs-cleanroom-sol-2026-10-26.json](../results/rerun-cnslabs-cleanroom-sol-2026-10-26.json).

## Exact executed commands and outputs

Working directory: `/Users/moltmike/.openclaw/state/x402-cleanroom-checker-20261026`.

### Synthetic selftest, before freeze

```text
$ .venv313/bin/python -B checker/cli.py selftest
selftest: 84 passed; 0 failed (fresh synthetic keys; no published vectors read)
exit_status=0
```

### First vector run, using the unchanged freeze commit

```text
$ .venv313/bin/python -B runner/run_vectors.py --json rerun-cnslabs-cleanroom-sol-2026-10-26.json
{"totals":{"vectors":127,"passed":127,"failed":0},"checkerCommit":"bec16636ff3c2afa0b7ec7a0a32ab2179f96817c","checkerDirty":false,"vectorSha256":"8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5","output":"rerun-cnslabs-cleanroom-sol-2026-10-26.json"}
exit_status=0
```

### Standalone verify CLI

```text
$ .venv313/bin/python -B checker/cli.py verify runner/baseline-inputs.json
{"result":"verified","conditions":[],"disposition":"accepted"}
exit_status=0
```

## Ambiguities and underspecified points

All ten were recorded before vector access in `checker/IMPLEMENTATION-NOTES.md`:

1. **§5 input transport:** key encodings, raw invalid-UTF-8 records, outcome bytes and chain/call JSON shapes are not specified. The checker documents its own binding; the external runner adapts the vectors' binding.
2. **AR-6 / AR-35 steps 2 and 4:** parsing checks appear in both passes. Syntax, duplicate names, UTF-8/surrogates and forbidden numeric lexemes are preflight errors; other JWS member forms/ranges and JCS equality are checked after the key/signature step.
3. **AR-35 dependent comparisons:** no explicit dependency graph is given. Comparisons are independently gated; an invalid subject reference does not suppress independent outcome/time checks when its profile still identifies available evidence.
4. **AR-12 / AR-14:** no chain freshness, conflicting-fact or block-selection policy is specified. This binding requires a stated block, takes the first matching account fact, and uses an exact digest/signature call. AR-14's explicit invalid-syntax-with-no-call rule takes precedence over call availability, after account classification/support checks.
5. **AR-27 and pinned x402ev rule 1:** the upstream schema is partial and several nested objects are open. The checker enforces stated forms/authentication and chooses nonnegative safe-integer subject timestamps; the latter range is not explicit in the acceptance subject profile.
6. **AR-27 payer derivation:** unlike AR-11, “eip155:<decimal>” does not exclude leading zeroes, zero or oversized chain IDs. Subject network spelling is preserved; only a hex payer address is lowercased. Non-EVM values do not resolve payer authority.
7. **AR-29 and pinned offer §§4.2–4.5/10:** unknown payload fields, numeric expiration bounds and optional-field handling need tighter wording. The checker refuses unknown signed fields, uses nonnegative safe-integer expiration, permits omitted expiration only for JWS, requires transmitted EIP-712 fields, and applies upstream JCS requirements to JWS offers.
8. **AR-29 versus AR-13:** upstream offer ECDSA does not pin low-s, lowercase hex or v spelling. Its recovery path permits uppercase/high-s and v=0/1 or 27/28; acceptance ECDSA strictly enforces AR-13.
9. **AR-33 / §5 issuer accounts:** Ethereum issuer addresses have no explicit JSON representation or chain scoping. They are compared as case-insensitive 20-byte account identities; Ed25519 keys as 32-byte values. Only authenticated subject signers are considered.
10. **Absence/null and AR-18:** null record/outcome is treated as absent/unsupplied. Duplicate trust-key IDs are refused before verify, even without a record; the CLI emits an input error, not an AR-36 result.

The explicit absence of resource binding and settlement verification is honored; passing the vectors does not resolve the ambiguities above.

## Boundary disclosure and artifacts

No external project source, reference implementation or private conformance repository was read; no pushes or messages were sent. The staged `seeds.json` was not opened. Only a results README was staged, so vector layout came from `vectors.json` itself after freeze.

**Write-boundary exception:** initial pip attempts used the host-default `/Users/moltmike/.openclaw/tmp/pip-*` for incidental package build/install temporaries before TMPDIR was explicitly confined to the task directory. Those directories were not opened by the agent and supplied no project context. All agent-authored files are inside the assigned directory. Python 3.9 was unused, a Python 3.14 dependency build failed, and Python 3.13 succeeded; the unused environments and build logs were retained. See `ENVIRONMENT-NOTES.md`. This is disclosed rather than claiming perfect write confinement.

Artifacts: `checker/` (frozen implementation, README and synthetic selftest), `runner/` (adapter and CLI fixture), `FREEZE.md`, `READ-LOG.md`, `STAGE2-ANALYSIS.md`, the result JSON and exact execution receipts under `build-logs/`.
