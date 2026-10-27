# Stage-one freeze — before any stage-two read

- Commit (`git -C checker rev-parse HEAD`): `bec16636ff3c2afa0b7ec7a0a32ab2179f96817c`
- Committed-tree archive SHA-256 (`cd checker && git archive HEAD | shasum -a 256`): `98aa4293a8094aeeeaa76fc153ee97f8dde319a08d0cef301352b5c7a00b22eb`
- UTC freeze timestamp: `2026-10-26T19:03:24Z`
- Synthetic selftest: 84 passed, 0 failed; see `build-logs/stage1-selftest-final.txt`.
- Stage-two inputs have not been opened as of this freeze.
- The checksum hashes the exact `git archive HEAD` bytes, not the mutable working directory.
- Checker version: cleanroom-sol-python 0.1.0.

The checker was written entirely by an AI agent in a clean context from the six permitted source documents. For a disclosed package-install temporary-directory exception, see `ENVIRONMENT-NOTES.md`; it did not involve project source access.
