<!-- human-doc: evidence -->
# Publication review corrections — 26 October 2026

The publication copy now retains Git commit hashes and the full original input packet, copies executable source
unchanged, and provides a reproduction helper that cannot overwrite the recorded fixtures. This corrects the export
described in the [earlier metadata review](publication-metadata-review-2026-10-26.md); that historical report remains
unchanged. No normative specification, corpus, expected result or frozen checker was changed.

- Commit hashes in JSON records and provenance text are restored. Private repository locators and machine paths
  remain redacted. The independent checker's entire `inputs/` directory, including `SOURCE-MANIFEST.json`, matches
  the original packet byte-for-byte; its provenance text is also unchanged.
- The TypeScript runner's public display name is defined in the source package. All 53 exported executable files
  matched their source copies byte-for-byte; the exporter refuses any transformation of Python, TypeScript or
  JavaScript source. Metadata redactions remain explicit in the original/export hash manifest.
- The r1 reproduction helper requires a new output directory outside the package. Help, missing/unknown arguments,
  and importing the module do not generate files. Existing directories and paths into the package, including a
  symlink alias, are refused. A successful run creates five new signed fixtures and a new result report; rerunning
  into the same destination is refused. Source-file hashes identify the checker rather than the enclosing Git repo.
- The original helper is retained byte-for-byte as `repro-original.py.txt`, with hash
  `cf0a15c75b6ae9d7d2f361b9673b0a457171013316da2299f7de7a663bd12782`. The original recorded fixtures, results and both
  checker bundles remain unchanged. This packaging correction is separate from the r1 checker revision itself.

| Verification on the updated public copy | Result |
| --- | --- |
| Original/export metadata manifests and independent-checker artifact manifests | All hashes verified |
| Git commit fields across source and exported JSON | Unchanged |
| Original frozen input packet and recorded blind-checker JSON evidence | Byte-identical |
| TypeScript regeneration, checker and typecheck | 127 vectors regenerate byte-for-byte; 127/127; typecheck passes |
| Independent Python | 127/127 outputs and 89/89 statement identifiers |
| Frozen Python and r1 | Each 127/127; bundle-to-source checks and original freeze archive hash verified |
| Helper safety regression on source and public copy | Passed; no package files or prior outputs modified |
| Fresh helper output | All five CLI observations match the recorded r1 results; API observations match CLI |

The conformance workflow includes the helper safety regression. Run it with the blind checker's pinned Python
dependencies using `tools/test-review-repro.py --package <checker-blind-directory>` in the source package.
The public copy's helper and its usage are documented in [r1/README.md](../checker-blind/r1/README.md#running-a-new-reproduction).

The outgoing announcement and PR draft say r1 matches the fresh-context checker on the five signed review inputs.
The TypeScript checker differs on the CAIP-2 example; matching these observations does not settle that textual
interpretation. No new spec decision, merge, tag or upstream posting is established by this correction.
