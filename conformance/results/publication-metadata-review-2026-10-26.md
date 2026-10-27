<!-- human-doc: evidence -->
# Publication metadata verification — 26 October 2026

The public export removes private locators while preserving checker behavior and evidence outcomes. These are
publication-copy changes; the source archive, frozen checker bundles and original run records were not edited.

The export manifest records original and public SHA-256 values for 25 changed files, including explanatory notices
and the updated artifact hash manifest. All other 128 files under the checker, vector, generator, results and review
directories compared byte-for-byte with the source package during this check. The original independent-checker
artifact manifest is retained separately; both the original and public manifests were verified.

| Verification | Result |
| --- | --- |
| Recorded JSON outcomes, signed input bodies and input-file hashes | Unchanged in every transformed report |
| TypeScript generator | 127 vectors regenerate byte-for-byte |
| TypeScript checker and typecheck | 127/127; typecheck passes |
| Independent Python on the exported packet | 127/127 outputs; 89/89 statement identifiers |
| Original frozen Python on the exported package | 127/127; bundle/source equality and original archive hash verified |
| Post-review Python r1 on the exported package | 127/127; bundle/source equality verified |
| Five signed review inputs against exported r1 | 5/5 expected outcomes |
| Private locator introduced into protected verifier source | Export refused before writing |
| Path-like string introduced into a signed input body | Evidence-preservation guard detects a change |

The Python reruns used the already-installed pinned environments (3.14 for the independent implementation, 3.13
for the frozen/r1 implementation). TypeScript dependencies were installed from the package lock with lifecycle
scripts disabled. No checker logic, normative specification, vector bytes or expected outcomes changed. The
TypeScript runner's display name now names the public package.

Reproduce the export with the packaging command, verify the hashes in
[PUBLICATION-METADATA.json](../PUBLICATION-METADATA.json) in the exported package, and follow the existing checker
run instructions. The conformance workflow now exercises the export as well as the existing checker checks.
The manifest is generated in the export; this source copy of the report does not itself contain that manifest.

This review does not authorize a merge, tag or upstream submission. Removing locators from the current candidate
does not remove them from earlier Git history. The original evidence remains available in the source archive.
