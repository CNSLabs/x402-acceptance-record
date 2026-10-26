# Publication copies and original evidence

Primary job: explain which metadata was redacted and how to verify the published files.

This export removes private source repository locators, private source commit identifiers, a private communication
locator and machine-specific workspace paths. It also replaces the TypeScript runner's display name with its public
package name. These are publication changes, not checker corrections or a new test run.

The original evidence is retained unchanged in the source archive. Public metadata copies are labelled as such;
they are not claimed to be byte-identical originals. [PUBLICATION-METADATA.json](PUBLICATION-METADATA.json) records
the original and exported SHA-256 for every changed file. Those hashes establish the stated byte identities;
without access to the original archive they do not independently prove what a redacted locator contained.

Both blind-checker Git bundles and their copied source trees are unchanged. The independent checker's source,
attempt snapshots, specification texts and vector inputs are unchanged. All signed review inputs, recorded expected
and actual outputs, result totals, event timestamps and source-file hashes are unchanged. Mike's original first-run
result is itself unchanged. Metadata redaction does not remove failed attempts or change the disclosed read order.

For the independent checker, [ARTIFACT-SHA256.json](checker-python-independent/ARTIFACT-SHA256.json) verifies the
exported copies. [ORIGINAL-ARTIFACT-SHA256.json](checker-python-independent/ORIGINAL-ARTIFACT-SHA256.json) retains the
original artifact's manifest. Historical access-log hashes describe the files as originally read; they are not
replaced with hashes of later publication copies. The original corpus source commit is withheld, while the exact
corpus and specification content hashes remain available and are checked by the runners.

The build and read-order claims retain their documented limits. Publication cleanup supplies no new proof of
independence, ratification or release approval, and does not erase earlier Git history.
