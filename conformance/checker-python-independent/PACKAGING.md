# Packaging and coordination disclosure

This directory preserves the implementation agent's artifact byte-for-byte for every file listed in `ARTIFACT-SHA256.json`. License notices, this note, and the repository CI workflow were added during packaging. Original reports and source snapshots were not rewritten.

The implementation agent started in a fresh context with the same inherited model and reasoning effort as the coordinator. The coordinator had previously reviewed the reference implementation. It supplied only the declared specification/case/vector packet and data-only numeric probes to the implementer, and did not supply reference code or reference-derived implementation guidance. A second fresh-context reviewer read the new implementation and permitted normative texts; its reproduced findings are disclosed in the disagreement ledger.

The independence claim is therefore about the implementing and reviewing agents' unopened reference implementations. It is not a claim that every participant had never seen the reference, that the filesystem was inaccessible, that expected results were hidden, or that an unrelated organization supplied the checker. The access restrictions were instruction-based within separate agent contexts and an allowlisted input workspace.

The publication coordinator reran the packaged implementation and records its exact Git source commit in the separate result entry under `v0/results/`. This private review contribution does not publish or ratify the acceptance-record specification and does not establish a live-chain wallet integration.
