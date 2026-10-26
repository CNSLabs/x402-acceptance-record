# Source and licensing notices

The Python implementation, its test code, and documentation use the repository's [Apache-2.0 license](../../LICENSE). Generated run results are offered under [CC0 1.0](../../LICENSE-CC0).

The frozen input packet preserves its sources' licenses:

- `SPEC.md` and `VECTOR-FORMAT.md`: CNS Labs documentation, Apache-2.0. `CASES.md` and `vectors.json`: CNS Labs requirement cases and vectors, CC0 1.0. Exact source commits and digests are in `inputs/SOURCE-MANIFEST.json`.
- `execution_evidence.md` and `extension-offer-and-receipt.md`: x402 specification texts, Apache-2.0, at the immutable commits recorded in the manifest.
- `numeric-probes/stillmarcus-inputs.txt` and `stillmarcus-vectors.json`: [stillmarcus24/assurance-run](https://github.com/stillmarcus24/assurance-run/tree/335ed5df8ca16658ec2c5b5e0cb34449bf1dc6f0/probes/jcs-numbers), MIT. The full notice is in [LICENSE-MIT-stillmarcus.txt](LICENSE-MIT-stillmarcus.txt).
- `numeric-probes/jcs-number-vectors.tsv` and its `FROZEN.txt`: [aos-standard/catalog's JCS number corpus](https://github.com/aos-standard/catalog/tree/40b21297af1289dde5849da1ea6f1caa3ab8d140/docs/runs/jcs-number-vectors), expressly dedicated to CC0 in that directory's README.

Normative standards and general-purpose dependencies remain credited in the implementer's provenance document. The supplemental number corpora are validation inputs; they do not expand the acceptance-record release commitment.
