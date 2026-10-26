# Results

One file per checker per run: `<checker>-<short commit>.json`, written by the checker's runner with `--json`. The
runner records the checker's name, version and the git commit it ran at (with a `dirty` flag when the checker's own
files had uncommitted changes), the SHA-256 of the vector file, the profile and specification pin the vector file
carries, one outcome per vector (pass or fail, with expected and actual on failure) and the totals.

Because a file cannot carry the hash of the commit that adds it, a run is recorded in the commit after the checker
change it reports on: commit the checker, run it, then commit the result file named after the first commit.

An independent rerun is recorded as `rerun-<author>-<date>.json`, by its author's own pull request, with the
author, platform and checker named. A result here is a claim by whoever recorded it, not by the repository.
