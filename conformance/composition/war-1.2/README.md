# war/1.2 as a second subject profile

`war/1.2` is maximusrufus's draft subject profile for the x402 acceptance record, version 0: the subject is a
work-acceptance record (schema `trilatic.acceptance-receipt/1.2`), defined in
[composition/COMPOSITION.md](https://github.com/maximusrufus/work-acceptance-record/blob/8ce7f42/composition/COMPOSITION.md)
of his repository and proposed on [x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4). It is
his profile, outside the core text; this directory records what happened when the authors' TypeScript checker
implemented it as a second profile beside `x402ev/1` and ran his vectors. SPEC.md is unchanged: the profile fits
the subject-profile slot (AR-23 to AR-29) as written, and the terms evidence is the authenticated work record itself
(`criteria.sha256`), which AR-29 allows "as the subject profile defines it".

**Provenance and licences.** The profile text and the sixteen vectors are maximusrufus's work, read from
[composition/](https://github.com/maximusrufus/work-acceptance-record/tree/8ce7f42/composition) of his repository at
commit `8ce7f42` (2026-11-07); `sources.json` records every file's digest. His LICENSES.md dedicates
`composition/vectors/` to the public domain (CC0 1.0) and licenses `composition/*.md` under CC BY 4.0: the vectors
are carried here under that dedication, with the licence stated in the bundle header, and the profile text is quoted
and paraphrased under this attribution. His checker is run, not copied; `results/run-maximusrufus-check-*.txt` are
transcripts of running it. COMPOSITION.md names profile 1.4.2 of the work specification while his repository is at
1.4.11 (see the version note at the end). Everything else here is ours: the adapter under Apache-2.0, the mutations
and the pinned runs under CC0 1.0, as the package README's table says.

## What was implemented

`checker/subject-war.ts`, from COMPOSITION.md at `8ce7f42` (2026-11-07), behind the profile interface in
`checker/profile.ts`; `checker/profiles.ts` lists the supported profiles. The 127 vectors and the checker's
synthetic checks pass as before (127 of 127; 182 checks: `results/checker-ts-4c2e3d7.json` and
`results/checker-ts-4c2e3d7-selftest.txt` at the package root). One reading changed in `verify.ts` and no vector decides
it: AR-33's "signed the subject record" is now read under the subject's named profile, so under a profile this
verifier does not support it is not evaluated (before, the subject was always read as `x402ev/1` for that clause).

## Runs

| File | What |
|---|---|
| `sources.json` | SHA-256 of every file read from his `composition/` at `8ce7f42`. |
| `vectors-C01-C16.json` | His sixteen vectors, bundled unchanged (inputs and `expect` byte for byte) in the layout `checker/run-vectors.ts` reads. |
| `mutations.json` | Thirteen mutations of C01 and C02 built by `tools/mutations.ts` (re-signed with his published throwaway seeds where the receipt or body changes); expectations are our reading of COMPOSITION.md. |
| `results/` | Pinned runs of both files through our checker (`run-ts-*.json`) and his `check.py` (`run-maximusrufus-check-*.txt`). |

```
npx tsx checker/run-vectors.ts composition/war-1.2/vectors-C01-C16.json
npx tsx checker/run-vectors.ts composition/war-1.2/mutations.json
npx tsx composition/war-1.2/tools/mutations.ts <his composition/vectors dir> <out.json>   # rebuilds mutations.json byte for byte
```

**C01 to C16: 15 of 16 agree with his `expect`; his `check.py` passes 16 of 16 of the same files here.** The one
difference is C05, and it is the one his vector note and his table in COMPOSITION.md section 5.1 predict: a work
record named under `x402ev/1` is `profile_unavailable` from his checker, which does not implement `x402ev/1`, and
`evidence_unavailable` from ours, which does, because a work record does not authenticate as execution evidence.
Both results follow AR-35 steps 6 and 7; the vector's `expect` assumes his verifier.

**Mutations: 13 of 13 agree between the two checkers**, including the two the profile text leaves open (below).

## Readings for the profile text

Found while implementing; none changes SPEC.md. The first two are places where COMPOSITION.md is silent and both
checkers happened to decide the same way; the profile should say so.

1. **Envelope members (section 3.2 item 1).** "The envelope has the members of W3.1" (`receipt`, `signature`,
   `timestamp`). Both checkers accept an envelope without `timestamp` (C85) and one with an unsigned extra member
   (C84). Suggested wording: `receipt` and `signature` are required, `timestamp` optional, other members ignored.
2. **Suite object exactness (item 2).** We compare `receipt.suite` as exactly the two members; his checker compares
   dict equality, which is the same. Worth stating.
3. **Key id match (item 4).** Our `trust.issuers` entries carry an optional `kid`; an entry without one never matches
   under war/1.2, so a relying party must list the checker key with its key id. His NOTES.md item 3 raises this for
   the acceptance specification; the profile's rule is clear once the key id is present.
4. **AR-33 under an unsupported profile** (ours, not his): see above. Candidate for the next revision's text.
5. **`issued_utc` form.** The profile cites W7.3 step 6; the form we implemented is `YYYY-MM-DDTHH:MM:SS[.fff]Z`, one
   to three fraction digits, calendar-valid, second 60 excluded, taken from the work specification's step 10 notes
   and his checker. A four-digit fraction is unavailability (C88); a zero fraction does not round (C89).

Versions: COMPOSITION.md names profile 1.4.2 of the work specification; his repository is at 1.4.11 (126 vectors).
Nothing in sections 3.2 to 3.4 depends on a rule that changed between them, as far as the changelog shows, but the
profile text should be re-read against 1.4.11 when he updates it.
