# Specification ambiguities and binding decisions (recorded before freeze)

These are observations from SPEC.md and its pinned texts, not from any vectors.

1. **Section 5 is an abstract input model, not a JSON wire schema.** It does not fix
   the encoding of trust keys, the shape of chain/block/call entries, the transport
   of record bytes that are invalid UTF-8, or the transport of `outcome` bytes. This
   checker defines a documented JSON/Python binding in README. The later vector
   runner may adapt a published transport to that binding without changing verify.
2. **AR-6 and AR-35 preflight versus malformed pass.** Preflight explicitly parses
   JWS under AR-6; the malformed pass again includes AR-6. We reject duplicate
   names, bad UTF-8/surrogates, and forbidden numeric lexical forms at preflight;
   validly parsed wrong member types/ranges/extra members stay after the key step
   for JWS. EIP-712 preflight checks every form needed to build its typed message,
   leaving extra members and disposition enumeration to the malformed pass.
3. **AR-35 dependency suppression granularity.** The text does not enumerate the
   dependency graph. Each digest/time comparison is independently gated by its
   own form. A string subject profile can select the authenticator even when the
   subject reference has the wrong form; a bad reference suppresses that equality,
   not unrelated outcome or timing conditions. An unknown profile still permits
   independent member and signer-is-issuer conditions.
4. **AR-12/14 chain fact precedence and block selection.** There is no freshness,
   finality, conflicting-fact, or duplicate-fact policy. This binding requires a
   caller-declared block and boolean `hasCode`, selecting the first matching
   `(chainId, account)` entry. A code-bearing account is always contract-classified;
   the caller must classify EIP-7702 designators as code. Only an exact digest and
   signature call is used. AR-14's explicit syntax-with-no-call rule is applied
   before searching for its call, after account classification/support resolution.
   This reconciles that rule with AR-35's broader 'any chain state' key-step wording.
5. **AR-27's upstream 'Canonical Schema' step is incomplete as a schema.** Pinned
   x402ev supplies an example and a partial JSON Schema, with open `request`,
   `delivery`, and `signer` objects. We require the stated profile/canonicalization,
   required objects, nonempty string payment fields, distinct non-null payer and
   payee, strict Ed25519 evidence authentication/identity, lowercase SHA-256 outcome
   digest and integer seconds. Because no timestamp bounds are stated for subject
   time, this implementation chooses nonnegative safe JSON integer seconds.
   Optional settlement and transparency evidence is not checked.
6. **AR-27 payer CAIP-2 spelling.** 'eip155:<decimal>' does not explicitly exclude
   leading zeroes, zero, or oversized chain IDs as AR-11 does for the acceptance
   signer. The subject payer derivation preserves any decimal digit network string
   verbatim and lowercases only a 20-byte hex payer address. Non-EVM payer values
   can authenticate a subject but do not resolve `payer/0`.
7. **AR-29 upstream offer scope.** The pinned offer extension allows optional
   `acceptIndex`, has a SHOULD about unknown fields, and specifies `validUntil` as
   a number without a numeric domain. This checker ignores `acceptIndex`, refuses
   unknown signed payload members, requires integer safe nonnegative expiration,
   requires all EIP-712 fields as transmitted, and accepts omitted `validUntil` only
   in JWS. It applies upstream §10's JCS requirement to signed JWS offer bytes.
   No runtime clock is used; zero expiration is absent and an expiration equal to
   the delivery time qualifies. The spec's resource-binding omission is explicit,
   not treated here as a bug or an implementation liberty.
8. **AR-29 ECDSA versus AR-13 ECDSA.** The offer extension asks for a 65-byte r+s+v
   hex signature but does not pin low-s, lowercase hex, or the v convention as the
   acceptance does. Its separate recovery path permits either 0/1 or 27/28 v,
   uppercase hex and high-s. Acceptance signatures always obey strict AR-13.
9. **AR-33 issuer account identity.** Section 5 says Ethereum addresses, without
   spelling their JSON representation or chain scoping. We compare those address
   entries case-insensitively as 20-byte account identities without imposing a
   chain, and Ed25519 entries as 32-byte values. The subject signer comparison is
   performed only against authenticated subject evidence.
10. **Absent versus explicit null.** The spec discusses absent record/outcome but
    does not define a CLI null convention. In this binding null record is absent,
    null outcome is unsupplied. Duplicate `trust.keys.kid` is refused as an input
    configuration error before verify, even if record is absent (AR-18).

None of these choices imports implementation behavior from another checker.
