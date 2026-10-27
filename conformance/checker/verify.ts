// verify(): the x402 acceptance record, version 0 (AR-35), with the output of AR-36.
import { checkBody, type BodyFacts, type Disposition } from './body.ts';
import { keyAcceptable, verifyEd25519 } from './ed25519.ts';
import {
  acceptanceDigest, buildAcceptanceMessage, CONTRACT_SIGNATURE_FORM, erc1271CallValid, findCall, findDeclaration, recoverOrdinary,
} from './eip712.ts';
import { b64uDecode, bytesEqual, jcs, sha256Hex, utf8 } from './encoding.ts';
import { issuerKeysFor, type IssuerKeys, type Trust, type VerifyInputs } from './inputs.ts';
import { hasExactlyMembers, parseStrictJson, toPlain, type JsonNode } from './json.ts';
import { acceptanceHeaderKid, signingInput, splitCompactJws, type CompactJws } from './jws.ts';
import { authenticateX402ev1, contextIdOf, parseX402ev1, subjectSignedBy, X402EV1, type ParsedSubject, type SubjectFacts } from './subject.ts';
import { qualifyingOfferDigests } from './terms.ts';

export type { VerifyInputs, Trust, TrustIssuer, TrustKey, TrustAuthority, ChainDeclaration, ChainCall } from './inputs.ts';

export type Result = 'verified' | 'malformed' | 'key_unresolved' | 'unknown' | 'no_record';

export type Condition =
  | 'confirming_party_absent'
  | 'acceptance_signer_is_issuer'
  | 'acceptance_terms_digest_mismatch'
  | 'acceptance_outcome_digest_mismatch'
  | 'acceptance_record_digest_mismatch'
  | 'acceptance_precedes_outcome'
  | 'acceptance_member_invalid'
  | 'acceptance_authority_unresolved'
  | 'signature_invalid';

export type Reason =
  | 'key_missing'
  | 'signer_mismatch'
  | 'key_refused'
  | 'chain_state_unavailable'
  | 'contract_accounts_unsupported'
  | 'profile_unavailable'
  | 'evidence_unavailable';

/** AR-36. Members are absent (not undefined) when the specification says absent. */
export interface Output {
  result: Result;
  conditions: Condition[];
  disposition?: Disposition;
  reason?: Reason;
  policy_refusal?: boolean;
}

/** An input refused before verify runs (AR-18: trust.keys lists one kid twice). It has no result. */
export class InputRefusedError extends Error {}

/** AR-18: refuses an input whose trust.keys lists one kid twice. */
export function refuseInputs(trust: Trust): void {
  const seen = new Set<string>();
  for (const entry of trust.keys ?? []) {
    if (!entry || typeof entry.kid !== 'string') continue;
    if (seen.has(entry.kid)) throw new InputRefusedError(`trust.keys lists kid ${JSON.stringify(entry.kid)} twice`);
    seen.add(entry.kid);
  }
}

type Preflight =
  | { form: 'eip712'; body: JsonNode; signature: string; digest: `0x${string}`; chainId: bigint; account: string }
  | { form: 'jws'; body: JsonNode; jws: CompactJws; kid: string; signer: string };

/** The key or account that verified the record (AR-33). */
type Verifier = { kind: 'account'; account: string } | { kind: 'key'; key: Uint8Array };

type KeyStep = { ok: true; verifier: Verifier } | { ok: false; output: Output };

const malformed = (...conditions: Condition[]): Output => ({ result: 'malformed', conditions });
const keyUnresolved = (reason: Reason, policyRefusal: boolean): KeyStep => ({
  ok: false,
  output: { result: 'key_unresolved', conditions: [], reason, policy_refusal: policyRefusal },
});
const signatureInvalid = (): KeyStep => ({ ok: false, output: malformed('signature_invalid') });

export function verify(inputs: VerifyInputs): Output {
  refuseInputs(inputs.trust);

  // AR-35 step 1 (AR-37): no record.
  if (inputs.record === null || inputs.record === undefined) return { result: 'no_record', conditions: [] };

  // Step 2: preflight.
  const pre = preflight(inputs.record);
  if (!pre) return malformed('acceptance_member_invalid');

  // Step 3: key step.
  const key = pre.form === 'eip712' ? keyStepEip712(pre, inputs) : keyStepJws(pre, inputs);
  if (!key.ok) return key.output;

  // Steps 4 to 9.
  return evaluate(pre, key.verifier, inputs);
}

// ---------------------------------------------------------------------------------------------
// Step 2: preflight (AR-7; EIP-712: AR-6, AR-10, AR-11; JWS: AR-15 and the payload parse)

function preflight(record: Uint8Array): Preflight | null {
  const envelope = parseStrictJson(record); // AR-6: the JSON text is I-JSON
  if (!envelope || envelope.kind !== 'object') return null;
  const format = envelope.members.get('format');
  if (!format || format.kind !== 'string') return null;

  if (format.value === 'eip712') {
    // AR-7: exactly {format, payload, signature}
    if (!hasExactlyMembers(envelope, ['format', 'payload', 'signature'])) return null;
    const body = envelope.members.get('payload')!;
    const signature = envelope.members.get('signature')!;
    if (body.kind !== 'object' || signature.kind !== 'string') return null;
    // AR-10, AR-11: build the typed message; a used member failing AR-5, AR-6 or AR-11 stops here.
    const message = buildAcceptanceMessage(checkBody(body));
    if (!message) return null;
    const digest = acceptanceDigest(message); // AR-8, AR-9
    if (!digest) return null;
    return { form: 'eip712', body, signature: signature.value, digest, chainId: message.signerChainId, account: message.signerAccount };
  }

  if (format.value === 'jws') {
    // AR-7: exactly {format, signature}
    if (!hasExactlyMembers(envelope, ['format', 'signature'])) return null;
    const signature = envelope.members.get('signature')!;
    if (signature.kind !== 'string') return null;
    const jws = splitCompactJws(signature.value); // AR-15: three canonical segments
    if (!jws) return null;
    const kid = acceptanceHeaderKid(jws.header); // AR-15: the protected header
    if (kid === null) return null;
    const body = parseStrictJson(jws.payload); // AR-6: a JSON object whose signer is a non-empty string
    if (!body || body.kind !== 'object') return null;
    const signer = body.members.get('signer');
    if (!signer || signer.kind !== 'string' || signer.value === '') return null;
    return { form: 'jws', body, jws, kid, signer: signer.value };
  }

  return null; // AR-7: any other format
}

// ---------------------------------------------------------------------------------------------
// Step 3: key step

function keyStepEip712(pre: Extract<Preflight, { form: 'eip712' }>, inputs: VerifyInputs): KeyStep {
  // AR-12: the account type comes from chain facts for signerChainId, and no other chain.
  const declaration = findDeclaration(inputs.chain, pre.chainId, pre.account);
  if (!declaration || typeof declaration.code !== 'boolean') return keyUnresolved('chain_state_unavailable', false);

  if (!declaration.code) {
    // AR-13: ordinary account; the recovered address must equal signerAccount.
    const recovered = recoverOrdinary(pre.digest, pre.signature);
    if (recovered === null || recovered !== pre.account) return signatureInvalid();
    return { ok: true, verifier: { kind: 'account', account: pre.account } };
  }

  // AR-14: contract account (including an EIP-7702 delegation designator); recovery never runs.
  if (inputs.contractAccounts === false) return keyUnresolved('contract_accounts_unsupported', false);
  if (!CONTRACT_SIGNATURE_FORM.test(pre.signature)) return signatureInvalid(); // form failure: signature_invalid with no call
  const call = findCall(declaration, pre.digest, pre.signature);
  if (!call) return keyUnresolved('chain_state_unavailable', false); // the call is not among the declared chain state
  if (!erc1271CallValid(call)) return signatureInvalid();
  return { ok: true, verifier: { kind: 'account', account: pre.account } };
}

function keyStepJws(pre: Extract<Preflight, { form: 'jws' }>, inputs: VerifyInputs): KeyStep {
  const complete = inputs.trust.complete === true; // AR-22
  // AR-18: the trust.keys entry whose kid equals the header kid and whose signer equals the body's signer.
  const entry = (inputs.trust.keys ?? []).find((k) => k && k.kid === pre.kid);
  if (!entry) return keyUnresolved('key_missing', complete);
  if (entry.signer !== pre.signer) return keyUnresolved('signer_mismatch', complete);
  // AR-19: canonical 32-byte encoding of a point of order exactly L.
  const key = typeof entry.key === 'string' ? b64uDecode(entry.key) : null;
  if (!key || !keyAcceptable(key)) return keyUnresolved('key_refused', complete);
  // AR-17, AR-20: the signature over protected || "." || payload.
  if (!verifyEd25519(pre.jws.signature, signingInput(pre.jws), key)) return signatureInvalid();
  return { ok: true, verifier: { kind: 'key', key } };
}

// ---------------------------------------------------------------------------------------------
// Steps 4 to 9

function evaluate(pre: Preflight, verifier: Verifier, inputs: VerifyInputs): Output {
  const conditions = new Set<Condition>();

  // Step 4: the malformed pass reports every remaining condition.
  const facts = checkBody(pre.body); // AR-1, AR-4, AR-5, AR-6
  if (facts.invalid) conditions.add('acceptance_member_invalid');
  if (pre.form === 'jws' && !payloadIsJcsOfBody(pre.jws, pre.body)) conditions.add('acceptance_member_invalid'); // AR-16
  if (facts.confirmingParty === '') conditions.add('confirming_party_absent'); // AR-34

  const issuerKeys: IssuerKeys = facts.deliveryIssuer !== null ? issuerKeysFor(inputs.trust, facts.deliveryIssuer) : { ed25519: [], addresses: [] };
  const profileKnown = facts.subject !== null && facts.subject.profile === X402EV1;
  const parsedSubject = inputs.subject ? parseX402ev1(inputs.subject) : null;
  // AR-23, AR-27: the subject is available only when it authenticates under its profile with a key listed for deliveryIssuer.
  const subject: SubjectFacts | null = profileKnown && facts.deliveryIssuer !== null && parsedSubject
    ? authenticateX402ev1(parsedSubject, issuerKeys.ed25519)
    : null;

  if (signerIsIssuer(facts, verifier, issuerKeys, parsedSubject)) conditions.add('acceptance_signer_is_issuer'); // AR-33

  let termsAvailable = false;
  if (subject) {
    // AR-24: subject.reference equals the identity byte-exact; contextId is its 64 hex digits.
    if (facts.subject!.reference !== subject.evidenceRef || (facts.contextId !== null && facts.contextId !== contextIdOf(subject.evidenceRef))) {
      conditions.add('acceptance_record_digest_mismatch');
    }
    // AR-25: outcomeDigest equals the subject's bound outcome digest, and the SHA-256 of `outcome` when supplied.
    if (facts.outcomeDigest !== null) {
      const outcomeBytesDiffer = inputs.outcome !== undefined && '0x' + sha256Hex(inputs.outcome) !== facts.outcomeDigest;
      if (facts.outcomeDigest !== subject.outcomeDigest || outcomeBytesDiffer) conditions.add('acceptance_outcome_digest_mismatch');
    }
    // AR-26: issuedAt is not earlier than the outcome time; equal is allowed.
    if (facts.issuedAt !== null && facts.issuedAt < BigInt(subject.outcomeTime)) conditions.add('acceptance_precedes_outcome');
    // AR-29: termsDigest equals the digest of a qualifying offer; no qualifying offer is missing evidence, never a mismatch.
    const digests = qualifyingOfferDigests(inputs.terms ?? [], issuerKeys, subject);
    termsAvailable = digests.size > 0;
    if (termsAvailable && facts.termsDigest !== null && !digests.has(facts.termsDigest)) conditions.add('acceptance_terms_digest_mismatch');
  }

  // Step 5: any condition is malformed.
  if (conditions.size > 0) return malformed(...conditions);

  // From here every member is well formed, so the disposition can be copied from the signed body.
  const disposition = facts.disposition as Disposition;

  // Step 6: unknown subject profile.
  if (!profileKnown) return { result: 'unknown', conditions: [], disposition, reason: 'profile_unavailable' };

  // Step 7: subject or terms evidence unavailable.
  if (!subject || !termsAvailable) return { result: 'unknown', conditions: [], disposition, reason: 'evidence_unavailable' };

  // Step 8: authority (AR-30 to AR-32).
  if (!authorityResolves(facts, subject, inputs.trust)) return { result: 'unknown', conditions: ['acceptance_authority_unresolved'], disposition };

  // Step 9.
  return { result: 'verified', conditions: [], disposition };
}

/** AR-16: the payload is exactly the JCS serialization of its decoded body. */
function payloadIsJcsOfBody(jws: CompactJws, body: JsonNode): boolean {
  try {
    return bytesEqual(jws.payload, utf8(jcs(toPlain(body))));
  } catch {
    return false;
  }
}

/** AR-33: confirmingParty or signer equals deliveryIssuer, or the verifying key or account is listed for deliveryIssuer or signed the subject record. */
function signerIsIssuer(facts: BodyFacts, verifier: Verifier, issuerKeys: IssuerKeys, parsedSubject: ParsedSubject | null): boolean {
  if (facts.deliveryIssuer !== null) {
    if (facts.confirmingParty === facts.deliveryIssuer || facts.signer === facts.deliveryIssuer) return true;
    if (verifier.kind === 'account' && issuerKeys.addresses.includes(verifier.account)) return true;
    if (verifier.kind === 'key' && issuerKeys.ed25519.some((k) => bytesEqual(k, verifier.key))) return true;
  }
  return verifier.kind === 'key' && parsedSubject !== null && subjectSignedBy(parsedSubject, verifier.key);
}

/** AR-30 to AR-32. */
function authorityResolves(facts: BodyFacts, subject: SubjectFacts, trust: Trust): boolean {
  const a = facts.authority!;
  if (a.mode === 'direct' && a.profile === 'payer/0' && a.reference === '') {
    // AR-31: signer, confirmingParty and the subject's payer are the same string; a subject without a payer does not resolve.
    return subject.payer !== null && facts.signer === facts.confirmingParty && facts.confirmingParty === subject.payer;
  }
  if (a.mode === 'declared' && a.profile === 'declared-evidence/0' && a.reference === '') {
    // AR-32: a trust.authority entry whose four members equal the body's.
    return (trust.authority ?? []).some(
      (e) => e && e.confirmingParty === facts.confirmingParty && e.signer === facts.signer &&
        e.subjectProfile === facts.subject!.profile && e.subjectReference === facts.subject!.reference,
    );
  }
  return false; // AR-30: an unsupported triple does not resolve
}
