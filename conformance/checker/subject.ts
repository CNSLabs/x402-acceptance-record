// The x402ev/1 subject profile (AR-23, AR-27): x402 execution evidence, PR #3682 at 23b5c21.
import { keyAcceptable, verifyEd25519 } from './ed25519.ts';
import { addressOrStringEqual, b64uDecode, bytesEqual, isEthAddress, isPlainObject, jcs, sha256Hex, utf8 } from './encoding.ts';
import type { IssuerKeys } from './inputs.ts';
import { parseStrictJson, toPlain } from './json.ts';
import { UNREADABLE, type SubjectFacts, type SubjectProfile, type SubjectReading } from './profile.ts';
import { qualifyingOfferDigests } from './terms.ts';

export const X402EV1 = 'x402ev/1';
const EVIDENCE_REF_PREFIX = 'x402ev/1:sha256:';

/** A parsed `execution-evidence` info object, before authentication. */
export interface ParsedSubject {
  info: Record<string, unknown>;
  /** JCS of the body (info minus evidenceRef, signer.signature and transparency), or null when not canonicalizable. */
  bodyJcs: Uint8Array | null;
  publicKey: Uint8Array | null; // signer.publicKey, 32 bytes
  signature: Uint8Array | null; // signer.signature without its "base64url:" prefix, 64 bytes
  keyTypeOk: boolean; // signer.keyType is "Ed25519"
  evidenceRef: string | null;
}

/** What an authenticated x402ev/1 record says (AR-27): the generic facts plus what AR-29 matches offers against. */
export interface X402ev1Facts extends SubjectFacts {
  /** The identity, byte-exact: the receipt's evidenceRef. */
  evidenceRef: string;
  /** The payment terms the offer must match (AR-29), or null when a member is not a string. */
  payment: { network: string; amount: string; asset: string; payee: string } | null;
}

/**
 * Parses the info object. The reader is the strict one: a text with duplicate member names has no
 * single JCS and so no identity, so it cannot be authenticated. Number spellings are not restricted
 * here; JCS fixes them.
 */
export function parseX402ev1(bytes: Uint8Array): ParsedSubject | null {
  const node = parseStrictJson(bytes);
  if (!node || node.kind !== 'object') return null;
  const info = toPlain(node) as Record<string, unknown>;
  const signer = isPlainObject(info.signer) ? info.signer : null;

  // body = info minus evidenceRef, signer.signature and transparency
  const body: Record<string, unknown> = { ...info };
  delete body.evidenceRef;
  delete body.transparency;
  if (signer) {
    const s = { ...signer };
    delete s.signature;
    body.signer = s;
  }
  let bodyJcs: Uint8Array | null = null;
  try {
    bodyJcs = utf8(jcs(body));
  } catch {
    bodyJcs = null;
  }

  const publicKey = signer && typeof signer.publicKey === 'string' ? b64uDecode(signer.publicKey) : null;
  const sigText = signer && typeof signer.signature === 'string' && signer.signature.startsWith('base64url:')
    ? signer.signature.slice('base64url:'.length)
    : null;
  const signature = sigText !== null ? b64uDecode(sigText) : null;
  return {
    info,
    bodyJcs,
    publicKey: publicKey && publicKey.length === 32 ? publicKey : null,
    signature: signature && signature.length === 64 ? signature : null,
    keyTypeOk: signer !== null && signer.keyType === 'Ed25519',
    evidenceRef: typeof info.evidenceRef === 'string' ? info.evidenceRef : null,
  };
}

/** Whether `key` signed the subject record (AR-33), applying AR-19 and AR-20. */
export function subjectSignedBy(parsed: ParsedSubject, key: Uint8Array): boolean {
  if (!parsed.bodyJcs || !parsed.signature) return false;
  return keyAcceptable(key) && verifyEd25519(parsed.signature, parsed.bodyJcs, key);
}

/**
 * AR-23 and AR-27: authenticates the record under x402ev/1 verification rule 1 with a key that
 * trust.issuers lists for deliveryIssuer, and reads the fields in their stated forms. Anything off
 * makes the subject unavailable (null); it never produces a mismatch.
 */
export function authenticateX402ev1(p: ParsedSubject, issuerKeys: Uint8Array[]): X402ev1Facts | null {
  if (!p.keyTypeOk || !p.publicKey || !p.signature || !p.bodyJcs || p.evidenceRef === null) return null;
  const publicKey = p.publicKey;
  if (!issuerKeys.some((k) => bytesEqual(k, publicKey))) return null; // listed for deliveryIssuer, compared as 32 bytes
  if (!keyAcceptable(publicKey)) return null; // AR-19 through AR-23
  if (!verifyEd25519(p.signature, p.bodyJcs, publicKey)) return null; // rule 1: signature over JCS(body); AR-20 through AR-23
  if (p.evidenceRef !== EVIDENCE_REF_PREFIX + sha256Hex(p.bodyJcs)) return null; // rule 1: evidenceRef recomputed

  const payment = isPlainObject(p.info.payment) ? p.info.payment : null;
  if (!payment) return null;
  const { payer, payee, network, amount, asset } = payment;
  // rule 1: payer and payee are distinct non-null entities, addresses compared case-insensitively
  if (typeof payer !== 'string' || typeof payee !== 'string' || addressOrStringEqual(payer, payee)) return null;

  const delivery = isPlainObject(p.info.delivery) ? p.info.delivery : null;
  if (!delivery) return null;
  const contentDigest = delivery.contentDigest;
  if (typeof contentDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(contentDigest)) return null; // stated form
  const timestamp = delivery.timestamp;
  if (typeof timestamp !== 'number' || !Number.isSafeInteger(timestamp)) return null; // integer seconds

  // Payer: eip155:<chain>:<address> from payment.network "eip155:<decimal>" and payment.payer with its hex lowercased; otherwise no payer.
  const payerId = typeof network === 'string' && /^eip155:[0-9]+$/.test(network) && isEthAddress(payer)
    ? `${network}:${payer.toLowerCase()}`
    : null;

  const terms = typeof network === 'string' && typeof amount === 'string' && typeof asset === 'string'
    ? { network, amount, asset, payee }
    : null;

  return {
    identity: p.evidenceRef,
    contextId: contextIdOf(p.evidenceRef),
    evidenceRef: p.evidenceRef,
    payer: payerId,
    outcomeDigest: '0x' + contentDigest.slice('sha256:'.length),
    outcomeTime: timestamp,
    payment: terms,
    publicKey,
  };
}

/** AR-24: contextId is 0x + the 64 hex digits of the identity. */
export function contextIdOf(evidenceRef: string): string {
  return '0x' + evidenceRef.slice(EVIDENCE_REF_PREFIX.length);
}

/** x402ev/1 as a subject profile: AR-27 for the record, AR-29's signed offers for the terms evidence. */
export const X402EV1_PROFILE: SubjectProfile = {
  id: X402EV1,
  read(bytes: Uint8Array, issuerKeys: IssuerKeys): SubjectReading {
    const parsed = parseX402ev1(bytes);
    if (!parsed) return UNREADABLE;
    const facts = authenticateX402ev1(parsed, issuerKeys.ed25519);
    return {
      facts,
      signedBy: (key) => subjectSignedBy(parsed, key),
      termsDigests: (terms) => (facts ? qualifyingOfferDigests(terms, issuerKeys, facts) : new Set()),
    };
  },
};
