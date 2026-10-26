// Terms evidence for x402ev/1 (AR-29): the seller's signed x402 offer, EIP-712 or JWS (EdDSA) form.
import { keyAcceptable, verifyEd25519 } from './ed25519.ts';
import { offerTypedDataDigest, recoverOfferSigner } from './eip712.ts';
import { addressOrStringEqual, jcs, sha256Hex, utf8 } from './encoding.ts';
import type { IssuerKeys } from './inputs.ts';
import { parseStrictJson, toPlain } from './json.ts';
import { signingInput, splitCompactJws } from './jws.ts';
import type { SubjectFacts } from './subject.ts';

/** The digests (0x + hex SHA-256 of JCS of the payload) of every qualifying offer. Empty means no terms evidence. */
export function qualifyingOfferDigests(terms: Uint8Array[], issuerKeys: IssuerKeys, subject: SubjectFacts): Set<string> {
  const digests = new Set<string>();
  if (!subject.payment) return digests;
  for (const artifact of terms) {
    const digest = qualifyingOfferDigest(artifact, issuerKeys, subject);
    if (digest !== null) digests.add(digest);
  }
  return digests;
}

function qualifyingOfferDigest(artifact: Uint8Array, issuerKeys: IssuerKeys, subject: SubjectFacts): string | null {
  const env = parseStrictJson(artifact);
  if (!env || env.kind !== 'object') return null;
  const format = env.members.get('format');
  const signature = env.members.get('signature');
  if (!format || format.kind !== 'string' || !signature || signature.kind !== 'string') return null;

  let payload: Record<string, unknown>;
  if (format.value === 'jws') {
    // Offer verification, JWS (extension section 4.5): header alg must be EdDSA (AR-29); kid is required by section 3.3.
    const jws = splitCompactJws(signature.value);
    if (!jws) return null;
    const header = parseStrictJson(jws.header);
    if (!header || header.kind !== 'object') return null;
    const alg = header.members.get('alg');
    const kid = header.members.get('kid');
    if (!alg || alg.kind !== 'string' || alg.value !== 'EdDSA') return null;
    if (!kid || kid.kind !== 'string') return null;
    const payloadNode = parseStrictJson(jws.payload);
    if (!payloadNode || payloadNode.kind !== 'object') return null;
    payload = toPlain(payloadNode) as Record<string, unknown>;
    // Reading: any Ed25519 key trust.issuers lists for deliveryIssuer authorizes; the header kid is a lookup hint only.
    const input = signingInput(jws);
    if (!issuerKeys.ed25519.some((k) => keyAcceptable(k) && verifyEd25519(jws.signature, input, k))) return null; // AR-19, AR-20 through AR-23
  } else if (format.value === 'eip712') {
    // Offer verification, EIP-712 (extension sections 3.2, 4.3, 4.5): the payload is used exactly as transmitted.
    const payloadNode = env.members.get('payload');
    if (!payloadNode || payloadNode.kind !== 'object') return null;
    payload = toPlain(payloadNode) as Record<string, unknown>;
    const digest = offerTypedDataDigest(payload);
    if (!digest) return null;
    const signer = recoverOfferSigner(digest, signature.value);
    if (!signer || !issuerKeys.addresses.includes(signer)) return null; // an address trust.issuers lists for deliveryIssuer
  } else {
    return null;
  }

  // Extension section 4.5: only payload version 1 is defined.
  if (payload.version !== 1) return null;
  if (!matchesPayment(payload, subject)) return null;
  try {
    return '0x' + sha256Hex(utf8(jcs(payload)));
  } catch {
    return null;
  }
}

/** AR-29: network and amount byte-equal; asset and payTo equal to payment.asset and payment.payee (addresses case-insensitively); validUntil, when non-zero, not earlier than the outcome time. */
function matchesPayment(payload: Record<string, unknown>, subject: SubjectFacts): boolean {
  const pay = subject.payment!;
  if (payload.network !== pay.network || payload.amount !== pay.amount) return false;
  if (typeof payload.asset !== 'string' || !addressOrStringEqual(payload.asset, pay.asset)) return false;
  if (typeof payload.payTo !== 'string' || !addressOrStringEqual(payload.payTo, pay.payee)) return false;
  const validUntil = payload.validUntil;
  if (validUntil === undefined) return true; // absent
  if (typeof validUntil !== 'number' || !Number.isSafeInteger(validUntil) || validUntil < 0) return false;
  if (validUntil === 0) return true; // 0 means absence (extension section 4.3)
  return validUntil >= subject.outcomeTime; // the verifier's clock is never an input
}
