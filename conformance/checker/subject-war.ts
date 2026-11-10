// The war/1.2 subject profile: a work-acceptance record (schema trilatic.acceptance-receipt/1.2) as the subject,
// as maximusrufus/work-acceptance-record composition/COMPOSITION.md defines it (draft identifier; may change).
// Implemented from that text at 8ce7f42 (2026-11-07). The envelope's byte form is not significant: digests and
// the signature are over JCS of the parsed `receipt` (section 3.1).
import { keyAcceptable, verifyEd25519 } from './ed25519.ts';
import { isEthAddress, isPlainObject, jcs, sha256Hex, utf8 } from './encoding.ts';
import type { IssuerKeys } from './inputs.ts';
import { parseStrictJson, toPlain } from './json.ts';
import { UNREADABLE, type SubjectFacts, type SubjectProfile, type SubjectReading } from './profile.ts';

export const WAR12 = 'war/1.2';
const IDENTITY_PREFIX = 'war/1.2:sha256:';
const SCHEMA = 'trilatic.acceptance-receipt/1.2';
const HEX64 = /^[0-9a-f]{64}$/;
// Section 3.2 item 7: issued_utc in the work specification's form, YYYY-MM-DDTHH:MM:SS[.fff]Z (one to three fraction digits).
const ISSUED_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

/** What an authenticated work record says: the generic facts plus the committed criteria digest (section 3.4). */
export interface WarFacts extends SubjectFacts {
  /** 0x + criteria.sha256: the terms digest, from the record itself. */
  termsDigest: string;
}

/** A parsed envelope, before authentication. */
export interface ParsedWar {
  receipt: Record<string, unknown>;
  signature: Record<string, unknown> | null;
  /** JCS of `receipt` (section 3.1), or null when it cannot be canonicalized. */
  receiptJcs: Uint8Array | null;
  /** signature.value decoded from canonical padded base64, 64 bytes, or null. */
  signatureBytes: Uint8Array | null;
}

/** Canonical padded standard base64 (section 3.2 item 6): alphabet, `=` padding to a multiple of four, round-trips to itself. */
function b64StdDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  const bytes = new Uint8Array(Buffer.from(s, 'base64'));
  return Buffer.from(bytes).toString('base64') === s ? bytes : null;
}

/** Section 3.4: issued_utc as Unix seconds; a non-zero fraction rounds up to the next whole second. Null when not in form. */
export function issuedUtcSeconds(s: unknown): number | null {
  if (typeof s !== 'string') return null;
  const m = ISSUED_UTC.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return null; // second 60 is not a calendar value
  const ms = Date.UTC(y, mo - 1, d, h, mi, se);
  const date = new Date(ms);
  if (date.getUTCFullYear() !== y || date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d) return null; // day beyond the month
  const t = ms / 1000;
  return m[7] !== undefined && Number(m[7]) !== 0 ? t + 1 : t;
}

export function parseWar12(bytes: Uint8Array): ParsedWar | null {
  const node = parseStrictJson(bytes); // section 3.2 item 1: I-JSON
  if (!node || node.kind !== 'object') return null;
  const env = toPlain(node) as Record<string, unknown>;
  if (!isPlainObject(env.receipt)) return null;
  const receipt = env.receipt;
  const signature = isPlainObject(env.signature) ? env.signature : null;
  let receiptJcs: Uint8Array | null = null;
  try {
    receiptJcs = utf8(jcs(receipt));
  } catch {
    receiptJcs = null;
  }
  const signatureBytes = signature && typeof signature.value === 'string' ? b64StdDecode(signature.value) : null;
  return { receipt, signature, receiptJcs, signatureBytes: signatureBytes && signatureBytes.length === 64 ? signatureBytes : null };
}

/** AR-33 under this profile: `key` signed JCS(receipt), applying AR-19 and AR-20. */
export function warSignedBy(p: ParsedWar, key: Uint8Array): boolean {
  if (!p.receiptJcs || !p.signatureBytes) return false;
  return keyAcceptable(key) && verifyEd25519(p.signatureBytes, p.receiptJcs, key);
}

function memberPath(o: Record<string, unknown>, ...path: string[]): unknown {
  let cur: unknown = o;
  for (const name of path) {
    if (!isPlainObject(cur)) return undefined;
    cur = cur[name];
  }
  return cur;
}

/**
 * Section 3.2: the subject is available if and only if every item holds; anything off makes it unavailable
 * (null), never a mismatch. Section 3.3 and 3.4 give the identity and the bound values.
 */
export function authenticateWar12(p: ParsedWar, issuerKeys: IssuerKeys): WarFacts | null {
  const r = p.receipt;
  const sig = p.signature;
  if (!sig || !p.receiptJcs || !p.signatureBytes) return null; // items 1 and 6: the envelope has its members, the value decodes
  // Item 2: schema, canonicalization and suite.
  if (r.schema !== SCHEMA || r.canonicalization !== 'JCS-RFC8785') return null;
  const suite = isPlainObject(r.suite) ? r.suite : null;
  if (!suite || Object.keys(suite).length !== 2 || suite.digest !== 'sha-256' || suite.signature !== 'Ed25519') return null;
  // Item 3: alg, and the three key ids are one string.
  if (sig.alg !== 'Ed25519') return null;
  const kid = r.key_id;
  if (typeof kid !== 'string' || sig.key_id !== kid || memberPath(r, 'parties', 'checker', 'key_id') !== kid) return null;
  // Item 4: trust.issuers holds, for deliveryIssuer, exactly one Ed25519 key whose key id equals receipt.key_id.
  const matching = issuerKeys.entries.filter((e) => e.kid === kid);
  if (matching.length !== 1) return null;
  const publicKey = matching[0]!.key;
  // Item 5: AR-19. Item 6: RFC 8032 over JCS(receipt) with the AR-20 rule.
  if (!keyAcceptable(publicKey)) return null;
  if (!verifyEd25519(p.signatureBytes, p.receiptJcs, publicKey)) return null;
  // Item 7: the two digests and issued_utc in their stated forms.
  const remediated = memberPath(r, 'files', 'remediated', 'sha256');
  const criteria = memberPath(r, 'criteria', 'sha256');
  if (typeof remediated !== 'string' || !HEX64.test(remediated)) return null;
  if (typeof criteria !== 'string' || !HEX64.test(criteria)) return null;
  const outcomeTime = issuedUtcSeconds(r.issued_utc);
  if (outcomeTime === null) return null;

  // Section 3.4: payer from receipt.payment when network is eip155:<decimal> and payer an address; otherwise none.
  const payment = isPlainObject(r.payment) ? r.payment : null;
  const network = payment?.network;
  const payer = payment?.payer;
  const payerId = typeof network === 'string' && /^eip155:[0-9]+$/.test(network) && typeof payer === 'string' && isEthAddress(payer)
    ? `${network}:${payer.toLowerCase()}`
    : null;

  const digest = sha256Hex(p.receiptJcs); // section 3.3
  return {
    identity: IDENTITY_PREFIX + digest,
    contextId: '0x' + digest,
    payer: payerId,
    outcomeDigest: '0x' + remediated,
    outcomeTime,
    publicKey,
    termsDigest: '0x' + criteria,
  };
}

/** war/1.2 as a subject profile. The terms evidence is the authenticated record itself: `criteria.sha256` (section 3.4). */
export const WAR12_PROFILE: SubjectProfile = {
  id: WAR12,
  read(bytes: Uint8Array, issuerKeys: IssuerKeys): SubjectReading {
    const parsed = parseWar12(bytes);
    if (!parsed) return UNREADABLE;
    const facts = authenticateWar12(parsed, issuerKeys);
    return {
      facts,
      signedBy: (key) => warSignedBy(parsed, key),
      termsDigests: () => (facts ? new Set([facts.termsDigest]) : new Set()),
    };
  },
};
