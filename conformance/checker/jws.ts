// JWS compact serialization (RFC 7515) as AR-15 and AR-17 constrain it.
import { b64uDecode, utf8 } from './encoding.ts';
import { parseStrictJson } from './json.ts';

export interface CompactJws {
  h: string;
  p: string;
  s: string;
  header: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
}

/** AR-15: exactly three segments, each canonical base64url (no padding, zero unused trailing bits). */
export function splitCompactJws(token: string): CompactJws | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const header = b64uDecode(h);
  const payload = b64uDecode(p);
  const signature = b64uDecode(s);
  if (!header || !payload || !signature) return null;
  return { h, p, s, header, payload, signature };
}

/** AR-17: the signing input is the ASCII of protected || "." || payload. */
export const signingInput = (jws: CompactJws): Uint8Array => utf8(`${jws.h}.${jws.p}`);

/**
 * AR-15: the protected header is I-JSON (AR-6) with exactly `alg: "EdDSA"`, a non-empty string
 * `kid` and `typ: "x402-acceptance+jws"`. Returns the kid, or null for any other header.
 */
export function acceptanceHeaderKid(headerBytes: Uint8Array): string | null {
  const node = parseStrictJson(headerBytes);
  if (!node || node.kind !== 'object' || node.members.size !== 3) return null;
  const alg = node.members.get('alg');
  const kid = node.members.get('kid');
  const typ = node.members.get('typ');
  if (!alg || alg.kind !== 'string' || alg.value !== 'EdDSA') return null;
  if (!kid || kid.kind !== 'string' || kid.value === '') return null;
  if (!typ || typ.kind !== 'string' || typ.value !== 'x402-acceptance+jws') return null;
  return kid.value;
}
