// Byte-level helpers shared by the checker: UTF-8, SHA-256, JCS, hex and canonical base64url.
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/**
 * Strict UTF-8 decode (AR-6: the JSON text must be valid UTF-8). The WHATWG decoder in fatal mode
 * rejects invalid sequences, overlong forms and encoded surrogates. A BOM is kept in the output so
 * the JSON reader rejects it as an unexpected character.
 */
export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

export const sha256 = (data: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(data).digest());
/** Lowercase hex SHA-256 without a prefix. */
export const sha256Hex = (data: Uint8Array): string => bytesToHex(sha256(data));

/** RFC 8785 serialization (AR-6); throws when the value cannot be canonicalized. */
export function jcs(value: unknown): string {
  const s = canonicalize(value);
  if (typeof s !== 'string') throw new Error('value is not canonicalizable');
  return s;
}

export const bytesToHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/** `0x` followed by an even number of hex digits of either case; anything else is null. */
export function hexToBytes(s: string): Uint8Array | null {
  if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(s)) return null;
  return new Uint8Array(Buffer.from(s.slice(2), 'hex'));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Unpadded base64url (RFC 4648 section 5). */
export function b64uEncode(bytes: Uint8Array): string {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += B64U_ALPHABET[(acc >> bits) & 0x3f];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B64U_ALPHABET[(acc << (6 - bits)) & 0x3f];
  return out;
}

/**
 * Canonical base64url decode (AR-15, RFC 7515 section 2): only the base64url alphabet, no padding,
 * a length that is not 1 mod 4, and zero unused trailing bits. A text that does not round-trip to
 * itself is refused, so the same bytes have exactly one accepted spelling.
 */
export function b64uDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  if (s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let j = 0;
  for (const ch of s) {
    acc = (acc << 6) | B64U_ALPHABET.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[j++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) return null; // non-zero unused trailing bits: not canonical
  return out;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
export const isEthAddress = (s: string): boolean => ETH_ADDRESS.test(s);

/** Ethereum addresses (`0x` + 40 hex digits) compare case-insensitively; every other value byte-exact (AR-27, AR-29). */
export function addressOrStringEqual(a: string, b: string): boolean {
  if (isEthAddress(a) && isEthAddress(b)) return a.toLowerCase() === b.toLowerCase();
  return a === b;
}
