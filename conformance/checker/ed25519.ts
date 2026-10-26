// Ed25519 with the point-order and scalar checks of AR-19 and AR-20 (also applied to subject and
// terms evidence through AR-23). Adapted from the earlier checkers/ts/src/ed25519.ts helper.
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesEqual } from './encoding.ts';

const Point = ed25519.Point;
/** L, the order of the base point. */
export const L: bigint = Point.CURVE().n;

export type PointOrder = 'ok' | 'small' | 'mixed' | 'invalid';

/**
 * Classifies a 32-byte encoding: a canonical encoding of a point of order exactly L ('ok'), a
 * small-order point including the identity ('small'), a point with a small-order component
 * ('mixed'), or an undecodable or non-canonical encoding ('invalid').
 */
export function pointOrder(bytes: Uint8Array): PointOrder {
  if (bytes.length !== 32) return 'invalid';
  let p;
  try {
    p = Point.fromBytes(bytes, false); // RFC 8032 decoding: y >= p and (x = 0, sign bit set) are refused
  } catch {
    return 'invalid';
  }
  if (!bytesEqual(p.toBytes(), bytes)) return 'invalid'; // canonical: re-encoding reproduces the input
  if (p.isSmallOrder()) return 'small';
  if (!p.isTorsionFree()) return 'mixed';
  return 'ok';
}

/** S, little-endian, is below L. */
export function scalarBelowL(sBytes: Uint8Array): boolean {
  if (sBytes.length !== 32) return false;
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sBytes[i]);
  return s < L;
}

/** AR-19: a public key must be a canonical encoding of a point of order exactly L. */
export const keyAcceptable = (publicKey: Uint8Array): boolean => pointOrder(publicKey) === 'ok';

/**
 * AR-17 and AR-20: 64 bytes R || S, R a canonical encoding of a point of order exactly L, S < L,
 * and the RFC 8032 section 5.1.7 check without ZIP215 leniency. The key must already satisfy AR-19.
 */
export function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  if (pointOrder(signature.subarray(0, 32)) !== 'ok') return false;
  if (!scalarBelowL(signature.subarray(32, 64))) return false;
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
