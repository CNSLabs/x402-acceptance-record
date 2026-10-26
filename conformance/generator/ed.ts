// Ed25519 signing and the hand-built signatures and keys of AR-C16 (f)–(i), AR-C20 and AR-C24 (i).
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512, concat, bigToLe32, leToBig, utf8, unhex } from './util.ts';

const Point = ed25519.Point;
export const L: bigint = Point.CURVE().n;
export const P_FIELD: bigint = Point.CURVE().p;

export const edPublicKey = (seed: Uint8Array) => ed25519.getPublicKey(seed);
export const edSign = (seed: Uint8Array, msg: Uint8Array) => ed25519.sign(msg, seed);
export const edVerify = (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => {
  try { return ed25519.verify(sig, msg, pub, { zip215: false }); } catch { return false; }
};

/** The secret scalar a (clamped) of a seed, per RFC 8032 §5.1.5. */
export function secretScalar(seed: Uint8Array): bigint {
  return ed25519.utils.getExtendedPublicKey(seed).scalar;
}

/** k = SHA-512(R ‖ A ‖ M) mod L. */
export function challenge(R: Uint8Array, A: Uint8Array, M: Uint8Array): bigint {
  return leToBig(sha512(concat(R, A, M))) % L;
}

export const IDENTITY_ENCODING = (() => { const b = new Uint8Array(32); b[0] = 1; return b; })();
/** A point of order 8 (one of the eight torsion points), from its canonical encoding. */
export const TORSION_8 = Point.fromBytes(unhex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'));
/** The identity point encoded with y = p + 1 ≥ p: a non-canonical encoding (AR-19). */
export const NON_CANONICAL_IDENTITY = bigToLe32(P_FIELD + 1n);

const scalarFromLabel = (label: string) => (leToBig(sha512(utf8(label))) % (L - 1n)) + 1n;

/** AR-C16 (h): R = identity, S = k·a mod L. The cofactorless equation [S]B = R + [k]A holds; R has small order. */
export function forgeIdentityR(seed: Uint8Array, msg: Uint8Array): Uint8Array {
  const a = secretScalar(seed);
  const A = edPublicKey(seed);
  const k = challenge(IDENTITY_ENCODING, A, msg);
  const S = (k * a) % L;
  return concat(IDENTITY_ENCODING, bigToLe32(S));
}

/** AR-C16 (i): R' = rB + T with T of order 8, S' = r + k'·a mod L. The cofactored equation accepts, the cofactorless one fails. */
export function forgeMixedR(seed: Uint8Array, msg: Uint8Array, label: string): Uint8Array {
  const a = secretScalar(seed);
  const A = edPublicKey(seed);
  const r = scalarFromLabel(label);
  const Rp = Point.BASE.multiply(r).add(TORSION_8).toBytes();
  const k = challenge(Rp, A, msg);
  const S = (r + k * a) % L;
  return concat(Rp, bigToLe32(S));
}

/** AR-C20 (b): the mixed-order key A' = A + T, and a signature by a that both RFC 8032 equations accept under A'. */
export function mixedOrderKey(seed: Uint8Array): Uint8Array {
  const A = Point.fromBytes(edPublicKey(seed));
  return A.add(TORSION_8).toBytes();
}
export function signForMixedKey(seed: Uint8Array, msg: Uint8Array, label: string): Uint8Array {
  const a = secretScalar(seed);
  const Ap = mixedOrderKey(seed);
  for (let i = 0; i < 4096; i++) {
    const r = scalarFromLabel(`${label}:${i}`);
    const R = Point.BASE.multiply(r).toBytes();
    const k = challenge(R, Ap, msg);
    if (k % 8n !== 0n) continue; // [k]T = 0 only when 8 | k, which makes the cofactorless equation hold under A'
    const S = (r + k * a) % L;
    return concat(R, bigToLe32(S));
  }
  throw new Error('no r found with 8 | k');
}

/** S replaced by S + L: the same point equation, a non-canonical scalar (AR-20). */
export function withSPlusL(sig: Uint8Array): Uint8Array {
  const S = leToBig(sig.subarray(32, 64));
  return concat(sig.subarray(0, 32), bigToLe32(S + L));
}

export function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const out = new Uint8Array(bytes);
  out[index] ^= 0x01;
  return out;
}

/** Canonical compact JWS over exact header and payload bytes. */
export function compactJws(headerBytes: Uint8Array, payloadBytes: Uint8Array, sign: (signingInput: Uint8Array) => Uint8Array) {
  const h = Buffer.from(headerBytes).toString('base64url');
  const p = Buffer.from(payloadBytes).toString('base64url');
  const sig = sign(utf8(`${h}.${p}`));
  return { h, p, s: Buffer.from(sig).toString('base64url'), sig, token: `${h}.${p}.${Buffer.from(sig).toString('base64url')}` };
}
