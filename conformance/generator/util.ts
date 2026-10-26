// Shared helpers for the generator: bytes, hashing, canonical JSON, base64url, seeds.
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const here = dirname(fileURLToPath(import.meta.url));
export const V0 = join(here, '..');

export const utf8 = (s: string) => new TextEncoder().encode(s);
export const latin1 = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
export const ascii = (b: Uint8Array) => Buffer.from(b).toString('latin1');
export const concat = (...parts: Uint8Array[]) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export const sha256 = (data: Uint8Array | string) => new Uint8Array(createHash('sha256').update(data).digest());
export const sha256hex = (data: Uint8Array | string) => createHash('sha256').update(data).digest('hex');
export const sha512 = (data: Uint8Array) => new Uint8Array(createHash('sha512').update(data).digest());

/** RFC 8785 canonical JSON text. canonicalize uses JSON.stringify for numbers, which is the ES Number::toString rule. */
export function jcs(value: unknown): string {
  const s = canonicalize(value);
  if (typeof s !== 'string') throw new Error('not canonicalizable');
  return s;
}

export const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
export const b64uDecode = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
export const hex = (b: Uint8Array): `0x${string}` => `0x${Buffer.from(b).toString('hex')}`;
export const unhex = (s: string) => new Uint8Array(Buffer.from(s.replace(/^0x/, ''), 'hex'));
export const hexNo0x = (b: Uint8Array) => Buffer.from(b).toString('hex');

export const bigToBe32 = (x: bigint) => unhex(x.toString(16).padStart(64, '0'));
export const bigToLe32 = (x: bigint) => bigToBe32(x).reverse();
export const leToBig = (b: Uint8Array) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
export const beToBig = (b: Uint8Array) => { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; };

/** Seeds: every private key derives from a published seed, itself derived from a label. */
export const SEED_LABEL_PREFIX = 'x402-acceptance-record/v0 conformance seed: ';
export const seedFor = (name: string) => sha256(utf8(SEED_LABEL_PREFIX + name));

export type Seeds = { description: string; derivation: string; seeds: Record<string, string> };
export function loadSeeds(): Seeds {
  return JSON.parse(readFileSync(join(V0, 'vectors', 'seeds.json'), 'utf8'));
}
