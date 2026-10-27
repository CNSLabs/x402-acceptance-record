// EIP-712 digests and secp256k1 signatures for acceptance records (SPEC §4.1) and signed offers (offer-receipt §4.3).
import { hashTypedData, getAddress, keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex, unhex, utf8, bigToBe32, beToBig, concat } from './util.ts';

export const SECP256K1_N: bigint = secp256k1.Point.CURVE().n;

export const ACCEPTANCE_DOMAIN = { name: 'x402 acceptance', version: '0' } as const;
export const ACCEPTANCE_TYPES = {
  Acceptance: [
    { name: 'version', type: 'uint256' },
    { name: 'contextId', type: 'bytes32' },
    { name: 'deliveryIssuer', type: 'string' },
    { name: 'confirmingParty', type: 'string' },
    { name: 'signerChainId', type: 'uint256' },
    { name: 'signerAccount', type: 'address' },
    { name: 'authority', type: 'Authority' },
    { name: 'termsDigest', type: 'bytes32' },
    { name: 'outcomeDigest', type: 'bytes32' },
    { name: 'subject', type: 'Subject' },
    { name: 'disposition', type: 'string' },
    { name: 'issuedAt', type: 'uint64' },
  ],
  Authority: [
    { name: 'mode', type: 'string' },
    { name: 'profile', type: 'string' },
    { name: 'reference', type: 'string' },
  ],
  Subject: [
    { name: 'profile', type: 'string' },
    { name: 'reference', type: 'string' },
  ],
} as const;

export const OFFER_DOMAIN = { name: 'x402 offer', version: '1', chainId: 1 } as const;
export const OFFER_TYPES = {
  Offer: [
    { name: 'version', type: 'uint256' },
    { name: 'resourceUrl', type: 'string' },
    { name: 'scheme', type: 'string' },
    { name: 'network', type: 'string' },
    { name: 'asset', type: 'string' },
    { name: 'payTo', type: 'string' },
    { name: 'amount', type: 'string' },
    { name: 'validUntil', type: 'uint256' },
  ],
} as const;

export type Body = {
  version: number; contextId: string; deliveryIssuer: string; confirmingParty: string; signer: string;
  authority: { mode: string; profile: string; reference: string }; termsDigest: string; outcomeDigest: string;
  subject: { profile: string; reference: string }; disposition: string; issuedAt: number;
};

/** Splits an AR-11 signer into chain id and account. Throws when the body cannot be built as a typed message. */
export function splitSigner(signer: string): { chainId: bigint; account: `0x${string}` } {
  const m = /^eip155:([1-9][0-9]*):(0x[0-9a-f]{40})$/.exec(signer);
  if (!m) throw new Error(`signer not buildable: ${signer}`);
  return { chainId: BigInt(m[1]), account: m[2] as `0x${string}` };
}

/** The EIP-712 digest of a body under the given domain and types (defaults: the normative ones). */
export function acceptanceDigest(body: Body, opts: { domain?: Record<string, unknown>; types?: Record<string, readonly { name: string; type: string }[]> } = {}): `0x${string}` {
  const { chainId, account } = splitSigner(body.signer);
  const message = {
    version: BigInt(body.version),
    contextId: body.contextId as `0x${string}`,
    deliveryIssuer: body.deliveryIssuer,
    confirmingParty: body.confirmingParty,
    signerChainId: chainId,
    signerAccount: getAddress(account),
    authority: body.authority,
    termsDigest: body.termsDigest as `0x${string}`,
    outcomeDigest: body.outcomeDigest as `0x${string}`,
    subject: body.subject,
    disposition: body.disposition,
    issuedAt: BigInt(body.issuedAt),
  };
  return hashTypedData({
    domain: (opts.domain ?? ACCEPTANCE_DOMAIN) as any,
    types: (opts.types ?? ACCEPTANCE_TYPES) as any,
    primaryType: 'Acceptance',
    message: message as any,
  });
}

export type OfferPayload = { version: number; resourceUrl: string; scheme: string; network: string; asset: string; payTo: string; amount: string; validUntil: number };

export function offerDigest712(payload: OfferPayload): `0x${string}` {
  return hashTypedData({
    domain: OFFER_DOMAIN as any,
    types: OFFER_TYPES as any,
    primaryType: 'Offer',
    message: { ...payload, version: BigInt(payload.version), validUntil: BigInt(payload.validUntil) } as any,
  });
}

/** Deterministic (RFC 6979) low-s secp256k1 signature of a digest, r ‖ s ‖ v with v in {27, 28}, lowercase hex. */
export function signDigest(seed: Uint8Array, digest: `0x${string}`): `0x${string}` {
  const sig = secp256k1.sign(unhex(digest), seed, { prehash: false, format: 'recovered' });
  const rec = sig[0]; const rs = sig.subarray(1);
  return hex(concat(rs, Uint8Array.of(27 + rec)));
}

export const evmAddress = (seed: Uint8Array) => privateKeyToAccount(hex(seed) as `0x${string}`).address;
export const lower = (addr: string) => addr.toLowerCase();
export const checksum = (addr: string) => getAddress(addr);
/** A deterministic pseudo-address not derived from any key (contract account, payee, asset). */
export const pseudoAddress = (label: string) => ('0x' + keccak256(utf8('x402-acceptance-record/v0 conformance address: ' + label)).slice(26)) as `0x${string}`;

/** AR-C16 (a): s → n − s, v switched. */
export function withHighS(sig: `0x${string}`): `0x${string}` {
  const b = unhex(sig);
  const s = beToBig(b.subarray(32, 64));
  const v = b[64] === 27 ? 28 : 27;
  return hex(concat(b.subarray(0, 32), bigToBe32(SECP256K1_N - s), Uint8Array.of(v)));
}
/** AR-C16 (b): v → v − 27. */
export function withRawV(sig: `0x${string}`): `0x${string}` {
  const b = unhex(sig);
  return hex(concat(b.subarray(0, 64), Uint8Array.of(b[64] - 27)));
}
/** AR-C16 (c): the 64-byte compact form r ‖ (yParity·2^255 + s). */
export function compact2098(sig: `0x${string}`): `0x${string}` {
  const b = unhex(sig);
  const s = beToBig(b.subarray(32, 64));
  const yParity = BigInt(b[64] - 27);
  return hex(concat(b.subarray(0, 32), bigToBe32((yParity << 255n) | s)));
}
export const upperHex = (sig: string) => '0x' + sig.slice(2).toUpperCase();
