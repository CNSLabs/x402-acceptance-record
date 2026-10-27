// The EIP-712 signing form (AR-8 to AR-14) and the x402 signed offer's EIP-712 form (AR-29).
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hashTypedData, keccak256, type Hex } from 'viem';
import type { BodyFacts } from './body.ts';
import { bytesToHex, hexToBytes } from './encoding.ts';
import type { ChainCall, ChainDeclaration } from './inputs.ts';

const N: bigint = secp256k1.Point.CURVE().n; // secp256k1 group order
const HALF_N = N >> 1n; // floor(n / 2); "0 < s <= n/2" of EIP-2
const MAX_CHAIN_ID = 2n ** 256n - 1n;
const ZERO_ADDRESS = '0x' + '0'.repeat(40);

export interface Eip155Signer {
  chainId: bigint;
  account: string; // 0x + 40 lowercase hex digits
}

/** AR-11: `eip155:` + decimal chain ID 1..2^256-1 without a leading zero + `:` + 0x + 40 lowercase hex; the zero address refused. */
export function parseEip155Signer(signer: string): Eip155Signer | null {
  const m = /^eip155:([1-9][0-9]*):(0x[0-9a-f]{40})$/.exec(signer);
  if (!m) return null;
  const chainId = BigInt(m[1]);
  if (chainId > MAX_CHAIN_ID) return null;
  if (m[2] === ZERO_ADDRESS) return null;
  return { chainId, account: m[2] };
}

/** AR-8: the domain has only name and version. */
export const ACCEPTANCE_DOMAIN = { name: 'x402 acceptance', version: '0' } as const;

/** AR-9: the types, in the stated order. */
export const ACCEPTANCE_TYPES = {
  EIP712Domain: [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
  ],
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

export interface AcceptanceMessage {
  version: bigint;
  contextId: Hex;
  deliveryIssuer: string;
  confirmingParty: string;
  signerChainId: bigint;
  signerAccount: Hex;
  authority: { mode: string; profile: string; reference: string };
  termsDigest: Hex;
  outcomeDigest: Hex;
  subject: { profile: string; reference: string };
  disposition: string;
  issuedAt: bigint;
}

/** AR-10: the typed message from the body; null when a member it uses fails AR-5, AR-6 or AR-11. */
export function buildAcceptanceMessage(f: BodyFacts): AcceptanceMessage | null {
  if (
    !f.version || f.contextId === null || f.deliveryIssuer === null || f.confirmingParty === null || f.signer === null ||
    f.authority === null || f.termsDigest === null || f.outcomeDigest === null || f.subject === null ||
    f.disposition === null || f.issuedAt === null
  ) return null;
  const signer = parseEip155Signer(f.signer);
  if (!signer) return null;
  return {
    version: 0n,
    contextId: f.contextId as Hex,
    deliveryIssuer: f.deliveryIssuer,
    confirmingParty: f.confirmingParty,
    signerChainId: signer.chainId,
    signerAccount: signer.account as Hex,
    authority: f.authority,
    termsDigest: f.termsDigest as Hex,
    outcomeDigest: f.outcomeDigest as Hex,
    subject: f.subject,
    disposition: f.disposition,
    issuedAt: f.issuedAt,
  };
}

/** AR-9: keccak256(0x19 || 0x01 || domainSeparator || hashStruct(Acceptance, message)). */
export function acceptanceDigest(message: AcceptanceMessage): Hex | null {
  try {
    return hashTypedData({ domain: ACCEPTANCE_DOMAIN, types: ACCEPTANCE_TYPES, primaryType: 'Acceptance', message });
  } catch {
    return null;
  }
}

/** ecrecover: the lowercase address of the key that produced (r, s) over the digest, or null. */
export function recoverAddress(digest: Hex, r: bigint, s: bigint, recovery: number): string | null {
  const hash = hexToBytes(digest);
  if (!hash || hash.length !== 32) return null;
  try {
    const point = new secp256k1.Signature(r, s, recovery).recoverPublicKey(hash);
    const uncompressed = point.toBytes(false); // 0x04 || X || Y
    const addressHash = keccak256(uncompressed.subarray(1), 'bytes');
    return '0x' + bytesToHex(addressHash.subarray(12));
  } catch {
    return null;
  }
}

/**
 * AR-13: for an ordinary account the signature is 0x + 130 lowercase hex digits r || s || v with
 * v 27 or 28, 0 < r < n and 0 < s <= n/2; nothing is normalized. Returns the recovered address.
 */
export function recoverOrdinary(digest: Hex, signature: string): string | null {
  if (!/^0x[0-9a-f]{130}$/.test(signature)) return null;
  const r = BigInt('0x' + signature.slice(2, 66));
  const s = BigInt('0x' + signature.slice(66, 130));
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (v !== 27 && v !== 28) return null;
  if (r <= 0n || r >= N) return null;
  if (s <= 0n || s > HALF_N) return null;
  return recoverAddress(digest, r, s, v - 27);
}

/** AR-14: 0x + an even number of lowercase hex digits. */
export const CONTRACT_SIGNATURE_FORM = /^0x(?:[0-9a-f]{2})*$/;

/** AR-12: the declaration for (signerChainId, signerAccount), or null when the chain state is unavailable. */
export function findDeclaration(chain: ChainDeclaration[] | undefined, chainId: bigint, account: string): ChainDeclaration | null {
  for (const d of chain ?? []) {
    if (!d || typeof d !== 'object') continue;
    if (toBigInt(d.chainId) !== chainId) continue;
    if (typeof d.account !== 'string' || d.account.toLowerCase() !== account) continue;
    return d;
  }
  return null;
}

function toBigInt(v: unknown): bigint | null {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === 'string' && /^(?:0|[1-9][0-9]*)$/.test(v)) return BigInt(v);
  return null;
}

/** AR-14: the declared `isValidSignature(digest, signature)` call for exactly this digest and signature bytes. */
export function findCall(declaration: ChainDeclaration, digest: Hex, signature: string): ChainCall | null {
  for (const c of declaration.calls ?? []) {
    if (!c || typeof c !== 'object') continue;
    if (typeof c.digest !== 'string' || c.digest.toLowerCase() !== digest.toLowerCase()) continue;
    if (typeof c.signature !== 'string' || c.signature.toLowerCase() !== signature.toLowerCase()) continue;
    return c;
  }
  return null;
}

const ERC1271_MAGIC_WORD = '1626ba7e' + '00'.repeat(28);

/** AR-14: valid iff at least 32 bytes of return data whose first 32 bytes are 0x1626ba7e followed by 28 zero bytes (OpenZeppelin SignatureChecker). A revert is invalid. */
export function erc1271CallValid(call: ChainCall): boolean {
  if (call.revert === true) return false;
  if (typeof call.returns !== 'string') return false;
  const data = hexToBytes(call.returns);
  if (!data || data.length < 32) return false;
  return bytesToHex(data.subarray(0, 32)) === ERC1271_MAGIC_WORD;
}

// --- x402 signed offer, EIP-712 form (offer and receipt extension sections 3.2, 4.3, 4.5) ---

export const OFFER_DOMAIN = { name: 'x402 offer', version: '1', chainId: 1n } as const;

export const OFFER_TYPES = {
  EIP712Domain: [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' },
  ],
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

const isUint = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

/** The EIP-712 digest of an offer payload used exactly as transmitted; null when it cannot be typed. */
export function offerTypedDataDigest(payload: Record<string, unknown>): Hex | null {
  const { version, resourceUrl, scheme, network, asset, payTo, amount, validUntil } = payload;
  if (!isUint(version) || !isUint(validUntil)) return null;
  if ([resourceUrl, scheme, network, asset, payTo, amount].some((s) => typeof s !== 'string')) return null;
  try {
    return hashTypedData({
      domain: OFFER_DOMAIN,
      types: OFFER_TYPES,
      primaryType: 'Offer',
      message: {
        version: BigInt(version),
        resourceUrl: resourceUrl as string,
        scheme: scheme as string,
        network: network as string,
        asset: asset as string,
        payTo: payTo as string,
        amount: amount as string,
        validUntil: BigInt(validUntil),
      },
    });
  } catch {
    return null;
  }
}

/** The extension's offer signature: 0x-prefixed 65 bytes r || s || v. Hex case and a high s are not constrained there; v must be 27 or 28. */
export function recoverOfferSigner(digest: Hex, signature: string): string | null {
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) return null;
  const r = BigInt('0x' + signature.slice(2, 66));
  const s = BigInt('0x' + signature.slice(66, 130));
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (v !== 27 && v !== 28) return null;
  if (r <= 0n || r >= N || s <= 0n || s >= N) return null;
  return recoverAddress(digest, r, s, v - 27);
}
