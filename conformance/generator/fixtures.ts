// The baseline fixture of CASES.md: parties, keys, seller records, baseline bodies, trust and chain inputs.
import { utf8, jcs, b64u, sha256, sha256hex, hex, concat, seedFor, hexNo0x } from './util.ts';
import { edPublicKey, edSign, compactJws } from './ed.ts';
import {
  type Body, type OfferPayload, acceptanceDigest, offerDigest712, signDigest, evmAddress, lower, checksum, pseudoAddress,
} from './eip712.ts';

export const t0 = 1791500000;
export const CHAIN_ID = 84532;
export const BLOCK = 1000;
export const MAGIC32 = '0x1626ba7e' + '00'.repeat(28);

// Seeds and keys. Ed25519: ks (seller), kb (buyer, kid cp-1), kx (a key never listed in trust.keys), ky (an issuer
// key never listed in trust.issuers). secp256k1: buyer, other, seller.
export const SEED_NAMES = ['ks', 'kb', 'kx', 'ky', 'buyer', 'other', 'seller'] as const;
export type SeedName = (typeof SEED_NAMES)[number];
export const SEED: Record<SeedName, Uint8Array> = Object.fromEntries(SEED_NAMES.map((n) => [n, seedFor(n)])) as Record<SeedName, Uint8Array>;

export const KS = edPublicKey(SEED.ks);
export const KB = edPublicKey(SEED.kb);
export const KX = edPublicKey(SEED.kx);
export const KY = edPublicKey(SEED.ky);
export const KS_B64 = b64u(KS);
export const KB_B64 = b64u(KB);

export const BUYER = lower(evmAddress(SEED.buyer));
export const OTHER = lower(evmAddress(SEED.other));
export const SELLER = lower(evmAddress(SEED.seller));
export const WALLET = lower(pseudoAddress('wallet'));
export const PAYEE = lower(pseudoAddress('payee'));
export const ASSET = lower(pseudoAddress('asset'));

export const SELLER_DID = 'did:web:seller.example';
export const SELLER_KID = 'did:web:seller.example#ks';
export const BUYER_DID = 'did:example:buyer';
export const eip155 = (chainId: number, account: string) => `eip155:${chainId}:${account}`;

// The delivered bytes and their digest DA. Positive cases never supply the bytes.
export const DELIVERED = utf8('{"report":"q3","pages":12}');
export const DA = sha256hex(DELIVERED);

// ---- Receipts (x402ev/1 `info` objects) ----
export type Receipt = { info: Record<string, unknown>; text: Uint8Array; hashHex: string; evidenceRef: string; signature: Uint8Array; body: Record<string, unknown> };

export function receipt(o: {
  payer?: string; clientNonce?: string; contentDigest?: string; latencyMs?: number; signSeed?: Uint8Array; publicKey?: Uint8Array;
} = {}): Receipt {
  const seed = o.signSeed ?? SEED.ks;
  const pub = o.publicKey ?? edPublicKey(seed);
  const body: Record<string, unknown> = {
    scheme: 'x402ev/1',
    canonicalization: 'RFC8785',
    payment: { network: `eip155:${CHAIN_ID}`, payer: o.payer ?? checksum(BUYER), payee: PAYEE, amount: '10000', asset: ASSET },
    request: {
      method: 'GET',
      urlHash: 'sha256:' + sha256hex('https://seller.example/report'),
      clientNonce: o.clientNonce ?? '7c1d0e5a9b3f2468',
      timestamp: t0 - 2,
    },
    delivery: { statusCode: 200, contentDigest: o.contentDigest ?? 'sha256:' + DA, contentType: 'application/json', latencyMs: o.latencyMs ?? 42, timestamp: t0 },
    signer: { keyType: 'Ed25519', publicKey: b64u(pub) },
  };
  const bodyJcs = jcs(body);
  const hashHex = sha256hex(bodyJcs);
  const evidenceRef = 'x402ev/1:sha256:' + hashHex;
  const signature = edSign(seed, utf8(bodyJcs));
  const info: Record<string, unknown> = {
    ...body,
    evidenceRef,
    signer: { ...(body.signer as Record<string, unknown>), signature: 'base64url:' + b64u(signature) },
  };
  return { info, text: utf8(jcs(info)), hashHex, evidenceRef, signature, body };
}

export const RECEIPT_A = receipt();
export const RECEIPT_B = receipt({ clientNonce: 'e4a7c2d9b1f06385' });
export const RECEIPT_C = receipt({ payer: checksum(WALLET) });
export const HA = RECEIPT_A.hashHex, HB = RECEIPT_B.hashHex, HC = RECEIPT_C.hashHex;
export const EA = RECEIPT_A.evidenceRef, EB = RECEIPT_B.evidenceRef, EC = RECEIPT_C.evidenceRef;

// ---- Offers (x402 offer and receipt extension, signed offers) ----
export const OFFER_PAYLOAD_A: OfferPayload = {
  version: 1,
  resourceUrl: 'https://seller.example/report',
  scheme: 'exact',
  network: `eip155:${CHAIN_ID}`,
  asset: checksum(ASSET),
  payTo: checksum(PAYEE),
  amount: '10000',
  validUntil: t0 + 3600,
};
export type Offer = { text: Uint8Array; digest: `0x${string}`; payload: OfferPayload };
export const offerPayloadDigest = (p: OfferPayload) => ('0x' + sha256hex(jcs(p))) as `0x${string}`;

/** JWS offer: header {alg: EdDSA, kid}, payload JCS(payload), Ed25519 signature by the seed. */
export function offerJws(payload: OfferPayload, seed: Uint8Array, kid = SELLER_KID): Offer {
  const headerBytes = utf8(JSON.stringify({ alg: 'EdDSA', kid }));
  const { token } = compactJws(headerBytes, utf8(jcs(payload)), (input) => edSign(seed, input));
  return { text: utf8(JSON.stringify({ format: 'jws', signature: token })), digest: offerPayloadDigest(payload), payload };
}
/** EIP-712 offer under {x402 offer, 1, chainId 1}, signed by a secp256k1 seed. */
export function offerEip712(payload: OfferPayload, seed: Uint8Array): Offer {
  const signature = signDigest(seed, offerDigest712(payload));
  return { text: utf8(JSON.stringify({ format: 'eip712', payload, signature })), digest: offerPayloadDigest(payload), payload };
}

export const OFFER_A = offerJws(OFFER_PAYLOAD_A, SEED.ks);
export const OFFER_A2 = offerJws({ ...OFFER_PAYLOAD_A, validUntil: t0 + 7200 }, SEED.ks);
export const OFFER_A_20000 = offerJws({ ...OFFER_PAYLOAD_A, amount: '20000' }, SEED.ks);
export const OFFER_A_KY = offerJws(OFFER_PAYLOAD_A, SEED.ky);
export const OFFER_A0_712_SELLER = offerEip712({ ...OFFER_PAYLOAD_A, validUntil: 0 }, SEED.seller);
export const OFFER_A_712_OTHER = offerEip712(OFFER_PAYLOAD_A, SEED.other);
export const TA = OFFER_A.digest;
export const TA_20000 = OFFER_A_20000.digest;

// ---- Baseline bodies ----
export const bodyE = (): Body => ({
  version: 0,
  contextId: '0x' + HA,
  deliveryIssuer: SELLER_DID,
  confirmingParty: eip155(CHAIN_ID, BUYER),
  signer: eip155(CHAIN_ID, BUYER),
  authority: { mode: 'direct', profile: 'payer/0', reference: '' },
  termsDigest: TA,
  outcomeDigest: '0x' + DA,
  subject: { profile: 'x402ev/1', reference: EA },
  disposition: 'accepted',
  issuedAt: t0 + 600,
});
export const bodyJ = (): Body => ({
  ...bodyE(),
  confirmingParty: BUYER_DID,
  signer: BUYER_DID,
  authority: { mode: 'declared', profile: 'declared-evidence/0', reference: '' },
});
export const STATEMENT_ID_PREFIX = 'x402accept/0:sha256:';
export const statementId = (body: Body) => STATEMENT_ID_PREFIX + sha256hex(jcs(body));

// ---- Records ----
/** The contract account's "signature": a deterministic 65-byte blob for a digest. Only the declared call gives it meaning. */
export function walletSignature(digest: string): `0x${string}` {
  return hex(concat(sha256(utf8('wallet-sig-1:' + digest)), sha256(utf8('wallet-sig-2:' + digest)), Uint8Array.of(0x1b)));
}

export type EipRecord = { text: Uint8Array; bodyBytes: Uint8Array; digest: `0x${string}` | null; signature: string };
export function eipRecord(body: Body, o: {
  seed?: Uint8Array; wallet?: boolean; domain?: Record<string, unknown>; types?: Record<string, readonly { name: string; type: string }[]>;
  bodyBytes?: Uint8Array; signature?: string; envelopeExtra?: string;
} = {}): EipRecord {
  let digest: `0x${string}` | null = null;
  try { digest = acceptanceDigest(body, { domain: o.domain, types: o.types }); } catch { digest = null; }
  let signature = o.signature;
  if (signature === undefined) {
    if (digest === null) throw new Error('typed message not buildable and no signature given');
    signature = o.wallet ? walletSignature(digest) : signDigest(o.seed ?? SEED.buyer, digest);
  }
  const bodyBytes = o.bodyBytes ?? utf8(jcs(body));
  const text = concat(utf8('{"format":"eip712","payload":'), bodyBytes, utf8(`,"signature":"${signature}"${o.envelopeExtra ?? ''}}`));
  return { text, bodyBytes, digest, signature };
}

export const JWS_HEADER = utf8('{"alg":"EdDSA","kid":"cp-1","typ":"x402-acceptance+jws"}');
export type JwsRecord = { text: Uint8Array; token: string; signingInput: Uint8Array; sig: Uint8Array; payloadBytes: Uint8Array };
export function jwsRecord(body: Body, o: {
  seed?: Uint8Array; headerBytes?: Uint8Array; payloadBytes?: Uint8Array; sign?: (input: Uint8Array) => Uint8Array; sigBytes?: Uint8Array;
  token?: (token: string) => string; envelopeExtra?: string;
} = {}): JwsRecord {
  const headerBytes = o.headerBytes ?? JWS_HEADER;
  const payloadBytes = o.payloadBytes ?? utf8(jcs(body));
  const signer = o.sigBytes ? () => o.sigBytes! : (o.sign ?? ((input: Uint8Array) => edSign(o.seed ?? SEED.kb, input)));
  const j = compactJws(headerBytes, payloadBytes, signer);
  const token = o.token ? o.token(j.token) : j.token;
  const text = utf8(`{"format":"jws","signature":"${token}"${o.envelopeExtra ?? ''}}`);
  return { text, token, signingInput: utf8(`${j.h}.${j.p}`), sig: j.sig, payloadBytes };
}

// ---- Trust and chain inputs ----
export type IssuerKey = { ed25519: string; kid?: string } | { address: string };
export type Trust = {
  issuers: { issuer: string; keys: IssuerKey[] }[];
  keys: { kid: string; signer: string; key: string }[];
  authority: { confirmingParty: string; signer: string; subjectProfile: string; subjectReference: string }[];
  complete?: unknown;
};
export const trustBase = (): Trust => ({
  issuers: [{ issuer: SELLER_DID, keys: [{ ed25519: KS_B64, kid: SELLER_KID }] }],
  keys: [{ kid: 'cp-1', signer: BUYER_DID, key: KB_B64 }],
  authority: [{ confirmingParty: BUYER_DID, signer: BUYER_DID, subjectProfile: 'x402ev/1', subjectReference: EA }],
});

export type Call = { digest: string; signature: string; returns?: string; revert?: true };
export type ChainEntry = { chainId: number; block: number; account: string; code: boolean; calls?: Call[] };
export function chainBase(o: { walletCalls?: Call[]; omitWallet?: boolean; buyer?: { code: boolean; calls?: Call[] }; extra?: ChainEntry[] } = {}): ChainEntry[] {
  const entries: ChainEntry[] = [
    { chainId: CHAIN_ID, block: BLOCK, account: BUYER, code: o.buyer?.code ?? false, ...(o.buyer?.calls ? { calls: o.buyer.calls } : {}) },
    { chainId: CHAIN_ID, block: BLOCK, account: OTHER, code: false },
  ];
  if (!o.omitWallet) entries.push({ chainId: CHAIN_ID, block: BLOCK, account: WALLET, code: true, calls: o.walletCalls ?? [] });
  return [...entries, ...(o.extra ?? [])];
}

/** What the vector file publishes about the fixture, for readers following a vector back to its row. */
export function fixtureSummary() {
  return {
    t0,
    chainId: CHAIN_ID,
    block: BLOCK,
    keys: { KS: KS_B64, KB: KB_B64, KX: b64u(KX), KY: b64u(KY) },
    addresses: { BUYER, OTHER, SELLER, WALLET, PAYEE, ASSET },
    digests: { TA, TA_20000, DA, HA, HB, HC, EA, EB, EC },
    offerPayloadA: OFFER_PAYLOAD_A,
    deliveredBytesSha256: DA,
    walletSignatureRule: 'sha256("wallet-sig-1:"+digest) || sha256("wallet-sig-2:"+digest) || 0x1b; meaningful only through the declared isValidSignature call',
    receiptExampleShape: 'x402ev/1 info object as in PR #3682 at 23b5c21, without txHash, fingerprint or transparency',
    daHex: hexNo0x(sha256(DELIVERED)),
  };
}
