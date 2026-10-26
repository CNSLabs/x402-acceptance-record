// Generator self-test: checks that the bytes the generator claims to have produced have the properties the case rows
// describe. It is not a conformance checker; it guards against generator defects before any checker runs.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from 'viem';
import { V0, utf8, jcs, b64uDecode, unhex, sha256hex, leToBig } from './util.ts';
import { acceptanceDigest, offerDigest712, type Body } from './eip712.ts';
import { L, challenge, TORSION_8 } from './ed.ts';
import * as F from './fixtures.ts';

const doc = JSON.parse(readFileSync(join(V0, 'vectors', 'vectors.json'), 'utf8'));
const vectors: any[] = doc.vectors;
let failures = 0;
const check = (cond: boolean, what: string) => { if (!cond) { failures++; console.log('FAIL', what); } };
const byId = (id: string) => vectors.find((v) => v.id === id) ?? (() => { throw new Error(`no vector ${id}`); })();
const dec = (s: string) => b64uDecode(s);
const txt = (s: string) => Buffer.from(dec(s)).toString('utf8');
const Point = ed25519.Point;

function recover(digest: `0x${string}`, sig: string): string | null {
  const b = unhex(sig);
  if (b.length !== 65) return null;
  try {
    const s = secp256k1.Signature.fromBytes(b.subarray(0, 64), 'compact').addRecoveryBit(b[64] - 27);
    const pub = s.recoverPublicKey(unhex(digest)).toBytes(false);
    return '0x' + keccak256(pub.subarray(1)).slice(26);
  } catch { return null; }
}

// 1. Baseline EIP-712 record recovers to BUYER under the normative digest.
{
  const v = byId('AR-C01-a-eip712');
  const env = JSON.parse(txt(v.inputs.record));
  const digest = acceptanceDigest(env.payload as Body);
  check(recover(digest, env.signature) === F.BUYER, 'baseline EIP-712 signature recovers to BUYER');
  check(env.payload.contextId === '0x' + F.HA && env.payload.subject.reference === F.EA, 'baseline body names Receipt A');
  check(v.statementId === F.statementId(env.payload), 'statementId matches JCS(body)');
}
// 2. Baseline JWS verifies under KB, header is byte-exact, payload is JCS(body).
{
  const v = byId('AR-C01-a-jws');
  const env = JSON.parse(txt(v.inputs.record));
  const [h, p, s] = env.signature.split('.');
  check(Buffer.from(h, 'base64url').toString() === '{"alg":"EdDSA","kid":"cp-1","typ":"x402-acceptance+jws"}', 'JWS header bytes');
  const payload = Buffer.from(p, 'base64url').toString();
  check(payload === jcs(JSON.parse(payload)), 'JWS payload is JCS of its body');
  check(ed25519.verify(Buffer.from(s, 'base64url'), utf8(`${h}.${p}`), F.KB, { zip215: false }), 'baseline JWS verifies under KB');
}
// 3. Receipts verify under KS and their evidenceRef recomputes.
for (const r of [F.RECEIPT_A, F.RECEIPT_B, F.RECEIPT_C]) {
  const info = JSON.parse(Buffer.from(r.text).toString());
  const { evidenceRef, signer, ...rest } = info;
  const body = { ...rest, signer: { keyType: signer.keyType, publicKey: signer.publicKey } };
  const ref = 'x402ev/1:sha256:' + sha256hex(jcs(body));
  check(ref === evidenceRef && ref === r.evidenceRef, 'receipt evidenceRef recomputes');
  const sig = Buffer.from(signer.signature.replace(/^base64url:/, ''), 'base64url');
  check(ed25519.verify(sig, utf8(jcs(body)), Buffer.from(signer.publicKey, 'base64url'), { zip215: false }), 'receipt signature verifies');
  check(/^0x[0-9a-fA-F]{40}$/.test(info.payment.payer) && info.payment.payer.toLowerCase() !== info.payment.payer, 'receipt payer is EIP-55 mixed case');
}
// 4. Offers: JWS verifies under KS, EIP-712 offers recover to their signers, digests as declared.
{
  const o = JSON.parse(Buffer.from(F.OFFER_A.text).toString());
  const [h, p, s] = o.signature.split('.');
  check(JSON.parse(Buffer.from(h, 'base64url').toString()).alg === 'EdDSA', 'offer header alg');
  check(ed25519.verify(Buffer.from(s, 'base64url'), utf8(`${h}.${p}`), F.KS, { zip215: false }), 'Offer A verifies under KS');
  check('0x' + sha256hex(jcs(JSON.parse(Buffer.from(p, 'base64url').toString()))) === F.TA, 'TA is the digest of JCS(payload)');
  const e = JSON.parse(Buffer.from(F.OFFER_A0_712_SELLER.text).toString());
  check(recover(offerDigest712(e.payload), e.signature) === F.SELLER && e.payload.validUntil === 0, 'EIP-712 offer with validUntil 0 recovers to SELLER');
  const g = JSON.parse(Buffer.from(F.OFFER_A_712_OTHER.text).toString());
  check(recover(offerDigest712(g.payload), g.signature) === F.OTHER, 'EIP-712 offer by OTHER recovers to OTHER');
}
// 5. AR-C16 (h): cofactorless equation holds with small-order R; (i): cofactored holds, cofactorless fails.
{
  const msg = (id: string) => { const env = JSON.parse(txt(byId(id).inputs.record)); const [h, p, s] = env.signature.split('.'); return { m: utf8(`${h}.${p}`), sig: new Uint8Array(Buffer.from(s, 'base64url')) }; };
  const eq = (sig: Uint8Array, m: Uint8Array, A: Uint8Array, cofactored: boolean) => {
    const R = Point.fromBytes(sig.subarray(0, 32)); const S = leToBig(sig.subarray(32, 64)); const k = challenge(sig.subarray(0, 32), A, m);
    const lhs = S === 0n ? Point.ZERO : Point.BASE.multiply(S); const rhs = R.add(k === 0n ? Point.ZERO : Point.fromBytes(A).multiply(k));
    return cofactored ? lhs.multiplyUnsafe(8n).equals(rhs.multiplyUnsafe(8n)) : lhs.equals(rhs);
  };
  const h = msg('AR-C16-h-jws');
  check(Point.fromBytes(h.sig.subarray(0, 32)).isSmallOrder() && eq(h.sig, h.m, F.KB, false), 'C16 (h): small-order R, cofactorless equation accepts');
  const i = msg('AR-C16-i-jws');
  check(!Point.fromBytes(i.sig.subarray(0, 32)).isTorsionFree() && eq(i.sig, i.m, F.KB, true) && !eq(i.sig, i.m, F.KB, false), 'C16 (i): mixed-order R, cofactored accepts, cofactorless fails');
  // AR-C20 (b): key A' = KB + T is mixed order; both equations accept under A'.
  const v = byId('AR-C20-b-jws');
  const Ap = new Uint8Array(Buffer.from(v.inputs.trust.keys[0].key, 'base64url'));
  check(!Point.fromBytes(Ap).isTorsionFree() && !Point.fromBytes(Ap).isSmallOrder(), 'C20 (b): key is mixed order');
  const b = msg('AR-C20-b-jws');
  check(eq(b.sig, b.m, Ap, true) && eq(b.sig, b.m, Ap, false), 'C20 (b): both equations accept under the mixed key');
  check(Point.fromBytes(F.KB).add(TORSION_8).equals(Point.fromBytes(Ap)), 'C20 (b): key is KB + T');
  // AR-C20 (c): non-canonical encoding rejected by a canonical decoder.
  const c = byId('AR-C20-c-jws'); let rejected = false; try { Point.fromBytes(new Uint8Array(Buffer.from(c.inputs.trust.keys[0].key, 'base64url'))); } catch { rejected = true; }
  check(rejected, 'C20 (c): key encoding is non-canonical');
  // AR-C16 (g) and AR-C24 (i): S + L.
  const g = msg('AR-C16-g-jws'); check(leToBig(g.sig.subarray(32, 64)) >= L, 'C16 (g): S >= L');
}
// 6. AR-C21 (g): the altered token decodes to the same bytes as the canonical one.
{
  const base = JSON.parse(txt(byId('AR-C01-a-jws').inputs.record)).signature;
  const alt = JSON.parse(txt(byId('AR-C21-g-jws').inputs.record)).signature;
  check(alt !== base && Buffer.from(alt.split('.')[2], 'base64url').equals(Buffer.from(base.split('.')[2], 'base64url')), 'C21 (g): same bytes, different text');
}
// 7. AR-C25 (k) carries a byte that is not UTF-8; (n) carries the escape text.
{
  const k = dec(byId('AR-C25-k-eip712').inputs.record); check(k.includes(0xff), 'C25 (k) eip712 contains 0xFF');
  const kj = JSON.parse(txt(byId('AR-C25-k-jws').inputs.record)).signature.split('.')[1]; check(Buffer.from(kj, 'base64url').includes(0xff), 'C25 (k) jws payload contains 0xFF');
  check(txt(byId('AR-C25-n-eip712').inputs.record).includes('\\ud800'), 'C25 (n) carries \\ud800 escape text');
  check(txt(byId('AR-C25-h-eip712').inputs.record).includes('"issuedAt":1791500600.0'), 'C25 (h) lexical form');
  check(txt(byId('AR-C25-c-jws').inputs.record).length > 0, 'C25 (c) present');
}
// 8. Contract-account vectors: the listed call's digest is the record's digest, the signature is the record's.
for (const id of ['AR-C17-a-eip712', 'AR-C17-b-eip712', 'AR-C18-c-eip712', 'AR-C16-e-eip712', 'AR-C22-b-eip712']) {
  const v = byId(id); const env = JSON.parse(txt(v.inputs.record));
  const wallet = v.inputs.chain.find((c: any) => c.account === F.WALLET && c.chainId === F.CHAIN_ID);
  const call = wallet.calls[0];
  check(call.digest === acceptanceDigest(env.payload as Body) && call.signature === env.signature, `${id}: declared call matches the record`);
}
// 9. Every vector decodes; ids unique; forms consistent with the record.
{
  const ids = new Set<string>();
  for (const v of vectors) {
    check(!ids.has(v.id), `unique id ${v.id}`); ids.add(v.id);
    if (v.form === 'none') { check(v.inputs.record === null, `${v.id}: no record`); continue; }
    const t = Buffer.from(dec(v.inputs.record)).toString('latin1');
    check(t.startsWith(v.form === 'eip712' ? '{"format":"eip712"' : '{"format":"jws"'), `${v.id}: envelope format matches form`);
    for (const term of v.inputs.terms) check(txt(term).startsWith('{"format":'), `${v.id}: terms artifact shape`);
  }
}
console.log(failures === 0 ? `selftest ok: ${vectors.length} vectors` : `selftest: ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
