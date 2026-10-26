// Synthetic checks for the checker, usable before vectors.json exists:
//   tsx checker/selftest.ts            runs every check and exits non-zero on a failure
//   tsx checker/selftest.ts <out.json> also writes a vector-shaped file for run-vectors.ts
// Fixtures mirror CASES.md's baseline with locally derived test keys; nothing here is a published vector.
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { getAddress, hashTypedData, keccak256, type Hex } from 'viem';
import { checkBody } from './body.ts';
import { L, pointOrder, verifyEd25519 } from './ed25519.ts';
import { ACCEPTANCE_TYPES, acceptanceDigest, buildAcceptanceMessage, offerTypedDataDigest } from './eip712.ts';
import { b64uDecode, b64uEncode, bytesToHex, hexToBytes, jcs, sha256Hex, utf8 } from './encoding.ts';
import { parseStrictJson, toPlain } from './json.ts';
import { compareOutput, decodeInputs } from './run-vectors.ts';
import { verify, type Output, type VerifyInputs } from './verify.ts';

let failures = 0;
let checks = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  checks++;
  if (!ok) {
    failures++;
    console.log(`FAIL ${name}${detail === undefined ? '' : ` ${JSON.stringify(detail)}`}`);
  }
}

// ------------------------------------------------------------------ strict JSON reader
{
  const parse = (s: string) => parseStrictJson(utf8(s));
  const lex = (s: string) => {
    const n = parse(s);
    const m = n && n.kind === 'object' ? n.members.get('issuedAt') : undefined;
    return m && m.kind === 'number' ? m.lexeme : m ? m.kind : null;
  };
  check('json: plain integer lexeme', lex('{"issuedAt":1791500600}') === '1791500600');
  check('json: fraction lexeme kept', lex('{"issuedAt":1791500600.0}') === '1791500600.0');
  check('json: exponent lexeme kept', lex('{"issuedAt":1.7915006e9}') === '1.7915006e9');
  check('json: leading zero rejected', parse('{"issuedAt":01791500600}') === null);
  check('json: string is a string node', lex('{"issuedAt":"1791500600"}') === 'string');
  check('json: negative integer lexeme', lex('{"issuedAt":-5}') === '-5');
  check('json: duplicate member rejected', parse('{"a":1,"a":1}') === null);
  check('json: nested duplicate rejected', parse('{"a":{"b":1,"b":2}}') === null);
  check('json: lone high surrogate rejected', parse('{"a":"\\ud800"}') === null);
  check('json: lone low surrogate rejected', parse('{"a":"\\udc00"}') === null);
  check('json: surrogate pair accepted', (() => { const n = parse('{"a":"\\ud83d\\ude00"}'); const a = n && n.kind === 'object' ? n.members.get('a') : undefined; return a?.kind === 'string' && a.value === '\u{1F600}'; })());
  check('json: invalid UTF-8 byte rejected', parseStrictJson(new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])) === null);
  check('json: overlong UTF-8 rejected', parseStrictJson(new Uint8Array([0x22, 0xc0, 0xaf, 0x22])) === null);
  check('json: UTF-8 encoded surrogate rejected', parseStrictJson(new Uint8Array([0x22, 0xed, 0xa0, 0x80, 0x22])) === null);
  check('json: BOM rejected', parseStrictJson(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d])) === null);
  check('json: raw control char rejected', parse('{"a":"x\u0001y"}') === null);
  check('json: trailing comma rejected', parse('{"a":1,}') === null && parse('[1,]') === null);
  check('json: trailing content rejected', parse('{} x') === null);
  check('json: leading plus rejected', parse('{"a":+1}') === null);
  check('json: whitespace tolerated', parse(' \t\r\n{ "a" : [ 1 , 2 ] } \n') !== null);
  check('json: empty object and array', parse('{}') !== null && parse('[]') !== null);
  check('json: escapes', (() => { const n = parse('"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041"'); return n?.kind === 'string' && n.value === '"\\/\b\f\n\r\tA'; })());
  check('json: bad escape rejected', parse('"\\x"') === null);
  check('json: literals', parse('[true,false,null]') !== null && parse('[tru]') === null);
  check('json: toPlain round trip', jcs(toPlain(parse('{"b":[1,2.5,"x",true,null],"a":{"__proto__":1}}')!)) === '{"a":{"__proto__":1},"b":[1,2.5,"x",true,null]}');
  check('json: depth limit', parse('['.repeat(70) + ']'.repeat(70)) === null && parse('['.repeat(60) + ']'.repeat(60)) !== null);
}

// ------------------------------------------------------------------ canonical base64url
{
  const eq = (a: Uint8Array | null, b: number[]) => a !== null && a.length === b.length && b.every((x, i) => a[i] === x);
  check('b64u: empty', eq(b64uDecode(''), []));
  check('b64u: one byte canonical', eq(b64uDecode('AQ'), [1]));
  check('b64u: one byte non-zero trailing bits rejected', b64uDecode('AR') === null);
  check('b64u: two bytes canonical', eq(b64uDecode('AQI'), [1, 2]));
  check('b64u: two bytes non-zero trailing bits rejected', b64uDecode('AQJ') === null);
  check('b64u: padding rejected', b64uDecode('AQ==') === null);
  check('b64u: length 1 mod 4 rejected', b64uDecode('A') === null);
  check('b64u: standard alphabet rejected', b64uDecode('+/8') === null);
  check('b64u: url alphabet', eq(b64uDecode('-_8'), [0xfb, 0xff]));
  const rnd = new Uint8Array(77).map((_, i) => (i * 37 + 11) & 0xff);
  check('b64u: round trip', eq(b64uDecode(b64uEncode(rnd)), [...rnd]));
  check('b64u: matches Buffer encoding', b64uEncode(rnd) === Buffer.from(rnd).toString('base64url'));
}

// ------------------------------------------------------------------ helpers for the fixtures
const sha256 = (s: string) => new Uint8Array(createHash('sha256').update(s).digest());
const sha512 = (b: Uint8Array) => new Uint8Array(createHash('sha512').update(b).digest());
const le = (n: bigint): Uint8Array => { const out = new Uint8Array(32); for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; } return out; };
const fromLe = (b: Uint8Array): bigint => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const concat = (...parts: Uint8Array[]) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const mod = (a: bigint, m: bigint) => ((a % m) + m) % m;
const Point = ed25519.Point;
const T8 = Point.fromBytes(hexToBytes('0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05')!); // a point of order 8
const secretScalar = (seed: Uint8Array): bigint => { const h = sha512(seed).subarray(0, 32); h[0] &= 248; h[31] &= 127; h[31] |= 64; return fromLe(h); };
const addressOf = (priv: Uint8Array): string => '0x' + bytesToHex(keccak256(secp256k1.getPublicKey(priv, false).subarray(1), 'bytes').subarray(12));
const signDigest = (digest: Hex, priv: Uint8Array): string => {
  const sig = secp256k1.sign(hexToBytes(digest)!, priv, { prehash: false, format: 'recovered' }); // recovery byte first
  return '0x' + bytesToHex(sig.subarray(1)) + (27 + sig[0]).toString(16);
};
const KS = sha256('KS'), KB = sha256('KB'), KX = sha256('KX');
const KSpub = ed25519.getPublicKey(KS), KBpub = ed25519.getPublicKey(KB), KXpub = ed25519.getPublicKey(KX);
const BUYERk = sha256('BUYER'), OTHERk = sha256('OTHER'), SELLERk = sha256('SELLER'), UNLISTEDk = sha256('UNLISTED');
const BUYER = addressOf(BUYERk), OTHER = addressOf(OTHERk), SELLER = addressOf(SELLERk);
const WALLET = '0x' + bytesToHex(sha256('WALLET')).slice(0, 40);
const PAYEE = '0x' + bytesToHex(sha256('PAYEE')).slice(0, 40);
const ASSET = '0x' + bytesToHex(sha256('ASSET')).slice(0, 40);
const t0 = 1791500000;
const OUTCOME = utf8('{"report":"ok"}');
const DA = sha256Hex(OUTCOME);
const ISSUER = 'did:web:seller.example';

// ------------------------------------------------------------------ Ed25519 order checks
{
  const id = new Uint8Array(32); id[0] = 1;
  check('ed25519: identity is small order', pointOrder(id) === 'small');
  check('ed25519: T8 is small order', pointOrder(T8.toBytes()) === 'small');
  check('ed25519: KB is order L', pointOrder(KBpub) === 'ok');
  const mixed = Point.fromBytes(KBpub).add(T8).toBytes();
  check('ed25519: KB + T is mixed order', pointOrder(mixed) === 'mixed');
  const nonCanonical = le(2n ** 255n - 19n + 1n); // y = p + 1 (y >= p), sign bit 0
  check('ed25519: y >= p is invalid', pointOrder(nonCanonical) === 'invalid');
  const allOnes = new Uint8Array(32).fill(0xff);
  check('ed25519: 0xff..ff is invalid', pointOrder(allOnes) === 'invalid');
  check('ed25519: wrong length invalid', pointOrder(new Uint8Array(31)) === 'invalid');

  const msg = utf8('hello');
  const good = ed25519.sign(msg, KB);
  check('ed25519: honest signature verifies', verifyEd25519(good, msg, KBpub));
  const a = secretScalar(KB);
  check('ed25519: secret scalar reproduces the public key', bytesToHex(Point.BASE.multiply(mod(a, L)).toBytes()) === bytesToHex(KBpub));
  // AR-C16 (h): R = identity, S = k·a mod L; the cofactorless equation accepts
  const kH = mod(fromLe(sha512(concat(id, KBpub, msg))), L);
  const sigH = concat(id, le(mod(kH * a, L)));
  check('ed25519: forgery (h) passes the bare equation', ed25519.verify(sigH, msg, KBpub, { zip215: false }) === true);
  check('ed25519: forgery (h) refused by AR-20', verifyEd25519(sigH, msg, KBpub) === false);
  // AR-C16 (i): R' = rB + T, S' = r + k'·a mod L; the cofactored equation accepts
  const r = 123456789n;
  const Rp = Point.BASE.multiply(r).add(T8).toBytes();
  const kI = mod(fromLe(sha512(concat(Rp, KBpub, msg))), L);
  const sigI = concat(Rp, le(mod(r + kI * a, L)));
  check('ed25519: forgery (i) passes the cofactored equation', ed25519.verify(sigI, msg, KBpub, { zip215: false }) === true);
  check('ed25519: forgery (i) refused by AR-20', verifyEd25519(sigI, msg, KBpub) === false);
  // AR-C16 (g): S + L
  const sigG = concat(good.subarray(0, 32), le(fromLe(good.subarray(32)) + L));
  check('ed25519: S + L refused', verifyEd25519(sigG, msg, KBpub) === false);
  const flipped = new Uint8Array(good); flipped[40] ^= 1;
  check('ed25519: flipped byte refused', verifyEd25519(flipped, msg, KBpub) === false);
}

// ------------------------------------------------------------------ body form checks
{
  const body = (s: string) => checkBody(parseStrictJson(utf8(s))!);
  const base = `{"version":0,"contextId":"0x${'a'.repeat(64)}","deliveryIssuer":"i","confirmingParty":"c","signer":"s","authority":{"mode":"direct","profile":"payer/0","reference":""},"termsDigest":"0x${'b'.repeat(64)}","outcomeDigest":"0x${'c'.repeat(64)}","subject":{"profile":"x402ev/1","reference":"r"},"disposition":"accepted","issuedAt":ISSUED}`;
  check('body: valid', body(base.replace('ISSUED', '1791500600')).invalid === false);
  check('body: issuedAt 2^53-1 valid', body(base.replace('ISSUED', '9007199254740991')).issuedAt === 9007199254740991n);
  check('body: issuedAt 2^53 invalid', body(base.replace('ISSUED', '9007199254740992')).issuedAt === null);
  check('body: issuedAt fraction invalid', body(base.replace('ISSUED', '1791500600.0')).issuedAt === null);
  check('body: issuedAt exponent invalid', body(base.replace('ISSUED', '1.7915006e9')).issuedAt === null);
  check('body: issuedAt string invalid', body(base.replace('ISSUED', '"1791500600"')).issuedAt === null);
  check('body: issuedAt zero valid', body(base.replace('ISSUED', '0')).issuedAt === 0n);
  check('body: version 0.0 invalid', body(base.replace('ISSUED', '1').replace('"version":0', '"version":0.0')).version === false);
  check('body: version 1 invalid', body(base.replace('ISSUED', '1').replace('"version":0', '"version":1')).version === false);
  check('body: extra member invalid', body(base.replace('ISSUED', '1').replace('"version":0', '"version":0,"reason":"late"')).invalid === true);
  check('body: uppercase hex invalid', body(base.replace('ISSUED', '1').replace('a'.repeat(64), 'A'.repeat(64))).contextId === null);
  const empty = body(base.replace('ISSUED', '1').replace('"confirmingParty":"c"', '"confirmingParty":""'));
  check('body: empty confirmingParty is a form-valid string', empty.invalid === false && empty.confirmingParty === '');
  check('body: not_responded fails AR-1', body(base.replace('ISSUED', '1').replace('accepted', 'not_responded')).invalid === true);
}

// ------------------------------------------------------------------ fixtures (CASES.md baseline, local keys)
interface Receipt { text: string; evidenceRef: string; hex: string }
function receipt(mutate: (info: Record<string, unknown>) => void = () => {}, seed: Uint8Array = KS, publicKey: Uint8Array = KSpub, post: (info: Record<string, unknown>) => void = () => {}): Receipt {
  const info: Record<string, unknown> = {
    scheme: 'x402ev/1',
    canonicalization: 'RFC8785',
    payment: { network: 'eip155:84532', payer: getAddress(BUYER), payee: PAYEE, amount: '10000', asset: ASSET },
    request: { method: 'GET', urlHash: 'sha256:' + sha256Hex(utf8('https://seller.example/report')), clientNonce: 'nonce-a', timestamp: t0 - 2 },
    delivery: { statusCode: 200, contentDigest: 'sha256:' + DA, contentType: 'application/json', latencyMs: 42, timestamp: t0 },
    signer: { keyType: 'Ed25519', publicKey: b64uEncode(publicKey) },
  };
  mutate(info);
  const bodyJcs = utf8(jcs(info));
  const hex = sha256Hex(bodyJcs);
  const evidenceRef = 'x402ev/1:sha256:' + hex;
  (info.signer as Record<string, unknown>).signature = 'base64url:' + b64uEncode(ed25519.sign(bodyJcs, seed));
  info.evidenceRef = evidenceRef;
  post(info);
  return { text: JSON.stringify(info), evidenceRef, hex };
}
const receiptA = receipt();
const receiptB = receipt((i) => { (i.request as Record<string, unknown>).clientNonce = 'nonce-b'; });
const receiptC = receipt((i) => { (i.payment as Record<string, unknown>).payer = getAddress(WALLET); });
const EA = receiptA.evidenceRef, HA = receiptA.hex, HB = receiptB.hex, EC = receiptC.evidenceRef, HC = receiptC.hex;

const offerPayload = (over: Record<string, unknown> = {}) => ({
  version: 1, resourceUrl: 'https://seller.example/report', scheme: 'exact', network: 'eip155:84532',
  asset: getAddress(ASSET), payTo: getAddress(PAYEE), amount: '10000', validUntil: t0 + 3600, ...over,
});
function offerJws(payload: Record<string, unknown>, seed: Uint8Array = KS, header: Record<string, unknown> = { alg: 'EdDSA', kid: 'did:web:seller.example#ks' }): string {
  const h = b64uEncode(utf8(JSON.stringify(header)));
  const p = b64uEncode(utf8(jcs(payload)));
  return JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(ed25519.sign(utf8(`${h}.${p}`), seed))}` });
}
function offerEip712(payload: Record<string, unknown>, priv: Uint8Array): string {
  return JSON.stringify({ format: 'eip712', payload, signature: signDigest(offerTypedDataDigest(payload)!, priv) });
}
const digestOf = (payload: unknown) => '0x' + sha256Hex(utf8(jcs(payload)));
const offerA = offerJws(offerPayload());
const TA = digestOf(offerPayload());

const bodyEip712 = (over: Record<string, unknown> = {}) => ({
  version: 0, contextId: '0x' + HA, deliveryIssuer: ISSUER, confirmingParty: `eip155:84532:${BUYER}`, signer: `eip155:84532:${BUYER}`,
  authority: { mode: 'direct', profile: 'payer/0', reference: '' }, termsDigest: TA, outcomeDigest: '0x' + DA,
  subject: { profile: 'x402ev/1', reference: EA }, disposition: 'accepted', issuedAt: t0 + 600, ...over,
});
const bodyJws = (over: Record<string, unknown> = {}) => bodyEip712({
  confirmingParty: 'did:example:buyer', signer: 'did:example:buyer', authority: { mode: 'declared', profile: 'declared-evidence/0', reference: '' }, ...over,
});
const digestFor = (body: Record<string, unknown>): Hex => acceptanceDigest(buildAcceptanceMessage(checkBody(parseStrictJson(utf8(JSON.stringify(body)))!))!)!;
function recordEip712(body: Record<string, unknown>, priv: Uint8Array, digest: Hex = digestFor(body)): string {
  return JSON.stringify({ format: 'eip712', payload: body, signature: signDigest(digest, priv) });
}
const JWS_HEADER = { alg: 'EdDSA', kid: 'cp-1', typ: 'x402-acceptance+jws' };
function recordJws(body: Record<string, unknown>, seed: Uint8Array = KB, header: Record<string, unknown> | string = JWS_HEADER, payloadText: string = jcs(body)): string {
  const h = b64uEncode(utf8(typeof header === 'string' ? header : JSON.stringify(header)));
  const p = b64uEncode(utf8(payloadText));
  return JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(ed25519.sign(utf8(`${h}.${p}`), seed))}` });
}
const walletCall = (body: Record<string, unknown>, signature: string, outcome: { returns?: string; revert?: true }) => ({ digest: digestFor(body), signature, ...outcome });
const MAGIC = '0x1626ba7e' + '00'.repeat(28);

type Raw = Record<string, unknown>;
function baseInputs(form: 'eip712' | 'jws', over: Raw = {}): Raw {
  return {
    record: form === 'eip712' ? recordEip712(bodyEip712(), BUYERk) : recordJws(bodyJws()),
    subject: receiptA.text,
    terms: [offerA],
    trust: {
      issuers: [{ issuer: ISSUER, keys: [{ ed25519: b64uEncode(KSpub), kid: 'did:web:seller.example#ks' }] }],
      keys: [{ kid: 'cp-1', signer: 'did:example:buyer', key: b64uEncode(KBpub) }],
      authority: [{ confirmingParty: 'did:example:buyer', signer: 'did:example:buyer', subjectProfile: 'x402ev/1', subjectReference: EA }],
    },
    chain: [
      { chainId: 84532, block: 1000, account: BUYER, code: false },
      { chainId: 84532, block: 1000, account: OTHER, code: false },
    ],
    ...over,
  };
}
/** Raw inputs (texts) to the decoded VerifyInputs the verifier takes. */
function toInputs(raw: Raw): VerifyInputs {
  const bytes = (s: unknown) => (typeof s === 'string' ? utf8(s) : s instanceof Uint8Array ? s : null);
  return {
    record: raw.record === null || raw.record === undefined ? null : bytes(raw.record)!,
    subject: raw.subject === null || raw.subject === undefined ? null : bytes(raw.subject)!,
    terms: ((raw.terms as unknown[]) ?? []).map((t) => bytes(t)!),
    ...(raw.outcome === undefined ? {} : { outcome: bytes(raw.outcome)! }),
    trust: (raw.trust ?? {}) as VerifyInputs['trust'],
    chain: (raw.chain ?? []) as VerifyInputs['chain'],
    contractAccounts: raw.contractAccounts === undefined ? true : (raw.contractAccounts as boolean),
  };
}

interface Scenario { id: string; inputs: Raw; expect: Record<string, unknown> }
const scenarios: Scenario[] = [];
const scenario = (id: string, inputs: Raw, expect: Record<string, unknown>) => scenarios.push({ id, inputs, expect });
const VERIFIED = { result: 'verified', conditions: [], disposition: 'accepted' };
const malformed = (...c: string[]) => ({ result: 'malformed', conditions: c });
const unresolved = (reason: string, policy_refusal: boolean) => ({ result: 'key_unresolved', conditions: [], reason, policy_refusal });
const unknown = (reason?: string) => (reason ? { result: 'unknown', conditions: [], reason, disposition: 'accepted' } : { result: 'unknown', conditions: ['acceptance_authority_unresolved'], disposition: 'accepted' });

// AR-C01
scenario('C01-a-eip712', baseInputs('eip712'), VERIFIED);
scenario('C01-a-jws', baseInputs('jws'), VERIFIED);
scenario('C01-b-jws', baseInputs('jws', { terms: [offerJws(offerPayload({ validUntil: t0 + 7200 })), offerA] }), VERIFIED);
{
  const body = bodyEip712({ authority: { mode: 'declared', profile: 'declared-evidence/0', reference: '' } });
  const base = baseInputs('eip712', { record: recordEip712(body, BUYERk) });
  (base.trust as Raw).authority = [...((base.trust as Raw).authority as unknown[]), { confirmingParty: `eip155:84532:${BUYER}`, signer: `eip155:84532:${BUYER}`, subjectProfile: 'x402ev/1', subjectReference: EA }];
  scenario('C01-c-eip712', base, VERIFIED);
}
{
  const payload = offerPayload({ validUntil: 0 });
  const base = baseInputs('eip712', { record: recordEip712(bodyEip712({ termsDigest: digestOf(payload) }), BUYERk), terms: [offerEip712(payload, SELLERk)] });
  ((base.trust as Raw).issuers as Raw[])[0].keys = [{ ed25519: b64uEncode(KSpub), kid: 'did:web:seller.example#ks' }, { address: SELLER }];
  scenario('C01-d-eip712', base, VERIFIED);
}
// AR-C02
scenario('C02-D-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ disposition: 'disputed', issuedAt: t0 + 900 }), BUYERk) }), { ...VERIFIED, disposition: 'disputed' });
// AR-C03
scenario('C03-none', baseInputs('eip712', { record: null }), { result: 'no_record', conditions: [] });
// AR-C04
scenario('C04-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ disposition: 'not_responded' }), BUYERk) }), malformed('acceptance_member_invalid'));
scenario('C04-jws', baseInputs('jws', { record: recordJws(bodyJws({ disposition: 'not_responded' })) }), malformed('acceptance_member_invalid'));
// AR-C05
scenario('C05-a-eip712', baseInputs('eip712', { record: recordEip712({ ...bodyEip712(), reason: 'late' }, BUYERk, digestFor(bodyEip712())) }), malformed('acceptance_member_invalid'));
scenario('C05-a-jws', baseInputs('jws', { record: recordJws({ ...bodyJws(), reason: 'late' }) }), malformed('acceptance_member_invalid'));
scenario('C05-d-jws', baseInputs('jws', { record: recordJws(bodyJws({ subject: { profile: 'x402ev/1', reference: EA, uri: 'x' } })) }), malformed('acceptance_member_invalid'));
scenario('C05-e-eip712', baseInputs('eip712', { record: JSON.stringify({ ...JSON.parse(recordEip712(bodyEip712(), BUYERk)), hint: 1 }) }), malformed('acceptance_member_invalid'));
scenario('C05-l-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ version: 1 }), BUYERk, digestFor(bodyEip712())) }), malformed('acceptance_member_invalid'));
scenario('C05-l-jws', baseInputs('jws', { record: recordJws(bodyJws({ version: 1 })) }), malformed('acceptance_member_invalid'));
scenario('C05-f-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ signer: `eip155:84532:${getAddress(BUYER)}` }), BUYERk, digestFor(bodyEip712())) }), malformed('acceptance_member_invalid'));
scenario('C05-g-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ signer: `eip155:84532:0x${'0'.repeat(40)}` }), BUYERk, digestFor(bodyEip712())) }), malformed('acceptance_member_invalid'));
scenario('C05-o-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ signer: `eip155:084532:${BUYER}`, confirmingParty: `eip155:084532:${BUYER}` }), BUYERk, digestFor(bodyEip712())) }), malformed('acceptance_member_invalid'));
scenario('C05-p-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ signer: `eip155:0:${BUYER}`, confirmingParty: `eip155:0:${BUYER}` }), BUYERk, digestFor(bodyEip712())) }), malformed('acceptance_member_invalid'));
// AR-C06
scenario('C06-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ confirmingParty: '' }), BUYERk) }), malformed('confirming_party_absent'));
scenario('C06-jws', baseInputs('jws', { record: recordJws(bodyJws({ confirmingParty: '' })) }), malformed('confirming_party_absent'));
// AR-C07
{
  const base = baseInputs('jws', { record: recordJws(bodyJws(), KS, { alg: 'EdDSA', kid: 'cp-9', typ: 'x402-acceptance+jws' }) });
  (base.trust as Raw).keys = [...((base.trust as Raw).keys as unknown[]), { kid: 'cp-9', signer: 'did:example:buyer', key: b64uEncode(KSpub) }];
  scenario('C07-a-jws', base, malformed('acceptance_signer_is_issuer'));
}
{
  const base = baseInputs('jws', { record: recordJws(bodyJws({ signer: ISSUER, confirmingParty: ISSUER })) });
  (base.trust as Raw).keys = [{ kid: 'cp-1', signer: ISSUER, key: b64uEncode(KBpub) }];
  (base.trust as Raw).authority = [{ confirmingParty: ISSUER, signer: ISSUER, subjectProfile: 'x402ev/1', subjectReference: EA }];
  scenario('C07-b-jws', base, malformed('acceptance_signer_is_issuer'));
}
{
  const base = baseInputs('eip712');
  ((base.trust as Raw).issuers as Raw[])[0].keys = [{ ed25519: b64uEncode(KSpub) }, { address: BUYER }];
  scenario('C07-c-eip712', base, malformed('acceptance_signer_is_issuer'));
}
// AR-C08
const TA2 = digestOf(offerPayload({ amount: '20000' }));
scenario('C08-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ termsDigest: TA2 }), BUYERk) }), malformed('acceptance_terms_digest_mismatch'));
scenario('C08-jws', baseInputs('jws', { record: recordJws(bodyJws({ termsDigest: TA2 })) }), malformed('acceptance_terms_digest_mismatch'));
// AR-C09
scenario('C09-a-jws', baseInputs('jws', { record: recordJws(bodyJws({ outcomeDigest: '0x' + sha256Hex(utf8('other')) })) }), malformed('acceptance_outcome_digest_mismatch'));
scenario('C09-b-eip712', baseInputs('eip712', { outcome: utf8('not the report') }), malformed('acceptance_outcome_digest_mismatch'));
scenario('C09-ok-eip712', baseInputs('eip712', { outcome: OUTCOME }), VERIFIED);
// AR-C10
scenario('C10-a-eip712', baseInputs('eip712', { subject: receiptB.text }), malformed('acceptance_record_digest_mismatch'));
scenario('C10-b-jws', baseInputs('jws', { record: recordJws(bodyJws({ contextId: '0x' + HB })) }), malformed('acceptance_record_digest_mismatch'));
// AR-C11, AR-C12
scenario('C11-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ issuedAt: t0 - 1 }), BUYERk) }), malformed('acceptance_precedes_outcome'));
scenario('C12-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ issuedAt: t0, disposition: 'rejected' }), BUYERk) }), { ...VERIFIED, disposition: 'rejected' });
// AR-C13
scenario('C13-jws', baseInputs('jws', { record: recordJws(bodyJws({ termsDigest: TA2, outcomeDigest: '0xabc' })) }), malformed('acceptance_member_invalid', 'acceptance_terms_digest_mismatch'));
// AR-C14
scenario('C14-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ termsDigest: TA2 }), BUYERk, digestFor(bodyEip712())) }), malformed('signature_invalid'));
// AR-C15
{
  const body = bodyEip712();
  const message = buildAcceptanceMessage(checkBody(parseStrictJson(utf8(JSON.stringify(body)))!))!;
  const withChain = hashTypedData({ domain: { name: 'x402 acceptance', version: '0', chainId: 84532n }, types: { ...ACCEPTANCE_TYPES, EIP712Domain: [...ACCEPTANCE_TYPES.EIP712Domain, { name: 'chainId', type: 'uint256' }] }, primaryType: 'Acceptance', message });
  scenario('C15-a-eip712', baseInputs('eip712', { record: recordEip712(body, BUYERk, withChain) }), malformed('signature_invalid'));
  const v1 = hashTypedData({ domain: { name: 'x402 acceptance', version: '1' }, types: ACCEPTANCE_TYPES, primaryType: 'Acceptance', message });
  scenario('C15-b-eip712', baseInputs('eip712', { record: recordEip712(body, BUYERk, v1) }), malformed('signature_invalid'));
  const sorted = hashTypedData({ domain: { name: 'x402 acceptance', version: '0' }, types: { ...ACCEPTANCE_TYPES, Acceptance: [...ACCEPTANCE_TYPES.Acceptance].sort((a, b) => a.name.localeCompare(b.name)) }, primaryType: 'Acceptance', message });
  scenario('C15-c-eip712', baseInputs('eip712', { record: recordEip712(body, BUYERk, sorted) }), malformed('signature_invalid'));
  const other = bodyEip712({ signer: `eip155:8453:${BUYER}`, confirmingParty: `eip155:8453:${BUYER}` });
  const base = baseInputs('eip712', { record: recordEip712(other, BUYERk, digestFor(body)) });
  (base.chain as unknown[]).push({ chainId: 8453, block: 1, account: BUYER, code: false });
  scenario('C15-d-eip712', base, malformed('signature_invalid'));
}
// AR-C16 (EIP-712 encodings)
{
  const env = JSON.parse(recordEip712(bodyEip712(), BUYERk)) as { signature: string; payload: Raw; format: string };
  const sig = env.signature;
  const n = secp256k1.Point.CURVE().n;
  const s = BigInt('0x' + sig.slice(66, 130));
  const v = Number.parseInt(sig.slice(130), 16);
  const highS = sig.slice(0, 66) + (n - s).toString(16).padStart(64, '0') + (v === 27 ? '1c' : '1b');
  scenario('C16-a-eip712', baseInputs('eip712', { record: JSON.stringify({ ...env, signature: highS }) }), malformed('signature_invalid'));
  scenario('C16-b-eip712', baseInputs('eip712', { record: JSON.stringify({ ...env, signature: sig.slice(0, 130) + (v - 27).toString(16).padStart(2, '0') }) }), malformed('signature_invalid'));
  const yParity = BigInt(v - 27);
  const compact = sig.slice(0, 66) + ((yParity << 255n) | s).toString(16).padStart(64, '0');
  scenario('C16-c-eip712', baseInputs('eip712', { record: JSON.stringify({ ...env, signature: compact }) }), malformed('signature_invalid'));
  scenario('C16-d-eip712', baseInputs('eip712', { record: JSON.stringify({ ...env, signature: '0x' + sig.slice(2).toUpperCase() }) }), malformed('signature_invalid'));
  const base = baseInputs('eip712');
  (base.chain as Raw[])[0] = { chainId: 84532, block: 1000, account: BUYER, code: true, calls: [walletCall(bodyEip712(), sig, { returns: '0xffffffff' + '00'.repeat(28) })] };
  scenario('C16-j-eip712', base, malformed('signature_invalid'));
}
// AR-C17 and the contract-account AR-C16 and AR-C18 variants
{
  const bodyW = bodyEip712({ contextId: '0x' + HC, subject: { profile: 'x402ev/1', reference: EC }, signer: `eip155:84532:${WALLET}`, confirmingParty: `eip155:84532:${WALLET}` });
  const sigW = '0x' + bytesToHex(sha256('wallet signature'));
  const envW = JSON.stringify({ format: 'eip712', payload: bodyW, signature: sigW });
  const withWallet = (call: Raw | null, over: Raw = {}) => {
    const base = baseInputs('eip712', { record: envW, subject: receiptC.text, ...over });
    if (call) (base.chain as unknown[]).push({ chainId: 84532, block: 1000, account: WALLET, code: true, calls: [call] });
    return base;
  };
  scenario('C17-a-eip712', withWallet(walletCall(bodyW, sigW, { returns: MAGIC })), VERIFIED);
  scenario('C17-b-eip712', withWallet(walletCall(bodyW, sigW, { returns: '0x1626ba7e' + '00'.repeat(60) })), VERIFIED);
  scenario('C16-e-eip712', withWallet(walletCall(bodyW, sigW, { returns: '0xffffffff' + '00'.repeat(28) })), malformed('signature_invalid'));
  scenario('C16-k-eip712', withWallet(walletCall(bodyW, sigW, { revert: true })), malformed('signature_invalid'));
  scenario('C16-l-eip712', withWallet(walletCall(bodyW, sigW, { returns: MAGIC }), { record: JSON.stringify({ format: 'eip712', payload: bodyW, signature: '0x' + sigW.slice(2).toUpperCase() }) }), malformed('signature_invalid'));
  scenario('C16-m-eip712', withWallet(walletCall(bodyW, sigW, { returns: '0x1626ba7e' + '00'.repeat(27) })), malformed('signature_invalid'));
  scenario('C18-a-eip712', withWallet(null), unresolved('chain_state_unavailable', false));
  scenario('C18-b-eip712', withWallet(walletCall(bodyW, sigW, { returns: MAGIC }), { contractAccounts: false }), unresolved('contract_accounts_unsupported', false));
  const body8453 = { ...bodyW, signer: `eip155:8453:${WALLET}`, confirmingParty: `eip155:8453:${WALLET}` };
  scenario('C18-c-eip712', withWallet(walletCall(bodyW, sigW, { returns: MAGIC }), { record: JSON.stringify({ format: 'eip712', payload: body8453, signature: sigW }) }), unresolved('chain_state_unavailable', false));
  const d = withWallet(null); (d.trust as Raw).complete = true;
  scenario('C18-d-eip712', d, unresolved('chain_state_unavailable', false));
  scenario('C18-nocall-eip712', (() => { const b = withWallet(null); (b.chain as unknown[]).push({ chainId: 84532, block: 1000, account: WALLET, code: true, calls: [] }); return b; })(), unresolved('chain_state_unavailable', false));
  scenario('C22-b-eip712', withWallet(walletCall({ ...bodyW, confirmingParty: 'did:web:acme.example' }, sigW, { returns: MAGIC }), { record: JSON.stringify({ format: 'eip712', payload: { ...bodyW, confirmingParty: 'did:web:acme.example' }, signature: sigW }) }), unknown());
}
// AR-C16 (JWS encodings)
{
  const env = JSON.parse(recordJws(bodyJws())) as { signature: string };
  const [h, p, s] = env.signature.split('.');
  const sigBytes = b64uDecode(s)!;
  const flipped = new Uint8Array(sigBytes); flipped[5] ^= 0x10;
  scenario('C16-f-jws', baseInputs('jws', { record: JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(flipped)}` }) }), malformed('signature_invalid'));
  const plusL = concat(sigBytes.subarray(0, 32), le(fromLe(sigBytes.subarray(32)) + L));
  scenario('C16-g-jws', baseInputs('jws', { record: JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(plusL)}` }) }), malformed('signature_invalid'));
  const msg = utf8(`${h}.${p}`);
  const a = secretScalar(KB);
  const id = new Uint8Array(32); id[0] = 1;
  const kH = mod(fromLe(sha512(concat(id, KBpub, msg))), L);
  scenario('C16-h-jws', baseInputs('jws', { record: JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(concat(id, le(mod(kH * a, L))))}` }) }), malformed('signature_invalid'));
  const r = 987654321n;
  const Rp = Point.BASE.multiply(r).add(T8).toBytes();
  const kI = mod(fromLe(sha512(concat(Rp, KBpub, msg))), L);
  scenario('C16-i-jws', baseInputs('jws', { record: JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(concat(Rp, le(mod(r + kI * a, L))))}` }) }), malformed('signature_invalid'));
}
// AR-C19
{
  const complete = (over: Raw) => { const b = baseInputs('jws', over); (b.trust as Raw).complete = true; return b; };
  scenario('C19-a-jws', complete({ record: recordJws(bodyJws(), KX, { alg: 'EdDSA', kid: 'cp-2', typ: 'x402-acceptance+jws' }) }), unresolved('key_missing', true));
  scenario('C19-b-jws', complete({ record: recordJws(bodyJws({ signer: 'did:example:other', confirmingParty: 'did:example:other' })) }), unresolved('signer_mismatch', true));
  scenario('C19-c-jws', complete({ record: recordJws({ ...bodyJws(), reason: 'late' }, KX, { alg: 'EdDSA', kid: 'cp-2', typ: 'x402-acceptance+jws' }) }), unresolved('key_missing', true));
  const notDeclared = baseInputs('jws', { record: recordJws(bodyJws(), KX, { alg: 'EdDSA', kid: 'cp-2', typ: 'x402-acceptance+jws' }) });
  scenario('C19-nodecl-jws', notDeclared, unresolved('key_missing', false));
}
// AR-C20
{
  const refused = (key: Uint8Array, record: string) => { const b = baseInputs('jws', { record }); (b.trust as Raw).complete = 'true'; ((b.trust as Raw).keys as Raw[])[0].key = b64uEncode(key); return b; };
  const id = new Uint8Array(32); id[0] = 1;
  const [h, p] = (JSON.parse(recordJws(bodyJws())) as { signature: string }).signature.split('.');
  scenario('C20-a-jws', refused(id, JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(new Uint8Array(64).map((_, i) => (i === 0 ? 1 : 0)))}` })), unresolved('key_refused', false));
  scenario('C20-b-jws', refused(Point.fromBytes(KBpub).add(T8).toBytes(), recordJws(bodyJws())), unresolved('key_refused', false));
  scenario('C20-c-jws', refused(le(2n ** 255n - 19n + fromLe(KBpub.subarray(0, 1))), recordJws(bodyJws())), unresolved('key_refused', false));
}
// AR-C21
{
  scenario('C21-a-jws', baseInputs('jws', { record: recordJws(bodyJws(), KB, { alg: 'EdDSA', kid: 'cp-1', typ: 'JWT' }) }), malformed('acceptance_member_invalid'));
  scenario('C21-b-jws', baseInputs('jws', { record: recordJws(bodyJws(), KB, { ...JWS_HEADER, cty: 'json' }) }), malformed('acceptance_member_invalid'));
  scenario('C21-c-jws', baseInputs('jws', { record: recordJws(bodyJws(), KB, { alg: 'ES256K', kid: 'cp-1', typ: 'x402-acceptance+jws' }) }), malformed('acceptance_member_invalid'));
  scenario('C21-d-jws', baseInputs('jws', { record: recordJws(bodyJws(), KB, JWS_HEADER, jcs(bodyJws()).replace(/":/g, '": ')) }), malformed('acceptance_member_invalid'));
  const arr = JSON.parse(recordJws(bodyJws(), KB, JWS_HEADER, '[1,2]')) as { signature: string };
  const [h, p, s] = arr.signature.split('.');
  const flipped = b64uDecode(s)!; flipped[0] ^= 1;
  scenario('C21-e-jws', baseInputs('jws', { record: JSON.stringify({ format: 'jws', signature: `${h}.${p}.${b64uEncode(flipped)}` }) }), malformed('acceptance_member_invalid'));
  scenario('C21-f-jws', baseInputs('jws', { record: recordJws(bodyJws(), KB, '{"alg":"EdDSA","alg":"EdDSA","kid":"cp-1","typ":"x402-acceptance+jws"}') }), malformed('acceptance_member_invalid'));
  const good = (JSON.parse(recordJws(bodyJws())) as { signature: string }).signature;
  const last = good[good.length - 1];
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  // 64 bytes -> 86 chars, 4 unused bits in the last char: set the lowest unused bit
  const bumped = good.slice(0, -1) + alphabet[alphabet.indexOf(last) | 1];
  check('C21-g: bumped signature decodes to the same bytes leniently', Buffer.from(bumped.split('.')[2], 'base64url').equals(Buffer.from(good.split('.')[2], 'base64url')));
  scenario('C21-g-jws', baseInputs('jws', { record: JSON.stringify({ format: 'jws', signature: bumped }) }), malformed('acceptance_member_invalid'));
}
// AR-C22
scenario('C22-a-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ signer: `eip155:84532:${OTHER}`, confirmingParty: `eip155:84532:${OTHER}` }), OTHERk) }), unknown());
scenario('C22-e-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ authority: { mode: 'direct', profile: 'payer/1', reference: '' } }), BUYERk) }), unknown());
scenario('C22-f-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ authority: { mode: 'declared', profile: 'payer/0', reference: '' } }), BUYERk) }), unknown());
scenario('C22-g-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ authority: { mode: 'direct', profile: 'payer/0', reference: 'x' } }), BUYERk) }), unknown());
scenario('C22-h-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ confirmingParty: 'did:web:acme.example' }), BUYERk) }), unknown());
{
  const c = baseInputs('jws'); (c.trust as Raw).authority = [];
  scenario('C22-c-jws', c, unknown());
  const d = baseInputs('jws'); ((d.trust as Raw).authority as Raw[])[0].subjectReference = receiptB.evidenceRef;
  scenario('C22-d-jws', d, unknown());
}
// AR-C23
scenario('C23-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ subject: { profile: 'other/9', reference: EA } }), BUYERk) }), unknown('profile_unavailable'));
scenario('C23-jws', baseInputs('jws', { record: recordJws(bodyJws({ subject: { profile: 'other/9', reference: EA } })) }), unknown('profile_unavailable'));
// AR-C24
scenario('C24-a-eip712', baseInputs('eip712', { terms: [] }), unknown('evidence_unavailable'));
scenario('C24-b-jws', baseInputs('jws', { subject: null }), unknown('evidence_unavailable'));
scenario('C24-c-eip712', baseInputs('eip712', { subject: receiptA.text.replace('"latencyMs":42', '"latencyMs":43') }), unknown('evidence_unavailable'));
scenario('C24-d-jws', baseInputs('jws', { terms: [offerJws(offerPayload({ amount: '20000' }))] }), unknown('evidence_unavailable'));
scenario('C24-e-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ deliveryIssuer: 'did:web:other.example' }), BUYERk) }), unknown('evidence_unavailable'));
scenario('C24-f-jws', baseInputs('jws', { terms: [offerJws(offerPayload(), KX)] }), unknown('evidence_unavailable'));
scenario('C24-g-eip712', baseInputs('eip712', { terms: [offerEip712(offerPayload({ validUntil: 0 }), UNLISTEDk)] }), unknown('evidence_unavailable'));
{
  const upper = receipt((i) => { (i.delivery as Raw).contentDigest = 'sha256:' + DA.toUpperCase(); });
  scenario('C24-h-eip712', baseInputs('eip712', { record: recordEip712(bodyEip712({ contextId: '0x' + upper.hex, subject: { profile: 'x402ev/1', reference: upper.evidenceRef }, outcomeDigest: '0x' + DA.toUpperCase() }), BUYERk, digestFor(bodyEip712())) }), malformed('acceptance_member_invalid'));
  scenario('C24-h-jws', baseInputs('jws', { record: recordJws(bodyJws({ contextId: '0x' + upper.hex, subject: { profile: 'x402ev/1', reference: upper.evidenceRef } })), subject: upper.text }), unknown('evidence_unavailable'));
  const info = JSON.parse(receiptA.text) as { signer: { signature: string } };
  const sig = b64uDecode(info.signer.signature.slice('base64url:'.length))!;
  info.signer.signature = 'base64url:' + b64uEncode(concat(sig.subarray(0, 32), le(fromLe(sig.subarray(32)) + L)));
  scenario('C24-i-eip712', baseInputs('eip712', { subject: JSON.stringify(info) }), unknown('evidence_unavailable'));
  const resigned = receipt(() => {}, KX, KXpub);
  scenario('C24-j-jws', baseInputs('jws', { record: recordJws(bodyJws({ contextId: '0x' + resigned.hex, subject: { profile: 'x402ev/1', reference: resigned.evidenceRef } })), subject: resigned.text }), unknown('evidence_unavailable'));
  const expired = offerJws(offerPayload({ validUntil: t0 - 1 }));
  scenario('C24-expired-jws', baseInputs('jws', { terms: [expired] }), unknown('evidence_unavailable'));
}
// AR-C25 (lexical forms, EIP-712 envelope text edited after signing; JWS payload text)
{
  const env = recordEip712(bodyEip712(), BUYERk);
  const edit = (from: string, to: string) => { if (!env.includes(from)) throw new Error(`fixture lacks ${from}`); return env.replace(from, to); };
  scenario('C25-b-eip712', baseInputs('eip712', { record: edit(`"issuedAt":${t0 + 600}`, `"issuedAt":"${t0 + 600}"`) }), malformed('acceptance_member_invalid'));
  scenario('C25-c-eip712', baseInputs('eip712', { record: edit('"disposition":"accepted"', '"disposition":"accepted","disposition":"accepted"') }), malformed('acceptance_member_invalid'));
  scenario('C25-h-eip712', baseInputs('eip712', { record: edit(`"issuedAt":${t0 + 600}`, `"issuedAt":${t0 + 600}.0`) }), malformed('acceptance_member_invalid'));
  scenario('C25-i-eip712', baseInputs('eip712', { record: edit(`"issuedAt":${t0 + 600}`, '"issuedAt":1.7915006e9') }), malformed('acceptance_member_invalid'));
  scenario('C25-j-eip712', baseInputs('eip712', { record: edit(`"issuedAt":${t0 + 600}`, `"issuedAt":0${t0 + 600}`) }), malformed('acceptance_member_invalid'));
  const withFF = concat(utf8(env.slice(0, env.indexOf('"disposition":"accepted"') + '"disposition":"'.length)), new Uint8Array([0xff]), utf8(env.slice(env.indexOf('"disposition":"accepted"') + '"disposition":"'.length)));
  scenario('C25-k-eip712', baseInputs('eip712', { record: withFF }), malformed('acceptance_member_invalid'));
  scenario('C25-m-eip712', baseInputs('eip712', { record: edit(`"issuedAt":${t0 + 600}`, '"issuedAt":9007199254740992') }), malformed('acceptance_member_invalid'));
  scenario('C25-n-eip712', baseInputs('eip712', { record: edit('"disposition":"accepted"', '"disposition":"\\ud800accepted"') }), malformed('acceptance_member_invalid'));
  const payload = jcs(bodyJws());
  const jedit = (from: string, to: string) => { if (!payload.includes(from)) throw new Error(`fixture lacks ${from}`); return recordJws(bodyJws(), KB, JWS_HEADER, payload.replace(from, to)); };
  scenario('C25-b-jws', baseInputs('jws', { record: jedit(`"issuedAt":${t0 + 600}`, `"issuedAt":"${t0 + 600}"`) }), malformed('acceptance_member_invalid'));
  scenario('C25-c-jws', baseInputs('jws', { record: jedit('"disposition":"accepted"', '"disposition":"accepted","disposition":"accepted"') }), malformed('acceptance_member_invalid'));
  scenario('C25-h-jws', baseInputs('jws', { record: jedit(`"issuedAt":${t0 + 600}`, `"issuedAt":${t0 + 600}.0`) }), malformed('acceptance_member_invalid'));
  scenario('C25-j-jws', baseInputs('jws', { record: jedit(`"issuedAt":${t0 + 600}`, `"issuedAt":0${t0 + 600}`) }), malformed('acceptance_member_invalid'));
  scenario('C25-m-jws', baseInputs('jws', { record: jedit(`"issuedAt":${t0 + 600}`, '"issuedAt":9007199254740992') }), malformed('acceptance_member_invalid'));
  scenario('C25-n-jws', baseInputs('jws', { record: jedit('"disposition":"accepted"', '"disposition":"\\ud800accepted"') }), malformed('acceptance_member_invalid'));
}

// ------------------------------------------------------------------ run the scenarios
for (const s of scenarios) {
  let actual: Output | null = null;
  let error: string | null = null;
  try { actual = verify(toInputs(s.inputs)); } catch (e) { error = (e as Error).message; }
  const diffs = actual ? compareOutput(s.expect, actual) : [`threw: ${error}`];
  check(`scenario ${s.id}`, diffs.length === 0, { expected: s.expect, actual, diffs });
}

// ------------------------------------------------------------------ the runner's own helpers
{
  const encoded = { record: b64uEncode(utf8('{}')), subject: null, terms: [b64uEncode(utf8('x'))], trust: {}, chain: [] };
  const d = decodeInputs(encoded);
  check('runner: decodeInputs record', bytesToHex(d.record!) === bytesToHex(utf8('{}')));
  check('runner: decodeInputs defaults', d.subject === null && d.contractAccounts === true && d.outcome === undefined && d.terms.length === 1);
  check('runner: decodeInputs rejects padding', (() => { try { decodeInputs({ ...encoded, record: 'e30=' }); return false; } catch { return true; } })());
  const out: Output = { result: 'unknown', conditions: ['acceptance_authority_unresolved'], disposition: 'accepted' };
  check('runner: compare set order', compareOutput({ result: 'unknown', conditions: ['acceptance_authority_unresolved'], disposition: 'accepted' }, out).length === 0);
  check('runner: compare absent member', compareOutput({ result: 'unknown', conditions: ['acceptance_authority_unresolved'] }, out).length === 1);
  check('runner: compare missing member', compareOutput({ result: 'unknown', conditions: ['acceptance_authority_unresolved'], disposition: 'accepted', reason: 'x' }, out).length === 1);
  check('runner: compare condition set', compareOutput({ result: 'unknown', conditions: [] }, out).length === 2);
}

// ------------------------------------------------------------------ optional: a vector-shaped file for run-vectors.ts
const out = process.argv[2];
if (out) {
  const enc = (v: unknown) => (v === null || v === undefined ? null : typeof v === 'string' ? b64uEncode(utf8(v)) : b64uEncode(v as Uint8Array));
  const vectors = scenarios.map((s) => ({
    id: `SYN-${s.id}`, case: `SYN-${s.id.split('-')[0]}`, variant: s.id.split('-')[1] ?? '', form: s.id.endsWith('jws') ? 'jws' : s.id.endsWith('eip712') ? 'eip712' : 'none',
    title: 'synthetic self-test scenario', note: 'generated by checker/selftest.ts; not a published vector',
    inputs: {
      record: enc(s.inputs.record), subject: enc(s.inputs.subject), terms: ((s.inputs.terms as unknown[]) ?? []).map(enc),
      ...(s.inputs.outcome === undefined ? {} : { outcome: enc(s.inputs.outcome) }),
      trust: s.inputs.trust, chain: s.inputs.chain ?? [], ...(s.inputs.contractAccounts === undefined ? {} : { contractAccounts: s.inputs.contractAccounts }),
    },
    expect: s.expect,
  }));
  writeFileSync(out, JSON.stringify({ profile: 'synthetic self-test (not the published vectors)', vectors }, null, 1));
  console.log(`wrote ${vectors.length} synthetic vectors to ${out}`);
}

console.log(`${checks} checks, ${failures} failed`);
process.exit(failures > 0 ? 1 : 0);
