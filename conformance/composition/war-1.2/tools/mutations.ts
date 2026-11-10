// Builds envelope- and receipt-level mutations of maximusrufus's C01/C02 composition vectors, re-signing with the
// published throwaway seeds where the receipt or acceptance body changes. Output: a vectors.json-shaped bundle.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { b64uDecode, b64uEncode, jcs, utf8 } from '../../../checker/encoding.ts';

const [srcDir, out] = process.argv.slice(2);
const load = (name: string) => JSON.parse(readFileSync(`${srcDir}/${name}`, 'utf8'));
const dec = (s: string) => new TextDecoder().decode(b64uDecode(s)!);
const enc = (s: string) => b64uEncode(utf8(s));
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const seedKey = (seed: string) => createHash('sha256').update(seed).digest();
const KC = seedKey('composition-vectors/checker');
const KB = seedKey('composition-vectors/buyer');
const KP = seedKey('composition-vectors/payer');

const c01 = load('C01-valid-declared.json');
const c02 = load('C02-valid-payer.json');
const base = (v: any) => {
  const env = JSON.parse(dec(v.inputs.record));
  const [h, p] = env.signature.split('.');
  return { record: env, header: h, body: JSON.parse(dec(p)), subject: JSON.parse(dec(v.inputs.subject)), trust: structuredClone(v.inputs.trust) };
};
// sanity: seeds reproduce the listed keys
const pubB64u = (sk: Uint8Array) => b64uEncode(ed25519.getPublicKey(sk));
if (pubB64u(KC) !== c01.inputs.trust.issuers[0].keys[0].ed25519) throw new Error('checker seed mismatch');
if (pubB64u(KB) !== c01.inputs.trust.keys[0].key) throw new Error('buyer seed mismatch');
if (pubB64u(KP) !== c02.inputs.trust.keys[0].key) throw new Error('payer seed mismatch');

function signReceipt(subject: any, sk: Uint8Array) {
  const r = subject.receipt;
  const sig = ed25519.sign(utf8(jcs(r)), sk);
  subject.signature.value = Buffer.from(sig).toString('base64');
  return sha256(utf8(jcs(r)));
}
function signAcceptance(header: string, body: any, sk: Uint8Array) {
  const payload = enc(jcs(body));
  const sig = ed25519.sign(utf8(`${header}.${payload}`), sk);
  return { format: 'jws', signature: `${header}.${payload}.${b64uEncode(sig)}` };
}
/** Rebinds the acceptance to a (re-signed) subject. */
function rebind(b: ReturnType<typeof base>, sk: Uint8Array, over: Record<string, unknown> = {}) {
  const digest = signReceipt(b.subject, KC);
  const body = { ...b.body, contextId: '0x' + digest, subject: { profile: 'war/1.2', reference: 'war/1.2:sha256:' + digest },
    outcomeDigest: '0x' + b.subject.receipt.files.remediated.sha256, termsDigest: '0x' + b.subject.receipt.criteria.sha256, ...over };
  b.record = signAcceptance(b.header, body, sk);
  b.body = body;
  if (b.trust.authority) for (const a of b.trust.authority) a.subjectReference = body.subject.reference;
  return b;
}
const pack = (id: string, title: string, b: ReturnType<typeof base>, expect: unknown, subjectText?: string) => ({
  id, title, inputs: { record: enc(JSON.stringify(b.record)), subject: enc(subjectText ?? JSON.stringify(b.subject)), terms: [], trust: b.trust }, expect,
});
const unknownEvidence = { result: 'unknown', conditions: [], disposition: 'accepted', reason: 'evidence_unavailable' };
const verified = { result: 'verified', conditions: [], disposition: 'accepted' };

const vectors: unknown[] = [];
let b: ReturnType<typeof base>;

b = base(c01); b.subject.signature.value = b.subject.signature.value.replace(/=+$/, '');
vectors.push(pack('C81-signature-value-unpadded', 'signature.value with its = padding removed (section 3.2 item 6: canonical padded base64)', b, unknownEvidence));

b = base(c01); b.trust.issuers[0].keys.push({ ...b.trust.issuers[0].keys[0] });
vectors.push(pack('C82-issuer-key-listed-twice', 'trust.issuers lists the checker key twice under ck-1 (item 4: exactly one entry)', b, unknownEvidence));

b = base(c01); b.trust.issuers[0].keys[0].kid = 'ck-2';
vectors.push(pack('C83-issuer-kid-differs', 'trust.issuers lists the checker key under ck-2 while receipt.key_id is ck-1 (item 4)', b, unknownEvidence));

b = base(c01); b.subject.extra = 1;
vectors.push(pack('C84-envelope-extra-member', 'An unsigned extra member in the envelope (item 1: "has the members of W3.1"; extras unspecified)', b, verified));

b = base(c01); delete b.subject.timestamp;
vectors.push(pack('C85-envelope-without-timestamp', 'Envelope without the timestamp member (item 1; W3.1 lists it)', b, verified));

b = base(c01);
const reordered = JSON.stringify({ timestamp: b.subject.timestamp, signature: b.subject.signature, receipt: Object.fromEntries(Object.entries(b.subject.receipt).reverse()) }, null, 3);
vectors.push(pack('C86-subject-reserialized', 'The same envelope with members reordered and indented (section 3.1: byte form not significant)', b, verified, reordered));

b = base(c01); b.subject.signature.key_id = 'ck-2';
vectors.push(pack('C87-envelope-key-id-differs', 'signature.key_id ck-2 while receipt.key_id is ck-1 (item 3)', b, unknownEvidence));

b = base(c01); b.subject.receipt.issued_utc = '2026-06-01T12:00:00.0001Z'; rebind(b, KB);
vectors.push(pack('C88-issued-utc-four-digit-fraction', 'issued_utc with a four-digit fraction, re-signed (item 7: form of W7.3 step 6)', b, unknownEvidence));

b = base(c01); b.subject.receipt.issued_utc = '2026-06-01T12:00:00.000Z'; rebind(b, KB);
vectors.push(pack('C89-issued-utc-zero-fraction-equal', 'issued_utc 12:00:00.000Z with issuedAt at that second, re-signed (section 3.4: only a non-zero fraction rounds up)', b, verified));

b = base(c02); delete b.subject.receipt.payment; rebind(b, KP);
vectors.push(pack('C90-payer-authority-without-payment', 'C02 with receipt.payment removed, re-signed; payer/0 has no payer to resolve to (section 3.4, AR-31)', b, { result: 'unknown', conditions: ['acceptance_authority_unresolved'], disposition: 'accepted' }));

b = base(c01); b.subject.receipt.criteria.sha256 = b.subject.receipt.criteria.sha256.toUpperCase(); rebind(b, KB, { termsDigest: '0x' + b.subject.receipt.criteria.sha256.toLowerCase() });
vectors.push(pack('C91-criteria-digest-uppercase', 'criteria.sha256 in upper-case hex, re-signed; termsDigest carries the lowercase digest (item 7: form failure is unavailability, NOTES 4)', b, unknownEvidence));

b = base(c01); b.subject.receipt.schema = 'trilatic.acceptance-receipt/1.1'; rebind(b, KB);
vectors.push(pack('C92-schema-1-1', 'receipt.schema names schema 1.1, re-signed (item 2)', b, unknownEvidence));

b = base(c01); b.subject.receipt.parties.checker.key_id = 'ck-2'; rebind(b, KB);
vectors.push(pack('C93-checker-party-key-id-differs', 'parties.checker.key_id ck-2 while receipt.key_id and signature.key_id are ck-1, re-signed (item 3)', b, unknownEvidence));

writeFileSync(out, JSON.stringify({
  profile: 'war/1.2 mutations of C01/C02 (CNS Labs, 2026-11-09); expectations are our reading of COMPOSITION.md at 8ce7f42',
  license: 'CC0-1.0',
  derivedFrom: { repository: 'https://github.com/maximusrufus/work-acceptance-record', commit: '8ce7f42', path: 'composition/vectors', files: ['C01-valid-declared.json', 'C02-valid-payer.json'], author: 'maximusrufus', license: 'CC0-1.0' },
  vectors,
}, null, 1) + '\n');
for (const v of vectors as any[]) writeFileSync(`${out.replace(/[^/]+$/, '')}split/${v.id}.json`, JSON.stringify(v, null, 1) + '\n');
console.log(`${vectors.length} mutations written`);
