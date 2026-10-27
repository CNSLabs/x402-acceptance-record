// The 25 cases of CASES.md: each variant, in each form the row names, as one vector.
// Expected outputs are typed here from the rows; nothing is read back from a checker.
import * as F from './fixtures.ts';
import { type Body, ACCEPTANCE_TYPES, withHighS, withRawV, compact2098, upperHex, checksum } from './eip712.ts';
import { utf8, jcs, b64u, concat, sha256, sha256hex } from './util.ts';
import { edSign, forgeIdentityR, forgeMixedR, mixedOrderKey, signForMixedKey, withSPlusL, flipByte, IDENTITY_ENCODING, NON_CANONICAL_IDENTITY } from './ed.ts';
import { secp256k1 } from '@noble/curves/secp256k1.js';

export type Form = 'eip712' | 'jws';
export type Expect = { result: string; conditions: string[]; disposition?: string; reason?: string; policy_refusal?: boolean };
export type Inputs = {
  record: string | null; subject: string | null; terms: string[]; outcome?: string;
  trust: F.Trust; chain: F.ChainEntry[]; contractAccounts: boolean;
};
export type Vector = {
  id: string; case: string; variant: string; form: Form | 'none'; title: string; note: string;
  inputs: Inputs; expect: Expect; statementId?: string;
};

export const TITLES: Record<string, string> = {
  'AR-C01': 'Baseline acceptance',
  'AR-C02': 'A later dispute leaves an earlier acceptance as it was',
  'AR-C03': 'No record',
  'AR-C04': 'Signed not_responded',
  'AR-C05': 'Record not closed or not in the stated shape',
  'AR-C06': 'Confirming party absent',
  'AR-C07': 'Signer is the delivery issuer',
  'AR-C08': "Terms differ from the seller's offer",
  'AR-C09': 'Outcome differs from the receipt',
  'AR-C10': 'Acceptance presented against another delivery',
  'AR-C11': 'Acceptance before the outcome',
  'AR-C12': 'Rejection in the same second as the outcome',
  'AR-C13': 'All conditions reported; a dependent check skipped',
  'AR-C14': 'Signature checked before bindings',
  'AR-C15': 'Signed under another domain, type or chain',
  'AR-C16': 'Signature encodings refused',
  'AR-C17': 'Contract account',
  'AR-C18': 'Contract account not resolvable',
  'AR-C19': 'JWS key absent from a complete trust input',
  'AR-C20': 'Refused Ed25519 keys',
  'AR-C21': 'JWS header or payload not in the profile',
  'AR-C22': 'Valid signature, authority not established',
  'AR-C23': 'Unknown subject profile',
  'AR-C24': 'Evidence unavailable',
  'AR-C25': 'Numbers and text not in the stated encoding',
};

const MI = 'acceptance_member_invalid';
const VERIFIED = (d: string): Expect => ({ result: 'verified', conditions: [], disposition: d });
const MALFORMED = (...c: string[]): Expect => ({ result: 'malformed', conditions: c });
const KEY_UNRESOLVED = (reason: string, policy: boolean): Expect => ({ result: 'key_unresolved', conditions: [], reason, policy_refusal: policy });
const UNKNOWN = (reason: string, d: string): Expect => ({ result: 'unknown', conditions: [], reason, disposition: d });
const UNKNOWN_AUTH = (d: string): Expect => ({ result: 'unknown', conditions: ['acceptance_authority_unresolved'], disposition: d });
const NO_RECORD: Expect = { result: 'no_record', conditions: [] };

type Over = {
  body?: Body; record?: Uint8Array | null; subject?: Uint8Array | null; terms?: Uint8Array[]; outcome?: Uint8Array;
  trust?: F.Trust; chain?: F.ChainEntry[]; contractAccounts?: boolean;
};
const baseBody = (form: Form) => (form === 'eip712' ? F.bodyE() : F.bodyJ());
const sign = (form: Form, body: Body) => (form === 'eip712' ? F.eipRecord(body).text : F.jwsRecord(body).text);

function inputs(form: Form, o: Over = {}): Inputs {
  const body = o.body ?? baseBody(form);
  const record = o.record === undefined ? sign(form, body) : o.record;
  return {
    record: record === null ? null : b64u(record),
    subject: o.subject === undefined ? b64u(F.RECEIPT_A.text) : o.subject === null ? null : b64u(o.subject),
    terms: (o.terms ?? [F.OFFER_A.text]).map(b64u),
    ...(o.outcome ? { outcome: b64u(o.outcome) } : {}),
    trust: o.trust ?? F.trustBase(),
    chain: o.chain ?? F.chainBase(),
    contractAccounts: o.contractAccounts ?? true,
  };
}

const text = (b: Uint8Array) => Buffer.from(b).toString('utf8');
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const ACME = 'did:web:acme.example';

export function buildVectors(): Vector[] {
  const out: Vector[] = [];
  const add = (c: string, variant: string, form: Form | 'none', note: string, inp: Inputs, expect: Expect, body?: Body) => {
    out.push({ id: `${c}-${variant}-${form}`, case: c, variant, form, title: TITLES[c], note, inputs: inp, expect, ...(body ? { statementId: F.statementId(body) } : {}) });
  };
  const both = (fn: (form: Form) => void) => { fn('eip712'); fn('jws'); };
  const baselineE = F.eipRecord(F.bodyE());
  const baselineJ = F.jwsRecord(F.bodyJ());

  // AR-C01 Baseline acceptance
  both((f) => add('AR-C01', 'a', f, 'None.', inputs(f), VERIFIED('accepted'), baseBody(f)));
  both((f) => add('AR-C01', 'b', f, 'terms holds Offer A2 (validUntil t0 + 7200) and then Offer A; the record is unchanged.',
    inputs(f, { terms: [F.OFFER_A2.text, F.OFFER_A.text] }), VERIFIED('accepted'), baseBody(f)));
  {
    const b = F.bodyE();
    b.authority = { mode: 'declared', profile: 'declared-evidence/0', reference: '' };
    const trust = F.trustBase();
    trust.authority.push({ confirmingParty: b.confirmingParty, signer: b.signer, subjectProfile: 'x402ev/1', subjectReference: F.EA });
    add('AR-C01', 'c', 'eip712', 'EIP-712 body with authority declared-evidence/0; trust.authority gains the matching entry for BUYER.',
      inputs('eip712', { body: b, trust }), VERIFIED('accepted'), b);
  }
  both((f) => {
    const b = baseBody(f);
    b.termsDigest = F.OFFER_A0_712_SELLER.digest;
    const trust = F.trustBase();
    trust.issuers[0].keys.push({ address: F.SELLER });
    add('AR-C01', 'd', f, 'terms holds only Offer A in EIP-712 form with validUntil 0, signed by SELLER, listed for the seller in this variant; termsDigest is that payload\'s digest.',
      inputs(f, { body: b, terms: [F.OFFER_A0_712_SELLER.text], trust }), VERIFIED('accepted'), b);
  });

  // AR-C02 A later dispute leaves an earlier acceptance as it was
  add('AR-C02', 'record-A', 'eip712', 'The baseline record, verified on its own.', inputs('eip712'), VERIFIED('accepted'), F.bodyE());
  {
    const d = F.bodyE(); d.disposition = 'disputed'; d.issuedAt = F.t0 + 900;
    add('AR-C02', 'record-D', 'eip712', 'Record D: the baseline body with disposition disputed and issuedAt t0 + 900, verified on its own.', inputs('eip712', { body: d }), VERIFIED('disputed'), d);
  }

  // AR-C03 No record
  add('AR-C03', 'a', 'none', 'record absent.', inputs('eip712', { record: null }), NO_RECORD);

  // AR-C04 Signed not_responded
  both((f) => { const b = baseBody(f); b.disposition = 'not_responded'; add('AR-C04', 'a', f, 'disposition "not_responded".', inputs(f, { body: b }), MALFORMED(MI), b); });

  // AR-C05 Record not closed or not in the stated shape
  both((f) => {
    const b = baseBody(f);
    const extra = utf8(jcs({ ...b, reason: 'late' }));
    const rec = f === 'eip712' ? F.eipRecord(b, { bodyBytes: extra }).text : F.jwsRecord(b, { payloadBytes: extra }).text;
    add('AR-C05', 'a', f, 'Extra body member "reason": "late"; validly signed.', inputs(f, { record: rec }), MALFORMED(MI));
  });
  both((f) => {
    const b = baseBody(f);
    const extra = utf8(jcs({ ...b, subject: { ...b.subject, uri: 'https://seller.example/report' } }));
    const rec = f === 'eip712' ? F.eipRecord(b, { bodyBytes: extra }).text : F.jwsRecord(b, { payloadBytes: extra }).text;
    add('AR-C05', 'd', f, 'subject gains member "uri"; validly signed.', inputs(f, { record: rec }), MALFORMED(MI));
  });
  both((f) => {
    const b = baseBody(f);
    const rec = f === 'eip712' ? F.eipRecord(b, { envelopeExtra: ',"hint":"x"' }).text : F.jwsRecord(b, { envelopeExtra: ',"hint":"x"' }).text;
    add('AR-C05', 'e', f, 'The envelope gains member "hint".', inputs(f, { record: rec }), MALFORMED(MI));
  });
  both((f) => {
    const b = { ...baseBody(f), version: 1 };
    const rec = f === 'eip712' ? F.eipRecord(b, { signature: baselineE.signature }).text : F.jwsRecord(b).text;
    add('AR-C05', 'l', f, 'version 1. EIP-712: the typed message cannot be built, so the baseline signature is carried unchanged.', inputs(f, { record: rec }), MALFORMED(MI));
  });
  {
    const b = F.bodyE(); b.signer = F.eip155(F.CHAIN_ID, checksum(F.BUYER));
    add('AR-C05', 'f', 'eip712', 'signer with its address in EIP-55 mixed case, confirmingParty unchanged; baseline signature unchanged.', inputs('eip712', { record: F.eipRecord(b, { signature: baselineE.signature }).text }), MALFORMED(MI));
  }
  {
    const b = F.bodyE(); b.signer = `eip155:${F.CHAIN_ID}:0x${'0'.repeat(40)}`;
    add('AR-C05', 'g', 'eip712', 'signer is the zero address, with the baseline 65-byte signature.', inputs('eip712', { record: F.eipRecord(b, { signature: baselineE.signature }).text }), MALFORMED(MI));
  }
  {
    const b = F.bodyE(); b.signer = `eip155:0${F.CHAIN_ID}:${F.BUYER}`; b.confirmingParty = b.signer;
    add('AR-C05', 'o', 'eip712', 'signer and confirmingParty eip155:084532:BUYER (leading zero); baseline signature unchanged.', inputs('eip712', { record: F.eipRecord(b, { signature: baselineE.signature }).text }), MALFORMED(MI));
  }
  {
    const b = F.bodyE(); b.signer = `eip155:0:${F.BUYER}`; b.confirmingParty = b.signer;
    add('AR-C05', 'p', 'eip712', 'signer and confirmingParty eip155:0:BUYER; baseline signature unchanged.', inputs('eip712', { record: F.eipRecord(b, { signature: baselineE.signature }).text }), MALFORMED(MI));
  }

  // AR-C06 Confirming party absent
  both((f) => { const b = baseBody(f); b.confirmingParty = ''; add('AR-C06', 'a', f, 'confirmingParty "".', inputs(f, { body: b }), MALFORMED('confirming_party_absent'), b); });

  // AR-C07 Signer is the delivery issuer
  {
    const trust = F.trustBase();
    trust.keys.push({ kid: 'cp-9', signer: F.BUYER_DID, key: F.KS_B64 });
    const rec = F.jwsRecord(F.bodyJ(), { seed: F.SEED.ks, headerBytes: utf8('{"alg":"EdDSA","kid":"cp-9","typ":"x402-acceptance+jws"}') });
    add('AR-C07', 'a', 'jws', 'trust.keys gains {cp-9, did:example:buyer, KS}; the record\'s header kid is cp-9 and it is signed with KS, the issuer\'s key.', inputs('jws', { record: rec.text, trust }), MALFORMED('acceptance_signer_is_issuer'), F.bodyJ());
  }
  {
    const b = F.bodyJ(); b.signer = F.SELLER_DID; b.confirmingParty = F.SELLER_DID;
    const trust = F.trustBase();
    trust.keys[0].signer = F.SELLER_DID;
    trust.authority = [{ confirmingParty: F.SELLER_DID, signer: F.SELLER_DID, subjectProfile: 'x402ev/1', subjectReference: F.EA }];
    add('AR-C07', 'b', 'jws', 'Body signer and confirmingParty are did:web:seller.example; the cp-1 entry and the trust.authority entry name that party.', inputs('jws', { body: b, trust }), MALFORMED('acceptance_signer_is_issuer'), b);
  }
  {
    const trust = F.trustBase();
    trust.issuers[0].keys.push({ address: F.BUYER });
    add('AR-C07', 'c', 'eip712', 'The trust.issuers entry for did:web:seller.example also lists BUYER\'s address.', inputs('eip712', { trust }), MALFORMED('acceptance_signer_is_issuer'), F.bodyE());
  }

  // AR-C08 Terms differ from the seller's offer
  both((f) => { const b = baseBody(f); b.termsDigest = F.TA_20000; add('AR-C08', 'a', f, 'termsDigest is the digest of Offer A\'s payload with amount "20000"; that offer is not supplied.', inputs(f, { body: b }), MALFORMED('acceptance_terms_digest_mismatch'), b); });

  // AR-C09 Outcome differs from the receipt
  both((f) => { const b = baseBody(f); b.outcomeDigest = '0x' + sha256hex('other'); add('AR-C09', 'a', f, 'outcomeDigest is another SHA-256 value.', inputs(f, { body: b }), MALFORMED('acceptance_outcome_digest_mismatch'), b); });
  both((f) => add('AR-C09', 'b', f, 'The baseline record, with outcome supplied as bytes whose SHA-256 is not DA.', inputs(f, { outcome: utf8('not the report') }), MALFORMED('acceptance_outcome_digest_mismatch'), baseBody(f)));

  // AR-C10 Acceptance presented against another delivery
  both((f) => add('AR-C10', 'a', f, 'subject input is Receipt B; the record still names EA and HA.', inputs(f, { subject: F.RECEIPT_B.text }), MALFORMED('acceptance_record_digest_mismatch'), baseBody(f)));
  both((f) => { const b = baseBody(f); b.contextId = '0x' + F.HB; add('AR-C10', 'b', f, 'contextId is 0x + HB; subject.reference stays EA; subject input is Receipt A.', inputs(f, { body: b }), MALFORMED('acceptance_record_digest_mismatch'), b); });

  // AR-C11 Acceptance before the outcome
  both((f) => { const b = baseBody(f); b.issuedAt = F.t0 - 1; add('AR-C11', 'a', f, 'issuedAt t0 − 1.', inputs(f, { body: b }), MALFORMED('acceptance_precedes_outcome'), b); });

  // AR-C12 Rejection in the same second as the outcome
  { const b = F.bodyE(); b.issuedAt = F.t0; b.disposition = 'rejected'; add('AR-C12', 'a', 'eip712', 'issuedAt t0; disposition "rejected".', inputs('eip712', { body: b }), VERIFIED('rejected'), b); }

  // AR-C13 All conditions reported; a dependent check skipped
  { const b = F.bodyJ(); b.termsDigest = F.TA_20000; b.outcomeDigest = '0xabc'; add('AR-C13', 'a', 'jws', 'termsDigest as in AR-C08; outcomeDigest "0xabc".', inputs('jws', { body: b }), MALFORMED(MI, 'acceptance_terms_digest_mismatch')); }

  // AR-C14 Signature checked before bindings
  {
    const b = F.bodyE();
    const bodyBytes = utf8(jcs(b).replace(F.TA, F.TA_20000));
    add('AR-C14', 'a', 'eip712', 'After signing, termsDigest is replaced as in AR-C08; the signature is unchanged.', inputs('eip712', { record: F.eipRecord(b, { bodyBytes, signature: baselineE.signature }).text }), MALFORMED('signature_invalid'));
  }

  // AR-C15 Signed under another domain, type or chain
  {
    const b = F.bodyE();
    const sv = MALFORMED('signature_invalid');
    add('AR-C15', 'a', 'eip712', 'Signed under domain {name, version, chainId: 84532}.', inputs('eip712', { record: F.eipRecord(b, { domain: { ...{ name: 'x402 acceptance', version: '0' }, chainId: 84532 } }).text }), sv, b);
    add('AR-C15', 'b', 'eip712', 'Signed under domain version "1".', inputs('eip712', { record: F.eipRecord(b, { domain: { name: 'x402 acceptance', version: '1' } }).text }), sv, b);
    const alpha = { ...ACCEPTANCE_TYPES, Acceptance: [...ACCEPTANCE_TYPES.Acceptance].sort((x, y) => x.name.localeCompare(y.name)) };
    add('AR-C15', 'c', 'eip712', 'Signed with the Acceptance members in alphabetical order.', inputs('eip712', { record: F.eipRecord(b, { types: alpha as any }).text }), sv, b);
    const bodyBytes = utf8(jcs(b).split(`eip155:${F.CHAIN_ID}:`).join('eip155:8453:'));
    add('AR-C15', 'd', 'eip712', 'A body naming chain 84532 was signed; it is presented with signer and confirmingParty naming chain 8453, where BUYER has no code.',
      inputs('eip712', { record: F.eipRecord(b, { bodyBytes, signature: baselineE.signature }).text, chain: F.chainBase({ extra: [{ chainId: 8453, block: F.BLOCK, account: F.BUYER, code: false }] }) }), sv);
    add('AR-C15', 'e', 'eip712', 'Signed under domain {name, version, verifyingContract: PAYEE}.', inputs('eip712', { record: F.eipRecord(b, { domain: { name: 'x402 acceptance', version: '0', verifyingContract: checksum(F.PAYEE) } }).text }), sv, b);
  }

  // Contract-account inputs (AR-C17), reused by AR-C16, AR-C18 and AR-C22 (b)
  function c17(o: {
    confirmingParty?: string; chainId?: number; returns?: string; revert?: boolean; listCall?: boolean; signature?: (s: string) => string;
    omitWallet?: boolean; contractAccounts?: boolean; complete?: unknown;
  } = {}) {
    const chainId = o.chainId ?? F.CHAIN_ID;
    const b = F.bodyE();
    b.contextId = '0x' + F.HC;
    b.subject = { profile: 'x402ev/1', reference: F.EC };
    b.signer = F.eip155(chainId, F.WALLET);
    b.confirmingParty = o.confirmingParty ?? b.signer;
    const rec0 = F.eipRecord(b, { wallet: true });
    const signature = o.signature ? o.signature(rec0.signature) : rec0.signature;
    const rec = signature === rec0.signature ? rec0 : F.eipRecord(b, { signature });
    const call: F.Call = o.revert ? { digest: rec0.digest!, signature, revert: true } : { digest: rec0.digest!, signature, returns: o.returns ?? F.MAGIC32 };
    const trust = F.trustBase();
    if (o.complete !== undefined) trust.complete = o.complete;
    const inp = inputs('eip712', {
      body: b, record: rec.text, subject: F.RECEIPT_C.text, trust,
      chain: F.chainBase({ walletCalls: o.listCall === false ? [] : [call], omitWallet: o.omitWallet }),
      contractAccounts: o.contractAccounts,
    });
    return { body: b, inp };
  }

  // AR-C16 Signature encodings refused
  {
    const sv = MALFORMED('signature_invalid');
    const b = F.bodyE();
    const withSig = (s: string) => inputs('eip712', { record: F.eipRecord(b, { signature: s }).text });
    add('AR-C16', 'a', 'eip712', 's replaced by n − s and v switched between 27 and 28.', withSig(withHighS(baselineE.signature as `0x${string}`)), sv, b);
    add('AR-C16', 'b', 'eip712', 'v replaced by v − 27.', withSig(withRawV(baselineE.signature as `0x${string}`)), sv, b);
    add('AR-C16', 'c', 'eip712', 'The 64-byte compact form r ‖ (yParity · 2^255 + s).', withSig(compact2098(baselineE.signature as `0x${string}`)), sv, b);
    add('AR-C16', 'd', 'eip712', 'The signature hex in uppercase.', withSig(upperHex(baselineE.signature)), sv, b);
    { const v = c17({ returns: '0xffffffff' + '00'.repeat(28) }); add('AR-C16', 'e', 'eip712', 'AR-C17\'s inputs with the call returning 0xffffffff followed by 28 zero bytes.', v.inp, sv, v.body); }
    {
      const chain = F.chainBase({ buyer: { code: true, calls: [{ digest: baselineE.digest!, signature: baselineE.signature, returns: '0xffffffff' + '00'.repeat(28) }] } });
      add('AR-C16', 'j', 'eip712', 'The baseline record, with chain saying BUYER has code on 84532 and the call for that record returning 0xffffffff…; the 65-byte signature would recover.', inputs('eip712', { chain }), sv, b);
    }
    { const v = c17({ revert: true }); add('AR-C16', 'k', 'eip712', 'AR-C17\'s inputs with the call giving revert.', v.inp, sv, v.body); }
    { const v = c17({ signature: upperHex, listCall: false }); add('AR-C16', 'l', 'eip712', 'AR-C17\'s inputs with the signature hex in uppercase; no call listed for it.', v.inp, sv, v.body); }
    { const v = c17({ returns: '0x1626ba7e' + '00'.repeat(27) }); add('AR-C16', 'm', 'eip712', 'AR-C17\'s inputs with the call returning 0x1626ba7e followed by 27 zero bytes (31 bytes).', v.inp, sv, v.body); }
    const bj = F.bodyJ();
    const withJ = (sigBytes: Uint8Array) => inputs('jws', { record: F.jwsRecord(bj, { sigBytes }).text });
    add('AR-C16', 'f', 'jws', 'One byte of the signature flipped.', withJ(flipByte(baselineJ.sig, 10)), sv, bj);
    add('AR-C16', 'g', 'jws', 'S replaced by S + L.', withJ(withSPlusL(baselineJ.sig)), sv, bj);
    add('AR-C16', 'h', 'jws', 'R = the identity point\'s encoding and S = k·a mod L: the cofactorless equation accepts, R has small order.', withJ(forgeIdentityR(F.SEED.kb, baselineJ.signingInput)), sv, bj);
    add('AR-C16', 'i', 'jws', 'R\' = rB + T with T of order 8, S\' = r + k\'·a mod L: the cofactored equation accepts, the cofactorless one fails.', withJ(forgeMixedR(F.SEED.kb, baselineJ.signingInput, 'AR-C16-i')), sv, bj);
  }

  // AR-C17 Contract account
  { const v = c17(); add('AR-C17', 'a', 'eip712', 'subject is Receipt C; signer and confirmingParty are WALLET; the listed call returns the 32-byte magic value.', v.inp, VERIFIED('accepted'), v.body); }
  { const v = c17({ returns: '0x1626ba7e' + '00'.repeat(60) }); add('AR-C17', 'b', 'eip712', 'The listed call returns 0x1626ba7e followed by 60 zero bytes: 64 bytes whose first word is the magic value.', v.inp, VERIFIED('accepted'), v.body); }

  // AR-C18 Contract account not resolvable
  { const v = c17({ omitWallet: true }); add('AR-C18', 'a', 'eip712', 'No chain entry for WALLET on 84532.', v.inp, KEY_UNRESOLVED('chain_state_unavailable', false), v.body); }
  { const v = c17({ contractAccounts: false }); add('AR-C18', 'b', 'eip712', 'contractAccounts false.', v.inp, KEY_UNRESOLVED('contract_accounts_unsupported', false), v.body); }
  { const v = c17({ chainId: 8453 }); add('AR-C18', 'c', 'eip712', 'signer and confirmingParty name eip155:8453:WALLET; chain lists WALLET on 84532 with code and a valid call for this record, nothing for 8453.', v.inp, KEY_UNRESOLVED('chain_state_unavailable', false), v.body); }
  { const v = c17({ omitWallet: true, complete: true }); add('AR-C18', 'd', 'eip712', 'As (a), with trust.complete true.', v.inp, KEY_UNRESOLVED('chain_state_unavailable', false), v.body); }

  // AR-C19 JWS key absent from a complete trust input
  {
    const complete = () => { const t = F.trustBase(); t.complete = true; return t; };
    const hdr2 = utf8('{"alg":"EdDSA","kid":"cp-2","typ":"x402-acceptance+jws"}');
    add('AR-C19', 'a', 'jws', 'trust.complete true; header kid cp-2, signed with a key that is not in trust.keys.', inputs('jws', { record: F.jwsRecord(F.bodyJ(), { seed: F.SEED.kx, headerBytes: hdr2 }).text, trust: complete() }), KEY_UNRESOLVED('key_missing', true), F.bodyJ());
    const b = F.bodyJ(); b.signer = 'did:example:other'; b.confirmingParty = 'did:example:other';
    add('AR-C19', 'b', 'jws', 'trust.complete true; header kid cp-1, signed with KB; body signer and confirmingParty "did:example:other".', inputs('jws', { body: b, trust: complete() }), KEY_UNRESOLVED('signer_mismatch', true), b);
    add('AR-C19', 'c', 'jws', '(a)\'s input with an extra body member "reason": "late".', inputs('jws', { record: F.jwsRecord(F.bodyJ(), { seed: F.SEED.kx, headerBytes: hdr2, payloadBytes: utf8(jcs({ ...F.bodyJ(), reason: 'late' })) }).text, trust: complete() }), KEY_UNRESOLVED('key_missing', true));
  }

  // AR-C20 Refused Ed25519 keys
  {
    const trustWith = (key: Uint8Array) => { const t = F.trustBase(); t.complete = 'true'; t.keys[0].key = b64u(key); return t; };
    const bj = F.bodyJ();
    add('AR-C20', 'a', 'jws', 'trust.complete is the string "true"; the cp-1 key is the identity point; signature R = identity, S = 0.', inputs('jws', { record: F.jwsRecord(bj, { sigBytes: concat(IDENTITY_ENCODING, new Uint8Array(32)) }).text, trust: trustWith(IDENTITY_ENCODING) }), KEY_UNRESOLVED('key_refused', false), bj);
    add('AR-C20', 'b', 'jws', 'The cp-1 key is KB + T, T of order 8, with a signature both RFC 8032 equations accept.', inputs('jws', { record: F.jwsRecord(bj, { sign: (input) => signForMixedKey(F.SEED.kb, input, 'AR-C20-b') }).text, trust: trustWith(mixedOrderKey(F.SEED.kb)) }), KEY_UNRESOLVED('key_refused', false), bj);
    add('AR-C20', 'c', 'jws', 'The cp-1 key is a non-canonical encoding with y ≥ p (the identity point written as y = p + 1); the record is the baseline.', inputs('jws', { trust: trustWith(NON_CANONICAL_IDENTITY) }), KEY_UNRESOLVED('key_refused', false), bj);
  }

  // AR-C21 JWS header or payload not in the profile
  {
    const bj = F.bodyJ();
    const rec = (o: Parameters<typeof F.jwsRecord>[1]) => inputs('jws', { record: F.jwsRecord(bj, o).text });
    add('AR-C21', 'a', 'jws', 'typ "JWT".', rec({ headerBytes: utf8('{"alg":"EdDSA","kid":"cp-1","typ":"JWT"}') }), MALFORMED(MI));
    add('AR-C21', 'b', 'jws', 'The header gains "cty": "json".', rec({ headerBytes: utf8('{"alg":"EdDSA","cty":"json","kid":"cp-1","typ":"x402-acceptance+jws"}') }), MALFORMED(MI));
    add('AR-C21', 'c', 'jws', 'alg "ES256K" with a valid secp256k1 signature over the signing input.', rec({
      headerBytes: utf8('{"alg":"ES256K","kid":"cp-1","typ":"x402-acceptance+jws"}'),
      sign: (input) => secp256k1.sign(sha256(input), F.SEED.buyer, { prehash: false, format: 'compact' }) as Uint8Array,
    }), MALFORMED(MI));
    add('AR-C21', 'd', 'jws', 'The payload is the body serialized with a space after each colon, validly signed over those bytes.', rec({ payloadBytes: utf8(jcs(bj).replace(/":/g, '": ')) }), MALFORMED(MI), bj);
    add('AR-C21', 'e', 'jws', 'The payload decodes to a JSON array, and one signature byte is flipped.', rec({ payloadBytes: utf8('["accepted"]'), sign: (input) => flipByte(edSign(F.SEED.kb, input), 3) }), MALFORMED(MI));
    add('AR-C21', 'f', 'jws', 'The protected header names alg twice, both times "EdDSA".', rec({ headerBytes: utf8('{"alg":"EdDSA","alg":"EdDSA","kid":"cp-1","typ":"x402-acceptance+jws"}') }), MALFORMED(MI));
    add('AR-C21', 'g', 'jws', 'The signature segment\'s last character changed so that its unused bits are non-zero; it decodes to the same bytes.', rec({
      token: (t) => { const last = t[t.length - 1]; const alt = B64URL[B64URL.indexOf(last) | 1]; if (alt === last) throw new Error('unused bits already set'); return t.slice(0, -1) + alt; },
    }), MALFORMED(MI), bj);
  }

  // AR-C22 Valid signature, authority not established
  {
    const b = F.bodyE(); b.signer = F.eip155(F.CHAIN_ID, F.OTHER); b.confirmingParty = b.signer;
    add('AR-C22', 'a', 'eip712', 'signer and confirmingParty are OTHER, signed by OTHER, who is not Receipt A\'s payer.', inputs('eip712', { record: F.eipRecord(b, { seed: F.SEED.other }).text }), UNKNOWN_AUTH('accepted'), b);
    const v = c17({ confirmingParty: ACME });
    add('AR-C22', 'b', 'eip712', 'AR-C17\'s inputs with confirmingParty "did:web:acme.example".', v.inp, UNKNOWN_AUTH('accepted'), v.body);
    for (const [variant, authority, note] of [
      ['e', { mode: 'direct', profile: 'payer/1', reference: '' }, 'authority {direct, payer/1, ""}.'],
      ['f', { mode: 'declared', profile: 'payer/0', reference: '' }, 'authority {declared, payer/0, ""}.'],
      ['g', { mode: 'direct', profile: 'payer/0', reference: 'x' }, 'authority {direct, payer/0, "x"}.'],
    ] as const) {
      const bb = F.bodyE(); bb.authority = { ...authority };
      add('AR-C22', variant, 'eip712', note, inputs('eip712', { body: bb }), UNKNOWN_AUTH('accepted'), bb);
    }
    const bh = F.bodyE(); bh.confirmingParty = ACME;
    add('AR-C22', 'h', 'eip712', 'The baseline EIP-712 record with confirmingParty "did:web:acme.example", still signed by BUYER, the payer.', inputs('eip712', { body: bh }), UNKNOWN_AUTH('accepted'), bh);
    const tc = F.trustBase(); tc.authority = [];
    add('AR-C22', 'c', 'jws', 'trust.authority empty.', inputs('jws', { trust: tc }), UNKNOWN_AUTH('accepted'), F.bodyJ());
    const td = F.trustBase(); td.authority[0].subjectReference = F.EB;
    add('AR-C22', 'd', 'jws', 'The trust.authority entry\'s subjectReference is EB.', inputs('jws', { trust: td }), UNKNOWN_AUTH('accepted'), F.bodyJ());
  }

  // AR-C23 Unknown subject profile
  both((f) => { const b = baseBody(f); b.subject = { ...b.subject, profile: 'other/9' }; add('AR-C23', 'a', f, 'subject.profile "other/9".', inputs(f, { body: b }), UNKNOWN('profile_unavailable', 'accepted'), b); });

  // AR-C24 Evidence unavailable
  {
    const EU = UNKNOWN('evidence_unavailable', 'accepted');
    both((f) => add('AR-C24', 'a', f, 'terms empty.', inputs(f, { terms: [] }), EU, baseBody(f)));
    both((f) => add('AR-C24', 'b', f, 'subject absent.', inputs(f, { subject: null }), EU, baseBody(f)));
    both((f) => add('AR-C24', 'c', f, 'Receipt A with delivery.latencyMs changed after signing.', inputs(f, { subject: utf8(text(F.RECEIPT_A.text).replace('"latencyMs":42', '"latencyMs":43')) }), EU, baseBody(f)));
    both((f) => add('AR-C24', 'd', f, 'terms holds only Offer A with amount "20000", signed with KS.', inputs(f, { terms: [F.OFFER_A_20000.text] }), EU, baseBody(f)));
    both((f) => { const b = baseBody(f); b.deliveryIssuer = 'did:web:other.example'; add('AR-C24', 'e', f, 'deliveryIssuer "did:web:other.example", which trust.issuers does not list.', inputs(f, { body: b }), EU, b); });
    both((f) => add('AR-C24', 'f', f, 'terms holds only Offer A re-signed with an Ed25519 key not listed in trust.issuers.', inputs(f, { terms: [F.OFFER_A_KY.text] }), EU, baseBody(f)));
    both((f) => add('AR-C24', 'g', f, 'terms holds only Offer A in EIP-712 form, signed by an address not listed.', inputs(f, { terms: [F.OFFER_A_712_OTHER.text] }), EU, baseBody(f)));
    const rh = F.receipt({ contentDigest: 'sha256:' + F.DA.toUpperCase() });
    both((f) => { const b = baseBody(f); b.contextId = '0x' + rh.hashHex; b.subject = { ...b.subject, reference: rh.evidenceRef }; add('AR-C24', 'h', f, 'Receipt A re-signed with delivery.contentDigest in uppercase hex; its new evidenceRef and digest carried into subject.reference and contextId.', inputs(f, { body: b, subject: rh.text }), EU, b); });
    const sigOld = 'base64url:' + b64u(F.RECEIPT_A.signature), sigNew = 'base64url:' + b64u(withSPlusL(F.RECEIPT_A.signature));
    both((f) => add('AR-C24', 'i', f, 'Receipt A with its signature\'s S replaced by S + L.', inputs(f, { subject: utf8(text(F.RECEIPT_A.text).replace(sigOld, sigNew)) }), EU, baseBody(f)));
    const rj = F.receipt({ signSeed: F.SEED.ky });
    both((f) => { const b = baseBody(f); b.contextId = '0x' + rj.hashHex; b.subject = { ...b.subject, reference: rj.evidenceRef }; add('AR-C24', 'j', f, 'Receipt A re-signed with an Ed25519 key not listed for deliveryIssuer, signer.publicKey set to that key; its new evidenceRef and digest carried into the record.', inputs(f, { body: b, subject: rj.text }), EU, b); });
  }

  // AR-C25 Numbers and text not in the stated encoding
  {
    const lex = (f: Form, variant: string, note: string, mutate: (t: string) => string | Uint8Array) => {
      const b = baseBody(f);
      const m = mutate(jcs(b));
      const bytes = typeof m === 'string' ? utf8(m) : m;
      const rec = f === 'eip712' ? F.eipRecord(b, { bodyBytes: bytes, signature: baselineE.signature }).text : F.jwsRecord(b, { payloadBytes: bytes }).text;
      add('AR-C25', variant, f, note + (f === 'eip712' ? ' EIP-712: the typed message cannot be built; the baseline signature is carried unchanged.' : ' JWS: validly signed over those bytes.'), inputs(f, { record: rec }), MALFORMED(MI));
    };
    const ISSUED = `"issuedAt":${F.t0 + 600}`;
    const DI = '"deliveryIssuer":"did:web:seller.example"';
    both((f) => lex(f, 'b', 'issuedAt as the JSON string "1791500600".', (t) => t.replace(ISSUED, `"issuedAt":"${F.t0 + 600}"`)));
    both((f) => lex(f, 'c', 'The member name disposition appears twice, both times "accepted".', (t) => t.replace('"disposition":"accepted"', '"disposition":"accepted","disposition":"accepted"')));
    both((f) => lex(f, 'h', 'issuedAt written 1791500600.0.', (t) => t.replace(ISSUED, `"issuedAt":${F.t0 + 600}.0`)));
    both((f) => lex(f, 'i', 'issuedAt written 1.7915006e9.', (t) => t.replace(ISSUED, '"issuedAt":1.7915006e9')));
    both((f) => lex(f, 'j', 'issuedAt written 01791500600.', (t) => t.replace(ISSUED, `"issuedAt":0${F.t0 + 600}`)));
    both((f) => lex(f, 'k', 'A string member contains the byte 0xFF.', (t) => {
      const i = t.indexOf(DI) + DI.length - 1; // before the closing quote of the value
      return concat(utf8(t.slice(0, i)), Uint8Array.of(0xff), utf8(t.slice(i)));
    }));
    both((f) => lex(f, 'm', 'issuedAt 9007199254740992.', (t) => t.replace(ISSUED, '"issuedAt":9007199254740992')));
    both((f) => lex(f, 'n', 'A string member contains the escape \\ud800.', (t) => t.replace(DI, '"deliveryIssuer":"did:web:seller.example\\ud800"')));
  }

  const ids = new Set<string>();
  for (const v of out) { if (ids.has(v.id)) throw new Error(`duplicate vector id ${v.id}`); ids.add(v.id); }
  return out;
}
