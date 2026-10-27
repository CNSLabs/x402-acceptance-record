// The acceptance body (SPEC section 3): AR-1, AR-4, AR-5 and the number forms of AR-6.
import type { JsonNode } from './json.ts';

export const BODY_MEMBERS = [
  'version', 'contextId', 'deliveryIssuer', 'confirmingParty', 'signer', 'authority',
  'termsDigest', 'outcomeDigest', 'subject', 'disposition', 'issuedAt',
] as const;

export const DISPOSITIONS = ['accepted', 'rejected', 'disputed'] as const;
export type Disposition = (typeof DISPOSITIONS)[number];

const HEX32 = /^0x[0-9a-f]{64}$/; // AR-5
const PLAIN_INTEGER = /^(?:0|[1-9][0-9]*)$/; // AR-6: plain decimal digits, no sign, fraction, exponent or leading zero
const MAX_ISSUED_AT = 2n ** 53n - 1n; // AR-5

/**
 * What the body says, member by member. A member is null when it is missing or fails its form; the
 * checks that depend on it are then skipped (AR-35 step 4). `invalid` is true when any of AR-1,
 * AR-4, AR-5 or AR-6 failed, which is `acceptance_member_invalid`.
 */
export interface BodyFacts {
  invalid: boolean;
  version: boolean;
  contextId: string | null;
  deliveryIssuer: string | null; // non-empty
  confirmingParty: string | null; // any string; "" is AR-34, not a form failure
  signer: string | null; // non-empty
  authority: { mode: string; profile: string; reference: string } | null;
  termsDigest: string | null;
  outcomeDigest: string | null;
  subject: { profile: string; reference: string } | null;
  /** The string value, whatever it is; AR-1 validity is `dispositionValid`. */
  disposition: string | null;
  dispositionValid: boolean;
  issuedAt: bigint | null;
}

function stringMember(node: JsonNode | undefined): string | null {
  return node && node.kind === 'string' ? node.value : null;
}
function nonEmptyString(node: JsonNode | undefined): string | null {
  const s = stringMember(node);
  return s !== null && s !== '' ? s : null;
}
function hex32(node: JsonNode | undefined): string | null {
  const s = stringMember(node);
  return s !== null && HEX32.test(s) ? s : null;
}

export function checkBody(body: JsonNode): BodyFacts {
  const facts: BodyFacts = {
    invalid: false, version: false, contextId: null, deliveryIssuer: null, confirmingParty: null, signer: null,
    authority: null, termsDigest: null, outcomeDigest: null, subject: null, disposition: null, dispositionValid: false, issuedAt: null,
  };
  if (body.kind !== 'object') return { ...facts, invalid: true };
  const m = (name: string) => body.members.get(name);
  let invalid = false;

  // AR-4: exactly the eleven members
  if (body.members.size !== BODY_MEMBERS.length || !BODY_MEMBERS.every((n) => body.members.has(n))) invalid = true;

  // AR-5 and AR-6: version is the integer 0, written as plain digits
  const version = m('version');
  facts.version = version !== undefined && version.kind === 'number' && version.lexeme === '0';

  // AR-5: hex32 members
  facts.contextId = hex32(m('contextId'));
  facts.termsDigest = hex32(m('termsDigest'));
  facts.outcomeDigest = hex32(m('outcomeDigest'));

  // AR-5: string members
  facts.deliveryIssuer = nonEmptyString(m('deliveryIssuer'));
  facts.confirmingParty = stringMember(m('confirmingParty'));
  facts.signer = nonEmptyString(m('signer'));

  // AR-4 and AR-5: authority is exactly {mode, profile, reference}, strings
  const authority = m('authority');
  if (authority && authority.kind === 'object') {
    if (authority.members.size !== 3) invalid = true;
    const mode = stringMember(authority.members.get('mode'));
    const profile = stringMember(authority.members.get('profile'));
    const reference = stringMember(authority.members.get('reference'));
    if (mode !== null && profile !== null && reference !== null) facts.authority = { mode, profile, reference };
  }

  // AR-4 and AR-5: subject is exactly {profile, reference}, strings
  const subject = m('subject');
  if (subject && subject.kind === 'object') {
    if (subject.members.size !== 2) invalid = true;
    const profile = stringMember(subject.members.get('profile'));
    const reference = stringMember(subject.members.get('reference'));
    if (profile !== null && reference !== null) facts.subject = { profile, reference };
  }

  // AR-5 string form, then AR-1 value
  facts.disposition = stringMember(m('disposition'));
  facts.dispositionValid = facts.disposition !== null && (DISPOSITIONS as readonly string[]).includes(facts.disposition);
  if (!facts.dispositionValid) invalid = true;

  // AR-5 and AR-6: issuedAt is an integer from 0 to 2^53 - 1, written as plain digits
  const issuedAt = m('issuedAt');
  if (issuedAt && issuedAt.kind === 'number' && PLAIN_INTEGER.test(issuedAt.lexeme)) {
    const v = BigInt(issuedAt.lexeme);
    if (v <= MAX_ISSUED_AT) facts.issuedAt = v;
  }

  if (
    !facts.version || facts.contextId === null || facts.termsDigest === null || facts.outcomeDigest === null ||
    facts.deliveryIssuer === null || facts.confirmingParty === null || facts.signer === null ||
    facts.authority === null || facts.subject === null || facts.disposition === null || facts.issuedAt === null
  ) invalid = true;

  facts.invalid = invalid;
  return facts;
}
