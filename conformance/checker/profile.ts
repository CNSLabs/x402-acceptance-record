// Subject profiles (AR-23 to AR-29): what the verifier needs from a subject record, whatever its profile.
import type { IssuerKeys } from './inputs.ts';

/** What an authenticated subject record says, in the forms AR-24 to AR-26 and AR-31 compare. */
export interface SubjectFacts {
  /** The identity, byte-exact: what `subject.reference` must equal (AR-24). */
  identity: string;
  /** 0x + the 64 hex digits of the identity: what `contextId` must equal (AR-24). */
  contextId: string;
  /** `eip155:<chain>:<lowercase address>`, or null when the record has no payer (AR-31). */
  payer: string | null;
  /** 0x + 64 hex digits (AR-25). */
  outcomeDigest: string;
  /** Integer seconds (AR-26). */
  outcomeTime: number;
  /** The issuer key that signed it. */
  publicKey: Uint8Array;
}

/** One supplied subject record read under one profile. */
export interface SubjectReading {
  /** The authenticated facts, or null when the subject is unavailable (AR-23). */
  facts: SubjectFacts | null;
  /** AR-33: whether `key` signed the subject record, as the profile defines its signature. */
  signedBy(key: Uint8Array): boolean;
  /**
   * AR-29: the terms digests committed in authenticated evidence from the subject's issuer, as the
   * profile defines it. Empty means no evidence. Only meaningful when `facts` is not null.
   */
  termsDigests(terms: Uint8Array[]): Set<string>;
}

export interface SubjectProfile {
  id: string;
  /** Reads the supplied subject under this profile with the keys `trust.issuers` lists for `deliveryIssuer`. */
  read(bytes: Uint8Array, issuerKeys: IssuerKeys): SubjectReading;
}

/** A reading of a subject that could not be parsed at all. */
export const UNREADABLE: SubjectReading = { facts: null, signedBy: () => false, termsDigests: () => new Set() };
