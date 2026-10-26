// The verifier's inputs (SPEC section 5), in the decoded form the runner hands to verify().
import { b64uDecode, isEthAddress } from './encoding.ts';

export interface TrustIssuerKey {
  ed25519?: string; // unpadded base64url, 32 bytes
  kid?: string;
  address?: string; // 0x + 40 hex digits
}
export interface TrustIssuer {
  issuer: string;
  keys: TrustIssuerKey[];
}
export interface TrustKey {
  kid: string;
  signer: string;
  key: string; // unpadded base64url, 32 bytes
}
export interface TrustAuthority {
  confirmingParty: string;
  signer: string;
  subjectProfile: string;
  subjectReference: string;
}
export interface Trust {
  issuers?: TrustIssuer[];
  keys?: TrustKey[];
  authority?: TrustAuthority[];
  /** Any JSON value; absent when the input is absent. A declaration only when exactly `true` (AR-22). */
  complete?: unknown;
}
export interface ChainCall {
  digest: string;
  signature: string;
  returns?: string;
  revert?: boolean;
}
export interface ChainDeclaration {
  chainId: number | string | bigint;
  block?: number;
  account: string;
  code: boolean;
  calls?: ChainCall[];
}

export interface VerifyInputs {
  /** The envelope's JSON text, or null when the `record` input is absent. */
  record: Uint8Array | null;
  /** The subject record as its profile transmits it, or null when absent. */
  subject: Uint8Array | null;
  /** Zero or more terms artifacts, each the JSON text of a signed x402 offer object. */
  terms: Uint8Array[];
  /** The delivered bytes, when supplied. */
  outcome?: Uint8Array;
  trust: Trust;
  chain: ChainDeclaration[];
  /** Whether the verifier validates contract accounts (default true). */
  contractAccounts: boolean;
}

/** The keys and addresses `trust.issuers` lists for one issuer. */
export interface IssuerKeys {
  ed25519: Uint8Array[];
  /** Lowercase `0x` + 40 hex digits. */
  addresses: string[];
}

export function issuerKeysFor(trust: Trust, issuer: string): IssuerKeys {
  const out: IssuerKeys = { ed25519: [], addresses: [] };
  for (const entry of trust.issuers ?? []) {
    if (!entry || entry.issuer !== issuer) continue;
    for (const key of entry.keys ?? []) {
      if (!key) continue;
      if (typeof key.ed25519 === 'string') {
        const bytes = b64uDecode(key.ed25519);
        if (bytes && bytes.length === 32) out.ed25519.push(bytes);
      }
      if (typeof key.address === 'string' && isEthAddress(key.address)) out.addresses.push(key.address.toLowerCase());
    }
  }
  return out;
}
