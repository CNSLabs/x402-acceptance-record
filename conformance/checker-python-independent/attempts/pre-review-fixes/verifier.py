"""Acceptance record verifier derived from the supplied v0 specification.

No vector IDs, fixtures, expected results, network access, or mutable global state.
The API accepts the decoded byte inputs of SPEC section 5. Trust and chain
objects are caller declarations; chain calls are matched exactly as supplied.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

import rfc8785
from Crypto.Hash import keccak
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from nacl import bindings
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

SAFE = 2**53 - 1
L = 2**252 + 27742317777372353535851937790883648493
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
IDENTITY = b'\x01' + b'\x00' * 31
HEX32 = re.compile(r'0x[0-9a-f]{64}\Z')
ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}\Z')
ACCOUNT = re.compile(r'eip155:([1-9][0-9]*):(0x[0-9a-f]{40})\Z')
BODY_MEMBERS = frozenset(('version', 'contextId', 'deliveryIssuer',
                         'confirmingParty', 'signer', 'authority', 'termsDigest',
                         'outcomeDigest', 'subject', 'disposition', 'issuedAt'))
INVALID = 'acceptance_member_invalid'
ECC = KeyAPI(NativeECCBackend())


class EncodingError(ValueError):
    """Unacceptable wire encoding."""


class InputRefused(ValueError):
    """Caller input is contradictory, so verification has no result."""


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64decode(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r'[A-Za-z0-9_-]*', text):
        raise EncodingError('Non-base64url character or padding')
    try:
        raw = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    except Exception as exc:
        raise EncodingError('Invalid base64url length') from exc
    if b64encode(raw) != text:
        raise EncodingError('Non-zero unused bits')
    return raw


def parse_json(raw: bytes, *, acceptance: bool = False) -> Any:
    """Strict I-JSON parse. General evidence numbers have binary64 semantics.

    Acceptance numbers retain integer lexical restrictions. This does not impose
    the acceptance body's integer restriction on arbitrary signed offer data.
    """
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EncodingError('Duplicate member')
            result[key] = value
        return result

    def integer(token):
        if acceptance:
            if not re.fullmatch(r'0|[1-9][0-9]*', token):
                raise EncodingError('Integer spelling')
            return int(token)
        n = int(token)
        return n if abs(n) <= SAFE else floating(token)

    def floating(token):
        if acceptance:
            raise EncodingError('Fraction/exponent in acceptance JSON')
        n = float(token)
        if not math.isfinite(n):
            raise EncodingError('Non-finite number')
        return n

    def constant(token):
        raise EncodingError('Non-JSON numeric constant')

    def strings(value):
        if isinstance(value, str):
            value.encode('utf-8', errors='strict')
        elif isinstance(value, dict):
            for key, child in value.items():
                strings(key)
                strings(child)
        elif isinstance(value, list):
            for child in value:
                strings(child)

    try:
        text = raw.decode('utf-8', errors='strict')
        result = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                            parse_float=floating, parse_constant=constant)
        strings(result)
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise EncodingError(str(exc)) from exc


def check_body_number_locations(body):
    def walk(value, path):
        if type(value) in (int, float) and path not in (('version',), ('issuedAt',)):
            raise EncodingError('Number outside version/issuedAt')
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, path + (k,))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, path + (i,))
    walk(body, ())


def canonicalize(value: Any) -> bytes:
    return rfc8785.dumps(value)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def statement_id(body: dict) -> str:
    return 'x402accept/0:sha256:' + sha(canonicalize(body))


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def valid_point(point: bytes) -> bool:
    """Canonical encoding and exact prime order, including mixed-order refusal.

    The explicit [L-1]P + P test follows the documented libsodium workaround
    for versions <= 1.0.20 whose is_valid_point subgroup check was incomplete.
    It is retained even on newer versions as a defense independent of that fix.
    """
    try:
        return (len(point) == 32
                and (int.from_bytes(point, 'little') & (2**255 - 1)) < 2**255 - 19
                and bindings.crypto_core_ed25519_is_valid_point(point)
                and bindings.crypto_core_ed25519_add(
                    bindings.crypto_scalarmult_ed25519_noclamp(
                        (L - 1).to_bytes(32, 'little'), point), point) == IDENTITY)
    except (ValueError, RuntimeError):
        return False


def ed25519_verify(key: bytes, message: bytes, sig: bytes) -> bool:
    if (not valid_point(key) or len(sig) != 64 or not valid_point(sig[:32])
            or int.from_bytes(sig[32:], 'little') >= L):
        return False
    try:
        VerifyKey(key).verify(message, sig)
        return True
    except (BadSignatureError, ValueError):
        return False


def uint(n: int) -> bytes:
    if type(n) is not int or not 0 <= n < 2**256:
        raise EncodingError('Not uint256')
    return n.to_bytes(32, 'big')


def hstring(value: str) -> bytes:
    return keccak256(value.encode('utf-8'))


def hstruct(type_text: str, words: list[bytes]) -> bytes:
    return keccak256(keccak256(type_text.encode('ascii')) + b''.join(words))


def signer_account(signer: str) -> tuple[int, str]:
    match = ACCOUNT.fullmatch(signer) if isinstance(signer, str) else None
    if not match:
        raise EncodingError('Signer account syntax')
    chain_id, account = int(match[1]), match[2]
    if chain_id >= 2**256 or int(account, 16) == 0:
        raise EncodingError('Signer account range')
    return chain_id, account


def acceptance_digest(body: dict) -> bytes:
    chain_id, account = signer_account(body['signer'])
    authority_type = 'Authority(string mode,string profile,string reference)'
    subject_type = 'Subject(string profile,string reference)'
    acceptance_type = ('Acceptance(uint256 version,bytes32 contextId,string deliveryIssuer,'
                       'string confirmingParty,uint256 signerChainId,address signerAccount,'
                       'Authority authority,bytes32 termsDigest,bytes32 outcomeDigest,'
                       'Subject subject,string disposition,uint64 issuedAt)')
    authority = hstruct(authority_type, [hstring(body['authority'][k])
                                       for k in ('mode', 'profile', 'reference')])
    subject = hstruct(subject_type, [hstring(body['subject'][k]) for k in ('profile', 'reference')])
    message = hstruct(acceptance_type + authority_type + subject_type, [
        uint(body['version']), bytes.fromhex(body['contextId'][2:]),
        hstring(body['deliveryIssuer']), hstring(body['confirmingParty']),
        uint(chain_id), b'\x00' * 12 + bytes.fromhex(account[2:]), authority,
        bytes.fromhex(body['termsDigest'][2:]), bytes.fromhex(body['outcomeDigest'][2:]),
        subject, hstring(body['disposition']), uint(body['issuedAt'])])
    domain = hstruct('EIP712Domain(string name,string version)',
                     [hstring('x402 acceptance'), hstring('0')])
    return keccak256(b'\x19\x01' + domain + message)


def recover_address(digest: bytes, signature: str, *, acceptance=True) -> str | None:
    pattern = r'0x[0-9a-f]{130}' if acceptance else r'0x[0-9a-fA-F]{130}'
    if not isinstance(signature, str) or not re.fullmatch(pattern, signature):
        return None
    raw = bytes.fromhex(signature[2:])
    r, s, v = int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:64], 'big'), raw[64]
    if v not in (27, 28) or not 0 < r < N or not 0 < s < N:
        return None
    if acceptance and s > N // 2:
        return None
    try:
        # v is checked before conversion to the library's representation.
        sig = ECC.Signature(vrs=(v - 27, r, s))
        return ECC.ecdsa_recover(digest, sig).to_address().lower()
    except Exception:
        # eth_keys exposes backend-specific validation/recovery exceptions.
        return None


def offer_digest(payload: dict) -> bytes:
    domain = hstruct('EIP712Domain(string name,string version,uint256 chainId)',
                     [hstring('x402 offer'), hstring('1'), uint(1)])
    typ = ('Offer(uint256 version,string resourceUrl,string scheme,string network,'
           'string asset,string payTo,string amount,uint256 validUntil)')
    message = hstruct(typ, [uint(payload['version'])] +
                     [hstring(payload[k]) for k in ('resourceUrl', 'scheme', 'network', 'asset', 'payTo', 'amount')] +
                     [uint(payload['validUntil'])])
    return keccak256(b'\x19\x01' + domain + message)


def body_validity(body: dict) -> tuple[set[str], bool]:
    """Per-member form validity and separate closure result (AR-4 vs AR-5)."""
    valid = set()
    for k in ('contextId', 'termsDigest', 'outcomeDigest'):
        if isinstance(body.get(k), str) and HEX32.fullmatch(body[k]):
            valid.add(k)
    for k in ('deliveryIssuer', 'confirmingParty', 'signer', 'disposition'):
        if isinstance(body.get(k), str) and (k not in ('deliveryIssuer', 'signer') or body[k]):
            valid.add(k)
    if type(body.get('version')) is int and body['version'] == 0:
        valid.add('version')
    if type(body.get('issuedAt')) is int and 0 <= body['issuedAt'] <= SAFE:
        valid.add('issuedAt')
    closed = set(body) == BODY_MEMBERS
    for k, members in [('authority', {'mode', 'profile', 'reference'}), ('subject', {'profile', 'reference'})]:
        obj = body.get(k)
        if isinstance(obj, dict) and all(isinstance(obj.get(n), str) for n in members):
            valid.add(k)
            closed &= set(obj) == members
        else:
            closed = False
    return valid, closed


def split_jws(compact: str, *, acceptance: bool):
    if not isinstance(compact, str) or compact.count('.') != 2:
        raise EncodingError('Not compact JWS')
    head_segment, body_segment, sig_segment = compact.split('.')
    header_raw, payload_raw, signature = map(b64decode, (head_segment, body_segment, sig_segment))
    header = parse_json(header_raw, acceptance=acceptance)
    body = parse_json(payload_raw, acceptance=acceptance)
    if not isinstance(header, dict) or not isinstance(body, dict):
        raise EncodingError('Header/payload not object')
    if header.get('alg') != 'EdDSA' or not isinstance(header.get('kid'), str) or not header['kid']:
        raise EncodingError('Unsupported header')
    if acceptance and (set(header) != {'alg', 'kid', 'typ'} or header['typ'] != 'x402-acceptance+jws'):
        raise EncodingError('Acceptance header')
    return header, body, payload_raw, (head_segment + '.' + body_segment).encode('ascii'), signature


def issuer_keys(trust: dict, issuer: str) -> list[dict]:
    return [k for entry in trust.get('issuers', []) if entry.get('issuer') == issuer for k in entry.get('keys', [])]


def bytes_key(entry, name):
    try:
        return b64decode(entry[name])
    except (KeyError, ValueError, TypeError):
        return None


def address_equal(a, b):
    if isinstance(a, str) and isinstance(b, str) and ADDRESS.fullmatch(a) and ADDRESS.fullmatch(b):
        return a.lower() == b.lower()
    return a == b


@dataclass(frozen=True)
class SubjectEvidence:
    reference: str
    outcome: str
    timestamp: int
    payer: str | None
    payment: dict
    key: bytes


def authenticate_subject(raw: bytes | None, keys: list[dict]) -> SubjectEvidence | None:
    if raw is None:
        return None
    try:
        info = parse_json(raw)
        required = {'evidenceRef', 'scheme', 'canonicalization', 'payment', 'request', 'delivery', 'signer'}
        if not isinstance(info, dict) or not required <= info.keys():
            return None
        if info['scheme'] != 'x402ev/1' or info['canonicalization'] != 'RFC8785':
            return None
        payment, delivery, signer = info['payment'], info['delivery'], info['signer']
        if not all(isinstance(info[k], dict) for k in ('payment', 'request', 'delivery', 'signer')):
            return None
        if not all(isinstance(payment.get(k), str) for k in ('network', 'payer', 'payee', 'amount', 'asset')):
            return None
        if not payment['payer'] or not payment['payee'] or address_equal(payment['payer'], payment['payee']):
            return None
        if signer.get('keyType') != 'Ed25519':
            return None
        key = b64decode(signer['publicKey'])
        if key not in [bytes_key(k, 'ed25519') for k in keys]:
            return None
        signature = signer['signature']
        if not isinstance(signature, str) or not signature.startswith('base64url:'):
            return None
        signature = b64decode(signature[len('base64url:'):])
        body = {k: v for k, v in info.items() if k not in ('evidenceRef', 'transparency')}
        body['signer'] = {k: v for k, v in signer.items() if k != 'signature'}
        preimage = canonicalize(body)
        reference = 'x402ev/1:sha256:' + sha(preimage)
        if info['evidenceRef'] != reference or not ed25519_verify(key, preimage, signature):
            return None
        digest = delivery.get('contentDigest')
        timestamp = delivery.get('timestamp')
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            return None
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or int(timestamp) != timestamp:
            return None
        payer = None
        if re.fullmatch(r'eip155:[0-9]+', payment['network']) and ADDRESS.fullmatch(payment['payer']):
            payer = payment['network'] + ':' + payment['payer'].lower()
        return SubjectEvidence(reference, '0x' + digest[7:], int(timestamp), payer, payment, key)
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def qualifying_terms(terms: list[bytes], keys: list[dict], subject: SubjectEvidence) -> set[str]:
    digests = set()
    for raw in terms:
        try:
            env = parse_json(raw)
            fmt = env['format']
            if fmt == 'jws':
                if 'payload' in env:
                    continue
                header, payload, payload_raw, message, sig = split_jws(env['signature'], acceptance=False)
                matching_keys = [bytes_key(k, 'ed25519') for k in keys if k.get('kid') == header['kid']]
                if not any(k is not None and ed25519_verify(k, message, sig) for k in matching_keys):
                    continue
                if payload_raw != canonicalize(payload):
                    continue
            elif fmt == 'eip712':
                payload = env['payload']
            else:
                continue
            required = {'version', 'resourceUrl', 'scheme', 'network', 'asset', 'payTo', 'amount'}
            # Unknown fields have no defined signed meaning in this upstream profile.
            if not isinstance(payload, dict) or not required <= payload.keys() or not set(payload) <= required | {'validUntil'}:
                continue
            if type(payload['version']) not in (int, float) or payload['version'] != 1:
                continue
            if not all(isinstance(payload[k], str) for k in required - {'version'}):
                continue
            expiration = payload.get('validUntil', 0)
            if type(expiration) not in (int, float) or not math.isfinite(expiration):
                continue
            if expiration != 0 and expiration < subject.timestamp:
                continue
            if fmt == 'eip712':
                if not re.fullmatch(r'eip155:[0-9]+', payload['network']) or not ADDRESS.fullmatch(payload['payTo']):
                    continue
                address = recover_address(offer_digest(payload), env['signature'], acceptance=False)
                if address is None or not any(address_equal(address, k.get('address')) for k in keys):
                    continue
            if payload['network'] != subject.payment['network'] or payload['amount'] != subject.payment['amount']:
                continue
            if not address_equal(payload['asset'], subject.payment['asset']) or not address_equal(payload['payTo'], subject.payment['payee']):
                continue
            digests.add('0x' + sha(canonicalize(payload)))
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
    return digests


def result(token, conditions=(), **members):
    return {'result': token, 'conditions': sorted(set(conditions)), **members}


def verify(*, record: bytes | None, subject: bytes | None = None,
           terms: list[bytes] | None = None, outcome: bytes | None = None,
           trust: dict | None = None, chain: list[dict] | None = None,
           contractAccounts: bool = True) -> dict:
    """Verify one record using explicit local trust and declared chain evidence.

    Raises InputRefused for duplicate trust.keys kids. All returned members are
    normative AR-36 members except optional identity and chain diagnostics.
    """
    trust, chain, terms = trust or {}, chain or [], terms or []
    kids = [entry.get('kid') for entry in trust.get('keys', [])]
    if len(kids) != len(set(kids)):
        raise InputRefused('trust.keys contains duplicate kid')
    if record is None:
        return result('no_record')
    try:
        env = parse_json(record, acceptance=True)
        if not isinstance(env, dict):
            raise EncodingError('Envelope not object')
        fmt = env.get('format')
        if fmt == 'eip712':
            if set(env) != {'format', 'payload', 'signature'} or not isinstance(env['payload'], dict):
                raise EncodingError('Envelope shape')
            body = env['payload']
            check_body_number_locations(body)
            valid, closed = body_validity(body)
            if valid != BODY_MEMBERS:
                raise EncodingError('Typed message cannot be built')
            chain_id, account = signer_account(body['signer'])
            digest = acceptance_digest(body)
        elif fmt == 'jws':
            if set(env) != {'format', 'signature'}:
                raise EncodingError('Envelope shape')
            header, body, payload_raw, message, signature = split_jws(env['signature'], acceptance=True)
            check_body_number_locations(body)
            if not isinstance(body.get('signer'), str) or not body['signer']:
                raise EncodingError('Signer missing')
            valid, closed = body_validity(body)
        else:
            raise EncodingError('Unknown envelope format')
    except (ValueError, TypeError, KeyError, OverflowError):
        return result('malformed', [INVALID])

    # Key step. Do not compute evidence bindings until signature succeeds.
    signing_key = None
    signing_address = None
    diagnostics = {}
    if fmt == 'jws':
        key_entry = next((k for k in trust.get('keys', []) if k.get('kid') == header['kid']), None)
        key_reason = None
        if key_entry is None:
            key_reason = 'key_missing'
        elif key_entry.get('signer') != body['signer']:
            key_reason = 'signer_mismatch'
        else:
            signing_key = bytes_key(key_entry, 'key')
            if signing_key is None or not valid_point(signing_key):
                key_reason = 'key_refused'
        if key_reason:
            return result('key_unresolved', reason=key_reason, policy_refusal=trust.get('complete') is True)
        if not ed25519_verify(signing_key, message, signature):
            return result('malformed', ['signature_invalid'])
    else:
        fact = next((d for d in chain if d.get('chainId') == chain_id and d.get('account') == account), None)
        if fact is None or type(fact.get('code')) is not bool:
            return result('key_unresolved', reason='chain_state_unavailable', policy_refusal=False)
        diagnostics = {'chainId': chain_id, 'account': account, 'block': fact.get('block')}
        sig = env['signature']
        if fact['code']:
            if not contractAccounts:
                return result('key_unresolved', reason='contract_accounts_unsupported', policy_refusal=False)
            if not isinstance(sig, str) or not re.fullmatch(r'0x(?:[0-9a-f]{2})*', sig):
                return result('malformed', ['signature_invalid'])
            call = next((c for c in fact.get('calls', []) if c.get('digest') == '0x' + digest.hex() and c.get('signature') == sig), None)
            if call is None:
                return result('key_unresolved', reason='chain_state_unavailable', policy_refusal=False)
            returned = call.get('returns')
            if call.get('revert') is True or not isinstance(returned, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', returned):
                return result('malformed', ['signature_invalid'])
            returned_bytes = bytes.fromhex(returned[2:])
            if len(returned_bytes) < 32 or returned_bytes[:32] != bytes.fromhex('1626ba7e' + '00' * 28):
                return result('malformed', ['signature_invalid'])
        elif recover_address(digest, sig) != account:
            return result('malformed', ['signature_invalid'])
        signing_address = account

    conditions = set()
    if valid != BODY_MEMBERS or not closed or body.get('disposition') not in ('accepted', 'rejected', 'disputed'):
        conditions.add(INVALID)
    if fmt == 'jws':
        try:
            if payload_raw != canonicalize(body):
                conditions.add(INVALID)
        except (ValueError, TypeError):
            conditions.add(INVALID)
    if 'confirmingParty' in valid and body['confirmingParty'] == '':
        conditions.add('confirming_party_absent')
    keys = issuer_keys(trust, body['deliveryIssuer']) if 'deliveryIssuer' in valid else []
    known_profile = isinstance(body.get('subject'), dict) and body['subject'].get('profile') == 'x402ev/1'
    evidence = authenticate_subject(subject, keys) if known_profile else None
    if 'deliveryIssuer' in valid:
        issuer = body['deliveryIssuer']
        same_name = (('confirmingParty' in valid and body['confirmingParty'] == issuer) or body['signer'] == issuer)
        same_key = signing_key is not None and (any(signing_key == bytes_key(k, 'ed25519') for k in keys) or (evidence and signing_key == evidence.key))
        same_account = signing_address is not None and any(address_equal(signing_address, k.get('address')) for k in keys)
        if same_name or same_key or same_account:
            conditions.add('acceptance_signer_is_issuer')
    term_digests = set()
    if evidence:
        if isinstance(body['subject'].get('reference'), str) and body['subject']['reference'] != evidence.reference:
            conditions.add('acceptance_record_digest_mismatch')
        if 'contextId' in valid and body['contextId'] != '0x' + evidence.reference.split(':')[-1]:
            conditions.add('acceptance_record_digest_mismatch')
        if 'outcomeDigest' in valid:
            if body['outcomeDigest'] != evidence.outcome or (outcome is not None and '0x' + sha(outcome) != body['outcomeDigest']):
                conditions.add('acceptance_outcome_digest_mismatch')
        if 'issuedAt' in valid and body['issuedAt'] < evidence.timestamp:
            conditions.add('acceptance_precedes_outcome')
        term_digests = qualifying_terms(terms, keys, evidence)
        if term_digests and 'termsDigest' in valid and body['termsDigest'] not in term_digests:
            conditions.add('acceptance_terms_digest_mismatch')
    if conditions:
        return result('malformed', conditions)
    disposition = body['disposition']
    if not known_profile:
        return result('unknown', disposition=disposition, reason='profile_unavailable')
    if evidence is None or not term_digests:
        return result('unknown', disposition=disposition, reason='evidence_unavailable')
    authority = body['authority']
    resolved = False
    if authority == {'mode': 'direct', 'profile': 'payer/0', 'reference': ''}:
        resolved = evidence.payer is not None and body['signer'] == body['confirmingParty'] == evidence.payer
    elif authority == {'mode': 'declared', 'profile': 'declared-evidence/0', 'reference': ''}:
        desired = {'confirmingParty': body['confirmingParty'], 'signer': body['signer'],
                   'subjectProfile': body['subject']['profile'], 'subjectReference': body['subject']['reference']}
        resolved = any(all(entry.get(k) == v for k, v in desired.items()) for entry in trust.get('authority', []))
    if not resolved:
        return result('unknown', ['acceptance_authority_unresolved'], disposition=disposition)
    output = result('verified', disposition=disposition)
    output['statementId'] = statement_id(body)
    if diagnostics:
        output['chainEvidence'] = diagnostics
    return output
