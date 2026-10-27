"""Clean-room x402 acceptance v0 verifier. Built from specification text alone.

No network access. All trust and chain facts are caller-owned inputs. See README.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from functools import lru_cache
from typing import Any

import rfc8785
from coincurve import PublicKey
from Crypto.Hash import keccak
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

NAME = 'cleanroom-sol-python'
VERSION = '0.1.0'
MAX_SAFE = (1 << 53) - 1
HEX32 = re.compile(r'0x[0-9a-f]{64}\Z')
ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}\Z')
SIGNER = re.compile(r'eip155:([1-9][0-9]*):(0x[0-9a-f]{40})\Z')
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ED_P = (1 << 255) - 19
ED_L = (1 << 252) + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, -1, ED_P) % ED_P
BODY_MEMBERS = {'version', 'contextId', 'deliveryIssuer', 'confirmingParty', 'signer',
                'authority', 'termsDigest', 'outcomeDigest', 'subject', 'disposition', 'issuedAt'}
AUTH_MEMBERS = {'mode', 'profile', 'reference'}
SUBJECT_MEMBERS = {'profile', 'reference'}
MEMBER_INVALID = 'acceptance_member_invalid'


class InputRefused(ValueError):
    """Invalid caller configuration, not an AR-36 verification result."""


def _fail(message: str = 'invalid encoding'):
    raise ValueError(message)


def _pairs(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            _fail('duplicate JSON member')
        obj[k] = v
    return obj


def _unicode(value):
    if isinstance(value, str):
        value.encode('utf-8', 'strict')
    elif isinstance(value, dict):
        for k, v in value.items():
            _unicode(k)
            _unicode(v)
    elif isinstance(value, list):
        for v in value:
            _unicode(v)


def parse_json(text: str | bytes, *, acceptance_numbers: bool = False):
    """I-JSON syntax, preserving rejection of forbidden AR-6 numeric lexemes."""
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'strict')
    if not isinstance(text, str):
        _fail('JSON text required')
    text.encode('utf-8', 'strict')

    def integer(s):
        if acceptance_numbers and not re.fullmatch(r'0|[1-9][0-9]*', s):
            _fail('integer must be plain unsigned decimal')
        return int(s)

    def floating(s):
        if acceptance_numbers:
            _fail('fractional and exponent number syntax forbidden')
        n = float(s)
        if not __import__('math').isfinite(n):
            _fail('nonfinite JSON number')
        return n

    obj = json.loads(text, object_pairs_hook=_pairs, parse_int=integer,
                     parse_float=floating, parse_constant=lambda s: _fail('non-JSON constant'))
    _unicode(obj)
    return obj


def jcs(value) -> bytes:
    return rfc8785.dumps(value)


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def b64d(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r'[A-Za-z0-9_-]*', text):
        _fail('invalid base64url alphabet or padding')
    if len(text) % 4 == 1:
        _fail('invalid base64url length')
    data = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    if b64e(data) != text:
        _fail('nonzero unused base64url bits')
    return data


def key_bytes(value) -> bytes:
    """JSON binding: unpadded base64url, or explicit hex/base64url object."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        if 'key' in value:
            return key_bytes(value['key'])
        if 'publicKey' in value:
            return key_bytes(value['publicKey'])
        if set(value) == {'hex'}:
            return bytes.fromhex(value['hex'].removeprefix('0x'))
        if set(value) == {'base64url'}:
            return b64d(value['base64url'])
        _fail('unsupported key encoding')
    return b64d(value)


def _ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % ED_P
    b = (y1 + x1) * (y2 + x2) % ED_P
    c = 2 * ED_D * t1 * t2 % ED_P
    d = 2 * z1 * z2 % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P


def _ed_mul(p, n):
    out = (0, 1, 1, 0)
    while n:
        if n & 1:
            out = _ed_add(out, p)
        p = _ed_add(p, p)
        n >>= 1
    return out


@lru_cache(maxsize=4096)
def prime_order_point(encoded: bytes) -> bool:
    """AR-19/20: canonical compressed point, exact order L, not just cofactored."""
    if len(encoded) != 32:
        return False
    bits = int.from_bytes(encoded, 'little')
    sign, y = bits >> 255, bits & ((1 << 255) - 1)
    if y >= ED_P:
        return False
    denom = (ED_D * y * y + 1) % ED_P
    if not denom:
        return False
    x2 = (y * y - 1) * pow(denom, -1, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if x * x % ED_P != x2:
        x = x * pow(2, (ED_P - 1) // 4, ED_P) % ED_P
    if x * x % ED_P != x2 or (x == 0 and sign):
        return False
    if x & 1 != sign:
        x = ED_P - x
    if x == 0 and y == 1:
        return False
    q = _ed_mul((x, y, 1, x * y % ED_P), ED_L)
    return q[0] == 0 and (q[1] - q[2]) % ED_P == 0


def ed_verify(key: bytes, signature: bytes, message: bytes) -> bool:
    if (not prime_order_point(key) or len(signature) != 64
            or not prime_order_point(signature[:32])
            or int.from_bytes(signature[32:], 'little') >= ED_L):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        return True
    except (ValueError, InvalidSignature):
        return False


def keccak256(message: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=message).digest()


def uint_word(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < (1 << 256):
        _fail('uint256 out of range')
    return value.to_bytes(32, 'big')


def struct_hash(type_text: str, words: list[bytes]) -> bytes:
    return keccak256(keccak256(type_text.encode('ascii')) + b''.join(words))


def string_word(s: str) -> bytes:
    if not isinstance(s, str):
        _fail('string required')
    return keccak256(s.encode('utf-8'))


def parse_signer(s: str):
    m = SIGNER.fullmatch(s) if isinstance(s, str) else None
    if not m:
        _fail('invalid eip155 account')
    chain = int(m[1])
    if chain >= 1 << 256 or m[2] == '0x' + '0' * 40:
        _fail('invalid chain or zero signer')
    return chain, m[2]


def member_forms(b: dict) -> dict[str, bool]:
    """Independent form flags; closedness is separate, and booleans are not ints."""
    f = {k: False for k in BODY_MEMBERS}
    f['version'] = type(b.get('version')) is int and b['version'] == 0
    f['issuedAt'] = type(b.get('issuedAt')) is int and 0 <= b['issuedAt'] <= MAX_SAFE
    for k in ('contextId', 'termsDigest', 'outcomeDigest'):
        f[k] = isinstance(b.get(k), str) and bool(HEX32.fullmatch(b[k]))
    for k in ('deliveryIssuer', 'confirmingParty', 'signer', 'disposition'):
        f[k] = isinstance(b.get(k), str) and (bool(b[k]) if k in ('deliveryIssuer', 'signer') else True)
    for k, names in (('authority', AUTH_MEMBERS), ('subject', SUBJECT_MEMBERS)):
        f[k] = isinstance(b.get(k), dict) and all(isinstance(b[k].get(n), str) for n in names)
    return f


ACCEPTANCE_TYPE = ('Acceptance(uint256 version,bytes32 contextId,string deliveryIssuer,'
                   'string confirmingParty,uint256 signerChainId,address signerAccount,'
                   'Authority authority,bytes32 termsDigest,bytes32 outcomeDigest,'
                   'Subject subject,string disposition,uint64 issuedAt)'
                   'Authority(string mode,string profile,string reference)'
                   'Subject(string profile,string reference)')


def acceptance_digest(b: dict) -> bytes:
    if not isinstance(b, dict) or not all(member_forms(b).values()):
        _fail('cannot build typed message')
    chain, account = parse_signer(b['signer'])
    a, s = b['authority'], b['subject']
    ah = struct_hash('Authority(string mode,string profile,string reference)',
                     [string_word(a[k]) for k in ('mode', 'profile', 'reference')])
    sh = struct_hash('Subject(string profile,string reference)',
                     [string_word(s[k]) for k in ('profile', 'reference')])
    h = struct_hash(ACCEPTANCE_TYPE, [
        uint_word(b['version']), bytes.fromhex(b['contextId'][2:]),
        string_word(b['deliveryIssuer']), string_word(b['confirmingParty']), uint_word(chain),
        bytes.fromhex(account[2:]).rjust(32, b'\0'), ah,
        bytes.fromhex(b['termsDigest'][2:]), bytes.fromhex(b['outcomeDigest'][2:]), sh,
        string_word(b['disposition']), uint_word(b['issuedAt'])])
    domain = struct_hash('EIP712Domain(string name,string version)',
                         [string_word('x402 acceptance'), string_word('0')])
    return keccak256(b'\x19\x01' + domain + h)


def recover_address(signature: str, digest: bytes, *, acceptance: bool = True) -> str | None:
    pattern = r'0x[0-9a-f]{130}' if acceptance else r'0x[0-9a-fA-F]{130}'
    if not isinstance(signature, str) or not re.fullmatch(pattern, signature):
        return None
    sig = bytes.fromhex(signature[2:])
    r, s, v = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:64], 'big'), sig[64]
    if not 0 < r < SECP_N or not 0 < s < SECP_N:
        return None
    if acceptance and (s > SECP_N // 2 or v not in (27, 28)):
        return None
    if not acceptance and v in (0, 1):
        v += 27
    if v not in (27, 28):
        return None
    try:
        public = PublicKey.from_signature_and_message(sig[:64] + bytes([v - 27]), digest, hasher=None)
        return '0x' + keccak256(public.format(compressed=False)[1:])[-20:].hex()
    except ValueError:
        return None


def statement_id(body: dict) -> str:
    return 'x402accept/0:sha256:' + hashlib.sha256(jcs(body)).hexdigest()


def _issuer_keys(trust: dict, issuer: str) -> list:
    return [k for e in trust.get('issuers', []) if isinstance(e, dict) and e.get('issuer') == issuer
            for k in e.get('keys', [])]


def _issuer_address(entry) -> str | None:
    if isinstance(entry, str) and ADDRESS.fullmatch(entry):
        return entry.lower()
    if isinstance(entry, dict):
        address = entry.get('address', entry.get('account'))
        if isinstance(address, str) and ADDRESS.fullmatch(address):
            return address.lower()
    return None


def _issuer_ed(entry) -> bytes | None:
    try:
        if _issuer_address(entry) is not None:
            return None
        data = key_bytes(entry)
        return data if len(data) == 32 else None
    except (ValueError, TypeError):
        return None


def _parse_jws(compact: str, *, acceptance: bool):
    if not isinstance(compact, str) or len(parts := compact.split('.')) != 3:
        _fail('JWS compact required')
    h, p, s = map(b64d, parts)
    header = parse_json(h, acceptance_numbers=acceptance)
    if not isinstance(header, dict):
        _fail('protected header object required')
    if acceptance:
        if (set(header) != {'alg', 'kid', 'typ'} or header.get('alg') != 'EdDSA'
                or header.get('typ') != 'x402-acceptance+jws'):
            _fail('invalid acceptance protected header')
    elif header.get('alg') != 'EdDSA':
        _fail('only EdDSA offers supported by AR-29')
    if not isinstance(header.get('kid'), str) or not header['kid']:
        _fail('nonempty kid required')
    payload = parse_json(p, acceptance_numbers=acceptance)
    if not isinstance(payload, dict):
        _fail('payload object required')
    return header, payload, p, s, (parts[0] + '.' + parts[1]).encode('ascii')


def _authenticate_subject(info, issuer_keys):
    """AR-23/27 and pinned x402ev rule 1, not settlement/content checks."""
    try:
        if not isinstance(info, dict):
            return None
        if (info.get('scheme') != 'x402ev/1' or info.get('canonicalization') != 'RFC8785'
                or not all(isinstance(info.get(k), dict) for k in ('signer', 'payment', 'request', 'delivery'))):
            return None
        signer, payment, delivery = info['signer'], info['payment'], info['delivery']
        if signer.get('keyType') != 'Ed25519':
            return None
        key = b64d(signer['publicKey'])
        if key not in [_issuer_ed(k) for k in issuer_keys]:
            return None
        signature = signer['signature']
        if not isinstance(signature, str) or not signature.startswith('base64url:'):
            return None
        signature = b64d(signature[len('base64url:'):])
        if not all(isinstance(payment.get(k), str) and payment[k]
                   for k in ('network', 'payer', 'payee', 'asset', 'amount')):
            return None
        payer, payee = payment['payer'], payment['payee']
        if _address_equal(payer, payee) or payer in ('null', '0x' + '0' * 40) or payee in ('null', '0x' + '0' * 40):
            return None
        if (not isinstance(delivery.get('contentDigest'), str)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', delivery['contentDigest'])
                or type(delivery.get('timestamp')) is not int
                or not 0 <= delivery['timestamp'] <= MAX_SAFE):
            return None
        body = copy.deepcopy(info)
        body.pop('evidenceRef', None)
        body.pop('transparency', None)
        body['signer'].pop('signature', None)
        canonical = jcs(body)
        identity = 'x402ev/1:sha256:' + hashlib.sha256(canonical).hexdigest()
        if info.get('evidenceRef') != identity or not ed_verify(key, signature, canonical):
            return None
        payer_id = None
        if re.fullmatch(r'eip155:[0-9]+', payment['network']) and ADDRESS.fullmatch(payer):
            payer_id = payment['network'] + ':' + payer.lower()
        return {'reference': identity, 'outcomeDigest': '0x' + delivery['contentDigest'][7:],
                'time': delivery['timestamp'], 'payment': payment, 'payer': payer_id, 'key': key}
    except (ValueError, TypeError, KeyError, OverflowError, rfc8785.CanonicalizationError):
        return None


def _address_equal(left, right):
    if isinstance(left, str) and isinstance(right, str) and ADDRESS.fullmatch(left) and ADDRESS.fullmatch(right):
        return left.lower() == right.lower()
    return left == right


OFFER_TYPE = ('Offer(uint256 version,string resourceUrl,string scheme,string network,'
              'string asset,string payTo,string amount,uint256 validUntil)')


def offer_digest(payload: dict) -> bytes:
    h = struct_hash(OFFER_TYPE, [uint_word(payload['version']),
                    *[string_word(payload[k]) for k in ('resourceUrl', 'scheme', 'network', 'asset', 'payTo', 'amount')],
                    uint_word(payload['validUntil'])])
    domain = struct_hash('EIP712Domain(string name,string version,uint256 chainId)',
                         [string_word('x402 offer'), string_word('1'), uint_word(1)])
    return keccak256(b'\x19\x01' + domain + h)


def _qualifying_terms(terms, subject, issuer_keys) -> set[str]:
    qualifying = set()
    if not isinstance(terms, list):
        terms = [terms]  # convenient single-artifact API binding
    for artifact in terms:
        try:
            if not isinstance(artifact, dict):
                continue
            if artifact.get('format') == 'jws':
                if 'payload' in artifact:
                    continue
                h, p, raw, sig, signing = _parse_jws(artifact['signature'], acceptance=False)
                # Upstream §10 requires consistent JCS payload canonicalization.
                if raw != jcs(p):
                    continue
                candidates = [k for k in issuer_keys if not isinstance(k, dict) or k.get('kid') in (None, h['kid'])]
                if not any((key := _issuer_ed(k)) is not None and ed_verify(key, sig, signing) for k in candidates):
                    continue
            elif artifact.get('format') == 'eip712':
                p = artifact['payload']
                if not isinstance(p, dict) or not re.fullmatch(r'eip155:[0-9]+', p.get('network', '')):
                    continue
                if not ADDRESS.fullmatch(p.get('payTo', '')):
                    continue
                address = recover_address(artifact['signature'], offer_digest(p), acceptance=False)
                if address is None or address not in [_issuer_address(k) for k in issuer_keys]:
                    continue
            else:
                continue
            if type(p.get('version')) is not int or p['version'] != 1:
                continue
            if not all(isinstance(p.get(k), str) for k in ('resourceUrl', 'scheme', 'network', 'asset', 'payTo', 'amount')):
                continue
            if set(p) - {'version', 'resourceUrl', 'scheme', 'network', 'asset', 'payTo', 'amount', 'validUntil'}:
                continue
            if 'validUntil' in p and (type(p['validUntil']) is not int or not 0 <= p['validUntil'] <= MAX_SAFE):
                continue
            if p.get('validUntil', 0) and p['validUntil'] < subject['time']:
                continue
            payment = subject['payment']
            if (p['network'] != payment['network'] or p['amount'] != payment['amount']
                    or not _address_equal(p['asset'], payment['asset'])
                    or not _address_equal(p['payTo'], payment['payee'])):
                continue
            qualifying.add('0x' + hashlib.sha256(jcs(p)).hexdigest())
        except (ValueError, TypeError, KeyError, OverflowError, rfc8785.CanonicalizationError):
            continue
    return qualifying


def _chain_entry(chain, chain_id, account):
    if not isinstance(chain, list):
        return None
    for entry in chain:
        if (isinstance(entry, dict) and str(entry.get('chainId')) == str(chain_id)
                and _address_equal(entry.get('account'), account) and 'block' in entry
                and type(entry.get('hasCode')) is bool):
            return entry
    return None


def _outcome_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    if isinstance(value, dict) and set(value) == {'hex'}:
        return bytes.fromhex(value['hex'].removeprefix('0x'))
    if isinstance(value, dict) and set(value) == {'base64url'}:
        return b64d(value['base64url'])
    raise InputRefused('outcome must be bytes, UTF-8 text, or an explicit hex/base64url object')


def verify(inputs: dict) -> dict:
    """AR-35, in order. Caller configuration errors are exceptions, not results."""
    trust = inputs.get('trust', {})
    seen = set()
    for key in trust.get('keys', []):
        kid = key.get('kid')
        if kid in seen:
            raise InputRefused('duplicate trust.keys kid (AR-18): no verification result')
        seen.add(kid)

    def result(token, conditions=(), **members):
        return {'result': token, 'conditions': sorted(set(conditions)), **members}

    def key_unresolved(reason, *, jws=False):
        return result('key_unresolved', reason=reason,
                      policy_refusal=jws and trust.get('complete') is True)

    # Step 1: missing or explicitly null record is absent in this JSON binding.
    if inputs.get('record') is None:
        return result('no_record')

    # Step 2: preflight. No trust/key lookup is performed here.
    try:
        raw_record = inputs['record']
        if isinstance(raw_record, dict):
            raw_record = jcs(raw_record)
        envelope = parse_json(raw_record, acceptance_numbers=True)
        if not isinstance(envelope, dict):
            _fail('envelope must be object')
        fmt = envelope.get('format')
        if fmt == 'eip712':
            if set(envelope) != {'format', 'payload', 'signature'}:
                _fail('not a closed EIP-712 envelope')
            body = envelope['payload']
            digest = acceptance_digest(body)
            signer_chain, signer_account = parse_signer(body['signer'])
        elif fmt == 'jws':
            if set(envelope) != {'format', 'signature'}:
                _fail('not a closed JWS envelope')
            header, body, raw_payload, signature, signing = _parse_jws(envelope['signature'], acceptance=True)
            if not isinstance(body.get('signer'), str) or not body['signer']:
                _fail('nonempty signer required in preflight')
        else:
            _fail('unknown format')
    except (ValueError, TypeError, KeyError, OverflowError, rfc8785.CanonicalizationError):
        return result('malformed', [MEMBER_INVALID])

    # Step 3: resolve key/chain first, then verify exactly the designated signature.
    record_key = None
    record_account = None
    if fmt == 'jws':
        entry = next((k for k in trust.get('keys', []) if k.get('kid') == header['kid']), None)
        if entry is None:
            return key_unresolved('key_missing', jws=True)
        if entry.get('signer') != body['signer']:
            return key_unresolved('signer_mismatch', jws=True)
        try:
            record_key = key_bytes(entry.get('key'))
        except (ValueError, TypeError):
            return key_unresolved('key_refused', jws=True)
        if not prime_order_point(record_key):
            return key_unresolved('key_refused', jws=True)
        if not ed_verify(record_key, signature, signing):
            return result('malformed', ['signature_invalid'])
    else:
        record_account = signer_account
        facts = _chain_entry(inputs.get('chain'), signer_chain, signer_account)
        if facts is None:
            return key_unresolved('chain_state_unavailable')
        if not facts['hasCode']:
            if recover_address(envelope['signature'], digest) != signer_account:
                return result('malformed', ['signature_invalid'])
        else:
            if inputs.get('contractAccounts', True) is False:
                return key_unresolved('contract_accounts_unsupported')
            sig_text = envelope['signature']
            if not isinstance(sig_text, str) or not re.fullmatch(r'0x(?:[0-9a-f]{2})*', sig_text):
                return result('malformed', ['signature_invalid'])
            call = next((c for c in facts.get('calls', []) if c.get('digest') == '0x' + digest.hex()
                         and c.get('signature') == sig_text), None)
            if call is None:
                return key_unresolved('chain_state_unavailable')
            returned = call.get('returnData')
            if returned == 'revert' or call.get('revert') is True:
                return result('malformed', ['signature_invalid'])
            try:
                if not isinstance(returned, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', returned):
                    return result('malformed', ['signature_invalid'])
                returned = bytes.fromhex(returned[2:])
            except ValueError:
                return result('malformed', ['signature_invalid'])
            if len(returned) < 32 or returned[:32] != bytes.fromhex('1626ba7e' + '00' * 28):
                return result('malformed', ['signature_invalid'])

    # Step 4: aggregate every independent malformed condition, suppress dependencies.
    conditions = set()
    forms = member_forms(body)
    if (set(body) != BODY_MEMBERS or not all(forms.values())
            or (forms['authority'] and set(body['authority']) != AUTH_MEMBERS)
            or (forms['subject'] and set(body['subject']) != SUBJECT_MEMBERS)):
        conditions.add(MEMBER_INVALID)
    if forms['disposition'] and body['disposition'] not in ('accepted', 'rejected', 'disputed'):
        conditions.add(MEMBER_INVALID)
    if fmt == 'jws':
        try:
            if raw_payload != jcs(body):
                conditions.add(MEMBER_INVALID)
        except (ValueError, rfc8785.CanonicalizationError):
            conditions.add(MEMBER_INVALID)
    if forms['confirmingParty'] and not body['confirmingParty']:
        conditions.add('confirming_party_absent')
    keys = _issuer_keys(trust, body['deliveryIssuer']) if forms['deliveryIssuer'] else []
    subject = None
    known_profile = isinstance(body.get('subject'), dict) and body['subject'].get('profile') == 'x402ev/1'
    if known_profile and forms['deliveryIssuer']:
        subject = _authenticate_subject(inputs.get('subject'), keys)
    if forms['deliveryIssuer']:
        issuer = body['deliveryIssuer']
        if ((forms['confirmingParty'] and body['confirmingParty'] == issuer)
                or body['signer'] == issuer
                or (record_key is not None and (record_key in [_issuer_ed(k) for k in keys]
                                               or (subject is not None and record_key == subject['key'])))
                or (record_account is not None and record_account in [_issuer_address(k) for k in keys])):
            conditions.add('acceptance_signer_is_issuer')
    terms = set()
    if subject is not None:
        if ((isinstance(body['subject'].get('reference'), str) and body['subject']['reference'] != subject['reference'])
                or (forms['contextId'] and body['contextId'] != '0x' + subject['reference'].rsplit(':', 1)[1])):
            conditions.add('acceptance_record_digest_mismatch')
        if forms['outcomeDigest']:
            if (body['outcomeDigest'] != subject['outcomeDigest']
                    or ('outcome' in inputs and inputs['outcome'] is not None
                        and '0x' + hashlib.sha256(_outcome_bytes(inputs['outcome'])).hexdigest() != body['outcomeDigest'])):
                conditions.add('acceptance_outcome_digest_mismatch')
        if forms['issuedAt'] and body['issuedAt'] < subject['time']:
            conditions.add('acceptance_precedes_outcome')
        terms = _qualifying_terms(inputs.get('terms', []), subject, keys)
        if forms['termsDigest'] and terms and body['termsDigest'] not in terms:
            conditions.add('acceptance_terms_digest_mismatch')

    # Steps 5–9: terminal categories in normative priority order.
    if conditions:
        return result('malformed', conditions)
    if not known_profile:
        return result('unknown', reason='profile_unavailable', disposition=body['disposition'])
    if subject is None or not terms:
        return result('unknown', reason='evidence_unavailable', disposition=body['disposition'])
    authority = body['authority']
    resolved = False
    if authority == {'mode': 'direct', 'profile': 'payer/0', 'reference': ''}:
        resolved = subject['payer'] is not None and body['signer'] == body['confirmingParty'] == subject['payer']
    elif authority == {'mode': 'declared', 'profile': 'declared-evidence/0', 'reference': ''}:
        resolved = any(e.get('confirmingParty') == body['confirmingParty'] and e.get('signer') == body['signer']
                       and e.get('subjectProfile') == body['subject']['profile']
                       and e.get('subjectReference') == body['subject']['reference']
                       for e in trust.get('authority', []))
    if not resolved:
        return result('unknown', ['acceptance_authority_unresolved'], disposition=body['disposition'])
    return result('verified', disposition=body['disposition'])
