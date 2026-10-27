"""Synthetic-only selftest: creates fresh local keys, subject, offers and records.

No vectors or other implementations are imported or read. Published example shapes
and CASES.md expectations inform these checks; none of their placeholder bytes do.
"""
import copy
import hashlib
import json
import os

from coincurve import PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import acceptance as ar


def run():
    count = 0

    def check(label, condition):
        nonlocal count
        if not condition:
            raise AssertionError(label)
        count += 1

    def expect(label, inputs, expected):
        actual = ar.verify(inputs)
        check(label + ': ' + repr(actual) + ' != ' + repr(expected), actual == expected)

    def malformed(*conditions):
        return {'result': 'malformed', 'conditions': sorted(conditions)}

    def unknown(reason='evidence_unavailable'):
        return {'result': 'unknown', 'conditions': [], 'reason': reason, 'disposition': 'accepted'}

    def key_unknown(reason, refusal=False):
        return {'result': 'key_unresolved', 'conditions': [], 'reason': reason, 'policy_refusal': refusal}

    def public(key):
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    seller = Ed25519PrivateKey.generate()
    buyer = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    eoa = PrivateKey()
    sell_eoa = PrivateKey()
    buyer_address = '0x' + ar.keccak256(eoa.public_key.format(compressed=False)[1:])[-20:].hex()
    seller_address = '0x' + ar.keccak256(sell_eoa.public_key.format(compressed=False)[1:])[-20:].hex()
    payer = 'eip155:84532:' + buyer_address
    payee = '0x' + 'a1' * 20
    asset = '0x' + 'b2' * 20
    issuer = 'did:web:synthetic.example'
    t0 = 1791500000
    delivered = b'generated synthetic delivery\n'
    delivered_digest = hashlib.sha256(delivered).hexdigest()
    offer = {'version': 1, 'resourceUrl': 'https://synthetic.example/report', 'scheme': 'exact',
             'network': 'eip155:84532', 'asset': asset, 'payTo': payee,
             'amount': '10000', 'validUntil': t0 + 3600}

    def signed_jws(payload, key=buyer, kid='cp-selftest', acceptance=True, raw=None, header=None):
        if header is None:
            header = {'alg': 'EdDSA', 'kid': kid}
            if acceptance:
                header['typ'] = 'x402-acceptance+jws'
        hp = ar.b64e(ar.jcs(header)) + '.' + ar.b64e(ar.jcs(payload) if raw is None else raw)
        return {'format': 'jws', 'signature': hp + '.' + ar.b64e(key.sign(hp.encode('ascii')))}

    def sign_subject(subject):
        body = copy.deepcopy(subject)
        body.pop('evidenceRef', None)
        body.pop('transparency', None)
        body['signer'].pop('signature', None)
        canonical = ar.jcs(body)
        subject['evidenceRef'] = 'x402ev/1:sha256:' + hashlib.sha256(canonical).hexdigest()
        subject['signer']['signature'] = 'base64url:' + ar.b64e(seller.sign(canonical))
        return subject

    subject = sign_subject({'scheme': 'x402ev/1', 'canonicalization': 'RFC8785',
                           'payment': {'network': 'eip155:84532', 'payer': buyer_address,
                                       'payee': payee, 'amount': '10000', 'asset': asset},
                           'request': {'method': 'POST', 'urlHash': 'sha256:' + '12' * 32,
                                       'payloadHash': 'sha256:' + '34' * 32,
                                       'clientNonce': ar.b64e(os.urandom(16)), 'timestamp': t0 - 1},
                           'delivery': {'statusCode': 200, 'contentDigest': 'sha256:' + delivered_digest,
                                        'contentType': 'application/json', 'latencyMs': 1, 'timestamp': t0},
                           'signer': {'keyType': 'Ed25519', 'publicKey': ar.b64e(public(seller))}})
    body = {'version': 0, 'contextId': '0x' + subject['evidenceRef'].rsplit(':', 1)[1],
            'deliveryIssuer': issuer, 'confirmingParty': 'did:example:synthetic-buyer',
            'signer': 'did:example:synthetic-buyer',
            'authority': {'mode': 'declared', 'profile': 'declared-evidence/0', 'reference': ''},
            'termsDigest': '0x' + hashlib.sha256(ar.jcs(offer)).hexdigest(),
            'outcomeDigest': '0x' + delivered_digest,
            'subject': {'profile': 'x402ev/1', 'reference': subject['evidenceRef']},
            'disposition': 'accepted', 'issuedAt': t0 + 600}
    base = {'subject': subject, 'terms': [signed_jws(offer, seller, 'seller-test', False)],
            'trust': {'issuers': [{'issuer': issuer, 'keys': [{'kid': 'seller-test', 'key': ar.b64e(public(seller))},
                                                            {'address': seller_address}]}],
                      'keys': [{'kid': 'cp-selftest', 'signer': body['signer'], 'key': ar.b64e(public(buyer))}],
                      'authority': [{'confirmingParty': body['confirmingParty'], 'signer': body['signer'],
                                     'subjectProfile': 'x402ev/1', 'subjectReference': subject['evidenceRef']}]},
            'chain': [{'chainId': '84532', 'account': buyer_address, 'block': 1000, 'hasCode': False}]}
    good = {'result': 'verified', 'conditions': [], 'disposition': 'accepted'}

    def record(inputs, changed_body, fmt='jws', **options):
        if fmt == 'jws':
            envelope = signed_jws(changed_body, **options)
        else:
            digest = ar.acceptance_digest(changed_body)
            sig = eoa.sign_recoverable(digest, hasher=None)
            envelope = {'format': 'eip712', 'payload': changed_body,
                        'signature': '0x' + (sig[:64] + bytes([sig[64] + 27])).hex()}
        inputs['record'] = json.dumps(envelope, ensure_ascii=False, separators=(',', ':'))
        return inputs

    for fmt in ('jws', 'eip712'):
        b = copy.deepcopy(body)
        if fmt == 'eip712':
            b.update(signer=payer, confirmingParty=payer,
                     authority={'mode': 'direct', 'profile': 'payer/0', 'reference': ''})
        baseline = record(copy.deepcopy(base), b, fmt)
        expect(fmt + ' baseline', baseline, good)
        inp = copy.deepcopy(baseline)
        inp['outcome'] = delivered
        expect(fmt + ' delivered bytes', inp, good)
        for key, value, cond in [
            ('disposition', 'not_responded', ar.MEMBER_INVALID),
            ('confirmingParty', '', 'confirming_party_absent'),
            ('termsDigest', '0x' + '01' * 32, 'acceptance_terms_digest_mismatch'),
            ('outcomeDigest', '0x' + '02' * 32, 'acceptance_outcome_digest_mismatch'),
            ('contextId', '0x' + '03' * 32, 'acceptance_record_digest_mismatch'),
            ('issuedAt', t0 - 1, 'acceptance_precedes_outcome'),
        ]:
            changed = copy.deepcopy(b)
            changed[key] = value
            expect(fmt + ' ' + key, record(copy.deepcopy(base), changed, fmt), malformed(cond))
        changed = copy.deepcopy(b)
        changed['issuedAt'] = t0
        changed['disposition'] = 'rejected'
        expect(fmt + ' equality timestamp', record(copy.deepcopy(base), changed, fmt),
               {'result': 'verified', 'conditions': [], 'disposition': 'rejected'})
        expect(fmt + ' history independence', baseline, good)
        for label, mutation in [('missing subject', lambda x: x.pop('subject')),
                                ('missing terms', lambda x: x.update(terms=[])),
                                ('wrong receipt signature', lambda x: x['subject']['delivery'].update(latencyMs=2)),
                                ('nonqualifying terms', lambda x: x.update(terms=[signed_jws(
                                    dict(offer, amount='20000'), seller, 'seller-test', False)]))]:
            inp = copy.deepcopy(baseline)
            mutation(inp)
            expect(fmt + ' ' + label, inp, unknown())
        changed = copy.deepcopy(b)
        changed['subject']['profile'] = 'unknown/9'
        expect(fmt + ' unknown profile', record(copy.deepcopy(base), changed, fmt), unknown('profile_unavailable'))
        inp = copy.deepcopy(baseline)
        inp['outcome'] = b'wrong'
        expect(fmt + ' wrong outcome bytes', inp, malformed('acceptance_outcome_digest_mismatch'))
        changed = copy.deepcopy(b)
        changed['authority']['reference'] = 'unsupported'
        expect(fmt + ' unsupported authority', record(copy.deepcopy(base), changed, fmt),
               {'result': 'unknown', 'conditions': ['acceptance_authority_unresolved'], 'disposition': 'accepted'})
        inp = copy.deepcopy(baseline)
        eip_offer = dict(offer, validUntil=0)
        sig = sell_eoa.sign_recoverable(ar.offer_digest(eip_offer), hasher=None)
        inp['terms'] = [{'format': 'eip712', 'payload': eip_offer,
                         'signature': '0x' + (sig[:64] + bytes([sig[64] + 27])).hex()}]
        changed = copy.deepcopy(b)
        changed['termsDigest'] = '0x' + hashlib.sha256(ar.jcs(eip_offer)).hexdigest()
        expect(fmt + ' EIP712 zero-expiry offer', record(inp, changed, fmt), good)
        inp = copy.deepcopy(baseline)
        inp['terms'].insert(0, signed_jws(dict(offer, validUntil=t0+7200), seller, 'seller-test', False))
        expect(fmt + ' any qualifying terms', inp, good)
        inp = copy.deepcopy(baseline)
        inp['terms'] = [signed_jws(dict(offer, validUntil=t0 - 1), seller, 'seller-test', False)]
        expect(fmt + ' offer expired at outcome', inp, unknown())
        inp = copy.deepcopy(baseline)
        inp['subject']['transparency'] = {'logId': 'ignored after signing'}
        expect(fmt + ' transparency excluded', inp, good)
        changed = copy.deepcopy(b)
        changed['reason'] = 'not allowed'
        expect(fmt + ' closed body', record(copy.deepcopy(base), changed, fmt), malformed(ar.MEMBER_INVALID))

    jb = record(copy.deepcopy(base), copy.deepcopy(body))
    expect('no record', {}, {'result': 'no_record', 'conditions': []})
    inp = copy.deepcopy(jb)
    inp['trust']['complete'] = True
    inp['trust']['keys'] = []
    expect('missing complete key', inp, key_unknown('key_missing', True))
    inp['trust']['complete'] = 'true'
    expect('string true not declaration', inp, key_unknown('key_missing'))
    inp = copy.deepcopy(jb)
    inp['trust']['keys'][0]['signer'] = 'wrong-signer'
    expect('signer mismatch', inp, key_unknown('signer_mismatch'))
    for key in (b'\x01' + b'\0' * 31, ((1 << 255) - 19).to_bytes(32, 'little'), b'\0' * 32):
        inp = copy.deepcopy(jb)
        inp['trust']['keys'][0]['key'] = ar.b64e(key)
        expect('nonprime or noncanonical key', inp, key_unknown('key_refused'))
    inp = copy.deepcopy(jb)
    inp['trust']['keys'].append(copy.deepcopy(inp['trust']['keys'][0]))
    try:
        ar.verify(inp)
        check('duplicate kid refusal', False)
    except ar.InputRefused:
        check('duplicate kid refusal', True)
    inp = copy.deepcopy(jb)
    inp['trust']['keys'][0]['key'] = ar.b64e(public(seller))
    inp = record(inp, copy.deepcopy(body), key=seller)
    expect('issuer signing key', inp, malformed('acceptance_signer_is_issuer'))
    for bad in ('0.0', '0e0', '-0', '00'):
        raw = ar.jcs(body).replace(b'"version":0', ('"version":' + bad).encode())
        expect('bad numeric lexeme ' + bad, record(copy.deepcopy(base), body, raw=raw), malformed(ar.MEMBER_INVALID))
    raw = ar.jcs(body).replace(b'"issuedAt":1791500600', b'"issuedAt":1791500600,"issuedAt":1791500600')
    expect('duplicate payload member', record(copy.deepcopy(base), body, raw=raw), malformed(ar.MEMBER_INVALID))
    raw = ar.jcs(body).replace(b'"accepted"', b'"\xff"')
    expect('invalid UTF8 payload', record(copy.deepcopy(base), body, raw=raw), malformed(ar.MEMBER_INVALID))
    raw = ar.jcs(body).replace(b'"accepted"', b'"\\ud800"')
    expect('lone surrogate payload', record(copy.deepcopy(base), body, raw=raw), malformed(ar.MEMBER_INVALID))
    raw = json.dumps(body, separators=(',', ': ')).encode()
    expect('signed non-JCS body', record(copy.deepcopy(base), body, raw=raw), malformed(ar.MEMBER_INVALID))
    inp = record(copy.deepcopy(base), body, raw=raw)
    inp['trust']['keys'] = []
    expect('key before JCS comparison', inp, key_unknown('key_missing'))
    changed = copy.deepcopy(body)
    changed['outcomeDigest'] = '0xabc'
    changed['termsDigest'] = '0x' + 'ab' * 32
    expect('independent malformed conditions', record(copy.deepcopy(base), changed),
           malformed(ar.MEMBER_INVALID, 'acceptance_terms_digest_mismatch'))
    for mutation in ('bad-R', 'bad-S', 'flipped'):
        inp = copy.deepcopy(jb)
        envelope = json.loads(inp['record'])
        parts = envelope['signature'].split('.')
        sig = bytearray(ar.b64d(parts[2]))
        if mutation == 'bad-R':
            sig[:32] = b'\x01' + b'\0' * 31
        elif mutation == 'bad-S':
            sig[32:] = ar.ED_L.to_bytes(32, 'little')
        else:
            sig[63] ^= 1
        parts[2] = ar.b64e(sig)
        envelope['signature'] = '.'.join(parts)
        inp['record'] = json.dumps(envelope)
        expect('Ed signature ' + mutation, inp, malformed('signature_invalid'))
    inp = copy.deepcopy(jb)
    envelope = json.loads(inp['record'])
    parts = envelope['signature'].split('.')
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    parts[2] = parts[2][:-1] + alphabet[alphabet.index(parts[2][-1]) | 1]
    envelope['signature'] = '.'.join(parts)
    inp['record'] = json.dumps(envelope)
    expect('nonzero signature encoding trailing bits', inp, malformed(ar.MEMBER_INVALID))

    ebody = copy.deepcopy(body)
    ebody.update(signer=payer, confirmingParty=payer,
                 authority={'mode': 'direct', 'profile': 'payer/0', 'reference': ''})
    eb = record(copy.deepcopy(base), ebody, 'eip712')
    inp = copy.deepcopy(eb)
    inp['chain'] = []
    expect('chain facts needed even for EOA', inp, key_unknown('chain_state_unavailable'))
    for mutation in ('high-S', 'zero-v', 'uppercase', 'tampered-body'):
        inp = copy.deepcopy(eb)
        env = json.loads(inp['record'])
        sig = bytearray.fromhex(env['signature'][2:])
        if mutation == 'high-S':
            sig[32:64] = (ar.SECP_N - int.from_bytes(sig[32:64], 'big')).to_bytes(32, 'big')
            sig[64] = 55 - sig[64]
        elif mutation == 'zero-v':
            sig[64] -= 27
        elif mutation == 'tampered-body':
            env['payload']['termsDigest'] = '0x' + 'ca' * 32
        env['signature'] = '0x' + sig.hex()
        if mutation == 'uppercase':
            env['signature'] = '0x' + sig.hex().upper()
        inp['record'] = json.dumps(env)
        expect('EOA ' + mutation, inp, malformed('signature_invalid'))

    # A code-bearing account is always ERC-1271, including an EOA-shaped signature.
    digest = '0x' + ar.acceptance_digest(ebody).hex()
    env = json.loads(eb['record'])
    for returned, expected in [('0x1626ba7e' + '00' * 28, good),
                               ('0x1626ba7e' + '00' * 60, good),
                               ('0x1626ba7e' + '00' * 27, malformed('signature_invalid')),
                               ('0xffffffff' + '00' * 28, malformed('signature_invalid')),
                               ('revert', malformed('signature_invalid'))]:
        inp = copy.deepcopy(eb)
        inp['chain'][0].update(hasCode=True, calls=[{'digest': digest, 'signature': env['signature'], 'returnData': returned}])
        expect('ERC1271 ' + returned[:18], inp, expected)
    inp = copy.deepcopy(eb)
    inp['chain'][0].update(hasCode=True, calls=[])
    expect('ERC1271 missing exact call', inp, key_unknown('chain_state_unavailable'))
    inp['contractAccounts'] = False
    expect('ERC1271 unsupported', inp, key_unknown('contract_accounts_unsupported'))
    inp['contractAccounts'] = True
    env['signature'] = '0xAABB'
    inp['record'] = json.dumps(env)
    expect('ERC1271 syntax before absent call', inp, malformed('signature_invalid'))

    check('keccak is Ethereum keccak, not SHA3', ar.keccak256(b'').hex() ==
          'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
    check('JCS UTF16 ordering', ar.jcs({'\ue000': 1, '\U00010000': 2}) ==
          '{"\U00010000":2,"\ue000":1}'.encode())
    check('JCS ECMAScript float rendering', ar.jcs([1e-7, 1e20, 1.0]) == b'[1e-7,100000000000000000000,1]')
    check('statement identity', ar.statement_id(body) == 'x402accept/0:sha256:' + hashlib.sha256(ar.jcs(body)).hexdigest())
    print(f'selftest: {count} passed; 0 failed (fresh synthetic keys; no published vectors read)')
    return count
