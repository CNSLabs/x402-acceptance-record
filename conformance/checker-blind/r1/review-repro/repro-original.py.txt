#!/usr/bin/env python3
"""Independent reproduction of Vic's 2026-10-26 16:03 review findings against the
frozen clean-room checker (commit bec16636). Built from Vic's description only,
with fresh synthetic keys; Vic's zip was not opened. The frozen checker is imported
read-only; nothing under checker/ is modified.

Cases
  A1 jws offer + subject, network eip155:84532            (baseline)
  A2 jws offer + subject, network "base"                   (Vic finding 1)
  B1 eip712 offer, version 1, validUntil 100, t0=50        (baseline)
  B2 B1 text with  "version":1.0                           (Vic finding 2a)
  B3 B1 text with  "validUntil":1e2                        (Vic finding 2b)
Each case runs through the real CLI (cli.py verify <file>) and, for B2/B3, also
through the Python API with plain json.loads (a runner's path).
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKER = HERE.parent / 'checker'
sys.path.insert(0, str(CHECKER))

from coincurve import PrivateKey                                   # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
import acceptance as ar                                            # noqa: E402


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


seller = Ed25519PrivateKey.generate()
buyer = Ed25519PrivateKey.generate()
sell_eoa = PrivateKey()
seller_address = '0x' + ar.keccak256(sell_eoa.public_key.format(compressed=False)[1:])[-20:].hex()
buyer_address = '0x' + 'c3' * 20
payee = '0x' + 'a1' * 20
asset = '0x' + 'b2' * 20
issuer = 'did:web:synthetic.example'
delivered = b'generated synthetic delivery\n'
delivered_digest = hashlib.sha256(delivered).hexdigest()


def sign_subject(subject):
    body = copy.deepcopy(subject)
    body.pop('evidenceRef', None)
    body.pop('transparency', None)
    body['signer'].pop('signature', None)
    canonical = ar.jcs(body)
    subject['evidenceRef'] = 'x402ev/1:sha256:' + hashlib.sha256(canonical).hexdigest()
    subject['signer']['signature'] = 'base64url:' + ar.b64e(seller.sign(canonical))
    return subject


def make_subject(network, t0):
    return sign_subject({'scheme': 'x402ev/1', 'canonicalization': 'RFC8785',
                         'payment': {'network': network, 'payer': buyer_address,
                                     'payee': payee, 'amount': '10000', 'asset': asset},
                         'request': {'method': 'POST', 'urlHash': 'sha256:' + '12' * 32,
                                     'payloadHash': 'sha256:' + '34' * 32,
                                     'clientNonce': ar.b64e(os.urandom(16)), 'timestamp': t0 - 1},
                         'delivery': {'statusCode': 200, 'contentDigest': 'sha256:' + delivered_digest,
                                      'contentType': 'application/json', 'latencyMs': 1, 'timestamp': t0},
                         'signer': {'keyType': 'Ed25519', 'publicKey': ar.b64e(public(seller))}})


def signed_jws(payload, key, kid, acceptance):
    header = {'alg': 'EdDSA', 'kid': kid}
    if acceptance:
        header['typ'] = 'x402-acceptance+jws'
    hp = ar.b64e(ar.jcs(header)) + '.' + ar.b64e(ar.jcs(payload))
    return {'format': 'jws', 'signature': hp + '.' + ar.b64e(key.sign(hp.encode('ascii')))}


def eip712_offer(payload):
    sig = sell_eoa.sign_recoverable(ar.offer_digest(payload), hasher=None)
    return {'format': 'eip712', 'payload': payload,
            'signature': '0x' + (sig[:64] + bytes([sig[64] + 27])).hex()}


def build(network, t0, offer_payload, offer_artifact):
    subject = make_subject(network, t0)
    body = {'version': 0, 'contextId': '0x' + subject['evidenceRef'].rsplit(':', 1)[1],
            'deliveryIssuer': issuer, 'confirmingParty': 'did:example:synthetic-buyer',
            'signer': 'did:example:synthetic-buyer',
            'authority': {'mode': 'declared', 'profile': 'declared-evidence/0', 'reference': ''},
            'termsDigest': '0x' + hashlib.sha256(ar.jcs(offer_payload)).hexdigest(),
            'outcomeDigest': '0x' + delivered_digest,
            'subject': {'profile': 'x402ev/1', 'reference': subject['evidenceRef']},
            'disposition': 'accepted', 'issuedAt': t0 + 10}
    record = signed_jws(body, buyer, 'cp-repro', True)
    inputs = {'subject': subject,
              'trust': {'issuers': [{'issuer': issuer, 'keys': [{'kid': 'seller-repro', 'key': ar.b64e(public(seller))},
                                                              {'address': seller_address}]}],
                        'keys': [{'kid': 'cp-repro', 'signer': body['signer'], 'key': ar.b64e(public(buyer))}],
                        'authority': [{'confirmingParty': body['confirmingParty'], 'signer': body['signer'],
                                       'subjectProfile': 'x402ev/1', 'subjectReference': subject['evidenceRef']}]},
              'chain': [],
              'record': json.dumps(record, ensure_ascii=False, separators=(',', ':'))}
    # terms spliced in as text so number spellings survive verbatim
    head = json.dumps(inputs, ensure_ascii=False, separators=(',', ':'))[:-1]
    art = json.dumps(offer_artifact, ensure_ascii=False, separators=(',', ':'))
    return head + ',"terms":[' + art + ']}'


def offer(network, valid_until):
    return {'version': 1, 'resourceUrl': 'https://synthetic.example/report', 'scheme': 'exact',
            'network': network, 'asset': asset, 'payTo': payee, 'amount': '10000', 'validUntil': valid_until}


py = sys.executable
cases = {}
# A: JWS offers, t0 large
t0 = 1791500000
o = offer('eip155:84532', t0 + 3600)
cases['A1_jws_eip155_baseline'] = build('eip155:84532', t0, o, signed_jws(o, seller, 'seller-repro', False))
o = offer('base', t0 + 3600)
cases['A2_jws_network_base'] = build('base', t0, o, signed_jws(o, seller, 'seller-repro', False))
# B: EIP-712 offers, t0 = 50 so validUntil 100 qualifies
t0 = 50
o = offer('eip155:84532', 100)
b1 = build('eip155:84532', t0, o, eip712_offer(o))
assert b1.count('"version":1,') == 1 and b1.count('"validUntil":100') == 1, 'splice check'
cases['B1_eip712_baseline'] = b1
cases['B2_eip712_version_1.0'] = b1.replace('"version":1,', '"version":1.0,')
cases['B3_eip712_validUntil_1e2'] = b1.replace('"validUntil":100', '"validUntil":1e2')

out = {'checker_commit': subprocess.run(['git', '-C', str(CHECKER), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip(),
       'checker_dirty': bool(subprocess.run(['git', '-C', str(CHECKER), 'status', '--porcelain'], capture_output=True, text=True).stdout.strip()),
       'python': py, 'cases': {}}
for name, text in cases.items():
    f = HERE / f'{name}.json'
    f.write_text(text)
    r = subprocess.run([py, str(CHECKER / 'cli.py'), 'verify', str(f)], capture_output=True, text=True, cwd=str(CHECKER))
    entry = {'cli_exit': r.returncode, 'cli_stdout': r.stdout.strip(), 'cli_stderr': r.stderr.strip()}
    if name.startswith('B'):
        try:
            entry['api_plain_json_loads'] = ar.verify(json.loads(text))
        except Exception as e:  # noqa: BLE001
            entry['api_plain_json_loads'] = {'exception': repr(e)}
    out['cases'][name] = entry
    print(f'{name:28s} exit={r.returncode} {r.stdout.strip() or r.stderr.strip()}')
(HERE / 'results.json').write_text(json.dumps(out, indent=2))
print('checker', out['checker_commit'][:8], 'dirty' if out['checker_dirty'] else 'clean')
