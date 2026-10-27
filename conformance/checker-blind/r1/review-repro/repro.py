#!/usr/bin/env python3
"""Generate five fresh signed review fixtures against r1 in a NEW output directory.

This is a post-review packaging fix to the reproduction helper, not a checker change.
The original helper is preserved as repro-original.py.txt. Existing recorded fixtures
and results are never overwritten. --help and importing this module perform no run.
"""
import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CHECKER = HERE.parent / 'checker'
PACKAGE = HERE.parents[2]  # The enclosing conformance/ (or source v0/) package.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True,
                        help='New directory outside the conformance package; existing paths are refused')
    args = parser.parse_args()
    destination = args.output_dir.resolve()
    if destination == PACKAGE or PACKAGE in destination.parents:
        parser.error('--output-dir must be outside the conformance package')
    if destination.exists():
        parser.error('--output-dir must not already exist')

    # Parse help/arguments before importing dependencies or generating keys.
    sys.path.insert(0, str(CHECKER))
    from coincurve import PrivateKey                                   # noqa: E402
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
    import acceptance as ar                                            # noqa: E402

    destination.mkdir(parents=True, exist_ok=False)

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

    out = {'checker_revision': 'r1', 'checker_version': ar.VERSION,
           'checker_source_sha256': {name: hashlib.sha256((CHECKER / name).read_bytes()).hexdigest()
                                     for name in ('acceptance.py', 'cli.py', 'requirements.lock')},
           'python': py, 'cases': {}}
    for name, text in cases.items():
        f = destination / f'{name}.json'
        with f.open('x') as handle:
            handle.write(text)
        r = subprocess.run([py, '-B', str(CHECKER / 'cli.py'), 'verify', str(f)], capture_output=True, text=True, cwd=str(CHECKER))
        entry = {'cli_exit': r.returncode, 'cli_stdout': r.stdout.strip(), 'cli_stderr': r.stderr.strip()}
        if name.startswith('B'):
            try:
                entry['api_plain_json_loads'] = ar.verify(json.loads(text))
            except Exception as e:  # noqa: BLE001
                entry['api_plain_json_loads'] = {'exception': repr(e)}
        out['cases'][name] = entry
        print(f'{name:28s} exit={r.returncode} {r.stdout.strip() or r.stderr.strip()}')
    with (destination / 'results.json').open('x') as handle:
        json.dump(out, handle, indent=2)
        handle.write('\n')
    print('new reproduction:', destination)
    return int(any(case['cli_exit'] != 0 for case in out['cases'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
