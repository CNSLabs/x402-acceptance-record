"""Additional verifier tests authored from normative requirements, not corpus rows."""
import argparse
import copy
import json
import unittest
from nacl.signing import SigningKey
from verifier import (EncodingError, InputRefused, L, b64encode, canonicalize,
                      ed25519_verify, parse_json, sha, valid_point, verify)
from reporting import now, runtime_metadata, source_manifest, write_report

SELLER = SigningKey(bytes(range(32)))
BUYER = SigningKey(bytes(range(32, 64)))


def jws(payload, key=BUYER, kid='test-buyer', acceptance=True, payload_bytes=None):
    header = {'alg': 'EdDSA', 'kid': kid}
    if acceptance:
        header['typ'] = 'x402-acceptance+jws'
    head = b64encode(canonicalize(header))
    body = b64encode(payload_bytes if payload_bytes is not None else canonicalize(payload))
    message = (head + '.' + body).encode('ascii')
    return head + '.' + body + '.' + b64encode(key.sign(message).signature)


def fixture():
    payment = {'network': 'eip155:1', 'payer': '0x' + '12' * 20,
               'payee': '0x' + '34' * 20, 'asset': 'native', 'amount': '27'}
    receipt_body = {'scheme': 'x402ev/1', 'canonicalization': 'RFC8785',
                    'payment': payment, 'request': {},
                    'delivery': {'timestamp': 42, 'contentDigest': 'sha256:' + sha(b'outcome')},
                    'signer': {'keyType': 'Ed25519', 'publicKey': b64encode(bytes(SELLER.verify_key))}}
    receipt = sign_receipt(receipt_body)
    offer = {'version': 1, 'resourceUrl': 'https://example.test/x', 'scheme': 'exact',
             'network': payment['network'], 'asset': payment['asset'], 'payTo': payment['payee'],
             'amount': payment['amount'], 'validUntil': 100}
    body = {'version': 0, 'contextId': '0x' + receipt['evidenceRef'].split(':')[-1],
            'deliveryIssuer': 'seller', 'confirmingParty': 'buyer', 'signer': 'buyer',
            'authority': {'mode': 'declared', 'profile': 'declared-evidence/0', 'reference': ''},
            'termsDigest': '0x' + sha(canonicalize(offer)), 'outcomeDigest': '0x' + sha(b'outcome'),
            'subject': {'profile': 'x402ev/1', 'reference': receipt['evidenceRef']},
            'disposition': 'accepted', 'issuedAt': 42}
    trust = {'issuers': [{'issuer': 'seller', 'keys': [{'kid': 'test-seller', 'ed25519': b64encode(bytes(SELLER.verify_key))}]}],
             'keys': [{'kid': 'test-buyer', 'signer': 'buyer', 'key': b64encode(bytes(BUYER.verify_key))}],
             'authority': [{'confirmingParty': 'buyer', 'signer': 'buyer',
                            'subjectProfile': 'x402ev/1', 'subjectReference': receipt['evidenceRef']}]}
    inputs = {'record': record(body), 'subject': canonicalize(receipt),
              'terms': [canonicalize({'format': 'jws', 'signature': jws(offer, SELLER, 'test-seller', False)})],
              'trust': trust}
    return body, receipt, offer, inputs


def sign_receipt(body):
    body = copy.deepcopy(body)
    body.pop('evidenceRef', None)
    body['signer'].pop('signature', None)
    preimage = canonicalize(body)
    signed = copy.deepcopy(body)
    signed['evidenceRef'] = 'x402ev/1:sha256:' + sha(preimage)
    signed['signer']['signature'] = 'base64url:' + b64encode(SELLER.sign(preimage).signature)
    return signed


def record(body, **kwargs):
    return canonicalize({'format': 'jws', 'signature': jws(body, **kwargs)})


class VerifierTests(unittest.TestCase):
    def test_independent_signed_delivery(self):
        body, receipt, offer, args = fixture()
        self.assertEqual(verify(**args)['result'], 'verified')
        args['outcome'] = b'outcome'
        self.assertEqual(verify(**args)['result'], 'verified')

    def test_missing_key_before_body_form(self):
        body, _, _, args = fixture()
        body['issuedAt'] = 'wrong type'
        body['confirmingParty'] = ''
        args['record'] = record(body)
        args['trust']['keys'] = []
        args['trust']['complete'] = 1
        self.assertEqual(verify(**args), {'result': 'key_unresolved', 'conditions': [],
                                          'reason': 'key_missing', 'policy_refusal': False})

    def test_invalid_signature_precedes_noncanonical_payload(self):
        body, _, _, args = fixture()
        compact = jws(body, payload_bytes=json.dumps(body).encode())
        parts = compact.split('.')
        from verifier import b64decode
        signature = bytearray(b64decode(parts[2])); signature[3] ^= 1
        parts[2] = b64encode(signature)
        args['record'] = canonicalize({'format': 'jws', 'signature': '.'.join(parts)})
        self.assertEqual(verify(**args)['conditions'], ['signature_invalid'])

    def test_bad_reference_form_skips_only_dependent_comparison(self):
        body, _, _, args = fixture()
        body['subject']['reference'] = None
        body['outcomeDigest'] = '0x' + '01' * 32
        body['issuedAt'] = 41
        args['record'] = record(body)
        self.assertEqual(set(verify(**args)['conditions']),
                         {'acceptance_member_invalid', 'acceptance_outcome_digest_mismatch', 'acceptance_precedes_outcome'})

    def test_duplicate_trust_kid_refused_without_result(self):
        _, _, _, args = fixture()
        args['trust']['keys'] *= 2
        with self.assertRaises(InputRefused): verify(**args)

    def test_stateless_after_unknown_and_bad_signature(self):
        _, _, _, args = fixture()
        before = verify(**args)
        modified = copy.deepcopy(args); modified['subject'] = None
        self.assertEqual(verify(**modified)['result'], 'unknown')
        self.assertEqual(verify(**args), before)

    def test_expiration_boundary_and_no_clock(self):
        body, _, offer, args = fixture()
        for expiration, expected in [(42, 'verified'), (41, 'unknown'), (0, 'verified')]:
            offer['validUntil'] = expiration
            body['termsDigest'] = '0x' + sha(canonicalize(offer))
            args['record'] = record(body)
            args['terms'] = [canonicalize({'format': 'jws', 'signature': jws(offer, SELLER, 'test-seller', False)})]
            self.assertEqual(verify(**args)['result'], expected)

    def test_unicode_utf16_key_order(self):
        self.assertEqual(canonicalize({'\ue000': 1, '\U00010000': 2}), '{"\U00010000":2,"\ue000":1}'.encode())
        self.assertNotEqual(canonicalize({'s': 'é'}), canonicalize({'s': 'e\u0301'}))

    def test_strict_parser(self):
        for raw in (b'{"x":1,"x":2}', b'"\\ud800"', b'"\xff"', b'NaN', b'1e400'):
            with self.subTest(raw=raw):
                with self.assertRaises(EncodingError): parse_json(raw)
        for raw in (b'-0', b'1.0', b'1e0', b'01', b'+1'):
            with self.subTest(raw=raw):
                with self.assertRaises(EncodingError): parse_json(raw, acceptance=True)

    def test_rfc8032_known_signature(self):
        # RFC 8032 section 7.1, TEST 1: empty message.
        key = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        sig = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
                            'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.assertTrue(ed25519_verify(key, b'', sig))
        self.assertFalse(ed25519_verify(key, b'x', sig))
        self.assertFalse(valid_point(b'\x01' + b'\x00' * 31))
        self.assertFalse(valid_point((2**255 - 19).to_bytes(32, 'little')))
        self.assertFalse(ed25519_verify(key, b'', sig[:32] + L.to_bytes(32, 'little')))


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw); self.records = []
    def addSuccess(self, test):
        super().addSuccess(test); self.records.append({'test': test.id(), 'passed': True})
    def addFailure(self, test, err):
        super().addFailure(test, err); self.records.append({'test': test.id(), 'passed': False, 'failure': self._exc_info_to_string(err, test)})
    def addError(self, test, err):
        super().addError(test, err); self.records.append({'test': test.id(), 'passed': False, 'error': self._exc_info_to_string(err, test)})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(VerifierTests)
    execution = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    write_report(args.output, {'created_utc': now(), 'runtime': runtime_metadata(),
                              'checker_sources': source_manifest(), 'tests': execution.records,
                              'summary': {'total': execution.testsRun, 'failures': len(execution.failures), 'errors': len(execution.errors)}})
    raise SystemExit(not execution.wasSuccessful())
