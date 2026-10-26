"""Corpus adapter/assertion runner. Expectations never enter verifier.verify."""
import argparse
import json
from pathlib import Path

from verifier import b64decode, parse_json, split_jws, statement_id, verify
from reporting import (ROOT, CORPUS_SHA256, digest, loaded_sources_log, now,
                       packet_pins, runtime_metadata, source_manifest, write_report)

NORMATIVE = ('result', 'conditions', 'disposition', 'reason', 'policy_refusal')


def decode_inputs(encoded):
    decoded = dict(encoded)
    for key in ('record', 'subject', 'outcome'):
        if key in decoded and decoded[key] is not None:
            decoded[key] = b64decode(decoded[key])
    decoded['terms'] = [b64decode(item) for item in decoded.get('terms', [])]
    return decoded


def comparison(actual, expected):
    errors = []
    for key in NORMATIVE:
        if (key in actual) != (key in expected):
            errors.append(f'{key}: presence differs')
        elif key in expected:
            if key == 'conditions':
                same = set(actual[key]) == set(expected[key])
            else:
                same = type(actual[key]) is type(expected[key]) and actual[key] == expected[key]
            if not same:
                errors.append(f'{key}: value differs')
    return errors


def run(output):
    pins = packet_pins()
    code_hashes = source_manifest()
    corpus = json.loads((ROOT / 'inputs/vectors.json').read_bytes())
    rows = []
    for vector in corpus['vectors']:
        inputs = decode_inputs(vector['inputs'])
        try:
            actual = verify(**inputs)
        except Exception as exc:
            actual = {'exception': type(exc).__name__, 'message': str(exc)}
        errors = comparison(actual, vector['expect'])
        row = {'id': vector['id'], 'actual': actual, 'expected': vector['expect'],
               'passed': not errors, 'differences': errors}
        if 'statementId' in vector:
            try:
                env = parse_json(inputs['record'], acceptance=True)
                body = env['payload'] if env['format'] == 'eip712' else split_jws(env['signature'], acceptance=True)[1]
                actual_id = statement_id(body)
            except Exception as exc:
                actual_id = f'{type(exc).__name__}: {exc}'
            row['statementId'] = {'actual': actual_id, 'expected': vector['statementId'],
                                  'passed': actual_id == vector['statementId']}
        rows.append(row)
    identity_rows = [r for r in rows if 'statementId' in r]
    report = {'created_utc': now(), 'method': 'Fresh-context Python implementation; reference acceptance implementations unopened; expectations visible to implementer but not verifier.',
              'pins': pins, 'corpus_sha256_before': CORPUS_SHA256,
              'runtime': runtime_metadata(), 'checker_sources': code_hashes,
              'summary': {'total': len(rows), 'passed': sum(r['passed'] for r in rows),
                          'failed': sum(not r['passed'] for r in rows),
                          'identity_total': len(identity_rows),
                          'identity_passed': sum(r['statementId']['passed'] for r in identity_rows)},
              'vectors': rows, 'corpus_sha256_after': digest(ROOT / 'inputs/vectors.json'),
              'loaded_library_and_module_sources': loaded_sources_log()}
    if report['corpus_sha256_after'] != CORPUS_SHA256:
        raise RuntimeError('Corpus changed during verification')
    write_report(output, report)
    print(json.dumps(report['summary']))
    for row in rows:
        if not row['passed']:
            print(json.dumps(row))
    return int(report['summary']['failed'] != 0 or report['summary']['identity_passed'] != len(identity_rows))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.output))
