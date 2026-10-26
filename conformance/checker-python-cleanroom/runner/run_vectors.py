#!/usr/bin/env python3
"""Post-freeze transport adapter/runner. Never edits checker/ or overwrites runs."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / 'checker'
NORMATIVE = ('result', 'conditions', 'disposition', 'reason', 'policy_refusal')


def logged_read(path: Path, detail: str = '') -> bytes:
    relative = path.relative_to(ROOT)
    with (ROOT / 'READ-LOG.md').open('a') as log:
        log.write(f'- {datetime.now(timezone.utc).isoformat()} — `{relative}` (post-freeze runner read{": " + detail if detail else ""})\n')
    return path.read_bytes()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=CHECKER,
                                   env=dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1'))


def adapt_inputs(inputs, ar):
    """Transport only: no vector ID, expectation, result or verification logic."""
    adapted = copy.deepcopy(inputs)
    if adapted.get('record') is not None:
        adapted['record'] = ar.b64d(adapted['record'])  # retain exact bytes, even invalid UTF-8
    if adapted.get('subject') is not None:
        adapted['subject'] = ar.parse_json(ar.b64d(adapted['subject']))
    adapted['terms'] = [ar.parse_json(ar.b64d(artifact)) for artifact in adapted.get('terms', [])]
    if adapted.get('outcome') is not None:
        adapted['outcome'] = ar.b64d(adapted['outcome'])
    for issuer in adapted.get('trust', {}).get('issuers', []):
        for key in issuer.get('keys', []):
            if isinstance(key, dict) and 'ed25519' in key:
                key['key'] = key.pop('ed25519')
    for facts in adapted.get('chain', []):
        if 'code' in facts:
            facts['hasCode'] = facts.pop('code')
        for call in facts.get('calls', []):
            if 'returns' in call:
                call['returnData'] = call.pop('returns')
    return adapted


def normalize(value):
    normalized = {k: value[k] for k in NORMATIVE if k in value}
    if 'conditions' in normalized:
        normalized['conditions'] = sorted(set(normalized['conditions']))
    return normalized


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vectors', type=Path, default=ROOT / 'inputs/stage2-vectors-after-freeze/vectors.json')
    parser.add_argument('--json', type=Path, required=True, help='new output file; existing files are never overwritten')
    args = parser.parse_args()
    output = args.json.resolve()
    if not output.is_relative_to(ROOT) or output.is_relative_to(CHECKER):
        parser.error('result must be inside task directory and outside checker/')
    if output.exists():
        parser.error('result exists; refusing to overwrite an immutable run')
    if not args.vectors.resolve().is_relative_to(ROOT / 'inputs/stage2-vectors-after-freeze'):
        parser.error('only staged stage-two vectors are allowed')
    freeze_text = logged_read(ROOT / 'FREEZE.md', 'provenance commit/tree').decode()
    freeze_commit = re.search(r'Commit .*?: `([0-9a-f]{40})`', freeze_text)[1]
    freeze_hash = re.search(r'archive SHA-256 .*?: `([0-9a-f]{64})`', freeze_text)[1]
    commit_before = git('rev-parse', 'HEAD').decode().strip()
    status_before = git('status', '--porcelain').decode()
    if status_before:
        raise RuntimeError('checker has uncommitted files; result refused')
    archive_hash = hashlib.sha256(git('archive', 'HEAD')).hexdigest()
    if commit_before == freeze_commit and archive_hash != freeze_hash:
        raise RuntimeError('frozen archive SHA-256 mismatch')
    raw = logged_read(args.vectors.resolve(), 'exact vector bytes')
    vectors = json.loads(raw)
    if len(vectors['vectors']) != 127:
        raise RuntimeError('expected exactly 127 staged vectors')
    manifest = json.loads(logged_read(CHECKER / 'SOURCE-MANIFEST.json', 'specification pins'))
    for name, digest in vectors['specification']['files'].items():
        if manifest.get(name) != digest:
            raise RuntimeError('stage-one source differs from vector specification pin: ' + name)
    with (ROOT / 'READ-LOG.md').open('a') as log:
        log.write(f'- {datetime.now(timezone.utc).isoformat()} — `checker/acceptance.py` (post-freeze import/execution; bytecode writes disabled)\n')
    sys.path.insert(0, str(CHECKER))
    import acceptance as ar

    rows = []
    for vector in vectors['vectors']:
        try:
            actual = ar.verify(adapt_inputs(vector['inputs'], ar))
        except Exception as error:
            # Never fabricate an AR-36 output for a thrown exception.
            actual = {'exception': type(error).__name__, 'message': str(error)}
        passed = 'exception' not in actual and normalize(actual) == normalize(vector['expect'])
        rows.append({**{k: vector[k] for k in ('id', 'case', 'variant', 'form')},
                     'expected': vector['expect'], 'outcome': 'pass' if passed else 'fail', 'actual': actual})
    if git('rev-parse', 'HEAD').decode().strip() != commit_before or git('status', '--porcelain').decode() != status_before:
        raise RuntimeError('checker changed while vectors ran; result refused')
    if hashlib.sha256(git('archive', 'HEAD')).hexdigest() != archive_hash:
        raise RuntimeError('checker committed tree changed during run')
    passed = sum(row['outcome'] == 'pass' for row in rows)
    result = {
        'author': 'CNS Labs clean-context agent (GPT-6.1 Sol, operated by Molt)',
        'platform': {'os': platform.platform(), 'machine': platform.machine(),
                     'runtime': 'Python ' + platform.python_version(), 'implementation': platform.python_implementation()},
        'checker': {'name': ar.NAME, 'language': 'python', 'version': ar.VERSION,
                    'commit': commit_before, 'dirty': False},
        'vectorFile': {'path': str(args.vectors.resolve().relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest()},
        'profile': vectors['profile'], 'specification': vectors['specification'],
        'ranAt': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        'provenance': {'freezeCommit': freeze_commit, 'checkerArchiveSha256': archive_hash,
                       'stageOneSourcesMatchSpecificationPins': True,
                       'runner': 'runner/run_vectors.py',
                       'note': 'Checker frozen before vector access. Runner only decodes transport and renames input binding fields.'},
        'totals': {'vectors': len(rows), 'passed': passed, 'failed': len(rows) - passed},
        'results': rows,
    }
    with output.open('x') as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)
        handle.write('\n')
    print(json.dumps({'totals': result['totals'], 'checkerCommit': commit_before,
                      'checkerDirty': False, 'vectorSha256': result['vectorFile']['sha256'],
                      'output': str(output.relative_to(ROOT))}, separators=(',', ':')))
    for row in rows:
        if row['outcome'] == 'fail':
            print('FAIL ' + row['id'] + ' expected=' + json.dumps(row['expected'], separators=(',', ':'))
                  + ' actual=' + json.dumps(row['actual'], separators=(',', ':')))
    return 0 if passed == len(rows) else 1


if __name__ == '__main__':
    sys.exit(main())
