"""Reproducibility helpers; not imported by the verifier."""
import hashlib
import importlib.metadata
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS_SHA256 = '8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_manifest():
    names = sorted([p.name for p in ROOT.glob('*.py')] + ['requirements.lock'])
    return {name: digest(ROOT / name) for name in names}


def runtime_metadata():
    versions = {d.metadata['Name']: d.version for d in importlib.metadata.distributions()}
    sodium = None
    try:
        import ctypes
        import nacl._sodium
        lib = ctypes.CDLL(nacl._sodium.__file__)
        lib.sodium_version_string.restype = ctypes.c_char_p
        sodium = lib.sodium_version_string().decode('ascii')
    except (AttributeError, OSError):
        sodium = 'not exposed by PyNaCl binary'
    return {'python': sys.version, 'implementation': platform.python_implementation(),
            'platform': platform.platform(), 'machine': platform.machine(),
            'libraries': dict(sorted(versions.items())), 'libsodium': sodium,
            'ecdsa_backend': 'eth_keys.backends.NativeECCBackend'}


def packet_pins():
    manifest = json.loads((ROOT / 'inputs/SOURCE-MANIFEST.json').read_text())
    for name, expected in manifest['files'].items():
        actual = digest(ROOT / 'inputs' / name)
        if actual != expected:
            raise RuntimeError(f'Packet hash mismatch: {name}: {actual}')
    if digest(ROOT / 'inputs/vectors.json') != CORPUS_SHA256:
        raise RuntimeError('Corpus changed')
    return manifest


def write_report(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Deliberately refuse overwriting prior attempts.
    with path.open('x') as out:
        json.dump(report, out, indent=2, ensure_ascii=False)
        out.write('\n')


def now():
    return datetime.now(timezone.utc).isoformat()


def loaded_sources_log():
    """Record every file-backed module loaded; dependencies are not acceptance code."""
    entries = []
    for name, module in sorted(sys.modules.items()):
        path = getattr(module, '__file__', None)
        if path and Path(path).is_file():
            entries.append({'module': name, 'path': str(Path(path).resolve()), 'sha256': digest(path)})
    return entries
