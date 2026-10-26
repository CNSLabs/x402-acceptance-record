"""Exact-byte adapter for the public VECTOR-FORMAT input transport."""
from verifier import b64decode


def decode_inputs(encoded):
    decoded = dict(encoded)
    for key in ('record', 'subject', 'outcome'):
        if key in decoded and decoded[key] is not None:
            decoded[key] = b64decode(decoded[key])
    decoded['terms'] = [b64decode(item) for item in decoded.get('terms', [])]
    return decoded
