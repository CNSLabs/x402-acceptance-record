"""CLI accepting one VECTOR-FORMAT inputs object, with exact bytes in base64url."""
import argparse
import json
from pathlib import Path
import sys

from run_vectors import decode_inputs
from verifier import InputRefused, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Input JSON file, or - for stdin')
    args = parser.parse_args()
    raw = sys.stdin.buffer.read() if args.input == '-' else Path(args.input).read_bytes()
    try:
        data = json.loads(raw)
        output = verify(**decode_inputs(data))
    except InputRefused as exc:
        print(json.dumps({'input_refused': str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(output, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
