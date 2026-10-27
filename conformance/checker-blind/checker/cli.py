#!/usr/bin/env python3
"""CLI: verify <inputs.json> or selftest; no network at runtime."""
import argparse
import json
import sys
from pathlib import Path

from acceptance import InputRefused, parse_json, verify


def main():
    parser = argparse.ArgumentParser(description='Clean-room x402 acceptance record v0 checker')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('verify').add_argument('inputs', type=Path)
    sub.add_parser('selftest')
    args = parser.parse_args()
    if args.command == 'selftest':
        from selftest import run
        run()
        return 0
    try:
        inputs = parse_json(args.inputs.read_bytes())
        if not isinstance(inputs, dict):
            raise InputRefused('inputs must be a JSON object')
        output = verify(inputs)
    except (InputRefused, ValueError) as error:
        print(json.dumps({'input_refused': str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(output, ensure_ascii=False, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
