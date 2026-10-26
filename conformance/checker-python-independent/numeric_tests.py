"""Independent canonicalization probes: RFC 8785 Appendix B and frozen data."""
import argparse
import csv
import io
import json
import struct
from pathlib import Path
from verifier import canonicalize, parse_json
from reporting import ROOT, now, packet_pins, runtime_metadata, source_manifest, write_report

# RFC 8785 Appendix B, expressed as raw binary64 bits, not host-language literals.
RFC8785 = [
 ('0000000000000000','0'), ('8000000000000000','0'),
 ('0000000000000001','5e-324'), ('8000000000000001','-5e-324'),
 ('7fefffffffffffff','1.7976931348623157e+308'), ('ffefffffffffffff','-1.7976931348623157e+308'),
 ('4340000000000000','9007199254740992'), ('c340000000000000','-9007199254740992'),
 ('4430000000000000','295147905179352830000'), ('7fffffffffffffff',None), ('7ff0000000000000',None),
 ('44b52d02c7e14af5','9.999999999999997e+22'), ('44b52d02c7e14af6','1e+23'),
 ('44b52d02c7e14af7','1.0000000000000001e+23'), ('444b1ae4d6e2ef4e','999999999999999700000'),
 ('444b1ae4d6e2ef4f','999999999999999900000'), ('444b1ae4d6e2ef50','1e+21'),
 ('3eb0c6f7a0b5ed8c','9.999999999999997e-7'), ('3eb0c6f7a0b5ed8d','0.000001'),
 ('41b3de4355555553','333333333.3333332'), ('41b3de4355555554','333333333.33333325'),
 ('41b3de4355555555','333333333.3333333'), ('41b3de4355555556','333333333.3333334'),
 ('41b3de4355555557','333333333.33333343'), ('becbf647612f3696','-0.0000033333333333333333'),
 ('43143ff3c1cb0959','1424953923781206.2')]


def canon_or_error(value):
    try:
        return canonicalize(value).decode('utf-8'), None
    except ValueError as exc:
        return None, type(exc).__name__


def run(output):
    pins = packet_pins()
    rows = []
    for bits, expected in RFC8785:
        actual, error = canon_or_error(struct.unpack('>d', bytes.fromhex(bits))[0])
        rows.append({'source': 'RFC8785-Appendix-B', 'bits': bits, 'expected': expected,
                     'actual': actual, 'error': error, 'passed': actual == expected})
    folder = ROOT / 'inputs/numeric-probes'
    supplied = json.loads((folder / 'stillmarcus-vectors.json').read_text())
    exact_input_lines = (folder / 'stillmarcus-inputs.txt').read_text().splitlines()
    if exact_input_lines != [v['json_text'] for v in supplied['vectors']]:
        raise RuntimeError('Numeric input text list mismatch')
    for item in supplied['vectors']:
        original = item['json_text']
        value = parse_json(original.encode('utf-8'))
        actual, error = canon_or_error(value)
        rows.append({'source': 'stillmarcus24/assurance-run', 'json_text': original,
                     'expected': item['required'], 'actual': actual, 'error': error,
                     'passed': actual == item['required']})
    tsv = (folder / 'jcs-number-vectors.tsv').read_text()
    for item in csv.DictReader(io.StringIO('\n'.join(line for line in tsv.splitlines() if not line.startswith('#'))), delimiter='\t'):
        value = parse_json(item['json'].encode('utf-8'))
        bits = struct.pack('>d', value).hex()
        actual, error = canon_or_error(value)
        rows.append({'source': 'aos-standard/catalog', 'json_text': item['json'], 'bits': bits,
                     'expected_bits': item['bits'], 'expected': item['expected'],
                     'actual': actual, 'error': error,
                     'passed': actual == item['expected'] and bits == item['bits']})
    summary = {}
    for source in sorted({r['source'] for r in rows}):
        items = [r for r in rows if r['source'] == source]
        summary[source] = {'total': len(items), 'passed': sum(r['passed'] for r in items),
                           'failed': sum(not r['passed'] for r in items)}
    report = {'created_utc': now(), 'pins': pins, 'runtime': runtime_metadata(),
              'checker_sources': source_manifest(), 'summary': summary, 'probes': rows,
              'limits': 'Supplemental numeric diagnostics, not new release commitments. Original JSON number spellings retained; no JavaScript pre-coercion.'}
    write_report(output, report)
    print(json.dumps(summary))
    for row in rows:
        if not row['passed']: print(json.dumps(row))
    return int(any(not r['passed'] for r in rows))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    raise SystemExit(run(parser.parse_args().output))
