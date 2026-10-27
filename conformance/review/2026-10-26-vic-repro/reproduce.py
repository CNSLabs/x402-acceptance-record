#!/usr/bin/env python3
"""Run the five signed review fixtures without changing the frozen checker or logs."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
parser = argparse.ArgumentParser()
parser.add_argument("--package", type=Path, required=True, help="Directory containing checker/ and runner/")
parser.add_argument("--revision", choices=("frozen", "r1"), default="frozen")
args = parser.parse_args()
package = args.package.resolve()
sys.path.insert(0, str(package / ("r1/checker" if args.revision == "r1" else "checker")))
import acceptance
spec = importlib.util.spec_from_file_location("review_transport", package / "runner/run_vectors.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
packet = json.loads(Path(__file__).with_name("repro.json").read_text())
for case in packet["cases"]:
    actual = acceptance.verify(runner.adapt_inputs(case["inputs"], acceptance))
    print(json.dumps({"id": case["id"], "actual": actual,
        "matches_recorded_mike_result": runner.normalize(actual) == runner.normalize(case["mike_result"]),
        "matches_expected_result": runner.normalize(actual) == runner.normalize(case["our_result"])}, separators=(",", ":")))
