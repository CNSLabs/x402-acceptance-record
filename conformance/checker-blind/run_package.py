#!/usr/bin/env python3
"""Rerun a bundled checker without replacing sources or changing historical logs."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
REVISIONS = {
    "frozen": ("checker-freeze-bec16636.bundle", "bec16636ff3c2afa0b7ec7a0a32ab2179f96817c", "checker"),
    "r1": ("checker-r1.bundle", "68bb522d71aa5a0e4a65da28020bae474ec5dbc8", "r1/checker"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", choices=REVISIONS, default="r1")
    parser.add_argument("--author", required=True, help="Name of the person recording this rerun")
    parser.add_argument("--output", required=True, type=Path, help="New report path; never overwritten")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        parser.error("output must be a new file outside the checker package")
    bundle, commit, copied = REVISIONS[args.revision]
    vector_path = ROOT.parent / "vectors/vectors.json"
    raw = vector_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != "8c20c905ae9af000f9664ee78bf73a6ac2c47f501c221789b835121a0af16ec5":
        raise ValueError("vector bytes differ from the reviewed corpus")
    corpus = json.loads(raw)
    with tempfile.TemporaryDirectory(prefix="acceptance-rerun-") as temporary:
        tree = Path(temporary) / "checker"
        subprocess.run(["git", "clone", "--quiet", str(ROOT / "provenance" / bundle), str(tree)], check=True)
        subprocess.run(["git", "-C", str(tree), "checkout", "--quiet", "--detach", commit], check=True)
        def git(*arguments):
            return subprocess.check_output(["git", "-C", str(tree), *arguments])
        for filename in git("ls-files", "-z").decode().split("\0"):
            if filename and (tree / filename).read_bytes() != (ROOT / copied / filename).read_bytes():
                raise ValueError("copied source differs from bundle: " + filename)
        archive_hash = hashlib.sha256(git("archive", commit)).hexdigest()
        if args.revision == "frozen" and archive_hash != "98aa4293a8094aeeeaa76fc153ee97f8dde319a08d0cef301352b5c7a00b22eb":
            raise ValueError("original freeze archive hash differs")
        manifest = json.loads((tree / "SOURCE-MANIFEST.json").read_text())
        if any(manifest.get(k) != v for k, v in corpus["specification"]["files"].items()):
            raise ValueError("checker specification pins differ from corpus")
        sys.path.insert(0, str(tree))
        import acceptance
        spec = importlib.util.spec_from_file_location("transport", ROOT / "runner/run_vectors.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        rows = []
        for vector in corpus["vectors"]:
            try:
                actual = acceptance.verify(runner.adapt_inputs(vector["inputs"], acceptance))
                passed = runner.normalize(actual) == runner.normalize(vector["expect"])
            except Exception as error:
                actual = {"exception": type(error).__name__, "message": str(error)}
                passed = False
            rows.append({**{k: vector[k] for k in ("id", "case", "variant", "form")},
                         "expected": vector["expect"], "actual": actual,
                         "outcome": "pass" if passed else "fail"})
        if git("status", "--porcelain").strip():
            raise ValueError("checker changed during rerun")
        report = {
            "author": args.author,
            "ranAt": datetime.now(timezone.utc).isoformat(),
            "platform": {"os": platform.platform(), "runtime": platform.python_version()},
            "checker": {"name": acceptance.NAME, "version": acceptance.VERSION,
                        "commit": commit, "archiveSha256": archive_hash, "dirty": False},
            "revision": args.revision,
            "vectorFile": {"path": "vectors/vectors.json", "sha256": digest},
            "profile": corpus["profile"], "specification": corpus["specification"],
            "totals": {"vectors": len(rows), "passed": sum(r["outcome"] == "pass" for r in rows),
                       "failed": sum(r["outcome"] == "fail" for r in rows)},
            "results": rows,
        }
        with output.open("x") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print(json.dumps({"revision": args.revision, "checkerCommit": commit, "totals": report["totals"]}))
        return int(report["totals"]["failed"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
