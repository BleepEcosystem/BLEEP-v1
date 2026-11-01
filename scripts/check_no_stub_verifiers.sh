#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path
import re
import sys

checks = {
    "unconditional-true proof verifier": re.compile(
        r"\bfn\s+verify(?:_[A-Za-z0-9_]+)?\s*\([^{}]*?\)[^{}]*"
        r"\{\s*(?:return\s+)?Ok\s*\(\s*true\s*\)",
        re.DOTALL,
    ),
    "placeholder ZKP key material": re.compile(
        r"dummy_proving_key|dummy_verifying_key"
    ),
    "placeholder ZKP constructor": re.compile(
        r"BLEEPZKPModule::new\s*\("
    ),
    "placeholder ZKP key saver": re.compile(r"\bfn\s+save_keys\b"),
    "AI-local ZKP stub": re.compile(r"pub\s+struct\s+BLEEPZKPModule\s*;"),
    "state zk_snarks stub": re.compile(r"\bpub\s+mod\s+zk_snarks\b"),
    "metadata-only batch verifier": re.compile(
        r"\bfn\s+verify_batch_proof\b"
    ),
    "false batch-verification success log": re.compile(
        r"Batch STARK proof verified"
    ),
}

failed = False
for source in Path("crates").rglob("*.rs"):
    text = source.read_text(encoding="utf-8")
    for description, pattern in checks.items():
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            print(f"FATAL: {description} found in {source}:{line}", file=sys.stderr)
            failed = True

if failed:
    sys.exit(1)
PY
