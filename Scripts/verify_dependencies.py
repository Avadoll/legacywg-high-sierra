"""Check vendored source trees against the project lock before any build."""
import json
from pathlib import Path
from finalize_lock import tree_hash

ROOT = Path(__file__).resolve().parents[1]
lock = json.loads((ROOT / "deps.lock.json").read_text(encoding="utf-8"))
for component in lock["components"]:
    actual = tree_hash(ROOT / component["path"])
    if actual != component["source_tree_sha256"]:
        raise SystemExit("FAIL: vendored source integrity differs from lock: " + component["role"])
print("PASS: vendored source integrity matches reviewed lock")
