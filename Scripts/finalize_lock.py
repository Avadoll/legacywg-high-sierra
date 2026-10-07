"""Record downloaded module checksums and licenses without altering upstream."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
from security_review import decode_stream

ROOT = Path(__file__).resolve().parents[1]


def tree_hash(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((p for p in directory.rglob("*") if p.is_file()), key=lambda p: p.relative_to(directory).as_posix()):
        name = path.relative_to(directory).as_posix().encode("utf-8")
        digest.update(name + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def main() -> None:
    lock_file = ROOT / "deps.lock.json"
    lock = json.loads(lock_file.read_text(encoding="utf-8"))
    notices = ROOT / "Licenses"
    notices.mkdir(exist_ok=True)
    shutil.copyfile(ROOT / ".tools" / "go1.24.13" / "go" / "LICENSE", notices / "Go-LICENSE")
    shutil.copyfile(ROOT / ".tools" / "go1.24.13" / "go" / "PATENTS", notices / "Go-PATENTS")
    for component in lock["components"]:
        label = component["role"]
        directory = ROOT / component["path"]
        component["source_tree_sha256"] = tree_hash(directory)
        component["tree_hash_algorithm"] = "sha256(sorted(relative-path + NUL + sha256(file-bytes)))"
        component["go_mod_sha256"] = hashlib.sha256((directory / "go.mod").read_bytes()).hexdigest()
        component["go_sum_sha256"] = hashlib.sha256((directory / "go.sum").read_bytes()).hexdigest()
        component["module_graph"] = f"Docs/Evidence/graph-{label}.txt"
        data = (ROOT / "Docs" / "Evidence" / ("module-lock-" + label + ".txt")).read_text(encoding="utf-8")
        component["modules"] = []
        for module in decode_stream(data):
            if module.get("Main"): continue
            entry = {key: module[key] for key in ("Path", "Version", "Sum", "GoModSum", "Indirect") if key in module}
            entry["source"] = "https://proxy.golang.org/" + module["Path"] + "/@v/" + module["Version"] + ".zip"
            module_cache = ROOT / ".cache" / "gomod"
            archive = module_cache / "cache" / "download" / module["Path"] / "@v" / (module["Version"] + ".zip")
            if archive.exists(): entry["archive_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
            location = module_cache / (module["Path"] + "@" + module["Version"])
            license_file = location / "LICENSE"
            if license_file.exists():
                target = notices / (module["Path"].replace("/", "_") + "-" + module["Version"] + "-LICENSE")
                shutil.copyfile(license_file, target)
                entry["license"] = target.relative_to(ROOT).as_posix()
                entry["license_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            if module["Path"].startswith("golang.org/x/") or module["Path"] == "github.com/google/btree":
                entry["spdx"] = "BSD-3-Clause" if license_file.exists() else "NOASSERTION"
            elif module["Path"] == "golang.zx2c4.com/wintun": entry["spdx"] = "MIT"
            elif module["Path"] == "gvisor.dev/gvisor": entry["spdx"] = "Apache-2.0"
            else: entry["spdx"] = "NOASSERTION"
            entry["darwin_engine_included"] = module["Path"] in ("golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys")
            entry["local_patches"] = []
            component["modules"].append(entry)
    lock["analyzer"] = {"module": "golang.org/x/vuln", "version": "v1.8.0",
                        "commit": "709015412431dd2b5b28a53c06c70bc02d49074c",
                        "spdx": "BSD-3-Clause", "role": "build-time-analysis-only",
                        "build_info": "Docs/Evidence/analyzer-buildinfo.txt"}
    lock_file.write_text(json.dumps(lock, indent=2)+"\n", encoding="utf-8")
    print("Recorded source-tree integrity, full module graphs and available licenses.")


if __name__ == "__main__": main()
