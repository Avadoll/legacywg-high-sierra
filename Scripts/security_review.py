"""Run a pinned current analyzer against built legacy research binaries."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "Docs" / "Evidence"
TOOL_GO = ROOT / ".tools" / "go1.27.1" / "go" / "bin" / "go.exe"
SCANNER = ROOT / ".tools" / "security" / "govulncheck.exe"
SCANNER_VERSION = "v1.8.0"


def decode_stream(text: str) -> list[dict]:
    decoder = json.JSONDecoder()
    result = []
    remaining = text.lstrip()
    while remaining:
        item, length = decoder.raw_decode(remaining)
        result.append(item)
        remaining = remaining[length:].lstrip()
    return result


def main() -> None:
    SCANNER.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod", "GOENV": "off",
           "GOCACHE": str(ROOT / ".cache" / "security-build"), "GOMODCACHE": str(ROOT / ".cache" / "gomod"),
           "GOBIN": str(SCANNER.parent), "CGO_ENABLED": "0", "GOOS": "windows", "GOARCH": "amd64"}
    if not SCANNER.exists():
        print("Building govulncheck " + SCANNER_VERSION, flush=True)
        subprocess.run([str(TOOL_GO), "install", "golang.org/x/vuln/cmd/govulncheck@" + SCANNER_VERSION], env=env, cwd=ROOT, check=True, timeout=360)
    info = subprocess.check_output([str(TOOL_GO), "version", "-m", str(SCANNER)], env=env, text=True)
    (EVIDENCE / "analyzer-buildinfo.txt").write_text(info, encoding="utf-8")
    if "golang.org/x/vuln\tv1.8.0\t" not in info:
        raise ValueError("Analyzer does not match reviewed pin")
    summaries = []
    for label in ("baseline", "candidate"):
        artifact = ROOT / "Build" / "Research" / ("wireguard-go-" + label + "-darwin-amd64")
        if not artifact.exists():
            summaries.append({"candidate": label, "status": "NOT_RUN", "reason": "Binary has not been built."})
            continue
        print("Scanning " + label, flush=True)
        result = subprocess.run([str(SCANNER), "-mode=binary", "-format=json", str(artifact)], env=env, cwd=ROOT,
                                capture_output=True, text=True, timeout=180)
        (EVIDENCE / ("govulncheck-" + label + ".json")).write_text(result.stdout, encoding="utf-8")
        (EVIDENCE / ("govulncheck-" + label + "-stderr.txt")).write_text(result.stderr, encoding="utf-8")
        if result.returncode not in (0, 3):
            summaries.append({"candidate": label, "status": "FAIL", "exit_code": result.returncode, "reason": "Analyzer failed; consult stderr evidence."})
            continue
        events = decode_stream(result.stdout)
        osv = {event["osv"]["id"]: event["osv"] for event in events if "osv" in event}
        findings = [event["finding"] for event in events if "finding" in event]
        symbol_findings = []
        reviewed_exclusions = []
        for finding in findings:
            trace = finding.get("trace", [])
            if not trace or not trace[0].get("function"): continue
            advisory = osv.get(finding["osv"], {})
            item = {"id": finding["osv"], "summary": advisory.get("summary"),
                    "fixed_version": finding.get("fixed_version"), "trace": trace}
            # This is a reviewed exception for these Darwin artifacts only,
            # based on the official advisory's explicit Windows-only scope.
            if finding["osv"] == "GO-2026-4971" and "panic on Windows" in advisory.get("details", ""):
                item.update({"status": "NOT_APPLICABLE", "target": "darwin/amd64",
                             "reason": "Official advisory describes Windows NUL-byte handling; these are Darwin binaries.",
                             "source": "https://pkg.go.dev/vuln/GO-2026-4971"})
                reviewed_exclusions.append(item)
            else:
                symbol_findings.append(item)
        # Keep a call-graph scan as separate evidence; symbol matches alone
        # do not prove that an exploitable path exists on the target OS.
        source_env = {**env, "GOOS": "darwin", "GOFLAGS": "-mod=readonly",
                      "GOROOT": str(ROOT / ".tools" / "go1.24.13" / "go"),
                      "PATH": str(ROOT / ".tools" / "go1.24.13" / "go" / "bin") + os.pathsep + os.environ["PATH"]}
        source = subprocess.run([str(SCANNER), "-format=json", "."],
                                cwd=ROOT / "Vendor" / ("wireguard-" + label), env=source_env,
                                capture_output=True, text=True, timeout=180)
        (EVIDENCE / ("govulncheck-" + label + "-source.json")).write_text(source.stdout, encoding="utf-8")
        (EVIDENCE / ("govulncheck-" + label + "-source-stderr.txt")).write_text(source.stderr, encoding="utf-8")
        source_failed = source.returncode not in (0, 3)
        source_events = decode_stream(source.stdout) if not source_failed else []
        source_osv = {event["osv"]["id"]: event["osv"] for event in source_events if "osv" in event}
        source_unreviewed = []
        for event in source_events:
            finding = event.get("finding", {})
            trace = finding.get("trace", [])
            if not trace or not trace[0].get("function"): continue
            advisory = source_osv.get(finding["osv"], {})
            if finding["osv"] == "GO-2026-4971" and "panic on Windows" in advisory.get("details", ""): continue
            source_unreviewed.append(finding)
        summaries.append({"candidate": label, "status": "FAIL" if symbol_findings or source_failed or source_unreviewed else "PASS", "exit_code": result.returncode,
                          "unreviewed_symbol_findings": symbol_findings, "reviewed_exclusions": reviewed_exclusions,
                          "source_scan_exit_code": source.returncode, "source_unreviewed_findings": source_unreviewed,
                          "all_finding_count": len(findings),
                          "limitation": "Binary analysis is conservative. Findings require applicability review; absence is not an audit."})
    summary = {"date": "2026-10-07", "analyzer": SCANNER_VERSION, "analyzer_toolchain": "go1.27.1", "results": summaries}
    (EVIDENCE / "security-summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    if any(item["status"] == "FAIL" for item in summaries): sys.exit(1)


if __name__ == "__main__": main()
