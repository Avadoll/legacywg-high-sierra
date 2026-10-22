"""Validate endpoint path decoding and observe native Intel CI egress read-only.

This driver never exports raw subprocess output. Reports contain the exact
status/boolean observation schema below, decoder result and validated source/OS
identity. Failure reasons are restricted to REASONS; no raw exception is emitted.
PASS/CHARACTERIZED means an observation completed; conservative route refusals
and absent IPv6 are valid observations, not proof of physical egress support.
"""

import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[1]
MARKER = "LEGACYWG_ROUTE_CHARACTERIZATION="
MAX_OUTPUT = 1024 * 1024
MAX_MARKER = 16384
NATIVE_TEST = "^TestNativeReadOnlyEgressCharacterization$"
DECODER_TESTS = frozenset({
    "TestScopedDecoderIPv4IPv6AndDefault",
    "TestScopedDecoderRefusesWrongIdentity",
    "TestScopedDecoderDirectHostAndDynamicLinkAddress",
    "TestUnscopedCompatibilityKeepsOptionalSourceAndNoPrefix",
    "TestScopedIPv6GatewayZoneAndInterfaceLoss",
    "TestReplyCorrelationRejectsEveryOtherRequest",
    "TestSharedAllocatorConcurrentUniqueAndPermanentlyExhausted",
    "TestCanceledQueryRefusesBeforeSocket",
    "TestKernelEndpointRouteRejectsUnsafeReplies",
    "TestScopedObservationDoesNotAdmitImplicitDefault",
    "TestScopedHostOwnershipMatchesOnlyExactStaticIdentity",
    "TestScopedHostDirectIPv6NeighborAnnotation",
})

FAMILY_STATUS = frozenset({
    "SCOPED_SNAPSHOT_PASS", "REFUSED_IMPLICIT_PRIMARY", "REFUSED_UNSCOPED_ROUTE", "NO_ROUTE",
    "QUERY_ERROR", "NOT_EN_ETHERNET", "SOURCE_UNASSIGNED", "PATH_CHANGED",
    "STRICT_QUERY_REFUSED",
})
STRICT_STATUS = frozenset({"PASS", "REFUSED", "NOT_RUN"})
CONCURRENT_STATUS = frozenset({
    "PASS_WITH_CROSS_REPLIES", "PASS_WITHOUT_OBSERVED_CROSS_REPLIES",
    "NOT_RUN", "FAILED_OR_CHANGED",
})
FAMILY_BOOLEANS = frozenset({
    "unscoped_query_succeeded", "scoped_query_succeeded", "en_interface_name",
    "ethernet_type", "interface_identity_current", "source_assigned",
    "scope_matches_egress", "path_matches_unscoped", "explicit_scoped_flag",
    "selected_route_is_default", "baseline_unchanged",
    "concurrent_queries_checked", "concurrent_queries_match",
    "shared_sequence_allocation_unique", "cross_replies_observed",
})
FIXED_OBSERVATIONS = {
    "read_only": True,
    "payload_packets_sent": False,
    "udp_sockets_opened": False,
    "route_mutations": False,
    "pf_mutations": False,
    "dns_queries": False,
    "network_metadata_exported": False,
    "physical_hardware_tested": False,
    "high_sierra_tested": False,
}
REASONS = frozenset({
    "CHARACTERIZED", "REQUIRES_DARWIN_AMD64", "REQUIRES_GITHUB_ACTIONS",
    "TOOLCHAIN_UNAVAILABLE", "TOOLCHAIN_MISMATCH", "TOOLCHAIN_CHECK_FAILED",
    "BUILD_FAILED", "BUILD_TIMEOUT", "NATIVE_FAILED", "NATIVE_TIMEOUT",
    "INVALID_REPORT", "OUTPUT_LIMIT", "INVALID_OUTPUT_PATH",
    "OUTPUT_WRITE_FAILED", "DRIVER_ERROR",
    "MISSING_SOURCE_IDENTITY", "DECODER_TESTS_FAILED", "DECODER_TESTS_TIMEOUT",
})


class OutputLimit(Exception):
    pass


def envelope(status, reason, observation=None, decoder_tests="NOT_RUN"):
    if status not in {"PASS", "NOT_RUN", "FAIL"} or reason not in REASONS:
        raise ValueError("Invalid driver result")
    if decoder_tests not in {"PASS", "NOT_RUN", "FAIL"}:
        raise ValueError("Invalid decoder result")
    source = os.environ.get("GITHUB_SHA", "")
    host_os = platform.mac_ver()[0]
    return {"driver_status": status, "reason": reason, "observation": observation,
            "decoder_tests": decoder_tests,
            "source_commit": source if re.fullmatch(r"[0-9a-f]{40}", source) else None,
            "host_os": host_os if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", host_os) else None,
            "host_arch": "amd64" if platform.machine() == "x86_64" else None}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("Invalid constant")


def validate_observation(value):
    expected = set(FIXED_OBSERVATIONS) | {"status", "ipv4", "ipv6"}
    if type(value) is not dict or set(value) != expected:
        raise ValueError("Invalid observation schema")
    if type(value["status"]) is not str or value["status"] not in {"COMPLETE", "FAILED"}:
        raise ValueError("Invalid observation status")
    for key, wanted in FIXED_OBSERVATIONS.items():
        if type(value[key]) is not bool or value[key] is not wanted:
            raise ValueError("Invalid observation scope")
    family_fields = set(FAMILY_BOOLEANS) | {"status", "strict_scoped_snapshot", "concurrent_status"}
    for name in ("ipv4", "ipv6"):
        family = value[name]
        if type(family) is not dict or set(family) != family_fields:
            raise ValueError("Invalid family schema")
        for key, vocabulary in (
            ("status", FAMILY_STATUS), ("strict_scoped_snapshot", STRICT_STATUS),
            ("concurrent_status", CONCURRENT_STATUS),
        ):
            if type(family[key]) is not str or family[key] not in vocabulary:
                raise ValueError("Invalid family status")
        if any(type(family[key]) is not bool for key in FAMILY_BOOLEANS):
            raise ValueError("Invalid family observation")
    return value


def parse_observation(stdout):
    markers = [line[len(MARKER):] for line in stdout.splitlines() if line.startswith(MARKER)]
    if len(markers) != 1 or len(markers[0].encode("utf-8")) > MAX_MARKER:
        raise ValueError("Invalid report marker")
    value = json.loads(markers[0], object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    return validate_observation(value)


def contained_path(candidate):
    base = ROOT.resolve()
    resolved = candidate.resolve()
    if resolved == base or base not in resolved.parents:
        raise ValueError("Invalid output path")
    return resolved


def write_report(path, report):
    # Re-resolve after making parents; export only the fixed sanitized artifact.
    path.parent.mkdir(parents=True, exist_ok=True)
    if contained_path(path) != path:
        raise ValueError("Invalid output path")
    name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".egress-", suffix=".json", delete=False) as handle:
            name = handle.name
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(name, path)
        name = None
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def _kill_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_captured(command, *, cwd, env, timeout):
    """Bound output in memory; kill the entire private subprocess group on failure."""
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    chunks = {"stdout": [], "stderr": []}
    count = 0
    lock = threading.Lock()
    oversized = threading.Event()
    reader_failed = threading.Event()

    def read_pipe(pipe, label):
        nonlocal count
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                with lock:
                    count += len(chunk)
                    if count > MAX_OUTPUT:
                        oversized.set()
                        _kill_process_group(process)
                        break
                    chunks[label].append(chunk)
        except (OSError, ValueError):
            reader_failed.set()
        finally:
            pipe.close()

    readers = [threading.Thread(target=read_pipe, args=(process.stdout, "stdout"), daemon=True),
               threading.Thread(target=read_pipe, args=(process.stderr, "stderr"), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        process.wait(timeout=5)
        raise
    finally:
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            _kill_process_group(process)
            reader_failed.set()
    if oversized.is_set():
        raise OutputLimit()
    if reader_failed.is_set():
        raise OSError("Subprocess capture failed")
    return subprocess.CompletedProcess(command, process.returncode,
                                       b"".join(chunks["stdout"]).decode("utf-8", errors="replace"),
                                       b"".join(chunks["stderr"]).decode("utf-8", errors="replace"))


def native_environment(build):
    environment = dict(os.environ)
    environment.update({
        "GOROOT": str(ROOT / ".tools" / "go1.24.13" / "go"),
        "GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off",
        "GO111MODULE": "on", "GOPROXY": "https://proxy.golang.org,direct",
        "GOSUMDB": "sum.golang.org", "GONOPROXY": "none", "GONOSUMDB": "none",
        "GOPRIVATE": "", "GOTELEMETRY": "off",
        "GOFLAGS": "-mod=readonly", "GOEXPERIMENT": "", "GODEBUG": "",
        "GOOS": "darwin", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0",
        "GOCACHE": str(build / "go-build"), "GOMODCACHE": str(ROOT / ".cache" / "gomod"),
        "GOPATH": str(build / "gopath"),
        "LEGACYWG_READONLY_ROUTE_CHARACTERIZATION": "1",
    })
    return environment


def characterize():
    if platform.system() != "Darwin" or platform.machine() != "x86_64":
        return envelope("NOT_RUN", "REQUIRES_DARWIN_AMD64")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return envelope("NOT_RUN", "REQUIRES_GITHUB_ACTIONS")
    if not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")):
        return envelope("FAIL", "MISSING_SOURCE_IDENTITY")
    go = ROOT / ".tools" / "go1.24.13" / "go" / "bin" / "go"
    if not go.is_file():
        return envelope("FAIL", "TOOLCHAIN_UNAVAILABLE")
    build = ROOT / "Build" / "EndpointPaths"
    try:
        for path in (build, build / "go-build", build / "gopath", build / "endpoint-paths.test"):
            contained_path(path)
    except (ValueError, OSError, RuntimeError):
        return envelope("FAIL", "INVALID_OUTPUT_PATH")
    build.mkdir(parents=True, exist_ok=True)
    environment = native_environment(build)
    try:
        version = run_captured([str(go), "version"], cwd=ROOT, env=environment, timeout=10)
    except subprocess.TimeoutExpired:
        return envelope("FAIL", "TOOLCHAIN_CHECK_FAILED")
    if version.returncode != 0:
        return envelope("FAIL", "TOOLCHAIN_CHECK_FAILED")
    if version.stdout.strip() != "go version go1.24.13 darwin/amd64":
        return envelope("FAIL", "TOOLCHAIN_MISMATCH")
    binary = build / "endpoint-paths.test"
    try:
        compiled = run_captured([str(go), "test", "-c", "-o", str(binary), "./NetworkCore"],
                                cwd=ROOT, env=environment, timeout=180)
    except subprocess.TimeoutExpired:
        return envelope("FAIL", "BUILD_TIMEOUT")
    if compiled.returncode != 0:
        return envelope("FAIL", "BUILD_FAILED")
    decoder_pattern = "^(" + "|".join(sorted(DECODER_TESTS)) + ")$"
    try:
        decoded = run_captured([str(go), "tool", "test2json", "-p", "legacywg/NetworkCore", "-t",
                               str(binary), "-test.run=" + decoder_pattern,
                               "-test.v=test2json", "-test.timeout=45s"],
                              cwd=ROOT, env=environment, timeout=60)
    except subprocess.TimeoutExpired:
        return envelope("FAIL", "DECODER_TESTS_TIMEOUT", decoder_tests="FAIL")
    try:
        events = [json.loads(line) for line in decoded.stdout.splitlines() if line.strip()]
        passed = {event.get("Test") for event in events if event.get("Action") == "pass"}
        decoder_passed = decoded.returncode == 0 and DECODER_TESTS <= passed
    except (ValueError, TypeError, AttributeError, RecursionError):
        decoder_passed = False
    if not decoder_passed:
        return envelope("FAIL", "DECODER_TESTS_FAILED", decoder_tests="FAIL")
    try:
        native = run_captured([str(binary), "-test.run=" + NATIVE_TEST,
                               "-test.v", "-test.timeout=45s"],
                              cwd=ROOT, env=environment, timeout=60)
    except subprocess.TimeoutExpired:
        return envelope("FAIL", "NATIVE_TIMEOUT", decoder_tests="PASS")
    try:
        observation = parse_observation(native.stdout)
    except (ValueError, TypeError, RecursionError):
        return envelope("FAIL", "INVALID_REPORT", decoder_tests="PASS")
    if native.returncode != 0 or observation["status"] != "COMPLETE":
        return envelope("FAIL", "NATIVE_FAILED", observation, decoder_tests="PASS")
    return envelope("PASS", "CHARACTERIZED", observation, decoder_tests="PASS")


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments:
            raise ValueError("Arguments are not supported")
        output = contained_path(ROOT / "Build" / "CI" / "endpoint-paths-ci.json")
    except (ValueError, OSError, RuntimeError):
        print("Read-only egress characterization failed: INVALID_OUTPUT_PATH", file=sys.stderr)
        return 1
    try:
        report = characterize()
    except OutputLimit:
        report = envelope("FAIL", "OUTPUT_LIMIT")
    except Exception:
        report = envelope("FAIL", "DRIVER_ERROR")
    try:
        write_report(output, report)
    except Exception:
        print("Read-only egress characterization failed: OUTPUT_WRITE_FAILED", file=sys.stderr)
        return 1
    print("Read-only egress characterization: " + report["driver_status"] + "/" + report["reason"])
    return 0 if report["driver_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
