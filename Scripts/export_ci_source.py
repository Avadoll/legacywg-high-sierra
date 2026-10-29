"""Export a reviewed source allowlist without private project Git history."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / '.cache' / 'ci-source'
DIRECTORIES = ('ConfigCore', 'NetworkCore', 'RecoveryCore', 'NetworkAgent', 'Engine', 'PlatformProbe', 'Shared', 'Helper', 'App', 'Installer', 'Tests', 'Vendor', 'Licenses', '.github')
FILES = ('.gitignore', '.gitattributes', 'go.mod', 'go.sum', 'deps.lock.json', 'THIRD_PARTY_NOTICES.md')
SCRIPTS = ('bootstrap_macos_ci.py', 'build_macos.sh', 'build_platform_probe.py', 'build_uninstaller_macos.py',
           'finalize_lock.py', 'inspect_macho.py', 'security_review.py', 'verify_dependencies.py', 'test_mach_auth_macos.py', 'build_client_macos.py', 'security_review_client.py', 'test_installer_macos.py', 'fetch_ci_artifacts.py', 'verify_upstream_signature.py', 'probe_pf_macos.py', 'test_pf_guard_macos.py', 'test_pf_tcp_macos.py', 'test_pf_reference_macos.py', 'test_pf_anchor_macos.py', 'test_pf_lifecycle_macos.py', 'test_pf_rules_macos.py', 'test_endpoint_paths_macos.py', 'build_pf_single_rule_probe.py', 'review_legacy_receipt.py')
EVIDENCE = ('graph-baseline.txt', 'graph-candidate.txt')
PUBLIC_DOCS = ('READINESS.md', 'CLIENT_RESEARCH.md', 'ENDPOINT_RESOLUTION.md', 'STATUS_SEMANTICS.md',
               'GUI_BEHAVIOR.md', 'PF_RESEARCH.md', 'NETWORK_CHANGE.md', 'SCOPED_ENDPOINT.md', 'LEGACY_COMPATIBILITY.md', 'RECOVERY_JOURNAL.md')
PUBLIC_README = '''# LegacyWG experimental client

Research AppKit client for Intel macOS 10.13.6. The full product is not ready. Current native CI has verified IPv4/IPv6 split tunnels, simultaneous dual stack, routed OS DNS over UDP/TCP, authenticated Mach helper, Keychain, crash cleanup and a fresh unsigned research package on Intel macOS 15.7.9.

Native checks have verified bounded hostname bootstrap/encrypted localhost, independently encrypted peers and statistics, menu bar/live window launch/close, Keychain label rename and sanitized diagnostic preview/export. Duplicate normalized-name/exact-content import now offers exact-item replacement or a copy with a new name. Private selected-profile routing/addresses/endpoints and a bundled license viewer are implemented. Native Keychain/metadata tests and actual About/controller cancel/changed-state refusal sheets passed; active modal VPN heartbeat, file-picker/typed-copy/GUI replacement acceptance remains untested. Hostname bootstrap uses the existing system resolver before tunnel changes with a five-second total deadline; validation performs no lookup. One address is selected, IPv4 preferred, IPv6-only answers supported. Protected reconnect and automatic fallback are not implemented.

The worker captures initial endpoint paths using kernel RTM_GET and closes a split session when its path changes or cannot be checked. This bounded monitor is not traffic protection, persistent route ownership. A root-only utun/DNS journal now records intent/interface/configuration, refuses unsafe ACL/identity/corrupt records and passed five controlled SIGKILL checkpoints on modern CI. Authenticated startup/recover tests now verify RecoveryRequired on corruption, safe idempotency without intent and refusal to recover an active encrypted tunnel. GUI recovery controls and unknown-state latch are tested offscreen; live encrypted About/hidden-window/nested Quit and GUI SIGKILL cleanup have modern native evidence; recovery/error-Quit/accessibility/target acceptance remain open. It cannot undo physical routes/PF; see RECOVERY_JOURNAL.md. Current proof and limits are recorded in NETWORK_CHANGE.md.

Full tunnel, kill switch, physical route/PF journal, actual GUI recovery modal tests, sleep/network reconnect, GUI uninstall/update, High Sierra runtime and Developer ID distribution remain unfinished. Ad-hoc components and unsigned research pkg are not a trusted end-user installer. Do not disable Gatekeeper, SIP or quarantine.

Developer PF experiments verified existing keep-state UDP/TCP bypass, refusal before mutation on nonempty states, stateless UDP/owned-utun TCP4/TCP6 exception removal and normal own state expiry. A separate process-death experiment verified lost-token recovery and other-reference preservation, with synthetic identity mismatch refusal. These are research evidence: physical TCP/IPv6/DNS, foreign quick rules/concurrency, production durable PF journal and atomic reference compare-and-release are unproven. See PF_RESEARCH.md.

Run the manually dispatched free standard macOS feasibility workflow. Official unmodified WireGuard/toolchains are pinned with SHA256 in deps.lock.json; third-party licenses are retained. Candidate commit is unsigned; the older upstream baseline tag signature was verified against the key linked on the maintainer site. The project is independent of official WireGuard. Own-code license remains undecided.

[Current scope](Docs/READINESS.md), [verified native evidence](Docs/CLIENT_RESEARCH.md), [hostname limits](Docs/ENDPOINT_RESOLUTION.md).

Only reviewed source files are published. Private specification, original Git history, local tools/caches and user configuration/keys are excluded.
'''


def main() -> None:
    if TARGET.exists():
        raise SystemExit('CI source snapshot already exists; refusing to overwrite published or user-edited source')
    TARGET.mkdir(parents=True)
    for directory in DIRECTORIES:
        shutil.copytree(ROOT / directory, TARGET / directory)
    for filename in FILES:
        shutil.copyfile(ROOT / filename, TARGET / filename)
    (TARGET / 'Scripts').mkdir()
    for filename in SCRIPTS:
        shutil.copyfile(ROOT / 'Scripts' / filename, TARGET / 'Scripts' / filename)
    (TARGET / 'Docs' / 'Evidence').mkdir(parents=True)
    for filename in PUBLIC_DOCS:
        shutil.copyfile(ROOT / 'Docs' / filename, TARGET / 'Docs' / filename)
    for filename in EVIDENCE:
        shutil.copyfile(ROOT / 'Docs' / 'Evidence' / filename, TARGET / 'Docs' / 'Evidence' / filename)
    (TARGET / 'README.md').write_text(PUBLIC_README, encoding='utf-8')
    files = [path for path in TARGET.rglob('*') if path.is_file()]
    forbidden = ('.conf', '.p12', '.key', '.pem', '.mobileprovision')
    if any(path.suffix.lower() in forbidden for path in files):
        raise SystemExit('Forbidden credential/configuration suffix in export')
    if any(path.name == 'SPEC_RU.md' or '__pycache__' in path.parts or '.git' in path.parts for path in files):
        raise SystemExit('Private/history/cache file in export')
    manifest = [{'path': path.relative_to(TARGET).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in sorted(files)]
    (ROOT / '.cache' / 'ci-publication-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    subprocess.run(['git', 'init', '-b', 'main', str(TARGET)], check=True, capture_output=True)
    subprocess.run(['git', 'add', '.'], cwd=TARGET, check=True, capture_output=True)
    subprocess.run(['git', '-c', 'user.name=Codex', '-c', 'user.email=codex@localhost', '-c', 'commit.gpgsign=false',
                    'commit', '-q', '-m', 'Add pinned native macOS feasibility build and platform probe'], cwd=TARGET, check=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=TARGET, text=True).strip()
    print(json.dumps({'files': len(manifest), 'source_commit': commit, 'private_history_included': False,
                      'uploaded': False, 'snapshot': str(TARGET)}, indent=2))


if __name__ == '__main__': main()
