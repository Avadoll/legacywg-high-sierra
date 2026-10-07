"""Compile a real AppKit compatibility probe, never a mock VPN client."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
from inspect_macho import inspect

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'Build' / 'CI'
APP = OUTPUT / 'LegacyWGPlatformProbe.app'


def run(arguments: list[str], timeout: int = 90) -> str:
    try:
        return subprocess.check_output(arguments, cwd=ROOT, text=True, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.CalledProcessError as error:
        print(error.output)
        raise


def main() -> None:
    if platform.system() != 'Darwin' or platform.machine() != 'x86_64':
        raise SystemExit('Native AppKit compilation requires the authorized Intel macOS builder')
    if APP.exists():
        raise SystemExit('Output app already exists; use a fresh build workspace rather than overwrite it')
    lock = json.loads((ROOT / 'deps.lock.json').read_text(encoding='utf-8'))
    contents = APP / 'Contents'
    for name in ('MacOS', 'Helpers', 'Resources', 'Resources/Licenses'):
        (contents / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'PlatformProbe' / 'Info.plist', contents / 'Info.plist')
    identity = os.environ.get('LEGACYWG_SIGNING_IDENTITY', '-')
    if identity != '-':
        available = run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'])
        if identity not in available or 'Developer ID Application:' not in available:
            raise SystemExit('Specified Developer ID identity is not available in the build keychain')
    sign_args = ['/usr/bin/codesign', '--force', '--sign', identity]
    sign_args += ['--timestamp=none'] if identity == '-' else ['--timestamp', '--options', 'runtime']
    engines = {}
    for label in ('baseline', 'candidate'):
        source = ROOT / 'Build' / 'Research' / ('wireguard-go-' + label + '-darwin-amd64')
        target = contents / 'Helpers' / ('wireguard-go-' + label)
        shutil.copyfile(source, target)
        target.chmod(0o755)
        run(sign_args + [str(target)])
        run(['/usr/bin/codesign', '--verify', '--strict', str(target)])
        component = next(item for item in lock['components'] if item['role'] == label)
        engines[label] = {'commit': component['commit'], 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    executable = contents / 'MacOS' / 'LegacyWGPlatformProbe'
    run(['/usr/bin/xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=10.13', '-fobjc-arc',
         '-Wall', '-Wextra', '-Werror', '-Wunguarded-availability', '-Wno-deprecated-declarations',
         '-framework', 'Cocoa', '-framework', 'Security', str(ROOT / 'PlatformProbe' / 'main.m'), '-o', str(executable)])
    source_commit = os.environ.get('GITHUB_SHA') or run(['git', 'rev-parse', 'HEAD']).strip()
    manifest = {'schema_version': 1, 'source_commit': source_commit, 'kind': 'platform-probe',
                'go': 'go1.24.13', 'deployment_target': '10.13.6', 'engines': engines,
                'signing_mode': 'ad-hoc' if identity == '-' else 'developer-id',
                'signed_for_distribution': False, 'high_sierra_runtime': 'NOT_RUN', 'vpn_ready': False}
    (contents / 'Resources' / 'BuildManifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    (contents / 'Resources' / 'THIRD_PARTY_NOTICES.md').write_bytes((ROOT / 'THIRD_PARTY_NOTICES.md').read_bytes())
    for path in (ROOT / 'Licenses').iterdir():
        if path.is_file(): shutil.copyfile(path, contents / 'Resources' / 'Licenses' / path.name)
    for label in ('baseline', 'candidate'):
        shutil.copyfile(ROOT / 'Vendor' / ('wireguard-' + label) / 'LICENSE',
                        contents / 'Resources' / 'Licenses' / ('wireguard-' + label + '-LICENSE'))
    run(sign_args + [str(APP)])
    run(['/usr/bin/codesign', '--verify', '--strict', '--deep', str(APP)])
    (OUTPUT / 'app-signature.txt').write_text(run(['/usr/bin/codesign', '-d', '--verbose=4', str(APP)]), encoding='utf-8')
    metadata = inspect(executable)
    minimums = [item['minos'] for item in metadata['versions']]
    if not minimums or any(item not in ('10.13.0', '10.13.6') for item in minimums):
        raise SystemExit('GUI executable deployment target changed unexpectedly')
    if plistlib.loads((contents / 'Info.plist').read_bytes())['LSMinimumSystemVersion'] != '10.13.6':
        raise SystemExit('App minimum OS changed unexpectedly')
    (OUTPUT / 'app-macho.json').write_text(json.dumps(metadata, indent=2)+'\n', encoding='utf-8')
    result = subprocess.run([str(executable), '--self-test'], cwd=ROOT, capture_output=True, text=True, timeout=20)
    (OUTPUT / 'app-self-test.json').write_text(result.stdout, encoding='utf-8')
    (OUTPUT / 'app-self-test-stderr.txt').write_text(result.stderr, encoding='utf-8')
    if result.returncode != 0:
        raise SystemExit('Real app/engine self-test failed on CI host; consult saved evidence')
    report = json.loads(result.stdout)
    if report.get('status') != 'PASS' or report.get('target_high_sierra') is not False:
        raise SystemExit('CI test did not produce the expected modern-host result')
    # Developer probes remain test artifacts; there is no root helper or VPN
    # installer and no claim of trusted distribution from an ad-hoc signature.
    zip_path = OUTPUT / 'LegacyWGPlatformProbe-test.zip'
    run(['/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(APP), str(zip_path)])
    app_source = OUTPUT / 'disk-image-source'
    app_source.mkdir()
    shutil.copytree(APP, app_source / APP.name)
    readme = ('Диагностическая сборка этапа A, не VPN-клиент.\n'
              'Локальная подпись не заменяет Developer ID и проверку доверия на High Sierra.\n'
              'Не отключайте Gatekeeper/SIP/quarantine.\n'
              'При разрешённом запуске: «Проверить движок» → «Сохранить результат».\n')
    (app_source / 'READ_ME_RU.txt').write_text(readme, encoding='utf-8')
    image = OUTPUT / 'LegacyWGPlatformProbe-test.dmg'
    run(['/usr/bin/hdiutil', 'create', '-quiet', '-format', 'UDZO', '-volname', 'LegacyWG Platform Probe',
         '-srcfolder', str(app_source), str(image)])
    checksums = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (zip_path, image)}
    (OUTPUT / 'SHA256SUMS.txt').write_text(''.join(f'{value}  {name}\n' for name, value in checksums.items()), encoding='utf-8')
    manifest['artifacts'] = checksums
    (OUTPUT / 'probe-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    # Keep only the compressed deliverables and evidence as artifact uploads.
    # Do not recursively remove the app: these intermediate files are useful
    # for CI diagnostics and disappear with the ephemeral runner itself.
    print('Built and tested real AppKit probe; High Sierra and VPN tests remain NOT_RUN.')


if __name__ == '__main__': main()
