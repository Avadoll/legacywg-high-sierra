"""Prepare a scoped pinned toolchain on an authorized Intel macOS CI host."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request
from finalize_lock import tree_hash

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    if platform.system() != 'Darwin' or platform.machine() != 'x86_64':
        raise SystemExit('Requires an authorized Intel macOS CI host')
    lock = json.loads((ROOT / 'deps.lock.json').read_text(encoding='utf-8'))
    for component in lock['components']:
        if tree_hash(ROOT / component['path']) != component['source_tree_sha256']:
            raise SystemExit('Source integrity differs from pinned lock')
    xcode = subprocess.check_output(['/usr/bin/xcodebuild', '-version'], text=True)
    if 'Xcode 16.4\n' not in xcode or 'Build version 16F6' not in xcode:
        raise SystemExit('Expected reviewed Xcode 16.4 / 16F6; refusing silent SDK changes')
    sdk = subprocess.check_output(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'], text=True).strip()
    if sdk != '15.5': raise SystemExit('Expected reviewed Apple macOS 15.5 SDK')
    output = ROOT / 'Build' / 'CI'
    output.mkdir(parents=True, exist_ok=True)
    host = {'source_commit': os.environ.get('GITHUB_SHA'), 'runner': os.environ.get('ImageVersion'),
            'os': platform.mac_ver()[0], 'arch': platform.machine(), 'xcode': xcode, 'sdk': sdk,
            'deployment_target': '10.13.6', 'target_high_sierra_test': 'NOT_RUN'}
    (output / 'build-host.json').write_text(json.dumps(host, indent=2)+'\n', encoding='utf-8')
    toolchain = next(item for item in lock['toolchains'] if item['version'] == 'go1.24.13')
    pin = next(item for item in toolchain['artifacts'] if item['filename'] == 'go1.24.13.darwin-amd64.tar.gz')
    cache = ROOT / '.cache'
    cache.mkdir(exist_ok=True)
    archive = cache / pin['filename']
    if not archive.exists():
        with urllib.request.urlopen('https://dl.google.com/go/' + pin['filename'], timeout=60) as response, archive.open('wb') as destination:
            while chunk := response.read(1024 * 1024): destination.write(chunk)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != pin['sha256']:
        raise SystemExit('Official Go archive checksum mismatch')
    target = ROOT / '.tools' / toolchain['version']
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as bundle:
        # Python 3.12+ data filter rejects unsafe paths and archive links.
        bundle.extractall(target, filter='data')
    print('Pinned sources, official Go archive and selected Xcode/SDK verified.')


if __name__ == '__main__': main()
