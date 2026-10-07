"""Fetch approved research CI artifacts without exposing credentials or signed URLs."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPO = 'Avadoll/legacywg-high-sierra'
MAX_ARCHIVE = 128 * 1024 * 1024

def gh(*args: str) -> str:
    result = subprocess.run(['gh', *args], capture_output=True, text=True, check=True, timeout=30)
    return result.stdout

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('run_id', type=int)
    parser.add_argument('commit')
    parser.add_argument('--verify-existing', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        raise SystemExit('Expected a full reviewed source commit')
    run = json.loads(gh('api', f'repos/{REPO}/actions/runs/{args.run_id}'))
    if run['head_sha'] != args.commit or run['conclusion'] != 'success':
        raise SystemExit('Run did not successfully build the expected source')
    artifacts = json.loads(gh('api', f'repos/{REPO}/actions/runs/{args.run_id}/artifacts'))['artifacts']
    matches = [a for a in artifacts if a['name'] == 'legacywg-platform-probe-' + args.commit and not a['expired']]
    if len(matches) != 1:
        raise SystemExit('Expected one unexpired native research artifact')
    artifact = matches[0]
    target = ROOT / '.cache' / f'artifact-{args.run_id}'
    if args.verify_existing:
        verify(target, args.run_id, args.commit, artifact['id'])
        return
    if target.exists():
        raise SystemExit('Download target already exists; refusing to overwrite')
    if artifact['size_in_bytes'] > MAX_ARCHIVE:
        raise SystemExit('Unexpectedly large archive')
    token = gh('auth', 'token').strip()
    request = urllib.request.Request(f'https://api.github.com/repos/{REPO}/actions/artifacts/{artifact["id"]}/zip',
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
    try:
        urllib.request.build_opener(NoRedirect()).open(request, timeout=30)
        raise RuntimeError('Expected storage redirect')
    except urllib.error.HTTPError as redirect:
        if redirect.code != 302:
            raise RuntimeError('Artifact redirect was unavailable') from None
        location = redirect.headers['Location']
    del request, token
    parsed = urllib.parse.urlparse(location)
    host = parsed.hostname or ''
    if parsed.scheme != 'https' or not any(host.endswith(suffix) for suffix in (
            '.blob.core.windows.net', '.actions.githubusercontent.com', '.githubusercontent.com')):
        raise RuntimeError('Unexpected artifact storage host')
    with urllib.request.urlopen(location, timeout=30) as response:
        data = response.read(MAX_ARCHIVE + 1)
    del location
    if len(data) > MAX_ARCHIVE:
        raise RuntimeError('Archive exceeds size limit')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if sum(member.file_size for member in archive.infolist()) > 512 * 1024 * 1024:
            raise RuntimeError('Expanded archive exceeds size limit')
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in member.filename or ':' in member.filename:
                raise RuntimeError('Unsafe archive path')
        target.mkdir(parents=True)
        archive.extractall(target)
    (target / 'archive-download.json').write_text(json.dumps({
        'archive_sha256': hashlib.sha256(data).hexdigest(), 'bytes_downloaded': len(data)}, indent=2) + '\n')
    verify(target, args.run_id, args.commit, artifact['id'])

def verify(target: Path, run_id: int, commit: str, artifact_id: int) -> None:
    native = target / 'Build' / 'CI'
    manifest = json.loads((native / 'client-manifest.json').read_text())
    if manifest['source_commit'] != commit:
        raise RuntimeError('Client manifest source differs from run')
    for name, digest in manifest['artifacts'].items():
        if Path(name).name != name or hashlib.sha256((native / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('Client artifact checksum mismatch')
    with zipfile.ZipFile(native / 'LegacyWG-research-0.2-app.zip') as archive:
        embedded = json.loads(archive.read('LegacyWG.app/Contents/Resources/BuildManifest.json'))
        worker = archive.read('LegacyWG.app/Contents/Helpers/legacywg-worker')
    if embedded['source_commit'] != commit:
        raise RuntimeError('Embedded client source differs from run')
    report = {'run_id': run_id, 'source_commit': commit, 'artifact_id': artifact_id,
        'client_checksums': 'PASS', 'embedded_source': 'PASS',
        'worker_sha256': hashlib.sha256(worker).hexdigest()}
    archive_metadata = target / 'archive-download.json'
    if archive_metadata.exists():
        report.update(json.loads(archive_metadata.read_text()))
    (target / 'download-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Network exceptions can include a private signed storage URL.
        raise SystemExit('Artifact fetch/verification failed: ' + type(error).__name__) from None
