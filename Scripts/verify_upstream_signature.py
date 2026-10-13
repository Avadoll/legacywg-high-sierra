"""Verify the baseline Git tag using the maintainer's published public key.

This validates the older baseline tag, not the unsigned newer candidate.
GPG uses a project-local keyring; no user keyring or ownertrust is changed.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
FINGERPRINT='AB9942E6D4A4CFC3412620A749FC7012A5DE03AE'
URL='https://www.zx2c4.com/keys/'+FINGERPRINT+'.asc'

def main() -> None:
    bundled=Path('C:/Program Files/Git/usr/bin/gpg.exe')
    gpg=str(bundled) if bundled.is_file() else shutil.which('gpg')
    if not gpg:raise SystemExit('Developer GPG tool is unavailable')
    repo=ROOT/'.cache/wireguard-upstream'
    if not (repo/'.git').is_dir():raise SystemExit('Expected reviewed upstream Git checkout')
    evidence=ROOT/'Docs/Evidence/SourceTrust'
    evidence.mkdir(parents=True,exist_ok=True)
    with urllib.request.urlopen(URL,timeout=30) as response:data=response.read(65537)
    if len(data)>65536 or b'-----BEGIN PGP PUBLIC KEY BLOCK-----' not in data:
        raise SystemExit('Unexpected public key payload')
    key=evidence/(FINGERPRINT+'.asc');key.write_bytes(data)
    home=ROOT/'.cache/gnupg';home.mkdir(parents=True,exist_ok=True)
    env={**os.environ,'GNUPGHOME':home.as_posix()}
    show=subprocess.run([gpg,'--homedir',home.as_posix(),'--batch','--with-colons','--show-keys',key.as_posix()],
        capture_output=True,text=True,env=env,check=True,timeout=30)
    if FINGERPRINT not in [line.split(':')[9] for line in show.stdout.splitlines() if line.startswith('fpr:')]:
        raise SystemExit('Published key fingerprint mismatch')
    subprocess.run([gpg,'--homedir',home.as_posix(),'--batch','--import',key.as_posix()],capture_output=True,env=env,check=True,timeout=30)
    raw=subprocess.check_output(['git','cat-file','-p','refs/tags/0.0.20250522'],cwd=repo,timeout=30)
    (evidence/'baseline-tag-object.txt').write_bytes(raw)
    result=subprocess.run(['git','-c','gpg.program='+gpg,'verify-tag','--raw','0.0.20250522'],
        cwd=repo,env=env,capture_output=True,text=True,timeout=30)
    (evidence/'baseline-tag-verification.txt').write_text(result.stdout+result.stderr,encoding='utf-8')
    if result.returncode!=0 or '[GNUPG:] VALIDSIG '+FINGERPRINT+' ' not in result.stderr:
        raise SystemExit('Baseline tag signature was not validated')
    report={'status':'PASS','verification':'baseline annotated tag signature against maintainer published key',
        'tag':'0.0.20250522','baseline_commit':'f333402bd9cbe0f3eeb02507bd14e23d7d639280',
        'signer_fingerprint':FINGERPRINT,'published_key_url':URL,'public_key_sha256':hashlib.sha256(data).hexdigest(),
        'identity_source':'HTTPS GPG link on https://www.zx2c4.com/ (upstream maintainer website)',
        'limitations':['No Web of Trust claim','Candidate commit 2631ce9 is not covered by this older tag signature']}
    (evidence/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
