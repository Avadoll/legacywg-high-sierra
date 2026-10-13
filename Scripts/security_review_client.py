"""Review the downloaded Darwin worker and its production source call graph."""
from __future__ import annotations
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import argparse
from datetime import datetime, timezone
from inspect_macho import inspect
from security_review import decode_stream

ROOT=Path(__file__).resolve().parents[1]
SCANNER=ROOT/'.tools/security/govulncheck.exe'
EVIDENCE=ROOT/'Docs/Evidence/ClientSecurity'

def classify(output: str) -> dict:
    events=decode_stream(output)
    advisories={event['osv']['id']:event['osv'] for event in events if 'osv' in event}
    findings=[event['finding'] for event in events if 'finding' in event]
    unreviewed=[];excluded=[]
    for finding in findings:
        trace=finding.get('trace',[])
        if not trace or not trace[0].get('function'):continue
        advisory=advisories.get(finding['osv'],{})
        if finding['osv']=='GO-2026-4971' and 'panic on Windows' in advisory.get('details',''):
            excluded.append({'id':finding['osv'],'status':'NOT_APPLICABLE','target':'darwin/amd64',
                'reason':'Official advisory explicitly limits the NUL panic to Windows',
                'source':'https://pkg.go.dev/vuln/GO-2026-4971'})
        else:unreviewed.append(finding)
    return {'all_finding_count':len(findings),'unreviewed_symbol_findings':unreviewed,'reviewed_exclusions':excluded}

def verify_reviewed_source(commit: str) -> dict:
    import re
    if not re.fullmatch(r'[0-9a-f]{40}',commit):raise SystemExit('Expected full reviewed source commit')
    checkout=ROOT/'.cache/ci-source'
    paths=subprocess.check_output(['git','ls-tree','-r','--name-only',commit,'--',
        'ConfigCore','NetworkCore','RecoveryCore','Engine/session','Engine/worker','Vendor/wireguard-candidate','go.mod','go.sum'],cwd=checkout,text=True).splitlines()
    paths=[path for path in paths if Path(path).suffix in ('.go','.mod','.sum')]
    local=[path.relative_to(ROOT).as_posix() for directory in ('ConfigCore','NetworkCore','RecoveryCore','Engine/session','Engine/worker','Vendor/wireguard-candidate')
        for path in (ROOT/directory).rglob('*') if path.is_file() and path.suffix in ('.go','.mod','.sum')]+['go.mod','go.sum']
    if set(paths)!=set(local):raise SystemExit('Production Go file set differs from reviewed native source')
    records=[]
    for name in sorted(paths):
        reviewed=subprocess.check_output(['git','show',commit+':'+name],cwd=checkout)
        actual=(ROOT/name).read_bytes().replace(b'\r\n',b'\n')
        if actual!=reviewed.replace(b'\r\n',b'\n'):raise SystemExit('Production Go source differs from reviewed native source: '+name)
        records.append({'path':name,'sha256_lf':hashlib.sha256(actual).hexdigest()})
    return {'status':'PASS','files':len(records),'manifest_sha256':hashlib.sha256(json.dumps(records,sort_keys=True).encode()).hexdigest(),
        'scope':'production Go tree including test/build-specific files; dependencies additionally pinned by lock'}

def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('--evidence-directory')
    parser.add_argument('--source-commit')
    args=parser.parse_args()
    binary=Path(args.binary).resolve()
    evidence=Path(args.evidence_directory).resolve() if args.evidence_directory else EVIDENCE
    if inspect(binary)['arch']!='x86_64':raise SystemExit('Expected the verified Darwin worker')
    info=subprocess.check_output([str(ROOT/'.tools/go1.27.1/go/bin/go.exe'),'version','-m',str(SCANNER)],text=True)
    if 'golang.org/x/vuln\tv1.8.0\t' not in info:raise SystemExit('Analyzer pin mismatch')
    evidence.mkdir(parents=True,exist_ok=True)
    env={**os.environ,'GOTOOLCHAIN':'local','GOENV':'off','GOFLAGS':'-mod=readonly','CGO_ENABLED':'0',
        'GOOS':'darwin','GOARCH':'amd64','GOCACHE':str(ROOT/'.cache/security-build'),
        'GOMODCACHE':str(ROOT/'.cache/gomod'),'GOROOT':str(ROOT/'.tools/go1.24.13/go'),
        'PATH':str(ROOT/'.tools/go1.24.13/go/bin')+os.pathsep+os.environ['PATH']}
    checked=datetime.now(timezone.utc)
    summary={'date':checked.date().isoformat(),'checked_at_utc':checked.isoformat(),
        'source_commit':args.source_commit,'analyzer':'v1.8.0','target':'darwin/amd64','binary':binary.name,
        'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'limitation':'Limited Go analysis; does not audit Objective-C, installation, target OS or all attack paths','results':[]}
    summary['source_identity']=verify_reviewed_source(args.source_commit) if args.source_commit else {'status':'NOT_VERIFIED'}
    for label,args in [('binary',['-mode=binary','-format=json',str(binary)]),
                       ('source',['-format=json','./Engine/worker'])]:
        result=subprocess.run([str(SCANNER),*args],env=env,cwd=ROOT,capture_output=True,text=True,timeout=180)
        (evidence/(label+'.json')).write_text(result.stdout,encoding='utf-8')
        (evidence/(label+'-stderr.txt')).write_text(result.stderr,encoding='utf-8')
        review=classify(result.stdout) if result.returncode in (0,3) else {'unreviewed_symbol_findings':['analysis failed']}
        summary['results'].append({'kind':label,'exit_code':result.returncode,
            'status':'PASS' if not review['unreviewed_symbol_findings'] else 'FAIL',**review})
    (evidence/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    if any(item['status']=='FAIL' for item in summary['results']):sys.exit(1)

if __name__=='__main__':main()
