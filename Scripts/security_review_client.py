"""Review the downloaded Darwin worker and its production source call graph."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
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

def main() -> None:
    binary=Path(sys.argv[1]).resolve()
    if inspect(binary)['arch']!='x86_64':raise SystemExit('Expected the verified Darwin worker')
    info=subprocess.check_output([str(ROOT/'.tools/go1.27.1/go/bin/go.exe'),'version','-m',str(SCANNER)],text=True)
    if 'golang.org/x/vuln\tv1.8.0\t' not in info:raise SystemExit('Analyzer pin mismatch')
    EVIDENCE.mkdir(parents=True,exist_ok=True)
    env={**os.environ,'GOTOOLCHAIN':'local','GOENV':'off','GOFLAGS':'-mod=readonly','CGO_ENABLED':'0',
        'GOOS':'darwin','GOARCH':'amd64','GOCACHE':str(ROOT/'.cache/security-build'),
        'GOMODCACHE':str(ROOT/'.cache/gomod'),'GOROOT':str(ROOT/'.tools/go1.24.13/go'),
        'PATH':str(ROOT/'.tools/go1.24.13/go/bin')+os.pathsep+os.environ['PATH']}
    summary={'date':'2026-10-07','analyzer':'v1.8.0','target':'darwin/amd64','binary':binary.name,
        'limitation':'Limited Go analysis; does not audit Objective-C, installation, target OS or all attack paths','results':[]}
    for label,args in [('binary',['-mode=binary','-format=json',str(binary)]),
                       ('source',['-format=json','./Engine/worker'])]:
        result=subprocess.run([str(SCANNER),*args],env=env,cwd=ROOT,capture_output=True,text=True,timeout=180)
        (EVIDENCE/(label+'.json')).write_text(result.stdout,encoding='utf-8')
        (EVIDENCE/(label+'-stderr.txt')).write_text(result.stderr,encoding='utf-8')
        review=classify(result.stdout) if result.returncode in (0,3) else {'unreviewed_symbol_findings':['analysis failed']}
        summary['results'].append({'kind':label,'exit_code':result.returncode,
            'status':'PASS' if not review['unreviewed_symbol_findings'] else 'FAIL',**review})
    (EVIDENCE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    if any(item['status']=='FAIL' for item in summary['results']):sys.exit(1)

if __name__=='__main__':main()
