"""Read-only developer PF feasibility evidence, never a shipped guard."""
from __future__ import annotations
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
COMMANDS={
    'info':['-s','info'],
    'root_rules':['-s','rules'],
    'all_anchor_rules':['-a','*','-s','rules'],
    'anchors':['-s','Anchors'],
}

def read(kind: str) -> str:
    # Fixed read-only argv; no -f/-F/-e/-E/-d/-X/-k operation is permitted.
    result=subprocess.run(['/usr/bin/sudo','-n','/sbin/pfctl',*COMMANDS[kind]],
        stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10,
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'})
    if result.returncode or len(result.stdout.encode())>512*1024:
        raise RuntimeError('PF read-only inspection unavailable')
    return result.stdout

def main() -> None:
    if os.uname().sysname!='Darwin':raise SystemExit('Native macOS developer probe only')
    output=ROOT/'Build/CI';output.mkdir(parents=True,exist_ok=True)
    report={'kind':'read-only-pf-feasibility','read_only':True,'safe_to_enable_protection':False,
        'protection_test':'NOT_RUN','high_sierra':'NOT_RUN','host_os':platform.mac_ver()[0],
        'host_arch':platform.machine(),'source_commit':os.environ.get('GITHUB_SHA')}
    try:
        info=read('info');rules=read('root_rules');all_rules=read('all_anchor_rules');anchors=read('anchors')
        enabled=re.search(r'^Status:\s+(Enabled|Disabled)\b',info,re.M)
        states=re.search(r'^\s*current entries\s+(\d+)\b',info,re.M)
        if not enabled or not states:raise RuntimeError('Unknown native PF information format')
        # Preserve only hashes/counts of foreign metadata. Actual rule text,
        # anchor names and state endpoint addresses are not exported.
        report.update({'pf_enabled':enabled[1]=='Enabled','current_state_count':int(states[1]),
            'root_rules_sha256':hashlib.sha256(rules.encode()).hexdigest(),
            'all_anchor_rules_sha256':hashlib.sha256(all_rules.encode()).hexdigest(),
            'anchor_names_sha256':hashlib.sha256(anchors.encode()).hexdigest(),
            'root_has_apple_filter_wildcard':bool(re.search(r'^anchor "com\.apple/\*"',rules,re.M)),
            'root_quick_pass_count':len(re.findall(r'^pass\b[^\n]*\bquick\b',rules,re.M)),
            'recursive_quick_pass_count':len(re.findall(r'^\s*pass\b[^\n]*\bquick\b',all_rules,re.M)),
            'root_rules_unchanged':read('root_rules')==rules})
        if not report['root_rules_unchanged']:raise RuntimeError('PF rules changed during inspection')
        report['status']='PASS'
    except Exception:
        report['status']='UNAVAILABLE'
        report['reason']='Read-only inspection unavailable; no protection may be inferred'
    (output/'pf-feasibility-ci.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    # Feasibility absence is evidence, not a fake protected success or a reason
    # to discard verified split-client artifacts.

if __name__=='__main__':main()
