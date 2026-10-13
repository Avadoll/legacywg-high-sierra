"""Read a MacPorts Darwin-17 receipt without installing or executing its binary.

Reference-only static comparison: a fetched package is not a release dependency,
trusted replacement worker or proof that this project's runtime runs on 10.13.
"""
from pathlib import Path
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.request
from inspect_macho import inspect

ROOT=Path(__file__).resolve().parents[1]
REVISION='7c220a7413aef99cd30f8aa88241a85f798d856b'
PACKAGE='https://packages.macports.org/wireguard-go/wireguard-go-0.0.20250522_0.darwin_17.x86_64.tbz2'

def fetch(url,limit):
    with urllib.request.urlopen(url,timeout=25) as response:
        if response.geturl()!=url:raise SystemExit('Unexpected reference download redirect')
        data=response.read(limit+1)
    if len(data)>limit:raise SystemExit('Reference download size limit')
    return data

def main():
    cache=ROOT/'.cache/legacy-receipt';cache.mkdir(parents=True,exist_ok=True)
    evidence=ROOT/'Docs/Evidence/Compatibility';evidence.mkdir(parents=True,exist_ok=True)
    sources=[]
    for name in ('_resources/port1.0/group/go_toolchain-1.0.tcl','lang/go-1.24/Portfile'):
        url='https://raw.githubusercontent.com/macports/macports-ports/'+REVISION+'/'+name
        data=fetch(url,128*1024)
        sources.append({'url':url,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
    archive=fetch(PACKAGE,8*1024*1024)
    binary=None;expanded=0
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r|bz2') as tar:
        for number,member in enumerate(tar):
            if number>4096 or member.size<0 or len(member.name)>1024:raise SystemExit('Reference archive member limit')
            expanded+=member.size
            if expanded>64*1024*1024:raise SystemExit('Reference archive expansion limit')
            name=member.name.removeprefix('./').removeprefix('/')
            if name=='opt/local/bin/wireguard-go':
                if binary is not None or not member.isfile() or member.size>32*1024*1024:raise SystemExit('Invalid reference binary member')
                stream=tar.extractfile(member)
                binary=stream.read(member.size+1)
                if len(binary)!=member.size:raise SystemExit('Truncated reference binary')
    if binary is None:raise SystemExit('Expected reference member absent')
    path=cache/'wireguard-go-darwin17-reference';path.write_bytes(binary)
    # go version -m parses build information; it never launches the target.
    info=subprocess.run([str(ROOT/'.tools/go1.24.13/go/bin/go.exe'),'version','-m',str(path)],capture_output=True,text=True,check=True,timeout=10).stdout
    (evidence/'macports-darwin17-buildinfo.txt').write_text(info.replace(str(path),'REFERENCE_BINARY'),encoding='utf-8')
    reference=inspect(path)
    worker=ROOT/'Build/Verified/legacywg-worker-EndpointPath-darwin-amd64'
    current=inspect(worker)
    summary={'date':'2026-10-13','status':'REFERENCE_ONLY','macports_source_commit':REVISION,'sources':sources,
        'package_url':PACKAGE,'observed_package_sha256':hashlib.sha256(archive).hexdigest(),
        'package_signature':'NOT_VERIFIED','binary_executed':False,'binary_installed':False,
        'reference_binary_sha256':hashlib.sha256(binary).hexdigest(),'reference_macho':reference,
        'worker_sha256':hashlib.sha256(worker.read_bytes()).hexdigest(),
        'worker_macho':current,'worker_imports_absent_from_reference':sorted(set(current['undefined_symbols'])-set(reference['undefined_symbols'])),
        'high_sierra_runtime':'NOT_RUN','limitation':'Static imports and a published Darwin-17 package do not prove target loading, API behavior, VPN or security support.'}
    (evidence/'macports-darwin17-reference.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:summary[key] for key in ('status','observed_package_sha256','worker_sha256','worker_imports_absent_from_reference','high_sierra_runtime')},indent=2))

if __name__=='__main__':main()
