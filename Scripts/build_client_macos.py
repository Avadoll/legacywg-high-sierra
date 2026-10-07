"""Build the real, limited native client and an explicitly research-only pkg."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
from test_mach_auth_macos import cdhash, run

ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'Build'/'Client'
OUT=ROOT/'Build'/'CI'

def main() -> None:
    if os.uname().sysname!='Darwin' or os.uname().machine!='x86_64':
        raise SystemExit('Requires the authorized native Intel macOS builder')
    if BUILD.exists(): raise SystemExit('Use a fresh native build workspace')
    BUILD.mkdir(parents=True)
    OUT.mkdir(parents=True,exist_ok=True)
    go=ROOT/'.tools/go1.24.13/go/bin/go'
    os.environ['GOCACHE']=str(ROOT/'.cache/macos-build')
    os.environ['GOMODCACHE']=str(ROOT/'.cache/gomod')
    run([str(go),'test','-count=1','./ConfigCore','./NetworkCore','./Engine/session','./Engine/worker'])
    run([str(go),'vet','./ConfigCore','./NetworkCore','./Engine/session','./Engine/worker'])
    worker=BUILD/'legacywg-worker'
    run([str(go),'build','-trimpath','-buildvcs=false','-o',str(worker),'./Engine/worker'],timeout=180)
    run([str(go),'build','-trimpath','-buildvcs=false','-o',str(BUILD/'peercheck'),'./Engine/peercheck'],timeout=180)
    common=['/usr/bin/xcrun','clang','-arch','x86_64','-mmacosx-version-min=10.13','-fobjc-arc',
            '-Wall','-Wextra','-Werror','-Wunguarded-availability','-Wno-deprecated-declarations',
            '-framework','Foundation','-framework','Security','-framework','SystemConfiguration','-lbsm',
            str(ROOT/'Shared/LWMach.m')]
    helper=BUILD/'org.legacywg.helper'
    run(common+[str(ROOT/'Helper/main.m'),'-o',str(helper)])
    for binary,identifier in ((worker,'org.legacywg.worker'),(helper,'org.legacywg.helper')):
        run(['/usr/bin/codesign','--force','--sign','-','--timestamp=none','--options','restrict,hard,kill',
             '--identifier',identifier,str(binary)])
        run(['/usr/bin/codesign','--verify','--strict',str(binary)])
    helper_requirement='identifier "org.legacywg.helper" and cdhash H"'+cdhash(helper)+'"'
    worker_requirement='identifier "org.legacywg.worker" and cdhash H"'+cdhash(worker)+'"'
    app=BUILD/'LegacyWG.app'
    for directory in ('Contents/MacOS','Contents/Helpers','Contents/Resources/Licenses'):
        (app/directory).mkdir(parents=True)
    shutil.copyfile(ROOT/'App/Info.plist',app/'Contents/Info.plist')
    shutil.copyfile(worker,app/'Contents/Helpers/legacywg-worker')
    (app/'Contents/Helpers/legacywg-worker').chmod(0o755)
    (app/'Contents/Resources/Helper.req').write_text(helper_requirement+'\n')
    for path in (ROOT/'Licenses').iterdir():
        if path.is_file():shutil.copyfile(path,app/'Contents/Resources/Licenses'/path.name)
    shutil.copyfile(ROOT/'Vendor/wireguard-candidate/LICENSE',app/'Contents/Resources/Licenses/WireGuard-LICENSE')
    shutil.copyfile(ROOT/'THIRD_PARTY_NOTICES.md',app/'Contents/Resources/THIRD_PARTY_NOTICES.md')
    source=os.environ['GITHUB_SHA']
    (app/'Contents/Resources/BuildManifest.json').write_text(json.dumps({'source_commit':source,'vpn_ready':False,
        'signing_mode':'ad-hoc','features':['IPv4 split tunnel','Keychain','authenticated Mach helper'],
        'unsupported':['full tunnel','DNS','IPv6','hostname endpoint','kill switch'],
        'high_sierra_runtime':'NOT_RUN','external_server':'NOT_RUN'},indent=2)+'\n')
    run(common+['-framework','Cocoa',str(ROOT/'App/main.m'),str(ROOT/'App/LWProfiles.m'),
                '-o',str(app/'Contents/MacOS/LegacyWG')])
    run(['/usr/bin/codesign','--force','--sign','-','--timestamp=none','--options','restrict,hard,kill',str(app)])
    run(['/usr/bin/codesign','--verify','--strict','--deep',str(app)])
    self_test=run([str(app/'Contents/MacOS/LegacyWG'),'--self-test'])
    (OUT/'client-self-test.json').write_text(self_test)
    if json.loads(self_test)['status']!='PASS':raise SystemExit('Client bundle self-test failed')
    payload=BUILD/'payload'
    for directory in ('Applications','Library/PrivilegedHelperTools','Library/Application Support/LegacyWG','Library/LaunchDaemons'):
        (payload/directory).mkdir(parents=True)
    shutil.copytree(app,payload/'Applications/LegacyWG.app')
    shutil.copyfile(helper,payload/'Library/PrivilegedHelperTools/org.legacywg.helper')
    (payload/'Library/PrivilegedHelperTools/org.legacywg.helper').chmod(0o755)
    target=payload/'Library/Application Support/LegacyWG'
    shutil.copyfile(worker,target/worker.name);(target/worker.name).chmod(0o755)
    (target/'Worker.req').write_text(worker_requirement+'\n')
    (target/'AllowedClient.req').write_text('identifier "org.legacywg.app" and cdhash H"'+cdhash(app)+'"\n')
    label='org.legacywg.helper'
    (payload/'Library/LaunchDaemons/org.legacywg.helper.plist').write_bytes(plistlib.dumps({
        'Label':label,'ProgramArguments':['/Library/PrivilegedHelperTools/'+label],
        'MachServices':{label:True},'RunAtLoad':True,'ProcessType':'Interactive'}))
    for path in (ROOT/'Installer/Scripts').iterdir():path.chmod(0o755)
    package=OUT/'LegacyWG-research-0.2.pkg'
    # The helper policy and application location are fixed. Do not let Installer
    # relocate the bundle onto another copy (including the build directory).
    components=BUILD/'components.plist'
    components.write_bytes(plistlib.dumps([{
        'RootRelativeBundlePath':'Applications/LegacyWG.app',
        'BundleIsRelocatable':False,'BundleIsVersionChecked':False,
        'BundleHasStrictIdentifier':True,'BundleOverwriteAction':'upgrade'}]))
    run(['/usr/bin/pkgbuild','--root',str(payload),'--ownership','recommended','--identifier','org.legacywg.research',
         '--version','0.2','--install-location','/','--component-plist',str(components),
         '--scripts',str(ROOT/'Installer/Scripts'),str(package)])
    archive=OUT/'LegacyWG-research-0.2-app.zip'
    run(['/usr/bin/ditto','-c','-k','--sequesterRsrc','--keepParent',str(app),str(archive)])
    manifest={'source_commit':source,'kind':'limited-native-client-research','signing_mode':'ad-hoc',
        'installer_signed':False,'signed_for_distribution':False,'vpn_ready':False,
        'high_sierra_runtime':'NOT_RUN','external_server':'NOT_RUN',
        'artifacts':{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (package,archive)}}
    (OUT/'client-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Real limited client and research package built; target installation is NOT_APPROVED.')

if __name__=='__main__':main()
