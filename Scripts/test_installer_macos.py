"""Install and clean up our unsigned research package on disposable CI only."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
from test_mach_auth_macos import cdhash, run

ROOT=Path(__file__).resolve().parents[1]
APP=Path('/Applications/LegacyWG.app')
SERVICE='org.legacywg.helper'
HELPER=Path('/Library/PrivilegedHelperTools')/SERVICE
POLICY=Path('/Library/Application Support/LegacyWG')
PLIST=Path('/Library/LaunchDaemons')/(SERVICE+'.plist')

def main() -> None:
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.uname().sysname!='Darwin':
        raise SystemExit('This developer installation test is allowed only on the disposable macOS CI runner')
    if any(path.exists() for path in (APP,HELPER,POLICY,PLIST)):
        raise SystemExit('Existing application/component found; refusing to overwrite it')
    if subprocess.run(['/usr/sbin/pkgutil','--pkg-info','org.legacywg.research'],capture_output=True).returncode==0:
        raise SystemExit('Existing research package receipt found; refusing to replace it')
    created_parent=not HELPER.parent.exists()
    results={}
    attempted=False
    try:
        attempted=True
        output=run(['/usr/bin/sudo','-n','/usr/sbin/installer','-pkg',
                    str(ROOT/'Build/CI/LegacyWG-research-0.2.pkg'),'-target','/'],timeout=90)
        (ROOT/'Build/CI/installer-ci-log.txt').write_text(output)
        for path in (APP,HELPER,POLICY,POLICY/'legacywg-worker',POLICY/'Worker.req',POLICY/'AllowedClient.req',PLIST):
            stat=path.lstat()
            if path.is_symlink() or stat.st_uid!=0 or stat.st_mode&0o022:
                raise RuntimeError('Installed component ownership or permissions are unsafe')
        run(['/usr/bin/codesign','--verify','--strict','--deep',str(APP)])
        run(['/usr/bin/codesign','--verify','--strict',str(HELPER)])
        assert cdhash(APP) in (POLICY/'AllowedClient.req').read_text()
        assert cdhash(POLICY/'legacywg-worker') in (POLICY/'Worker.req').read_text()
        run(['/usr/bin/sudo','-n','/bin/launchctl','print','system/'+SERVICE])
        self_test=json.loads(run([str(APP/'Contents/MacOS/LegacyWG'),'--self-test-installed']))
        assert self_test['keychain_write_read_delete']=='PASS'
        assert self_test['installed_helper_authentication']=='PASS'
        assert self_test['core_dumps_disabled'] is True
        client=ROOT/'Build/MachAuth/allowed-client'
        requirement='identifier "'+SERVICE+'" and cdhash H"'+cdhash(HELPER)+'"'
        denial=subprocess.run([str(client),requirement],capture_output=True,text=True,timeout=20)
        assert denial.returncode==1 and json.loads(denial.stdout)['error']=='Unauthorized client'
        results={'status':'PASS','installer_cli':'PASS','root_ownership':'PASS','component_signatures':'PASS',
            'launchd_postinstall':'PASS','app_policy_pin':'PASS','foreign_client_denied':'PASS',
            'installed_app_keychain':'PASS','installed_app_helper_authentication':'PASS',
            'installer_gui':'NOT_RUN','target_high_sierra':'NOT_RUN',
            'developer_id':'NOT_RUN','signed_for_distribution':False}
    finally:
        if attempted:
            subprocess.run(['/usr/bin/sudo','-n','/bin/launchctl','bootout','system/'+SERVICE],capture_output=True)
            for path in (HELPER,PLIST,POLICY/'AllowedClient.req',POLICY/'Worker.req',POLICY/'legacywg-worker'):
                subprocess.run(['/usr/bin/sudo','-n','/bin/rm','-f',str(path)],check=True)
            if POLICY.exists():run(['/usr/bin/sudo','-n','/bin/rmdir',str(POLICY)])
            # This fixed app path was verified absent before our installer ran.
            # Remove only the application created by this test, never its parent.
            if APP.exists():run(['/usr/bin/sudo','-n','/bin/rm','-rf',str(APP)])
            if created_parent and HELPER.parent.exists():run(['/usr/bin/sudo','-n','/bin/rmdir',str(HELPER.parent)])
            subprocess.run(['/usr/bin/sudo','-n','/usr/sbin/pkgutil','--forget','org.legacywg.research'],capture_output=True)
        (ROOT/'Build/CI/installer-ci.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))

if __name__=='__main__':main()
