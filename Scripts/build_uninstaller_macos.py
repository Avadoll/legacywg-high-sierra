"""Build a fixed-path, exact-build removal package for the research client."""
from pathlib import Path
import shlex
import shutil
from test_mach_auth_macos import cdhash, run

ROOT=Path(__file__).resolve().parents[1]

SCRIPT='''#!/bin/sh
set -eu
fail() { echo "$1" >&2; exit 1; }
[ "$(/usr/bin/id -u)" = 0 ] || fail 'Administrator authorization is required.'
[ "${3:-}" = / ] || fail 'Only the running system volume is supported.'
script_dir=$(/usr/bin/dirname "$0")
app='/Applications/LegacyWG.app'
policy='/Library/Application Support/LegacyWG'
helper='/Library/PrivilegedHelperTools/org.legacywg.helper'
plist='/Library/LaunchDaemons/org.legacywg.helper.plist'
root_item() {
    [ ! -L "$1" ] && [ "$(/usr/bin/stat -f '%u' "$1")" = 0 ] || fail 'Component ownership mismatch; nothing removed.'
}
for item in "$app" "$policy" "$helper" "$plist" "$policy/legacywg-worker" "$policy/legacywg-network"; do root_item "$item"; done
/usr/bin/codesign --verify --strict -R @APP_REQ@ "$app" || fail 'Application differs from this removal package.'
/usr/bin/codesign --verify --strict -R @HELPER_REQ@ "$helper" || fail 'Helper differs from this removal package.'
/usr/bin/codesign --verify --strict -R @WORKER_REQ@ "$policy/legacywg-worker" || fail 'Worker differs from this removal package.'
/usr/bin/codesign --verify --strict -R @NETWORK_REQ@ "$policy/legacywg-network" || fail 'Network component differs from this removal package.'
for name in AllowedClient.req Worker.req Network.req; do
    root_item "$policy/$name"
    /usr/bin/cmp -s "$policy/$name" "$script_dir/$name" || fail 'Component policy differs; nothing removed.'
done
/usr/bin/cmp -s "$plist" "$script_dir/helper.plist" || fail 'Service definition differs; nothing removed.'
for item in "$policy"/* "$policy"/.[!.]* "$policy"/..?*; do
    [ -e "$item" ] || [ -L "$item" ] || continue
    case "$item" in
        "$policy/legacywg-worker"|"$policy/legacywg-network"|"$policy/AllowedClient.req"|"$policy/Worker.req"|"$policy/Network.req"|"$policy/State") ;;
        *) fail 'Unexpected component files; nothing removed.' ;;
    esac
done
check_state() {
    state="$policy/State"
    if [ -e "$state" ] || [ -L "$state" ]; then
        root_item "$state"
        [ -d "$state" ] && [ "$(/usr/bin/stat -f '%Lp' "$state")" = 700 ] || fail 'Recovery directory requires attention.'
        for item in "$state"/* "$state"/.[!.]* "$state"/..?*; do
            [ -e "$item" ] || [ -L "$item" ] || continue
            [ "$item" = "$state/lock" ] && [ -f "$item" ] || fail 'Disconnect VPN and finish recovery before removal.'
            root_item "$item"
        done
    fi
}
check_state
if /usr/bin/pgrep -f '^/Applications/LegacyWG[.]app/Contents/MacOS/LegacyWG($| )' >/dev/null; then
    fail 'Quit LegacyWG before removal.'
else
    [ "$?" = 1 ] || fail 'Cannot verify application exit.'
fi
if /bin/launchctl print system/org.legacywg.helper >/dev/null 2>&1; then
    /bin/launchctl bootout system/org.legacywg.helper || fail 'Cannot stop the owned service.'
fi
for component in legacywg-worker legacywg-network; do
    count=0
    while :; do
        if /usr/bin/pgrep -f "^/Library/Application Support/LegacyWG/$component\u0024" >/dev/null; then
            count=$((count+1))
            [ "$count" -lt 40 ] || fail 'Owned component is still stopping; retry removal.'
            /bin/sleep 0.2
        else
            [ "$?" = 1 ] || fail 'Cannot verify component exit.'
            break
        fi
    done
done
check_state
if [ -d "$policy/State" ]; then
    /bin/rm -f "$policy/State/lock"
    /bin/rmdir "$policy/State" || fail 'Recovery state is not empty; preserved.'
fi
/bin/rm -f "$helper" "$plist" "$policy/legacywg-worker" "$policy/legacywg-network" "$policy/AllowedClient.req" "$policy/Worker.req" "$policy/Network.req"
/bin/rmdir "$policy" || fail 'Unknown component files preserved.'
/bin/rm -rf "$app"
/usr/sbin/pkgutil --forget org.legacywg.research >/dev/null
exit 0
'''

def build(build_directory:Path, output:Path, app:Path, helper:Path, worker:Path, network:Path, payload:Path)->Path:
    scripts=build_directory/'uninstaller-scripts';scripts.mkdir()
    text=SCRIPT
    for label,path in [('APP',app),('HELPER',helper),('WORKER',worker),('NETWORK',network)]:
        requirement='cdhash H"'+cdhash(path)+'"'
        text=text.replace('@'+label+'_REQ@',shlex.quote(requirement))
    (scripts/'postinstall').write_text(text)
    (scripts/'postinstall').chmod(0o755)
    for name in ('AllowedClient.req','Worker.req','Network.req'):
        shutil.copyfile(payload/'Library/Application Support/LegacyWG'/name,scripts/name)
    shutil.copyfile(payload/'Library/LaunchDaemons/org.legacywg.helper.plist',scripts/'helper.plist')
    package=output/'LegacyWG-remove-test-0.2.pkg'
    run(['/usr/bin/pkgbuild','--nopayload','--identifier','org.legacywg.research.uninstall',
         '--version','0.2','--scripts',str(scripts),str(package)])
    return package
