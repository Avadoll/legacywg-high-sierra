"""Build a developer-only singleton loader against mechanically extracted XNU ABI.

Downloaded declarations retain their original license notices in temporary build
headers. They and the probe binary are absent from application/package artifacts.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ('legacy', 'xnu-4570.71.2', '0a733e0aca05081174a14c635950f2d4113d5774ff5ee8de9dcd575f77a90f07'),
    ('modern', 'xnu-11417.140.69', 'aeaaa90c761577247bfa0328bd4765512f787f5af9a56b9bb530030c90a692c9'),
)

def declaration(text, name):
    match = re.search(r'^'+re.escape(name)+r'\s*\{', text, re.M)
    if not match:
        raise ValueError('Pinned ABI declaration missing')
    depth = 0
    for end in range(text.index('{', match.start()), len(text)):
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        if depth == 0:
            end = text.index(';', end)+1
            return text[match.start():end]+'\n'
    raise ValueError('Pinned ABI declaration incomplete')

def extract_header(text):
    notices = text[:text.index('#ifndef _NET_PFVAR_H_')]
    prefix = '''
#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#define PF_TABLE_NAME_SIZE 32
#define RTLABEL_LEN 32
typedef u_int32_t pf_osfp_t;
'''
    enums = []
    for name in ('PF_INOUT', 'PF_PASS', 'PF_RULESET_SCRUB', 'PFTM_TCP_FIRST_PACKET'):
        match = re.search(r'enum\s*\{\s*'+name+r'\b[^}]*\};', text)
        if not match: raise ValueError('Pinned ABI enum missing')
        enums.append(match.group(0))
    names = ('struct pf_addr', 'struct pf_addr_wrap', 'struct pf_port_range',
             'union pf_rule_xport', 'struct pf_rule_uid', 'struct pf_rule_gid',
             'struct pf_rule_addr', 'struct pf_pooladdr', 'struct pf_poolhashkey',
             'struct pf_pool', 'union pf_rule_ptr', 'struct pf_rule',
             'struct pfioc_rule', 'struct pfioc_pooladdr', 'struct pfioc_trans')
    parts = [notices, '/* Modified 2026-10-14: mechanical declaration subset for CI; no policy implementation.\n * Source: pinned Apple XNU pfvar.h; modifications are reproducible by this public builder.\n * Covered declarations remain subject to APSL-2.0 and their original notices. */\n', prefix,
             '\n'.join(enums)]
    for name in names:
        if name == 'struct pf_poolhashkey': parts.append('TAILQ_HEAD(pf_palist, pf_pooladdr);\n')
        parts.append(declaration(text, name))
    for name in ('DIOCXBEGIN','DIOCXCOMMIT','DIOCXROLLBACK','DIOCADDRULE','DIOCGETRULES','DIOCGETRULE','DIOCBEGINADDRS','DIOCADDADDR'):
        match = re.search(r'^#define\s+'+name+r'\s+[^\n]+',text,re.M)
        if not match: raise ValueError('Pinned ABI request missing')
        parts.append(match.group(0)+'\n')
    return '\n'.join(parts)

def build_probe(build):
    fields = {
        'pfioc_rule': ('action','ticket','pool_ticket','nr','anchor','anchor_call','rule'),
        'pf_rule': ('src','dst','skip','label','ifname','entries','rpool','rtableid',
                    'timeout','uid','gid','rule_flag','action','direction','quick','keep_state',
                    'af','proto','flags','flagset','owner','ticket'),
        'pf_rule_addr': ('addr','xport','neg'),
        'pf_addr_wrap': ('v','p','type','iflags'),
        'pf_port_range': ('port','op'),
        'pfioc_pooladdr': ('action','ticket','anchor','addr'),
        'pfioc_trans': ('size','esize','array'),
        'pfioc_trans_e': ('rs_num','anchor','ticket'),
    }
    lines = ['#include <stddef.h>', '#include <stdio.h>', '#include "pf_rule_abi.h"', 'int main(void) {']
    for struct, members in fields.items():
        lines.append(f'printf("{struct}.size=%zu\\n", sizeof(struct {struct}));')
        for member in members:
            lines.append(f'printf("{struct}.{member}=%zu\\n", offsetof(struct {struct}, {member}));')
    for name in ('DIOCXBEGIN','DIOCXCOMMIT','DIOCXROLLBACK','DIOCADDRULE','DIOCGETRULES','DIOCGETRULE','DIOCBEGINADDRS','DIOCADDADDR'):
        lines.append(f'printf("{name}=%lu\\n", (unsigned long){name});')
    lines += ['return 0;', '}']
    printer = build/'abi-layout.c';printer.write_text('\n'.join(lines)+'\n')
    layouts=[];pins=[]
    flags=['/usr/bin/xcrun','clang','-std=c11','-arch','x86_64','-mmacosx-version-min=10.13','-Wall','-Wextra','-Werror']
    for label,tag,sha in SOURCES:
        folder=build/label;folder.mkdir(exist_ok=True)
        url=f'https://raw.githubusercontent.com/apple-oss-distributions/xnu/{tag}/bsd/net/pfvar.h'
        with urllib.request.urlopen(url,timeout=30) as response: data=response.read(256*1024+1)
        if len(data)>256*1024 or hashlib.sha256(data).hexdigest()!=sha:
            raise ValueError('Pinned XNU header integrity mismatch')
        header=folder/'pf_rule_abi.h';header.write_text(extract_header(data.decode()),encoding='utf-8')
        program=folder/'abi-layout'
        subprocess.run(flags+['-I',str(folder),str(printer),'-o',str(program)],check=True,timeout=30)
        output=subprocess.check_output([str(program)],text=True,timeout=5)
        layout=dict(line.split('=',1) for line in output.splitlines())
        layouts.append(layout);pins.append({'tag':tag,'url':url,'sha256':sha})
    if layouts[0]!=layouts[1]:
        raise ValueError('Legacy/modern rule ABI differs; refusing mutation probe')
    evidence={'status':'PASS','kind':'compiler comparison of pinned primary declarations',
              'sources':pins,'layout':layouts[0],'running_kernel_layout_match':'NOT_PROVEN'}
    (build/'abi-comparison.json').write_text(json.dumps(evidence,indent=2)+'\n')
    probe=build/'pf-single-rule-probe'
    subprocess.run(flags+['-I',str(build/'modern'),str(ROOT/'Tests/PFSingleRuleProbe.c'),'-o',str(probe)],check=True,timeout=30)
    subprocess.run(flags+['-I',str(build/'modern'),str(ROOT/'Tests/PFNestedRuleProbe.c'),'-o',str(build/'pf-nested-rule-probe')],check=True,timeout=30)
    return probe,evidence
