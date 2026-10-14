/* Developer-only fixed filter policy experiment; absent from client packages.
 * Uses mechanically extracted, compiler-compared pinned primary declarations.
 * PF stays disabled. Only a random fixture leaf may receive deny or lo0+deny.
 * Pool staging uses PF's shared pool buffer: this is NOT a production API or
 * an atomic coexistence guarantee against another privileged policy writer.
 */
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "pf_rule_abi.h"

_Static_assert(sizeof(void *) == 8 && sizeof(struct pfioc_trans) == 16, "LP64 ABI");
_Static_assert(offsetof(struct pfioc_trans_e, anchor) == 4 &&
    offsetof(struct pfioc_trans_e, ticket) == 1028, "transaction field ABI");
_Static_assert(offsetof(struct pfioc_rule, anchor) == 16 &&
    offsetof(struct pfioc_rule, anchor_call) == 1040 &&
    offsetof(struct pfioc_rule, rule) == 2064, "rule ioctl field ABI");
_Static_assert(DIOCXBEGIN == 0xc0104451UL && DIOCXCOMMIT == 0xc0104452UL &&
    DIOCXROLLBACK == 0xc0104453UL, "transaction requests");

static int zero_bytes(const void *p, size_t size) {
    const unsigned char *bytes = p;
    for (size_t i=0; i<size; ++i) if (bytes[i]) return 0;
    return 1;
}

static int known_rule(const struct pf_rule *r, int loopback) {
    return r->action == (loopback ? PF_PASS : PF_DROP) &&
        r->direction == PF_OUT && r->quick == 1 && r->keep_state == 0 &&
        r->af == 0 && r->proto == 0 && r->flags == 0 && r->flagset == 0 &&
        r->rule_flag == 0 && r->rtableid == 0 &&
        strcmp(r->ifname, loopback ? "lo0" : "") == 0 &&
        r->src.addr.type == 0 && r->dst.addr.type == 0 &&
        r->src.addr.iflags == 0 && r->dst.addr.iflags == 0 &&
        zero_bytes(&r->src.addr.v,sizeof(r->src.addr.v)) &&
        zero_bytes(&r->dst.addr.v,sizeof(r->dst.addr.v)) &&
        zero_bytes(&r->src.xport,sizeof(r->src.xport)) &&
        zero_bytes(&r->dst.xport,sizeof(r->dst.xport)) &&
        !r->src.neg && !r->dst.neg && !r->log && !r->logif && !r->ifnot &&
        !r->match_tag_not && !r->natpass && !r->rt && !r->tos && !r->min_ttl &&
        !r->allow_opts && !r->return_ttl && !r->tag && !r->match_tag &&
        !r->os_fingerprint && !r->prob && !r->uid.op && !r->gid.op &&
        !r->anchor_relative && !r->anchor_wildcard && !r->flush &&
        !r->proto_variant && !r->extfilter && !r->extmap && !r->dnpipe && !r->dntype &&
        !r->label[0] && !r->owner[0] && !r->qname[0] && !r->pqname[0] &&
        !r->tagname[0] && !r->match_tagname[0] && !r->overload_tblname[0];
}

/* Absent lookup must fail with EINVAL BEFORE any write. This also refuses a
 * malformed anchor encoding that would accidentally select the existing root.
 * Existing leafs must contain only our exact fixed policy before replacement. */
static int current_policy(int fd, const char *path) {
    struct pfioc_rule request = {0};
    memcpy(request.anchor,path,strlen(path)+1);
    request.rule.action=PF_PASS;
    if (ioctl(fd,DIOCGETRULES,&request) != 0) return errno == EINVAL ? 0 : -1;
    unsigned count=request.nr, ticket=request.ticket;
    if (count != 1 && count != 2) return -1;
    for (unsigned i=0;i<count;++i) {
        memset(&request,0,sizeof(request));
        memcpy(request.anchor,path,strlen(path)+1);
        request.rule.action=PF_PASS;request.ticket=ticket;request.nr=i;
        if (ioctl(fd,DIOCGETRULE,&request) != 0 || request.anchor_call[0] ||
            !known_rule(&request.rule,count == 2 && i == 0)) return -1;
    }
    return (int)count;
}

/* Fixed read-only recipe vectors also validate the product Go codec against
 * actual primary C declarations. UDP recipes are emitted, never loaded here. */
static void fixed_recipe(struct pfioc_rule *request, const char *path, int kind) {
    memset(request,0,sizeof(*request));
    memcpy(request->anchor,path,strlen(path)+1);
    request->rule.action=kind ? PF_PASS : PF_DROP;
    request->rule.direction=PF_OUT;request->rule.quick=1;
    request->rule.rtableid=0; /* Apple's IFSCOPE_NONE */
    if (kind) memcpy(request->rule.ifname,"lo0",4);
    if (kind >= 2) {
        int family=kind == 2 ? AF_INET : AF_INET6;
        request->rule.af=family;request->rule.proto=IPPROTO_UDP;
        (void)inet_pton(family,kind == 2 ? "127.0.0.1" : "::1",&request->rule.src.addr.v.a.addr);
        (void)inet_pton(family,kind == 2 ? "127.0.0.2" : "::2",&request->rule.dst.addr.v.a.addr);
        memset(&request->rule.src.addr.v.a.mask,255,kind == 2 ? 4 : 16);
        memset(&request->rule.dst.addr.v.a.mask,255,kind == 2 ? 4 : 16);
        uint16_t port=htons(kind == 2 ? 53 : 443);
        request->rule.dst.xport.range.port[0]=port;
        request->rule.dst.xport.range.port[1]=port;
        request->rule.dst.xport.range.op=2; /* PF_OP_EQ */
        request->rule.uid.uid[0]=request->rule.uid.uid[1]=0;
        request->rule.uid.op=PF_OP_EQ; /* fixed root-owned socket escape */
    }
}

static int stage_rule(int fd, const char *path, unsigned ticket, int loopback) {
    struct pfioc_pooladdr pool = {0};
    memcpy(pool.anchor,path,strlen(path)+1);
    if (ioctl(fd,DIOCBEGINADDRS,&pool) != 0) return -1;
    struct pfioc_rule request;
    fixed_recipe(&request,path,loopback ? 1 : 0);
    request.ticket=ticket;request.pool_ticket=pool.ticket;
    return ioctl(fd,DIOCADDRULE,&request);
}

static void crash_checkpoint(void) {
    fputs("OWNED_SINGLE_RULE_CHECKPOINT\n",stdout);
    fflush(stdout);
    for (;;) pause(); /* disposable CI parent must send actual SIGKILL */
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int emit=-1;
    if (!strcmp(argv[2],"emit-deny")) emit=0;
    if (!strcmp(argv[2],"emit-loopback")) emit=1;
    if (!strcmp(argv[2],"emit-udp4")) emit=2;
    if (!strcmp(argv[2],"emit-udp6")) emit=3;
    const char *prefix=emit >= 0 ? "com.apple/legacywg-" : "com.apple/lw-rule-ci-";
    size_t prefix_length=strlen(prefix);
    const char *ci=getenv("GITHUB_ACTIONS");
    if (geteuid() != 0 || !ci || strcmp(ci,"true") ||
        strncmp(argv[1],prefix,prefix_length) || strlen(argv[1]) != prefix_length+32 ||
        strspn(argv[1]+prefix_length,"0123456789abcdef") != 32) return 2;
    if (emit >= 0) {
        struct pfioc_rule request;
        fixed_recipe(&request,argv[1],emit);
        return fwrite(&request,1,sizeof(request),stdout) == sizeof(request) ? 0 : 10;
    }
    int deny=strcmp(argv[2],"deny") == 0, loopback=strcmp(argv[2],"loopback") == 0;
    int rollback=strcmp(argv[2],"rollback") == 0, clear=strcmp(argv[2],"clear") == 0;
    int crash_begin=strcmp(argv[2],"crash-begin") == 0;
    int crash_rules=strcmp(argv[2],"crash-rules") == 0;
    int crash_commit=strcmp(argv[2],"crash-commit") == 0;
    int crash=crash_begin || crash_rules || crash_commit;
    if (!deny && !loopback && !rollback && !clear && !crash) return 2;
    int fd=open("/dev/pf",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    struct stat status;
    if (fd<0 || fstat(fd,&status) || status.st_uid || !S_ISCHR(status.st_mode)) {
        if (fd>=0) close(fd);
        return 3;
    }
    int old=current_policy(fd,argv[1]);
    if (old<0 || (deny && old != 0) || (!deny && !clear && old == 0)) { close(fd); return 4; }
    if (clear && old == 0) { close(fd); return 0; }
    struct pfioc_trans_e entry = {0};
    entry.rs_num=PF_RULESET_FILTER;
    memcpy(entry.anchor,argv[1],strlen(argv[1])+1);
    struct pfioc_trans tx = {1,sizeof(entry),&entry};
    if (ioctl(fd,DIOCXBEGIN,&tx) != 0) { close(fd); return 5; }
    if (entry.rs_num != PF_RULESET_FILTER || strcmp(entry.anchor,argv[1]) || !entry.ticket) {
        close(fd); return 6; /* unexpected identity is preserved */
    }
    if (crash_begin) crash_checkpoint();
    int result=0;
    int with_loopback=loopback || crash || (rollback && old == 1);
    if (!clear && ((with_loopback && stage_rule(fd,argv[1],entry.ticket,1)) ||
        stage_rule(fd,argv[1],entry.ticket,0))) result=7;
    if (!result && crash_rules) crash_checkpoint();
    if (result || rollback) {
        if (ioctl(fd,DIOCXROLLBACK,&tx) != 0) result=8;
    } else if (ioctl(fd,DIOCXCOMMIT,&tx) != 0) {
        (void)ioctl(fd,DIOCXROLLBACK,&tx); result=9;
    }
    if (!result && crash_commit) crash_checkpoint();
    close(fd);
    return result;
}
