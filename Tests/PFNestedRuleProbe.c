/* Developer-only nested foreign-policy fixture. No client-package entrypoint.
 * Primary ABI declarations, fixed absent nonce parent and fixed child only.
 * FILTER and NAT use separate single-entry transactions. Shared pool staging
 * is not atomic against privileged writers. PF enable/ref/state APIs absent. */
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "pf_rule_abi.h"

static int count_rules(int fd,const char *path,int action,unsigned *ticket) {
    struct pfioc_rule query={0};
    memcpy(query.anchor,path,strlen(path)+1);query.rule.action=action;
    if (ioctl(fd,DIOCGETRULES,&query)) return errno == EINVAL ? -2 : -1;
    *ticket=query.ticket;
    return query.nr <= 1 ? (int)query.nr : -1;
}

static int known_class(int fd,const char *path,int action,int parent) {
    unsigned ticket=0;
    int count=count_rules(fd,path,action,&ticket);
    if (count==0 || count==-2) return 1;
    if (count!=1) return 0;
    struct pfioc_rule query={0};
    memcpy(query.anchor,path,strlen(path)+1);
    query.rule.action=action;query.ticket=ticket;
    if (ioctl(fd,DIOCGETRULE,&query)) return 0;
    const struct pf_rule *r=&query.rule;
    if (r->rtableid || r->keep_state || r->rt || r->owner[0] || r->label[0] || r->log || r->rule_flag) return 0;
    if (parent) return action==PF_PASS && !strcmp(query.anchor_call,"hidden") && r->action==PF_PASS && !r->direction && !r->quick;
    if (query.anchor_call[0]) return 0;
    if (action==PF_PASS) return r->action==PF_PASS && r->direction==PF_OUT && r->quick && !r->af && !r->proto && !r->ifname[0];
    return r->action==PF_NAT && r->af==AF_INET && !strcmp(r->ifname,"lo0") && !r->proto;
}

static int replace_class(int fd,const char *path,int action,int recipe,int require_absent) {
    unsigned oldticket=0;
    int count=count_rules(fd,path,action,&oldticket);
    if (count==-1 || (require_absent && count!=-2)) return -1;
    if (recipe==0 && count==-2) return 0; /* never recreate removed nodes */
    struct pfioc_trans_e entry={0};
    entry.rs_num=action==PF_NAT ? PF_RULESET_NAT : PF_RULESET_FILTER;
    memcpy(entry.anchor,path,strlen(path)+1);
    struct pfioc_trans tx={1,sizeof(entry),&entry};
    if (ioctl(fd,DIOCXBEGIN,&tx)) return -1;
    if (entry.rs_num!=(action==PF_NAT ? PF_RULESET_NAT : PF_RULESET_FILTER) || strcmp(entry.anchor,path) || !entry.ticket) return -1;
    int result=0;
    if (recipe) {
        struct pfioc_pooladdr pool={0};
        memcpy(pool.anchor,path,strlen(path)+1);
        if (ioctl(fd,DIOCBEGINADDRS,&pool)) result=-1;
        if (!result && recipe==3) {
            pool.af=AF_INET;
            (void)inet_pton(AF_INET,"127.0.0.1",&pool.addr.addr.v.a.addr);
            memset(&pool.addr.addr.v.a.mask,255,4);
            if (ioctl(fd,DIOCADDADDR,&pool)) result=-1;
        }
        struct pfioc_rule rule={0};
        memcpy(rule.anchor,path,strlen(path)+1);
        rule.ticket=entry.ticket;rule.pool_ticket=pool.ticket;
        if (recipe==1) memcpy(rule.anchor_call,"hidden",7);
        if (recipe==2) { rule.rule.direction=PF_OUT;rule.rule.quick=1; }
        if (recipe==3) {
            rule.rule.action=PF_NAT;rule.rule.af=AF_INET;
            memcpy(rule.rule.ifname,"lo0",4);
            (void)inet_pton(AF_INET,"198.18.99.0",&rule.rule.src.addr.v.a.addr);
            unsigned char mask[4]={255,255,255,0};
            memcpy(&rule.rule.src.addr.v.a.mask,mask,4);
        }
        if (!result && ioctl(fd,DIOCADDRULE,&rule)) result=-1;
    }
    if (!result && ioctl(fd,DIOCXCOMMIT,&tx)) result=-1;
    if (result) (void)ioctl(fd,DIOCXROLLBACK,&tx);
    return result;
}

int main(int argc,char **argv) {
    const char prefix[]="com.apple/lw-enum-ci-";
    const char *ci=getenv("GITHUB_ACTIONS");
    if (argc!=3 || geteuid()!=0 || !ci || strcmp(ci,"true") ||
        strncmp(argv[1],prefix,sizeof(prefix)-1) || strlen(argv[1])!=sizeof(prefix)-1+32 ||
        strspn(argv[1]+sizeof(prefix)-1,"0123456789abcdef")!=32) return 2;
    if (strcmp(argv[2],"parent") && strcmp(argv[2],"quick") && strcmp(argv[2],"nat") && strcmp(argv[2],"clear")) return 2;
    char child[1024];
    if (snprintf(child,sizeof(child),"%s/hidden",argv[1])<0) return 2;
    int fd=open("/dev/pf",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    struct stat status;
    if (fd<0 || fstat(fd,&status) || status.st_uid || !S_ISCHR(status.st_mode)) {
        if (fd>=0) close(fd);
        return 3;
    }
    int result=0;
    if (!strcmp(argv[2],"parent")) result=replace_class(fd,argv[1],PF_PASS,1,1);
    else if (!known_class(fd,argv[1],PF_PASS,1) || !known_class(fd,child,PF_PASS,0) || !known_class(fd,child,PF_NAT,0)) result=-1;
    else if (!strcmp(argv[2],"quick")) result=replace_class(fd,child,PF_PASS,2,0);
    else if (!strcmp(argv[2],"nat")) {
        result=replace_class(fd,child,PF_PASS,0,0);
        if (!result) result=replace_class(fd,child,PF_NAT,3,0);
    } else {
        result=replace_class(fd,argv[1],PF_PASS,0,0);
        if (!result) result=replace_class(fd,child,PF_NAT,0,0);
        if (!result) result=replace_class(fd,child,PF_PASS,0,0);
    }
    close(fd);
    return result ? 4 : 0;
}
