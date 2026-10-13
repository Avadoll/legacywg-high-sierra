/* Developer-only private PF ABI experiment. Never installed with LegacyWG.
 * ABI provenance: Apple XNU xnu-4570.71.2 bsd/net/pfvar.h, and
 * f6217f891ac0bb64f3d375211650a4c1ff8ca1ea bsd/net/pf_ioctl.c.
 * These private ioctls are not a supported product API or target proof.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#pragma pack(push, 1)
struct RefEntry { uint64_t value, epoch; int32_t pid; char name[64]; };
#pragma pack(pop)
struct RefList { int32_t bytes; union { char *buffer; struct RefEntry *entries; } data __attribute__((aligned(8))); };
struct RefRemoval { uint64_t value, remaining; };
_Static_assert(sizeof(struct RefEntry)==84, "private token ABI");
_Static_assert(sizeof(struct RefList)==16 && offsetof(struct RefList,data)==8, "private list ABI");
_Static_assert(sizeof(struct RefRemoval)==16 && sizeof(void *)==8, "Intel 64-bit ABI");
#define REF_LIST _IOWR('D',5,struct RefList)
#define REF_START _IOR('D',8,uint64_t)
#define REF_STOP _IOWR('D',9,struct RefRemoval)

static int fail(void) { fputs("fixed developer reference operation failed\n",stderr); return 1; }

static int references(int fd) {
    struct RefList query={0};
    if (ioctl(fd,REF_LIST,&query)<0) {
        if (errno==ENOENT) { puts("{\"references\":[]}"); return 0; }
        return -1;
    }
    if (query.bytes<=0 || query.bytes>(int)(16*sizeof(struct RefEntry)) || query.bytes%sizeof(struct RefEntry)) return -1;
    int expected=query.bytes;
    struct RefEntry entries[16]={0};
    query.data.entries=entries;
    if (ioctl(fd,REF_LIST,&query)<0 || query.bytes!=expected) return -1;
    struct RefList check={0};
    if (ioctl(fd,REF_LIST,&check)<0 || check.bytes!=expected) return -1;
    for (size_t i=0;i<(size_t)expected/sizeof(*entries);i++) {
        if (!entries[i].value || entries[i].pid<=0 || !entries[i].epoch || !memchr(entries[i].name,0,sizeof(entries[i].name))) return -1;
    }
    fputs("{\"references\":[",stdout);
    for (size_t i=0;i<(size_t)expected/sizeof(*entries);i++) {
        struct RefEntry *e=&entries[i];
        printf("%s{\"token\":%" PRIu64 ",\"epoch\":%" PRIu64 ",\"pid\":%" PRId32 ",\"name\":\"",i?",":"",e->value,e->epoch,e->pid);
        for (size_t j=0;e->name[j];j++) {
            unsigned char c=(unsigned char)e->name[j];
            if (c=='"' || c=='\\') printf("\\%c",c);
            else if (c<32 || c>126) printf("\\u%04x",c);
            else putchar(c);
        }
        fputs("\"}",stdout);
    }
    puts("]}"); return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    struct stat input,output,device;
    const char *ci=getenv("GITHUB_ACTIONS");
    if (argc!=1 || geteuid()!=0 || !ci || strcmp(ci,"true") ||
        fstat(STDIN_FILENO,&input) || fstat(STDOUT_FILENO,&output) ||
        !S_ISFIFO(input.st_mode) || !S_ISFIFO(output.st_mode)) return fail();
    struct rlimit core={0,0};
    if (setrlimit(RLIMIT_CORE,&core)) return fail();
    int fd=open("/dev/pf",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0 || fstat(fd,&device) || !S_ISCHR(device.st_mode) || device.st_uid!=0) return fail();
    setvbuf(stdout,NULL,_IOLBF,0);
    printf("{\"ready\":true,\"pid\":%d,\"epoch\":%lld}\n",getpid(),(long long)time(NULL));
    uint64_t own=0; int acquired=0; char line[32];
    for (unsigned operations=0;operations<64 && fgets(line,sizeof(line),stdin);operations++) {
        if (!strchr(line,'\n')) { close(fd); return fail(); }
        if (!strcmp(line,"references\n")) {
            if (references(fd)) { close(fd); return fail(); }
        } else if (!strcmp(line,"acquire\n") && !acquired) {
            acquired=1;
            if (ioctl(fd,REF_START,&own)<0 || !own) { close(fd); return fail(); }
            printf("{\"acquired\":true,\"token\":%" PRIu64 "}\n",own);
        } else if (!strcmp(line,"release\n") && own) {
            struct RefRemoval removal={.value=own};
            if (ioctl(fd,REF_STOP,&removal)<0) { close(fd); return fail(); }
            puts("{\"released\":true}"); close(fd); return 0;
        } else { close(fd); return fail(); }
    }
    /* EOF/process death deliberately does not release: recovery must prove
       ownership from the write-before-effect intent plus kernel metadata. */
    close(fd); return 0;
}
