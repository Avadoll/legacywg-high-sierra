#ifndef LEGACYWG_ACL_CHECK_H
#define LEGACYWG_ACL_CHECK_H
#include <stddef.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/stat.h>

// Query the inherited, already opened inode using the native libc API.
// No pathname, metadata text, or ACL modification is accepted.
static int LWCheckNoACL(int fd) {
    filesec_t security=filesec_init();
    if(security==NULL)return 1;
    struct stat status;
    int present=1;
    int result=1;
    // Unlike acl_get_fd_np(NULL), successful metadata plus an absent property
    // distinguishes no ACL from a failed read. Conservatively reject even an
    // explicitly installed empty ACL, as well as any query/API failure.
    if(fstatx_np(fd,&status,security)==0 &&
       filesec_query_property(security,FILESEC_ACL,&present)==0 && present==0)result=0;
    filesec_free(security);
    return result;
}
#endif
