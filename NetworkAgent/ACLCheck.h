#ifndef LEGACYWG_ACL_CHECK_H
#define LEGACYWG_ACL_CHECK_H
#include <sys/types.h>
#include <sys/acl.h>
#include <errno.h>

// Query the inherited, already opened inode using the native libc API.
// No pathname, metadata text, or ACL modification is accepted.
static int LWCheckNoACL(int fd) {
    acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
    if(acl==NULL)return 1;
    int result=1;
    if(acl_valid(acl)==0) {
        acl_entry_t entry=NULL;
        errno=0;
        // Darwin returns -1/EINVAL when a valid ACL has no first entry.
        if(acl_get_entry(acl,ACL_FIRST_ENTRY,&entry)==-1 && errno==EINVAL)result=0;
    }
    if(acl_free(acl)!=0)return 1;
    return result;
}
#endif
