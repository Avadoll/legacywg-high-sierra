#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>

_Static_assert(sizeof(struct rt_msghdr) == 92, "Darwin route header size");
_Static_assert(offsetof(struct rt_msghdr, rtm_errno) == 24, "Darwin errno offset");
_Static_assert(offsetof(struct rt_msghdr, rtm_use) == 28, "Darwin use offset");

int main(void) {
    puts("LEGACYWG_DARWIN_ROUTE_HEADER_PASS");
    return 0;
}
