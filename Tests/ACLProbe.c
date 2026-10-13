#include "../NetworkAgent/ACLCheck.h"
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(geteuid()!=0 || argc!=2 || strcmp(argv[1],"--check-no-acl")!=0)return 1;
    return LWCheckNoACL(3);
}
