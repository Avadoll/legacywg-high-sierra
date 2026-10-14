/* Developer-only empty transaction experiment, never packaged in the client.
 * Original LP64 projection of XNU pfioc_trans, not a PF policy loader.
 * Only a random fixture path, empty filter/NAT classes and begin/commit/rollback
 * are admitted. No enable, references, states, global or foreign operations. */
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct transaction_entry { int32_t kind; uint32_t ticket; char anchor[1024]; };
struct transaction { int32_t count, entry_size; struct transaction_entry *entries; };
_Static_assert(sizeof(void *) == 8, "Intel LP64 only");
_Static_assert(sizeof(struct transaction_entry) == 1032, "entry ABI");
_Static_assert(sizeof(struct transaction) == 16, "header ABI");
#define BEGIN _IOWR('D', 81, struct transaction)
#define COMMIT _IOWR('D', 82, struct transaction)
#define ROLLBACK _IOWR('D', 83, struct transaction)

int main(int argc, char **argv) {
    const char prefix[] = "com.apple/lw-xact-ci-";
    const char *ci = getenv("GITHUB_ACTIONS");
    if (argc != 3 || geteuid() != 0 || !ci || strcmp(ci, "true") != 0 ||
        strncmp(argv[1], prefix, sizeof(prefix)-1) != 0 ||
        strlen(argv[1]) != sizeof(prefix)-1+32 ||
        strspn(argv[1]+sizeof(prefix)-1, "0123456789abcdef") != 32 ||
        (strcmp(argv[2], "single") != 0 && strcmp(argv[2], "multi") != 0)) return 2;
    struct transaction_entry entries[2] = {{0}};
    entries[0].kind = 1; /* PF_RULESET_FILTER */
    entries[1].kind = 2; /* PF_RULESET_NAT */
    memcpy(entries[0].anchor, argv[1], strlen(argv[1])+1);
    memcpy(entries[1].anchor, argv[1], strlen(argv[1])+1);
    struct transaction tx = {strcmp(argv[2], "single") == 0 ? 1 : 2, sizeof(entries[0]), entries};
    int fd = open("/dev/pf", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISCHR(status.st_mode) || status.st_uid != 0) {
        if (fd >= 0) close(fd);
        return 3;
    }
    int result = 0;
    if (ioctl(fd, BEGIN, &tx) != 0) result = 4;
    else if (ioctl(fd, COMMIT, &tx) != 0) {
        (void)ioctl(fd, ROLLBACK, &tx);
        result = 5;
    }
    close(fd);
    return result;
}
