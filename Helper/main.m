#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "../Shared/LWMach.h"
#include <servers/bootstrap.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>

static NSString *ReadPolicy(void) {
    const char *path = "/Library/Application Support/LegacyWG/AllowedClient.req";
    for (const char **ancestor = (const char *[]){"/Library", "/Library/Application Support",
         "/Library/Application Support/LegacyWG", NULL}; *ancestor; ++ancestor) {
        struct stat directory;
        if (lstat(*ancestor, &directory) != 0 || !S_ISDIR(directory.st_mode) ||
            directory.st_uid != 0 || (directory.st_mode & 0022)) return nil;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat status;
    char buffer[2049] = {0};
    ssize_t count = -1;
    if (fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_uid == 0 &&
        !(status.st_mode & 0022) && status.st_size > 0 && status.st_size <= 2048)
        count = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    return count > 0 && count == status.st_size ? [[NSString alloc] initWithBytes:buffer length:(NSUInteger)count encoding:NSUTF8StringEncoding] : nil;
}

static NSDictionary *HandleRequest(NSData *data, uid_t uid) {
    if (uid == 0) return @{@"ok": @NO, @"error": @"User session required"};
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![object isKindOfClass:[NSDictionary class]]) return @{@"ok": @NO, @"error": @"Invalid request"};
    NSDictionary *request = object;
    if (request.count != 2 || ![request[@"version"] isEqual:@1] || ![request[@"op"] isEqual:@"health"])
        return @{@"ok": @NO, @"error": @"Unsupported operation"};
    return @{@"ok": @YES, @"version": @1, @"state": @"Disconnected", @"authenticated_uid": @(uid),
             @"vpn_ready": @NO};
}

int main(void) {
    @autoreleasepool {
        if (geteuid() != 0) return 1;
        NSString *policy = ReadPolicy();
        if (!policy) return 2;
        mach_port_t port = MACH_PORT_NULL;
        if (bootstrap_check_in(bootstrap_port, LW_SERVICE, &port) != KERN_SUCCESS) return 3;
        for (;;) { @autoreleasepool {
            LWMessage *message = calloc(1, sizeof(*message));
            if (!message) return 4;
            mach_msg_return_t status = mach_msg(&message->header, MACH_RCV_MSG |
                MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                0, sizeof(*message), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            if (status != MACH_MSG_SUCCESS) { free(message); continue; }
            audit_token_t token;
            NSData *payload = nil;
            BOOL valid = LWDecodeMessage(message, &token, &payload);
            BOOL authorized = valid && LWVerifySender(&token, policy);
            NSDictionary *response = authorized ? HandleRequest(payload, audit_token_to_euid(token)) :
                @{@"ok": @NO, @"error": @"Unauthorized client"};
            mach_port_t reply = message->header.msgh_remote_port;
            BOOL canReply = !(message->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
                MACH_MSGH_BITS_REMOTE(message->header.msgh_bits) == MACH_MSG_TYPE_PORT_SEND_ONCE && MACH_PORT_VALID(reply);
            if (canReply) {
                NSData *json = [NSJSONSerialization dataWithJSONObject:response options:0 error:NULL];
                LWMessage *outgoing = calloc(1, sizeof(*outgoing));
                if (outgoing && json.length <= LW_MAX_PAYLOAD) {
                    outgoing->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
                    outgoing->header.msgh_remote_port = reply;
                    outgoing->header.msgh_id = LW_MESSAGE_ID;
                    outgoing->header.msgh_size = (mach_msg_size_t)((offsetof(LWMessage, payload) + json.length + 3U) & ~3U);
                    outgoing->length = (uint32_t)json.length;
                    memcpy(outgoing->payload, json.bytes, json.length);
                    mach_msg_return_t sent = mach_msg(&outgoing->header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                        outgoing->header.msgh_size, 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
                    if (sent != MACH_MSG_SUCCESS) mach_msg_destroy(&outgoing->header);
                    message->header.msgh_remote_port = MACH_PORT_NULL;
                }
                free(outgoing);
            }
            mach_msg_destroy(&message->header);
            memset_s(message, sizeof(*message), 0, sizeof(*message)); free(message);
        }}
    }
}
