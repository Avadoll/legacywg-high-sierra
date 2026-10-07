#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import "../Shared/LWMach.h"
#include <servers/bootstrap.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>

static NSString *ReadPolicy(const char *path) {
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

static NSTask *worker;
static NSPipe *workerInput;
static NSPipe *workerOutput;
static uid_t ownerUID = (uid_t)-1;
static NSTimeInterval lastOwnerMessage = 0;

static void StopWorker(void) {
    if (worker.running) {
        [workerInput.fileHandleForWriting closeFile];
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:3];
        while (worker.running && deadline.timeIntervalSinceNow > 0) [NSThread sleepForTimeInterval:0.02];
        if (worker.running) [worker terminate];
        deadline = [NSDate dateWithTimeIntervalSinceNow:1];
        while (worker.running && deadline.timeIntervalSinceNow > 0) [NSThread sleepForTimeInterval:0.02];
        if (worker.running) kill(worker.processIdentifier, SIGKILL);
        [worker waitUntilExit];
    }
    [workerOutput.fileHandleForReading closeFile];
    worker = nil; workerInput = nil; workerOutput = nil; ownerUID = (uid_t)-1;
}

static BOOL StartWorker(void) {
    const char *path = "/Library/Application Support/LegacyWG/legacywg-worker";
    NSString *requirement = ReadPolicy("/Library/Application Support/LegacyWG/Worker.req");
    struct stat file;
    if (!requirement || lstat(path, &file) != 0 || !S_ISREG(file.st_mode) || file.st_uid != 0 ||
        (file.st_mode & 0022)) return NO;
    SecStaticCodeRef code = NULL;
    SecRequirementRef policy = NULL;
    NSString *workerPath = [NSString stringWithUTF8String:path];
    OSStatus result = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:workerPath], kSecCSDefaultFlags, &code);
    if (result == errSecSuccess) result = SecRequirementCreateWithString((__bridge CFStringRef)requirement, kSecCSDefaultFlags, &policy);
    if (result == errSecSuccess) result = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, policy);
    if (code) CFRelease(code); if (policy) CFRelease(policy);
    if (result != errSecSuccess) return NO;
    worker = [[NSTask alloc] init]; worker.launchPath = workerPath; worker.arguments = @[];
    worker.environment = @{@"PATH": @"/usr/bin:/bin:/usr/sbin:/sbin", @"LANG": @"C"};
    workerInput = [NSPipe pipe]; workerOutput = [NSPipe pipe];
    worker.standardInput = workerInput; worker.standardOutput = workerOutput;
    worker.standardError = [NSFileHandle fileHandleWithNullDevice];
    @try { [worker launch]; } @catch (NSException *exception) { (void)exception; StopWorker(); return NO; }
    return YES;
}

static NSDictionary *WorkerRequest(NSDictionary *request) {
    if (!worker.running) return @{@"ok": @NO, @"error": @"Engine process is unavailable"};
    NSData *json = [NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
    NSMutableData *line = [json mutableCopy]; [line appendBytes:"\n" length:1];
    @try { [workerInput.fileHandleForWriting writeData:line]; }
    @catch (NSException *exception) { (void)exception; StopWorker(); return @{@"ok": @NO, @"error": @"Engine pipe closed"}; }
    memset_s(line.mutableBytes, line.length, 0, line.length);
    NSMutableData *response = [NSMutableData data];
    NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 12;
    int descriptor = workerOutput.fileHandleForReading.fileDescriptor;
    while (response.length < 65536 && NSProcessInfo.processInfo.systemUptime < deadline) {
        struct pollfd poller = {descriptor, POLLIN, 0};
        if (poll(&poller, 1, 100) <= 0) continue;
        uint8_t byte;
        if (read(descriptor, &byte, 1) != 1) break;
        if (byte == '\n') {
            id object = [NSJSONSerialization JSONObjectWithData:response options:0 error:NULL];
            if ([object isKindOfClass:[NSDictionary class]]) return object;
            break;
        }
        [response appendBytes:&byte length:1];
    }
    StopWorker();
    return @{@"ok": @NO, @"error": @"Engine request timed out; tunnel process closed"};
}

static NSDictionary *HandleRequest(NSData *data, uid_t uid) {
    if (uid == 0) return @{@"ok": @NO, @"error": @"User session required"};
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![object isKindOfClass:[NSDictionary class]]) return @{@"ok": @NO, @"error": @"Invalid request"};
    NSDictionary *request = object;
    NSString *operation = request[@"op"];
    if (![request[@"version"] isEqual:@1] || ![operation isKindOfClass:[NSString class]])
        return @{@"ok": @NO, @"error": @"Unsupported operation"};
    if ([operation isEqualToString:@"health"] && request.count == 2)
        return @{@"ok": @YES, @"version": @1, @"state": @"Available", @"authenticated_uid": @(uid), @"vpn_ready": @NO};
    if (worker && !worker.running) StopWorker();
    if (ownerUID != (uid_t)-1 && ownerUID != uid) return @{@"ok": @NO, @"error": @"Tunnel belongs to another user session"};
    uid_t consoleUID = (uid_t)-1;
    CFStringRef console = SCDynamicStoreCopyConsoleUser(NULL, &consoleUID, NULL);
    if (console) CFRelease(console);
    if (consoleUID != uid) return @{@"ok": @NO, @"error": @"Active console user required"};
    lastOwnerMessage = NSProcessInfo.processInfo.systemUptime;
    if ([operation isEqualToString:@"start"] && request.count == 3 && [request[@"profile"] isKindOfClass:[NSString class]]) {
        if ([request[@"profile"] lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 256*1024 || worker)
            return @{@"ok": @NO, @"error": @"Profile too large or tunnel already active"};
        if (!StartWorker()) return @{@"ok": @NO, @"error": @"Installed engine integrity check failed"};
        NSDictionary *reply = WorkerRequest(request);
        if (![reply[@"ok"] isEqual:@YES]) StopWorker(); else ownerUID = uid;
        return reply;
    }
    if ([operation isEqualToString:@"stop"] && request.count == 2) {
        NSDictionary *reply = worker ? WorkerRequest(request) : @{@"ok": @YES};
        StopWorker(); return reply;
    }
    if ([operation isEqualToString:@"status"] && request.count == 2)
        return worker ? WorkerRequest(request) : @{@"ok": @YES, @"status": @{@"state": @"Disconnected", @"protected": @NO}};
    return @{@"ok": @NO, @"error": @"Unsupported operation"};
}

int main(void) {
    @autoreleasepool {
        if (geteuid() != 0) return 1;
        struct rlimit coreLimit = {0,0}; if(setrlimit(RLIMIT_CORE,&coreLimit)!=0)return 5;
        signal(SIGPIPE, SIG_IGN);
        NSString *policy = ReadPolicy("/Library/Application Support/LegacyWG/AllowedClient.req");
        if (!policy) return 2;
        mach_port_t port = MACH_PORT_NULL;
        if (bootstrap_check_in(bootstrap_port, LW_SERVICE, &port) != KERN_SUCCESS) return 3;
        for (;;) { @autoreleasepool {
            if (worker && (NSProcessInfo.processInfo.systemUptime - lastOwnerMessage > 15 || !worker.running)) StopWorker();
            LWMessage *message = calloc(1, sizeof(*message));
            if (!message) return 4;
            mach_msg_return_t status = mach_msg(&message->header, MACH_RCV_MSG | MACH_RCV_TIMEOUT |
                MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                0, sizeof(*message), port, 1000, MACH_PORT_NULL);
            if (status != MACH_MSG_SUCCESS) {
                free(message);
                if (worker && (NSProcessInfo.processInfo.systemUptime - lastOwnerMessage > 15 || !worker.running)) StopWorker();
                continue;
            }
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
