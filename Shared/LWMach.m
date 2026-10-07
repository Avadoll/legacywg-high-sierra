#import "LWMach.h"
#import <Security/Security.h>
#include <servers/bootstrap.h>
#include <stddef.h>
#include <string.h>

BOOL LWVerifySender(const audit_token_t *token, NSString *requirement) {
    if (!token || !requirement.length || requirement.length > 2048) return NO;
    SecCodeRef code = NULL;
    SecRequirementRef policy = NULL;
    NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributeAudit:
        [NSData dataWithBytes:token length:sizeof(*token)]};
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes,
                                                   kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) status = SecRequirementCreateWithString((__bridge CFStringRef)requirement,
                                                                        kSecCSDefaultFlags, &policy);
    if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSStrictValidate, policy);
    if (policy) CFRelease(policy);
    if (code) CFRelease(code);
    return status == errSecSuccess;
}

BOOL LWDecodeMessage(LWMessage *message, audit_token_t *token, NSData **payload) {
    const size_t base = offsetof(LWMessage, payload);
    size_t size = message->header.msgh_size;
    if ((message->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) || message->header.msgh_id != LW_MESSAGE_ID ||
        size < base || size > base + LW_MAX_PAYLOAD || message->length > LW_MAX_PAYLOAD ||
        size != ((base + message->length + 3U) & ~3U)) return NO;
    mach_msg_audit_trailer_t *trailer = (void *)((uint8_t *)message + ((size + 3U) & ~3U));
    if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
        trailer->msgh_trailer_size < sizeof(*trailer) ||
        ((size + 3U) & ~3U) + trailer->msgh_trailer_size > sizeof(*message)) return NO;
    *token = trailer->msgh_audit;
    *payload = [NSData dataWithBytes:message->payload length:message->length];
    return YES;
}

NSDictionary *LWRequest(NSDictionary *request, NSString *serverRequirement) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
    if (!data || data.length > LW_MAX_PAYLOAD) return @{@"ok": @NO, @"error": @"Invalid request size"};
    mach_port_t server = MACH_PORT_NULL, reply = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, LW_SERVICE, &server) != KERN_SUCCESS)
        return @{@"ok": @NO, @"error": @"Сетевой компонент не установлен или недоступен"};
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply) != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), server);
        return @{@"ok": @NO, @"error": @"Cannot create response port"};
    }
    LWMessage *message = calloc(1, sizeof(*message));
    if (!message) {
        mach_port_destroy(mach_task_self(), reply); mach_port_deallocate(mach_task_self(), server);
        return @{@"ok": @NO, @"error": @"Insufficient memory"};
    }
    message->length = (uint32_t)data.length;
    memcpy(message->payload, data.bytes, data.length);
    message->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    message->header.msgh_remote_port = server;
    message->header.msgh_local_port = reply;
    message->header.msgh_id = LW_MESSAGE_ID;
    message->header.msgh_size = (mach_msg_size_t)((offsetof(LWMessage, payload) + data.length + 3U) & ~3U);
    mach_msg_return_t status = mach_msg(&message->header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                       message->header.msgh_size, 0, MACH_PORT_NULL, 2000, MACH_PORT_NULL);
    // Wipe outgoing key material before reusing this buffer for the response.
    memset_s(message, sizeof(*message), 0, sizeof(*message));
    if (status == MACH_MSG_SUCCESS) status = mach_msg(&message->header,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT), 0, sizeof(*message), reply, 15000, MACH_PORT_NULL);
    NSDictionary *result = nil;
    if (status == MACH_MSG_SUCCESS) {
        audit_token_t token;
        NSData *response = nil;
        if (LWDecodeMessage(message, &token, &response) && audit_token_to_euid(token) == 0 &&
            LWVerifySender(&token, serverRequirement)) {
            id object = [NSJSONSerialization JSONObjectWithData:response options:0 error:NULL];
            if ([object isKindOfClass:[NSDictionary class]]) result = object;
        }
        mach_msg_destroy(&message->header);
    }
    memset_s(message, sizeof(*message), 0, sizeof(*message)); free(message);
    mach_port_destroy(mach_task_self(), reply); mach_port_deallocate(mach_task_self(), server);
    return result ?: @{@"ok": @NO, @"error": @"Компонент не подтвердил подлинность ответа или не ответил вовремя"};
}
