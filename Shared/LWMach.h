#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>

#define LW_SERVICE "org.legacywg.helper"
#define LW_MAX_PAYLOAD (256U * 1024U + 4096U)
#define LW_MESSAGE_ID 0x4c574701

typedef struct {
    mach_msg_header_t header;
    uint32_t length;
    uint8_t payload[LW_MAX_PAYLOAD];
    mach_msg_max_trailer_t trailer;
} LWMessage;

// Authenticates the kernel-provided audit token, never a caller supplied PID.
BOOL LWVerifySender(const audit_token_t *token, NSString *requirement);
BOOL LWDecodeMessage(LWMessage *message, audit_token_t *token, NSData **payload);
NSDictionary *LWRequest(NSDictionary *request, NSString *serverRequirement);

