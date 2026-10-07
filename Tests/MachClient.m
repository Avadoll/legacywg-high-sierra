#import <Foundation/Foundation.h>
#import "../Shared/LWMach.h"
#include <stdio.h>
#include <string.h>

#ifdef LW_UNTRUSTED_TEST
__attribute__((used)) static const char differentBinary[] = "LegacyWG unsigned-caller rejection test";
#endif

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        NSDictionary *reply = LWRequest(@{@"version": @1, @"op": @"health"}, [NSString stringWithUTF8String:argv[1]]);
        NSData *json = [NSJSONSerialization dataWithJSONObject:reply options:NSJSONWritingPrettyPrinted error:NULL];
        fwrite(json.bytes, 1, json.length, stdout);
        return [reply[@"ok"] isEqual:@YES] ? 0 : 1;
    }
}
