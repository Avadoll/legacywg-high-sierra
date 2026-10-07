#import <Foundation/Foundation.h>
#import "../Shared/LWMach.h"
#include <stdio.h>
#include <string.h>

#ifdef LW_UNTRUSTED_TEST
__attribute__((used)) static const char differentBinary[] = "LegacyWG unsigned-caller rejection test";
#endif

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2 && argc != 3) return 2;
        NSString *operation=argc==3 ? [NSString stringWithUTF8String:argv[2]] : @"health";
        NSMutableDictionary *request=[@{@"version":@1,@"op":operation} mutableCopy];
        if([operation isEqualToString:@"start"]) {
            NSData *profile=[NSFileHandle.fileHandleWithStandardInput readDataOfLength:256*1024+1];
            NSString *text=profile.length<=256*1024 ? [[NSString alloc] initWithData:profile encoding:NSUTF8StringEncoding] : nil;
            if(!text)return 3; request[@"profile"]=text;
        }
        NSDictionary *reply = LWRequest(request, [NSString stringWithUTF8String:argv[1]]);
        NSData *json = [NSJSONSerialization dataWithJSONObject:reply options:NSJSONWritingPrettyPrinted error:NULL];
        fwrite(json.bytes, 1, json.length, stdout);
        return [reply[@"ok"] isEqual:@YES] ? 0 : 1;
    }
}
