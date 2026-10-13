#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>

// A private, root-only subprocess. It accepts numeric DNS settings, never a
// profile, executable path, shell command, preference key or recovery command.
static BOOL Reply(BOOL ok) {
    NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"ok":@(ok)} options:0 error:NULL];
    @try {
        [NSFileHandle.fileHandleWithStandardOutput writeData:json];
        [NSFileHandle.fileHandleWithStandardOutput writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
    } @catch(NSException *exception) { (void)exception; return NO; }
    return YES;
}

static BOOL NumericAddress(NSString *text) {
    if(![text isKindOfClass:NSString.class] || text.length>45)return NO;
    struct in_addr v4; struct in6_addr v6;
    return inet_pton(AF_INET,text.UTF8String,&v4)==1 || inet_pton(AF_INET6,text.UTF8String,&v6)==1;
}

int main(void) {
    struct rlimit core={0,0};
    if(geteuid()!=0 || setrlimit(RLIMIT_CORE,&core)!=0)return 1;
    signal(SIGPIPE,SIG_IGN);
    @autoreleasepool {
        NSMutableData *line=[NSMutableData data];
        // Bound the initialization wait and payload. Parent holds the pipe
        // open for the lifetime of the tunnel after one complete request.
        NSTimeInterval deadline=NSProcessInfo.processInfo.systemUptime+5;
        BOOL complete=NO;
        while(line.length<4096 && NSProcessInfo.processInfo.systemUptime<deadline) {
            struct pollfd input={STDIN_FILENO,POLLIN,0};
            if(poll(&input,1,100)<=0)continue;
            unsigned char byte;
            if(read(STDIN_FILENO,&byte,1)!=1)break;
            if(byte=='\n'){complete=YES;break;}
            [line appendBytes:&byte length:1];
        }
        id parsed=complete ? [NSJSONSerialization JSONObjectWithData:line options:0 error:NULL] : nil;
        if(![parsed isKindOfClass:NSDictionary.class]){Reply(NO);return 2;}
        NSDictionary *request=parsed;
        NSString *interface=request[@"interface"];
        NSArray *servers=request[@"servers"];
        if(request.count!=3 || ![request[@"version"] isEqual:@1] ||
           ![interface isKindOfClass:NSString.class] || ![interface hasPrefix:@"utun"] ||
           interface.length<5 || interface.length>15 ||
           [[interface substringFromIndex:4] rangeOfCharacterFromSet:NSCharacterSet.decimalDigitCharacterSet.invertedSet].location!=NSNotFound ||
           !if_nametoindex(interface.UTF8String) || ![servers isKindOfClass:NSArray.class] ||
           !servers.count || servers.count>8){Reply(NO);return 2;}
        for(id server in servers)if(!NumericAddress(server)){Reply(NO);return 2;}
        unsigned int interfaceIndex=if_nametoindex(interface.UTF8String);
        SCDynamicStoreRef store=SCDynamicStoreCreate(NULL,CFSTR("LegacyWG DNS transaction"),NULL,NULL);
        if(!store){Reply(NO);return 3;}
        CFStringRef key=CFSTR("State:/Network/Service/org.legacywg.tunnel/DNS");
        NSDictionary *dns=@{(__bridge NSString *)kSCPropNetDNSServerAddresses:servers,
            (__bridge NSString *)kSCPropNetDNSSupplementalMatchDomains:@[@""],
            (__bridge NSString *)kSCPropNetDNSSupplementalMatchOrders:@[@1],
            (__bridge NSString *)kSCPropNetDNSSearchOrder:@1};
        // Add, never overwrite. configd owns automatic cleanup of this key
        // when the owning session dies, including SIGKILL. No persistent
        // network service preferences or global DNS key are changed.
        BOOL added=SCDynamicStoreAddTemporaryValue(store,key,(__bridge CFDictionaryRef)dns);
        BOOL sent=Reply(added);
        if(added && sent) {
            for(;;) {
                struct pollfd input={STDIN_FILENO,POLLIN,0};
                int ready=poll(&input,1,1000);
                if(ready<0)break;
                if(ready>0)break; // EOF or any extra input closes our session.
                CFPropertyListRef current=SCDynamicStoreCopyValue(store,key);
                BOOL valid=current && CFEqual(current,(__bridge CFDictionaryRef)dns) &&
                    if_nametoindex(interface.UTF8String)==interfaceIndex;
                if(current)CFRelease(current);
                // A configd restart/key replacement/interface loss invalidates
                // the transaction. Never overwrite another session's value.
                if(!valid || !Reply(YES))break;
            }
        }
        CFRelease(store);
        return added ? 0 : 3;
    }
}
