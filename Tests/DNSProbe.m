// Developer-only probe. Not shipped in the application or installed payload.
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <CommonCrypto/CommonDigest.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

static id Normalize(id value) {
    if([value isKindOfClass:NSData.class])return [value base64EncodedStringWithOptions:0];
    if([value isKindOfClass:NSDate.class])return [value description];
    if([value isKindOfClass:NSArray.class]){
        NSMutableArray *items=[NSMutableArray array];for(id item in value)[items addObject:Normalize(item)];return items;
    }
    if([value isKindOfClass:NSDictionary.class]){
        NSMutableDictionary *items=[NSMutableDictionary dictionary];
        for(id key in value)items[key]=Normalize(value[key]);return items;
    }
    return value;
}

int main(int argc,const char *argv[]) {
    @autoreleasepool {
        NSDictionary *report=nil;
        if(argc==2 && strcmp(argv[1],"snapshot")==0){
            CFArrayRef patterns=(__bridge CFArrayRef)@[@"State:/Network/Service/.*/DNS",@"Setup:/Network/Service/.*/DNS",@"State:/Network/Global/DNS"];
            CFDictionaryRef raw=SCDynamicStoreCopyMultiple(NULL,NULL,patterns);
            if(!raw)return 1;
            NSMutableDictionary *foreign=[CFBridgingRelease(raw) mutableCopy];
            BOOL present=foreign[@"State:/Network/Service/org.legacywg.tunnel/DNS"]!=nil;
            [foreign removeObjectForKey:@"State:/Network/Service/org.legacywg.tunnel/DNS"];
            NSData *canonical=[NSJSONSerialization dataWithJSONObject:Normalize(foreign) options:NSJSONWritingSortedKeys error:NULL];
            if(!canonical || canonical.length>UINT32_MAX)return 1;
            unsigned char hash[CC_SHA256_DIGEST_LENGTH];CC_SHA256(canonical.bytes,(CC_LONG)canonical.length,hash);
            NSMutableString *digest=[NSMutableString string];
            for(NSUInteger i=0;i<sizeof(hash);i++)[digest appendFormat:@"%02x",hash[i]];
            report=@{@"dns_present":@(present),@"foreign_digest":digest,@"foreign_count":@(foreign.count)};
        } else if(argc==3 && strcmp(argv[1],"resolve")==0){
            struct addrinfo hints={0},*addresses=NULL;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
            int result=getaddrinfo(argv[2],NULL,&hints,&addresses);
            BOOL match=NO;
            if(result==0){
                for(struct addrinfo *item=addresses;item;item=item->ai_next){
                    struct sockaddr_in *socket=(struct sockaddr_in *)item->ai_addr;
                    char address[INET_ADDRSTRLEN]={0};
                    if(inet_ntop(AF_INET,&socket->sin_addr,address,sizeof(address)) && strcmp(address,"198.18.0.77")==0)match=YES;
                }
            }
            if(addresses)freeaddrinfo(addresses);
            report=@{@"ok":@(match),@"resolver_error":@(result)};
        } else return 2;
        NSData *json=[NSJSONSerialization dataWithJSONObject:report options:0 error:NULL];
        [NSFileHandle.fileHandleWithStandardOutput writeData:json];return 0;
    }
}
