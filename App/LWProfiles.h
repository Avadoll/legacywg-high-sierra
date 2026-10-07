#import <Foundation/Foundation.h>
NSArray<NSDictionary *> *LWListProfiles(void);
BOOL LWStoreProfile(NSData *data, NSString *name, NSString **identifier, NSError **error);
NSData *LWReadProfile(NSString *identifier, NSError **error);
BOOL LWDeleteProfile(NSString *identifier, NSError **error);
