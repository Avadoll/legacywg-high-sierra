#import <Foundation/Foundation.h>
NSArray<NSDictionary *> *LWListProfiles(void);
BOOL LWStoreProfile(NSData *data, NSString *name, NSString **identifier, NSError **error);
NSData *LWReadProfile(NSString *identifier, NSError **error);
BOOL LWDeleteProfile(NSString *identifier, NSError **error);
BOOL LWRenameProfile(NSString *identifier, NSString *name, NSError **error);
NSArray<NSDictionary *> *LWProfileImportConflicts(NSData *data, NSString *name, NSError **error);
BOOL LWProfileNameAvailable(NSString *name, NSError **error);
BOOL LWReplaceProfile(NSString *identifier, NSData *data, NSError **error);
