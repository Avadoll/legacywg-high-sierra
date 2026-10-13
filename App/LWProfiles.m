#import "LWProfiles.h"
#import <Security/Security.h>

static NSString *const service = @"org.legacywg.profile";

static BOOL ValidProfileName(NSString *name) {
    if(![name isKindOfClass:NSString.class] || !name.length || name.length>80 ||
       ![name canBeConvertedToEncoding:NSUTF8StringEncoding] ||
       ![name isEqualToString:[name stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]])return NO;
    NSMutableCharacterSet *forbidden=[NSCharacterSet.controlCharacterSet mutableCopy];
    [forbidden addCharactersInString:@"\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"];
    return [name rangeOfCharacterFromSet:forbidden].location==NSNotFound;
}

static NSError *NameError(void) {
    return [NSError errorWithDomain:@"LegacyWG.ProfileName" code:1 userInfo:@{NSLocalizedDescriptionKey:
        @"Имя должно содержать от 1 до 80 символов, без управляющих символов и пробелов по краям."}];
}

static NSError *KeychainError(OSStatus status) {
    CFStringRef text = SecCopyErrorMessageString(status, NULL);
    NSString *message = text ? CFBridgingRelease(text) : @"Keychain operation failed";
    return [NSError errorWithDomain:@"LegacyWG.Keychain" code:status userInfo:@{NSLocalizedDescriptionKey: message}];
}

static NSArray<NSDictionary *> *ListProfiles(NSError **error) {
    NSDictionary *query = @{(__bridge NSString *)kSecClass:(__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService:service, (__bridge NSString *)kSecReturnAttributes:@YES,
        (__bridge NSString *)kSecMatchLimit:(__bridge NSString *)kSecMatchLimitAll};
    CFTypeRef raw = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &raw);
    if (status != errSecSuccess) {
        if (raw) CFRelease(raw);
        if(status==errSecItemNotFound)return @[];
        if(error)*error=KeychainError(status);return nil;
    }
    id attributes = CFBridgingRelease(raw);
    if (![attributes isKindOfClass:[NSArray class]]) {if(error)*error=KeychainError(errSecDecode);return nil;}
    NSMutableArray *profiles = [NSMutableArray array];
    for (NSDictionary *item in attributes) {
        if(![item isKindOfClass:NSDictionary.class]){if(error)*error=KeychainError(errSecDecode);return nil;}
        NSString *identifier = item[(__bridge NSString *)kSecAttrAccount];
        NSString *name = item[(__bridge NSString *)kSecAttrLabel];
        if ([identifier isKindOfClass:[NSString class]] && [[NSUUID alloc] initWithUUIDString:identifier])
            [profiles addObject:@{@"id":identifier, @"name":ValidProfileName(name) ? name : @"WireGuard"}];
    }
    return [profiles sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *first, NSDictionary *second) {
        return [first[@"name"] localizedCaseInsensitiveCompare:second[@"name"]];
    }];
}

NSArray<NSDictionary *> *LWListProfiles(void) { return ListProfiles(NULL) ?: @[]; }

static BOOL SameName(NSString *first, NSString *second) {
    return [[first precomposedStringWithCanonicalMapping] caseInsensitiveCompare:
        [second precomposedStringWithCanonicalMapping]]==NSOrderedSame;
}

static NSError *ImportError(NSString *message) {
    return [NSError errorWithDomain:@"LegacyWG.ProfileImport" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
}

NSArray<NSDictionary *> *LWProfileImportConflicts(NSData *data, NSString *name, NSError **error) {
    if(!ValidProfileName(name)){if(error)*error=NameError();return nil;}
    if(!data.length || data.length>256*1024){if(error)*error=ImportError(@"Допустимый размер профиля — до 256 КиБ.");return nil;}
    NSArray *profiles=ListProfiles(error);if(!profiles)return nil;
    // A bounded private comparison; no hashes/keys/configs in public attributes.
    // Locked or unreadable Keychain aborts before any write instead of treating
    // the inaccessible item as absent. Explicit copies may share secret data.
    if(profiles.count>128){if(error)*error=ImportError(@"Для проверки повторного импорта поддерживается до 128 профилей.");return nil;}
    NSMutableArray *conflicts=[NSMutableArray array];
    for(NSDictionary *profile in profiles) {
        @autoreleasepool {
            NSData *existing=LWReadProfile(profile[@"id"],error);
            if(!existing)return nil;
            if(SameName(profile[@"name"],name) || [existing isEqualToData:data])[conflicts addObject:profile];
        }
    }
    return conflicts;
}

BOOL LWProfileNameAvailable(NSString *name, NSError **error) {
    if(!ValidProfileName(name)){if(error)*error=NameError();return NO;}
    NSArray *profiles=ListProfiles(error);if(!profiles)return NO;
    if(profiles.count>=128){if(error)*error=ImportError(@"Поддерживается до 128 профилей. Удалите ненужный профиль перед импортом.");return NO;}
    for(NSDictionary *profile in profiles)if(SameName(profile[@"name"],name)) {
        if(error)*error=ImportError(@"Профиль с таким именем уже существует. Выберите новое имя.");return NO;
    }
    return YES;
}

BOOL LWReplaceProfile(NSString *identifier, NSData *data, NSError **error) {
    if(![[NSUUID alloc] initWithUUIDString:identifier] || !data.length || data.length>256*1024) {
        if(error)*error=ImportError(@"Недопустимый профиль для замены.");return NO;
    }
    NSDictionary *query=@{(__bridge NSString *)kSecClass:(__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService:service,(__bridge NSString *)kSecAttrAccount:identifier};
    // One exact item update; no delete/add window, ID/label/access untouched.
    OSStatus status=SecItemUpdate((__bridge CFDictionaryRef)query,
        (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecValueData:data});
    if(status!=errSecSuccess){if(error)*error=KeychainError(status);return NO;}
    return YES;
}

BOOL LWStoreProfile(NSData *data, NSString *name, NSString **identifier, NSError **error) {
    if (!data.length || data.length > 256*1024) return NO;
    if(!ValidProfileName(name)){if(error)*error=NameError();return NO;}
    NSString *account = NSUUID.UUID.UUIDString;
    SecTrustedApplicationRef selfApplication = NULL;
    SecAccessRef access = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &selfApplication);
    if (status == errSecSuccess) status = SecAccessCreate((__bridge CFStringRef)[@"LegacyWG: " stringByAppendingString:name],
        (__bridge CFArrayRef)@[(__bridge id)selfApplication], &access);
    if (selfApplication) CFRelease(selfApplication);
    if (status == errSecSuccess) {
        NSDictionary *item = @{(__bridge NSString *)kSecClass:(__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService:service, (__bridge NSString *)kSecAttrAccount:account,
            (__bridge NSString *)kSecAttrLabel:name, (__bridge NSString *)kSecAttrAccess:(__bridge id)access,
            (__bridge NSString *)kSecValueData:data};
        status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    }
    if (access) CFRelease(access);
    if (status != errSecSuccess) { if (error) *error = KeychainError(status); return NO; }
    if (identifier) *identifier = account;
    return YES;
}

NSData *LWReadProfile(NSString *identifier, NSError **error) {
    if (![[NSUUID alloc] initWithUUIDString:identifier]) return nil;
    NSDictionary *query = @{(__bridge NSString *)kSecClass:(__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService:service, (__bridge NSString *)kSecAttrAccount:identifier,
        (__bridge NSString *)kSecReturnData:@YES, (__bridge NSString *)kSecMatchLimit:(__bridge NSString *)kSecMatchLimitOne};
    CFTypeRef raw = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &raw);
    if (status != errSecSuccess) { if (error) *error = KeychainError(status); if(raw)CFRelease(raw); return nil; }
    id data = CFBridgingRelease(raw);
    return [data isKindOfClass:[NSData class]] && [data length] <= 256*1024 ? data : nil;
}

BOOL LWDeleteProfile(NSString *identifier, NSError **error) {
    if (![[NSUUID alloc] initWithUUIDString:identifier]) return NO;
    NSDictionary *query = @{(__bridge NSString *)kSecClass:(__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService:service, (__bridge NSString *)kSecAttrAccount:identifier};
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess) { if (error) *error = KeychainError(status); return NO; }
    return YES;
}

BOOL LWRenameProfile(NSString *identifier, NSString *name, NSError **error) {
    if(![[NSUUID alloc] initWithUUIDString:identifier])return NO;
    if(!ValidProfileName(name)){if(error)*error=NameError();return NO;}
    NSDictionary *query=@{(__bridge NSString *)kSecClass:(__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService:service,(__bridge NSString *)kSecAttrAccount:identifier};
    // Change only the display label. Profile ID, secret data and ACL remain
    // untouched; an active session keeps exactly the same tunnel identity.
    OSStatus status=SecItemUpdate((__bridge CFDictionaryRef)query,
        (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecAttrLabel:name});
    if(status!=errSecSuccess){if(error)*error=KeychainError(status);return NO;}
    return YES;
}
