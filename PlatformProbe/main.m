#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#include <sys/utsname.h>
#include <string.h>

static NSDictionary *LoadManifest(void) {
    NSURL *url = [[NSBundle mainBundle] URLForResource:@"BuildManifest" withExtension:@"json"];
    NSData *data = url ? [NSData dataWithContentsOfURL:url] : nil;
    id object = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
    return [object isKindOfClass:[NSDictionary class]] ? object : nil;
}

static NSString *HashFile(NSURL *url) {
    NSNumber *size = nil;
    if (![url getResourceValue:&size forKey:NSURLFileSizeKey error:NULL] || size.unsignedLongLongValue > 50 * 1024 * 1024) {
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:NULL];
    if (!data) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [result appendFormat:@"%02x", digest[i]];
    return result;
}

static NSDictionary *RunEngine(NSString *label, NSDictionary *pin) {
    NSString *filename = [@"wireguard-go-" stringByAppendingString:label];
    NSURL *url = [[NSBundle mainBundle].bundleURL URLByAppendingPathComponent:
                  [@"Contents/Helpers/" stringByAppendingString:filename]];
    NSString *expected = pin[@"sha256"];
    NSString *actual = HashFile(url);
    if (![expected isKindOfClass:[NSString class]] || !actual || ![expected isEqualToString:actual]) {
        return @{@"status": @"FAIL", @"reason": @"Engine integrity check failed"};
    }
    NSTask *task = [[NSTask alloc] init];
    NSPipe *pipe = [NSPipe pipe];
    task.launchPath = url.path;
    task.arguments = @[@"--version"];
    task.environment = @{@"PATH": @"/usr/bin:/bin", @"LANG": @"C", @"LOG_LEVEL": @"silent"};
    task.standardInput = [NSFileHandle fileHandleWithNullDevice];
    task.standardOutput = pipe;
    task.standardError = pipe;
    @try { [task launch]; }
    @catch (NSException *exception) {
        (void)exception;
        return @{@"status": @"FAIL", @"reason": @"Operating system could not launch the engine"};
    }
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5.0];
    while (task.running && deadline.timeIntervalSinceNow > 0) [NSThread sleepForTimeInterval:0.02];
    BOOL timedOut = task.running;
    if (timedOut) [task terminate];
    // The pinned --version entry point installs no signal handlers. A SIGTERM
    // therefore terminates it; no tunnel or child daemon is created by this test.
    [task waitUntilExit];
    NSData *output = [pipe.fileHandleForReading readDataToEndOfFile];
    [pipe.fileHandleForReading closeFile];
    NSString *text = [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] ?: @"Non-UTF8 output";
    if (text.length > 4096) text = [text substringToIndex:4096];
    BOOL valid = !timedOut && task.terminationStatus == 0 && [text containsString:@"darwin-amd64"];
    return @{@"status": valid ? @"PASS" : @"FAIL", @"exit_code": @(task.terminationStatus),
             @"timed_out": @(timedOut), @"output": text, @"commit": pin[@"commit"] ?: @"unknown",
             @"sha256": expected};
}

static NSDictionary *RunChecks(void) {
    NSDictionary *manifest = LoadManifest();
    struct utsname system;
    NSString *architecture = uname(&system) == 0 ? [NSString stringWithUTF8String:system.machine] : @"unknown";
    NSOperatingSystemVersion version = NSProcessInfo.processInfo.operatingSystemVersion;
    NSString *osVersion = [NSString stringWithFormat:@"%ld.%ld.%ld", (long)version.majorVersion,
                          (long)version.minorVersion, (long)version.patchVersion];
    NSString *osBuild = @"unknown";
    NSDictionary *systemVersion = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    if ([systemVersion[@"ProductBuildVersion"] isKindOfClass:[NSString class]]) osBuild = systemVersion[@"ProductBuildVersion"];
    NSMutableDictionary *report = [@{@"schema_version": @1, @"kind": @"platform-probe",
        @"source_commit": manifest[@"source_commit"] ?: @"unknown", @"os_version": osVersion,
        @"os_build": osBuild, @"architecture": architecture, @"signed_for_distribution": manifest[@"signed_for_distribution"] ?: @NO,
        @"native_utun": @"NOT_RUN", @"handshake": @"NOT_RUN", @"server_traffic": @"NOT_RUN",
        @"vpn_ready": @NO} mutableCopy];
    if (!manifest || ![architecture isEqualToString:@"x86_64"]) {
        report[@"status"] = @"FAIL";
        report[@"reason"] = @"Build metadata missing or unsupported architecture";
        return report;
    }
    SecStaticCodeRef code = NULL;
    OSStatus codeStatus = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSBundle mainBundle].bundleURL, kSecCSDefaultFlags, &code);
    if (codeStatus == errSecSuccess) codeStatus = SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures | kSecCSStrictValidate, NULL);
    if (code) CFRelease(code);
    if (codeStatus != errSecSuccess) {
        report[@"status"] = @"FAIL";
        report[@"reason"] = @"Application signature or sealed resources are invalid";
        report[@"signature_status"] = @(codeStatus);
        return report;
    }
    NSDictionary *engines = manifest[@"engines"];
    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    BOOL allPassed = YES;
    for (NSString *label in @[@"baseline", @"candidate"]) {
        NSDictionary *result = RunEngine(label, engines[label]);
        results[label] = result;
        allPassed = allPassed && [result[@"status"] isEqualToString:@"PASS"];
    }
    report[@"engines"] = results;
    report[@"status"] = allPassed ? @"PASS" : @"FAIL";
    report[@"target_high_sierra"] = @(version.majorVersion == 10 && version.minorVersion == 13 && version.patchVersion == 6);
    return report;
}

@interface ProbeController : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) NSTextView *output;
@property(nonatomic, strong) NSButton *runButton;
@property(nonatomic, strong) NSButton *saveButton;
@property(nonatomic, strong) NSDictionary *report;
@end

@implementation ProbeController
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 700, 520)
                   styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                   backing:NSBackingStoreBuffered defer:NO];
    self.window.title = @"Проверка совместимости LegacyWG";
    self.window.minSize = NSMakeSize(700, 520);
    NSTextField *intro = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 445, 660, 55)];
    intro.editable = NO; intro.selectable = NO; intro.bordered = NO; intro.drawsBackground = NO;
    intro.stringValue = @"Проверяет запуск встроенного движка. VPN не включается.\nНе запрашивает ключи и не меняет настройки сети.";
    intro.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    [self.window.contentView addSubview:intro];
    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 75, 660, 360)];
    scroll.hasVerticalScroller = YES;
    scroll.borderType = NSBezelBorder;
    scroll.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    self.output = [[NSTextView alloc] initWithFrame:scroll.contentView.bounds];
    self.output.editable = NO;
    self.output.font = [NSFont userFixedPitchFontOfSize:12];
    self.output.autoresizingMask = NSViewWidthSizable;
    self.output.string = @"Нажмите «Проверить движок». После проверки можно сохранить результат в файл.\nЭто диагностическое приложение, не VPN-клиент.";
    scroll.documentView = self.output;
    [self.window.contentView addSubview:scroll];
    self.runButton = [[NSButton alloc] initWithFrame:NSMakeRect(20, 20, 200, 35)];
    self.runButton.title = @"Проверить движок";
    self.runButton.bezelStyle = NSBezelStyleRounded;
    self.runButton.target = self; self.runButton.action = @selector(runChecks:);
    [self.window.contentView addSubview:self.runButton];
    self.saveButton = [[NSButton alloc] initWithFrame:NSMakeRect(240, 20, 220, 35)];
    self.saveButton.title = @"Сохранить результат…";
    self.saveButton.bezelStyle = NSBezelStyleRounded;
    self.saveButton.target = self; self.saveButton.action = @selector(saveReport:);
    self.saveButton.enabled = NO;
    [self.window.contentView addSubview:self.saveButton];
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Main"];
    NSMenuItem *applicationItem = [[NSMenuItem alloc] initWithTitle:@"LegacyWG" action:NULL keyEquivalent:@""];
    NSMenu *applicationMenu = [[NSMenu alloc] initWithTitle:@"LegacyWG"];
    [applicationMenu addItemWithTitle:@"Выйти" action:@selector(terminate:) keyEquivalent:@"q"];
    applicationItem.submenu = applicationMenu; [menu addItem:applicationItem];
    NSApp.mainMenu = menu;
    [self.window center]; [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}
- (void)runChecks:(id)sender {
    (void)sender;
    self.runButton.enabled = NO; self.saveButton.enabled = NO;
    self.output.string = @"Проверка запуска движка…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *report = RunChecks();
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.report = report;
            self.output.string = [NSString stringWithFormat:@"%@\n\n%@",
                [report[@"status"] isEqualToString:@"PASS"] ? @"Движок запускается. Подключение VPN ещё не проверено." : @"Проверка не пройдена. Сохраните результат для разбора.",
                [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] ?: @"Ошибка формирования отчёта"];
            self.runButton.enabled = YES; self.saveButton.enabled = YES;
        });
    });
}
- (void)saveReport:(id)sender {
    (void)sender;
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.nameFieldStringValue = @"LegacyWG-platform-result.json";
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response != NSModalResponseOK) return;
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:self.report options:NSJSONWritingPrettyPrinted error:&error];
        if (!json || ![json writeToURL:panel.URL options:NSDataWritingAtomic error:&error]) {
            NSAlert *alert = [[NSAlert alloc] init]; alert.messageText = @"Не удалось сохранить результат";
            alert.informativeText = error.localizedDescription ?: @"Выберите другую папку.";
            [alert beginSheetModalForWindow:self.window completionHandler:nil];
        }
    }];
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application {
    (void)application; return YES;
}
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
            NSDictionary *report = RunChecks();
            NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL];
            [NSFileHandle.fileHandleWithStandardOutput writeData:data];
            return [report[@"status"] isEqualToString:@"PASS"] ? 0 : 1;
        }
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        ProbeController *controller = [[ProbeController alloc] init];
        NSApp.delegate = controller;
        [NSApp run];
    }
    return 0;
}
