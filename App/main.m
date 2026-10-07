#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import "LWProfiles.h"
#import "../Shared/LWMach.h"
#include <signal.h>
#include <string.h>
#include <sys/resource.h>

static NSString *ServerRequirement(void) {
    NSURL *url = [NSBundle.mainBundle URLForResource:@"Helper" withExtension:@"req"];
    NSString *requirement = url ? [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:NULL] : nil;
    return requirement.length <= 2048 ? requirement : nil;
}

static NSDictionary *ValidateProfile(NSData *data) {
    if (!data.length || data.length > 256*1024) return @{@"ok":@NO,@"error":@"Допустимый размер профиля — до 256 КиБ"};
    NSURL *path = [NSBundle.mainBundle.bundleURL URLByAppendingPathComponent:@"Contents/Helpers/legacywg-worker"];
    NSTask *task = [[NSTask alloc] init];
    NSPipe *input = [NSPipe pipe], *output = [NSPipe pipe];
    task.launchPath = path.path; task.arguments = @[@"--validate"];
    task.environment = @{@"PATH":@"/usr/bin:/bin",@"LANG":@"C"};
    task.standardInput = input; task.standardOutput = output; task.standardError = [NSFileHandle fileHandleWithNullDevice];
    @try {
        [task launch]; [input.fileHandleForWriting writeData:data]; [input.fileHandleForWriting closeFile];
    } @catch (NSException *exception) { (void)exception; if(task.running)[task terminate]; return @{@"ok":@NO,@"error":@"Не удалось проверить профиль"}; }
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
    while (task.running && deadline.timeIntervalSinceNow > 0) [NSThread sleepForTimeInterval:0.02];
    if (task.running) kill(task.processIdentifier,SIGKILL);
    [task waitUntilExit];
    NSData *reply = [output.fileHandleForReading readDataToEndOfFile];
    [output.fileHandleForReading closeFile];
    id object = reply.length <= 65536 ? [NSJSONSerialization JSONObjectWithData:reply options:0 error:NULL] : nil;
    return [object isKindOfClass:[NSDictionary class]] ? object : @{@"ok":@NO,@"error":@"Ошибка проверки профиля"};
}

@interface ClientController : NSObject <NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate>
@property(nonatomic,strong) NSWindow *window;
@property(nonatomic,strong) NSTableView *table;
@property(nonatomic,strong) NSTextField *state;
@property(nonatomic,strong) NSTextField *details;
@property(nonatomic,strong) NSButton *connect;
@property(nonatomic,strong) NSButton *disconnect;
@property(nonatomic,strong) NSArray<NSDictionary *> *profiles;
@property(nonatomic,strong) NSTimer *timer;
@property(nonatomic) BOOL busy;
@property(nonatomic) BOOL tunnelActive;
@end

@implementation ClientController
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,720,440)
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    self.window.title=@"LegacyWG — тестовая сборка"; self.window.minSize=NSMakeSize(720,440);
    NSTextField *notice = [NSTextField labelWithString:@"Исследовательская версия: только IPv4 split tunnel без DNS.\nПолный туннель и IPv6 пока отклоняются; защита всего трафика не заявлена."];
    notice.frame=NSMakeRect(20,365,680,55); notice.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;
    [self.window.contentView addSubview:notice];
    NSScrollView *scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(20,105,290,245)];
    scroll.hasVerticalScroller=YES; scroll.borderType=NSBezelBorder;
    scroll.autoresizingMask=NSViewHeightSizable|NSViewMaxXMargin;
    self.table=[[NSTableView alloc] initWithFrame:scroll.contentView.bounds];
    NSTableColumn *column=[[NSTableColumn alloc] initWithIdentifier:@"profile"]; column.width=280; column.title=@"Профили";
    [self.table addTableColumn:column]; self.table.dataSource=self; self.table.delegate=self;
    scroll.documentView=self.table; [self.window.contentView addSubview:scroll];
    self.state=[NSTextField labelWithString:@"Не подключено"]; self.state.frame=NSMakeRect(330,305,370,40);
    self.state.font=[NSFont boldSystemFontOfSize:18]; self.state.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;
    [self.window.contentView addSubview:self.state];
    self.details=[NSTextField wrappingLabelWithString:@"Импортируйте обычный WireGuard .conf. Ключи сохраняются в Keychain.\nСетевой компонент должен быть установлен через согласованный подписанный пакет."];
    self.details.frame=NSMakeRect(330,160,370,130); self.details.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;
    [self.window.contentView addSubview:self.details];
    NSArray *titles=@[@"Импорт…",@"Удалить",@"Подключить",@"Отключить"];
    SEL actions[]={@selector(importProfile:),@selector(deleteProfile:),@selector(connectProfile:),@selector(disconnectProfile:)};
    for (NSUInteger i=0;i<titles.count;i++) {
        NSButton *button=[[NSButton alloc] initWithFrame:NSMakeRect(20+175*i,40,160,35)];
        button.title=titles[i]; button.bezelStyle=NSBezelStyleRounded; button.target=self; button.action=actions[i];
        [self.window.contentView addSubview:button];
        if(i==2)self.connect=button; if(i==3)self.disconnect=button;
    }
    self.profiles=LWListProfiles(); [self.table reloadData];
    self.timer=[NSTimer scheduledTimerWithTimeInterval:2 target:self selector:@selector(refreshStatus:) userInfo:nil repeats:YES];
    NSMenu *menu=[[NSMenu alloc] initWithTitle:@"Main"], *submenu=[[NSMenu alloc] initWithTitle:@"LegacyWG"];
    NSMenuItem *item=[[NSMenuItem alloc] initWithTitle:@"LegacyWG" action:NULL keyEquivalent:@""];
    [submenu addItemWithTitle:@"Выйти" action:@selector(terminate:) keyEquivalent:@"q"];
    item.submenu=submenu; [menu addItem:item]; NSApp.mainMenu=menu;
    [self.window center]; [self.window makeKeyAndOrderFront:nil]; [NSApp activateIgnoringOtherApps:YES];
    [self refreshStatus:nil];
}
- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView { (void)tableView; return (NSInteger)self.profiles.count; }
- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)column row:(NSInteger)row {
    (void)tableView; (void)column; return self.profiles[(NSUInteger)row][@"name"];
}
- (void)alert:(NSString *)message {
    NSAlert *alert=[[NSAlert alloc] init]; alert.messageText=message ?: @"Операция не выполнена";
    [alert beginSheetModalForWindow:self.window completionHandler:nil];
}
- (NSDictionary *)selectedProfile {
    NSInteger row=self.table.selectedRow;
    return row>=0 && (NSUInteger)row<self.profiles.count ? self.profiles[(NSUInteger)row] : nil;
}
- (void)importProfile:(id)sender {
    (void)sender;
    if(self.busy || self.tunnelActive)return;
    NSOpenPanel *panel=[NSOpenPanel openPanel]; panel.allowedFileTypes=@[@"conf"]; panel.allowsMultipleSelection=NO;
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response!=NSModalResponseOK)return;
        NSNumber *size=nil; [panel.URL getResourceValue:&size forKey:NSURLFileSizeKey error:NULL];
        if(!size || size.unsignedLongLongValue>256*1024){[self alert:@"Профиль слишком большой"];return;}
        NSFileHandle *file=[NSFileHandle fileHandleForReadingFromURL:panel.URL error:NULL];
        NSData *data=file ? [file readDataOfLength:256*1024+1] : nil; [file closeFile];
        if(!data || data.length>256*1024){[self alert:@"Не удалось прочитать профиль или превышен лимит размера"];return;}
        self.busy=YES;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            NSDictionary *validation=ValidateProfile(data);
            dispatch_async(dispatch_get_main_queue(),^{
                self.busy=NO;
                if(![validation[@"ok"] isEqual:@YES]){[self alert:validation[@"error"]];return;}
                NSError *error=nil;
                NSString *name=panel.URL.lastPathComponent.stringByDeletingPathExtension;
                if(name.length>80)name=[name substringToIndex:80];
                if(!LWStoreProfile(data,name,NULL,&error)){[self alert:error.localizedDescription];return;}
                self.profiles=LWListProfiles();[self.table reloadData];
                if(![validation[@"native_supported"] isEqual:@YES])
                    [self alert:[@"Профиль сохранён, но пока не поддерживается этой сборкой: " stringByAppendingString:validation[@"limitation"] ?: @"ограничение backend"]];
            });
        });
    }];
}
- (void)deleteProfile:(id)sender {
    (void)sender;
    NSDictionary *profile=[self selectedProfile];if(!profile || self.busy || self.tunnelActive)return;
    NSAlert *alert=[[NSAlert alloc] init]; alert.messageText=@"Удалить профиль и его ключи из Keychain?";
    [alert addButtonWithTitle:@"Удалить"]; [alert addButtonWithTitle:@"Отмена"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response!=NSAlertFirstButtonReturn)return;
        NSError *error=nil;if(!LWDeleteProfile(profile[@"id"],&error)){[self alert:error.localizedDescription];return;}
        self.profiles=LWListProfiles();[self.table reloadData];
    }];
}
- (void)performRequest:(NSDictionary *)request {
    if(self.busy)return; self.busy=YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        NSDictionary *reply=LWRequest(request,ServerRequirement());
        dispatch_async(dispatch_get_main_queue(),^{self.busy=NO;[self showReply:reply];});
    });
}
- (void)showReply:(NSDictionary *)reply {
    if(![reply[@"ok"] isEqual:@YES]) { self.state.stringValue=@"Нет подтверждения подключения"; self.details.stringValue=reply[@"error"] ?: @"Ошибка компонента"; return; }
    NSDictionary *status=reply[@"status"];
    if(![status isKindOfClass:[NSDictionary class]])return;
    NSString *state=status[@"state"];
    self.tunnelActive=[state isEqual:@"Connected"] || [state isEqual:@"Connecting"];
    self.state.stringValue=[state isEqual:@"Connected"] ? @"Handshake получен" :
        [state isEqual:@"Connecting"] ? @"Ожидание handshake…" : [state isEqual:@"RecoveryRequired"] ? @"Нужно восстановление сети" : @"Не подключено";
    self.details.stringValue=self.tunnelActive ? [NSString stringWithFormat:@"%@\nПолучено: %@ байт\nОтправлено: %@ байт\nIPv4 split tunnel; защита всего трафика не включена.",status[@"interface"] ?: @"",status[@"rx_bytes"] ?: @0,status[@"tx_bytes"] ?: @0] : @"Выберите профиль для подключения.";
    self.connect.enabled=!self.tunnelActive; self.disconnect.enabled=self.tunnelActive;
}
- (void)connectProfile:(id)sender {
    (void)sender; NSDictionary *profile=[self selectedProfile];if(!profile || self.busy)return;
    NSError *error=nil;NSData *data=LWReadProfile(profile[@"id"],&error);
    if(!data){[self alert:error.localizedDescription];return;}
    NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if(!text){[self alert:@"Профиль должен быть UTF-8"];return;}
    [self performRequest:@{@"version":@1,@"op":@"start",@"profile":text}];
}
- (void)disconnectProfile:(id)sender { (void)sender;[self performRequest:@{@"version":@1,@"op":@"stop"}]; }
- (void)refreshStatus:(id)sender { (void)sender;[self performRequest:@{@"version":@1,@"op":@"status"}]; }
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)application {
    (void)application;[self.timer invalidate];
    LWRequest(@{@"version":@1,@"op":@"stop"},ServerRequirement());
    return NSTerminateNow;
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application { (void)application;return YES; }
@end

int main(int argc,const char *argv[]) {
    struct rlimit coreLimit = {0,0};
    if (setrlimit(RLIMIT_CORE,&coreLimit)!=0) return 5;
    @autoreleasepool {
        BOOL installedTest=argc==2 && strcmp(argv[1],"--self-test-installed")==0;
        if(argc==2 && (strcmp(argv[1],"--self-test")==0 || installedTest)) {
            NSString *requirement=ServerRequirement();
            NSError *error=nil; NSString *identifier=nil;
            NSData *sample=[@"LegacyWG ephemeral Keychain self-test" dataUsingEncoding:NSUTF8StringEncoding];
            BOOL keychain=LWStoreProfile(sample,@"LegacyWG CI self-test",&identifier,&error);
            if(keychain)keychain=[LWReadProfile(identifier,&error) isEqualToData:sample];
            if(identifier)keychain=LWDeleteProfile(identifier,&error) && keychain;
            NSDictionary *health=installedTest ? LWRequest(@{@"version":@1,@"op":@"health"},requirement) : nil;
            BOOL helper=installedTest && [health[@"ok"] isEqual:@YES] && [health[@"state"] isEqual:@"Available"];
            BOOL passed=requirement.length && keychain && (!installedTest || helper);
            NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":passed ? @"PASS" : @"FAIL",@"kind":@"client-bundle-self-test",
                @"keychain_write_read_delete":keychain ? @"PASS" : @"FAIL",@"keychain_error_code":@(error.code),
                @"installed_helper_authentication":installedTest ? (helper ? @"PASS" : @"FAIL") : @"NOT_RUN",
                @"core_dumps_disabled":@YES,@"vpn_ready":@NO} options:0 error:NULL];
            [NSFileHandle.fileHandleWithStandardOutput writeData:json]; return passed ? 0 : 1;
        }
        [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        ClientController *controller=[[ClientController alloc] init];NSApp.delegate=controller;[NSApp run];
    }
    return 0;
}
