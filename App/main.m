#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import "LWProfiles.h"
#import "../Shared/LWMach.h"
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <stdlib.h>

static NSString *ServerRequirement(void) {
    NSURL *url = [NSBundle.mainBundle URLForResource:@"Helper" withExtension:@"req"];
    NSString *requirement = url ? [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:NULL] : nil;
    return requirement.length <= 2048 ? requirement : nil;
}

static NSString *HandshakeDate(id value) {
    if(![value isKindOfClass:NSNumber.class] || [value doubleValue]<=0)return @"ещё не получен";
    NSDateFormatter *formatter=[[NSDateFormatter alloc] init];
    formatter.dateStyle=NSDateFormatterShortStyle; formatter.timeStyle=NSDateFormatterMediumStyle;
    return [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:[value doubleValue]]];
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

@interface ClientController : NSObject <NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate>
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
@property(nonatomic,strong) NSStatusItem *statusItem;
@property(nonatomic,strong) NSMenuItem *menuState;
@property(nonatomic,strong) NSMenuItem *menuProfile;
@property(nonatomic,strong) NSMenuItem *menuConnect;
@property(nonatomic,strong) NSMenuItem *menuDisconnect;
@property(nonatomic,copy) NSString *activeProfileName;
@property(nonatomic) BOOL quitting;
@end

@implementation ClientController
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,720,440)
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    self.window.title=@"LegacyWG — тестовая сборка"; self.window.minSize=NSMakeSize(720,440);
    self.window.releasedWhenClosed=NO;
    NSTextField *notice = [NSTextField labelWithString:@"Исследовательская версия: IPv4/IPv6 split tunnel; DNS профиля идёт через туннель.\nПолный туннель пока отклоняется; защита всего трафика не заявлена."];
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
        [button setAccessibilityLabel:button.title];
        [self.window.contentView addSubview:button];
        if(i==2)self.connect=button; if(i==3)self.disconnect=button;
    }
    self.profiles=LWListProfiles(); [self.table reloadData];
    self.timer=[NSTimer timerWithTimeInterval:2 target:self selector:@selector(refreshStatus:) userInfo:nil repeats:YES];
    [NSRunLoop.mainRunLoop addTimer:self.timer forMode:NSRunLoopCommonModes];
    NSMenu *menu=[[NSMenu alloc] initWithTitle:@"Main"], *submenu=[[NSMenu alloc] initWithTitle:@"LegacyWG"];
    NSMenuItem *item=[[NSMenuItem alloc] initWithTitle:@"LegacyWG" action:NULL keyEquivalent:@""];
    [submenu addItemWithTitle:@"Выйти" action:@selector(terminate:) keyEquivalent:@"q"];
    item.submenu=submenu; [menu addItem:item]; NSApp.mainMenu=menu;
    self.statusItem=[NSStatusBar.systemStatusBar statusItemWithLength:NSVariableStatusItemLength];
    self.statusItem.button.title=@"WG";
    self.statusItem.button.toolTip=@"LegacyWG — не подключено";
    [self.statusItem.button setAccessibilityLabel:@"LegacyWG: управление туннелем"];
    NSMenu *statusMenu=[[NSMenu alloc] initWithTitle:@"LegacyWG"];statusMenu.delegate=self;statusMenu.autoenablesItems=NO;
    self.menuState=[statusMenu addItemWithTitle:@"Не подключено" action:NULL keyEquivalent:@""];
    self.menuProfile=[statusMenu addItemWithTitle:@"Профиль не выбран" action:NULL keyEquivalent:@""];
    self.menuState.enabled=NO;self.menuProfile.enabled=NO;
    [statusMenu addItem:NSMenuItem.separatorItem];
    NSMenuItem *open=[statusMenu addItemWithTitle:@"Открыть окно" action:@selector(openWindow:) keyEquivalent:@""];open.target=self;
    self.menuConnect=[statusMenu addItemWithTitle:@"Подключить" action:@selector(connectProfile:) keyEquivalent:@""];self.menuConnect.target=self;
    self.menuDisconnect=[statusMenu addItemWithTitle:@"Отключить" action:@selector(disconnectProfile:) keyEquivalent:@""];self.menuDisconnect.target=self;
    [statusMenu addItem:NSMenuItem.separatorItem];
    NSMenuItem *quit=[statusMenu addItemWithTitle:@"Выйти" action:@selector(terminate:) keyEquivalent:@"q"];quit.target=NSApp;
    self.statusItem.menu=statusMenu;
    [self.window center]; [self.window makeKeyAndOrderFront:nil]; [NSApp activateIgnoringOtherApps:YES];
    [self refreshStatus:nil];
}
- (void)openWindow:(id)sender {
    (void)sender;[self.window makeKeyAndOrderFront:nil];[NSApp activateIgnoringOtherApps:YES];
}
- (void)menuNeedsUpdate:(NSMenu *)menu {
    (void)menu;
    self.menuState.title=self.busy ? @"Операция выполняется…" : self.state.stringValue;
    NSDictionary *selected=[self selectedProfile];
    NSString *name=self.tunnelActive ? self.activeProfileName : selected[@"name"];
    self.menuProfile.title=name.length ? name : @"Профиль не выбран";
    self.menuConnect.enabled=!self.busy && !self.tunnelActive && selected!=nil;
    self.menuDisconnect.enabled=!self.busy && self.tunnelActive;
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
    if(self.busy || self.quitting)return; self.busy=YES;
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
        [state isEqual:@"Connecting"] ? @"Ожидание handshake…" : [state isEqual:@"RecoveryRequired"] ? @"Нужно восстановление сети" : [state isEqual:@"Error"] ? @"Соединение остановлено" : @"Не подключено";
    NSUInteger handshakes=0;
    if([status[@"peer_details"] isKindOfClass:NSArray.class])
        for(NSDictionary *peer in status[@"peer_details"])
            if([peer[@"last_handshake_unix"] doubleValue]>0)handshakes++;
    self.details.stringValue=self.tunnelActive ? [NSString stringWithFormat:@"Туннель запущен: %@\nПоследний handshake: %@\nPeers с handshake: %lu из %@\nПолучено: %@ байт; отправлено: %@ байт\nDNS профиля: %@\nSplit tunnel; защита всего трафика не включена.",status[@"interface"] ?: @"",HandshakeDate(status[@"last_handshake_unix"]),(unsigned long)handshakes,status[@"peers"] ?: @0,status[@"rx_bytes"] ?: @0,status[@"tx_bytes"] ?: @0,[status[@"dns_configured"] isEqual:@YES] ? @"настроен через туннель" : @"используются системные настройки"] :
        [state isEqual:@"Error"] ? @"DNS-компонент потерял настройки или завершился. Туннель закрыт; можно подключиться снова." : @"Выберите профиль для подключения.";
    self.connect.enabled=!self.tunnelActive; self.disconnect.enabled=self.tunnelActive;
    self.statusItem.button.title=self.tunnelActive ? @"WG •" : @"WG";
    self.statusItem.button.toolTip=[@"LegacyWG — " stringByAppendingString:self.state.stringValue];
}
- (void)connectProfile:(id)sender {
    (void)sender; NSDictionary *profile=[self selectedProfile];if(!profile || self.busy)return;
    NSError *error=nil;NSData *data=LWReadProfile(profile[@"id"],&error);
    if(!data){[self alert:error.localizedDescription];return;}
    NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if(!text){[self alert:@"Профиль должен быть UTF-8"];return;}
    self.activeProfileName=profile[@"name"];
    [self performRequest:@{@"version":@1,@"op":@"start",@"profile":text}];
}
- (void)disconnectProfile:(id)sender { (void)sender;[self performRequest:@{@"version":@1,@"op":@"stop"}]; }
- (void)refreshStatus:(id)sender { (void)sender;[self performRequest:@{@"version":@1,@"op":@"status"}]; }
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)application {
    (void)application;
    if(self.quitting)return NSTerminateLater;
    if(self.busy){[self openWindow:nil];[self alert:@"Дождитесь завершения текущей операции перед выходом."];return NSTerminateCancel;}
    if(!self.tunnelActive){[self.timer invalidate];return NSTerminateNow;}
    NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Отключить туннель и выйти?";
    alert.informativeText=@"После отключения трафик снова использует обычную сеть.";
    [alert addButtonWithTitle:@"Отключить и выйти"];[alert addButtonWithTitle:@"Отмена"];
    if([alert runModal]!=NSAlertFirstButtonReturn)return NSTerminateCancel;
    self.quitting=YES;self.busy=YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        NSDictionary *reply=LWRequest(@{@"version":@1,@"op":@"stop"},ServerRequirement());
        dispatch_async(dispatch_get_main_queue(),^{
            BOOL stopped=[reply[@"ok"] isEqual:@YES];
            if(stopped)[self.timer invalidate];
            else {self.quitting=NO;self.busy=NO;[self openWindow:nil];[self alert:@"Компонент не подтвердил отключение. Проверьте состояние туннеля перед выходом."];}
            [NSApp replyToApplicationShouldTerminate:stopped];
        });
    });
    return NSTerminateLater;
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application { (void)application;return NO; }
@end

static int UILayoutTest(void) {
    // Only an authorized disposable GitHub runner may produce this developer
    // fixture screenshot. The normal GUI never creates a simulated status.
    const char *ci=getenv("GITHUB_ACTIONS");
    if(!ci || strcmp(ci,"true")!=0)return 3;
    [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    ClientController *controller=[[ClientController alloc] init];
    [controller applicationDidFinishLaunching:nil];[controller.timer invalidate];
    controller.profiles=@[@{@"id":@"layout-only",@"name":@"GUI layout test — без ключей"}];
    [controller.table reloadData];[controller.table selectRowIndexes:[NSIndexSet indexSetWithIndex:0] byExtendingSelection:NO];
    controller.busy=NO;
    [controller showReply:@{@"ok":@YES,@"status":@{@"state":@"Disconnected",@"protected":@NO}}];
    [controller menuNeedsUpdate:controller.statusItem.menu];
    BOOL menu=controller.statusItem.menu.numberOfItems==8 && controller.menuConnect.enabled &&
        !controller.menuDisconnect.enabled && ![controller applicationShouldTerminateAfterLastWindowClosed:NSApp];
    BOOL bounds=YES;
    for(NSView *view in @[controller.state,controller.details,controller.connect,controller.disconnect])
        bounds=bounds && NSContainsRect(controller.window.contentView.bounds,view.frame);
    [controller.window.contentView displayIfNeeded];
    NSBitmapImageRep *bitmap=[controller.window.contentView bitmapImageRepForCachingDisplayInRect:controller.window.contentView.bounds];
    [controller.window.contentView cacheDisplayInRect:controller.window.contentView.bounds toBitmapImageRep:bitmap];
    NSData *png=[bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    NSString *path=[NSFileManager.defaultManager.currentDirectoryPath stringByAppendingPathComponent:@"Build/CI/client-ui-layout.png"];
    BOOL saved=[png writeToFile:path atomically:YES];
    [NSStatusBar.systemStatusBar removeStatusItem:controller.statusItem];[controller.window close];
    BOOL passed=menu && bounds && saved;
    NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":passed ? @"PASS" : @"FAIL",
        @"kind":@"developer-only-gui-layout-fixture",@"menu_actions":@(menu),@"control_bounds":@(bounds),
        @"screenshot_saved":@(saved),@"vpn_test":@"NOT_RUN",@"high_sierra":@"NOT_RUN"} options:0 error:NULL];
    [NSFileHandle.fileHandleWithStandardOutput writeData:json];return passed ? 0 : 1;
}

int main(int argc,const char *argv[]) {
    struct rlimit coreLimit = {0,0};
    if (setrlimit(RLIMIT_CORE,&coreLimit)!=0) return 5;
    @autoreleasepool {
        if(argc==2 && strcmp(argv[1],"--ui-self-test")==0)return UILayoutTest();
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
