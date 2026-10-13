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

static NSNumber *DiagnosticCounter(id value) {
    return [value isKindOfClass:NSNumber.class] && [value compare:@0]!=NSOrderedAscending ?
        @([value unsignedLongLongValue]) : @0;
}

static NSDictionary *DiagnosticReport(NSDictionary *reply) {
    NSDictionary *status=[reply[@"status"] isKindOfClass:NSDictionary.class] ? reply[@"status"] : @{};
    id rawState=status[@"state"];
    NSString *state=[rawState isKindOfClass:NSString.class] && [@[@"Disconnected",@"Connecting",@"Connected",@"Error",@"RecoveryRequired"] containsObject:rawState] ? rawState : @"Unavailable";
    NSOperatingSystemVersion os=NSProcessInfo.processInfo.operatingSystemVersion;
    NSURL *url=[NSBundle.mainBundle URLForResource:@"BuildManifest" withExtension:@"json"];
    NSData *data=url ? [NSData dataWithContentsOfURL:url] : nil;
    id parsed=data.length<=65536 ? [NSJSONSerialization JSONObjectWithData:data ?: NSData.data options:0 error:NULL] : nil;
    NSString *source=[parsed isKindOfClass:NSDictionary.class] ? parsed[@"source_commit"] : nil;
    if(![source isKindOfClass:NSString.class] || source.length!=40 ||
       [source rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"].invertedSet].location!=NSNotFound)source=@"unknown";
    return @{@"schema":@1,@"product":@"LegacyWG",@"source_commit":source,@"product_ready":@NO,
        @"macos_version":[NSString stringWithFormat:@"%ld.%ld.%ld",(long)os.majorVersion,(long)os.minorVersion,(long)os.patchVersion],
        @"helper_authenticated":@([reply[@"ok"] isEqual:@YES]),@"state":state,
        @"tunnel_started":@([status[@"tunnel_started"] isEqual:@YES]),
        @"protection_confirmed":@([status[@"protected"] isEqual:@YES]),
        @"peer_count":DiagnosticCounter(status[@"peers"]),@"rx_bytes":DiagnosticCounter(status[@"rx_bytes"]),
        @"tx_bytes":DiagnosticCounter(status[@"tx_bytes"]),@"handshake_seen":@([DiagnosticCounter(status[@"last_handshake_unix"]) unsignedLongLongValue]>0),
        @"profile_dns_configured":@([status[@"dns_configured"] isEqual:@YES]),
        @"metadata_policy":@"Profile names, keys, endpoints, interface names, IP addresses, DNS servers and paths omitted"};
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
@property(nonatomic,copy) NSString *activeProfileIdentifier;
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
    NSTextField *notice = [NSTextField wrappingLabelWithString:@"Исследовательская версия: IPv4/IPv6 split tunnel; DNS профиля идёт через туннель.\nПолный туннель пока отклоняется; защита всего трафика не заявлена."];
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
    NSButton *rename=[[NSButton alloc] initWithFrame:NSMakeRect(330,110,170,28)];
    rename.title=@"Переименовать…";rename.bezelStyle=NSBezelStyleRounded;
    rename.target=self;rename.action=@selector(renameProfile:);[rename setAccessibilityLabel:rename.title];
    [self.window.contentView addSubview:rename];
    self.timer=[NSTimer timerWithTimeInterval:2 target:self selector:@selector(refreshStatus:) userInfo:nil repeats:YES];
    [NSRunLoop.mainRunLoop addTimer:self.timer forMode:NSRunLoopCommonModes];
    NSMenu *menu=[[NSMenu alloc] initWithTitle:@"Main"], *submenu=[[NSMenu alloc] initWithTitle:@"LegacyWG"];
    NSMenuItem *item=[[NSMenuItem alloc] initWithTitle:@"LegacyWG" action:NULL keyEquivalent:@""];
    [submenu addItemWithTitle:@"Выйти" action:@selector(terminate:) keyEquivalent:@"q"];
    NSMenuItem *diagnostics=[submenu insertItemWithTitle:@"Диагностика…" action:@selector(diagnostics:) keyEquivalent:@"" atIndex:0];diagnostics.target=self;
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
- (void)renameProfile:(id)sender {
    (void)sender;NSDictionary *profile=[self selectedProfile];if(!profile || self.busy || self.quitting)return;
    NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Новое имя профиля";
    [alert addButtonWithTitle:@"Сохранить"];[alert addButtonWithTitle:@"Отмена"];
    NSTextField *input=[[NSTextField alloc] initWithFrame:NSMakeRect(0,0,360,24)];
    input.stringValue=profile[@"name"];[input setAccessibilityLabel:@"Имя профиля"];
    alert.accessoryView=input;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response!=NSAlertFirstButtonReturn)return;
        NSString *name=[input.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSError *error=nil;
        if(!LWRenameProfile(profile[@"id"],name,&error)){[self alert:error.localizedDescription];return;}
        if([profile[@"id"] isEqual:self.activeProfileIdentifier])self.activeProfileName=name;
        self.profiles=LWListProfiles();[self.table reloadData];
    }];
}
- (void)diagnostics:(id)sender {
    (void)sender;if(self.busy || self.quitting)return;
    self.busy=YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        NSDictionary *reply=LWRequest(@{@"version":@1,@"op":@"status"},ServerRequirement());
        NSData *data=[NSJSONSerialization dataWithJSONObject:DiagnosticReport(reply) options:NSJSONWritingPrettyPrinted error:NULL];
        dispatch_async(dispatch_get_main_queue(),^{
            self.busy=NO;
            if(!data){[self alert:@"Не удалось подготовить диагностику"];return;}
            [self openWindow:nil];
            NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Просмотр диагностики перед сохранением";
            alert.informativeText=@"Отчёт сохраняется только локально по вашему выбору.";
            [alert addButtonWithTitle:@"Сохранить…"];[alert addButtonWithTitle:@"Отмена"];
            NSScrollView *scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(0,0,520,260)];scroll.hasVerticalScroller=YES;
            NSTextView *text=[[NSTextView alloc] initWithFrame:NSMakeRect(0,0,500,260)];
            text.editable=NO;text.font=[NSFont userFixedPitchFontOfSize:11];
            text.string=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];scroll.documentView=text;alert.accessoryView=scroll;
            [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
                if(response!=NSAlertFirstButtonReturn)return;
                NSSavePanel *panel=[NSSavePanel savePanel];panel.allowedFileTypes=@[@"json"];panel.nameFieldStringValue=@"LegacyWG-diagnostics.json";
                [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result) {
                    if(result==NSModalResponseOK && ![data writeToURL:panel.URL options:NSDataWritingAtomic error:NULL])
                        [self alert:@"Не удалось сохранить диагностику"];
                }];
            }];
        });
    });
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
    self.activeProfileIdentifier=profile[@"id"];
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
    [NSApp finishLaunching];
    ClientController *controller=[[ClientController alloc] init];
    [controller applicationDidFinishLaunching:[NSNotification notificationWithName:NSApplicationDidFinishLaunchingNotification object:NSApp]];
    [controller.timer invalidate];
    [NSRunLoop.mainRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.2]];
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
    controller.window.appearance=[NSAppearance appearanceNamed:NSAppearanceNameAqua];
    [controller.window.contentView layoutSubtreeIfNeeded];
    // A native Aqua layout fixture. Layer-backed NSTextField labels are not
    // consistently included by parent cacheDisplay on the headless CI host;
    // render those actual cells and cache the remaining native widgets.
    NSRect canvas=controller.window.contentView.bounds;
    NSBitmapImageRep *opaque=[[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL
        pixelsWide:(NSInteger)canvas.size.width pixelsHigh:(NSInteger)canvas.size.height bitsPerSample:8 samplesPerPixel:4
        hasAlpha:YES isPlanar:NO colorSpaceName:NSCalibratedRGBColorSpace bytesPerRow:0 bitsPerPixel:0];
    [NSGraphicsContext saveGraphicsState];
    [NSGraphicsContext setCurrentContext:[NSGraphicsContext graphicsContextWithBitmapImageRep:opaque]];
    [[NSColor colorWithCalibratedWhite:0.93 alpha:1] setFill];NSRectFill(canvas);
    for(NSView *view in controller.window.contentView.subviews) {
        if([view isKindOfClass:NSTextField.class]) {
            [((NSTextField *)view).cell drawWithFrame:view.frame inView:controller.window.contentView];
        } else {
            NSBitmapImageRep *widget=[view bitmapImageRepForCachingDisplayInRect:view.bounds];
            [view cacheDisplayInRect:view.bounds toBitmapImageRep:widget];
            NSImage *image=[[NSImage alloc] initWithSize:view.bounds.size];[image addRepresentation:widget];
            [image drawInRect:view.frame fromRect:NSZeroRect operation:NSCompositingOperationSourceOver fraction:1];
        }
    }
    [NSGraphicsContext restoreGraphicsState];
    NSUInteger labelPixels=0;
    for(NSInteger y=20;y<75;y++)for(NSInteger x=20;x<700;x++) {
        NSColor *pixel=[[opaque colorAtX:x y:y] colorUsingColorSpace:NSColorSpace.sRGBColorSpace];
        if(pixel && pixel.alphaComponent>0.99 && pixel.redComponent<0.5 && pixel.greenComponent<0.5 && pixel.blueComponent<0.5)labelPixels++;
    }
    NSData *png=[opaque representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    NSString *path=[NSFileManager.defaultManager.currentDirectoryPath stringByAppendingPathComponent:@"Build/CI/client-ui-layout.png"];
    BOOL saved=[png writeToFile:path atomically:YES];
    [NSStatusBar.systemStatusBar removeStatusItem:controller.statusItem];[controller.window close];
    BOOL passed=menu && bounds && saved && labelPixels>30;
    NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":passed ? @"PASS" : @"FAIL",
        @"kind":@"developer-only-gui-layout-fixture",@"menu_actions":@(menu),@"control_bounds":@(bounds),
        @"screenshot_saved":@(saved),@"notice_label_pixels":@(labelPixels),@"vpn_test":@"NOT_RUN",@"high_sierra":@"NOT_RUN"} options:0 error:NULL];
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
            BOOL rename=keychain && LWRenameProfile(identifier,@"LegacyWG renamed CI profile",&error) &&
                [LWReadProfile(identifier,&error) isEqualToData:sample];
            NSError *nameError=nil;
            BOOL nameValidation=rename && !LWRenameProfile(identifier,@"invalid\nlabel",&nameError);
            BOOL renamedLabel=NO;
            for(NSDictionary *profile in LWListProfiles())
                if([profile[@"id"] isEqual:identifier] && [profile[@"name"] isEqual:@"LegacyWG renamed CI profile"])renamedLabel=YES;
            keychain=keychain && rename && nameValidation && renamedLabel;
            NSDictionary *fixture=@{@"ok":@YES,@"status":@{@"state":@"Connected",@"rx_bytes":@12,@"tx_bytes":@34,
                @"private_key":@"private-marker",@"endpoint":@"endpoint-marker",@"interface":@"interface-marker",
                @"peers":@2,@"profile_name":@"profile-marker",@"dns_servers":@[@"dns-marker"]}};
            NSData *diagnostics=[NSJSONSerialization dataWithJSONObject:DiagnosticReport(fixture) options:0 error:NULL];
            NSString *report=[[NSString alloc] initWithData:diagnostics encoding:NSUTF8StringEncoding];
            BOOL privacy=diagnostics.length>0 && [report rangeOfString:@"-marker"].location==NSNotFound;
            if(identifier)keychain=LWDeleteProfile(identifier,&error) && keychain;
            NSDictionary *health=installedTest ? LWRequest(@{@"version":@1,@"op":@"health"},requirement) : nil;
            BOOL helper=installedTest && [health[@"ok"] isEqual:@YES] && [health[@"state"] isEqual:@"Available"];
            BOOL passed=requirement.length && keychain && privacy && (!installedTest || helper);
            NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":passed ? @"PASS" : @"FAIL",@"kind":@"client-bundle-self-test",
                @"keychain_write_read_delete":keychain ? @"PASS" : @"FAIL",@"keychain_error_code":@(error.code),
                @"rename_preserves_id_and_data":rename && renamedLabel ? @"PASS" : @"FAIL",
                @"unsafe_profile_label_refused":nameValidation ? @"PASS" : @"FAIL",
                @"diagnostic_metadata_privacy":privacy ? @"PASS" : @"FAIL",
                @"installed_helper_authentication":installedTest ? (helper ? @"PASS" : @"FAIL") : @"NOT_RUN",
                @"core_dumps_disabled":@YES,@"vpn_ready":@NO} options:0 error:NULL];
            [NSFileHandle.fileHandleWithStandardOutput writeData:json]; return passed ? 0 : 1;
        }
        [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        ClientController *controller=[[ClientController alloc] init];NSApp.delegate=controller;[NSApp run];
    }
    return 0;
}
