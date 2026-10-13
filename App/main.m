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

static NSString *PreviewText(NSDictionary *validation, BOOL abbreviated) {
    NSDictionary *view=[validation[@"preview"] isKindOfClass:NSDictionary.class] ? validation[@"preview"] : nil;
    NSDictionary *modes=@{@"split":@"выборочные маршруты",@"full_ipv4":@"полный IPv4",@"full_ipv6":@"полный IPv6",
        @"full_dual_stack":@"полный IPv4 и IPv6",@"unavailable":@"не определена для клиента"};
    NSString *routing=[view[@"routing"] isKindOfClass:NSString.class] ? modes[view[@"routing"]] : nil;
    NSArray *addresses=[view[@"addresses"] isKindOfClass:NSArray.class] ? view[@"addresses"] : nil;
    NSArray *endpoints=[view[@"endpoints"] isKindOfClass:NSArray.class] ? view[@"endpoints"] : nil;
    id count=view[@"address_count"];
    if(![validation[@"ok"] isEqual:@YES] || !routing || !addresses.count || addresses.count>8 || !endpoints.count || endpoints.count>16 ||
       ![count isKindOfClass:NSNumber.class] || [count unsignedIntegerValue]<addresses.count || [count unsignedIntegerValue]>2048)return @"Не удалось получить сведения о профиле.";
    for(id value in addresses)if(![value isKindOfClass:NSString.class] || [value length]>64 || ![value length] ||
        [value rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound)return @"Не удалось получить сведения о профиле.";
    for(id value in endpoints)if(![value isKindOfClass:NSString.class] || [value length]>300 ||
        [value rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound)return @"Не удалось получить сведения о профиле.";
    NSUInteger limit=abbreviated ? 1 : addresses.count;
    NSString *local=[[addresses subarrayWithRange:NSMakeRange(0,limit)] componentsJoinedByString:abbreviated ? @", " : @"\n"];
    if([count unsignedIntegerValue]>limit)local=[local stringByAppendingFormat:@" (+%lu)",(unsigned long)([count unsignedIntegerValue]-limit)];
    NSMutableArray *servers=[NSMutableArray array];
    for(NSString *endpoint in endpoints) {
        NSString *text=endpoint.length ? endpoint : @"не указан";
        if(abbreviated && text.length>52)text=[NSString stringWithFormat:@"%@…%@",[text substringToIndex:32],[text substringFromIndex:text.length-16]];
        [servers addObject:text];if(abbreviated)break;
    }
    NSString *remote=[servers componentsJoinedByString:@"\n"];
    if(abbreviated && endpoints.count>1)remote=[remote stringByAppendingFormat:@" (+%lu)",(unsigned long)(endpoints.count-1)];
    return [NSString stringWithFormat:@"Маршрутизация: %@\nАдреса: %@\nСерверы: %@",routing,local,remote];
}

static NSString *UnsupportedProfileReason(id value) {
    NSDictionary *reasons=@{@"full tunnel requires endpoint escape routing and verified traffic protection":@"Полный туннель пока недоступен: защита всего трафика не подтверждена.",
        @"at most eight DNS servers are supported":@"Поддерживается до восьми DNS-серверов.",
        @"profile DNS must be routed through the tunnel":@"DNS-сервер профиля должен входить в маршруты туннеля.",
        @"initial native executor permits at most 64 routes":@"В этой сборке поддерживается до 64 маршрутов.",
        @"initial native executor permits at most four local addresses":@"В этой сборке поддерживается до четырёх локальных адресов.",
        @"outgoing client requires at least one Endpoint":@"Укажите Endpoint хотя бы для одного сервера.",
        @"endpoint overlaps a tunnel route; physical endpoint routing required":@"Маршрут туннеля перекрывает адрес сервера. Этот профиль пока не поддерживается.",
        @"tunnel route requires a local address of the same family":@"Для маршрутов IPv4/IPv6 нужен локальный адрес того же типа.",
        @"full IPv6 tunnel requires an IPv6 interface address":@"Для полного IPv6-туннеля нужен локальный IPv6-адрес."};
    return [value isKindOfClass:NSString.class] ? reasons[value] ?: @"Профиль пока не поддерживается сетевым компонентом." : @"Профиль пока не поддерживается сетевым компонентом.";
}

static NSString *LicenseText(void) {
    NSArray *names=@[@"THIRD_PARTY_NOTICES.md",@"WireGuard-LICENSE",@"Go-LICENSE",@"Go-PATENTS",
        @"golang.org_x_crypto-v0.37.0-LICENSE",@"golang.org_x_net-v0.39.0-LICENSE",@"golang.org_x_sys-v0.32.0-LICENSE",
        @"github.com_google_btree-v1.1.2-LICENSE",@"golang.org_x_time-v0.7.0-LICENSE",
        @"golang.zx2c4.com_wintun-v0.0.0-20230126152724-0fa3db229ce2-LICENSE",
        @"gvisor.dev_gvisor-v0.0.0-20250503011706-39ed1f5ac29c-LICENSE"];
    NSMutableString *text=[NSMutableString stringWithString:@"LegacyWG — независимый проект, не официальное приложение WireGuard.\nЛицензия собственного кода ещё не определена; релизной поставки пока нет.\n\n"];
    for(NSString *name in names) {
        NSURL *directory=[NSBundle.mainBundle.resourceURL URLByAppendingPathComponent:[name isEqual:@"THIRD_PARTY_NOTICES.md"] ? @"" : @"Licenses"];
        NSURL *url=[directory URLByAppendingPathComponent:name];NSData *data=nil;
        @try {
            NSFileHandle *file=[NSFileHandle fileHandleForReadingFromURL:url error:NULL];
            @try {if(file)data=[file readDataOfLength:128*1024+1];}
            @finally {[file closeFile];}
        } @catch(NSException *exception) {(void)exception;return nil;}
        if(!data.length || data.length>128*1024)return nil;
        NSString *license=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];if(!license)return nil;
        [text appendFormat:@"—— %@ ——\n%@\n\n",name,license];
        if(text.length>1024*1024)return nil;
    }
    return text;
}

@interface ClientController : NSObject <NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate>
@property(nonatomic,strong) NSWindow *window;
@property(nonatomic,strong) NSTableView *table;
@property(nonatomic,strong) NSTextField *state;
@property(nonatomic,strong) NSTextField *details;
@property(nonatomic,strong) NSTextField *profileDetails;
@property(nonatomic,strong) NSNumber *selectedProfileSupported;
@property(nonatomic,copy) NSString *selectedProfileLimitation;
@property(nonatomic) NSUInteger previewGeneration;
@property(nonatomic,strong) dispatch_queue_t previewQueue;
@property(nonatomic,strong) NSButton *connect;
@property(nonatomic,strong) NSButton *disconnect;
@property(nonatomic,strong) NSButton *recover;
@property(nonatomic,strong) NSArray<NSDictionary *> *profiles;
@property(nonatomic,strong) NSTimer *timer;
@property(nonatomic) BOOL busy;
@property(nonatomic) BOOL interactionPending;
@property(nonatomic) BOOL statusKnown;
@property(nonatomic) BOOL tunnelActive;
@property(nonatomic) BOOL recoveryRequired;
@property(nonatomic,strong) NSStatusItem *statusItem;
@property(nonatomic,strong) NSMenuItem *menuState;
@property(nonatomic,strong) NSMenuItem *menuProfile;
@property(nonatomic,strong) NSMenuItem *menuConnect;
@property(nonatomic,strong) NSMenuItem *menuDisconnect;
@property(nonatomic,strong) NSMenuItem *menuRecover;
@property(nonatomic,copy) NSString *activeProfileName;
@property(nonatomic,copy) NSString *activeProfileIdentifier;
@property(nonatomic) BOOL quitting;
@end

@implementation ClientController
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.previewQueue=dispatch_queue_create("org.legacywg.profile-preview",DISPATCH_QUEUE_SERIAL);
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,720,520)
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    self.window.title=@"LegacyWG — тестовая сборка";
    self.window.minSize=[self.window frameRectForContentRect:NSMakeRect(0,0,720,520)].size;
    self.window.releasedWhenClosed=NO;
    NSTextField *notice = [NSTextField wrappingLabelWithString:@"Исследовательская версия: IPv4/IPv6 split tunnel; DNS профиля идёт через туннель.\nПолный туннель пока отклоняется; защита всего трафика не заявлена."];
    notice.frame=NSMakeRect(20,445,680,55); notice.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;
    [self.window.contentView addSubview:notice];
    NSScrollView *scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(20,105,290,325)];
    scroll.hasVerticalScroller=YES; scroll.borderType=NSBezelBorder;
    scroll.autoresizingMask=NSViewHeightSizable|NSViewMaxXMargin;
    self.table=[[NSTableView alloc] initWithFrame:scroll.contentView.bounds];
    NSTableColumn *column=[[NSTableColumn alloc] initWithIdentifier:@"profile"]; column.width=280; column.title=@"Профили";
    [self.table addTableColumn:column]; self.table.dataSource=self; self.table.delegate=self;
    scroll.documentView=self.table; [self.window.contentView addSubview:scroll];
    self.state=[NSTextField labelWithString:@"Не подключено"]; self.state.frame=NSMakeRect(330,385,370,40);
    self.state.font=[NSFont boldSystemFontOfSize:18]; self.state.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;
    [self.window.contentView addSubview:self.state];
    self.details=[NSTextField wrappingLabelWithString:@"Импортируйте обычный WireGuard .conf. Ключи сохраняются в Keychain.\nСетевой компонент должен быть установлен через согласованный подписанный пакет."];
    self.details.frame=NSMakeRect(330,250,370,130); self.details.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;
    [self.window.contentView addSubview:self.details];
    NSTextField *profileTitle=[NSTextField labelWithString:@"Выбранный профиль"];
    profileTitle.frame=NSMakeRect(330,225,370,20);profileTitle.font=[NSFont boldSystemFontOfSize:12];
    profileTitle.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;[self.window.contentView addSubview:profileTitle];
    self.profileDetails=[NSTextField wrappingLabelWithString:@"Выберите профиль. Адреса и серверы будут показаны без ключей."];
    self.profileDetails.frame=NSMakeRect(330,140,370,80);self.profileDetails.font=[NSFont systemFontOfSize:12];
    self.profileDetails.autoresizingMask=NSViewWidthSizable|NSViewMinYMargin;
    [self.profileDetails setAccessibilityLabel:@"Адреса, серверы и маршрутизация выбранного профиля"];
    [self.window.contentView addSubview:self.profileDetails];
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
    self.recover=[[NSButton alloc] initWithFrame:NSMakeRect(510,110,190,28)];
    self.recover.title=@"Восстановить сеть…";self.recover.bezelStyle=NSBezelStyleRounded;
    self.recover.target=self;self.recover.action=@selector(recoverNetwork:);self.recover.enabled=NO;
    [self.recover setAccessibilityLabel:self.recover.title];
    [self.window.contentView addSubview:self.recover];
    self.timer=[NSTimer timerWithTimeInterval:2 target:self selector:@selector(refreshStatus:) userInfo:nil repeats:YES];
    [NSRunLoop.mainRunLoop addTimer:self.timer forMode:NSRunLoopCommonModes];
    NSMenu *menu=[[NSMenu alloc] initWithTitle:@"Main"], *submenu=[[NSMenu alloc] initWithTitle:@"LegacyWG"];
    NSMenuItem *item=[[NSMenuItem alloc] initWithTitle:@"LegacyWG" action:NULL keyEquivalent:@""];
    [submenu addItemWithTitle:@"Выйти" action:@selector(terminate:) keyEquivalent:@"q"];
    NSMenuItem *diagnostics=[submenu insertItemWithTitle:@"Диагностика…" action:@selector(diagnostics:) keyEquivalent:@"" atIndex:0];diagnostics.target=self;
    NSMenuItem *about=[submenu insertItemWithTitle:@"О программе и лицензии…" action:@selector(about:) keyEquivalent:@"" atIndex:0];about.target=self;
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
    self.menuRecover=[statusMenu addItemWithTitle:@"Восстановить сеть…" action:@selector(recoverNetwork:) keyEquivalent:@""];self.menuRecover.target=self;
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
    self.menuConnect.enabled=!self.busy && !self.interactionPending && self.connect.enabled && selected!=nil;
    self.menuDisconnect.enabled=!self.busy && !self.interactionPending && self.tunnelActive;
    self.menuRecover.enabled=!self.busy && !self.interactionPending && self.recoveryRequired;
}
- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView { (void)tableView; return (NSInteger)self.profiles.count; }
- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)column row:(NSInteger)row {
    (void)tableView; (void)column; return self.profiles[(NSUInteger)row][@"name"];
}
- (void)alert:(NSString *)message {
    if(self.interactionPending)return;
    self.interactionPending=YES;
    NSAlert *alert=[[NSAlert alloc] init]; alert.messageText=message ?: @"Операция не выполнена";
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        (void)response;self.interactionPending=NO;
    }];
}
- (NSDictionary *)selectedProfile {
    NSInteger row=self.table.selectedRow;
    return row>=0 && (NSUInteger)row<self.profiles.count ? self.profiles[(NSUInteger)row] : nil;
}
- (void)updateConnectControl {
    self.connect.enabled=self.statusKnown && !self.tunnelActive && !self.recoveryRequired && !self.quitting &&
        [self.selectedProfileSupported isEqual:@YES] && [self selectedProfile]!=nil;
    self.connect.toolTip=self.selectedProfileLimitation;
    if(self.statusKnown && !self.tunnelActive && !self.recoveryRequired && [self.state.stringValue isEqual:@"Не подключено"] && self.selectedProfileLimitation.length)
        self.details.stringValue=self.selectedProfileLimitation;
}
- (void)tableViewSelectionDidChange:(NSNotification *)notification {
    (void)notification;[self refreshSelectedProfile];
}
- (void)refreshSelectedProfile {
    NSUInteger generation=++self.previewGeneration;NSDictionary *profile=[self selectedProfile];
    self.selectedProfileSupported=nil;self.selectedProfileLimitation=nil;self.profileDetails.toolTip=nil;[self updateConnectControl];
    if(self.statusKnown && [self.state.stringValue isEqual:@"Не подключено"])self.details.stringValue=@"Выберите профиль для подключения.";
    if(!profile){self.profileDetails.stringValue=@"Выберите профиль. Адреса и серверы будут показаны без ключей.";return;}
    self.profileDetails.stringValue=@"Проверка профиля…";
    dispatch_async(self.previewQueue,^{
        __block BOOL current=NO;
        dispatch_sync(dispatch_get_main_queue(),^{current=generation==self.previewGeneration && !self.quitting;});
        if(!current)return; // Superseded queued selections do not read secrets or spawn a worker.
        NSError *error=nil;NSData *data=LWReadProfile(profile[@"id"],&error);
        NSDictionary *validation=data ? ValidateProfile(data) : nil;
        NSString *shortText=validation ? PreviewText(validation,YES) : @"Не удалось прочитать профиль из Keychain.";
        NSString *fullText=validation ? PreviewText(validation,NO) : shortText;
        dispatch_async(dispatch_get_main_queue(),^{
            if(generation!=self.previewGeneration || ![[self selectedProfile][@"id"] isEqual:profile[@"id"]])return;
            self.profileDetails.stringValue=shortText;self.profileDetails.toolTip=fullText;
            BOOL known=[validation[@"ok"] isEqual:@YES] && ![shortText isEqual:@"Не удалось получить сведения о профиле."];
            self.selectedProfileSupported=@(known && [validation[@"native_supported"] isEqual:@YES]);
            self.selectedProfileLimitation=self.selectedProfileSupported.boolValue ? nil : known ? UnsupportedProfileReason(validation[@"limitation"]) : @"Профиль не подтверждён. Проверьте конфигурацию и доступ к Keychain.";
            if(self.selectedProfileLimitation)self.profileDetails.toolTip=[fullText stringByAppendingFormat:@"\n%@",self.selectedProfileLimitation];
            [self updateConnectControl];
        });
    });
}
- (void)reloadProfilesSelecting:(NSString *)identifier {
    self.profiles=LWListProfiles();[self.table reloadData];[self.table deselectAll:nil];
    for(NSUInteger row=0;row<self.profiles.count;row++)if([self.profiles[row][@"id"] isEqual:identifier])
        [self.table selectRowIndexes:[NSIndexSet indexSetWithIndex:row] byExtendingSelection:NO];
    [self refreshSelectedProfile];
}
- (void)about:(id)sender {
    (void)sender;if(self.busy || self.interactionPending || self.quitting)return;
    NSString *licenses=LicenseText();if(!licenses){[self alert:@"Не удалось загрузить лицензии. Проверьте установку приложения."];return;}
    self.interactionPending=YES;
    NSAlert *alert=[[NSAlert alloc] init];
    NSString *version=[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    alert.messageText=[@"LegacyWG " stringByAppendingString:version ?: @""];
    alert.informativeText=@"Клиент стандартного WireGuard для Intel Mac. Независимый проект.\nИсследовательская сборка: совместимость с High Sierra и полноценная защита трафика ещё не подтверждены.";
    [alert addButtonWithTitle:@"Закрыть"];
    NSScrollView *scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(0,0,520,300)];scroll.hasVerticalScroller=YES;
    NSTextView *text=[[NSTextView alloc] initWithFrame:NSMakeRect(0,0,500,300)];
    text.editable=NO;text.selectable=YES;text.font=[NSFont userFixedPitchFontOfSize:11];text.string=licenses;
    [text setAccessibilityLabel:@"Лицензии и уведомления о сторонних компонентах"];
    scroll.documentView=text;alert.accessoryView=scroll;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {(void)response;self.interactionPending=NO;}];
}
- (BOOL)canChangeStoredProfile {
    return self.statusKnown && !self.tunnelActive && !self.recoveryRequired && !self.quitting;
}
- (void)commitImport:(NSData *)data name:(NSString *)name replacing:(NSString *)identifier validation:(NSDictionary *)validation {
    if(![validation[@"ok"] isEqual:@YES]) {
        self.interactionPending=NO;[self alert:@"Невалидный профиль не сохранён."];return;
    }
    if(self.quitting || self.tunnelActive || (identifier && ![self canChangeStoredProfile])) {
        self.interactionPending=NO;[self alert:@"Профиль не изменён. Сначала подтвердите отключение туннеля."];return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        NSError *error=nil;NSString *stored=identifier;
        BOOL ok=identifier ? LWReplaceProfile(identifier,data,&error) :
            (LWProfileNameAvailable(name,&error) && LWStoreProfile(data,name,&stored,&error));
        dispatch_async(dispatch_get_main_queue(),^{
            self.interactionPending=NO;
            if(!ok){[self alert:error.localizedDescription];return;}
            [self reloadProfilesSelecting:stored];
            if(![validation[@"native_supported"] isEqual:@YES]) {
                NSString *limitation=[validation[@"limitation"] isKindOfClass:NSString.class] ? validation[@"limitation"] : @"ограничение backend";
                [self alert:[@"Профиль сохранён, но пока не поддерживается этой сборкой: " stringByAppendingString:limitation]];
            }
        });
    });
}
- (void)importCopy:(NSData *)data validation:(NSDictionary *)validation {
    NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Сохранить профиль под новым именем";
    alert.informativeText=@"Существующие профили сохранятся. Введите свободное имя.";
    [alert addButtonWithTitle:@"Сохранить"];[alert addButtonWithTitle:@"Отмена"];
    NSTextField *input=[[NSTextField alloc] initWithFrame:NSMakeRect(0,0,360,24)];
    [input setAccessibilityLabel:@"Новое имя импортируемого профиля"];alert.accessoryView=input;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response!=NSAlertFirstButtonReturn){self.interactionPending=NO;return;}
        NSString *name=[input.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        [self commitImport:data name:name replacing:nil validation:validation];
    }];
}
- (void)chooseImport:(NSData *)data name:(NSString *)name conflicts:(NSArray<NSDictionary *> *)conflicts validation:(NSDictionary *)validation {
    if(!conflicts.count){[self commitImport:data name:name replacing:nil validation:validation];return;}
    NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Этот профиль уже импортирован";
    alert.informativeText=@"Найдено совпадение имени или содержимого. Выберите конкретный профиль для замены либо сохраните копию с новым именем. Замена сохраняет имя выбранного профиля.";
    NSButton *replace=[alert addButtonWithTitle:@"Заменить выбранный"];
    replace.enabled=[self canChangeStoredProfile];
    [alert addButtonWithTitle:@"С новым именем…"];[alert addButtonWithTitle:@"Отмена"];
    NSPopUpButton *choice=[[NSPopUpButton alloc] initWithFrame:NSMakeRect(0,0,400,28) pullsDown:NO];
    for(NSDictionary *profile in conflicts)[choice addItemWithTitle:[NSString stringWithFormat:@"%@ — %@",profile[@"name"],[profile[@"id"] substringToIndex:8]]];
    [choice setAccessibilityLabel:@"Профиль для замены"];alert.accessoryView=choice;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response==NSAlertFirstButtonReturn && choice.indexOfSelectedItem>=0 && (NSUInteger)choice.indexOfSelectedItem<conflicts.count)
            [self commitImport:data name:nil replacing:conflicts[(NSUInteger)choice.indexOfSelectedItem][@"id"] validation:validation];
        else if(response==NSAlertSecondButtonReturn)[self importCopy:data validation:validation];
        else self.interactionPending=NO;
    }];
}
- (void)importProfile:(id)sender {
    (void)sender;if(self.busy || self.interactionPending || self.tunnelActive || self.quitting)return;
    self.interactionPending=YES;
    NSOpenPanel *panel=[NSOpenPanel openPanel];panel.allowedFileTypes=@[@"conf"];panel.allowsMultipleSelection=NO;
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response!=NSModalResponseOK){self.interactionPending=NO;return;}
        NSURL *url=panel.URL;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            NSData *data=nil;
            @try {
                NSNumber *size=nil;[url getResourceValue:&size forKey:NSURLFileSizeKey error:NULL];
                if(size && size.unsignedLongLongValue<=256*1024) {
                    NSFileHandle *file=[NSFileHandle fileHandleForReadingFromURL:url error:NULL];
                    @try {if(file)data=[file readDataOfLength:256*1024+1];}
                    @finally {[file closeFile];}
                }
            } @catch(NSException *exception) {(void)exception;data=nil;}
            NSDictionary *validation=ValidateProfile(data);NSError *error=nil;
            NSString *name=[url.lastPathComponent.stringByDeletingPathExtension stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            NSArray *conflicts=[validation[@"ok"] isEqual:@YES] ? LWProfileImportConflicts(data,name,&error) : nil;
            dispatch_async(dispatch_get_main_queue(),^{
                if(![validation[@"ok"] isEqual:@YES] || !conflicts) {
                    self.interactionPending=NO;[self alert:error.localizedDescription ?: validation[@"error"]];return;
                }
                [self chooseImport:data name:name conflicts:conflicts validation:validation];
            });
        });
    }];
}
- (void)deleteProfile:(id)sender {
    (void)sender;
    NSDictionary *profile=[self selectedProfile];if(!profile || self.busy || self.interactionPending || ![self canChangeStoredProfile])return;
    self.interactionPending=YES;
    NSAlert *alert=[[NSAlert alloc] init]; alert.messageText=@"Удалить профиль и его ключи из Keychain?";
    [alert addButtonWithTitle:@"Удалить"]; [alert addButtonWithTitle:@"Отмена"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response!=NSAlertFirstButtonReturn){self.interactionPending=NO;return;}
        if(![self canChangeStoredProfile]){self.interactionPending=NO;[self alert:@"Профиль не удалён. Сначала подтвердите отключение туннеля."];return;}
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            NSError *error=nil;BOOL ok=LWDeleteProfile(profile[@"id"],&error);
            dispatch_async(dispatch_get_main_queue(),^{
                self.interactionPending=NO;if(!ok){[self alert:error.localizedDescription];return;}
                [self reloadProfilesSelecting:nil];
            });
        });
    }];
}
- (void)renameProfile:(id)sender {
    (void)sender;NSDictionary *profile=[self selectedProfile];if(!profile || self.busy || self.interactionPending || self.quitting)return;
    self.interactionPending=YES;
    NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Новое имя профиля";
    [alert addButtonWithTitle:@"Сохранить"];[alert addButtonWithTitle:@"Отмена"];
    NSTextField *input=[[NSTextField alloc] initWithFrame:NSMakeRect(0,0,360,24)];
    input.stringValue=profile[@"name"];[input setAccessibilityLabel:@"Имя профиля"];
    alert.accessoryView=input;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if(response!=NSAlertFirstButtonReturn){self.interactionPending=NO;return;}
        NSString *name=[input.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            NSError *error=nil;BOOL ok=LWRenameProfile(profile[@"id"],name,&error);
            dispatch_async(dispatch_get_main_queue(),^{
                self.interactionPending=NO;if(!ok){[self alert:error.localizedDescription];return;}
                if([profile[@"id"] isEqual:self.activeProfileIdentifier])self.activeProfileName=name;
                [self reloadProfilesSelecting:profile[@"id"]];
            });
        });
    }];
}
- (void)diagnostics:(id)sender {
    (void)sender;if(self.busy || self.interactionPending || self.quitting)return;
    self.busy=YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        NSDictionary *reply=LWRequest(@{@"version":@1,@"op":@"status"},ServerRequirement());
        NSData *data=[NSJSONSerialization dataWithJSONObject:DiagnosticReport(reply) options:NSJSONWritingPrettyPrinted error:NULL];
        dispatch_async(dispatch_get_main_queue(),^{
            self.busy=NO;
            if(!data){[self alert:@"Не удалось подготовить диагностику"];return;}
            self.interactionPending=YES;
            [self openWindow:nil];
            NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Просмотр диагностики перед сохранением";
            alert.informativeText=@"Отчёт сохраняется только локально по вашему выбору.";
            [alert addButtonWithTitle:@"Сохранить…"];[alert addButtonWithTitle:@"Отмена"];
            NSScrollView *scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(0,0,520,260)];scroll.hasVerticalScroller=YES;
            NSTextView *text=[[NSTextView alloc] initWithFrame:NSMakeRect(0,0,500,260)];
            text.editable=NO;text.font=[NSFont userFixedPitchFontOfSize:11];
            text.string=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];scroll.documentView=text;alert.accessoryView=scroll;
            [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
                if(response!=NSAlertFirstButtonReturn){self.interactionPending=NO;return;}
                NSSavePanel *panel=[NSSavePanel savePanel];panel.allowedFileTypes=@[@"json"];panel.nameFieldStringValue=@"LegacyWG-diagnostics.json";
                [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result) {
                    self.interactionPending=NO;
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
    NSDictionary *status=reply[@"status"];
    NSString *state=[status isKindOfClass:NSDictionary.class] ? status[@"state"] : nil;
    if(![state isKindOfClass:NSString.class] ||
       ![@[@"Disconnected",@"Connecting",@"Connected",@"RecoveryRequired",@"Error"] containsObject:state]) {
        self.state.stringValue=@"Состояние не подтверждено";
        self.details.stringValue=[reply[@"error"] isKindOfClass:NSString.class] ? reply[@"error"] : @"Не удалось получить состояние сетевого компонента. Повторите проверку.";
        self.connect.enabled=NO;
        self.statusKnown=NO;
        return;
    }
    self.statusKnown=YES;
    self.tunnelActive=[state isEqual:@"Connected"] || [state isEqual:@"Connecting"];
    self.recoveryRequired=[state isEqual:@"RecoveryRequired"];
    self.state.stringValue=[state isEqual:@"Connected"] ? @"Handshake получен" :
        [state isEqual:@"Connecting"] ? @"Ожидание handshake…" : [state isEqual:@"RecoveryRequired"] ? @"Нужно восстановление сети" : [state isEqual:@"Error"] ? @"Соединение остановлено" : @"Не подключено";
    NSUInteger handshakes=0;
    if([status[@"peer_details"] isKindOfClass:NSArray.class])
        for(NSDictionary *peer in status[@"peer_details"])
            if([peer[@"last_handshake_unix"] doubleValue]>0)handshakes++;
    self.details.stringValue=self.tunnelActive ? [NSString stringWithFormat:@"Активный профиль: %@\nПоследний handshake: %@\nPeers с handshake: %lu из %@\nПолучено: %@ байт; отправлено: %@ байт\nDNS профиля: %@\nЗащита всего трафика не включена.",self.activeProfileName ?: @"имя не подтверждено",HandshakeDate(status[@"last_handshake_unix"]),(unsigned long)handshakes,status[@"peers"] ?: @0,status[@"rx_bytes"] ?: @0,status[@"tx_bytes"] ?: @0,[status[@"dns_configured"] isEqual:@YES] ? @"настроен через туннель" : @"используются системные настройки"] :
        self.recoveryRequired ? @"Компонент не подтвердил восстановление прежних настроек. Подключение недоступно. Повторите безопасную проверку кнопкой «Восстановить сеть…»." :
        [state isEqual:@"Error"] ? ([status[@"reason"] isEqual:@"endpoint route changed or became unavailable; tunnel closed"] ?
            @"Изменился маршрут до сервера. Туннель закрыт; можно подключиться снова." : @"Сетевой компонент завершил туннель. Можно подключиться снова.") : @"Выберите профиль для подключения.";
    if(![reply[@"ok"] isEqual:@YES] && !self.recoveryRequired && [reply[@"error"] isKindOfClass:NSString.class])
        self.details.stringValue=reply[@"error"];
    [self updateConnectControl];
    self.disconnect.enabled=self.tunnelActive;self.recover.enabled=self.recoveryRequired;
    self.statusItem.button.title=self.tunnelActive ? @"WG •" : self.recoveryRequired ? @"WG !" : @"WG";
    self.statusItem.button.toolTip=[@"LegacyWG — " stringByAppendingString:self.state.stringValue];
}
- (void)connectProfile:(id)sender {
    (void)sender; NSDictionary *profile=[self selectedProfile];if(!profile || self.busy || self.interactionPending || self.quitting || !self.connect.enabled)return;
    NSError *error=nil;NSData *data=LWReadProfile(profile[@"id"],&error);
    if(!data){[self alert:error.localizedDescription];return;}
    NSString *text=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if(!text){[self alert:@"Профиль должен быть UTF-8"];return;}
    self.activeProfileName=profile[@"name"];
    self.activeProfileIdentifier=profile[@"id"];
    [self performRequest:@{@"version":@1,@"op":@"start",@"profile":text}];
}
- (void)disconnectProfile:(id)sender { (void)sender;if(self.interactionPending)return;[self performRequest:@{@"version":@1,@"op":@"stop"}]; }
- (void)recoverNetwork:(id)sender {
    (void)sender;if(self.busy || self.interactionPending || self.quitting || !self.recoveryRequired)return;
    [self openWindow:nil];self.busy=YES;
    NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Восстановить обычную сеть?";
    alert.informativeText=@"Приложение попробует завершить восстановление собственных изменений. Если трафик блокировался, обычная сеть снова станет доступна. VPN не подключится автоматически.";
    [alert addButtonWithTitle:@"Восстановить"];[alert addButtonWithTitle:@"Отмена"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        self.busy=NO;
        if(response==NSAlertFirstButtonReturn)[self performRequest:@{@"version":@1,@"op":@"recover"}];
    }];
}
- (void)refreshStatus:(id)sender { (void)sender;[self performRequest:@{@"version":@1,@"op":@"status"}]; }
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)application {
    (void)application;
    if(self.interactionPending){[self openWindow:nil];return NSTerminateCancel;}
    if(self.quitting)return NSTerminateLater;
    if(self.busy){[self openWindow:nil];[self alert:@"Дождитесь завершения текущей операции перед выходом."];return NSTerminateCancel;}
    if(!self.tunnelActive){
        if(self.recoveryRequired) {
            NSAlert *warning=[[NSAlert alloc] init];warning.messageText=@"Восстановление сети не подтверждено";
            warning.informativeText=@"Закрытие программы не означает, что сеть восстановлена. Выйти сейчас?";
            [warning addButtonWithTitle:@"Выйти"];[warning addButtonWithTitle:@"Отмена"];
            self.interactionPending=YES;NSModalResponse response=[warning runModal];self.interactionPending=NO;
            if(response!=NSAlertFirstButtonReturn)return NSTerminateCancel;
        }
        [self.timer invalidate];return NSTerminateNow;
    }
    NSAlert *alert=[[NSAlert alloc] init];alert.messageText=@"Отключить туннель и выйти?";
    alert.informativeText=@"После отключения трафик снова использует обычную сеть.";
    [alert addButtonWithTitle:@"Отключить и выйти"];[alert addButtonWithTitle:@"Отмена"];
    self.interactionPending=YES;NSModalResponse response=[alert runModal];self.interactionPending=NO;
    if(response!=NSAlertFirstButtonReturn)return NSTerminateCancel;
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

static BOOL WaitFor(BOOL (^condition)(void)) {
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:3];
    while(!condition() && deadline.timeIntervalSinceNow>0)
        [NSRunLoop.mainRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.02]];
    return condition();
}

static NSData *UIProfileFixture(void) {
    // Deterministic parser-only credentials, never used for network traffic.
    NSMutableData *private=[NSMutableData dataWithLength:32], *public=[NSMutableData dataWithLength:32];
    memset(private.mutableBytes,1,32);memset(public.mutableBytes,2,32);
    NSString *text=[NSString stringWithFormat:@"[Interface]\nPrivateKey = %@\nAddress = 10.7.0.2/32\n[Peer]\nPublicKey = %@\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 10.20.0.0/24\n",
        [private base64EncodedStringWithOptions:0],[public base64EncodedStringWithOptions:0]];
    return [text dataUsingEncoding:NSUTF8StringEncoding];
}

static NSTextView *LicenseView(NSView *view, NSUInteger depth) {
    if(depth>8)return nil;
    if([view isKindOfClass:NSTextView.class])return (NSTextView *)view;
    for(NSView *child in view.subviews){NSTextView *found=LicenseView(child,depth+1);if(found)return found;}
    return nil;
}

static BOOL ProfileSheetTest(ClientController *controller) {
    NSString *identifier=nil;NSError *error=nil;
    NSData *original=UIProfileFixture();
    NSString *name=[@"Sheet test " stringByAppendingString:NSUUID.UUID.UUIDString];
    if(!LWStoreProfile(original,name,&identifier,&error))return NO;
    controller.profiles=@[@{@"id":identifier,@"name":name}];[controller.table reloadData];
    [controller.table selectRowIndexes:[NSIndexSet indexSetWithIndex:0] byExtendingSelection:NO];
    [controller showReply:@{@"ok":@YES,@"status":@{@"state":@"Disconnected"}}];controller.busy=NO;
    BOOL preview=WaitFor(^BOOL{return [controller.selectedProfileSupported isEqual:@YES];}) &&
        [controller.profileDetails.stringValue containsString:@"10.7.0.2/32"] && [controller.profileDetails.stringValue containsString:@"127.0.0.1:51820"];
    [controller deleteProfile:nil];
    BOOL opened=WaitFor(^BOOL{return controller.window.attachedSheet!=nil;});
    [controller menuNeedsUpdate:controller.statusItem.menu];
    BOOL guarded=opened && controller.interactionPending && !controller.busy && !controller.menuConnect.enabled &&
        [controller applicationShouldTerminate:NSApp]==NSTerminateCancel;
    [controller connectProfile:nil]; // Entry point must return before sending Start.
    guarded=guarded && !controller.busy;
    [controller showReply:@{@"ok":@YES,@"status":@{@"state":@"Connecting"}}];
    NSWindow *deletionSheet=controller.window.attachedSheet;
    if(opened)[NSApp endSheet:deletionSheet returnCode:NSAlertFirstButtonReturn];
    BOOL refused=WaitFor(^BOOL{return controller.window.attachedSheet!=nil && controller.interactionPending &&
        controller.window.attachedSheet!=deletionSheet;});
    // Drain the original sheet animation/callback. The refusal presents a new
    // informational sheet; the real Keychain item must still be unchanged.
    [NSRunLoop.mainRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.3]];
    refused=refused && [LWReadProfile(identifier,&error) isEqualToData:original];
    if(controller.window.attachedSheet)[NSApp endSheet:controller.window.attachedSheet returnCode:NSAlertFirstButtonReturn];
    BOOL closed=WaitFor(^BOOL{return !controller.interactionPending && !controller.window.attachedSheet;});
    [controller showReply:@{@"ok":@YES,@"status":@{@"state":@"Disconnected"}}];
    NSArray *conflicts=LWProfileImportConflicts(original,name,&error);
    [controller chooseImport:original name:name conflicts:conflicts validation:@{@"ok":@YES,@"native_supported":@YES}];
    // chooseImport is called with the same pending state as the real importer.
    controller.interactionPending=YES;
    BOOL duplicate=WaitFor(^BOOL{return controller.window.attachedSheet!=nil;});
    NSWindow *duplicateSheet=controller.window.attachedSheet;
    if(duplicate)[NSApp endSheet:duplicateSheet returnCode:NSAlertSecondButtonReturn];
    duplicate=duplicate && WaitFor(^BOOL{return controller.interactionPending && controller.window.attachedSheet!=nil && controller.window.attachedSheet!=duplicateSheet;});
    if(controller.window.attachedSheet)[NSApp endSheet:controller.window.attachedSheet returnCode:NSAlertSecondButtonReturn];
    BOOL canceled=WaitFor(^BOOL{return !controller.interactionPending && !controller.window.attachedSheet;}) &&
        [LWReadProfile(identifier,&error) isEqualToData:original];
    BOOL removed=LWDeleteProfile(identifier,&error);
    controller.profiles=@[@{@"id":@"layout-only",@"name":@"GUI layout test — без ключей"}];[controller.table reloadData];
    [controller.table selectRowIndexes:[NSIndexSet indexSetWithIndex:0] byExtendingSelection:NO];
    return preview && guarded && refused && closed && duplicate && canceled && removed;
}

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
    controller.previewGeneration++;controller.selectedProfileSupported=@YES;
    [controller showReply:@{@"ok":@YES,@"status":@{@"state":@"Disconnected",@"protected":@NO}}];
    [controller menuNeedsUpdate:controller.statusItem.menu];
    BOOL menu=controller.statusItem.menu.numberOfItems==9 && controller.menuConnect.enabled &&
        !controller.menuDisconnect.enabled && ![controller applicationShouldTerminateAfterLastWindowClosed:NSApp];
    [controller showReply:@{@"ok":@NO,@"error":@"owned network recovery requires attention",
        @"status":@{@"state":@"RecoveryRequired",@"protected":@NO}}];
    [controller menuNeedsUpdate:controller.statusItem.menu];
    BOOL recovery=controller.recoveryRequired && !controller.tunnelActive && !controller.connect.enabled &&
        controller.recover.enabled && controller.menuRecover.enabled && !controller.menuConnect.enabled &&
        [controller.state.stringValue isEqual:@"Нужно восстановление сети"];
    [controller showReply:@{@"ok":@NO,@"error":@"Unavailable"}];
    BOOL unknown=!controller.connect.enabled && controller.recoveryRequired;
    [controller showReply:@{@"ok":@YES,@"status":@{@"state":@"Disconnected",@"protected":@NO}}];
    recovery=recovery && unknown && !controller.recoveryRequired && !controller.recover.enabled;
    BOOL profileSheets=ProfileSheetTest(controller);
    controller.previewGeneration++;controller.selectedProfileSupported=@YES;
    NSDictionary *preview=ValidateProfile(UIProfileFixture());
    controller.profileDetails.stringValue=PreviewText(preview,YES);controller.profileDetails.toolTip=PreviewText(preview,NO);
    [controller updateConnectControl];
    BOOL metadata=[controller.profileDetails.stringValue containsString:@"10.7.0.2/32"] &&
        [controller.profileDetails.stringValue containsString:@"127.0.0.1:51820"] && ![controller.profileDetails.stringValue containsString:@"Key"];
    [controller about:nil];BOOL about=WaitFor(^BOOL{return controller.window.attachedSheet!=nil;});
    NSTextView *licenses=LicenseView(controller.window.attachedSheet.contentView,0);
    about=about && [licenses.string containsString:@"WireGuard-LICENSE"] && [licenses.string containsString:@"Go-PATENTS"];
    if(controller.window.attachedSheet)[NSApp endSheet:controller.window.attachedSheet returnCode:NSAlertFirstButtonReturn];
    about=about && WaitFor(^BOOL{return !controller.interactionPending && !controller.window.attachedSheet;});
    BOOL bounds=YES;
    for(NSView *view in @[controller.state,controller.details,controller.profileDetails,controller.connect,controller.disconnect,controller.recover])
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
    BOOL passed=menu && recovery && profileSheets && metadata && about && bounds && saved && labelPixels>30;
    NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":passed ? @"PASS" : @"FAIL",
        @"kind":@"developer-only-gui-layout-fixture",@"menu_actions":@(menu),@"control_bounds":@(bounds),
        @"recovery_controls_and_unknown_state":@(recovery),
        @"actual_profile_sheets_guard_cancel_and_changed_state_refusal":@(profileSheets),
        @"selected_profile_metadata":@(metadata),@"actual_about_license_sheet":@(about),
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
            NSData *updated=[@"LegacyWG replacement marker" dataUsingEncoding:NSUTF8StringEncoding];
            NSData *otherData=[@"LegacyWG unrelated marker" dataUsingEncoding:NSUTF8StringEncoding];
            NSString *otherIdentifier=nil;
            BOOL other=LWStoreProfile(otherData,@"LegacyWG unrelated CI profile",&otherIdentifier,&error);
            NSArray *contentConflicts=LWProfileImportConflicts(sample,@"LegacyWG different filename",&error);
            NSArray *nameConflicts=LWProfileImportConflicts(updated,@"legacywg RENAMED ci PROFILE",&error);
            NSDictionary *expectedProfile=@{@"id":identifier ?: @"",@"name":@"LegacyWG renamed CI profile"};
            BOOL conflicts=keychain && [contentConflicts containsObject:expectedProfile] && [nameConflicts containsObject:expectedProfile];
            BOOL replacement=other && LWReplaceProfile(identifier,updated,&error) &&
                [LWReadProfile(identifier,&error) isEqualToData:updated] && [LWReadProfile(otherIdentifier,&error) isEqualToData:otherData];
            BOOL labelAfterReplace=NO;
            for(NSDictionary *profile in LWListProfiles())if([profile[@"id"] isEqual:identifier] &&
                [profile[@"name"] isEqual:@"LegacyWG renamed CI profile"])labelAfterReplace=YES;
            NSError *refusal=nil;
            BOOL refused=replacement && !LWReplaceProfile(identifier,[NSMutableData dataWithLength:256*1024+1],&refusal) &&
                !LWReplaceProfile(NSUUID.UUID.UUIDString,updated,&refusal) &&
                !LWProfileNameAvailable(@"LEGACYWG RENAMED CI PROFILE",&refusal) &&
                !LWProfileNameAvailable(@"invalid\nlabel",&refusal) && [LWReadProfile(identifier,&error) isEqualToData:updated];
            BOOL copy=LWProfileNameAvailable([@"Free CI name " stringByAppendingString:NSUUID.UUID.UUIDString],&error);
            BOOL invalidValidation=![ValidateProfile(sample)[@"ok"] isEqual:@YES];
            NSDictionary *previewValidation=ValidateProfile(UIProfileFixture());
            NSString *previewText=PreviewText(previewValidation,NO);
            BOOL metadata=[previewValidation[@"native_supported"] isEqual:@YES] &&
                [previewText containsString:@"10.7.0.2/32"] && [previewText containsString:@"127.0.0.1:51820"] &&
                ![previewText containsString:@"Key"] && [PreviewText(@{@"ok":@YES,@"preview":@{}},YES) isEqual:@"Не удалось получить сведения о профиле."];
            NSString *licenseText=LicenseText();
            BOOL licenses=[licenseText containsString:@"WireGuard-LICENSE"] && [licenseText containsString:@"Go-PATENTS"] &&
                [licenseText containsString:@"golang.org_x_crypto-v0.37.0-LICENSE"];
            if(otherIdentifier)other=LWDeleteProfile(otherIdentifier,&error) && other;
            keychain=keychain && conflicts && replacement && labelAfterReplace && refused && copy && invalidValidation && other;
            NSDictionary *fixture=@{@"ok":@YES,@"status":@{@"state":@"Connected",@"rx_bytes":@12,@"tx_bytes":@34,
                @"private_key":@"private-marker",@"endpoint":@"endpoint-marker",@"interface":@"interface-marker",
                @"peers":@2,@"profile_name":@"profile-marker",@"dns_servers":@[@"dns-marker"],
                @"preview":@{@"addresses":@[@"address-marker"],@"endpoints":@[@"preview-marker"]}}};
            NSData *diagnostics=[NSJSONSerialization dataWithJSONObject:DiagnosticReport(fixture) options:0 error:NULL];
            NSString *report=[[NSString alloc] initWithData:diagnostics encoding:NSUTF8StringEncoding];
            BOOL privacy=diagnostics.length>0 && [report rangeOfString:@"-marker"].location==NSNotFound;
            if(identifier)keychain=LWDeleteProfile(identifier,&error) && keychain;
            NSDictionary *health=installedTest ? LWRequest(@{@"version":@1,@"op":@"health"},requirement) : nil;
            BOOL helper=installedTest && [health[@"ok"] isEqual:@YES] && [health[@"state"] isEqual:@"Available"];
            BOOL passed=requirement.length && keychain && metadata && licenses && privacy && (!installedTest || helper);
            NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":passed ? @"PASS" : @"FAIL",@"kind":@"client-bundle-self-test",
                @"keychain_write_read_delete":keychain ? @"PASS" : @"FAIL",@"keychain_error_code":@(error.code),
                @"rename_preserves_id_and_data":rename && renamedLabel ? @"PASS" : @"FAIL",
                @"unsafe_profile_label_refused":nameValidation ? @"PASS" : @"FAIL",
                @"duplicate_name_and_exact_content_detected":conflicts ? @"PASS" : @"FAIL",
                @"exact_item_replacement_preserves_id_label_and_other_item":replacement && labelAfterReplace ? @"PASS" : @"FAIL",
                @"oversized_missing_item_and_duplicate_name_refused":refused ? @"PASS" : @"FAIL",
                @"invalid_profile_validation_refused":invalidValidation ? @"PASS" : @"FAIL",
                @"private_profile_preview_without_keys":metadata ? @"PASS" : @"FAIL",
                @"bundled_licenses_complete":licenses ? @"PASS" : @"FAIL",
                @"diagnostic_metadata_privacy":privacy ? @"PASS" : @"FAIL",
                @"installed_helper_authentication":installedTest ? (helper ? @"PASS" : @"FAIL") : @"NOT_RUN",
                @"core_dumps_disabled":@YES,@"vpn_ready":@NO} options:0 error:NULL];
            [NSFileHandle.fileHandleWithStandardOutput writeData:json]; return passed ? 0 : 1;
        }
        [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        ClientController * __attribute__((objc_precise_lifetime)) controller=[[ClientController alloc] init];
        NSApp.delegate=controller;
        BOOL launchTest=argc==2 && strcmp(argv[1],"--launch-self-test")==0;
        __block BOOL launchPassed=NO;
        if(launchTest) {
            const char *ci=getenv("GITHUB_ACTIONS");if(!ci || strcmp(ci,"true")!=0)return 3;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
                BOOL visible=NSApp.delegate==controller && controller.window.visible && controller.timer.valid;
                [controller.window performClose:nil];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
                    launchPassed=visible && NSApp.running && !controller.window.visible && controller.timer.valid;
                    NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":launchPassed ? @"PASS" : @"FAIL",
                        @"kind":@"native-gui-live-lifecycle",@"automatic_delegate_launch":@(visible),
                        @"close_window_keeps_app_and_timer":@(launchPassed),@"vpn_test":@"NOT_RUN",@"high_sierra":@"NOT_RUN"}
                        options:0 error:NULL];
                    [NSFileHandle.fileHandleWithStandardOutput writeData:json];[controller.timer invalidate];[NSApp stop:nil];
                    // stop: sets the flag; a dispatch callback must also wake nextEventMatchingMask:.
                    NSEvent *wake=[NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint
                        modifierFlags:0 timestamp:0 windowNumber:0 context:nil subtype:0 data1:0 data2:0];
                    [NSApp postEvent:wake atStart:YES];
                });
            });
        }
        [NSApp run];
        if(launchTest)return launchPassed ? 0 : 1;
    }
    return 0;
}
