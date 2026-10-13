// Developer-only native controller test; this executable never enters the pkg.
// Reuse the exact application implementation instead of a simulated timer/UI.
#define main LWProductionMain
#include "../App/main.m"
#undef main

@interface ModalController : ClientController
@property(nonatomic) NSUInteger confirmedReplies;
@property(nonatomic) BOOL modalStarted;
@property(nonatomic,copy) NSString *originalInterface;
@property(nonatomic,copy) NSString *testMode;
@property(nonatomic) BOOL quitPromptOpened;
@property(nonatomic) NSUInteger quitRepliesBefore;
@property(nonatomic) NSTimeInterval quitBegan;
@end

@interface ModalApplication : NSApplication
@end

static void Emit(NSDictionary *value) {
    NSData *json=[NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
    [NSFileHandle.fileHandleWithStandardOutput writeData:json];
    [NSFileHandle.fileHandleWithStandardOutput writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
}

static void Finish(ModalController *controller, NSDictionary *proof) {
    Emit(proof);[controller.timer invalidate];[NSApp stop:nil];
    NSEvent *wake=[NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint
        modifierFlags:0 timestamp:0 windowNumber:0 context:nil subtype:0 data1:0 data2:0];
    [NSApp postEvent:wake atStart:YES];
}

@implementation ModalApplication
- (void)sendEvent:(NSEvent *)event {
    if(event.type==NSEventTypeApplicationDefined && event.subtype==71) {
        ModalController *controller=(ModalController *)self.delegate;
        controller.quitRepliesBefore=controller.confirmedReplies;
        controller.quitBegan=NSProcessInfo.processInfo.systemUptime;
        BOOL accepting=[controller.testMode isEqual:@"--quit-accept"];
        // Enter runModal from a real AppKit event, outside a main dispatch
        // callback. Blocking a GCD callback would make a false timer fixture.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.25*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
            controller.quitPromptOpened=self.modalWindow!=nil && controller.interactionPending;
            Emit(@{@"phase":@"quit_prompt",@"status":controller.quitPromptOpened ? @"READY" : @"FAIL"});
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(accepting ? 3 : 18)*NSEC_PER_SEC),dispatch_get_main_queue(),^{
            if(!self.modalWindow){Finish(controller,@{@"status":@"FAIL",@"phase":@"quit_modal_missing"});return;}
            [self stopModalWithCode:accepting ? NSAlertFirstButtonReturn : NSAlertSecondButtonReturn];
        });
        [self terminate:nil];
        if(!accepting) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.2*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
                NSUInteger replies=controller.confirmedReplies-controller.quitRepliesBefore;
                NSTimeInterval held=NSProcessInfo.processInfo.systemUptime-controller.quitBegan;
                BOOL canceled=controller.quitPromptOpened && self.running && !self.modalWindow &&
                    !controller.quitting && !controller.interactionPending && controller.timer.valid &&
                    controller.statusKnown && controller.tunnelActive && replies>=7 && held>=18;
                Finish(controller,@{@"status":canceled ? @"PASS" : @"FAIL",@"kind":@"native-live-quit-cancel",
                    @"real_appkit_terminate_event":@YES,@"quit_confirmation_held_seconds":@(held),
                    @"connected_replies_during_quit_confirmation":@(replies),@"cancel_preserves_active_tunnel":@(canceled),
                    @"high_sierra":@"NOT_RUN",@"mouse_accessibility":@"NOT_RUN"});
            });
        }
        return;
    }
    [super sendEvent:event];
}
@end

@implementation ModalController
- (void)showReply:(NSDictionary *)reply {
    [super showReply:reply];
    NSDictionary *status=reply[@"status"];
    if(![reply[@"ok"] isEqual:@YES] || ![status[@"state"] isEqual:@"Connected"] ||
       ![status[@"tunnel_started"] isEqual:@YES])return;
    NSString *interface=status[@"interface"];
    if(!self.originalInterface)self.originalInterface=interface;
    if(![interface isEqual:self.originalInterface])return;
    self.confirmedReplies++;
    if(self.modalStarted)return;
    self.modalStarted=YES;
    if([self.testMode hasPrefix:@"--quit-"]) {
        NSEvent *event=[NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint
            modifierFlags:0 timestamp:0 windowNumber:0 context:nil subtype:71 data1:0 data2:0];
        [NSApp postEvent:event atStart:YES];return;
    }
    [self about:nil];
    NSWindow *sheet=self.window.attachedSheet;
    BOOL opened=sheet!=nil && self.interactionPending && LicenseView(sheet.contentView,0)!=nil;
    // These are real production actions. While the sheet is open they must
    // neither mutate the active session nor terminate the application.
    [self connectProfile:nil];[self disconnectProfile:nil];[self recoverNetwork:nil];
    BOOL quitRefused=[self applicationShouldTerminate:NSApp]==NSTerminateCancel;
    [self menuNeedsUpdate:self.statusItem.menu];
    BOOL guarded=!self.busy && !self.quitting && !self.menuConnect.enabled &&
        !self.menuDisconnect.enabled && !self.menuRecover.enabled && quitRefused;
    if(!opened || !guarded){Finish(self,@{@"status":@"FAIL",@"phase":@"sheet_or_guard"});return;}
    NSUInteger before=self.confirmedReplies;
    NSTimeInterval began=NSProcessInfo.processInfo.systemUptime;
    Emit(@{@"phase":@"sheet_open",@"status":@"READY"});
    if([self.testMode isEqual:@"--crash"])return; // Coordinator sends actual SIGKILL.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,18*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        NSTimeInterval elapsed=NSProcessInfo.processInfo.systemUptime-began;
        NSUInteger during=self.confirmedReplies-before;
        BOOL held=self.window.attachedSheet==sheet && self.interactionPending && self.timer.valid &&
            self.statusKnown && self.tunnelActive && !self.recoveryRequired && during>=7 && elapsed>=18;
        [self.window endSheet:sheet returnCode:NSAlertFirstButtonReturn];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.2*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
            BOOL closed=!self.window.attachedSheet && !self.interactionPending;
            [self.window performClose:nil];NSUInteger hiddenBefore=self.confirmedReplies;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),dispatch_get_main_queue(),^{
                NSUInteger hidden=self.confirmedReplies-hiddenBefore;
                BOOL hiddenActive=NSApp.running && !self.window.visible && self.timer.valid &&
                    self.tunnelActive && self.statusKnown && hidden>=2;
                Finish(self,@{@"status":held && closed && hiddenActive ? @"PASS" : @"FAIL",
                    @"kind":@"native-real-controller-encrypted-long-sheet",
                    @"license_sheet_opened":@(opened),@"modal_actions_guarded":@(guarded),
                    @"sheet_held_seconds":@(elapsed),@"confirmed_replies_during_sheet":@(during),
                    @"sheet_heartbeat_and_same_active_interface":@(held),@"sheet_closed_cleanly":@(closed),
                    @"hidden_window_confirmed_replies":@(hidden),@"hidden_window_keeps_active_tunnel":@(hiddenActive),
                    @"helper_watchdog_seconds":@15,@"high_sierra":@"NOT_RUN",
                    @"mouse_menu_tracking_accessibility":@"NOT_RUN"});
            });
        });
    });
}
- (void)applicationWillTerminate:(NSNotification *)notification {
    (void)notification;
    if(![self.testMode isEqual:@"--quit-accept"])return;
    BOOL stopped=self.quitPromptOpened && self.quitting && !self.interactionPending && !self.timer.valid;
    Emit(@{@"status":stopped ? @"PASS" : @"FAIL",@"kind":@"native-live-quit-accept",
        @"real_appkit_termination_notification":@YES,@"authenticated_stop_acknowledged_before_exit":@(stopped),
        @"high_sierra":@"NOT_RUN",@"mouse_accessibility":@"NOT_RUN"});
}
@end

int main(int argc,const char *argv[]) {
    @autoreleasepool {
        const char *ci=getenv("GITHUB_ACTIONS");if(!ci || strcmp(ci,"true")!=0)return 3;
        struct rlimit coreLimit={0,0};if(setrlimit(RLIMIT_CORE,&coreLimit)!=0)return 5;
        NSString *mode=argc==2 ? [NSString stringWithUTF8String:argv[1]] : @"";
        if(argc>2 || ![@[@"",@"--quit-cancel",@"--quit-accept",@"--crash"] containsObject:mode])return 2;
        [ModalApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        ModalController * __attribute__((objc_precise_lifetime)) controller=[[ModalController alloc] init];
        controller.testMode=mode;
        NSApp.delegate=controller;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,40*NSEC_PER_SEC),dispatch_get_main_queue(),^{
            Finish(controller,@{@"status":@"FAIL",@"phase":@"deadline"});
        });
        [NSApp run];
    }
    return 0;
}
