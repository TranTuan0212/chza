#import "FloatingMenu.h"
#import "Config.h"
#import "SecurityManager.h"
#import <objc/runtime.h>
#import <Security/Security.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Đường dẫn file Audit Log trong Documents của Sandbox Zalo
static inline NSString *get_inapp_audit_log_path(void) {
    NSString *home = NSHomeDirectory();
    return [home stringByAppendingPathComponent:@"Documents/ZaloAudit.log"];
}

// Hàm hỗ trợ tìm UIWindow đang hoạt động
static UIWindow *get_active_key_window(void) {
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]] && scene.activationState == UISceneActivationStateForegroundActive) {
                UIWindowScene *winScene = (UIWindowScene *)scene;
                for (UIWindow *w in winScene.windows) {
                    if (w.isKeyWindow) return w;
                }
                if (winScene.windows.count > 0) return winScene.windows.firstObject;
            }
        }
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                UIWindowScene *winScene = (UIWindowScene *)scene;
                for (UIWindow *w in winScene.windows) {
                    if (w.isKeyWindow) return w;
                }
                if (winScene.windows.count > 0) return winScene.windows.firstObject;
            }
        }
    }
    UIWindow *w = [UIApplication sharedApplication].keyWindow;
    if (!w && [UIApplication sharedApplication].windows.count > 0) {
        w = [UIApplication sharedApplication].windows.firstObject;
    }
    return w;
}

// Hàm hỗ trợ tìm UIViewController cao nhất đang hiển thị
static UIViewController *get_top_view_controller(void) {
    UIWindow *keyWin = get_active_key_window();
    UIViewController *topVC = keyWin.rootViewController;
    while (topVC.presentedViewController) {
        topVC = topVC.presentedViewController;
    }
    if ([topVC isKindOfClass:[UINavigationController class]]) {
        topVC = [(UINavigationController *)topVC visibleViewController];
    } else if ([topVC isKindOfClass:[UITabBarController class]]) {
        topVC = [(UITabBarController *)topVC selectedViewController];
    }
    return topVC;
}

#pragma mark - ZTFloatingButton Implementation

@implementation ZTFloatingButton {
    CGPoint _startTouchPoint;
    CGPoint _startCenter;
    BOOL _isDragging;
}

+ (instancetype)sharedButton {
    static ZTFloatingButton *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [ZTFloatingButton buttonWithType:UIButtonTypeCustom];
        [instance setupUI];
    });
    return instance;
}

- (void)setupUI {
    CGFloat btnSize = 52.0;
    self.frame = CGRectMake(15, 120, btnSize, btnSize);
    self.layer.cornerRadius = btnSize / 2.0;
    self.clipsToBounds = YES;
    self.backgroundColor = [UIColor colorWithRed:0.06 green:0.42 blue:0.95 alpha:0.92]; // Màu xanh Zalo
    self.layer.borderColor = [UIColor whiteColor].CGColor;
    self.layer.borderWidth = 2.0;
    
    // Đổ bóng nổi
    self.layer.shadowColor = [UIColor blackColor].CGColor;
    self.layer.shadowOffset = CGSizeMake(0, 3);
    self.layer.shadowOpacity = 0.4;
    self.layer.shadowRadius = 4.0;
    self.layer.masksToBounds = NO;
    
    [self setTitle:@"⚡ZT" forState:UIControlStateNormal];
    [self setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    
    // Kéo thả cử chỉ
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [self addGestureRecognizer:pan];
    
    [self addTarget:self action:@selector(buttonTapped) forControlEvents:UIControlEventTouchUpInside];
}

- (void)attachToWindow:(UIWindow *)window {
    if (!window) return;
    if (self.superview != window) {
        [self removeFromSuperview];
        [window addSubview:self];
        [window bringSubviewToFront:self];
    }
}

- (void)handlePan:(UIPanGestureRecognizer *)pan {
    UIWindow *win = self.superview ? (UIWindow *)self.superview : get_active_key_window();
    if (!win) return;
    
    CGPoint translation = [pan translationInView:win];
    
    if (pan.state == UIGestureRecognizerStateBegan) {
        _isDragging = YES;
        _startCenter = self.center;
    } else if (pan.state == UIGestureRecognizerStateChanged) {
        self.center = CGPointMake(_startCenter.x + translation.x, _startCenter.y + translation.y);
    } else if (pan.state == UIGestureRecognizerStateEnded || pan.state == UIGestureRecognizerStateCancelled) {
        _isDragging = NO;
        // Tự động hít vào mép trái hoặc phải màn hình
        CGRect screenBounds = win.bounds;
        CGFloat btnRadius = self.frame.size.width / 2.0;
        CGFloat targetX = (self.center.x < screenBounds.size.width / 2.0) ? (btnRadius + 10.0) : (screenBounds.size.width - btnRadius - 10.0);
        
        CGFloat minY = btnRadius + 50.0; // Tránh tai thỏ/status bar
        CGFloat maxY = screenBounds.size.height - btnRadius - 40.0; // Tránh home bar
        CGFloat targetY = MIN(MAX(self.center.y, minY), maxY);
        
        [UIView animateWithDuration:0.3 delay:0 options:UIViewAnimationOptionCurveEaseOut animations:^{
            self.center = CGPointMake(targetX, targetY);
        } completion:nil];
    }
}

- (void)buttonTapped {
    if (_isDragging) return;
    [[ZTMenuManager sharedManager] presentMainMenuFrom:nil];
}

- (void)show {
    self.hidden = NO;
    if (self.superview) {
        [self.superview bringSubviewToFront:self];
    }
}

- (void)hide {
    self.hidden = YES;
}

@end

#pragma mark - ZTMenuManager Implementation

@implementation ZTMenuManager

+ (instancetype)sharedManager {
    static ZTMenuManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[ZTMenuManager alloc] init];
    });
    return instance;
}

- (void)setupInAppMenu {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self tryAttachFloatingButton];
    });
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(tryAttachFloatingButton)
                                                 name:UIApplicationDidBecomeActiveNotification
                                               object:nil];
}

- (void)tryAttachFloatingButton {
    UIWindow *win = get_active_key_window();
    if (win) {
        [[ZTFloatingButton sharedButton] attachToWindow:win];
        [[ZTFloatingButton sharedButton] show];
    }
}

- (void)presentMainMenuFrom:(UIViewController *)presentingVC {
    UIViewController *top = presentingVC ?: get_top_view_controller();
    if (!top) return;
    
    ZTSettings *settings = [ZTSettings sharedSettings];
    BOOL isLicensed = [[ZTSecurityManager sharedManager] isLicenseValid];
    NSString *licStatus = isLicensed ? @"🟢 Bản Quyền Hợp Lệ" : @"❌ Chưa Kích Hoạt Key";
    
    NSString *title = @"⚡ ZALOTWEAK CONTROL CENTER";
    NSString *message = [NSString stringWithFormat:@"Trạng Thái: %@\nThiết Bị: %@ | IDFV: %@...",
                         licStatus,
                         settings.deviceMachine,
                         [settings.spoofedIDFV substringToIndex:MIN((NSUInteger)8, settings.spoofedIDFV.length)]];
    
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    // 1. Bản Quyền & Kích Hoạt Key
    [sheet addAction:[UIAlertAction actionWithTitle:@"🛡️ Bản Quyền (DRM Supabase)"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showLicenseMenuFrom:top];
    }]];
    
    // 2. Wipe Sạch Dữ Liệu Clone (Deep Wipe)
    [sheet addAction:[UIAlertAction actionWithTitle:@"🧹 Deep Wipe Sạch Dữ Liệu Clone"
                                             style:UIAlertActionStyleDestructive
                                           handler:^(UIAlertAction *action) {
        [self confirmDeepWipeFrom:top];
    }]];
    
    // 3. Xem Cấu Hình Giả Lập
    [sheet addAction:[UIAlertAction actionWithTitle:@"📱 Xem Thông Số Thiết Bị Giả Lập"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showHardwareSpecsFrom:top];
    }]];
    
    // 4. Random Cấu Hình Mới
    [sheet addAction:[UIAlertAction actionWithTitle:@"🎲 Đổi Danh Tính Mới (Random Specs)"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [settings generateNewProfile];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"🎉 Đã Đổi Thiết Bị Mới"
                                                                      message:[NSString stringWithFormat:@"Đã cấp danh tính phần cứng mới:\n\n- IDFV: %@\n- Profile Keychain: Mới tinh\n- Uptime & Dung lượng: Ngẫu nhiên", settings.spoofedIDFV]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:done animated:YES completion:nil];
    }]];
    
    // 5. Nhật Ký Kiểm Toán (Audit Log)
    [sheet addAction:[UIAlertAction actionWithTitle:@"📋 Nhật Ký Kiểm Toán (Audit Log)"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showAuditLogMenuFrom:top];
    }]];
    
    // 6. Ẩn Nút Nổi
    [sheet addAction:[UIAlertAction actionWithTitle:@"👁️ Tạm Ẩn Nút Nổi Này"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [[ZTFloatingButton sharedButton] hide];
        UIAlertController *hint = [UIAlertController alertControllerWithTitle:@"Đã Ẩn Nút Nổi"
                                                                      message:@"Để hiện lại nút nổi, bạn chỉ cần bấm thoát ra màn hình chính rồi mở lại Zalo."
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [hint addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:hint animated:YES completion:nil];
    }]];
    
    [sheet addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
    
    // Hỗ trợ iPad popover
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        sheet.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }
    
    [top presentViewController:sheet animated:YES completion:nil];
}

#pragma mark - Submenus

- (void)showLicenseMenuFrom:(UIViewController *)top {
    NSString *realUDID = [[ZTSecurityManager sharedManager] getRealHardwareUDID];
    NSString *status = [[ZTSecurityManager sharedManager] getLicenseStatusText];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🛡️ Quản Lý Bản Quyền"
                                                                   message:[NSString stringWithFormat:@"UDID Máy Thật:\n%@\n\nTrạng thái: %@", realUDID, status]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"📋 Sao Chép UDID Gửi Admin" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [UIPasteboard generalPasteboard].string = realUDID;
        UIAlertController *copied = [UIAlertController alertControllerWithTitle:@"Đã Sao Chép"
                                                                        message:@"Đã copy mã UDID vào bộ nhớ tạm. Hãy gửi mã này cho admin để kích hoạt."
                                                                 preferredStyle:UIAlertControllerStyleAlert];
        [copied addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:copied animated:YES completion:nil];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"🔑 Nhập License Key" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self promptEnterLicenseKeyFrom:top];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
    [top presentViewController:alert animated:YES completion:nil];
}

- (void)promptEnterLicenseKeyFrom:(UIViewController *)top {
    UIAlertController *inputAlert = [UIAlertController alertControllerWithTitle:@"🔑 Nhập License Key"
                                                                        message:@"Dán mã key được cấp bởi Supabase DRM vào ô bên dưới:"
                                                                 preferredStyle:UIAlertControllerStyleAlert];
    [inputAlert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = @"VD: ZT-XXXX-XXXX-XXXX";
    }];
    
    [inputAlert addAction:[UIAlertAction actionWithTitle:@"Kích Hoạt" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        NSString *key = inputAlert.textFields.firstObject.text;
        if (!key || key.length == 0) return;
        
        UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"Đang Xác Thực..."
                                                                         message:@"Đang kết nối Supabase DRM để kiểm tra bản quyền..."
                                                                  preferredStyle:UIAlertControllerStyleAlert];
        [top presentViewController:loading animated:YES completion:nil];
        
        [[ZTSecurityManager sharedManager] verifyLicenseWithKey:key completion:^(BOOL success, NSString *message) {
            [loading dismissViewControllerAnimated:YES completion:^{
                UIAlertController *res = [UIAlertController alertControllerWithTitle:success ? @"🎉 Thành Công" : @"❌ Thất Bại"
                                                                             message:message
                                                                      preferredStyle:UIAlertControllerStyleAlert];
                [res addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [top presentViewController:res animated:YES completion:nil];
            }];
        }];
    }]];
    
    [inputAlert addAction:[UIAlertAction actionWithTitle:@"Hủy" style:UIAlertActionStyleCancel handler:nil]];
    [top presentViewController:inputAlert animated:YES completion:nil];
}

- (void)showHardwareSpecsFrom:(UIViewController *)top {
    ZTSettings *s = [ZTSettings sharedSettings];
    uint64_t nowSec = (uint64_t)[[NSDate date] timeIntervalSince1970];
    uint64_t uptimeHours = (nowSec > s.bootTimeSec) ? ((nowSec - s.bootTimeSec) / 3600) : 0;
    
    NSString *info = [NSString stringWithFormat:
                      @"• Model Máy: %@ (%@)\n"
                      @"• Tên Thiết Bị: %@\n"
                      @"• Phiên Bản iOS: %@ (Build %@)\n"
                      @"• IDFV Đang Giả: %@\n"
                      @"• Profile Keychain: %@\n"
                      @"• Số Nhân CPU: %u Cores\n"
                      @"• Dung Lượng RAM: %.1f GB\n"
                      @"• Màn Hình: %.0fx%.0f @%.0fx\n"
                      @"• Uptime: %llu giờ trước\n"
                      @"• Ổ Cứng: %.1f GB / %.1f GB",
                      s.deviceMachine, s.deviceModel,
                      s.deviceName,
                      s.systemVersion, s.kernOsVersion,
                      s.spoofedIDFV,
                      [s.profileId substringToIndex:MIN((NSUInteger)8, s.profileId.length)],
                      s.ncpu,
                      (double)s.memsize / (1024.0 * 1024.0 * 1024.0),
                      s.screenWidth, s.screenHeight, s.screenScale,
                      uptimeHours,
                      (double)s.diskFreeSize / (1000.0 * 1000.0 * 1000.0),
                      (double)s.diskTotalSize / (1000.0 * 1000.0 * 1000.0)];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"📱 Thông Số Phần Cứng Giả Lập"
                                                                   message:info
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
    [top presentViewController:alert animated:YES completion:nil];
}

- (void)showAuditLogMenuFrom:(UIViewController *)top {
    ZTSettings *settings = [ZTSettings sharedSettings];
    NSString *logPath = get_inapp_audit_log_path();
    
    NSString *modeStatus = settings.enableAuditLog ? @"🟢 Đang Bật" : @"⚪ Đang Tắt";
    NSString *title = [NSString stringWithFormat:@"📋 Nhật Ký Kiểm Toán (%@)", modeStatus];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:@"Theo dõi chính xác mọi truy vấn phần cứng, Keychain và file hệ thống mà Zalo âm thầm thực hiện."
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    NSString *toggleTitle = settings.enableAuditLog ? @"⚪ Tắt Chế Độ Soi Log" : @"🟢 Bật Chế Độ Soi Log";
    [alert addAction:[UIAlertAction actionWithTitle:toggleTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        settings.enableAuditLog = !settings.enableAuditLog;
        [settings saveSettings];
        UIAlertController *c = [UIAlertController alertControllerWithTitle:@"Đã Lưu"
                                                                   message:settings.enableAuditLog ? @"Đã BẬT soi log. ZaloTweak sẽ ghi lại mọi truy vấn của Zalo vào file log." : @"Đã TẮT soi log."
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:c animated:YES completion:nil];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"📄 Xem / Xuất File Log" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        NSError *err = nil;
        NSString *content = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:&err];
        if (!content || content.length == 0) {
            UIAlertController *empty = [UIAlertController alertControllerWithTitle:@"Chưa Có Dữ Liệu"
                                                                           message:@"File log hiện đang trống.\nVui lòng đảm bảo bạn đã: \n1. Bật công tắc soi log\n2. Mở dùng Zalo trong 5-10 giây để ghi nhận."
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [empty addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [top presentViewController:empty animated:YES completion:nil];
            return;
        }
        
        UIAlertController *viewAlert = [UIAlertController alertControllerWithTitle:@"📋 Nội Dung ZaloAudit.log"
                                                                           message:[content length] > 1200 ? [NSString stringWithFormat:@"%@\n\n... (Đã rút gọn hiển thị)", [content substringToIndex:1200]] : content
                                                                    preferredStyle:UIAlertControllerStyleAlert];
        
        [viewAlert addAction:[UIAlertAction actionWithTitle:@"📤 Chia Sẻ / Lưu File" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            NSURL *fileURL = [NSURL fileURLWithPath:logPath];
            UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL] applicationActivities:nil];
            [top presentViewController:avc animated:YES completion:nil];
        }]];
        
        [viewAlert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
        [top presentViewController:viewAlert animated:YES completion:nil];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"🗑️ Xóa Sạch File Log" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [[NSFileManager defaultManager] removeItemAtPath:logPath error:nil];
        UIAlertController *delAlert = [UIAlertController alertControllerWithTitle:@"Đã Xóa" message:@"Đã xóa sạch nội dung file ZaloAudit.log." preferredStyle:UIAlertControllerStyleAlert];
        [delAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:delAlert animated:YES completion:nil];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
    
    if (alert.popoverPresentationController) {
        alert.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        alert.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }
    
    [top presentViewController:alert animated:YES completion:nil];
}

- (void)confirmDeepWipeFrom:(UIViewController *)top {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"⚠️ XÁC NHẬN WIPE SẠCH DỮ LIỆU"
                                                                   message:@"Hành động này sẽ:\n"
                                                                           @"1. Xóa sạch mọi tài khoản, token đăng nhập, cơ sở dữ liệu chat của bản Zalo Clone này.\n"
                                                                           @"2. Sinh IDFV mới, Uptime mới, và phân vùng Keychain mới 100%.\n"
                                                                           @"3. BẢO VỆ TUYỆT ĐỐI các file backup .adbk của Apps Manager và file ZaloAudit.log.\n"
                                                                           @"4. Tự động đóng ứng dụng để Zalo khởi động lại như một chiếc máy mới tinh.\n\n"
                                                                           @"Bạn có chắc chắn muốn thực hiện?"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Wipe Ngay" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [self performInAppDeepWipe];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Hủy" style:UIAlertActionStyleCancel handler:nil]];
    [top presentViewController:alert animated:YES completion:nil];
}

- (void)performInAppDeepWipe {
    NSString *home = NSHomeDirectory();
    if (!home || home.length < 5) return;
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // 1. Xóa Clipboard để triệt tiêu mọi token tracking
    [UIPasteboard generalPasteboard].items = @[];
    [UIPasteboard generalPasteboard].string = @"";
    
    // 2. Xóa sạch Keychain của Zalo trong sandbox này
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword
    ];
    for (id secClass in secClasses) {
        NSDictionary *query = @{(__bridge id)kSecClass: secClass};
        SecItemDelete((__bridge CFDictionaryRef)query);
    }
    
    // Hàm xóa nội bộ có bảo vệ .adbk và ZaloAudit.log
    void (^wipeDirSafely)(NSString *) = ^(NSString *dirPath) {
        NSArray *items = [fm contentsOfDirectoryAtPath:dirPath error:nil];
        for (NSString *item in items) {
            NSString *lower = [item lowercaseString];
            // BẢO VỆ TUYỆT ĐỐI FILE BACKUP .adbk VÀ FILE AUDIT LOG
            if ([lower hasSuffix:@".adbk"] ||
                [lower containsString:@"appsmanager"] ||
                [lower containsString:@"adbk"] ||
                [lower isEqualToString:@"zaloaudit.log"] ||
                [lower isEqualToString:@"com.sonhu.zalotweak.plist"]) {
                continue;
            }
            NSString *fullPath = [dirPath stringByAppendingPathComponent:item];
            [fm removeItemAtPath:fullPath error:nil];
        }
    };
    
    // 3. Quét dọn các thư mục dữ liệu trong Sandbox
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *libDir = [home stringByAppendingPathComponent:@"Library"];
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];
    
    wipeDirSafely(docDir);
    wipeDirSafely(tmpDir);
    
    NSString *cachesDir = [libDir stringByAppendingPathComponent:@"Caches"];
    NSString *appSupportDir = [libDir stringByAppendingPathComponent:@"Application Support"];
    NSString *prefDir = [libDir stringByAppendingPathComponent:@"Preferences"];
    
    wipeDirSafely(cachesDir);
    wipeDirSafely(appSupportDir);
    wipeDirSafely(prefDir);
    
    // Tái tạo thư mục sạch để Zalo không bị lỗi I/O khi khởi động lại
    [fm createDirectoryAtPath:docDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:cachesDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:appSupportDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:prefDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    // 4. Sinh định danh & phần cứng mới tinh
    [[ZTSettings sharedSettings] generateNewProfile];
    
    // 5. Hiển thị thông báo và thoát app sạch sẽ
    UIViewController *top = get_top_view_controller();
    NSString *msg = [NSString stringWithFormat:
                     @"🎉 Đã làm sạch 100%% dữ liệu Zalo Clone!\n\n"
                     @"• IDFV Mới: %@\n"
                     @"• Keychain & Cache: Làm sạch hoàn toàn\n"
                     @"• File Backup .adbk: Được bảo vệ an toàn\n\n"
                     @"⚠️ Ứng dụng sẽ tự động đóng sau 2 giây.\n"
                     @"VUI LÒNG BẬT VÀ TẮT CHẾ ĐỘ MÁY BAY (AIRPLANE MODE) để đổi IP 4G trước khi mở lại Zalo!",
                     [ZTSettings sharedSettings].spoofedIDFV];
    
    UIAlertController *doneAlert = [UIAlertController alertControllerWithTitle:@"🧹 Deep Wipe Hoàn Tất"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
    
    if (top) {
        [top presentViewController:doneAlert animated:YES completion:^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                exit(0);
            });
        }];
    } else {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            exit(0);
        });
    }
}

@end

#pragma clang diagnostic pop
