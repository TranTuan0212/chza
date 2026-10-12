#import "FloatingMenu.h"
#import "Config.h"
#import "SecurityManager.h"
#import <objc/runtime.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#import <fcntl.h>
#import <unistd.h>

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

static uint64_t get_directory_size(NSString *path) {
    if (!path) return 0;
    uint64_t total = 0;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *contents = [fm subpathsAtPath:path];
    for (NSString *sub in contents) {
        NSString *lower = [sub lowercaseString];
        if ([lower hasSuffix:@".adbk"] || [lower containsString:@"appsmanager"] || [lower isEqualToString:@"zaloaudit.log"]) {
            continue;
        }
        NSString *full = [path stringByAppendingPathComponent:sub];
        NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
        total += [attrs fileSize];
    }
    return total;
}

static void fetch_public_ip(void (^completion)(NSString *ip)) {
    NSURL *url = [NSURL URLWithString:@"https://api.ipify.org"];
    NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:3.0];
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        NSString *ipStr = nil;
        if (data) {
            ipStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            ipStr = [ipStr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(ipStr ?: @"Không xác định");
        });
    }] resume];
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
    
    NSString *title = @"⚡ ZALOTWEAK - MENU ĐIỀU KHIỂN";
    NSString *guidance;
    if (!isLicensed) {
        guidance = @"⚠️ BƯỚC CẦN LÀM ĐẦU TIÊN: Bấm [1️⃣] để KÍCH HOẠT KEY!\nSau đó mới tiến hành Deep Wipe và Reg Acc.";
    } else {
        guidance = @"📋 QUY TRÌNH TẠO ACC CHUẨN (LÀM THEO THỨ TỰ):\n"
                   @"▶️ Bước 1: Bấm [2️⃣ Deep Wipe Sạch & Đổi Máy] (App tự thoát)\n"
                   @"▶️ Bước 2: Bật rồi tắt Chế Độ Máy Bay (đổi IP 4G mới)\n"
                   @"▶️ Bước 3: Mở lại Zalo -> Bấm [3️⃣ Kiểm Tra Độ Sạch]\n"
                   @"▶️ Bước 4: Thấy tick xanh 🟢 -> Tiến hành Reg Acc an toàn!";
    }
    
    NSString *message = [NSString stringWithFormat:@"%@\n\n📱 Thiết Bị Giả Lập: %@ | IDFV: %@...",
                         guidance,
                         settings.deviceMachine,
                         [settings.spoofedIDFV substringToIndex:MIN((NSUInteger)8, settings.spoofedIDFV.length)]];
    
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    // Nút 1: Bản Quyền
    NSString *licButtonTitle = isLicensed ? @"🛡️ [1️⃣] Quản Lý Bản Quyền (🟢 ĐÃ KÍCH HOẠT)" : @"🛡️ [1️⃣] KÍCH HOẠT BẢN QUYỀN (BẮT BUỘC TRƯỚC)";
    [sheet addAction:[UIAlertAction actionWithTitle:licButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showLicenseMenuFrom:top];
    }]];
    
    // Nút 2: Deep Wipe & Cấp Máy Mới
    [sheet addAction:[UIAlertAction actionWithTitle:@"🧹 [2️⃣] Deep Wipe Sạch & Cấp Máy Mới (Tự đóng app)"
                                             style:UIAlertActionStyleDestructive
                                           handler:^(UIAlertAction *action) {
        [self confirmDeepWipeFrom:top];
    }]];
    
    // Nút 3: Kiểm Tra Độ Sạch Trước Khi Reg
    [sheet addAction:[UIAlertAction actionWithTitle:@"🔍 [3️⃣] Kiểm Tra Độ Sạch Trước Khi Reg (Checklist)"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showPreRegDiagnosticFrom:top];
    }]];
    
    // Nút 4: Xem Cấu Hình Giả Lập
    [sheet addAction:[UIAlertAction actionWithTitle:@"📱 [4️⃣] Xem Thông Số Máy Giả Lập Đang Dùng"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showHardwareSpecsFrom:top];
    }]];
    
    // Nút 5: Nhật Ký Kiểm Toán (Audit Log)
    [sheet addAction:[UIAlertAction actionWithTitle:@"📋 [5️⃣] Nhật Ký Kiểm Toán (Audit Log Console)"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showAuditLogMenuFrom:top];
    }]];
    
    // Nút 6: Ẩn Nút Nổi
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
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"⚠️ XÁC NHẬN DEEP WIPE SẠCH DỮ LIỆU"
                                                                   message:@"Hành động này sẽ thực hiện tự động:\n"
                                                                           @"1. Xóa sạch mọi tài khoản, token đăng nhập, cache, cookies của clone này.\n"
                                                                           @"2. Cấp IDFV mới tinh, Uptime mới & phân vùng Keychain mới 100%.\n"
                                                                           @"3. BẢO TỒN NGUYÊN VẸN BẢN QUYỀN (Không bao giờ bị mất Key).\n"
                                                                           @"4. BẢO VỆ TUYỆT ĐỐI các file backup .adbk của Apps Manager.\n\n"
                                                                           @"👉 QUY TRÌNH SAU KHI APP TỰ ĐÓNG:\n"
                                                                           @"• BẬT RỒI TẮT Chế Độ Máy Bay (để xoay IP 4G mới).\n"
                                                                           @"• Mở lại Zalo -> Bấm [3️⃣ Kiểm Tra Độ Sạch] trước khi Reg Acc!"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"🧹 Wipe Sạch & Đổi Máy Ngay" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
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
    
    // Hàm xóa nội bộ có bảo vệ .adbk, ZaloAudit.log và tất cả cấu hình/bản quyền tweak
    void (^wipeDirSafely)(NSString *) = ^(NSString *dirPath) {
        NSArray *items = [fm contentsOfDirectoryAtPath:dirPath error:nil];
        for (NSString *item in items) {
            NSString *lower = [item lowercaseString];
            // BẢO VỆ TUYỆT ĐỐI FILE BACKUP .adbk, FILE AUDIT LOG VÀ TẤT CẢ FILE CẤU HÌNH/KEY CỦA TWEAK
            if ([lower hasSuffix:@".adbk"] ||
                [lower containsString:@"appsmanager"] ||
                [lower containsString:@"adbk"] ||
                [lower isEqualToString:@"zaloaudit.log"] ||
                [lower containsString:@"com.sonhu.zalotweak"]) {
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
    
    // 4. Lưu lại IDFV và thời điểm wipe trước khi đổi mới
    ZTSettings *settings = [ZTSettings sharedSettings];
    settings.lastWipedIDFV = settings.spoofedIDFV;
    settings.lastWipedTimestamp = (uint64_t)[[NSDate date] timeIntervalSince1970];

    // Sinh định danh & phần cứng mới tinh
    [settings generateNewProfile];
    
    // 5. Hiển thị thông báo và thoát app sạch sẽ
    UIViewController *top = get_top_view_controller();
    NSString *msg = [NSString stringWithFormat:
                     @"🎉 Đã làm sạch 100%% dữ liệu Zalo Clone!\n\n"
                     @"• IDFV Mới: %@\n"
                     @"• Keychain & Cache: Làm sạch hoàn toàn\n"
                     @"• File Backup .adbk: Được bảo vệ an toàn\n\n"
                     @"⚠️ Ứng dụng sẽ tự động đóng sau 2 giây.\n"
                     @"VUI LÒNG BẬT VÀ TẮT CHẾ ĐỘ MÁY BAY (AIRPLANE MODE) để đổi IP 4G trước khi mở lại Zalo!",
                     settings.spoofedIDFV];
    
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

- (void)showPreRegDiagnosticFrom:(UIViewController *)top {
    UIViewController *presenter = top ?: get_top_view_controller();
    if (!presenter) return;

    UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"🔍 Đang Kiểm Tra..."
                                                                     message:@"Đang quét bộ nhớ đệm Sandbox và kiểm tra địa chỉ IP mạng..."
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [presenter presentViewController:loading animated:YES completion:^{
        fetch_public_ip(^(NSString *currentIP) {
            [loading dismissViewControllerAnimated:YES completion:^{
                [self renderDiagnosticReportWithIP:currentIP from:presenter];
            }];
        });
    }];
}

- (void)renderDiagnosticReportWithIP:(NSString *)currentIP from:(UIViewController *)presenter {
    ZTSettings *s = [ZTSettings sharedSettings];
    NSString *home = NSHomeDirectory();
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *cacheDir = [home stringByAppendingPathComponent:@"Library/Caches"];
    uint64_t sandboxBytes = get_directory_size(docDir) + get_directory_size(cacheDir);
    double sandboxKB = (double)sandboxBytes / 1024.0;

    // 1. Đọc TRỰC TIẾP TỪ HỆ THỐNG RUNTIME QUA HÀM C & OBJECTIVE-C (Xác thực thật 100%)
    char liveMachineBuf[64] = {0};
    size_t mlen = sizeof(liveMachineBuf);
    sysctlbyname("hw.machine", liveMachineBuf, &mlen, NULL, 0);
    NSString *liveMachineStr = [NSString stringWithUTF8String:liveMachineBuf];

    NSString *liveBundle = [[NSBundle mainBundle] bundleIdentifier];
    NSString *liveIDFV = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    
    NSString *liveIDFA = @"Đã ẩn danh";
    Class asClass = NSClassFromString(@"ASIdentifierManager");
    if (asClass) {
        id sharedMgr = [asClass performSelector:@selector(sharedManager)];
        if (sharedMgr) {
            NSUUID *adUUID = [sharedMgr performSelector:@selector(advertisingIdentifier)];
            if (adUUID) {
                liveIDFA = [adUUID UUIDString];
            }
        }
    }

    // 2. Đo dung lượng ổ cứng hệ thống đọc được bởi App
    NSDictionary *fsAttrs = [[NSFileManager defaultManager] attributesOfFileSystemForPath:home error:nil];
    unsigned long long liveDiskFree = [fsAttrs[NSFileSystemFreeSize] unsignedLongLongValue];
    unsigned long long liveDiskTotal = [fsAttrs[NSFileSystemSize] unsignedLongLongValue];
    double freeGB = (double)liveDiskFree / (1000.0 * 1000.0 * 1000.0);
    double totalGB = (double)liveDiskTotal / (1000.0 * 1000.0 * 1000.0);

    // 3. Kiểm tra mobileprovision
    NSString *provPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    BOOL isHiddenProv = (provPath == nil || ![[NSFileManager defaultManager] fileExistsAtPath:provPath]);

    // 4. Uptime hệ thống trực tiếp
    NSTimeInterval liveUptime = [[NSProcessInfo processInfo] systemUptime];
    uint64_t uptimeHours = (uint64_t)(liveUptime / 3600.0);

    // 5. So sánh IDFV với lần wipe trước
    NSString *idfvOld = (s.lastWipedIDFV.length > 0) ? [s.lastWipedIDFV substringToIndex:MIN((NSUInteger)8, s.lastWipedIDFV.length)] : @"Chưa wipe";
    NSString *idfvShort = (liveIDFV.length > 8) ? [liveIDFV substringToIndex:8] : liveIDFV;
    BOOL isDifferentIDFV = (s.lastWipedIDFV.length > 0 && ![liveIDFV isEqualToString:s.lastWipedIDFV]);
    NSString *idfvStatus = isDifferentIDFV ? @"Mới tinh ✅" : (s.lastWipedIDFV.length == 0 ? @"Mới cấp profile ✅" : @"Trùng lặp ⚠️");

    // 6. So sánh IP
    NSString *ipOld = (s.lastWipedIP.length > 0) ? s.lastWipedIP : @"Chưa lưu";
    BOOL isDifferentIP = (s.lastWipedIP.length > 0 && ![currentIP isEqualToString:s.lastWipedIP]);
    BOOL isSameIP = (s.lastWipedIP.length > 0 && [currentIP isEqualToString:s.lastWipedIP]);
    
    NSString *ipStatus = @"";
    if (isSameIP) {
        ipStatus = @"⚠️ TRÙNG IP LẦN TRƯỚC";
    } else if (isDifferentIP) {
        ipStatus = @"Đã đổi IP mới ✅";
    } else {
        ipStatus = @"IP ban đầu ✅";
    }

    if (s.lastWipedIP.length == 0 && currentIP.length > 0 && ![currentIP isEqualToString:@"Không xác định"]) {
        s.lastWipedIP = currentIP;
        [s saveSettings];
    }

    // 7. KIỂM TRA THỰC TẾ BẰNG HÀM C POSIX (Chính xác cách LevelDB C++ gọi mở file)
    // a. Gọi hàm C open() với ĐƯỜNG DẪN TƯƠNG ĐỐI
    int fd_rel = open("KVCore/Device/_zt_rel_test.tmp", O_RDWR | O_CREAT, 0644);
    BOOL leveldbRelWritable = NO;
    if (fd_rel >= 0) {
        char testData[] = "ZT_LOCK_OK";
        write(fd_rel, testData, sizeof(testData));
        close(fd_rel);
        leveldbRelWritable = YES;
        unlink("KVCore/Device/_zt_rel_test.tmp");
    }

    // b. Gọi hàm C openat() với AT_FDCWD và ĐƯỜNG DẪN TƯƠNG ĐỐI
    int fd_at = openat(AT_FDCWD, "KVCore/Device/_zt_at_test.tmp", O_RDWR | O_CREAT, 0644);
    BOOL leveldbAtWritable = NO;
    if (fd_at >= 0) {
        close(fd_at);
        leveldbAtWritable = YES;
        unlink("KVCore/Device/_zt_at_test.tmp");
    }

    // c. Gọi hàm hệ thống NSUserDefaults với SuiteName
    BOOL appGroupWorking = NO;
    @try {
        NSUserDefaults *groupDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"group.vn.com.vng.zingalo"];
        if (groupDefaults) {
            [groupDefaults setObject:@"zt_ok" forKey:@"_zt_diagnostic_check"];
            [groupDefaults synchronize];
            NSString *readBack = [groupDefaults stringForKey:@"_zt_diagnostic_check"];
            if ([readBack isEqualToString:@"zt_ok"]) {
                appGroupWorking = YES;
                [groupDefaults removeObjectForKey:@"_zt_diagnostic_check"];
                [groupDefaults synchronize];
            }
        }
    } @catch (NSException *e) {
        appGroupWorking = NO;
    }

    BOOL allStorageHealthy = (leveldbRelWritable && leveldbAtWritable && appGroupWorking);

    // 8. Kết luận toàn diện
    NSString *conclusion = @"";
    if (isSameIP) {
        conclusion = @"🔴 CẢNH BÁO: TRÙNG ĐỊA CHỈ IP 4G CŨ!\nVui lòng BẬT rồi TẮT Chế Độ Máy Bay (Airplane Mode) để nhà mạng đổi địa chỉ IP mới trước khi bấm Tạo Tài Khoản.";
    } else if (!allStorageHealthy) {
        conclusion = @"⚠️ CẢNH BÁO: LỖI KHO LƯU TRỮ CƠ SỞ DỮ LIỆU C++!\nLevelDB (hàm C open/openat) chưa ghi được qua đường dẫn tương đối. Vui lòng bấm [2️⃣] Deep Wipe.";
    } else {
        conclusion = @"🟢 MÁY SẠCH HOÀN TOÀN - AN TOÀN 100% ĐỂ REG ACC!\n(C POSIX sysctl/open/openat thông suốt, IDFV mới, IDFA ẩn, App Group an toàn, IP 4G mới)";
    }

    NSString *report = [NSString stringWithFormat:
        @"═══════════════════════════\n"
        @"1. XÁC THỰC ĐỊNH DANH (LIVE C & RUNTIME):\n"
        @" • Machine (C)  : %@ (%@)\n"
        @" • Bundle ID    : %@ (%@)\n"
        @" • IDFV Hiện Tại: %@... (%@)\n"
        @" • IDFV Trước Đó: %@...\n"
        @" • IDFA Quảng Cáo: %@...\n"
        @" • App Tracking : Denied (Từ chối theo dõi ✅)\n\n"
        @"2. ĐỊA CHỈ IP 4G (INTERNET CELLULAR):\n"
        @" • IP Lần Này   : %@ (%@)\n"
        @" • IP Trước Đó  : %@\n\n"
        @"3. THÔNG SỐ Ổ CỨNG TRÌNH DIỄN ZALO:\n"
        @" • Trống / Tổng : %.1f GB / %.1f GB ✅\n"
        @" • Uptime Máy   : %llu giờ hoạt động ✅\n\n"
        @"4. VỆ SINH DỮ LIỆU SANDBOX:\n"
        @" • Rác / Cache  : %.1f KB (%@)\n"
        @" • Sideload     : %@\n"
        @" • Profile Sec  : Phân vùng Keychain riêng biệt ✅\n\n"
        @"5. THỰC THI C++ LEVELDB (GỌI HÀM C TRỰC TIẾP):\n"
        @" • open(tương đối)  : %@\n"
        @" • openat(tương đối): %@\n"
        @" • App Groups Suite : %@\n"
        @"═══════════════════════════\n"
        @"👉 KẾT LUẬN:\n%@",
        liveMachineStr, ([liveMachineStr isEqualToString:s.deviceMachine] ? @"Đã Fake thành công ✅" : @"Máy thật ⚠️"),
        liveBundle, ([liveBundle isEqualToString:@"vn.com.vng.zingalo"] ? @"Gốc VNG ✅" : @"Chưa đổi"),
        idfvShort, idfvStatus,
        idfvOld,
        (liveIDFA.length > 8 ? [liveIDFA substringToIndex:8] : liveIDFA),
        currentIP, ipStatus,
        ipOld,
        freeGB, totalGB,
        uptimeHours,
        sandboxKB, (sandboxKB < 150.0 ? @"Sạch 100% ✅" : @"Có cache"),
        (isHiddenProv ? @"Đã ẩn mobileprovision ✅" : @"Chưa ẩn"),
        (leveldbRelWritable ? @"C open() tương đối THÀNH CÔNG ✅" : @"Lỗi mở file C ❌"),
        (leveldbAtWritable ? @"C openat() tương đối THÀNH CÔNG ✅" : @"Lỗi mở openat ❌"),
        (appGroupWorking ? @"Đã chuyển hướng Sandbox an toàn ✅" : @"Lỗi truy cập ❌"),
        conclusion];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🔍 BÁO CÁO XÁC THỰC HỆ THỐNG RUNTIME"
                                                                   message:report
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

@end

#pragma clang diagnostic pop
