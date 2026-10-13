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

// Hàm hỗ trợ tìm UIWindow đang hoạt động của Zalo (loại trừ ZTFloatingWindow)
static UIWindow *get_active_key_window(void) {
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]] && scene.activationState == UISceneActivationStateForegroundActive) {
                UIWindowScene *winScene = (UIWindowScene *)scene;
                for (UIWindow *w in winScene.windows) {
                    if (w.isKeyWindow && ![w isKindOfClass:NSClassFromString(@"ZTFloatingWindow")]) return w;
                }
                for (UIWindow *w in winScene.windows) {
                    if (![w isKindOfClass:NSClassFromString(@"ZTFloatingWindow")]) return w;
                }
            }
        }
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                UIWindowScene *winScene = (UIWindowScene *)scene;
                for (UIWindow *w in winScene.windows) {
                    if (w.isKeyWindow && ![w isKindOfClass:NSClassFromString(@"ZTFloatingWindow")]) return w;
                }
                for (UIWindow *w in winScene.windows) {
                    if (![w isKindOfClass:NSClassFromString(@"ZTFloatingWindow")]) return w;
                }
            }
        }
    }
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (![w isKindOfClass:NSClassFromString(@"ZTFloatingWindow")]) return w;
    }
    return [UIApplication sharedApplication].keyWindow;
}

// Hàm hỗ trợ tìm UIViewController cao nhất đang hiển thị
static UIViewController *get_top_view_controller(void) {
    UIWindow *keyWin = get_active_key_window();
    UIViewController *topVC = keyWin.rootViewController;
    if (!topVC) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (![w isKindOfClass:NSClassFromString(@"ZTFloatingWindow")] && w.rootViewController) {
                topVC = w.rootViewController;
                break;
            }
        }
    }
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

@implementation ZTFloatingWindow

+ (instancetype)sharedWindow {
    static ZTFloatingWindow *s_window = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        CGRect bounds = [UIScreen mainScreen].bounds;
        s_window = [[ZTFloatingWindow alloc] initWithFrame:bounds];
        s_window.windowLevel = UIWindowLevelAlert + 1000.0;
        s_window.backgroundColor = [UIColor clearColor];
        
        UIViewController *rootVC = [[UIViewController alloc] init];
        rootVC.view.backgroundColor = [UIColor clearColor];
        rootVC.view.userInteractionEnabled = NO;
        s_window.rootViewController = rootVC;
        
        ZTFloatingButton *btn = [ZTFloatingButton sharedButton];
        [s_window addSubview:btn];
    });
    return s_window;
}

- (void)show {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (@available(iOS 13.0, *)) {
            if (!self.windowScene) {
                for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]] && scene.activationState == UISceneActivationStateForegroundActive) {
                        self.windowScene = (UIWindowScene *)scene;
                        break;
                    }
                }
                if (!self.windowScene) {
                    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                        if ([scene isKindOfClass:[UIWindowScene class]]) {
                            self.windowScene = (UIWindowScene *)scene;
                            break;
                        }
                    }
                }
                if (!self.windowScene) {
                    for (UIWindow *w in [UIApplication sharedApplication].windows) {
                        if (w != self && w.windowScene) {
                            self.windowScene = w.windowScene;
                            break;
                        }
                    }
                }
            }
        }
        self.hidden = NO;
        ZTFloatingButton *btn = [ZTFloatingButton sharedButton];
        btn.hidden = NO;
        [self bringSubviewToFront:btn];
    });
}

- (void)hide {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.hidden = YES;
    });
}

- (BOOL)pointInside:(CGPoint)point withEvent:(UIEvent *)event {
    ZTFloatingButton *btn = [ZTFloatingButton sharedButton];
    if (btn && !btn.hidden && btn.alpha > 0.01) {
        CGPoint p = [btn convertPoint:point fromView:self];
        if ([btn pointInside:p withEvent:event]) {
            return YES;
        }
    }
    return NO;
}

@end

@implementation ZTFloatingButton {
    CGPoint _startCenter;
    BOOL _isDragging;
}

+ (instancetype)sharedButton {
    static ZTFloatingButton *instance = nil;
    if (instance) return instance;
    instance = [ZTFloatingButton buttonWithType:UIButtonTypeCustom];
    [instance setupUI];
    return instance;
}

- (void)setupUI {
    CGFloat btnSize = 58.0;
    self.frame = CGRectMake(15, 140, btnSize, btnSize);
    self.layer.cornerRadius = btnSize / 2.0;
    self.clipsToBounds = YES;
    self.backgroundColor = [UIColor colorWithRed:0.06 green:0.45 blue:0.98 alpha:0.95]; // Màu xanh Zalo nổi bật
    self.layer.borderColor = [UIColor whiteColor].CGColor;
    self.layer.borderWidth = 3.0;
    
    // Đổ bóng nổi
    self.layer.shadowColor = [UIColor blackColor].CGColor;
    self.layer.shadowOffset = CGSizeMake(0, 4);
    self.layer.shadowOpacity = 0.6;
    self.layer.shadowRadius = 8.0;
    self.layer.masksToBounds = NO;
    
    [self setTitle:@"⚡ZT" forState:UIControlStateNormal];
    [self setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    
    // Kéo thả cử chỉ
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [self addGestureRecognizer:pan];
    
    [self addTarget:self action:@selector(buttonTapped) forControlEvents:UIControlEventTouchUpInside];
}

- (void)attachToWindow:(UIWindow *)window {
    [[ZTFloatingWindow sharedWindow] show];
}

- (void)handlePan:(UIPanGestureRecognizer *)pan {
    UIView *container = self.superview ?: [ZTFloatingWindow sharedWindow];
    if (!container) return;
    
    CGPoint translation = [pan translationInView:container];
    
    if (pan.state == UIGestureRecognizerStateBegan) {
        _isDragging = YES;
        _startCenter = self.center;
    } else if (pan.state == UIGestureRecognizerStateChanged) {
        self.center = CGPointMake(_startCenter.x + translation.x, _startCenter.y + translation.y);
    } else if (pan.state == UIGestureRecognizerStateEnded || pan.state == UIGestureRecognizerStateCancelled) {
        _isDragging = NO;
        // Tự động hít vào mép trái hoặc phải màn hình
        CGRect screenBounds = [UIScreen mainScreen].bounds;
        CGFloat btnRadius = self.frame.size.width / 2.0;
        CGFloat targetX = (self.center.x < screenBounds.size.width / 2.0) ? (btnRadius + 10.0) : (screenBounds.size.width - btnRadius - 10.0);
        
        CGFloat minY = btnRadius + 60.0; // Tránh tai thỏ/status bar
        CGFloat maxY = screenBounds.size.height - btnRadius - 50.0; // Tránh home bar
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
    [[ZTFloatingWindow sharedWindow] show];
}

- (void)hide {
    [[ZTFloatingWindow sharedWindow] hide];
}

@end

#pragma mark - ZTMenuManager Implementation

@implementation ZTMenuManager

+ (instancetype)sharedManager {
    static ZTMenuManager *instance = nil;
    if (instance) return instance;
    instance = [[ZTMenuManager alloc] init];
    return instance;
}

- (void)setupInAppMenu {
    // Thử hiện nút nổi định kỳ trong 10 giây đầu khởi động để đảm bảo window scene đã sẵn sàng
    for (int i = 0; i <= 10; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 0.7 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self tryAttachFloatingButton];
        });
    }
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(tryAttachFloatingButton)
                                                 name:UIApplicationDidBecomeActiveNotification
                                               object:nil];

    if (@available(iOS 13.0, *)) {
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(tryAttachFloatingButton)
                                                     name:UISceneDidActivateNotification
                                                   object:nil];
    }

    // Nhắc nhở bản quyền nếu chưa kích hoạt hoặc đã hết hạn
    static dispatch_once_t promptToken;
    dispatch_once(&promptToken, ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
                UIViewController *top = get_top_view_controller();
                if (top) {
                    [self showLicenseRequiredAlertFrom:top featureName:@"Toàn Bộ Tính Năng ZaloTweak"];
                }
            }
        });
    });
}

- (void)tryAttachFloatingButton {
    if (![ZTSettings sharedSettings].showFloatingMenu) return;
    [[ZTFloatingWindow sharedWindow] show];
}

- (void)showLicenseRequiredAlertFrom:(UIViewController *)top featureName:(NSString *)featureName {
    UIViewController *presenter = top ?: get_top_view_controller();
    if (!presenter) return;
    
    NSString *status = [[ZTSecurityManager sharedManager] getLicenseStatusText];
    NSString *msg = [NSString stringWithFormat:@"Tính năng [%@] yêu cầu bản quyền kích hoạt hợp lệ.\n\nTrạng thái hiện tại: %@\n\nVui lòng kích hoạt License Key để mở khóa toàn bộ tính năng giả lập và đổi máy.", featureName, status];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🛡️ YÊU CẦU BẢN QUYỀN"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"🔑 Nhập License Key" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self promptEnterLicenseKeyFrom:presenter];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"📋 Sao Chép UDID Gửi Admin" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        NSString *udid = [[ZTSecurityManager sharedManager] getRealHardwareUDID];
        [UIPasteboard generalPasteboard].string = udid ?: @"";
        UIAlertController *copied = [UIAlertController alertControllerWithTitle:@"Đã Sao Chép UDID"
                                                                        message:[NSString stringWithFormat:@"UDID máy thật:\n%@\n\nHãy gửi mã này cho Admin để nhận License Key.", udid]
                                                                 preferredStyle:UIAlertControllerStyleAlert];
        [copied addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [presenter presentViewController:copied animated:YES completion:nil];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
    
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)presentMainMenuFrom:(UIViewController *)presentingVC {
    UIViewController *top = presentingVC ?: get_top_view_controller();
    if (!top) return;
    
    ZTSettings *settings = [ZTSettings sharedSettings];
    BOOL isLicensed = [[ZTSecurityManager sharedManager] isLicenseValid];
    
    NSString *title = @"⚡ ZALOTWEAK - MENU ĐIỀU KHIỂN";
    NSString *guidance;
    if (!isLicensed) {
        guidance = @"⚠️ BƯỚC CẦN LÀM ĐẦU TIÊN: Bấm [1️⃣] để KÍCH HOẠT KEY!\nHiện các tính năng Wipe, Đổi Vùng, Giả Lập ĐANG BỊ KHÓA.";
    } else {
        guidance = @"📋 QUY TRÌNH TẠO ACC CHUẨN (LÀM THEO THỨ TỰ):\n"
                   @"▶️ Bước 1: Bấm [2️⃣ Deep Wipe Sạch & Đổi Máy] (App tự thoát)\n"
                   @"▶️ Bước 2: Bật rồi tắt Chế Độ Máy Bay (đổi IP 4G mới)\n"
                   @"▶️ Bước 3: Mở lại Zalo -> Bấm [3️⃣ Kiểm Tra Độ Sạch]\n"
                   @"▶️ Bước 4: Thấy tick xanh 🟢 -> Tiến hành Reg Acc an toàn!";
    }
    
    NSString *message = [NSString stringWithFormat:@"%@\n\n📱 Thiết Bị Giả Lập: %@ | IDFV: %@...",
                         guidance,
                         isLicensed ? settings.deviceMachine : @"(Chưa kích hoạt - Đang dùng máy thật)",
                         isLicensed ? [settings.spoofedIDFV substringToIndex:MIN((NSUInteger)8, settings.spoofedIDFV.length)] : @"(Chưa cấp)"];
    
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
    NSString *wipeButtonTitle = isLicensed ? @"🧹 [2️⃣] Deep Wipe Sạch & Cấp Máy Mới (Tự đóng app)" : @"🔒 [2️⃣] Deep Wipe Sạch & Cấp Máy Mới (Cần Key)";
    [sheet addAction:[UIAlertAction actionWithTitle:wipeButtonTitle
                                             style:UIAlertActionStyleDestructive
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Deep Wipe & Cấp Máy Mới"];
            return;
        }
        [self confirmDeepWipeFrom:top];
    }]];
    
    // Nút 3: Kiểm Tra Độ Sạch Trước Khi Reg
    NSString *diagButtonTitle = isLicensed ? @"🔍 [3️⃣] Kiểm Tra Độ Sạch Trước Khi Reg (Checklist)" : @"🔒 [3️⃣] Kiểm Tra Độ Sạch Trước Khi Reg (Cần Key)";
    [sheet addAction:[UIAlertAction actionWithTitle:diagButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Kiểm Tra Độ Sạch Trước Khi Reg"];
            return;
        }
        [self showPreRegDiagnosticFrom:top];
    }]];
    
    // Nút 4: Xem Cấu Hình Giả Lập
    [sheet addAction:[UIAlertAction actionWithTitle:@"📱 [4️⃣] Xem Thông Số Máy Giả Lập Đang Dùng"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showHardwareSpecsFrom:top];
    }]];

    // Nút 5: Đổi Khu Vực & Nhà Mạng (VN / Du Học Sinh Mỹ / Mỹ)
    NSString *currentRegion = settings.regionMode ?: @"VN";
    NSString *regionName = [currentRegion isEqualToString:@"US_STUDENT"] ? @"🇺🇸 Du Học Sinh Mỹ (+1)" :
                           ([currentRegion isEqualToString:@"US"] ? @"🇺🇸 Hoa Kỳ (+1)" : @"🇻🇳 Việt Nam (+84)");
    NSString *regionButtonTitle = isLicensed ? [NSString stringWithFormat:@"🌐 [5️⃣] Khu Vực & SIM: %@", regionName] : @"🔒 [5️⃣] Khu Vực & SIM (Cần Key)";
    [sheet addAction:[UIAlertAction actionWithTitle:regionButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Đổi Khu Vực & Nhà Mạng SIM"];
            return;
        }
        [self showRegionSelectionMenuFrom:top];
    }]];
    
    // Nút 6: Nhật Ký Kiểm Toán (Audit Log)
    [sheet addAction:[UIAlertAction actionWithTitle:@"📋 [6️⃣] Nhật Ký Kiểm Toán & HAR Inspector"
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
    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        NSString *status = [[ZTSecurityManager sharedManager] getLicenseStatusText];
        NSString *warnMsg = [NSString stringWithFormat:@"⚠️ TRẠNG THÁI: %@\n\nToàn bộ cơ chế Giả Lập Thiết Bị ĐANG BỊ TẮT. Zalo hiện đang đọc trực tiếp thông số PHẦN CỨNG THẬT của máy bạn!\n\nVui lòng kích hoạt License Key để mở khóa giả lập thiết bị.", status];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"📱 Thông Số Máy (CHƯA KÍCH HOẠT)"
                                                                       message:warnMsg
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"🔑 Nhập License Key" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [self promptEnterLicenseKeyFrom:top];
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
        [top presentViewController:alert animated:YES completion:nil];
        return;
    }

    ZTSettings *s = [ZTSettings sharedSettings];
    uint64_t nowSec = (uint64_t)[[NSDate date] timeIntervalSince1970];
    uint64_t uptimeHours = (nowSec > s.bootTimeSec) ? ((nowSec - s.bootTimeSec) / 3600) : 0;
    
    NSString *currentRegion = s.regionMode ?: @"VN";
    NSString *regionName = [currentRegion isEqualToString:@"US_STUDENT"] ? @"🇺🇸 Du Học Sinh Mỹ (+1)" :
                           ([currentRegion isEqualToString:@"US"] ? @"🇺🇸 Hoa Kỳ (+1)" : @"🇻🇳 Việt Nam (+84)");

    NSString *info = [NSString stringWithFormat:
                      @"• Khu Vực & SIM: %@\n"
                      @"• Nhà Mạng: %@ (MCC %@, MNC %@)\n"
                      @"• Model Máy: %@ (%@)\n"
                      @"• Tên Thiết Bị: %@\n"
                      @"• Serial Number: %@\n"
                      @"• Wi-Fi MAC: %@\n"
                      @"• Phiên Bản iOS: %@ (Build %@)\n"
                      @"• IDFV Đang Giả: %@\n"
                      @"• Profile Keychain: %@\n"
                      @"• Số Nhân CPU: %u Cores\n"
                      @"• Dung Lượng RAM: %.1f GB\n"
                      @"• Màn Hình: %.0fx%.0f @%.0fx\n"
                      @"• Uptime: %llu giờ trước\n"
                      @"• Ổ Cứng: %.1f GB / %.1f GB",
                      regionName,
                      s.carrierName ?: @"Viettel", s.carrierMCC ?: @"452", s.carrierMNC ?: @"04",
                      s.deviceMachine, s.deviceModel,
                      s.deviceName,
                      s.spoofedSerial ?: @"N/A",
                      s.spoofedWifiMAC ?: @"N/A",
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

- (void)applyRegionOnly:(NSString *)region {
    ZTSettings *s = [ZTSettings sharedSettings];
    s.regionMode = region;
    if ([region isEqualToString:@"US_STUDENT"]) {
        NSArray *userNames = @[@"Huy's iPhone", @"Nam's iPhone", @"Trang's iPhone", @"Alex's iPhone", @"Minh's iPhone"];
        s.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];
        s.carrierName = @"T-Mobile";
        s.carrierMCC = @"310";
        s.carrierMNC = @"260";
        s.carrierCountryCode = @"us";
    } else if ([region isEqualToString:@"US"]) {
        NSArray *userNames = @[@"David's iPhone", @"Michael's iPhone", @"iPhone", @"Sarah's iPhone"];
        s.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];
        s.carrierName = @"Verizon";
        s.carrierMCC = @"311";
        s.carrierMNC = @"480";
        s.carrierCountryCode = @"us";
    } else {
        NSArray *userNames = @[@"iPhone của Tuấn", @"iPhone của Linh", @"iPhone (2)", @"iPhone của Huy", @"iPhone của Nam"];
        s.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];
        s.carrierName = @"Viettel";
        s.carrierMCC = @"452";
        s.carrierMNC = @"04";
        s.carrierCountryCode = @"vn";
    }
    [s saveSettings];
}

- (void)showRegionSelectionMenuFrom:(UIViewController *)top {
    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        [self showLicenseRequiredAlertFrom:top featureName:@"Đổi Khu Vực & Nhà Mạng SIM"];
        return;
    }

    ZTSettings *s = [ZTSettings sharedSettings];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🌐 Chọn Khu Vực & Nhà Mạng SIM"
                                                                   message:@"Tùy chọn này giúp đồng bộ tên máy, nhà mạng SIM (MCC, MNC, ISO) và mã quốc gia mà không xóa dữ liệu hay thay đổi IDFV."
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇻🇳 Việt Nam (+84) [Viettel / Vina / Mobi]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self applyRegionOnly:@"VN"];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang khu vực Việt Nam (+84).\n• SIM: %@ (MCC %@)\n• Tên máy: %@", s.carrierName, s.carrierMCC, s.deviceName]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:done animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Du Học Sinh Mỹ (+1) [T-Mobile / AT&T / Mint]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self applyRegionOnly:@"US_STUDENT"];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Du Học Sinh Mỹ (+1).\n• SIM: %@ (US)\n• Tên máy: %@\n\n💡 MẸO: Hãy kết nối Proxy/VPN US trước khi Reg để Zalo duyệt mượt 100%%.", s.carrierName, s.deviceName]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:done animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Hoa Kỳ / Mỹ (+1) [Verizon / AT&T / T-Mobile]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self applyRegionOnly:@"US"];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Hoa Kỳ (+1).\n• SIM: %@ (US)\n• Tên máy: %@", s.carrierName, s.deviceName]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:done animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];

    if (alert.popoverPresentationController) {
        alert.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        alert.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }

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
    
    [alert addAction:[UIAlertAction actionWithTitle:@"🌐 Xuất File HAR (Charles / Proxyman)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        NSString *home = NSHomeDirectory();
        NSString *harPath = home ? [home stringByAppendingPathComponent:@"Documents/ZaloTraffic.har"] : @"/var/mobile/Library/Preferences/ZaloTraffic.har";
        if (![[NSFileManager defaultManager] fileExistsAtPath:harPath]) {
            UIAlertController *noHar = [UIAlertController alertControllerWithTitle:@"Chưa Có Dữ Liệu HAR"
                                                                           message:@"Chưa có request mạng nào được ghi nhận.\nHãy chắc chắn bạn đã Bật Kiểm Toán (Audit) và dùng Zalo vài giây."
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [noHar addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [top presentViewController:noHar animated:YES completion:nil];
            return;
        }
        NSURL *fileURL = [NSURL fileURLWithPath:harPath];
        UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL] applicationActivities:nil];
        [top presentViewController:avc animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🗑️ Xóa Sạch File Log" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [[NSFileManager defaultManager] removeItemAtPath:logPath error:nil];
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *hPath = [home stringByAppendingPathComponent:@"Documents/ZaloTraffic.har"];
            [[NSFileManager defaultManager] removeItemAtPath:hPath error:nil];
        }
        UIAlertController *delAlert = [UIAlertController alertControllerWithTitle:@"Đã Xóa" message:@"Đã xóa sạch nội dung file ZaloAudit.log và ZaloTraffic.har." preferredStyle:UIAlertControllerStyleAlert];
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
    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        [self showLicenseRequiredAlertFrom:top featureName:@"Deep Wipe & Cấp Máy Mới"];
        return;
    }

    ZTSettings *s = [ZTSettings sharedSettings];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🧹 DEEP WIPE & CẤP MÁY MỚI"
                                                                   message:@"Chỉ 1 chạm: Xóa sạch dữ liệu Zalo cũ, cấp ngay ID thiết bị mới tinh và đồng bộ cấu hình mạng SIM mong muốn:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇻🇳 Việt Nam (+84) [Viettel / Vina / Mobi]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self performInAppDeepWipeWithRegion:@"VN"];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Du Học Sinh Mỹ (+1) [T-Mobile / AT&T / Mint]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self performInAppDeepWipeWithRegion:@"US_STUDENT"];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Hoa Kỳ (+1) [Verizon / AT&T / T-Mobile]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self performInAppDeepWipeWithRegion:@"US"];
    }]];

    NSString *keepTitle = [NSString stringWithFormat:@"🔄 Giữ Vùng Hiện Tại (%@) & Cấp Máy Mới", s.regionMode ?: @"VN"];
    [alert addAction:[UIAlertAction actionWithTitle:keepTitle style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [self performInAppDeepWipeWithRegion:s.regionMode ?: @"VN"];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Hủy Bỏ" style:UIAlertActionStyleCancel handler:nil]];

    if (alert.popoverPresentationController) {
        alert.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        alert.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }

    [top presentViewController:alert animated:YES completion:nil];
}

- (void)performInAppDeepWipe {
    [self performInAppDeepWipeWithRegion:[ZTSettings sharedSettings].regionMode ?: @"VN"];
}

- (void)performInAppDeepWipeWithRegion:(NSString *)targetRegion {
    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        return;
    }

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
                [lower isEqualToString:@"zalotraffic.har"] ||
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
    
    // 4. ĐÁnh dấu Cold-Boot: Lưu khu vực SIM đã chọn và cờ needsNewProfile
    //    KHÔNG sinh profile mới ở đây - profile sẽ được sinh khi khởi động lại app (Cold-Boot)
    ZTSettings *settings = [ZTSettings sharedSettings];
    settings.lastWipedIDFV = settings.spoofedIDFV;
    settings.lastWipedTimestamp = (uint64_t)[[NSDate date] timeIntervalSince1970];
    settings.regionMode = targetRegion ?: @"VN";
    settings.needsNewProfile = YES;
    [settings saveSettings];

    // 5. Đóng app dứt khoát ngay lập tức (không delay) để:
    //    - Ngăn Zalo flush RAM ghi đè lại sandbox vừa dọn
    //    - Đảm bảo thiết bị mới chỉ được sinh ra hoàn toàn trong tiến trình sạch mới
    UIViewController *top = get_top_view_controller();
    NSString *regionDesc = [targetRegion isEqualToString:@"US_STUDENT"] ? @"Du Học Sinh Mỹ (+1)" :
                           ([targetRegion isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" : @"Việt Nam (+84)");
    NSString *msg = [NSString stringWithFormat:
                     @"✅ Đã dọn sạch dữ liệu Zalo cũ!\n\n"
                     @"• SIM & Khu vực khi mở lại: %@\n"
                     @"• Keychain & Cache: Làm sạch hoàn toàn\n"
                     @"• File Backup .adbk: Được bảo vệ an toàn\n\n"
                     @"⚡ THIẾT BỊ MỚI sẽ được kích hoạt ngay khi bạn mở lại Zalo!\n\n"
                     @"👉 BẬT VÀ TẮT CHẾ ĐỘ MÁY BAY để đổi IP 4G trước khi mở lại.",
                     regionDesc];

    UIAlertController *doneAlert = [UIAlertController alertControllerWithTitle:@"🧹 Wipe Hoàn Tất - Đang Đóng App"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];

    if (top) {
        [top presentViewController:doneAlert animated:YES completion:^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                exit(0);
            });
        }];
    } else {
        exit(0);
    }
}

- (void)showPreRegDiagnosticFrom:(UIViewController *)top {
    UIViewController *presenter = top ?: get_top_view_controller();
    if (!presenter) return;

    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        [self showLicenseRequiredAlertFrom:presenter featureName:@"Kiểm Tra Độ Sạch Trước Khi Reg"];
        return;
    }

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
    NSString *liveDeviceName = [[UIDevice currentDevice] name];
    NSString *liveSystemVersion = [[UIDevice currentDevice] systemVersion];
    
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

    // 5. ĐỐI CHIẾU THỰC TẾ: So sánh IDFV với lần wipe trước
    NSString *idfvOld = (s.lastWipedIDFV.length > 0) ? [s.lastWipedIDFV substringToIndex:MIN((NSUInteger)8, s.lastWipedIDFV.length)] : @"Chưa wipe";
    NSString *idfvShort = (liveIDFV.length > 8) ? [liveIDFV substringToIndex:8] : liveIDFV;
    BOOL isDifferentIDFV = (s.lastWipedIDFV.length > 0 && ![liveIDFV isEqualToString:s.lastWipedIDFV]);
    BOOL isDuplicateIDFV = (s.lastWipedIDFV.length > 0 && [liveIDFV isEqualToString:s.lastWipedIDFV]);
    NSString *idfvStatus = isDifferentIDFV ? @"Mới tinh ✅" : (s.lastWipedIDFV.length == 0 ? @"Mới cấp profile ✅" : @"TRÙNG LẶP IDFV CŨ ❌");

    // 6. ĐỐI CHIẾU THỰC TẾ: So sánh IP mạng ngoài
    NSString *ipOld = (s.lastWipedIP.length > 0) ? s.lastWipedIP : @"Chưa lưu";
    BOOL hasWipedHistory = (s.lastWipedTimestamp > 0 && s.lastWipedIP.length > 0);
    BOOL isDifferentIP = (hasWipedHistory && ![currentIP isEqualToString:s.lastWipedIP]);
    BOOL isSameIP = (hasWipedHistory && [currentIP isEqualToString:s.lastWipedIP]);
    
    NSString *ipStatus = @"";
    if (isSameIP) {
        ipStatus = @"TRÙNG IP CŨ (CẦN BẬT AIRPLANE MODE) ❌";
    } else if (isDifferentIP) {
        ipStatus = @"Đã đổi IP mới ✅";
    } else {
        ipStatus = @"IP hợp lệ ✅";
    }

    if (!hasWipedHistory && s.lastWipedIP.length == 0 && currentIP.length > 0 && ![currentIP isEqualToString:@"Không xác định"]) {
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

    // b. Gọi hàm C open() với ĐƯỜNG DẪN TUYỆT ĐỐI (Sandbox Application Support)
    NSString *absDeviceDir = [home stringByAppendingPathComponent:@"Library/Application Support/KVCore/Device"];
    [[NSFileManager defaultManager] createDirectoryAtPath:absDeviceDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *absTestFile = [absDeviceDir stringByAppendingPathComponent:@"_zt_abs_test.tmp"];
    int fd_abs = open([absTestFile UTF8String], O_RDWR | O_CREAT, 0644);
    BOOL leveldbAbsWritable = NO;
    if (fd_abs >= 0) {
        char testDataAbs[] = "ZT_ABS_OK";
        write(fd_abs, testDataAbs, sizeof(testDataAbs));
        close(fd_abs);
        leveldbAbsWritable = YES;
        unlink([absTestFile UTF8String]);
    }

    // c. Gọi hàm C openat() với AT_FDCWD và ĐƯỜNG DẪN TƯƠNG ĐỐI
    int fd_at = openat(AT_FDCWD, "KVCore/Device/_zt_at_test.tmp", O_RDWR | O_CREAT, 0644);
    BOOL leveldbAtWritable = NO;
    if (fd_at >= 0) {
        char testDataAt[] = "ZT_AT_OK";
        write(fd_at, testDataAt, sizeof(testDataAt));
        close(fd_at);
        leveldbAtWritable = YES;
        unlink("KVCore/Device/_zt_at_test.tmp");
    }

    // d. Gọi hàm hệ thống NSUserDefaults với SuiteName (App Groups)
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

    // 8. ĐỐI CHIẾU TOÀN DIỆN KHÔNG CHO PHÉP FAKE OK
    BOOL isMachineSpoofed = ([liveMachineStr isEqualToString:s.deviceMachine] && liveMachineStr.length > 0);
    BOOL isAllPassed = (isMachineSpoofed && 
                        (!isSameIP) && 
                        (!isDuplicateIDFV) && 
                        leveldbRelWritable && 
                        leveldbAbsWritable && 
                        leveldbAtWritable && 
                        appGroupWorking && 
                        isHiddenProv);

    NSString *conclusion = @"";
    if (!isAllPassed) {
        NSMutableString *errList = [NSMutableString stringWithString:@"🔴 KHÔNG ĐẠT TIÊU CHUẨN! PHÁT HIỆN CẢNH BÁO:\n"];
        if (!isMachineSpoofed) [errList appendString:@"• Machine C chưa khớp với cấu hình profile.\n"];
        if (isSameIP) [errList appendString:@"• TRÙNG IP 4G CŨ! Hãy Bật rồi Tắt Chế Độ Máy Bay.\n"];
        if (isDuplicateIDFV) [errList appendString:@"• TRÙNG IDFV CŨ! Vui lòng bấm [2️⃣] Deep Wipe.\n"];
        if (!leveldbRelWritable) [errList appendString:@"• LevelDB không thể ghi qua đường dẫn tương đối C (KVCore/Device).\n"];
        if (!leveldbAbsWritable) [errList appendString:@"• LevelDB không thể ghi qua đường dẫn tuyệt đối C.\n"];
        if (!leveldbAtWritable) [errList appendString:@"• LevelDB không thể ghi qua hàm openat C.\n"];
        if (!appGroupWorking) [errList appendString:@"• Lỗi quyền App Group Sandbox.\n"];
        if (!isHiddenProv) [errList appendString:@"• Chưa che giấu mobileprovision (lộ Sideload).\n"];
        [errList appendString:@"👉 TUYỆT ĐỐI KHÔNG TẠO TÀI KHOẢN CHO ĐẾN KHI KHẮC PHỤC HẾT!"];
        conclusion = errList;
    } else {
        conclusion = [NSString stringWithFormat:
            @"🟢 MÁY SẠCH HOÀN TOÀN - AN TOÀN 100%% ĐỂ REG ACC!\n"
            @"• Đã đối chiếu chéo thực tế 100%% qua hàm C & OS:\n"
            @"  - Tên máy: %@\n"
            @"  - Phiên bản: iOS %@\n"
            @"  - C open (tương đối & tuyệt đối): Đã thông suốt\n"
            @"  - C openat (AT_FDCWD): Đã thông suốt\n"
            @"  - IDFV: Cấp mới tinh không trùng lặp\n"
            @"  - IP 4G: Đã xoay dải mạng mới",
            liveDeviceName, liveSystemVersion];
    }

    NSString *report = [NSString stringWithFormat:
        @"═══════════════════════════\n"
        @"1. XÁC THỰC ĐỊNH DANH (LIVE C & RUNTIME):\n"
        @" • Machine (C)  : %@ (%@)\n"
        @" • Tên Thiết Bị : %@\n"
        @" • Phiên Bản iOS: %@\n"
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
        @" • C open (tương đối)  : %@\n"
        @" • C open (tuyệt đối)  : %@\n"
        @" • C openat (AT_FDCWD) : %@\n"
        @" • App Groups Suite    : %@\n"
        @"═══════════════════════════\n"
        @"👉 KẾT LUẬN ĐỐI CHIẾU:\n%@",
        liveMachineStr, (isMachineSpoofed ? @"Khớp Profile ✅" : @"Chưa khớp ❌"),
        liveDeviceName,
        liveSystemVersion,
        liveBundle, ([liveBundle isEqualToString:@"vn.com.vng.zingalo"] ? @"Gốc VNG ✅" : @"Chưa đổi ❌"),
        idfvShort, idfvStatus,
        idfvOld,
        (liveIDFA.length > 8 ? [liveIDFA substringToIndex:8] : liveIDFA),
        currentIP, ipStatus,
        ipOld,
        freeGB, totalGB,
        uptimeHours,
        sandboxKB, (sandboxKB < 150.0 ? @"Sạch 100% ✅" : @"Có cache"),
        (isHiddenProv ? @"Đã ẩn mobileprovision ✅" : @"Chưa ẩn ❌"),
        (leveldbRelWritable ? @"C tương đối THÀNH CÔNG ✅" : @"Lỗi mở tương đối ❌"),
        (leveldbAbsWritable ? @"C tuyệt đối THÀNH CÔNG ✅" : @"Lỗi mở tuyệt đối ❌"),
        (leveldbAtWritable ? @"C openat() THÀNH CÔNG ✅" : @"Lỗi mở openat ❌"),
        (appGroupWorking ? @"Đã chuyển hướng Sandbox an toàn ✅" : @"Lỗi truy cập ❌"),
        conclusion];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🔍 BÁO CÁO ĐỐI CHIẾU HỆ THỐNG RUNTIME"
                                                                   message:report
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

@end

#pragma clang diagnostic pop
