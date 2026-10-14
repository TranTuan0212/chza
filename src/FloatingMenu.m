#import "FloatingMenu.h"
#import "Config.h"
#import "SecurityManager.h"
#import "ZTDiagnosticViewController.h"
#import <objc/runtime.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#if __has_feature(modules)
@import Darwin.POSIX.sys.stat;
#endif
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <CFNetwork/CFNetwork.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <dlfcn.h>

// Hàm triệt tiêu toàn bộ socket và kết nối TCP đang mở
static void sever_all_network_sockets_immediately(void) {
    [[NSURLSession sharedSession] invalidateAndCancel];
    [[NSURLCache sharedURLCache] removeAllCachedResponses];

    int maxFd = getdtablesize();
    if (maxFd > 1024) maxFd = 1024;
    for (int fd = 3; fd < maxFd; fd++) {
        struct sockaddr_storage ss;
        socklen_t sslen = sizeof(ss);
        if (getpeername(fd, (struct sockaddr *)&ss, &sslen) == 0) {
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
    }
}

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
        if ([lower hasSuffix:@".adbk"] ||
            [lower containsString:@"appsmanager"] ||
            [lower containsString:@"com.sonhu.zalotweak"] ||
            [lower isEqualToString:@"zaloaudit.log"] ||
            [lower isEqualToString:@"zalotraffic.har"] ||
            [lower hasSuffix:@".db-wal"] ||
            [lower hasSuffix:@".db-shm"]) {
            continue;
        }
        NSString *full = [path stringByAppendingPathComponent:sub];
        NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
        total += [attrs fileSize];
    }
    return total;
}

static void fetch_public_ip(void (^completion)(NSString *ip)) {
    uint64_t now = (uint64_t)[[NSDate date] timeIntervalSince1970];
    NSString *urlStr = [NSString stringWithFormat:@"https://api.ipify.org?format=text&_t=%llu", (unsigned long long)now];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.URLCache = nil;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
    config.timeoutIntervalForRequest = 6.0;
    config.timeoutIntervalForResource = 6.0;
    config.HTTPShouldSetCookies = NO;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]
                                                       cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                   timeoutInterval:6.0];
    [req setValue:@"close" forHTTPHeaderField:@"Connection"];
    [req setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];
    [req setValue:@"no-cache" forHTTPHeaderField:@"Pragma"];

    [[session dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        NSString *ipStr = nil;
        if (data && !error) {
            ipStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            ipStr = [ipStr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        }
        if (ipStr.length >= 7 && ([ipStr containsString:@"."] || [ipStr containsString:@":"])) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [session finishTasksAndInvalidate];
                completion(ipStr);
            });
            return;
        }

        // Nguồn dự phòng nếu api.ipify.org bị nghẽn do proxy
        NSMutableURLRequest *backupReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"https://icanhazip.com?_t=%llu", (unsigned long long)now]]
                                                                 cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                             timeoutInterval:6.0];
        [backupReq setValue:@"close" forHTTPHeaderField:@"Connection"];
        [backupReq setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];

        [[session dataTaskWithRequest:backupReq completionHandler:^(NSData * _Nullable bdata, NSURLResponse * _Nullable bresp, NSError * _Nullable berr) {
            NSString *bip = nil;
            if (bdata && !berr) {
                bip = [[NSString alloc] initWithData:bdata encoding:NSUTF8StringEncoding];
                bip = [bip stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                [session finishTasksAndInvalidate];
                completion((bip.length >= 7 && ([bip containsString:@"."] || [bip containsString:@":"])) ? bip : @"Không xác định");
            });
        }] resume];
    }] resume];
}

UIViewController *ZTGetTopViewController(void) {
    return get_top_view_controller();
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
    NSTimeInterval _lastDragEndTime;
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
        _lastDragEndTime = [[NSDate date] timeIntervalSince1970];
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
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - _lastDragEndTime < 0.35) return;
    static NSTimeInterval s_lastButtonTap = 0;
    if (now - s_lastButtonTap < 0.6) return;
    s_lastButtonTap = now;
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
    // Chống dội click đúp / chống giật nhảy 2 lần
    static NSTimeInterval s_lastMenuPresent = 0;
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - s_lastMenuPresent < 0.6) return;

    UIViewController *top = presentingVC ?: get_top_view_controller();
    if (!top) return;
    if ([top isKindOfClass:[UIAlertController class]]) return;
    if (top.presentedViewController != nil) return;

    s_lastMenuPresent = now;

    ZTSettings *settings = [ZTSettings sharedSettings];
    BOOL isLicensed = [[ZTSecurityManager sharedManager] isLicenseValid];
    NSString *licStatusText = [[ZTSecurityManager sharedManager] getLicenseStatusText];

    NSString *title = [NSString stringWithFormat:@"⚡ ZALOTWEAK | %@", licStatusText];
    NSString *guidance;
    if (!isLicensed) {
        if (settings.hasConfiguredProfile) {
            guidance = @"⚠️ BẢN QUYỀN ĐÃ HẾT HẠN!\nProfile máy ảo hiện tại ĐÃ ĐƯỢC ĐÓNG BĂNG để bảo vệ tài khoản Zalo của bạn.\nCác chức năng Wipe và Đổi máy bị tạm khóa cho đến khi gia hạn.";
        } else {
            guidance = @"⚠️ BƯỚC ĐẦU TIÊN: Bấm nút Bản Quyền bên dưới để KÍCH HOẠT KEY!\nHiện tại app đang dùng máy thật. Hãy kích hoạt Key và bấm [1️⃣] để bắt đầu giả lập máy mới.";
        }
    } else {
        guidance = @"📋 QUY TRÌNH REG ACC CHUẨN:\n"
                   @"▶️ Bước 1: Bấm [1️⃣ Deep Wipe Sạch & Cấp Máy Mới] (Chọn SIM -> App tự dọn sạch & thoát)\n"
                   @"▶️ Bước 2: Bật/Tắt Chế Độ Máy Bay trong 5 giây để đổi IP 4G -> Mở lại Zalo\n"
                   @"▶️ Bước 3: Bấm [2️⃣ Kiểm Tra Độ Sạch Trước Khi Reg] -> Thấy 🟢 là Reg acc an toàn!";
    }

    NSString *deviceDisplay;
    if (settings.hasConfiguredProfile) {
        deviceDisplay = [NSString stringWithFormat:@"%@ | IDFV: %@...", settings.deviceMachine, [settings.spoofedIDFV substringToIndex:MIN((NSUInteger)8, settings.spoofedIDFV.length)]];
    } else {
        deviceDisplay = @"(Chưa cấp máy ảo - Đang dùng máy thật)";
    }

    NSString *message = [NSString stringWithFormat:@"%@\n\n📱 Thiết Bị Giả Lập: %@", guidance, deviceDisplay];

    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    // Nút 0: Hiển thị Hạn Bản Quyền ngay ngoài Menu chính
    NSString *licButtonTitle = [NSString stringWithFormat:@"🛡️ HẠN KEY: %@", licStatusText];
    [sheet addAction:[UIAlertAction actionWithTitle:licButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showLicenseMenuFrom:top];
    }]];

    // Nút 1: Deep Wipe & Cấp Máy Mới (Chọn SIM 1 chạm)
    NSString *wipeButtonTitle = isLicensed ? @"🚀 [1️⃣] Deep Wipe Sạch & Cấp Máy Mới (Chọn SIM)" : @"🔒 [1️⃣] Deep Wipe Sạch & Cấp Máy Mới (Cần Key)";
    [sheet addAction:[UIAlertAction actionWithTitle:wipeButtonTitle
                                             style:UIAlertActionStyleDestructive
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Deep Wipe & Cấp Máy Mới"];
            return;
        }
        [self confirmDeepWipeFrom:top];
    }]];

    // Nút 2: Kiểm Tra Độ Sạch Trước Khi Reg
    NSString *diagButtonTitle = isLicensed ? @"🔍 [2️⃣] Kiểm Tra Độ Sạch Trước Khi Reg (Checklist)" : @"🔒 [2️⃣] Kiểm Tra Độ Sạch Toàn Diện (Cần Key)";
    [sheet addAction:[UIAlertAction actionWithTitle:diagButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Kiểm Tra Độ Sạch Trước Khi Reg"];
            return;
        }
        [self showPreRegDiagnosticFrom:top];
    }]];

    // Nút 3: Cài Đặt Nâng Cao & Bản Quyền
    NSString *advButtonTitle = isLicensed ? @"⚙️ [3️⃣] Cài Đặt Nâng Cao & Quản Lý Profile" : @"🛡️ [3️⃣] KÍCH HOẠT BẢN QUYỀN & CÀI ĐẶT";
    [sheet addAction:[UIAlertAction actionWithTitle:advButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        [self showAdvancedSettingsFrom:top];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];

    // Hỗ trợ iPad popover
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        sheet.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }

    [top presentViewController:sheet animated:YES completion:nil];
}

- (void)showAdvancedSettingsFrom:(UIViewController *)top {
    UIViewController *presenter = top ?: get_top_view_controller();
    if (!presenter) return;

    BOOL isLicensed = [[ZTSecurityManager sharedManager] isLicenseValid];
    UIAlertController *advSheet = [UIAlertController alertControllerWithTitle:@"⚙️ CÀI ĐẶT NÂNG CAO & BẢN QUYỀN"
                                                                     message:@"Quản lý bản quyền DRM, xem chi tiết phần cứng và nhật ký kiểm toán hệ thống:"
                                                              preferredStyle:UIAlertControllerStyleActionSheet];

    // 1. Quản lý bản quyền
    NSString *licTitle = isLicensed ? @"🛡️ Quản Lý Bản Quyền (🟢 ĐÃ KÍCH HOẠT)" : @"🛡️ KÍCH HOẠT BẢN QUYỀN (Nhập Key)";
    [advSheet addAction:[UIAlertAction actionWithTitle:licTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self showLicenseMenuFrom:presenter];
    }]];

    // 2. Xem thông số máy ảo đang dùng
    [advSheet addAction:[UIAlertAction actionWithTitle:@"📱 Xem Chi Tiết Thông Số Máy Giả Lập" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self showHardwareSpecsFrom:presenter];
    }]];

    // 3. Nhật ký kiểm toán & HAR Inspector
    [advSheet addAction:[UIAlertAction actionWithTitle:@"📋 Nhật Ký Kiểm Toán (Audit Log & HAR Inspector)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self showAuditLogMenuFrom:presenter];
    }]];

    // 4. Tạm ẩn nút nổi
    [advSheet addAction:[UIAlertAction actionWithTitle:@"👁️ Tạm Ẩn Nút Nổi Trên Màn Hình" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [[ZTFloatingButton sharedButton] hide];
        UIAlertController *hint = [UIAlertController alertControllerWithTitle:@"Đã Ẩn Nút Nổi"
                                                                      message:@"Nút nổi đã được tạm ẩn.\nĐể hiện lại nút nổi, bạn chỉ cần bấm thoát ra màn hình chính rồi mở lại Zalo."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [hint addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
        [presenter presentViewController:hint animated:YES completion:nil];
    }]];

    [advSheet addAction:[UIAlertAction actionWithTitle:@"Quay Lại" style:UIAlertActionStyleCancel handler:nil]];

    if (advSheet.popoverPresentationController) {
        advSheet.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        advSheet.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }

    [presenter presentViewController:advSheet animated:YES completion:nil];
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
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Du Học Sinh Mỹ (+1).\n• SIM: %@ (US)\n• Tên máy: %@\n\n💡 MẸO: Hãy bật mạng 4G trước khi Reg để Zalo duyệt mượt 100%%.", s.carrierName, s.deviceName]
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
    
    [alert addAction:[UIAlertAction actionWithTitle:@"🌐 Xuất File Gói Tin Mạng (HAR)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
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
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🧹 CHỌN SIM & KHU VỰC THIẾT BỊ MỚI"
                                                                   message:@"Chọn khu vực SIM mong muốn cho thiết bị mới. Sau khi chọn, hệ thống sẽ dọn sạch toàn bộ dữ liệu Zalo cũ và tự động thoát app:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇻🇳 Việt Nam (+84) [Viettel / Vina / Mobi]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self startInAppDeepWipeSequenceWithRegion:@"VN" from:top];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Du Học Sinh Mỹ (+1) [T-Mobile / AT&T / Mint]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self startInAppDeepWipeSequenceWithRegion:@"US_STUDENT" from:top];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Hoa Kỳ (+1) [Verizon / AT&T / T-Mobile]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self startInAppDeepWipeSequenceWithRegion:@"US" from:top];
    }]];

    NSString *keepTitle = [NSString stringWithFormat:@"🔄 Giữ Vùng Hiện Tại (%@)", s.regionMode ?: @"VN"];
    [alert addAction:[UIAlertAction actionWithTitle:keepTitle style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [self startInAppDeepWipeSequenceWithRegion:s.regionMode ?: @"VN" from:top];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Hủy Bỏ" style:UIAlertActionStyleCancel handler:nil]];

    if (alert.popoverPresentationController) {
        alert.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        alert.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }

    [top presentViewController:alert animated:YES completion:nil];
}

- (void)startInAppDeepWipeSequenceWithRegion:(NSString *)targetRegion from:(UIViewController *)top {
    UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"🧹 Đang Dọn Dẹp Dữ Liệu..."
                                                                   message:@"Đang ghi nhận IP mạng 4G trước khi wipe và làm sạch sandbox..."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [top presentViewController:loading animated:YES completion:^{
        fetch_public_ip(^(NSString *currentIP) {
            [loading dismissViewControllerAnimated:YES completion:^{
                [self performInAppDeepWipeWithRegion:targetRegion currentIP:currentIP];
            }];
        });
    }];
}

- (void)performInAppDeepWipe {
    [self performInAppDeepWipeWithRegion:[ZTSettings sharedSettings].regionMode ?: @"VN" currentIP:nil];
}

- (void)performInAppDeepWipeWithRegion:(NSString *)targetRegion {
    [self performInAppDeepWipeWithRegion:targetRegion currentIP:nil];
}

- (void)performInAppDeepWipeWithRegion:(NSString *)targetRegion currentIP:(NSString *)currentIP {
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

    // 3. Xóa sạch dữ liệu in-memory của NSUserDefaults các App Suites để ngăn cfprefsd ghi ngược ra đĩa
    NSArray *suitesToPurge = @[
        @"group.vn.com.vng.zingalo",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo",
        @"com.zing.zalo.chatMigrateStore",
        @"vn.com.vng.zingalo.zalosdk",
        @"com.zing.zalo",
        @"vn.com.vng.zingalo",
        [[NSBundle mainBundle] bundleIdentifier] ?: @""
    ];
    for (NSString *suite in suitesToPurge) {
        if (suite.length == 0) continue;
        NSUserDefaults *ud = [[NSUserDefaults alloc] initWithSuiteName:suite];
        if (ud) {
            NSDictionary *dict = [ud dictionaryRepresentation];
            for (NSString *k in dict.allKeys) {
                [ud removeObjectForKey:k];
            }
            [ud synchronize];
        }
    }
    NSUserDefaults *stdUD = [NSUserDefaults standardUserDefaults];
    NSDictionary *stdDict = [stdUD dictionaryRepresentation];
    for (NSString *k in stdDict.allKeys) {
        [stdUD removeObjectForKey:k];
    }
    [stdUD synchronize];
    
    // Hàm xóa nội bộ có bảo vệ .adbk, ZaloAudit.log, ZaloTraffic.har và tất cả cấu hình/bản quyền tweak
    void (^wipeDirSafely)(NSString *) = ^(NSString *dirPath) {
        NSArray *items = [fm contentsOfDirectoryAtPath:dirPath error:nil];
        for (NSString *item in items) {
            NSString *lower = [item lowercaseString];
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
    
    // 4. Quét dọn các thư mục dữ liệu trong Sandbox
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *libDir = [home stringByAppendingPathComponent:@"Library"];
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];
    
    wipeDirSafely(docDir);
    wipeDirSafely(tmpDir);
    
    // Quét dọn toàn bộ các thư mục trong Library (WebKit, Cookies, HTTPStorages, Caches, Application Support...)
    NSArray *libItems = [fm contentsOfDirectoryAtPath:libDir error:nil];
    for (NSString *item in libItems) {
        NSString *lower = [item lowercaseString];
        if ([lower containsString:@"com.sonhu.zalotweak"]) continue;
        NSString *subDir = [libDir stringByAppendingPathComponent:item];
        wipeDirSafely(subDir);
    }

    // 4.1. Quét dọn Shared App Groups (nếu có quyền truy cập nhóm)
    NSArray *groupNames = @[@"group.vn.com.vng.zingalo", @"group.com.vng.zalo", @"group.com.zing.zalo"];
    for (NSString *grp in groupNames) {
        NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:grp];
        if (groupURL) {
            NSString *groupPath = [groupURL path];
            wipeDirSafely(groupPath);
            NSString *grpLib = [groupPath stringByAppendingPathComponent:@"Library"];
            [fm createDirectoryAtPath:[grpLib stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
            [fm createDirectoryAtPath:[grpLib stringByAppendingPathComponent:@"Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
            [fm createDirectoryAtPath:[grpLib stringByAppendingPathComponent:@"Application Support"] withIntermediateDirectories:YES attributes:nil error:nil];
        }
    }
    
    // Tái tạo thư mục sạch để Zalo không bị lỗi I/O khi khởi động lại
    [fm createDirectoryAtPath:docDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Application Support/KVCore/Device"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
    
    // 5. Đánh dấu Cold-Boot: Lưu khu vực SIM đã chọn, IP wipe và cờ needsNewProfile + needsSandboxPurge
    ZTSettings *settings = [ZTSettings sharedSettings];
    settings.lastWipedIDFV = settings.spoofedIDFV;
    if (currentIP.length > 0 && ![currentIP isEqualToString:@"Không xác định"]) {
        settings.lastWipedIP = currentIP;
    }
    settings.lastWipedTimestamp = (uint64_t)[[NSDate date] timeIntervalSince1970];
    settings.regionMode = targetRegion ?: @"VN";
    settings.needsNewProfile = YES;
    settings.needsSandboxPurge = YES;
    BOOL isJB = NO;
#if defined(THEOS_PACKAGE_SCHEME_ROOTHIDE) || defined(THEOS_PACKAGE_SCHEME_ROOTLESS)
    isJB = YES;
#endif
    if (!isJB) {
        if (dlsym(RTLD_DEFAULT, "jbrand") != NULL ||
            dlsym(RTLD_DEFAULT, "jbroot") != NULL ||
            dlsym(RTLD_DEFAULT, "roothide_check_path") != NULL ||
            dlsym(RTLD_DEFAULT, "MSHookFunction") != NULL ||
            dlsym(RTLD_DEFAULT, "ellekit_hook_c_function") != NULL ||
            getenv("JB_ROOT_PATH") != NULL ||
            getenv("ROOTHIDE_JB_ROOT_PATH") != NULL ||
            [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
            isJB = YES;
        }
    }
    if (!isJB) {
        settings.showFloatingMenu = YES;
    }
    [settings saveSettings];

    // 6. Ngắt kết nối mạng và toàn bộ session TCP ngay lập tức
    sever_all_network_sockets_immediately();

    // 7. Đóng app dứt khoát
    UIViewController *top = get_top_view_controller();
    NSString *regionDesc = [targetRegion isEqualToString:@"US_STUDENT"] ? @"Du Học Sinh Mỹ (+1)" :
                           ([targetRegion isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" : @"Việt Nam (+84)");

    NSString *msg = [NSString stringWithFormat:
                     @"✅ ĐÃ DỌN SẠCH DỮ LIỆU ZALO CŨ!\n\n"
                     @"• SIM & Khu Vực: %@\n"
                     @"• Keychain & Cache: Làm sạch 100%%\n"
                     @"• Socket & TCP: Đã ngắt kết nối tuyệt đối\n"
                     @"• File Backup .adbk: Được bảo vệ an toàn\n\n"
                     @"✈️ BƯỚC TIẾP THEO:\n"
                     @"Bật Chế Độ Máy Bay trong 5 giây rồi tắt đi để làm mới IP 4G, sau đó mở lại Zalo!",
                     regionDesc];

    UIAlertController *doneAlert = [UIAlertController alertControllerWithTitle:@"🧹 Wipe Xong - Đang Thoát Zalo"
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
                                                                     message:@"Đang truy vấn IP mạng 4G và rà soát độ sạch của hệ thống..."
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [presenter presentViewController:loading animated:YES completion:^{
        fetch_public_ip(^(NSString *currentIP) {
            [loading dismissViewControllerAnimated:YES completion:^{
                dispatch_async(dispatch_get_main_queue(), ^{
                    UIViewController *p = get_top_view_controller() ?: presenter;
                    ZTDiagnosticInfo *info = [self collectDiagnosticInfoWithIP:currentIP];
                    [ZTDiagnosticViewController presentFrom:p info:info];
                });
            }];
        });
    }];
}

- (ZTDiagnosticInfo *)collectDiagnosticInfoWithIP:(NSString *)currentIP {
    ZTSettings *s = [ZTSettings sharedSettings];
    ZTDiagnosticInfo *info = [[ZTDiagnosticInfo alloc] init];

    info.hasConfiguredProfile = s.hasConfiguredProfile;
    info.currentIP = currentIP ?: @"Không xác định";
    info.lastWipedIP = s.lastWipedIP;
    info.lastWipedIDFV = s.lastWipedIDFV;

    // Đọc TRỰC TIẾP TỪ HỆ THỐNG RUNTIME QUA HÀM C & OBJECTIVE-C
    char liveMachineBuf[64] = {0};
    size_t mlen = sizeof(liveMachineBuf);
    sysctlbyname("hw.machine", liveMachineBuf, &mlen, NULL, 0);
    info.deviceMachine = (strlen(liveMachineBuf) > 0) ? [NSString stringWithUTF8String:liveMachineBuf] : s.deviceMachine;

    info.deviceName = [[UIDevice currentDevice] name];
    info.iosVersion = [[UIDevice currentDevice] systemVersion];
    info.bundleId = [[NSBundle mainBundle] bundleIdentifier];

    if (!s.hasConfiguredProfile) {
        info.currentIDFV = @"Chưa cấp (Cần Wipe)";
        info.serial = @"";
        info.wifiMAC = @"";
    } else {
        info.currentIDFV = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
        info.serial = s.spoofedSerial;
        info.wifiMAC = s.spoofedWifiMAC;
    }

    info.idfa = @"00000000-0000-0000-0000-000000000000";

    NSString *regionDesc = [s.regionMode isEqualToString:@"US_STUDENT"] ? @"Du Học Sinh Mỹ (+1)" :
                           ([s.regionMode isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" : @"Việt Nam (+84)");
    info.regionName = regionDesc;
    info.carrierName = s.carrierName ?: @"Viettel";
    info.carrierMCC = s.carrierMCC ?: @"452";
    info.carrierMNC = s.carrierMNC ?: @"04";

    // Đo dung lượng Sandbox
    NSString *home = NSHomeDirectory();
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *cacheDir = [home stringByAppendingPathComponent:@"Library/Caches"];
    uint64_t sandboxBytes = get_directory_size(docDir) + get_directory_size(cacheDir);
    info.sandboxKB = (double)sandboxBytes / 1024.0;

    // LevelDB POSIX test
    int fd_rel = open("KVCore/Device/_zt_rel_test.tmp", O_RDWR | O_CREAT, 0644);
    BOOL leveldbRelWritable = NO;
    if (fd_rel >= 0) {
        char testData[] = "ZT_LOCK_OK";
        write(fd_rel, testData, sizeof(testData));
        close(fd_rel);
        leveldbRelWritable = YES;
        unlink("KVCore/Device/_zt_rel_test.tmp");
    }

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

    int fd_at = openat(AT_FDCWD, "KVCore/Device/_zt_at_test.tmp", O_RDWR | O_CREAT, 0644);
    BOOL leveldbAtWritable = NO;
    if (fd_at >= 0) {
        char testDataAt[] = "ZT_AT_OK";
        write(fd_at, testDataAt, sizeof(testDataAt));
        close(fd_at);
        leveldbAtWritable = YES;
        unlink("KVCore/Device/_zt_at_test.tmp");
    }

    BOOL appGroupWorking = NO;
    @try {
        NSURL *grpURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.vn.com.vng.zingalo"];
        if (grpURL) {
            NSString *testFilePath = [grpURL.path stringByAppendingPathComponent:@"_zt_grp_test.tmp"];
            if ([@"ZT_GRP_OK" writeToFile:testFilePath atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
                appGroupWorking = YES;
                [[NSFileManager defaultManager] removeItemAtPath:testFilePath error:nil];
            }
        }
        if (!appGroupWorking) {
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
        }
    } @catch (NSException *e) {
        appGroupWorking = NO;
    }
    BOOL leveldbWritable = (leveldbRelWritable || leveldbAbsWritable || leveldbAtWritable);
    info.leveldbOK = (leveldbWritable && appGroupWorking);

    // Mobileprovision check
    NSString *provPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    info.isHiddenProv = (provPath == nil || ![[NSFileManager defaultManager] fileExistsAtPath:provPath]);

    // Disk space & uptime
    NSDictionary *fsAttrs = [[NSFileManager defaultManager] attributesOfFileSystemForPath:home error:nil];
    unsigned long long liveDiskFree = [fsAttrs[NSFileSystemFreeSize] unsignedLongLongValue];
    unsigned long long liveDiskTotal = [fsAttrs[NSFileSystemSize] unsignedLongLongValue];
    info.diskFreeGB = (double)liveDiskFree / (1000.0 * 1000.0 * 1000.0);
    info.diskTotalGB = (double)liveDiskTotal / (1000.0 * 1000.0 * 1000.0);
    info.uptimeHours = (uint64_t)([[NSProcessInfo processInfo] systemUptime] / 3600.0);

    info.isLicensed = [[ZTSecurityManager sharedManager] isLicenseValid];
    info.licenseStatusText = [[ZTSecurityManager sharedManager] getLicenseStatusText];

    // 1. Mã device_id phần cứng (Zalo Hardware Fingerprint từ st_birthtimespec)
    struct stat st_hw;
    memset(&st_hw, 0, sizeof(st_hw));
    if (stat("/var/mobile", &st_hw) == 0 || (home && stat([home UTF8String], &st_hw) == 0)) {
        uint64_t birthMs = ((uint64_t)st_hw.st_birthtimespec.tv_sec) * 1000ULL;
        info.hardwareDeviceId = [NSString stringWithFormat:@"%llu-0-0", birthMs];
        
        BOOL isStaticHardware = (birthMs == 1753442559000ULL || birthMs == 1777525794000ULL);
        if (s.hasConfiguredProfile && s.bootTimeSec > 0) {
            uint64_t expectedMs = (s.bootTimeSec - 864000ULL) * 1000ULL;
            info.deviceIdPassed = (!isStaticHardware && (birthMs == expectedMs || (birthMs > 0 && !isStaticHardware)));
        } else {
            info.deviceIdPassed = (!isStaticHardware && birthMs > 0 && s.hasConfiguredProfile);
        }
    } else {
        info.hardwareDeviceId = @"Chưa cấp (Cần Wipe)";
        info.deviceIdPassed = NO;
    }

    // 2. Tập lệnh vi kiến trúc CPU (ARM Features Radar)
    int f_aes = 0, f_sha1 = 0, f_sha256 = 0, f_fp16 = 0;
    size_t f_sz = sizeof(int);
    sysctlbyname("hw.optional.arm.FEAT_AES", &f_aes, &f_sz, NULL, 0);
    sysctlbyname("hw.optional.arm.FEAT_SHA1", &f_sha1, &f_sz, NULL, 0);
    sysctlbyname("hw.optional.arm.FEAT_SHA256", &f_sha256, &f_sz, NULL, 0);
    sysctlbyname("hw.optional.arm.FEAT_FP16", &f_fp16, &f_sz, NULL, 0);

    info.armFeaturesSummary = [NSString stringWithFormat:@"AES:%d SHA1:%d SHA256:%d FP16:%d", f_aes, f_sha1, f_sha256, f_fp16];
    info.armCpuPassed = (f_aes == 1 && f_sha1 == 1 && f_sha256 == 1);

    // 3. Độ phân giải màn hình chuẩn Apple Specs (Chống hybrid 780x1688)
    UIScreen *screen = [UIScreen mainScreen];
    CGRect screenBounds = [screen bounds];
    CGFloat screenScale = [screen scale];
    CGFloat realWidth = screenBounds.size.width * screenScale;
    CGFloat realHeight = screenBounds.size.height * screenScale;
    info.screenResolutionText = [NSString stringWithFormat:@"%.0f × %.0f (@%.0fx)", realWidth, realHeight, screenScale];

    BOOL isStandardRes = NO;
    if ((realWidth == 750 && realHeight == 1334) ||
        (realWidth == 1080 && realHeight == 1920) ||
        (realWidth == 1242 && realHeight == 2208) ||
        (realWidth == 1125 && realHeight == 2436) ||
        (realWidth == 828 && realHeight == 1792) ||
        (realWidth == 1242 && realHeight == 2688) ||
        (realWidth == 1080 && realHeight == 2340) ||
        (realWidth == 1170 && realHeight == 2532) ||
        (realWidth == 1284 && realHeight == 2778) ||
        (realWidth == 1179 && realHeight == 2556) ||
        (realWidth == 1290 && realHeight == 2796)) {
        isStandardRes = YES;
    }
    if (s.hasConfiguredProfile && s.screenWidth > 0 && s.screenHeight > 0) {
        CGFloat expectedW = s.screenWidth * (s.screenScale > 0 ? s.screenScale : screenScale);
        CGFloat expectedH = s.screenHeight * (s.screenScale > 0 ? s.screenScale : screenScale);
        BOOL matchesProfile = (fabs(realWidth - expectedW) < 2.0 && fabs(realHeight - expectedH) < 2.0);
        info.screenResolutionPassed = (isStandardRes && matchesProfile);
    } else {
        info.screenResolutionPassed = isStandardRes;
    }

    // 4. Thời gian cài đặt ứng dụng (App Install Time / Creation Date)
    NSDate *installDate = nil;
    if (home) {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:home error:nil];
        installDate = [attrs fileCreationDate];
    }
    if (!installDate && docDir) {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:docDir error:nil];
        installDate = [attrs fileCreationDate];
    }
    if (installDate) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"yyyy-MM-dd HH:mm"];
        info.installTimeText = [df stringFromDate:installDate];
        if (s.hasConfiguredProfile && s.bootTimeSec > 0) {
            NSTimeInterval diff = fabs([installDate timeIntervalSince1970] - (NSTimeInterval)(s.bootTimeSec - 864000));
            info.installTimePassed = (diff < 3600.0 * 24.0);
        } else {
            info.installTimePassed = s.hasConfiguredProfile;
        }
    } else {
        info.installTimeText = @"Mới cấp theo Profile";
        info.installTimePassed = s.hasConfiguredProfile;
    }

    // 5. Phân vùng Keychain & Môi trường thực thi
    info.keychainIsolated = s.hasConfiguredProfile && (s.profileId.length > 0);

#if defined(THEOS_PACKAGE_SCHEME_ROOTHIDE)
    info.runtimeEnvDesc = @"🛡️ Roothide (DEB)";
#elif defined(THEOS_PACKAGE_SCHEME_ROOTLESS)
    info.runtimeEnvDesc = @"⚡ Rootless (DEB)";
#else
    if (dlsym(RTLD_DEFAULT, "jbrand") != NULL ||
        dlsym(RTLD_DEFAULT, "jbroot") != NULL ||
        dlsym(RTLD_DEFAULT, "roothide_check_path") != NULL) {
        info.runtimeEnvDesc = @"🛡️ Roothide (DEB)";
    } else {
        info.runtimeEnvDesc = @"🟢 An toàn (Đang tiêm dylib)";
    }
#endif

    // Cập nhật lastWipedIP nếu chưa có và ĐÃ CÓ profile đã cấu hình
    if (s.hasConfiguredProfile && s.lastWipedIP.length == 0 && currentIP.length > 0 && ![currentIP isEqualToString:@"Không xác định"]) {
        s.lastWipedIP = currentIP;
        [s saveSettings];
    }

    return info;
}

@end

#pragma clang diagnostic pop
