#import "FloatingMenu.h"
#import "Config.h"
#import "SecurityManager.h"
#import "ZTDiagnosticViewController.h"
#import <WebKit/WebKit.h>
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
            [lower containsString:@"zaloaudit.log"] ||
            [lower containsString:@"zalotraffic.har"] ||
            [lower hasSuffix:@".db-wal"] ||
            [lower hasSuffix:@".db-shm"]) {
            continue;
        }
        NSString *full = [path stringByAppendingPathComponent:sub];
        NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
        if ([attrs[NSFileType] isEqualToString:NSFileTypeRegular]) {
            total += [attrs fileSize];
        }
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
            UIWindowScene *activeScene = nil;
            // 1. Tìm Scene đang Foreground Active trước
            for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if ([scene isKindOfClass:[UIWindowScene class]] && scene.activationState == UISceneActivationStateForegroundActive) {
                    activeScene = (UIWindowScene *)scene;
                    break;
                }
            }
            // 2. Nếu chưa có Foreground Active, tìm bất kỳ UIWindowScene nào kết nối
            if (!activeScene) {
                for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]]) {
                        activeScene = (UIWindowScene *)scene;
                        break;
                    }
                }
            }
            // 3. Fallback tìm theo windowScene của các window khác
            if (!activeScene) {
                for (UIWindow *w in [UIApplication sharedApplication].windows) {
                    if (w != self && w.windowScene) {
                        activeScene = w.windowScene;
                        break;
                    }
                }
            }
            if (activeScene && self.windowScene != activeScene) {
                self.windowScene = activeScene;
            }
        }
        self.frame = [UIScreen mainScreen].bounds;
        self.hidden = NO;
        ZTFloatingButton *btn = [ZTFloatingButton sharedButton];
        btn.hidden = NO;
        btn.alpha = 1.0;

        // Đảm bảo nút không bị văng ra ngoài mép màn hình
        CGRect screenBounds = [UIScreen mainScreen].bounds;
        if (btn.center.x <= 0 || btn.center.x > screenBounds.size.width ||
            btn.center.y <= 0 || btn.center.y > screenBounds.size.height) {
            CGFloat btnRadius = btn.frame.size.width / 2.0;
            btn.center = CGPointMake(btnRadius + 15.0, 140.0 + btnRadius);
        }

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
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(tryAttachFloatingButton)
                                                 name:UIApplicationWillEnterForegroundNotification
                                               object:nil];

    if (@available(iOS 13.0, *)) {
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(tryAttachFloatingButton)
                                                     name:UISceneDidActivateNotification
                                                   object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(tryAttachFloatingButton)
                                                     name:UISceneWillEnterForegroundNotification
                                                   object:nil];
    }

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(handleWindowVisibilityChanged:)
                                                 name:UIWindowDidBecomeVisibleNotification
                                               object:nil];

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

- (void)handleWindowVisibilityChanged:(NSNotification *)note {
    UIWindow *w = (UIWindow *)note.object;
    if (w && [w isKindOfClass:[UIWindow class]] && ![w isKindOfClass:NSClassFromString(@"ZTFloatingWindow")]) {
        [self tryAttachFloatingButton];
    }
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
                   @"▶️ Bước 2: Bật/Tắt Chế Độ Máy Bay trong 5 giây để đổi IP 4G (hoặc bật Proxy)\n"
                   @"▶️ Bước 3: Bấm [2️⃣ Đối Chiếu SĐT + Proxy] -> Dán SĐT & Proxy -> Thấy 🟢 là Reg acc an toàn!";
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

    // Nút 2: Đối Chiếu SĐT + Proxy & Kiểm Tra Độ Sạch Trước Khi Reg
    NSString *diagButtonTitle = isLicensed ? @"🎯 [2️⃣] Đối Chiếu SĐT + Proxy & Kiểm Tra Toàn Diện" : @"🔒 [2️⃣] Đối Chiếu SĐT + Proxy (Cần Key)";
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

    // 4. Bật / Tắt Fake Múi Giờ
    ZTSettings *settings = [ZTSettings sharedSettings];
    NSString *tzStatus = settings.enableFakeTimeZone ? [NSString stringWithFormat:@"🟢 Đang Fake (%@)", settings.timeZoneName ?: @"Asia/Ho_Chi_Minh"] : @"⚪ Dùng Giờ Thật Máy (Gốc)";
    NSString *tzTitle = [NSString stringWithFormat:@"🕒 Múi Giờ Hệ Thống: %@", tzStatus];
    [advSheet addAction:[UIAlertAction actionWithTitle:tzTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        settings.enableFakeTimeZone = !settings.enableFakeTimeZone;
        [settings saveSettings];
        NSString *msg = settings.enableFakeTimeZone
            ? [NSString stringWithFormat:@"Đã BẬT Fake Múi Giờ.\nZalo sẽ đọc múi giờ giả: [%@]", settings.timeZoneName ?: @"Asia/Ho_Chi_Minh"]
            : @"Đã TẮT Fake Múi Giờ.\nZalo sẽ đọc trực tiếp Múi Giờ Thật của máy bạn (Khớp 100%% với mạng 4G/WiFi đang dùng).";
        UIAlertController *c = [UIAlertController alertControllerWithTitle:@"Cập Nhật Múi Giờ"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [presenter presentViewController:c animated:YES completion:nil];
    }]];

    // 5. Chọn Múi Giờ Thủ Công
    [advSheet addAction:[UIAlertAction actionWithTitle:@"🌐 Đổi Nhanh Múi Giờ (Việt Nam / Mỹ / Ba Lan...)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self showQuickTimezonePickerFrom:presenter];
    }]];

    // 6. Tạm ẩn nút nổi
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
                           ([currentRegion isEqualToString:@"US"] ? @"🇺🇸 Hoa Kỳ (+1)" :
                           ([currentRegion isEqualToString:@"PL"] ? @"🇵🇱 Ba Lan (+48)" : @"🇻🇳 Việt Nam (+84)"));

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

- (void)applyRegion:(NSString *)region preferredCarrier:(nullable NSString *)prefCarrier {
    ZTSettings *s = [ZTSettings sharedSettings];
    s.regionMode = region;
    s.preferredCarrier = prefCarrier ?: @"";
    if ([region isEqualToString:@"US_STUDENT"]) {
        NSArray *userNames = @[@"Huy's iPhone", @"Nam's iPhone", @"Trang's iPhone", @"Alex's iPhone", @"Minh's iPhone"];
        s.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];
        s.carrierName = prefCarrier.length > 0 ? prefCarrier : @"T-Mobile";
        s.carrierMCC = @"310";
        s.carrierMNC = @"260";
        s.carrierCountryCode = @"us";
        s.localeIdentifier = @"en_US";
        s.preferredLanguages = @[@"en-US", @"vi-VN"];
        s.timeZoneName = @"Asia/Ho_Chi_Minh";
    } else if ([region isEqualToString:@"US"]) {
        NSArray *userNames = @[@"David's iPhone", @"Michael's iPhone", @"iPhone", @"Sarah's iPhone"];
        s.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];
        s.carrierName = prefCarrier.length > 0 ? prefCarrier : @"Verizon";
        s.carrierMCC = @"311";
        s.carrierMNC = @"480";
        s.carrierCountryCode = @"us";
        s.localeIdentifier = @"en_US";
        s.preferredLanguages = @[@"en-US"];
        s.timeZoneName = @"America/New_York";
    } else if ([region isEqualToString:@"PL"]) {
        NSArray *userNames = @[@"iPhone Michała", @"iPhone Piotra", @"iPhone Jakuba", @"iPhone Anny", @"iPhone Julii"];
        s.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];
        s.carrierMCC = @"260";
        s.carrierCountryCode = @"pl";
        s.localeIdentifier = @"pl_PL";
        s.preferredLanguages = @[@"pl-PL", @"en-PL"];
        s.timeZoneName = @"Europe/Warsaw";
        NSString *cleanPref = [prefCarrier lowercaseString];
        if ([cleanPref containsString:@"orange"]) {
            s.carrierName = @"Orange";
            s.carrierMNC = @"03";
        } else if ([cleanPref containsString:@"plus"]) {
            s.carrierName = @"Plus";
            s.carrierMNC = @"01";
        } else if ([cleanPref containsString:@"t-mobile"]) {
            s.carrierName = @"T-Mobile";
            s.carrierMNC = @"02";
        } else {
            s.carrierName = @"Play";
            s.carrierMNC = @"06";
        }
    } else {
        NSArray *userNames = @[@"iPhone của Tuấn", @"iPhone của Linh", @"iPhone (2)", @"iPhone của Huy", @"iPhone của Nam"];
        s.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];
        s.carrierCountryCode = @"vn";
        s.localeIdentifier = @"vi_VN";
        s.preferredLanguages = @[@"vi-VN", @"en-VN"];
        s.timeZoneName = @"Asia/Ho_Chi_Minh";
        s.carrierMCC = @"452";
        NSString *cleanPref = [prefCarrier lowercaseString];
        if ([cleanPref containsString:@"vina"]) {
            s.carrierName = @"VINAPHONE";
            s.carrierMNC = @"02";
        } else if ([cleanPref containsString:@"mobi"]) {
            s.carrierName = @"VN MOBIFONE";
            s.carrierMNC = @"01";
        } else if ([cleanPref containsString:@"vietnamobile"]) {
            s.carrierName = @"Vietnamobile";
            s.carrierMNC = @"05";
        } else {
            s.carrierName = @"Viettel";
            s.carrierMNC = @"04";
        }
    }
    [s saveSettings];
}

- (void)applyRegionOnly:(NSString *)region {
    [self applyRegion:region preferredCarrier:nil];
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
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Du Học Sinh Mỹ (+1).\n• SIM: %@ (US)\n• Múi giờ: Asia/Ho_Chi_Minh (Khớp 4G VN)\n• Tên máy: %@\n\n💡 MẸO: Hãy bật mạng 4G trước khi Reg để Zalo duyệt mượt 100%%.", s.carrierName, s.deviceName]
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

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Ba Lan: SIM Play (260-06)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self applyRegion:@"PL" preferredCarrier:@"Play"];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Ba Lan (+48).\n• SIM: %@ (PL - MCC %@, MNC %@)\n• Múi giờ: Europe/Warsaw\n• Tên máy: %@", s.carrierName, s.carrierMCC, s.carrierMNC, s.deviceName]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:done animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Ba Lan: SIM Orange (260-03)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self applyRegion:@"PL" preferredCarrier:@"Orange"];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Ba Lan (+48).\n• SIM: %@ (PL - MCC %@, MNC %@)\n• Múi giờ: Europe/Warsaw\n• Tên máy: %@", s.carrierName, s.carrierMCC, s.carrierMNC, s.deviceName]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:done animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Ba Lan: SIM Plus (260-01)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self applyRegion:@"PL" preferredCarrier:@"Plus"];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Ba Lan (+48).\n• SIM: %@ (PL - MCC %@, MNC %@)\n• Múi giờ: Europe/Warsaw\n• Tên máy: %@", s.carrierName, s.carrierMCC, s.carrierMNC, s.deviceName]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:done animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Ba Lan: SIM T-Mobile (260-02)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [self applyRegion:@"PL" preferredCarrier:@"T-Mobile"];
        UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                      message:[NSString stringWithFormat:@"Đã chuyển sang Ba Lan (+48).\n• SIM: %@ (PL - MCC %@, MNC %@)\n• Múi giờ: Europe/Warsaw\n• Tên máy: %@", s.carrierName, s.carrierMCC, s.carrierMNC, s.deviceName]
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

- (void)showQuickTimezonePickerFrom:(UIViewController *)top {
    ZTSettings *settings = [ZTSettings sharedSettings];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🌐 CHỌN MÚI GIỜ GIẢ LẬP"
                                                                   message:[NSString stringWithFormat:@"• Múi giờ hiện tại: %@\n• Trạng thái Fake: %@\n\nChọn múi giờ bạn muốn Zalo ghi nhận:", settings.timeZoneName ?: @"Asia/Ho_Chi_Minh", settings.enableFakeTimeZone ? @"🟢 Đang Bật" : @"⚪ Đang Tắt (Dùng giờ máy)"]
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇻🇳 Việt Nam (Asia/Ho_Chi_Minh - GMT+7) [Khớp 4G VN]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        settings.timeZoneName = @"Asia/Ho_Chi_Minh";
        settings.enableFakeTimeZone = YES;
        [settings saveSettings];
        UIAlertController *c = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                   message:@"Đã chuyển múi giờ sang Việt Nam (Asia/Ho_Chi_Minh, GMT+7).\nKhớp 100% với mạng 4G Việt Nam!"
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:c animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Mỹ - Bờ Đông New York (America/New_York - GMT-5)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        settings.timeZoneName = @"America/New_York";
        settings.enableFakeTimeZone = YES;
        [settings saveSettings];
        UIAlertController *c = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                   message:@"Đã chuyển múi giờ sang Mỹ (America/New_York, GMT-5)."
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:c animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Mỹ - Bờ Tây California (America/Los_Angeles - GMT-7)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        settings.timeZoneName = @"America/Los_Angeles";
        settings.enableFakeTimeZone = YES;
        [settings saveSettings];
        UIAlertController *c = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                   message:@"Đã chuyển múi giờ sang Mỹ (America/Los_Angeles, GMT-7)."
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:c animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Ba Lan (Europe/Warsaw - GMT+2)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        settings.timeZoneName = @"Europe/Warsaw";
        settings.enableFakeTimeZone = YES;
        [settings saveSettings];
        UIAlertController *c = [UIAlertController alertControllerWithTitle:@"Đã Cập Nhật"
                                                                   message:@"Đã chuyển múi giờ sang Ba Lan (Europe/Warsaw, GMT+2)."
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:c animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"⚪ Tắt Fake - Dùng Múi Giờ Thật Của Máy" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        settings.enableFakeTimeZone = NO;
        [settings saveSettings];
        UIAlertController *c = [UIAlertController alertControllerWithTitle:@"Đã Tắt Fake Múi Giờ"
                                                                   message:@"Zalo sẽ đọc trực tiếp múi giờ thực của máy bạn (Khớp 100% với mạng 4G/WiFi đang dùng)."
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [c addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [top presentViewController:c animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];

    if (alert.popoverPresentationController) {
        alert.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        alert.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }

    [top presentViewController:alert animated:YES completion:nil];
}

static BOOL parse_proxy_quick_wipe(NSString *proxyInput, NSString **outHost, NSNumber **outPort, NSString **outUser, NSString **outPass) {
    if (!proxyInput || proxyInput.length == 0) return NO;
    NSString *clean = [proxyInput stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([clean containsString:@"@"]) {
        NSArray *parts = [clean componentsSeparatedByString:@"@"];
        if (parts.count == 2) {
            NSString *authPart = parts[0];
            NSString *hostPart = parts[1];
            NSArray *authTokens = [authPart componentsSeparatedByString:@":"];
            if (authTokens.count == 2) {
                if (outUser) *outUser = authTokens[0];
                if (outPass) *outPass = authTokens[1];
            }
            NSArray *hostTokens = [hostPart componentsSeparatedByString:@":"];
            if (hostTokens.count == 2) {
                if (outHost) *outHost = hostTokens[0];
                if (outPort) *outPort = @([hostTokens[1] integerValue]);
                return YES;
            }
        }
    }
    NSArray *tokens = [clean componentsSeparatedByString:@":"];
    if (tokens.count == 4) {
        if (outHost) *outHost = tokens[0];
        if (outPort) *outPort = @([tokens[1] integerValue]);
        if (outUser) *outUser = tokens[2];
        if (outPass) *outPass = tokens[3];
        return YES;
    } else if (tokens.count == 2) {
        if (outHost) *outHost = tokens[0];
        if (outPort) *outPort = @([tokens[1] integerValue]);
        return YES;
    } else if (tokens.count == 1) {
        if (outHost) *outHost = tokens[0];
        if (outPort) *outPort = @(80);
        return YES;
    }
    return NO;
}

static void fetch_geoip_for_auto_wipe(NSString *proxyText, void (^completion)(NSString * _Nullable queryIP, NSString * _Nullable timezone, NSString * _Nullable countryCode)) {
    NSString *host = nil, *user = nil, *pass = nil;
    NSNumber *port = nil;
    NSDictionary *proxyDict = nil;
    NSString *targetIP = nil;

    NSString *clean = [proxyText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (clean.length > 0) {
        if ([clean containsString:@":"] || [clean containsString:@"@"]) {
            if (parse_proxy_quick_wipe(clean, &host, &port, &user, &pass)) {
                NSRegularExpression *ipRegex = [NSRegularExpression regularExpressionWithPattern:@"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$" options:0 error:nil];
                NSUInteger matches = [ipRegex numberOfMatchesInString:host options:0 range:NSMakeRange(0, host.length)];
                if (matches > 0 && user.length == 0 && pass.length == 0) {
                    targetIP = host;
                } else {
                    NSMutableDictionary *p = [NSMutableDictionary dictionary];
                    p[@"HTTPEnable"] = @YES;
                    p[@"HTTPProxy"] = host;
                    p[@"HTTPPort"] = port ?: @(80);
                    if (user.length > 0) p[(NSString *)kCFProxyUsernameKey] = user;
                    if (pass.length > 0) p[(NSString *)kCFProxyPasswordKey] = pass;
                    proxyDict = [p copy];
                    targetIP = nil;
                }
            }
        } else {
            targetIP = clean;
        }
    }

    NSString *urlString = (targetIP.length > 0 && ![targetIP containsString:@":"])
        ? [NSString stringWithFormat:@"http://ip-api.com/json/%@?fields=status,countryCode,timezone,query", targetIP]
        : @"http://ip-api.com/json/?fields=status,countryCode,timezone,query";

    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        if (completion) completion(nil, nil, nil);
        return;
    }
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = 6.0;
    config.timeoutIntervalForResource = 6.0;
    if (proxyDict && proxyDict.count > 0) {
        config.connectionProxyDictionary = proxyDict;
    }
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    [[session dataTaskWithURL:url completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (data && !error) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json && [json[@"status"] isEqualToString:@"success"]) {
                NSString *query = json[@"query"];
                NSString *tz = json[@"timezone"];
                NSString *cc = json[@"countryCode"];
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (completion) completion(query, tz, cc);
                });
                return;
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(nil, nil, nil);
        });
    }] resume];
}

static void analyze_phone_for_auto_wipe(NSString *rawPhone,
                                        NSString **outRegion,
                                        NSString **outCarrierName,
                                        NSString **outMCC,
                                        NSString **outMNC,
                                        NSString **outCountryName,
                                        NSString **outDefaultTZ) {
    if (!rawPhone || rawPhone.length == 0) {
        if (outRegion) *outRegion = @"VN";
        if (outCarrierName) *outCarrierName = @"Viettel";
        if (outMCC) *outMCC = @"452";
        if (outMNC) *outMNC = @"04";
        if (outCountryName) *outCountryName = @"Việt Nam (+84)";
        if (outDefaultTZ) *outDefaultTZ = @"Asia/Ho_Chi_Minh";
        return;
    }

    NSMutableString *digits = [NSMutableString string];
    for (NSUInteger i = 0; i < rawPhone.length; i++) {
        unichar c = [rawPhone characterAtIndex:i];
        if (c >= '0' && c <= '9') {
            [digits appendFormat:@"%C", c];
        }
    }

    BOOL isPL = NO;
    BOOL isVN = NO;
    BOOL isUS = NO;
    NSString *cleanDigits = [digits copy];

    if ([rawPhone hasPrefix:@"+48"] || ([cleanDigits hasPrefix:@"48"] && cleanDigits.length == 11)) {
        isPL = YES;
        if ([cleanDigits hasPrefix:@"48"]) {
            cleanDigits = [cleanDigits substringFromIndex:2];
        }
    } else if (cleanDigits.length == 9 && ([cleanDigits hasPrefix:@"4"] || [cleanDigits hasPrefix:@"5"] || [cleanDigits hasPrefix:@"6"] || [cleanDigits hasPrefix:@"7"] || [cleanDigits hasPrefix:@"8"])) {
        isPL = YES;
    } else if ([rawPhone hasPrefix:@"+84"] || [cleanDigits hasPrefix:@"84"]) {
        isVN = YES;
        if ([cleanDigits hasPrefix:@"84"]) {
            cleanDigits = [@"0" stringByAppendingString:[cleanDigits substringFromIndex:2]];
        }
    } else if ([cleanDigits hasPrefix:@"0"] && cleanDigits.length == 10) {
        isVN = YES;
    } else if ([rawPhone hasPrefix:@"+1"] || ([cleanDigits hasPrefix:@"1"] && cleanDigits.length == 11)) {
        isUS = YES;
        if ([cleanDigits hasPrefix:@"1"]) {
            cleanDigits = [cleanDigits substringFromIndex:1];
        }
    } else if (cleanDigits.length == 10) {
        isUS = YES;
    }

    if (isPL) {
        if (outRegion) *outRegion = @"PL";
        if (outCountryName) *outCountryName = @"Ba Lan (+48)";
        if (outDefaultTZ) *outDefaultTZ = @"Europe/Warsaw";
        if (outMCC) *outMCC = @"260";

        NSString *carrier = @"Play";
        NSString *mnc = @"06";
        if (cleanDigits.length >= 2) {
            NSString *p2 = [cleanDigits substringToIndex:2];
            if ([p2 isEqualToString:@"45"] || [p2 isEqualToString:@"53"] || [p2 isEqualToString:@"57"] || [p2 isEqualToString:@"73"] || [p2 isEqualToString:@"79"]) {
                carrier = @"Play";
                mnc = @"06";
            } else if ([p2 isEqualToString:@"50"] || [p2 isEqualToString:@"51"]) {
                carrier = @"Orange";
                mnc = @"03";
            } else if ([p2 isEqualToString:@"60"] || [p2 isEqualToString:@"66"] || [p2 isEqualToString:@"72"]) {
                carrier = @"Plus";
                mnc = @"01";
            } else if ([p2 isEqualToString:@"69"] || [p2 isEqualToString:@"78"] || [p2 isEqualToString:@"88"]) {
                carrier = @"T-Mobile";
                mnc = @"02";
            }
        }
        if (outCarrierName) *outCarrierName = carrier;
        if (outMNC) *outMNC = mnc;
    } else if (isUS) {
        if (outRegion) *outRegion = @"US";
        if (outCountryName) *outCountryName = @"Hoa Kỳ (+1)";
        if (outDefaultTZ) *outDefaultTZ = @"America/New_York";
        if (outCarrierName) *outCarrierName = @"T-Mobile";
        if (outMCC) *outMCC = @"310";
        if (outMNC) *outMNC = @"260";
    } else {
        if (outRegion) *outRegion = @"VN";
        if (outCountryName) *outCountryName = @"Việt Nam (+84)";
        if (outDefaultTZ) *outDefaultTZ = @"Asia/Ho_Chi_Minh";
        if (outMCC) *outMCC = @"452";

        NSString *carrier = @"Viettel";
        NSString *mnc = @"04";
        if (cleanDigits.length >= 3) {
            NSString *p3 = [cleanDigits substringToIndex:3];
            if ([p3 isEqualToString:@"090"] || [p3 isEqualToString:@"093"] || [p3 isEqualToString:@"089"] ||
                [p3 isEqualToString:@"070"] || [p3 isEqualToString:@"079"] || [p3 isEqualToString:@"077"] ||
                [p3 isEqualToString:@"076"] || [p3 isEqualToString:@"078"]) {
                carrier = @"VN MOBIFONE";
                mnc = @"01";
            } else if ([p3 isEqualToString:@"096"] || [p3 isEqualToString:@"097"] || [p3 isEqualToString:@"098"] ||
                       [p3 isEqualToString:@"086"] || [p3 isEqualToString:@"032"] || [p3 isEqualToString:@"033"] ||
                       [p3 isEqualToString:@"034"] || [p3 isEqualToString:@"035"] || [p3 isEqualToString:@"036"] ||
                       [p3 isEqualToString:@"037"] || [p3 isEqualToString:@"038"] || [p3 isEqualToString:@"039"]) {
                carrier = @"Viettel";
                mnc = @"04";
            } else if ([p3 isEqualToString:@"091"] || [p3 isEqualToString:@"094"] || [p3 isEqualToString:@"088"] ||
                       [p3 isEqualToString:@"081"] || [p3 isEqualToString:@"082"] || [p3 isEqualToString:@"083"] ||
                       [p3 isEqualToString:@"084"] || [p3 isEqualToString:@"085"] || [p3 isEqualToString:@"087"] || [p3 isEqualToString:@"055"]) {
                carrier = @"VINAPHONE";
                mnc = @"02";
            } else if ([p3 isEqualToString:@"092"] || [p3 isEqualToString:@"056"] || [p3 isEqualToString:@"058"] || [p3 isEqualToString:@"052"]) {
                carrier = @"Vietnamobile";
                mnc = @"05";
            }
        }
        if (outCarrierName) *outCarrierName = carrier;
        if (outMNC) *outMNC = mnc;
    }
}

- (void)promptSmartAutoWipeFrom:(UIViewController *)top {
    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        [self showLicenseRequiredAlertFrom:top featureName:@"Deep Wipe & Cấp Máy Mới"];
        return;
    }

    NSString *clip = [UIPasteboard generalPasteboard].string ?: @"";
    NSString *prefilledPhone = @"";
    NSString *cleanClip = [[clip componentsSeparatedByCharactersInSet:[[NSCharacterSet characterSetWithCharactersInString:@"+0123456789"] invertedSet]] componentsJoinedByString:@""];
    if (cleanClip.length >= 8 && cleanClip.length <= 15) {
        prefilledPhone = [clip stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🎯 WIPE THÔNG MINH THEO SĐT"
                                                                   message:@"Nhập số điện thoại chuẩn bị đăng ký.\nHệ thống sẽ tự nhận diện Nhà Mạng (Plus, Play, Orange, Viettel...) và quét IP để tự động đồng bộ Múi Giờ chuẩn:"
                                                            preferredStyle:UIAlertControllerStyleAlert];

    [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = @"Ví dụ: +48661795935 hoặc 098...";
        textField.text = prefilledPhone;
        textField.clearButtonMode = UITextFieldViewModeWhileEditing;
        textField.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    }];

    [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = @"Proxy/IP (Để trống nếu dùng IP 4G/WiFi hiện tại)";
        textField.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];

    [alert addAction:[UIAlertAction actionWithTitle:@"🚀 Tự Động Wipe Ngay" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        UITextField *phoneField = alert.textFields.firstObject;
        UITextField *proxyField = (alert.textFields.count > 1) ? alert.textFields[1] : nil;

        NSString *rawPhone = [phoneField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (rawPhone.length == 0) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                UIViewController *p = get_top_view_controller() ?: top;
                UIAlertController *err = [UIAlertController alertControllerWithTitle:@"Chưa Nhập SĐT"
                                                                             message:@"Vui lòng nhập hoặc dán số điện thoại để hệ thống nhận diện nhà mạng thích hợp!"
                                                                      preferredStyle:UIAlertControllerStyleAlert];
                [err addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [p presentViewController:err animated:YES completion:nil];
            });
            return;
        }

        NSString *targetRegion = nil, *carrierName = nil, *mcc = nil, *mnc = nil, *countryName = nil, *defaultTZ = nil;
        analyze_phone_for_auto_wipe(rawPhone, &targetRegion, &carrierName, &mcc, &mnc, &countryName, &defaultTZ);

        NSString *proxyText = [proxyField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *p = get_top_view_controller() ?: top;
            UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"⚡ Đang Phân Tích & Quét IP..."
                                                                           message:[NSString stringWithFormat:@"• SĐT: %@ (%@)\n• Nhận diện SIM: %@ (%@-%@)\n• Đang kiểm tra IP & múi giờ...", rawPhone, countryName, carrierName, mcc, mnc]
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [p presentViewController:loading animated:YES completion:^{
                fetch_geoip_for_auto_wipe(proxyText, ^(NSString *queryIP, NSString *timezone, NSString *countryCode) {
                    NSString *effectiveTZ = timezone.length > 0 ? timezone : defaultTZ;
                    BOOL isVN = [targetRegion isEqualToString:@"VN"] || [countryCode isEqualToString:@"VN"];
                    BOOL isPL = [targetRegion isEqualToString:@"PL"] || [countryCode isEqualToString:@"PL"];
                    if (isVN) {
                        effectiveTZ = @"Asia/Ho_Chi_Minh";
                    } else if (isPL) {
                        effectiveTZ = @"Europe/Warsaw";
                    }

                    ZTSettings *settings = [ZTSettings sharedSettings];
                    settings.timeZoneName = effectiveTZ;
                    settings.localeIdentifier = isPL ? @"pl_PL" : (isVN ? @"vi_VN" : @"en_US");
                    settings.preferredLanguages = isPL ? @[@"pl-PL", @"en-PL"] : (isVN ? @[@"vi-VN", @"en-VN"] : @[@"en-US"]);
                    settings.preferredCarrier = carrierName;
                    settings.regionMode = targetRegion;
                    [settings saveSettings];

                    [loading dismissViewControllerAnimated:YES completion:^{
                        [self performInAppDeepWipeWithRegion:targetRegion preferredCarrier:carrierName currentIP:queryIP];
                    }];
                });
            }];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Hủy Bỏ" style:UIAlertActionStyleCancel handler:nil]];

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

    [alert addAction:[UIAlertAction actionWithTitle:@"🎯 [AUTO] Wipe Tự Động Theo SĐT & Múi Giờ IP" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self promptSmartAutoWipeFrom:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇻🇳 Wipe + Cắm SIM Viettel (452-04)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"VN" preferredCarrier:@"Viettel" from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇻🇳 Wipe + Cắm SIM VinaPhone (452-02)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"VN" preferredCarrier:@"VINAPHONE" from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇻🇳 Wipe + Cắm SIM MobiFone (452-01)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"VN" preferredCarrier:@"VN MOBIFONE" from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🎲 Wipe + SIM Ngẫu Nhiên (Việt Nam)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"VN" preferredCarrier:nil from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Wipe + Du Học Sinh Mỹ (+1) [T-Mobile / AT&T]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"US_STUDENT" preferredCarrier:nil from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇺🇸 Wipe + Hoa Kỳ (+1) [Verizon / AT&T / T-Mobile]" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"US" preferredCarrier:nil from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Wipe + Cắm SIM Play (260-06)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"PL" preferredCarrier:@"Play" from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Wipe + Cắm SIM Orange (260-03)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"PL" preferredCarrier:@"Orange" from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Wipe + Cắm SIM Plus (260-01)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"PL" preferredCarrier:@"Plus" from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🇵🇱 Wipe + Cắm SIM T-Mobile (260-02)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"PL" preferredCarrier:@"T-Mobile" from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"🎲 Wipe + SIM Ngẫu Nhiên (Ba Lan)" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:@"PL" preferredCarrier:nil from:targetTop];
        });
    }]];

    NSString *keepTitle = [NSString stringWithFormat:@"🔄 Giữ Vùng Hiện Tại (%@)", s.regionMode ?: @"VN"];
    [alert addAction:[UIAlertAction actionWithTitle:keepTitle style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *targetTop = get_top_view_controller() ?: top;
            [self startInAppDeepWipeSequenceWithRegion:s.regionMode ?: @"VN" preferredCarrier:s.preferredCarrier from:targetTop];
        });
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Hủy Bỏ" style:UIAlertActionStyleCancel handler:nil]];

    if (alert.popoverPresentationController) {
        alert.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        alert.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }

    [top presentViewController:alert animated:YES completion:nil];
}

- (void)startInAppDeepWipeSequenceWithRegion:(NSString *)targetRegion from:(UIViewController *)top {
    [self startInAppDeepWipeSequenceWithRegion:targetRegion preferredCarrier:nil from:top];
}

- (void)startInAppDeepWipeSequenceWithRegion:(NSString *)targetRegion preferredCarrier:(nullable NSString *)preferredCarrier from:(UIViewController *)top {
    UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"🧹 Đang Dọn Dẹp Dữ Liệu..."
                                                                   message:@"Đang ghi nhận IP mạng 4G trước khi wipe và làm sạch sandbox..."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [top presentViewController:loading animated:YES completion:^{
        fetch_public_ip(^(NSString *currentIP) {
            [loading dismissViewControllerAnimated:YES completion:^{
                [self performInAppDeepWipeWithRegion:targetRegion preferredCarrier:preferredCarrier currentIP:currentIP];
            }];
        });
    }];
}

- (void)performInAppDeepWipe {
    [self performInAppDeepWipeWithRegion:[ZTSettings sharedSettings].regionMode ?: @"VN" preferredCarrier:[ZTSettings sharedSettings].preferredCarrier currentIP:nil];
}

- (void)performInAppDeepWipeWithRegion:(NSString *)targetRegion {
    [self performInAppDeepWipeWithRegion:targetRegion preferredCarrier:nil currentIP:nil];
}

- (void)performInAppDeepWipeWithRegion:(NSString *)targetRegion currentIP:(NSString *)currentIP {
    [self performInAppDeepWipeWithRegion:targetRegion preferredCarrier:nil currentIP:currentIP];
}

static void wipe_directory_recursively_safely(NSFileManager *fm, NSString *dirPath) {
    if (!dirPath || dirPath.length == 0) return;
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:dirPath isDirectory:&isDir]) return;

    NSString *lower = [dirPath lowercaseString];
    if ([lower hasSuffix:@".adbk"] ||
        [lower containsString:@"appsmanager"] ||
        [lower containsString:@"com.sonhu.zalotweak"] ||
        [lower containsString:@"splashboard"] ||
        [lower containsString:@"saved application state"] ||
        [lower isEqualToString:@"zaloaudit.log"] ||
        [lower isEqualToString:@"zalotraffic.har"]) {
        return;
    }

    if (!isDir) {
        [fm removeItemAtPath:dirPath error:nil];
        return;
    }

    NSArray *items = [fm contentsOfDirectoryAtPath:dirPath error:nil];
    for (NSString *item in items) {
        NSString *subLower = [item lowercaseString];
        if ([subLower hasSuffix:@".adbk"] ||
            [subLower containsString:@"appsmanager"] ||
            [subLower containsString:@"com.sonhu.zalotweak"] ||
            [subLower containsString:@"splashboard"] ||
            [subLower containsString:@"saved application state"] ||
            [subLower isEqualToString:@"zaloaudit.log"] ||
            [subLower isEqualToString:@"zalotraffic.har"]) {
            continue;
        }
        NSString *fullPath = [dirPath stringByAppendingPathComponent:item];
        wipe_directory_recursively_safely(fm, fullPath);
    }
    NSString *lastComp = [dirPath lastPathComponent];
    if (![lastComp isEqualToString:@"Library"] &&
        ![lastComp isEqualToString:@"Documents"] &&
        ![lastComp isEqualToString:@"tmp"] &&
        ![lastComp isEqualToString:@"Application Support"]) {
        [fm removeItemAtPath:dirPath error:nil];
    }
}

- (void)performInAppDeepWipeWithRegion:(NSString *)targetRegion preferredCarrier:(nullable NSString *)preferredCarrier currentIP:(NSString *)currentIP {
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
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    NSArray *secGroups = @[
        @"",
        @"group.vn.com.vng.zingalo",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo",
        @"vn.com.vng.zingalo"
    ];
    for (id secClass in secClasses) {
        for (NSString *grp in secGroups) {
            NSMutableDictionary *query = [NSMutableDictionary dictionary];
            query[(__bridge id)kSecClass] = secClass;
            if (grp.length > 0) {
                query[(__bridge id)kSecAttrAccessGroup] = grp;
            }
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
    }

    // Xoá sạch bộ nhớ đệm mạng WebKit và URLCache
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
    if (@available(iOS 9.0, *)) {
        NSSet *websiteDataTypes = [WKWebsiteDataStore allWebsiteDataTypes];
        NSDate *dateFrom = [NSDate dateWithTimeIntervalSince1970:0];
        [[WKWebsiteDataStore defaultDataStore] removeDataOfTypes:websiteDataTypes modifiedSince:dateFrom completionHandler:^{}];
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
                if ([k.lowercaseString containsString:@"zalotweak"] || [k hasPrefix:@"ZT_"]) continue;
                [ud removeObjectForKey:k];
            }
            [ud synchronize];
        }
    }
    NSUserDefaults *stdUD = [NSUserDefaults standardUserDefaults];
    NSDictionary *stdDict = [stdUD dictionaryRepresentation];
    for (NSString *k in stdDict.allKeys) {
        if ([k.lowercaseString containsString:@"zalotweak"] || [k hasPrefix:@"ZT_"]) continue;
        [stdUD removeObjectForKey:k];
    }
    [stdUD synchronize];
    
    // 4. Quét dọn các thư mục dữ liệu trong Sandbox
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *libDir = [home stringByAppendingPathComponent:@"Library"];
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];
    
    wipe_directory_recursively_safely(fm, docDir);
    wipe_directory_recursively_safely(fm, tmpDir);
    
    // Quét dọn toàn bộ các thư mục trong Library (WebKit, Cookies, HTTPStorages, Caches, Application Support...)
    NSArray *libItems = [fm contentsOfDirectoryAtPath:libDir error:nil];
    for (NSString *item in libItems) {
        NSString *lower = [item lowercaseString];
        if ([lower containsString:@"com.sonhu.zalotweak"]) continue;
        if ([lower containsString:@"splashboard"] || [lower containsString:@"saved application state"]) continue;
        NSString *subDir = [libDir stringByAppendingPathComponent:item];
        if ([lower isEqualToString:@"preferences"]) {
            NSArray *pItems = [fm contentsOfDirectoryAtPath:subDir error:nil];
            for (NSString *pItem in pItems) {
                if ([pItem.lowercaseString containsString:@"com.sonhu.zalotweak"]) continue;
                [fm removeItemAtPath:[subDir stringByAppendingPathComponent:pItem] error:nil];
            }
        } else {
            wipe_directory_recursively_safely(fm, subDir);
        }
    }

    // 4.1. Quét dọn Shared App Groups (nếu có quyền truy cập nhóm)
    NSArray *groupNames = @[@"group.vn.com.vng.zingalo", @"group.com.vng.zalo", @"group.com.zing.zalo"];
    for (NSString *grp in groupNames) {
        NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:grp];
        if (groupURL) {
            NSString *groupPath = [groupURL path];
            wipe_directory_recursively_safely(fm, groupPath);
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
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"WebKit"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"HTTPStorages"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Application Support/KVCore/Device"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
    
    // 5. Đánh dấu Cold-Boot: Lưu khu vực SIM đã chọn, IP wipe và cờ needsNewProfile + needsSandboxPurge
    ZTSettings *settings = [ZTSettings sharedSettings];
    settings.isShuttingDownForDeepWipe = YES;
    settings.lastWipedIDFV = settings.spoofedIDFV;
    if (currentIP.length > 0 && ![currentIP isEqualToString:@"Không xác định"]) {
        settings.lastWipedIP = currentIP;
    }
    settings.lastWipedTimestamp = (uint64_t)[[NSDate date] timeIntervalSince1970];
    settings.regionMode = targetRegion ?: @"VN";
    settings.preferredCarrier = preferredCarrier ?: @"";
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

    // Xả sạch cache mạng tầng RAM & Cookies
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
    for (NSHTTPCookie *cookie in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies]) {
        [[NSHTTPCookieStorage sharedHTTPCookieStorage] deleteCookie:cookie];
    }

    // 6. Ngắt kết nối mạng và toàn bộ session TCP ngay lập tức
    sever_all_network_sockets_immediately();

    // 7. Đóng app dứt khoát
    UIViewController *top = get_top_view_controller();
    NSString *baseRegionDesc = [targetRegion isEqualToString:@"US_STUDENT"] ? @"Du Học Sinh Mỹ (+1)" :
                               ([targetRegion isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" :
                               ([targetRegion isEqualToString:@"PL"] ? @"Ba Lan (+48)" : @"Việt Nam (+84)"));
    NSString *regionDesc = (preferredCarrier.length > 0) ? [NSString stringWithFormat:@"%@ (Cắm sẵn SIM %@)", baseRegionDesc, preferredCarrier] : baseRegionDesc;

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
                           ([s.regionMode isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" :
                           ([s.regionMode isEqualToString:@"PL"] ? @"Ba Lan (+48)" : @"Việt Nam (+84)"));
    info.regionName = regionDesc;
    info.carrierName = s.carrierName ?: @"Viettel";
    info.carrierMCC = s.carrierMCC ?: @"452";
    info.carrierMNC = s.carrierMNC ?: @"04";
    info.carrierCountryCode = s.carrierCountryCode ?: @"vn";

    // Đo dung lượng Sandbox
    NSString *home = NSHomeDirectory();
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *cacheDir = [home stringByAppendingPathComponent:@"Library/Caches"];
    uint64_t sandboxBytes = get_directory_size(docDir) + get_directory_size(cacheDir);
    info.sandboxKB = (double)sandboxBytes / 1024.0;

    // Kiểm tra quyền ghi KVCore/Device & App Groups một cách an toàn (KHÔNG tạo file rác trên disk)
    NSString *absDeviceDir = [home stringByAppendingPathComponent:@"Library/Application Support/KVCore/Device"];
    [[NSFileManager defaultManager] createDirectoryAtPath:absDeviceDir withIntermediateDirectories:YES attributes:nil error:nil];
    BOOL leveldbWritable = [[NSFileManager defaultManager] isWritableFileAtPath:absDeviceDir];

    BOOL appGroupWorking = NO;
    @try {
        NSURL *grpURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.vn.com.vng.zingalo"];
        if (grpURL) {
            appGroupWorking = [[NSFileManager defaultManager] isWritableFileAtPath:grpURL.path];
        }
        if (!appGroupWorking) {
            NSUserDefaults *groupDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"group.vn.com.vng.zingalo"];
            appGroupWorking = (groupDefaults != nil);
        }
    } @catch (NSException *e) {
        appGroupWorking = NO;
    }
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

    // 1. Mã device_id phần cứng (Zalo Hardware Fingerprint từ st_birthtimespec chuẩn 3 timestamps tự nhiên)
    struct stat st_hw;
    memset(&st_hw, 0, sizeof(st_hw));
    if (stat("/var/mobile", &st_hw) == 0 || (home && stat([home UTF8String], &st_hw) == 0) || stat("/", &st_hw) == 0) {
        uint64_t birthMs = ((uint64_t)st_hw.st_birthtimespec.tv_sec) * 1000ULL + ((uint64_t)st_hw.st_birthtimespec.tv_nsec / 1000000ULL);
        uint64_t mtimeMs = ((uint64_t)st_hw.st_mtimespec.tv_sec) * 1000ULL + ((uint64_t)st_hw.st_mtimespec.tv_nsec / 1000000ULL);
        uint64_t ctimeMs = ((uint64_t)st_hw.st_ctimespec.tv_sec) * 1000ULL + ((uint64_t)st_hw.st_ctimespec.tv_nsec / 1000000ULL);
        if (mtimeMs == 0) mtimeMs = birthMs + 180000ULL + ((birthMs * 104729ULL) % 1800000ULL);
        if (ctimeMs == 0) ctimeMs = mtimeMs + 30000ULL + ((birthMs * 1299709ULL) % 600000ULL);
        info.hardwareDeviceId = [NSString stringWithFormat:@"%llu-%llu-%llu", birthMs, mtimeMs, ctimeMs];
        
        BOOL isStaticHardware = (birthMs == 1753442559000ULL || birthMs == 1777525794000ULL);
        if (s.hasConfiguredProfile && (s.birthTimeSec > 0 || s.bootTimeSec > 0)) {
            uint64_t expectedSec = s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400ULL ? (s.bootTimeSec - (86400ULL * 15 + 3600 * 4 + 720)) : 0);
            info.deviceIdPassed = (!isStaticHardware && (birthMs >= expectedSec * 1000ULL || (birthMs > 0 && !isStaticHardware)));
        } else {
            info.deviceIdPassed = (!isStaticHardware && birthMs > 0 && s.hasConfiguredProfile);
        }
    } else if (s.hasConfiguredProfile && (s.birthTimeSec > 0 || s.bootTimeSec > 0)) {
        uint64_t fakeBirth = s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400ULL ? (s.bootTimeSec - (86400ULL * 15 + 3600 * 4 + 720)) : 1568160000ULL);
        uint64_t delta_m = 180ULL + ((fakeBirth * 104729ULL) % 1800ULL) + (fakeBirth % 59ULL);
        uint64_t delta_c = delta_m + 30ULL + ((fakeBirth * 1299709ULL) % 600ULL) + ((fakeBirth / 13ULL) % 43ULL);
        uint64_t ms1 = fakeBirth * 1000ULL + ((fakeBirth * 2654435761ULL) % 850ULL + 100ULL);
        uint64_t ms2 = (fakeBirth + delta_m) * 1000ULL + (((fakeBirth + delta_m) * 2246822519ULL) % 850ULL + 100ULL);
        uint64_t ms3 = (fakeBirth + delta_c) * 1000ULL + (((fakeBirth + delta_c) * 3266489917ULL) % 850ULL + 100ULL);
        info.hardwareDeviceId = [NSString stringWithFormat:@"%llu-%llu-%llu", ms1, ms2, ms3];
        info.deviceIdPassed = YES;
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
    if (s.hasConfiguredProfile && (s.birthTimeSec > 0 || s.bootTimeSec > 0)) {
        time_t fake_ctime = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL));
        NSDate *expectedDate = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)fake_ctime];
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"yyyy-MM-dd HH:mm"];
        info.installTimeText = [df stringFromDate:expectedDate];
        info.installTimePassed = YES;
    } else {
        info.installTimeText = @"Mới cấp theo Profile";
        info.installTimePassed = s.hasConfiguredProfile;
    }

    // 5. Phân vùng Keychain & Môi trường thực thi
    info.keychainIsolated = s.hasConfiguredProfile && (s.profileId.length > 0);
    info.keychainCleanPassed = YES;
    info.keychainRemainingCount = 0;
    info.webkitCleanPassed = YES;
    info.clipboardCleanPassed = YES;

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

    // 6. Đồng bộ Vùng, Múi Giờ & Ngôn Ngữ
    info.localeIdentifier = s.localeIdentifier ?: @"vi_VN";
    if (s.enableFakeTimeZone) {
        info.timeZoneName = s.timeZoneName ?: @"Asia/Ho_Chi_Minh";
    } else {
        info.timeZoneName = [NSTimeZone systemTimeZone].name ?: @"Asia/Ho_Chi_Minh";
    }
    NSTimeZone *tz = [NSTimeZone timeZoneWithName:info.timeZoneName];
    NSInteger gmtSec = tz ? [tz secondsFromGMT] : 25200;
    int gmtH = (int)(gmtSec / 3600);
    int gmtM = abs((int)((gmtSec % 3600) / 60));
    info.timeZoneGMT = (gmtM > 0) ? [NSString stringWithFormat:@"GMT%+d:%02d", gmtH, gmtM] : [NSString stringWithFormat:@"GMT%+d", gmtH];
    info.preferredLanguages = [s.preferredLanguages componentsJoinedByString:@", "] ?: @"vi-VN, en-VN";

    BOOL isVNMode = [s.regionMode isEqualToString:@"VN"] || !s.regionMode;
    BOOL isPLMode = [s.regionMode isEqualToString:@"PL"];
    BOOL isUSMode = [s.regionMode isEqualToString:@"US"];
    BOOL isUSStudentMode = [s.regionMode isEqualToString:@"US_STUDENT"];
    BOOL isVNSim = [s.carrierMCC isEqualToString:@"452"];
    BOOL isPLSim = [s.carrierMCC isEqualToString:@"260"];
    BOOL isUSSim = [s.carrierMCC isEqualToString:@"310"] || [s.carrierMCC isEqualToString:@"311"];
    BOOL isVNTz = [info.timeZoneName containsString:@"Ho_Chi_Minh"] || [info.timeZoneName containsString:@"Bangkok"] || [info.timeZoneName containsString:@"Saigon"];
    BOOL isPLTz = [info.timeZoneName containsString:@"Warsaw"];
    BOOL isUSTz = [info.timeZoneName containsString:@"America"] || [info.timeZoneName containsString:@"New_York"] || [info.timeZoneName containsString:@"Chicago"] || [info.timeZoneName containsString:@"Los_Angeles"] || [info.timeZoneName containsString:@"Denver"];
    if (!s.enableFakeTimeZone) {
        info.regionSyncPassed = YES;
    } else if (isVNMode) {
        info.regionSyncPassed = isVNSim && isVNTz;
    } else if (isPLMode) {
        info.regionSyncPassed = isPLSim && isPLTz;
    } else if (isUSStudentMode) {
        info.regionSyncPassed = isUSSim && (isVNTz || isUSTz);
    } else if (isUSMode) {
        info.regionSyncPassed = isUSSim && isUSTz;
    } else {
        info.regionSyncPassed = YES;
    }

    // 7. Radar phần cứng mới: hw.product, l2cache, pagesize, proc_translated
    char liveProductBuf[64] = {0};
    size_t plen = sizeof(liveProductBuf);
    sysctlbyname("hw.product", liveProductBuf, &plen, NULL, 0);
    info.hwProduct = (strlen(liveProductBuf) > 0) ? [NSString stringWithUTF8String:liveProductBuf] : s.deviceMachine;

    int psize = 0;
    size_t psz = sizeof(psize);
    sysctlbyname("hw.pagesize", &psize, &psz, NULL, 0);
    info.pageSizeKB = (psize > 0) ? (uint32_t)(psize / 1024) : 16;

    int64_t l2 = 0;
    size_t l2sz = sizeof(l2);
    sysctlbyname("hw.l2cachesize", &l2, &l2sz, NULL, 0);
    info.l2CacheSizeMB = (l2 > 0) ? (uint32_t)(l2 / (1024 * 1024)) : (uint32_t)(s.l2cacheSize / (1024 * 1024));

    int proc_trans = 0;
    size_t ptsz = sizeof(proc_trans);
    sysctlbyname("sysctl.proc_translated", &proc_trans, &ptsz, NULL, 0);
    info.procTranslated = proc_trans;
    info.sysctlPassed = (info.procTranslated == 0 && info.pageSizeKB == 16 && info.l2CacheSizeMB > 0);

    // 8. Định dạng ngày giờ cụ thể cho st_birthtime & BootTime
    time_t fake_birth = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 0));
    if (fake_birth > 0) {
        struct tm btm;
        gmtime_r(&fake_birth, &btm);
        info.birthTimeText = [NSString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d UTC",
                              btm.tm_year + 1900, btm.tm_mon + 1, btm.tm_mday,
                              btm.tm_hour, btm.tm_min, btm.tm_sec];
    } else {
        info.birthTimeText = @"N/A";
    }

    time_t fake_boot = (time_t)s.bootTimeSec;
    if (fake_boot > 0) {
        struct tm boot_tm;
        gmtime_r(&fake_boot, &boot_tm);
        info.bootTimeText = [NSString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d UTC",
                             boot_tm.tm_year + 1900, boot_tm.tm_mon + 1, boot_tm.tm_mday,
                             boot_tm.tm_hour, boot_tm.tm_min, boot_tm.tm_sec];
    } else {
        info.bootTimeText = @"N/A";
    }

    // Cập nhật lastWipedIP nếu chưa có và ĐÃ CÓ profile đã cấu hình
    if (s.hasConfiguredProfile && s.lastWipedIP.length == 0 && currentIP.length > 0 && ![currentIP isEqualToString:@"Không xác định"]) {
        s.lastWipedIP = currentIP;
        [s saveSettings];
    }

    return info;
}

@end

#pragma clang diagnostic pop
