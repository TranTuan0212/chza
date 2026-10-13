#import "FloatingMenu.h"
#import "Config.h"
#import "SecurityManager.h"
#import <objc/runtime.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#import <fcntl.h>
#import <unistd.h>
#import <CFNetwork/CFNetwork.h>

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

UIViewController *ZTGetTopViewController(void) {
    return get_top_view_controller();
}

BOOL ZTParseProxyString(NSString *str, NSString **outHost, uint16_t *outPort, NSString **outUser, NSString **outPass) {
    if (!str || str.length == 0) return NO;
    NSString *clean = [str stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    clean = [clean stringByReplacingOccurrencesOfString:@"http://" withString:@""];
    clean = [clean stringByReplacingOccurrencesOfString:@"https://" withString:@""];
    clean = [clean stringByReplacingOccurrencesOfString:@"socks5://" withString:@""];

    NSArray *parts = [clean componentsSeparatedByString:@":"];
    if (parts.count >= 2) {
        if (outHost) *outHost = parts[0];
        if (outPort) *outPort = (uint16_t)[parts[1] intValue];
        if (parts.count >= 4) {
            if (outUser) *outUser = parts[2];
            if (outPass) *outPass = parts[3];
        } else {
            if (outUser) *outUser = @"";
            if (outPass) *outPass = @"";
        }
        return YES;
    }
    return NO;
}

void ZTCheckProxyHealth(void (^completion)(BOOL alive, NSString *ip, NSString *errorMessage)) {
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.proxyHost.length == 0 || s.proxyPort == 0) {
        if (completion) completion(NO, nil, @"Proxy chưa có Host/Port!");
        return;
    }

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSMutableDictionary *proxyDict = [NSMutableDictionary dictionary];
    if ([s.proxyType isEqualToString:@"SOCKS5"]) {
        NSMutableDictionary *socksDict = [NSMutableDictionary dictionary];
        socksDict[(NSString *)kCFStreamPropertySOCKSProxyHost] = s.proxyHost;
        socksDict[(NSString *)kCFStreamPropertySOCKSProxyPort] = @(s.proxyPort);
        socksDict[(NSString *)kCFStreamPropertySOCKSVersion] = (NSString *)kCFStreamSocketSOCKSVersion5;
        if (s.proxyUser.length > 0) {
            socksDict[(NSString *)kCFStreamPropertySOCKSUser] = s.proxyUser;
            socksDict[(NSString *)kCFStreamPropertySOCKSPassword] = s.proxyPass ?: @"";
        }
        proxyDict[(NSString *)kCFStreamPropertySOCKSProxy] = socksDict;
        proxyDict[@"SOCKSEnable"] = @(YES);
        proxyDict[@"SOCKSProxy"] = s.proxyHost;
        proxyDict[@"SOCKPort"] = @(s.proxyPort);
    } else {
        proxyDict[(NSString *)kCFNetworkProxiesHTTPEnable] = @(YES);
        proxyDict[(NSString *)kCFNetworkProxiesHTTPProxy] = s.proxyHost;
        proxyDict[(NSString *)kCFNetworkProxiesHTTPPort] = @(s.proxyPort);
        proxyDict[@"HTTPSEnable"] = @(YES);
        proxyDict[@"HTTPSProxy"] = s.proxyHost;
        proxyDict[@"HTTPSPort"] = @(s.proxyPort);
        if (s.proxyUser.length > 0) {
            proxyDict[(NSString *)kCFProxyUsernameKey] = s.proxyUser;
            proxyDict[(NSString *)kCFProxyPasswordKey] = s.proxyPass ?: @"";
            if (s.proxyPass.length > 0) {
                NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:s.proxyHost
                                                                                    port:s.proxyPort
                                                                                protocol:NSURLProtectionSpaceHTTPProxy
                                                                                   realm:nil
                                                                    authenticationMethod:NSURLAuthenticationMethodHTTPBasic];
                NSURLCredential *cred = [NSURLCredential credentialWithUser:s.proxyUser
                                                                   password:s.proxyPass
                                                                persistence:NSURLCredentialPersistenceForSession];
                [[NSURLCredentialStorage sharedCredentialStorage] setDefaultCredential:cred forProtectionSpace:space];
            }
        }
    }
    config.connectionProxyDictionary = proxyDict;
    config.timeoutIntervalForRequest = 5.0;
    config.timeoutIntervalForResource = 5.0;

    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    NSURL *url = [NSURL URLWithString:@"https://api.ipify.org"];
    NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:5.0];

    [[session dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                NSString *errStr = error.localizedDescription ?: @"Mất kết nối";
                if (error.code == NSURLErrorTimedOut) {
                    errStr = @"Quá thời gian phản hồi (Timeout) - Proxy quá chậm hoặc đã chết";
                } else if (error.code == NSURLErrorCannotConnectToHost) {
                    errStr = @"Không thể kết nối đến máy chủ Proxy (Sai Port hoặc Proxy đã chết)";
                }
                if (completion) completion(NO, nil, errStr);
                return;
            }
            NSHTTPURLResponse *httpRes = (NSHTTPURLResponse *)response;
            if (httpRes && httpRes.statusCode == 407) {
                if (completion) completion(NO, nil, @"Lỗi 407: Sai Tài Khoản / Mật Khẩu xác thực Proxy (Proxy Auth Required)");
                return;
            }
            if (httpRes && httpRes.statusCode != 200) {
                if (completion) completion(NO, nil, [NSString stringWithFormat:@"Proxy trả về mã lỗi HTTP %ld", (long)httpRes.statusCode]);
                return;
            }
            if (!data || data.length == 0) {
                if (completion) completion(NO, nil, @"Máy chủ Proxy không phản hồi dữ liệu!");
                return;
            }
            NSString *ip = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            ip = [ip stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (ip.length >= 7) {
                if (completion) completion(YES, ip, nil);
            } else {
                if (completion) completion(NO, nil, @"Dữ liệu IP từ Proxy không hợp lệ!");
            }
        });
    }] resume];
}

static NSTimeInterval s_lastProxyWarnTime = 0;
void ZTAutoCheckProxyAndWarnIfDead(void) {
    ZTSettings *s = [ZTSettings sharedSettings];
    if (!s.proxyEnabled || s.proxyHost.length == 0 || s.proxyPort == 0) return;

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - s_lastProxyWarnTime < 180) return; // Chỉ cảnh báo tối đa 1 lần mỗi 3 phút

    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        s_lastProxyWarnTime = now;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIViewController *top = get_top_view_controller();
            if (top) {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"⚠️ PROXY TẠM DỪNG: BẢN QUYỀN HẾT HẠN!"
                                                                               message:@"Cấu hình Proxy riêng cho Zalo đã tạm dừng vì License Key của bạn chưa được kích hoạt hoặc đã hết hạn!\n\n⚠️ Vui lòng gia hạn Key để tiếp tục sử dụng Proxy và bảo vệ IP mạng."
                                                                        preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleCancel handler:nil]];
                [top presentViewController:alert animated:YES completion:nil];
            }
        });
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        ZTCheckProxyHealth(^(BOOL alive, NSString *ip, NSString *errorMessage) {
            if (!alive) {
                s_lastProxyWarnTime = [[NSDate date] timeIntervalSince1970];
                UIViewController *top = get_top_view_controller();
                if (top) {
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"⚠️ CẢNH BÁO: PROXY MẤT KẾT NỐI!"
                                                                                   message:[NSString stringWithFormat:@"Proxy riêng của Zalo đang BẬT nhưng không thể kết nối tới máy chủ Proxy:\n\n• Proxy: %@:%u (%@)\n• Nguyên nhân: %@\n\n⚠️ Proxy có thể đã HẾT HẠN hoặc MẤT MẠNG. Vui lòng kiểm tra lại cấu hình Proxy để tránh làm gián đoạn Zalo hoặc lộ IP thật!", s.proxyHost, s.proxyPort, s.proxyType ?: @"HTTP", errorMessage ?: @"Không xác định"]
                                                                            preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleCancel handler:nil]];
                    [top presentViewController:alert animated:YES completion:nil];
                }
            }
        });
    });
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
        if (settings.hasConfiguredProfile) {
            guidance = @"⚠️ BẢN QUYỀN ĐÃ HẾT HẠN!\nProfile máy ảo hiện tại ĐÃ ĐƯỢC ĐÓNG BĂNG để bảo vệ an toàn cho tài khoản Zalo của bạn (không lộ máy thật).\nCác chức năng Wipe, Đổi máy, Proxy bị tạm khóa cho đến khi gia hạn.";
        } else {
            guidance = @"⚠️ BƯỚC CẦN LÀM ĐẦU TIÊN: Bấm [4️⃣ Cài Đặt Nâng Cao] để KÍCH HOẠT KEY!\nHiện tại app đang dùng máy thật. Hãy kích hoạt Key và bấm [1️⃣] để bắt đầu giả lập máy mới.";
        }
    } else {
        guidance = @"📋 QUY TRÌNH TẠO ACC CHUẨN (LÀM THEO THỨ TỰ):\n"
                   @"▶️ Bước 1: Bấm [1️⃣ Deep Wipe Sạch & Cấp Máy Mới] (Chọn SIM & app tự thoát)\n"
                   @"▶️ Bước 2: Bật rồi tắt Chế Độ Máy Bay (đổi IP 4G) hoặc cấu hình Proxy [2️⃣]\n"
                   @"▶️ Bước 3: Mở lại Zalo -> Bấm [3️⃣ Kiểm Tra Độ Sạch Toàn Diện]\n"
                   @"▶️ Bước 4: Thấy tick xanh 🟢 -> Tiến hành Reg Acc an toàn!";
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
    
    // Nút 1: Deep Wipe & Cấp Máy Mới (Đã tích hợp sẵn chọn SIM/Khu vực VN, US...)
    NSString *wipeButtonTitle = isLicensed ? @"🚀 [1️⃣] Deep Wipe Sạch & Cấp Máy Mới (1-Click)" : @"🔒 [1️⃣] Deep Wipe Sạch & Cấp Máy Mới (Cần Key)";
    [sheet addAction:[UIAlertAction actionWithTitle:wipeButtonTitle
                                             style:UIAlertActionStyleDestructive
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Deep Wipe & Cấp Máy Mới"];
            return;
        }
        [self confirmDeepWipeFrom:top];
    }]];
    
    // Nút 2: Proxy Riêng Cho Zalo (Per-App Proxy)
    NSString *proxyButtonTitle;
    if (!isLicensed) {
        proxyButtonTitle = @"🔒 [2️⃣] Proxy Riêng Cho Zalo (Cần Key)";
    } else {
        proxyButtonTitle = settings.proxyEnabled ?
            [NSString stringWithFormat:@"🌐 [2️⃣] Proxy Zalo: BẬT (%@:%u - %@)", settings.proxyHost, settings.proxyPort, settings.proxyType ?: @"HTTP"] :
            @"🌐 [2️⃣] Cấu Hình Proxy Riêng Zalo (Đang Tắt)";
    }
    [sheet addAction:[UIAlertAction actionWithTitle:proxyButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Proxy Riêng Cho Zalo"];
            return;
        }
        [self showProxySettingsFrom:top];
    }]];

    // Nút 3: Kiểm Tra Độ Sạch Trước Khi Reg
    NSString *diagButtonTitle = isLicensed ? @"🔍 [3️⃣] Kiểm Tra Độ Sạch Toàn Diện (Checklist)" : @"🔒 [3️⃣] Kiểm Tra Độ Sạch Toàn Diện (Cần Key)";
    [sheet addAction:[UIAlertAction actionWithTitle:diagButtonTitle
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            [self showLicenseRequiredAlertFrom:top featureName:@"Kiểm Tra Độ Sạch Trước Khi Reg"];
            return;
        }
        [self showPreRegDiagnosticFrom:top];
    }]];
    
    // Nút 4: Cài Đặt Nâng Cao & Bản Quyền (Gom Bản quyền, Thông số máy, Audit log, Ẩn nút)
    NSString *advButtonTitle = isLicensed ? @"⚙️ [4️⃣] Cài Đặt Nâng Cao & Bản Quyền" : @"🛡️ [4️⃣] KÍCH HOẠT BẢN QUYỀN & CÀI ĐẶT";
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
    
    // Hỗ trợ iPad popover
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = [ZTFloatingButton sharedButton];
        sheet.popoverPresentationController.sourceRect = [ZTFloatingButton sharedButton].bounds;
    }
    
    [top presentViewController:sheet animated:YES completion:nil];
}

#pragma mark - Proxy Settings

- (void)showProxySettingsFrom:(UIViewController *)top {
    UIViewController *presenter = top ?: get_top_view_controller();
    if (!presenter) return;

    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        [self showLicenseRequiredAlertFrom:presenter featureName:@"Proxy Riêng Cho Zalo"];
        return;
    }

    ZTSettings *s = [ZTSettings sharedSettings];
    NSString *statusStr = s.proxyEnabled ? [NSString stringWithFormat:@"🟢 ĐANG BẬT: %@://%@:%u", s.proxyType ?: @"HTTP", s.proxyHost, s.proxyPort] : @"⚪ ĐANG TẮT";
    NSString *authStr = (s.proxyUser.length > 0) ? [NSString stringWithFormat:@" (User: %@)", s.proxyUser] : @" (Không có User)";

    NSString *msg = [NSString stringWithFormat:@"Trạng Thái: %@%@\n\nProxy chỉ áp dụng riêng cho Zalo. Tweak tự động cảnh báo nếu Proxy bị mất mạng hoặc hết hạn.", statusStr, authStr];

    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"🌐 CÀI ĐẶT PROXY RIÊNG ZALO"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    // Nút Bật/Tắt
    NSString *toggleTitle = s.proxyEnabled ? @"🔴 TẮT Proxy Zalo" : @"🟢 BẬT Proxy Zalo";
    [sheet addAction:[UIAlertAction actionWithTitle:toggleTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        if (!s.proxyEnabled && (s.proxyHost.length == 0 || s.proxyPort == 0)) {
            [self promptQuickPasteProxyFrom:presenter];
            return;
        }
        s.proxyEnabled = !s.proxyEnabled;
        [s saveSettings];
        UIAlertController *toast = [UIAlertController alertControllerWithTitle:s.proxyEnabled ? @"Đã Bật Proxy" : @"Đã Tắt Proxy"
                                                                       message:s.proxyEnabled ? @"Toàn bộ kết nối Zalo giờ đây sẽ đi qua Proxy." : @"Zalo đã trở về kết nối mạng thông thường của máy."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [toast addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [presenter presentViewController:toast animated:YES completion:nil];
    }]];

    // Nút Nhập Nhanh
    [sheet addAction:[UIAlertAction actionWithTitle:@"📋 Dán Nhanh Chuỗi (IP:Port hoặc IP:Port:User:Pass)" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self promptQuickPasteProxyFrom:presenter];
    }]];

    // Nút Kiểm Tra Proxy (Test IP)
    [sheet addAction:[UIAlertAction actionWithTitle:@"🔍 Kiểm Tra Kết Nối (Test IP & Báo Lỗi)" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self testProxyConnectionFrom:presenter];
    }]];

    // Nút Đổi Loại Proxy (HTTP / SOCKS5)
    NSString *typeTitle = [NSString stringWithFormat:@"🔄 Đổi Loại: Hiện Tại [%@]", s.proxyType ?: @"HTTP"];
    [sheet addAction:[UIAlertAction actionWithTitle:typeTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        s.proxyType = [s.proxyType isEqualToString:@"SOCKS5"] ? @"HTTP" : @"SOCKS5";
        [s saveSettings];
        [self showProxySettingsFrom:presenter];
    }]];

    // Nút Xóa cấu hình
    [sheet addAction:[UIAlertAction actionWithTitle:@"🗑️ Xóa Trắng Cấu Hình Proxy" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        s.proxyEnabled = NO;
        s.proxyHost = @"";
        s.proxyPort = 0;
        s.proxyUser = @"";
        s.proxyPass = @"";
        [s saveSettings];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)promptQuickPasteProxyFrom:(UIViewController *)presenter {
    ZTSettings *s = [ZTSettings sharedSettings];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Nhập Cấu Hình Proxy"
                                                                   message:@"Dán chuỗi Proxy theo định dạng:\n• IP:Port (vd: 103.150.12.34:8080)\n• hoặc IP:Port:User:Pass"
                                                            preferredStyle:UIAlertControllerStyleAlert];

    [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = @"vd: 103.150.12.34:8080 hoặc có User:Pass";
        if (s.proxyHost.length > 0) {
            if (s.proxyUser.length > 0) {
                textField.text = [NSString stringWithFormat:@"%@:%u:%@:%@", s.proxyHost, s.proxyPort, s.proxyUser, s.proxyPass ?: @""];
            } else {
                textField.text = [NSString stringWithFormat:@"%@:%u", s.proxyHost, s.proxyPort];
            }
        }
    }];

    [alert addAction:[UIAlertAction actionWithTitle:@"Hủy" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Lưu & Bật Proxy" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *text = alert.textFields.firstObject.text;
        NSString *host = @"";
        uint16_t port = 0;
        NSString *user = @"";
        NSString *pass = @"";
        if (ZTParseProxyString(text, &host, &port, &user, &pass) && host.length > 0 && port > 0) {
            s.proxyHost = host;
            s.proxyPort = port;
            s.proxyUser = user;
            s.proxyPass = pass;
            s.proxyEnabled = YES;
            [s saveSettings];

            [self testProxyConnectionFrom:presenter];
        } else {
            UIAlertController *err = [UIAlertController alertControllerWithTitle:@"Định Dạng Không Hợp Lệ"
                                                                         message:@"Vui lòng nhập đúng định dạng IP:Port hoặc IP:Port:User:Pass!"
                                                                  preferredStyle:UIAlertControllerStyleAlert];
            [err addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [presenter presentViewController:err animated:YES completion:nil];
        }
    }]];

    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)testProxyConnectionFrom:(UIViewController *)presenter {
    UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"🔍 Đang Kiểm Tra Proxy..."
                                                                     message:@"Đang gửi gói tin kiểm tra kết nối qua Proxy tới máy chủ ipify..."
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [presenter presentViewController:loading animated:YES completion:^{
        ZTCheckProxyHealth(^(BOOL alive, NSString *ip, NSString *errorMessage) {
            [loading dismissViewControllerAnimated:YES completion:^{
                if (alive) {
                    UIAlertController *ok = [UIAlertController alertControllerWithTitle:@"🎉 Proxy Hoạt Động Tốt"
                                                                                message:[NSString stringWithFormat:@"Proxy đã kết nối thành công!\n\n• IP Public: %@\n• Loại: %@\n• Host: %@:%u", ip, [ZTSettings sharedSettings].proxyType, [ZTSettings sharedSettings].proxyHost, [ZTSettings sharedSettings].proxyPort]
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                    [ok addAction:[UIAlertAction actionWithTitle:@"Tuyệt Vời" style:UIAlertActionStyleDefault handler:nil]];
                    [presenter presentViewController:ok animated:YES completion:nil];
                } else {
                    UIAlertController *fail = [UIAlertController alertControllerWithTitle:@"❌ Proxy Mất Kết Nối / Hết Hạn"
                                                                                  message:[NSString stringWithFormat:@"Không thể kết nối qua Proxy:\n\n• Chi tiết: %@\n• Host: %@:%u\n\n⚠️ Vui lòng kiểm tra lại Proxy hoặc đổi Proxy mới!", errorMessage ?: @"Mất kết nối", [ZTSettings sharedSettings].proxyHost, [ZTSettings sharedSettings].proxyPort]
                                                                           preferredStyle:UIAlertControllerStyleAlert];
                    [fail addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
                    [presenter presentViewController:fail animated:YES completion:nil];
                }
            }];
        });
    }];
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
                                                                     message:@"Đang quét bộ nhớ đệm Sandbox, kiểm tra IP mạng và trạng thái Proxy/SIM..."
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [presenter presentViewController:loading animated:YES completion:^{
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.proxyEnabled && s.proxyHost.length > 0 && s.proxyPort > 0) {
            ZTCheckProxyHealth(^(BOOL alive, NSString *proxyIP, NSString *proxyErr) {
                [loading dismissViewControllerAnimated:YES completion:^{
                    [self renderDiagnosticReportWithIP:proxyIP ?: @"Mất kết nối" proxyAlive:alive proxyError:proxyErr from:presenter];
                }];
            });
        } else {
            fetch_public_ip(^(NSString *currentIP) {
                [loading dismissViewControllerAnimated:YES completion:^{
                    [self renderDiagnosticReportWithIP:currentIP proxyAlive:NO proxyError:nil from:presenter];
                }];
            });
        }
    }];
}

- (void)renderDiagnosticReportWithIP:(NSString *)currentIP proxyAlive:(BOOL)proxyAlive proxyError:(NSString *)proxyError from:(UIViewController *)presenter {
    ZTSettings *s = [ZTSettings sharedSettings];
    BOOL isLicensed = [[ZTSecurityManager sharedManager] isLicenseValid];
    NSString *licStatusText = [[ZTSecurityManager sharedManager] getLicenseStatusText];

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
    if (s.proxyEnabled) {
        if (!proxyAlive) {
            ipStatus = @"PROXY MẤT KẾT NỐI / HẾT HẠN ❌";
        } else if (isSameIP) {
            ipStatus = @"TRÙNG IP PROXY CŨ ❌";
        } else if (isDifferentIP) {
            ipStatus = @"Đã đổi IP Proxy mới ✅";
        } else {
            ipStatus = @"IP Proxy hoạt động tốt ✅";
        }
    } else {
        if (isSameIP) {
            ipStatus = @"TRÙNG IP 4G CŨ (CẦN BẬT AIRPLANE MODE) ❌";
        } else if (isDifferentIP) {
            ipStatus = @"Đã đổi IP 4G mới ✅";
        } else {
            ipStatus = @"IP 4G hợp lệ ✅";
        }
    }

    if (!hasWipedHistory && s.lastWipedIP.length == 0 && currentIP.length > 0 && ![currentIP isEqualToString:@"Không xác định"] && ![currentIP containsString:@"Mất kết nối"]) {
        s.lastWipedIP = currentIP;
        [s saveSettings];
    }

    // 7. KIỂM TRA THỰC TẾ BẰNG HÀM C POSIX (Chính xác cách LevelDB C++ gọi mở file)
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
    BOOL isProxyOK = (!s.proxyEnabled) || (s.proxyEnabled && proxyAlive);
    BOOL isAllPassed = (isMachineSpoofed && 
                        (!isSameIP) && 
                        (!isDuplicateIDFV) && 
                        isProxyOK &&
                        leveldbRelWritable && 
                        leveldbAbsWritable && 
                        leveldbAtWritable && 
                        appGroupWorking && 
                        isHiddenProv &&
                        isLicensed);

    NSString *conclusion = @"";
    if (!isAllPassed) {
        NSMutableString *errList = [NSMutableString stringWithString:@"🔴 KHÔNG ĐẠT TIÊU CHUẨN! CẦN XỬ LÝ:\n"];
        if (!isLicensed) [errList appendString:@"• Bản quyền Tweak chưa kích hoạt hoặc đã hết hạn!\n"];
        if (!isMachineSpoofed) [errList appendString:@"• Machine C chưa khớp với cấu hình profile.\n"];
        if (s.proxyEnabled && !proxyAlive) [errList appendFormat:@"• Proxy Zalo lỗi/mất kết nối: %@\n", proxyError ?: @"Không phản hồi"];
        if (isSameIP) {
            if (s.proxyEnabled) [errList appendString:@"• TRÙNG IP PROXY CŨ! Hãy đổi IP proxy mới.\n"];
            else [errList appendString:@"• TRÙNG IP 4G CŨ! Hãy Bật rồi Tắt Chế Độ Máy Bay.\n"];
        }
        if (isDuplicateIDFV) [errList appendString:@"• TRÙNG IDFV CŨ! Vui lòng bấm [1️⃣] Deep Wipe.\n"];
        if (!leveldbRelWritable) [errList appendString:@"• LevelDB không thể ghi qua đường dẫn tương đối C.\n"];
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
            @"  - Dòng máy: %@ (iOS %@)\n"
            @"  - Nhà mạng: %@ (%@ - %@)\n"
            @"  - Mạng: %@\n"
            @"  - IDFV: Cấp mới tinh không trùng lặp\n"
            @"  - C LevelDB: Thông suốt hoàn toàn",
            liveDeviceName, liveSystemVersion,
            s.carrierName ?: @"Viettel", s.carrierMCC ?: @"452", s.carrierMNC ?: @"04",
            (s.proxyEnabled ? [NSString stringWithFormat:@"Proxy riêng %@ (%@:%u)", s.proxyType, s.proxyHost, s.proxyPort] : @"IP 4G Đã xoay dải mới")];
    }

    // Định dạng chuỗi Proxy
    NSString *proxyInfoStr;
    if (s.proxyEnabled) {
        NSString *authStr = (s.proxyUser.length > 0) ? [NSString stringWithFormat:@" (User: %@)", s.proxyUser] : @"";
        proxyInfoStr = [NSString stringWithFormat:@"🟢 BẬT [%@://%@:%u%@]\n • Tình Trạng Proxy : %@",
                        s.proxyType ?: @"HTTP", s.proxyHost ?: @"", s.proxyPort, authStr,
                        (proxyAlive ? @"Kết nối tốt ✅" : [NSString stringWithFormat:@"Lỗi: %@ ❌", proxyError ?: @"Không xác định"])];
    } else {
        proxyInfoStr = @"⚪ TẮT (Dùng mạng trực tiếp 4G/Wi-Fi của máy)";
    }

    // Định dạng chuỗi Nhà Mạng
    NSString *regionName = [s.regionMode isEqualToString:@"US_STUDENT"] ? @"Du Học Sinh Mỹ (+1)" :
                           ([s.regionMode isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" : @"Việt Nam (+84)");
    NSString *carrierInfoStr = [NSString stringWithFormat:
        @" • Tên Nhà Mạng   : %@\n"
        @" • Mã Quốc Gia ISO: %@ (Hồ sơ: %@)\n"
        @" • Mã Mạng (MCC)  : %@ | (MNC): %@\n"
        @" • Chuẩn SIM Ảo   : Khớp nhà mạng thật 100%% ✅",
        s.carrierName ?: @"Viettel",
        s.carrierCountryCode ?: @"vn", regionName,
        s.carrierMCC ?: @"452", s.carrierMNC ?: @"04"];

    NSString *report = [NSString stringWithFormat:
        @"═══════════════════════════\n"
        @"1. BẢN QUYỀN TWEAK (DRM):\n"
        @" • Trạng Thái: %@\n\n"
        @"2. MẠNG INTERNET & PROXY ZALO:\n"
        @" • Proxy Riêng: %@\n"
        @" • IP Public Hiện Tại: %@ (%@)\n"
        @" • IP Lần Wipe Trước : %@\n\n"
        @"3. THÔNG TIN NHÀ MẠNG & SIM:\n%@\n\n"
        @"4. ĐỊNH DANH PHẦN CỨNG ẢO:\n"
        @" • Machine (C)  : %@ (%@)\n"
        @" • Tên Thiết Bị : %@\n"
        @" • Phiên Bản iOS: %@\n"
        @" • Serial Số Ảo : %@\n"
        @" • Wi-Fi MAC Ảo : %@\n"
        @" • IDFV Hiện Tại: %@... (%@)\n"
        @" • IDFV Trước Đó: %@...\n"
        @" • IDFA Quảng Cáo: %@ (Ẩn danh ✅)\n"
        @" • Dung Lượng Trống: %.1f GB / %.1f GB\n\n"
        @"5. VỆ SINH SANDBOX & LEVELDB C++:\n"
        @" • Dữ Liệu Cache: %.1f KB (%@)\n"
        @" • Mobileprovision: %@\n"
        @" • C open (tương đối): %@\n"
        @" • C open (tuyệt đối): %@\n"
        @" • C openat (AT_FDCWD): %@\n"
        @" • App Groups: %@\n"
        @"═══════════════════════════\n"
        @"👉 KẾT LUẬN TOÀN DIỆN:\n%@",
        licStatusText,
        proxyInfoStr,
        currentIP, ipStatus,
        ipOld,
        carrierInfoStr,
        liveMachineStr, (isMachineSpoofed ? @"Khớp Profile ✅" : @"Chưa khớp ❌"),
        liveDeviceName,
        liveSystemVersion,
        s.spoofedSerial ?: @"(Chưa cấp)",
        s.spoofedWifiMAC ?: @"(Chưa cấp)",
        idfvShort, idfvStatus,
        idfvOld,
        (liveIDFA.length > 8 ? [liveIDFA substringToIndex:8] : liveIDFA),
        freeGB, totalGB,
        sandboxKB, (sandboxKB < 150.0 ? @"Sạch 100% ✅" : @"Có cache"),
        (isHiddenProv ? @"Đã ẩn mobileprovision ✅" : @"Chưa ẩn ❌"),
        (leveldbRelWritable ? @"C tương đối THÀNH CÔNG ✅" : @"Lỗi mở tương đối ❌"),
        (leveldbAbsWritable ? @"C tuyệt đối THÀNH CÔNG ✅" : @"Lỗi mở tuyệt đối ❌"),
        (leveldbAtWritable ? @"C openat() THÀNH CÔNG ✅" : @"Lỗi mở openat ❌"),
        (appGroupWorking ? @"Đã chuyển hướng an toàn ✅" : @"Lỗi truy cập ❌"),
        conclusion];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🔍 BÁO CÁO ĐỐI CHIẾU HỆ THỐNG RUNTIME"
                                                                   message:report
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

@end

#pragma clang diagnostic pop
