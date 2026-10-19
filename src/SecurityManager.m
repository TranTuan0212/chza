#import "SecurityManager.h"
#import "Obfuscation.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

#define SUPABASE_RPC_URL        GET_SUPABASE_RPC_URL()
#define SUPABASE_API_KEY        GET_SUPABASE_API_KEY()
#define SHARED_SECRET_SALT      GET_SHARED_SECRET_SALT()
#define LICENSE_STORAGE_PATH    GET_LICENSE_STORAGE_PATH()

static NSString *get_roothide_license_path(void) {
    typedef const char* (*jbroot_fn_t)(const char*);
    jbroot_fn_t jbroot_fn = (jbroot_fn_t)dlsym(RTLD_DEFAULT, "jbroot");
    if (jbroot_fn) {
        const char *p = jbroot_fn([LICENSE_STORAGE_PATH UTF8String]);
        if (p) return [NSString stringWithUTF8String:p];
    }
    return LICENSE_STORAGE_PATH;
}

@interface ZTSecurityManager ()
@property (nonatomic, copy, readwrite) NSString *realUDID;
@property (nonatomic, copy, readwrite, nullable) NSString *currentLicenseKey;
@property (nonatomic, copy, readwrite, nullable) NSDate *expiryDate;
@property (nonatomic, assign, readwrite) BOOL isLicenseActive;
@property (nonatomic, assign) NSTimeInterval lastCheckTime;
@end

static uint64_t s_cached_guard_token = 0;
static IMP s_expected_isLicenseValid_imp = NULL;

@implementation ZTSecurityManager

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Method m = class_getInstanceMethod([ZTSecurityManager class], @selector(isLicenseValid));
        if (m) {
            s_expected_isLicenseValid_imp = method_getImplementation(m);
        }
    });
}

+ (instancetype)sharedManager {
    static ZTSecurityManager *instance = nil;
    if (instance) return instance;
    static BOOL s_in_init = NO;
    if (s_in_init) return instance;
    s_in_init = YES;
    instance = [[ZTSecurityManager alloc] init];
    s_in_init = NO;
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _realUDID = [self resolveHardwareUDID];
        [self loadCachedLicense];
    }
    return self;
}

// 1. LẤY UDID PHẦN CỨNG THẬT QUA LIBGIBGALT HOẶC IOKIT
- (NSString *)resolveHardwareUDID {
    // Cách 1: MobileGestalt (Chuẩn nhất trên iOS Jailbreak / Rootless)
    typedef CFTypeRef (*MGCopyAnswerFunc)(CFStringRef property);
    void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_GLOBAL | RTLD_LAZY);
    if (gestalt) {
        MGCopyAnswerFunc func = (MGCopyAnswerFunc)dlsym(gestalt, "MGCopyAnswer");
        if (func) {
            CFTypeRef answer = func(CFSTR("UniqueDeviceID"));
            if (answer) {
                NSString *udid = [(__bridge id)answer copy];
                CFRelease(answer);
                if (udid && udid.length >= 16) {
                    dlclose(gestalt);
                    return [udid lowercaseString];
                }
            }
        }
        dlclose(gestalt);
    }

    // Cách 2: sysctl hw.uuid
    char uuid_str[128] = {0};
    size_t size = sizeof(uuid_str);
    if (sysctlbyname("hw.uuid", uuid_str, &size, NULL, 0) == 0 && strlen(uuid_str) > 0) {
        return [[NSString stringWithUTF8String:uuid_str] lowercaseString];
    }

    // Cách 3: Đọc file lockdownd pairing nếu có quyền root
    NSString *pairPath = @"/var/root/Library/Lockdown/pair_records";
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pairPath error:nil];
    for (NSString *file in files) {
        if ([file hasSuffix:@".plist"]) {
            NSString *candidate = [file stringByDeletingPathExtension];
            if (candidate.length >= 24) {
                return [candidate lowercaseString];
            }
        }
    }

    // Fallback: Tạo định danh cố định theo máy
    return @"00008101-unknown-udid";
}

- (NSString *)getRealHardwareUDID {
    return self.realUDID ?: @"Đang tải UDID...";
}

// 2. TÍNH TOÁN CHỮ KÝ SỐ HMAC-SHA256
static NSString *computeHMACSHA256(NSString *data, NSString *key) {
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [data cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];

    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", cHMAC[i]];
    }
    return [hex lowercaseString];
}

// 3. ĐỌC DỮ LIỆU BẢN QUYỀN ĐÃ LƯU TẠI MÁY
- (void)loadCachedLicense {
    NSDictionary *dict = nil;
    NSString *loadedFrom = nil;

    // 1. Thử đọc từ đường dẫn preferences của container hiện tại
    NSString *path = [self getLicenseFilePath];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        dict = [NSDictionary dictionaryWithContentsOfFile:path];
        if (dict) loadedFrom = path;
    }

    // 2. Fallback đọc từ Documents nếu Preferences bị tác động
    if (!dict) {
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *backupPath = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.license.plist"];
            if ([[NSFileManager defaultManager] fileExistsAtPath:backupPath]) {
                dict = [NSDictionary dictionaryWithContentsOfFile:backupPath];
                if (dict) loadedFrom = backupPath;
            }
        }
    }

    // 3. Fallback đọc từ Roothide / Global Preferences (/var/mobile/Library/Preferences/...)
    NSString *rhLicPath = get_roothide_license_path();
    if (!dict && [[NSFileManager defaultManager] fileExistsAtPath:rhLicPath]) {
        dict = [NSDictionary dictionaryWithContentsOfFile:rhLicPath];
        if (dict) loadedFrom = rhLicPath;
    }
    if (!dict && ![rhLicPath isEqualToString:LICENSE_STORAGE_PATH] && [[NSFileManager defaultManager] fileExistsAtPath:LICENSE_STORAGE_PATH]) {
        dict = [NSDictionary dictionaryWithContentsOfFile:LICENSE_STORAGE_PATH];
        if (dict) loadedFrom = LICENSE_STORAGE_PATH;
    }

    // 4. Fallback đọc từ Shared AppGroup của Zalo
    if (!dict) {
        NSArray *groupNames = @[@"group.vn.com.vng.zingalo", @"group.com.vng.zalo", @"group.com.zing.zalo"];
        for (NSString *grp in groupNames) {
            NSURL *grpURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:grp];
            if (grpURL) {
                NSString *grpFile = [grpURL.path stringByAppendingPathComponent:@"com.sonhu.zalotweak.license.plist"];
                if ([[NSFileManager defaultManager] fileExistsAtPath:grpFile]) {
                    dict = [NSDictionary dictionaryWithContentsOfFile:grpFile];
                    if (dict) {
                        loadedFrom = grpFile;
                        break;
                    }
                }
            }
        }
    }

    // 5. Fallback đọc từ CFPreferences (cfprefsd - hỗ trợ vượt rào sandbox hoàn hảo)
    if (!dict) {
        CFPreferencesAppSynchronize((__bridge CFStringRef)GET_PREFS_ID());
        CFDictionaryRef cfDict = CFPreferencesCopyMultiple(NULL, (__bridge CFStringRef)GET_PREFS_ID(), kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        if (cfDict) {
            dict = [NSDictionary dictionaryWithDictionary:(__bridge NSDictionary *)cfDict];
            CFRelease(cfDict);
            if (dict.count > 0 && (dict[GET_KEY_LICENSE_KEY()] || dict[@"license_key"]) && (dict[GET_KEY_TOKEN()] || dict[@"token"])) {
                loadedFrom = [NSString stringWithFormat:@"cfprefsd:%@", GET_PREFS_ID()];
            } else {
                dict = nil;
            }
        }
    }
    if (!dict) {
        id k = (__bridge_transfer id)CFPreferencesCopyAppValue((__bridge CFStringRef)GET_KEY_LICENSE_KEY(), (__bridge CFStringRef)GET_PREFS_ID());
        id t = (__bridge_transfer id)CFPreferencesCopyAppValue((__bridge CFStringRef)GET_KEY_TOKEN(), (__bridge CFStringRef)GET_PREFS_ID());
        id exp = (__bridge_transfer id)CFPreferencesCopyAppValue((__bridge CFStringRef)GET_KEY_EXPIRES_AT(), (__bridge CFStringRef)GET_PREFS_ID());
        id chk = (__bridge_transfer id)CFPreferencesCopyAppValue((__bridge CFStringRef)GET_KEY_LAST_CHECK(), (__bridge CFStringRef)GET_PREFS_ID());
        id rudid = (__bridge_transfer id)CFPreferencesCopyAppValue((__bridge CFStringRef)GET_KEY_REAL_UDID(), (__bridge CFStringRef)GET_PREFS_ID());
        if (k && t && exp) {
            NSMutableDictionary *m = [NSMutableDictionary dictionaryWithDictionary:@{
                GET_KEY_LICENSE_KEY(): k,
                GET_KEY_TOKEN(): t,
                GET_KEY_EXPIRES_AT(): exp,
                GET_KEY_LAST_CHECK(): chk ?: @([[NSDate date] timeIntervalSince1970])
            }];
            if (rudid) m[GET_KEY_REAL_UDID()] = rudid;
            dict = m;
            loadedFrom = [NSString stringWithFormat:@"cfprefsd:%@", GET_PREFS_ID()];
        }
    }

    if (!dict) {
        self.isLicenseActive = NO;
        return;
    }

    NSString *savedKey = dict[GET_KEY_LICENSE_KEY()] ?: dict[@"license_key"];
    NSString *savedToken = dict[GET_KEY_TOKEN()] ?: dict[@"token"];
    NSString *savedExpiryStr = dict[GET_KEY_EXPIRES_AT()] ?: dict[@"expires_at"];
    NSTimeInterval savedCheck = [(dict[GET_KEY_LAST_CHECK()] ?: dict[@"last_check"]) doubleValue];

    if (!savedKey || !savedToken || !savedExpiryStr) {
        self.isLicenseActive = NO;
        return;
    }

    // Format ISO 8601 (hỗ trợ cả mili-giây .SSS và múi giờ)
    NSISO8601DateFormatter *formatter = [[NSISO8601DateFormatter alloc] init];
    formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;
    NSDate *expDate = [formatter dateFromString:savedExpiryStr];
    if (!expDate) {
        formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime;
        expDate = [formatter dateFromString:savedExpiryStr];
    }
    if (!expDate) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setLocale:[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]];
        [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
        [df setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
        expDate = [df dateFromString:savedExpiryStr];
    }
    if (!expDate) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setLocale:[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]];
        [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ssZZZZZ"];
        expDate = [df dateFromString:savedExpiryStr];
    }
    if (!expDate) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setLocale:[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]];
        [df setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
        [df setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
        expDate = [df dateFromString:savedExpiryStr];
    }

    if (!expDate || [expDate compare:[NSDate date]] != NSOrderedDescending) {
        // Đã quá ngày hết hạn
        self.isLicenseActive = NO;
        self.expiryDate = expDate;
        self.currentLicenseKey = savedKey;
        return;
    }

    // Lấy UDID hợp lệ (ưu tiên UDID đã được lưu từ Cài Đặt Settings để vượt rào Sandbox Zalo)
    // Lấy UDID hợp lệ (ưu tiên UDID đã được lưu từ Cài Đặt Settings để vượt rào Sandbox Zalo)
    NSString *effectiveUDID = self.realUDID;
    NSString *savedUDID = dict[GET_KEY_REAL_UDID()] ?: dict[@"real_udid"];
    if (!savedUDID || savedUDID.length == 0) {
        savedUDID = (__bridge_transfer NSString *)CFPreferencesCopyAppValue((__bridge CFStringRef)GET_KEY_REAL_UDID(), (__bridge CFStringRef)GET_PREFS_ID());
    }
    if (savedUDID && savedUDID.length >= 16) {
        effectiveUDID = [savedUDID lowercaseString];
    }

    // Kiểm tra tính toàn vẹn của Token (Chống sửa file plist để hack hạn dùng)
    NSString *rawPayload = [NSString stringWithFormat:@"%@:%@:%@", savedKey, effectiveUDID, savedExpiryStr];
    NSString *expectedToken = computeHMACSHA256(rawPayload, SHARED_SECRET_SALT);

    if ([expectedToken isEqualToString:savedToken]) {
        self.isLicenseActive = YES;
        self.currentLicenseKey = savedKey;
        self.expiryDate = expDate;
        self.lastCheckTime = savedCheck;
        self.realUDID = effectiveUDID;
        s_cached_guard_token = (uint64_t)[expDate timeIntervalSince1970] ^ 0xA5A55A5ADEADBEEFULL;

        // Nếu file được đọc từ nguồn khác (ví dụ Global hay AppGroup), tự động copy lưu vào container hiện tại để truy xuất nhanh
        if (loadedFrom && ![loadedFrom isEqualToString:path]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
            [dict writeToFile:path atomically:YES];
            chmod([path UTF8String], 0666);
        }
    } else {
        self.isLicenseActive = NO; // Token bị can thiệp!
        s_cached_guard_token = 0;
    }
}

// 4. LƯU THÔNG TIN BẢN QUYỀN
- (void)saveLicenseWithKey:(NSString *)key expiresAt:(NSString *)expiryStr token:(NSString *)token {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[GET_KEY_LICENSE_KEY()] = key;
    dict[GET_KEY_EXPIRES_AT()] = expiryStr;
    dict[GET_KEY_TOKEN()] = token;
    dict[GET_KEY_REAL_UDID()] = self.realUDID ?: @"";
    dict[GET_KEY_LAST_CHECK()] = @([[NSDate date] timeIntervalSince1970]);

    // 1. Lưu tại getLicenseFilePath
    NSString *path = [self getLicenseFilePath];
    [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    [dict writeToFile:path atomically:YES];
    chmod([path UTF8String], 0666);

    // 2. Lưu thêm 1 bản dự phòng trong Documents để tuyệt đối không bị mất key khi dọn dẹp
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *backupPath = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.license.plist"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[backupPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:backupPath atomically:YES];
        chmod([backupPath UTF8String], 0666);
    }

    // 3. Nếu có quyền, lưu vào Roothide / Global Preferences (/var/mobile/Library/Preferences)
    NSString *rhLicPath = get_roothide_license_path();
    [[NSFileManager defaultManager] createDirectoryAtPath:[rhLicPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    [dict writeToFile:rhLicPath atomically:YES];
    chmod([rhLicPath UTF8String], 0666);

    if (![rhLicPath isEqualToString:LICENSE_STORAGE_PATH]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:[LICENSE_STORAGE_PATH stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:LICENSE_STORAGE_PATH atomically:YES];
        chmod([LICENSE_STORAGE_PATH UTF8String], 0666);
    }

    // 4. Lưu vào các Shared AppGroup
    NSArray *groupNames = @[@"group.vn.com.vng.zingalo", @"group.com.vng.zalo", @"group.com.zing.zalo"];
    for (NSString *grp in groupNames) {
        NSURL *grpURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:grp];
        if (grpURL) {
            NSString *grpFile = [grpURL.path stringByAppendingPathComponent:@"com.sonhu.zalotweak.license.plist"];
            [dict writeToFile:grpFile atomically:YES];
            chmod([grpFile UTF8String], 0666);
        }
    }

    // 5. Lưu vào CFPreferences để cfprefsd đồng bộ xuyên sandbox
    CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_LICENSE_KEY(), (__bridge CFPropertyListRef)key, (__bridge CFStringRef)GET_PREFS_ID());
    CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_EXPIRES_AT(), (__bridge CFPropertyListRef)expiryStr, (__bridge CFStringRef)GET_PREFS_ID());
    CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_TOKEN(), (__bridge CFPropertyListRef)token, (__bridge CFStringRef)GET_PREFS_ID());
    if (self.realUDID) CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_REAL_UDID(), (__bridge CFPropertyListRef)self.realUDID, (__bridge CFStringRef)GET_PREFS_ID());
    CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_LAST_CHECK(), (__bridge CFPropertyListRef)@([[NSDate date] timeIntervalSince1970]), (__bridge CFStringRef)GET_PREFS_ID());
    CFPreferencesAppSynchronize((__bridge CFStringRef)GET_PREFS_ID());

    [self loadCachedLicense];
}

- (NSString *)getLicenseFilePath {
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *containerPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.license.plist"];
        return containerPref;
    }
    return LICENSE_STORAGE_PATH;
}

// 5. KIỂM TRA BẢN QUYỀN REALTIME (ĐƯỢC GỌI TỪ TWEAK.X)
- (BOOL)isLicenseValid {
    return ZTSecurityCheckLicenseFast();
}

// ==============================================================================
// C-LEVEL FAST LICENSE CHECK & ANTI-TAMPER IMPLEMENTATION
// ==============================================================================

BOOL ZTSecurityDetectTampering(void) {
    // 1. Kiểm tra debugger (LLDB, DebugServer, GDB, IDA Pro)
    if (zt_is_debugger_attached()) {
        return YES;
    }

    // 2. Kiểm tra ARM64 function prologue của hàm kiểm tra bản quyền (Anti-Dobby/Anti-Substrate/Anti-Frida/Anti-HexPatch)
    if (!zt_verify_code_prologue((const void *)&ZTSecurityCheckLicenseFast)) {
        return YES;
    }

    // 3. Kiểm tra Flex 3 / Frida swizzling trên -[ZTSecurityManager isLicenseValid]
    if (s_expected_isLicenseValid_imp) {
        Method m = class_getInstanceMethod([ZTSecurityManager class], @selector(isLicenseValid));
        if (m) {
            IMP cur = method_getImplementation(m);
#if defined(__has_feature)
#if __has_feature(ptrauth_calls)
            cur = (IMP)__builtin_ptrauth_strip((void *)cur, 0);
            IMP exp = (IMP)__builtin_ptrauth_strip((void *)s_expected_isLicenseValid_imp, 0);
            if (cur != exp) return YES;
#else
            if (cur != s_expected_isLicenseValid_imp) return YES;
#endif
#else
            if (cur != s_expected_isLicenseValid_imp) return YES;
#endif
        }
    }
    return NO;
}

BOOL ZTSecurityCheckLicenseFast(void) {
    // Nếu phát hiện can thiệp debug, hook, hay swizzle -> từ chối bản quyền
    if (ZTSecurityDetectTampering()) {
        return NO;
    }

    ZTSecurityManager *mgr = [ZTSecurityManager sharedManager];
    if (!mgr.isLicenseActive || !mgr.expiryDate) {
        return NO;
    }

    // Kiểm tra guard token để chống cracker can thiệp sửa trực tiếp property isLicenseActive = YES
    uint64_t expected_guard = (uint64_t)[mgr.expiryDate timeIntervalSince1970] ^ 0xA5A55A5ADEADBEEFULL;
    if (s_cached_guard_token != expected_guard) {
        return NO;
    }

    // Kiểm tra hết hạn thời gian thực
    if ([[NSDate date] compare:mgr.expiryDate] == NSOrderedDescending) {
        mgr.isLicenseActive = NO;
        s_cached_guard_token = 0;
        return NO;
    }

    return YES;
}

// 6. XÂY DỰNG CHUỖI HIỂN THỊ TRÊN CÀI ĐẶT
- (NSString *)getLicenseStatusText {
    if (!self.isLicenseActive) {
        if (self.expiryDate && [[NSDate date] compare:self.expiryDate] == NSOrderedDescending) {
            return @"❌ Bản quyền đã HẾT HẠN!";
        }
        return @"🔴 Chưa kích hoạt bản quyền";
    }

    if (!self.expiryDate) {
        return @"🟢 Đã kích hoạt";
    }

    NSTimeInterval diff = [self.expiryDate timeIntervalSinceNow];
    if (diff <= 0) {
        return @"❌ Đã hết hạn";
    }

    NSInteger days = (NSInteger)(diff / 86400);
    NSInteger hours = (NSInteger)(((uint64_t)diff % 86400) / 3600);

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setDateFormat:@"dd/MM/yyyy HH:mm"];
    NSString *dateStr = [df stringFromDate:self.expiryDate];

    if (days > 3650) {
        return @"🟢 Hợp lệ: Bản quyền Doanh Nghiệp (Không giới hạn)";
    } else if (days > 0) {
        return [NSString stringWithFormat:@"🟢 Hợp lệ: Còn %ld ngày %ld giờ (Hết: %@)", (long)days, (long)hours, dateStr];
    } else {
        NSInteger mins = (NSInteger)(((uint64_t)diff % 3600) / 60);
        return [NSString stringWithFormat:@"⚠️ Sắp hết: Còn %ld giờ %ld phút (Hết: %@)", (long)hours, (long)mins, dateStr];
    }
}

// 7. GỌI API SUPABASE RPC XÁC THỰC KEY
- (void)verifyLicenseWithKey:(NSString *)licenseKey completion:(void (^)(BOOL success, NSString *message))completion {
    NSString *cleanKey = [licenseKey stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!cleanKey || cleanKey.length == 0) {
        if (completion) completion(NO, @"Vui lòng nhập License Key!");
        return;
    }

    NSString *udid = self.realUDID;
    NSString *deviceModel = @"iPhone";

    // Tạo Body JSON gửi đến Supabase
    NSDictionary *params = @{
        @"p_license_key": cleanKey,
        @"p_udid": udid,
        @"p_model": deviceModel
    };

    NSError *err;
    NSData *postData = [NSJSONSerialization dataWithJSONObject:params options:0 error:&err];
    if (!postData) {
        if (completion) completion(NO, @"Lỗi khởi tạo dữ liệu JSON!");
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:SUPABASE_RPC_URL]];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:SUPABASE_API_KEY forHTTPHeaderField:GET_APIKEY_HEADER()];
    [request setValue:[NSString stringWithFormat:@"%@%@", GET_BEARER_PREFIX(), SUPABASE_API_KEY] forHTTPHeaderField:GET_AUTH_HEADER()];
    [request setHTTPBody:postData];
    [request setTimeoutInterval:15.0];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.connectionProxyDictionary = @{}; // Bypass proxy: Luôn kết nối trực tiếp đến Supabase để đảm bảo kiểm tra Key không bị chặn nếu proxy lỗi
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];

    [[session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                if (completion) completion(NO, [NSString stringWithFormat:@"Lỗi kết nối máy chủ: %@", error.localizedDescription]);
                return;
            }

            if (!data) {
                if (completion) completion(NO, @"Không nhận được phản hồi từ Supabase!");
                return;
            }

            NSError *jsonErr;
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonErr];
            if (!json || ![json isKindOfClass:[NSDictionary class]]) {
                NSString *rawStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (completion) completion(NO, [NSString stringWithFormat:@"Phản hồi không hợp lệ: %@", rawStr ?: @"(trống)"]);
                return;
            }

            BOOL isValid = [json[@"valid"] boolValue];
            NSString *msg = json[@"message"] ?: @"Đã xử lý";
            NSString *expiryStr = json[@"expires_at"];
            NSString *token = json[@"token"];

            if (isValid && expiryStr && token) {
                // Xác thực token tính ngược
                NSString *rawPayload = [NSString stringWithFormat:@"%@:%@:%@", cleanKey, udid, expiryStr];
                NSString *expectedToken = computeHMACSHA256(rawPayload, SHARED_SECRET_SALT);

                if ([expectedToken isEqualToString:token]) {
                    [self saveLicenseWithKey:cleanKey expiresAt:expiryStr token:token];
                    if (completion) completion(YES, msg);
                } else {
                    if (completion) completion(NO, @"Chữ ký số Server không khớp (Cảnh báo gian lận)!");
                }
            } else {
                [self resetLicense];
                if (completion) completion(NO, msg);
            }
        });
    }] resume];
}

- (void)resetLicense {
    self.isLicenseActive = NO;
    self.currentLicenseKey = nil;
    self.expiryDate = nil;
    s_cached_guard_token = 0;

    NSString *path = [self getLicenseFilePath];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];

    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *backupPath = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.license.plist"];
        [[NSFileManager defaultManager] removeItemAtPath:backupPath error:nil];
    }
    [[NSFileManager defaultManager] removeItemAtPath:LICENSE_STORAGE_PATH error:nil];

    NSArray *groupNames = @[@"group.vn.com.vng.zingalo", @"group.com.vng.zalo", @"group.com.zing.zalo"];
    for (NSString *grp in groupNames) {
        NSURL *grpURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:grp];
        if (grpURL) {
            NSString *grpFile = [grpURL.path stringByAppendingPathComponent:@"com.sonhu.zalotweak.license.plist"];
            [[NSFileManager defaultManager] removeItemAtPath:grpFile error:nil];
        }
    }

    CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_LICENSE_KEY(), NULL, (__bridge CFStringRef)GET_PREFS_ID());
    CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_EXPIRES_AT(), NULL, (__bridge CFStringRef)GET_PREFS_ID());
    CFPreferencesSetAppValue((__bridge CFStringRef)GET_KEY_TOKEN(), NULL, (__bridge CFStringRef)GET_PREFS_ID());
    CFPreferencesAppSynchronize((__bridge CFStringRef)GET_PREFS_ID());
}

@end
