#import "SecurityManager.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

#define SUPABASE_RPC_URL @"https://litfhujpobscqwpuhzvv.supabase.co/rest/v1/rpc/verify_license"
#define SUPABASE_API_KEY @"sb_publishable_4FuIC_rnNLkbihAIiTLUaA_f15jK9f3"
#define SHARED_SECRET_SALT @"ZaloTweakSecuredSalt2026!@#$"
#define LICENSE_STORAGE_PATH @"/var/mobile/Library/Preferences/com.sonhu.zalotweak.license.plist"

@interface ZTSecurityManager ()
@property (nonatomic, copy, readwrite) NSString *realUDID;
@property (nonatomic, copy, readwrite, nullable) NSString *currentLicenseKey;
@property (nonatomic, copy, readwrite, nullable) NSDate *expiryDate;
@property (nonatomic, assign, readwrite) BOOL isLicenseActive;
@property (nonatomic, assign) NSTimeInterval lastCheckTime;
@end

@implementation ZTSecurityManager

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

    // 3. Fallback đọc từ Global Preferences (/var/mobile/Library/Preferences/...)
    if (!dict && [[NSFileManager defaultManager] fileExistsAtPath:LICENSE_STORAGE_PATH]) {
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

    if (!dict) {
        self.isLicenseActive = NO;
        return;
    }

    NSString *savedKey = dict[@"license_key"];
    NSString *savedToken = dict[@"token"];
    NSString *savedExpiryStr = dict[@"expires_at"];
    NSTimeInterval savedCheck = [dict[@"last_check"] doubleValue];

    if (!savedKey || !savedToken || !savedExpiryStr) {
        self.isLicenseActive = NO;
        return;
    }

    // Format ISO 8601
    NSISO8601DateFormatter *formatter = [[NSISO8601DateFormatter alloc] init];
    NSDate *expDate = [formatter dateFromString:savedExpiryStr];
    if (!expDate) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
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

    // Kiểm tra tính toàn vẹn của Token (Chống sửa file plist để hack hạn dùng)
    NSString *rawPayload = [NSString stringWithFormat:@"%@:%@:%@", savedKey, self.realUDID, savedExpiryStr];
    NSString *expectedToken = computeHMACSHA256(rawPayload, SHARED_SECRET_SALT);

    if ([expectedToken isEqualToString:savedToken]) {
        self.isLicenseActive = YES;
        self.currentLicenseKey = savedKey;
        self.expiryDate = expDate;
        self.lastCheckTime = savedCheck;

        // Nếu file được đọc từ nguồn khác (ví dụ Global hay AppGroup), tự động copy lưu vào container hiện tại để truy xuất nhanh
        if (loadedFrom && ![loadedFrom isEqualToString:path]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
            [dict writeToFile:path atomically:YES];
            chmod([path UTF8String], 0666);
        }
    } else {
        self.isLicenseActive = NO; // Token bị can thiệp!
    }
}

// 4. LƯU THÔNG TIN BẢN QUYỀN
- (void)saveLicenseWithKey:(NSString *)key expiresAt:(NSString *)expiryStr token:(NSString *)token {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"license_key"] = key;
    dict[@"expires_at"] = expiryStr;
    dict[@"token"] = token;
    dict[@"last_check"] = @([[NSDate date] timeIntervalSince1970]);

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

    // 3. Nếu có quyền, lưu vào Global Preferences (/var/mobile/Library/Preferences)
    if (![path isEqualToString:LICENSE_STORAGE_PATH]) {
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
    if (!self.isLicenseActive || !self.expiryDate) {
        return NO;
    }
    // Đảm bảo thời gian hiện tại chưa vượt quá expiryDate
    if ([[NSDate date] compare:self.expiryDate] == NSOrderedDescending) {
        self.isLicenseActive = NO;
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

    if (days > 0) {
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
    [request setValue:SUPABASE_API_KEY forHTTPHeaderField:@"apikey"];
    [request setValue:[NSString stringWithFormat:@"Bearer %@", SUPABASE_API_KEY] forHTTPHeaderField:@"Authorization"];
    [request setHTTPBody:postData];
    [request setTimeoutInterval:15.0];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
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
}

@end
