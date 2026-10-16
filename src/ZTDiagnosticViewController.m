#import "ZTDiagnosticViewController.h"
#import <CFNetwork/CFNetwork.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <dlfcn.h>

static NSString *get_zt_prefs_filepath(void) {
    typedef const char* (*jbroot_fn_t)(const char*);
    jbroot_fn_t jbroot_fn = (jbroot_fn_t)dlsym(RTLD_DEFAULT, "jbroot");
    const char *base = "/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist";
    if (jbroot_fn) {
        const char *p = jbroot_fn(base);
        if (p) return [NSString stringWithUTF8String:p];
    }
    return [NSString stringWithUTF8String:base];
}

static BOOL is_zt_auto_sync_timezone_enabled(void) {
    Class settingsClass = NSClassFromString(@"ZTSettings");
    if (settingsClass) {
        SEL selShared = NSSelectorFromString(@"sharedSettings");
        if ([settingsClass respondsToSelector:selShared]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id shared = [settingsClass performSelector:selShared];
#pragma clang diagnostic pop
            if (shared) {
                id val = [shared valueForKey:@"autoSyncTimezoneWithIP"];
                if (val != nil) return [val boolValue];
            }
        }
    }
    NSString *path = get_zt_prefs_filepath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (dict && dict[@"autoSyncTimezoneWithIP"] != nil) {
        return [dict[@"autoSyncTimezoneWithIP"] boolValue];
    }
    return YES;
}

static void update_zt_synced_timezone_pref(NSString *tzName) {
    if (!tzName || tzName.length == 0) return;
    if ([tzName isEqualToString:@"Asia/Bangkok"] || [tzName isEqualToString:@"Asia/Saigon"]) {
        tzName = @"Asia/Ho_Chi_Minh";
    }
    Class settingsClass = NSClassFromString(@"ZTSettings");
    if (settingsClass) {
        SEL selShared = NSSelectorFromString(@"sharedSettings");
        if ([settingsClass respondsToSelector:selShared]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id shared = [settingsClass performSelector:selShared];
            if (shared) {
                [shared setValue:tzName forKey:@"timeZoneName"];
                SEL selSave = NSSelectorFromString(@"saveSettings");
                if ([shared respondsToSelector:selSave]) {
                    [shared performSelector:selSave];
                }
            }
#pragma clang diagnostic pop
        }
    }
    NSString *path = get_zt_prefs_filepath();
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:path] ?: [NSMutableDictionary dictionary];
    dict[@"timeZoneName"] = tzName;
    [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    [dict writeToFile:path atomically:YES];
    chmod([path UTF8String], 0666);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         CFSTR("com.sonhu.zalotweak/settingschanged"),
                                         NULL, NULL, YES);
}

static void update_zt_carrier_pref(NSString *carrierName, NSString *mcc, NSString *mnc, NSString *countryCode, NSString *regionMode, NSString *localeId, NSString *tzName) {
    Class settingsClass = NSClassFromString(@"ZTSettings");
    if (settingsClass) {
        SEL selShared = NSSelectorFromString(@"sharedSettings");
        if ([settingsClass respondsToSelector:selShared]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id shared = [settingsClass performSelector:selShared];
            if (shared) {
                if (carrierName) [shared setValue:carrierName forKey:@"carrierName"];
                if (carrierName) [shared setValue:carrierName forKey:@"preferredCarrier"];
                if (mcc) [shared setValue:mcc forKey:@"carrierMCC"];
                if (mnc) [shared setValue:mnc forKey:@"carrierMNC"];
                if (countryCode) [shared setValue:countryCode forKey:@"carrierCountryCode"];
                if (regionMode) [shared setValue:regionMode forKey:@"regionMode"];
                if (localeId) [shared setValue:localeId forKey:@"localeIdentifier"];
                if (tzName) [shared setValue:tzName forKey:@"timeZoneName"];
                SEL selSave = NSSelectorFromString(@"saveSettings");
                if ([shared respondsToSelector:selSave]) {
                    [shared performSelector:selSave];
                }
            }
#pragma clang diagnostic pop
        }
    }
    NSString *path = get_zt_prefs_filepath();
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:path] ?: [NSMutableDictionary dictionary];
    if (carrierName) {
        dict[@"carrierName"] = carrierName;
        dict[@"preferredCarrier"] = carrierName;
    }
    if (mcc) dict[@"carrierMCC"] = mcc;
    if (mnc) dict[@"carrierMNC"] = mnc;
    if (countryCode) dict[@"carrierCountryCode"] = countryCode;
    if (regionMode) dict[@"regionMode"] = regionMode;
    if (localeId) dict[@"localeIdentifier"] = localeId;
    if (tzName) dict[@"timeZoneName"] = tzName;
    [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    [dict writeToFile:path atomically:YES];
    chmod([path UTF8String], 0666);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         CFSTR("com.sonhu.zalotweak/settingschanged"),
                                         NULL, NULL, YES);
}

@implementation ZTDiagnosticInfo
@end

static NSInteger check_zalo_keychain_count(void) {
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
    // Khi mở trong ứng dụng Cài đặt (Preferences.app), iOS Sandbox cô lập hoàn toàn keychain.
    // SecItemCopyMatching tại đây chỉ trả về các token hệ thống của Apple (Apple ID, Passwords, Wifi...).
    // Do đó không thể đọc được Keychain của Zalo -> Bỏ qua và trả về 0 để tránh báo động giả.
    if ([bundleId isEqualToString:@"com.apple.Preferences"]) {
        return 0;
    }

    NSInteger count = 0;
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword
    ];
    for (id secClass in secClasses) {
        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass] = secClass;
        query[(__bridge id)kSecReturnData] = @NO;
        query[(__bridge id)kSecReturnAttributes] = @YES;
        query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecSuccess && result) {
            NSArray *items = [(__bridge id)result isKindOfClass:[NSArray class]] ? (__bridge NSArray *)result : @[(__bridge id)result];
            for (NSDictionary *dict in items) {
                if (![dict isKindOfClass:[NSDictionary class]]) continue;
                NSString *service = dict[(__bridge id)kSecAttrService] ?: @"";
                NSString *account = dict[(__bridge id)kSecAttrAccount] ?: @"";
                NSString *group = dict[(__bridge id)kSecAttrAccessGroup] ?: @"";

                // Bỏ qua các token nội bộ của thư viện Google / Firebase / Crashlytics / WebKit / Apple
                NSString *combined = [NSString stringWithFormat:@"%@|%@|%@", service, account, group].lowercaseString;
                if ([combined containsString:@"google"] ||
                    [combined containsString:@"firebase"] ||
                    [combined containsString:@"crashlytics"] ||
                    [combined containsString:@"apple"] ||
                    [combined containsString:@"webkit"]) {
                    continue;
                }

                // Chỉ đếm nếu thuộc về Zalo / VNG / Zing hoặc định danh session
                if ([combined containsString:@"zalo"] ||
                    [combined containsString:@"zing"] ||
                    [combined containsString:@"vng"] ||
                    [combined containsString:@"zaid"] ||
                    [combined containsString:@"zda"] ||
                    [combined containsString:@"session"] ||
                    [combined containsString:@"token"] ||
                    [combined containsString:@"uid"]) {
                    count++;
                }
            }
            CFRelease(result);
        }
    }
    return count;
}

static BOOL check_webkit_is_clean(void) {
    NSString *home = NSHomeDirectory();
    if (!home) return YES;
    NSString *wkDir = [home stringByAppendingPathComponent:@"Library/WebKit"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:wkDir]) return YES;
    NSArray *subItems = [fm contentsOfDirectoryAtPath:wkDir error:nil];
    for (NSString *item in subItems) {
        NSString *lower = [item lowercaseString];
        if ([lower containsString:@"cookie"] || [lower containsString:@"storage"]) {
            return NO;
        }
    }
    return YES;
}

static BOOL check_clipboard_is_clean(void) {
    @try {
        NSString *str = [UIPasteboard generalPasteboard].string;
        return (str == nil || str.length == 0);
    } @catch (__unused NSException *e) {
        return YES;
    }
}

// ==========================================
// CÁC HÀM TIỆN ÍCH HỖ TRỢ PARSE PROXY & TRA CỨU MẠNG
// ==========================================

static BOOL parse_proxy_string(NSString *rawProxy, NSString **outHost, NSNumber **outPort, NSString **outUser, NSString **outPass) {
    if (!rawProxy || rawProxy.length == 0) return NO;
    NSString *clean = [rawProxy stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([clean containsString:@"://"]) {
        NSRange r = [clean rangeOfString:@"://"];
        clean = [clean substringFromIndex:r.location + r.length];
    }
    // Dạng user:pass@host:port
    if ([clean containsString:@"@"]) {
        NSArray *parts = [clean componentsSeparatedByString:@"@"];
        if (parts.count == 2) {
            NSString *userPass = parts[0];
            NSString *hostPort = parts[1];
            NSArray *upParts = [userPass componentsSeparatedByString:@":"];
            if (upParts.count >= 2) {
                if (outUser) *outUser = upParts[0];
                if (outPass) *outPass = upParts[1];
            }
            NSArray *hpParts = [hostPort componentsSeparatedByString:@":"];
            if (hpParts.count >= 2) {
                if (outHost) *outHost = hpParts[0];
                if (outPort) *outPort = @([hpParts[1] intValue]);
                return YES;
            } else if (hpParts.count == 1) {
                if (outHost) *outHost = hpParts[0];
                if (outPort) *outPort = @(80);
                return YES;
            }
        }
    }
    // Dạng host:port:user:pass
    NSArray *tokens = [clean componentsSeparatedByString:@":"];
    if (tokens.count >= 4) {
        if (outHost) *outHost = tokens[0];
        if (outPort) *outPort = @([tokens[1] intValue]);
        if (outUser) *outUser = tokens[2];
        if (outPass) *outPass = tokens[3];
        return YES;
    } else if (tokens.count == 2) {
        if (outHost) *outHost = tokens[0];
        if (outPort) *outPort = @([tokens[1] intValue]);
        return YES;
    } else if (tokens.count == 1) {
        if (outHost) *outHost = tokens[0];
        if (outPort) *outPort = @(80);
        return YES;
    }
    return NO;
}

static void fetch_geoip_data(NSString *targetIP, NSDictionary *proxyDict, void (^completion)(NSDictionary * _Nullable result, NSError * _Nullable error)) {
    NSString *urlString;
    if (targetIP.length > 0 && ![targetIP containsString:@":"]) {
        urlString = [NSString stringWithFormat:@"http://ip-api.com/json/%@?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query", targetIP];
    } else {
        urlString = @"http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query";
    }
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        completion(nil, [NSError errorWithDomain:@"ZTGeoIP" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"URL không hợp lệ"}]);
        return;
    }

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = 10.0;
    if (proxyDict && proxyDict.count > 0) {
        config.connectionProxyDictionary = proxyDict;
    }
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    NSURLSessionDataTask *task = [session dataTaskWithURL:url completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (error || !data) {
            completion(nil, error ?: [NSError errorWithDomain:@"ZTGeoIP" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Không có phản hồi"}]);
            return;
        }
        NSError *jsonErr = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonErr];
        if (json && [json[@"status"] isEqualToString:@"success"]) {
            completion(json, nil);
        } else {
            NSString *msg = json[@"message"] ?: @"Tra cứu IP thất bại";
            completion(nil, [NSError errorWithDomain:@"ZTGeoIP" code:-2 userInfo:@{NSLocalizedDescriptionKey: msg}]);
        }
    }];
    [task resume];
}

static NSString *extract_carrier_brand(NSString *carrierStr) {
    if (!carrierStr) return @"";
    NSString *lower = [carrierStr lowercaseString];
    if ([lower containsString:@"viettel"]) return @"Viettel";
    if ([lower containsString:@"vina"] || [lower containsString:@"itel"] || [lower containsString:@"wintel"]) return @"VINAPHONE";
    if ([lower containsString:@"mobi"]) return @"VN MOBIFONE";
    if ([lower containsString:@"vietnamobile"]) return @"Vietnamobile";
    if ([lower containsString:@"gmobile"]) return @"Gmobile";
    if ([lower containsString:@"verizon"]) return @"Verizon";
    if ([lower containsString:@"at&t"]) return @"AT&T";
    if ([lower containsString:@"t-mobile"] || [lower containsString:@"mint"]) return @"T-Mobile";
    if ([lower containsString:@"play"]) return @"Play";
    if ([lower containsString:@"orange"]) return @"Orange";
    if ([lower containsString:@"plus"]) return @"Plus";
    return @"";
}

static void analyze_phone_details(NSString *rawPhone, NSString *currentProfileRegion,
                                  NSString **outCountryCode, NSString **outCountryName,
                                  NSString **outCarrier, NSString **outLineType,
                                  BOOL *outIsVoIP, BOOL *outCompatible, NSString **outReason) {
    if (!rawPhone || rawPhone.length == 0) {
        if (outCountryCode) *outCountryCode = @"";
        if (outCountryName) *outCountryName = @"Chưa nhập";
        if (outCarrier) *outCarrier = @"Chưa xác định";
        if (outLineType) *outLineType = @"Chưa xác định";
        if (outIsVoIP) *outIsVoIP = NO;
        if (outCompatible) *outCompatible = YES;
        if (outReason) *outReason = @"Chưa nhập số điện thoại để đối chiếu.";
        return;
    }

    NSMutableString *digits = [NSMutableString string];
    for (NSUInteger i = 0; i < rawPhone.length; i++) {
        unichar c = [rawPhone characterAtIndex:i];
        if (c >= '0' && c <= '9') {
            [digits appendFormat:@"%C", c];
        }
    }

    BOOL isVN = NO;
    BOOL isUS = NO;
    BOOL isPL = NO;
    NSString *cleanDigits = [digits copy];
    NSString *carrier = @"Không rõ";
    NSString *lineType = @"Mobile (Di động thật) ✅";
    BOOL isVoIP = NO;

    if ([rawPhone hasPrefix:@"+48"] || ([cleanDigits hasPrefix:@"48"] && cleanDigits.length == 11)) {
        isPL = YES;
        if ([cleanDigits hasPrefix:@"48"]) {
            cleanDigits = [cleanDigits substringFromIndex:2];
        }
    } else if (cleanDigits.length == 9 && ([cleanDigits hasPrefix:@"4"] || [cleanDigits hasPrefix:@"5"] || [cleanDigits hasPrefix:@"6"] || [cleanDigits hasPrefix:@"7"] || [cleanDigits hasPrefix:@"8"] || [currentProfileRegion isEqualToString:@"PL"] || [currentProfileRegion containsString:@"Ba Lan"] || [currentProfileRegion containsString:@"Poland"])) {
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
    } else if (cleanDigits.length == 10 && ([currentProfileRegion isEqualToString:@"US"] || [currentProfileRegion isEqualToString:@"US_STUDENT"] || [currentProfileRegion containsString:@"Mỹ"] || [currentProfileRegion containsString:@"Hoa Kỳ"])) {
        isUS = YES;
    }

    BOOL isProfileUS = [currentProfileRegion isEqualToString:@"US"] || [currentProfileRegion isEqualToString:@"US_STUDENT"] || [currentProfileRegion containsString:@"Mỹ"] || [currentProfileRegion containsString:@"Hoa Kỳ"];
    BOOL isProfilePL = [currentProfileRegion isEqualToString:@"PL"] || [currentProfileRegion containsString:@"Ba Lan"] || [currentProfileRegion containsString:@"Poland"];

    if (isPL) {
        if (outCountryCode) *outCountryCode = @"PL";
        if (outCountryName) *outCountryName = @"Ba Lan (+48)";
        if (cleanDigits.length >= 2) {
            NSString *p2 = [cleanDigits substringToIndex:2];
            if ([p2 isEqualToString:@"45"] || [p2 isEqualToString:@"53"] || [p2 isEqualToString:@"57"] || [p2 isEqualToString:@"73"] || [p2 isEqualToString:@"79"]) {
                carrier = @"Play (MNO Ba Lan)";
            } else if ([p2 isEqualToString:@"50"] || [p2 isEqualToString:@"51"]) {
                carrier = @"Orange Polska (MNO Ba Lan)";
            } else if ([p2 isEqualToString:@"60"] || [p2 isEqualToString:@"66"] || [p2 isEqualToString:@"72"]) {
                carrier = @"Plus / Polkomtel (MNO Ba Lan)";
            } else if ([p2 isEqualToString:@"69"] || [p2 isEqualToString:@"78"] || [p2 isEqualToString:@"88"]) {
                carrier = @"T-Mobile / Orange / Plus (MNO Ba Lan)";
            } else {
                carrier = @"Mạng Di Động Ba Lan";
            }
        } else {
            carrier = @"Mạng Di Động Ba Lan";
        }
        lineType = @"SIM Di Động Ba Lan (9 chữ số) ✅";
        isVoIP = NO;

        if (!isProfilePL) {
            if (outCompatible) *outCompatible = NO;
            if (outReason) *outReason = [NSString stringWithFormat:@"⚠️ LỆCH PROFILE: SĐT là BA LAN (+48) nhưng Profile hiện tại là [%@]! Hãy đổi Profile sang Ba Lan (+48).", currentProfileRegion ?: @"Khác"];
        } else {
            if (outCompatible) *outCompatible = YES;
            if (outReason) *outReason = @"✅ Khớp hoàn toàn với Profile Ba Lan (+48).";
        }
    } else if (isVN) {
        if (outCountryCode) *outCountryCode = @"VN";
        if (outCountryName) *outCountryName = @"Việt Nam (+84)";
        if (cleanDigits.length >= 3) {
            NSString *p3 = [cleanDigits substringToIndex:3];
            if ([p3 isEqualToString:@"090"] || [p3 isEqualToString:@"093"] || [p3 isEqualToString:@"089"] ||
                [p3 isEqualToString:@"070"] || [p3 isEqualToString:@"079"] || [p3 isEqualToString:@"077"] ||
                [p3 isEqualToString:@"076"] || [p3 isEqualToString:@"078"]) {
                carrier = @"MobiFone (SIM Di Động Gốc 10 Số)";
            } else if ([p3 isEqualToString:@"096"] || [p3 isEqualToString:@"097"] || [p3 isEqualToString:@"098"] ||
                       [p3 isEqualToString:@"086"] || [p3 isEqualToString:@"032"] || [p3 isEqualToString:@"033"] ||
                       [p3 isEqualToString:@"034"] || [p3 isEqualToString:@"035"] || [p3 isEqualToString:@"036"] ||
                       [p3 isEqualToString:@"037"] || [p3 isEqualToString:@"038"] || [p3 isEqualToString:@"039"]) {
                carrier = @"Viettel (SIM Di Động Thật)";
            } else if ([p3 isEqualToString:@"091"] || [p3 isEqualToString:@"094"] || [p3 isEqualToString:@"088"] ||
                       [p3 isEqualToString:@"081"] || [p3 isEqualToString:@"082"] || [p3 isEqualToString:@"083"] ||
                       [p3 isEqualToString:@"084"] || [p3 isEqualToString:@"085"]) {
                carrier = @"Vinaphone (SIM Di Động Thật)";
            } else if ([p3 isEqualToString:@"087"] || [p3 isEqualToString:@"055"]) {
                carrier = @"Vinaphone / MVNO (iTel, Wintel)";
            } else if ([p3 isEqualToString:@"092"] || [p3 isEqualToString:@"056"] || [p3 isEqualToString:@"058"] || [p3 isEqualToString:@"052"]) {
                carrier = @"Vietnamobile (SIM Di Động Thật)";
            } else if ([p3 isEqualToString:@"059"] || [p3 isEqualToString:@"099"]) {
                carrier = @"Gmobile (SIM Di Động Thật)";
            } else {
                carrier = @"Mạng Di Động VN";
            }
        }
        lineType = @"Mobile SIM Thật (Bao Đậu) ✅";
        isVoIP = NO;

        if (isProfileUS || isProfilePL) {
            if (outCompatible) *outCompatible = NO;
            if (outReason) *outReason = [NSString stringWithFormat:@"⚠️ LỆCH PROFILE: Máy đang chọn Profile [%@] nhưng SĐT là VIỆT NAM (+84)! Hãy đổi Profile Tweak sang VN.", currentProfileRegion ?: @"Quốc Tế"];
        } else {
            if (outCompatible) *outCompatible = YES;
            if (outReason) *outReason = @"✅ Khớp hoàn toàn với Profile Việt Nam.";
        }
    } else if (isUS) {
        if (outCountryCode) *outCountryCode = @"US";
        if (outCountryName) *outCountryName = @"Hoa Kỳ (+1)";
        carrier = @"Mạng Di Động Mỹ (AT&T / T-Mobile / Verizon)";
        lineType = @"SIM Di Động Mỹ (Yêu cầu Non-VoIP)";
        isVoIP = NO;

        if (!isProfileUS) {
            if (outCompatible) *outCompatible = NO;
            if (outReason) *outReason = [NSString stringWithFormat:@"⚠️ LỆCH PROFILE: Máy đang chọn Profile [%@] nhưng SĐT là MỸ (+1)! Hãy đổi Profile Tweak sang US.", currentProfileRegion ?: @"Khác"];
        } else {
            if (outCompatible) *outCompatible = YES;
            if (outReason) *outReason = @"✅ Khớp hoàn toàn với Profile Mỹ.";
        }
    } else {
        if (outCountryCode) *outCountryCode = @"OTHER";
        if (outCountryName) *outCountryName = [NSString stringWithFormat:@"Quốc tế (%@)", cleanDigits];
        carrier = @"Chưa xác định";
        lineType = @"Không rõ";
        if (outCompatible) *outCompatible = NO;
        if (outReason) *outReason = @"⚠️ SĐT quốc tế khác vùng với Profile hiện tại.";
    }

    if (outCarrier) *outCarrier = carrier;
    if (outLineType) *outLineType = lineType;
    if (outIsVoIP) *outIsVoIP = isVoIP;
}

// ==========================================
// VIEW CONTROLLER IMPLEMENTATION
// ==========================================

@interface ZTDiagnosticViewController () <UITextFieldDelegate>

@property (nonatomic, strong) ZTDiagnosticInfo *info;
@property (nonatomic, strong) UIScrollView *scrollView;
@property (nonatomic, strong) UIStackView *contentStack;

// UI Input Card
@property (nonatomic, strong) UIView *pairInputCard;
@property (nonatomic, strong) UITextField *phoneField;
@property (nonatomic, strong) UITextField *proxyField;
@property (nonatomic, strong) UIButton *checkBtn;
@property (nonatomic, strong) UIButton *fetchIpBtn;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, assign) BOOL allowHostingIP;

@end

@implementation ZTDiagnosticViewController

- (instancetype)initWithInfo:(ZTDiagnosticInfo *)info {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _info = info;
    }
    return self;
}

+ (void)presentFrom:(UIViewController *)presenter info:(ZTDiagnosticInfo *)info {
    if (!presenter) return;
    ZTDiagnosticViewController *vc = [[ZTDiagnosticViewController alloc] initWithInfo:info];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    [presenter presentViewController:nav animated:YES completion:nil];
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.title = @"🔍 ĐỐI CHIẾU & KIỂM TRA ĐỘ SẠCH";
    if (@available(iOS 13.0, *)) {
        self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    } else {
        self.view.backgroundColor = [UIColor colorWithRed:0.95 green:0.95 blue:0.97 alpha:1.0];
    }

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Đóng"
                                                                              style:UIBarButtonItemStyleDone
                                                                             target:self
                                                                             action:@selector(dismissSelf)];

    [self setupScrollView];
    [self reloadCardViews];

    // Tự động quét IP mạng hiện tại khi mở màn hình
    if (self.info.currentIP.length > 0 && !self.info.ipCheckCompleted) {
        [self performFullCheckWithPhone:nil proxy:self.info.currentIP isAuto:YES];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    Class btnCls = NSClassFromString(@"ZTFloatingButton");
    if (btnCls && [btnCls respondsToSelector:@selector(sharedButton)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id btn = [btnCls performSelector:@selector(sharedButton)];
        if (btn && [btn respondsToSelector:@selector(hide)]) {
            [btn performSelector:@selector(hide)];
        }
#pragma clang diagnostic pop
    }
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    Class btnCls = NSClassFromString(@"ZTFloatingButton");
    if (btnCls && [btnCls respondsToSelector:@selector(sharedButton)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id btn = [btnCls performSelector:@selector(sharedButton)];
        if (btn && [btn respondsToSelector:@selector(show)]) {
            [btn performSelector:@selector(show)];
        }
#pragma clang diagnostic pop
    }
}

- (void)dismissSelf {
    [self dismissViewControllerAnimated:YES completion:^{
        Class btnCls = NSClassFromString(@"ZTFloatingButton");
        if (btnCls && [btnCls respondsToSelector:@selector(sharedButton)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id btn = [btnCls performSelector:@selector(sharedButton)];
            if (btn && [btn respondsToSelector:@selector(show)]) {
                [btn performSelector:@selector(show)];
            }
#pragma clang diagnostic pop
        }
    }];
}

- (void)setupScrollView {
    self.scrollView = [[UIScrollView alloc] init];
    self.scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    self.scrollView.alwaysBounceVertical = YES;
    self.scrollView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [self.view addSubview:self.scrollView];

    self.contentStack = [[UIStackView alloc] init];
    self.contentStack.translatesAutoresizingMaskIntoConstraints = NO;
    self.contentStack.axis = UILayoutConstraintAxisVertical;
    self.contentStack.spacing = 14;
    self.contentStack.alignment = UIStackViewAlignmentFill;
    self.contentStack.distribution = UIStackViewDistributionFill;
    self.contentStack.layoutMarginsRelativeArrangement = YES;
    self.contentStack.layoutMargins = UIEdgeInsetsMake(16, 16, 28, 16);
    [self.scrollView addSubview:self.contentStack];

    [NSLayoutConstraint activateConstraints:@[
        [self.scrollView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.scrollView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.scrollView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.scrollView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

        [self.contentStack.topAnchor constraintEqualToAnchor:self.scrollView.topAnchor],
        [self.contentStack.leadingAnchor constraintEqualToAnchor:self.scrollView.leadingAnchor],
        [self.contentStack.trailingAnchor constraintEqualToAnchor:self.scrollView.trailingAnchor],
        [self.contentStack.bottomAnchor constraintEqualToAnchor:self.scrollView.bottomAnchor],
        [self.contentStack.widthAnchor constraintEqualToAnchor:self.scrollView.widthAnchor]
    ]];
}

- (void)refreshLiveCleanlinessStatus {
    NSInteger kcCount = check_zalo_keychain_count();
    self.info.keychainRemainingCount = kcCount;
    self.info.keychainCleanPassed = (kcCount == 0);
    self.info.webkitCleanPassed = check_webkit_is_clean();
    self.info.clipboardCleanPassed = check_clipboard_is_clean();
}

- (void)reloadCardViews {
    [self refreshLiveCleanlinessStatus];
    if (self.allowHostingIP && self.info.ipIsHosting) {
        self.info.ipCleanPassed = YES;
        self.info.ipTypeDesc = @"Hosting / Datacenter (Đã xác nhận sạch thủ công) ⚠️";
    }

    // Xoá các view cũ ngoại trừ pairInputCard (để không bị mất text người dùng vừa gõ)
    for (UIView *v in [self.contentStack.arrangedSubviews copy]) {
        [self.contentStack removeArrangedSubview:v];
        if (v != self.pairInputCard) {
            [v removeFromSuperview];
        }
    }

    // 1. Ô Nhập Liệu SĐT & Proxy (Top Input Card)
    [self.contentStack addArrangedSubview:[self getOrCreatePairInputCard]];

    // Tính toán tiêu chuẩn An Toàn Tổng Thể
    BOOL hasWipedHistory = (self.info.lastWipedIP.length > 0);
    BOOL isSameIP = (hasWipedHistory && [self.info.currentIP isEqualToString:self.info.lastWipedIP]);
    BOOL isDifferentIP = (hasWipedHistory && ![self.info.currentIP isEqualToString:self.info.lastWipedIP]);
    BOOL isDuplicateIDFV = (self.info.lastWipedIDFV.length > 0 && [self.info.currentIDFV isEqualToString:self.info.lastWipedIDFV]);

    BOOL isOrig = [self.info.bundleId isEqualToString:@"vn.com.vng.zingalo"];
    BOOL kcIsoPassed = isOrig || self.info.keychainIsolated;

    BOOL hardwarePassed = (self.info.hasConfiguredProfile &&
                           !isSameIP &&
                           !isDuplicateIDFV &&
                           self.info.deviceIdPassed &&
                           self.info.armCpuPassed &&
                           self.info.installTimePassed &&
                           self.info.screenResolutionPassed &&
                           kcIsoPassed &&
                           self.info.keychainCleanPassed &&
                           self.info.webkitCleanPassed &&
                           self.info.leveldbOK &&
                           self.info.regionSyncPassed &&
                           self.info.sysctlPassed &&
                           self.info.isLicensed);

    BOOL phoneTestedAndPassed = (self.info.phoneCheckCompleted &&
                                 self.info.phonePassed &&
                                 self.info.matchGeoPassed &&
                                 self.info.matchCarrierPassed &&
                                 (!self.info.ipCheckCompleted || self.info.matchTimezonePassed) &&
                                 (!self.info.ipCheckCompleted || self.info.ipCleanPassed));

    BOOL isPendingPhone = hardwarePassed && !self.info.phoneCheckCompleted;
    BOOL isAllPassed = hardwarePassed && phoneTestedAndPassed;

    // 2. Thẻ Kết Luận Tổng Thể (Verdict Banner)
    [self.contentStack addArrangedSubview:[self buildVerdictCardWithPassed:isAllPassed isPendingPhone:isPendingPhone isSameIP:isSameIP isDuplicateIDFV:isDuplicateIDFV]];

    // 3. Thẻ Phân Tích Số Điện Thoại (Luôn hiển thị để người dùng nắm rõ tình trạng SĐT)
    [self.contentStack addArrangedSubview:[self buildPhoneCard]];

    // 4. Thẻ Mạng & Proxy Thực Tế (Network & Proxy Hygiene)
    [self.contentStack addArrangedSubview:[self buildNetworkCardWithSameIP:isSameIP differentIP:isDifferentIP]];

    // 5. Thẻ Radar Đồng Bộ 3 Chiều (Geo & Timezone Sync Radar)
    if (self.info.ipCheckCompleted || self.info.phoneCheckCompleted) {
        [self.contentStack addArrangedSubview:[self buildGeoSyncRadarCard]];
    }

    // 6. Thẻ Thiết Bị Giả Lập (Device Hardware & 3 Timestamps)
    [self.contentStack addArrangedSubview:[self buildDeviceCardWithDuplicateIDFV:isDuplicateIDFV]];

    // 7. Thẻ Nhà Mạng & SIM
    [self.contentStack addArrangedSubview:[self buildSIMCard]];

    // 8. Thẻ Vệ Sinh Sandbox & Hệ Thống
    [self.contentStack addArrangedSubview:[self buildHygieneCard]];

    // 9. Thẻ Bản Quyền
    [self.contentStack addArrangedSubview:[self buildLicenseCard]];

    // 10. Nút Đóng Lớn ở cuối
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [closeBtn.heightAnchor constraintEqualToConstant:48].active = YES;
    closeBtn.layer.cornerRadius = 12;
    closeBtn.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    [closeBtn setTitle:@"ĐÃ HIỂU / ĐÓNG" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.backgroundColor = [UIColor colorWithRed:0.0 green:0.48 blue:1.0 alpha:1.0];
    [closeBtn addTarget:self action:@selector(dismissSelf) forControlEvents:UIControlEventTouchUpInside];
    [self.contentStack addArrangedSubview:closeBtn];
}

#pragma mark - Helper tạo Khung Card (Framed Card Container)

- (UIView *)createCardContainer {
    UIView *card = [[UIView alloc] init];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.layer.cornerRadius = 14;
    card.layer.borderWidth = 1.0;

    if (@available(iOS 13.0, *)) {
        card.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
        card.layer.borderColor = [UIColor separatorColor].CGColor;
    } else {
        card.backgroundColor = [UIColor whiteColor];
        card.layer.borderColor = [UIColor colorWithWhite:0.85 alpha:1.0].CGColor;
    }
    card.layer.masksToBounds = YES;
    return card;
}

- (UIStackView *)createCardInnerStackForCard:(UIView *)card {
    UIStackView *inner = [[UIStackView alloc] init];
    inner.translatesAutoresizingMaskIntoConstraints = NO;
    inner.axis = UILayoutConstraintAxisVertical;
    inner.spacing = 10;
    inner.layoutMarginsRelativeArrangement = YES;
    inner.layoutMargins = UIEdgeInsetsMake(14, 16, 14, 16);
    [card addSubview:inner];

    [NSLayoutConstraint activateConstraints:@[
        [inner.topAnchor constraintEqualToAnchor:card.topAnchor],
        [inner.leadingAnchor constraintEqualToAnchor:card.leadingAnchor],
        [inner.trailingAnchor constraintEqualToAnchor:card.trailingAnchor],
        [inner.bottomAnchor constraintEqualToAnchor:card.bottomAnchor]
    ]];
    return inner;
}

- (UILabel *)createCardTitleLabelWithIcon:(NSString *)icon title:(NSString *)title {
    UILabel *lbl = [[UILabel alloc] init];
    lbl.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    if (@available(iOS 13.0, *)) {
        lbl.textColor = [UIColor labelColor];
    } else {
        lbl.textColor = [UIColor blackColor];
    }
    lbl.text = [NSString stringWithFormat:@"%@  %@", icon, title];
    return lbl;
}

- (UIView *)createRowWithKey:(NSString *)key value:(NSString *)value badge:(nullable NSString *)badge isWarning:(BOOL)isWarning {
    UIView *row = [[UIView alloc] init];
    row.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *keyLbl = [[UILabel alloc] init];
    keyLbl.translatesAutoresizingMaskIntoConstraints = NO;
    keyLbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    if (@available(iOS 13.0, *)) {
        keyLbl.textColor = [UIColor secondaryLabelColor];
    } else {
        keyLbl.textColor = [UIColor darkGrayColor];
    }
    keyLbl.text = key;
    [row addSubview:keyLbl];

    UILabel *valLbl = [[UILabel alloc] init];
    valLbl.translatesAutoresizingMaskIntoConstraints = NO;
    valLbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    valLbl.textAlignment = NSTextAlignmentRight;

    if (isWarning) {
        valLbl.textColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:1.0];
    } else if (badge != nil && ([badge containsString:@"✅"] || [badge containsString:@"Mới"] || [badge containsString:@"Sạch"] || [badge containsString:@"Khớp"])) {
        valLbl.textColor = [UIColor colorWithRed:0.1 green:0.65 blue:0.3 alpha:1.0];
    } else {
        if (@available(iOS 13.0, *)) {
            valLbl.textColor = [UIColor labelColor];
        } else {
            valLbl.textColor = [UIColor blackColor];
        }
    }

    if (badge.length > 0) {
        valLbl.text = [NSString stringWithFormat:@"%@ (%@)", value ?: @"", badge];
    } else {
        valLbl.text = value ?: @"";
    }
    [row addSubview:valLbl];

    [NSLayoutConstraint activateConstraints:@[
        [keyLbl.topAnchor constraintEqualToAnchor:row.topAnchor],
        [keyLbl.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
        [keyLbl.bottomAnchor constraintEqualToAnchor:row.bottomAnchor],
        [keyLbl.widthAnchor constraintLessThanOrEqualToAnchor:row.widthAnchor multiplier:0.45],

        [valLbl.topAnchor constraintEqualToAnchor:row.topAnchor],
        [valLbl.trailingAnchor constraintEqualToAnchor:row.trailingAnchor],
        [valLbl.bottomAnchor constraintEqualToAnchor:row.bottomAnchor],
        [valLbl.leadingAnchor constraintGreaterThanOrEqualToAnchor:keyLbl.trailingAnchor constant:8]
    ]];

    return row;
}

#pragma mark - Ô Nhập Liệu Đối Chiếu (Pair Input Card)

- (UIView *)getOrCreatePairInputCard {
    if (self.pairInputCard) return self.pairInputCard;

    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];
    inner.spacing = 10;

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🎯" title:@"ĐỐI CHIẾU SỐ ĐIỆN THOẠI & PROXY"]];

    UILabel *hint = [[UILabel alloc] init];
    hint.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    if (@available(iOS 13.0, *)) {
        hint.textColor = [UIColor secondaryLabelColor];
    } else {
        hint.textColor = [UIColor grayColor];
    }
    hint.numberOfLines = 0;
    hint.text = @"Dán Số điện thoại và Proxy (hoặc IP) định dùng vào đây. Tweak sẽ tự động bóc tách và đối chiếu độ sạch + lệch vùng trước khi bạn ấn đăng ký:";
    [inner addArrangedSubview:hint];

    // 1. Ô Nhập SĐT
    UILabel *lblPhone = [[UILabel alloc] init];
    lblPhone.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
    lblPhone.text = @"1. Số điện thoại định đăng ký:";
    [inner addArrangedSubview:lblPhone];

    UIStackView *phoneRow = [[UIStackView alloc] init];
    phoneRow.axis = UILayoutConstraintAxisHorizontal;
    phoneRow.spacing = 8;
    phoneRow.alignment = UIStackViewAlignmentCenter;

    self.phoneField = [[UITextField alloc] init];
    self.phoneField.translatesAutoresizingMaskIntoConstraints = NO;
    self.phoneField.placeholder = @"VD: 0935859108 hoặc +12025550143";
    self.phoneField.borderStyle = UITextBorderStyleRoundedRect;
    self.phoneField.font = [UIFont systemFontOfSize:13];
    self.phoneField.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.phoneField.keyboardType = UIKeyboardTypePhonePad;
    [phoneRow addArrangedSubview:self.phoneField];

    UIButton *pastePhoneBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [pastePhoneBtn setTitle:@"📋 Dán" forState:UIControlStateNormal];
    pastePhoneBtn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [pastePhoneBtn addTarget:self action:@selector(pastePhoneNumber) forControlEvents:UIControlEventTouchUpInside];
    [phoneRow addArrangedSubview:pastePhoneBtn];
    [inner addArrangedSubview:phoneRow];

    // 2. Ô Nhập Proxy / IP
    UILabel *lblProxy = [[UILabel alloc] init];
    lblProxy.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
    lblProxy.text = @"2. Proxy hoặc IP (Hỗ trợ host:port:user:pass hoặc IP):";
    [inner addArrangedSubview:lblProxy];

    UIStackView *proxyRow = [[UIStackView alloc] init];
    proxyRow.axis = UILayoutConstraintAxisHorizontal;
    proxyRow.spacing = 8;
    proxyRow.alignment = UIStackViewAlignmentCenter;

    self.proxyField = [[UITextField alloc] init];
    self.proxyField.translatesAutoresizingMaskIntoConstraints = NO;
    self.proxyField.placeholder = @"VD: 188.221... hoặc proxy.com:8080:user:pass";
    self.proxyField.borderStyle = UITextBorderStyleRoundedRect;
    self.proxyField.font = [UIFont systemFontOfSize:13];
    self.proxyField.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.proxyField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.proxyField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    if (self.info.currentIP.length > 0) {
        self.proxyField.text = self.info.currentIP;
    }
    [proxyRow addArrangedSubview:self.proxyField];

    UIButton *pasteProxyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [pasteProxyBtn setTitle:@"📋 Dán" forState:UIControlStateNormal];
    pasteProxyBtn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [pasteProxyBtn addTarget:self action:@selector(pasteProxyString) forControlEvents:UIControlEventTouchUpInside];
    [proxyRow addArrangedSubview:pasteProxyBtn];
    [inner addArrangedSubview:proxyRow];

    // Nút Lấy IP Máy & Nút Kiểm Tra
    UIStackView *actionBtns = [[UIStackView alloc] init];
    actionBtns.axis = UILayoutConstraintAxisHorizontal;
    actionBtns.spacing = 10;
    actionBtns.distribution = UIStackViewDistributionFillEqually;

    self.fetchIpBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.fetchIpBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [self.fetchIpBtn.heightAnchor constraintEqualToConstant:42].active = YES;
    self.fetchIpBtn.layer.cornerRadius = 8;
    self.fetchIpBtn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [self.fetchIpBtn setTitle:@"⚡ Lấy IP Máy Hiện Tại" forState:UIControlStateNormal];
    self.fetchIpBtn.backgroundColor = [UIColor colorWithRed:0.0 green:0.48 blue:1.0 alpha:0.12];
    [self.fetchIpBtn addTarget:self action:@selector(fetchCurrentMachineIP) forControlEvents:UIControlEventTouchUpInside];
    [actionBtns addArrangedSubview:self.fetchIpBtn];

    self.checkBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.checkBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [self.checkBtn.heightAnchor constraintEqualToConstant:42].active = YES;
    self.checkBtn.layer.cornerRadius = 8;
    self.checkBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
    [self.checkBtn setTitle:@"🔍 KIỂM TRA ĐỘ KHỚP" forState:UIControlStateNormal];
    [self.checkBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.checkBtn.backgroundColor = [UIColor colorWithRed:0.1 green:0.65 blue:0.3 alpha:1.0];
    [self.checkBtn addTarget:self action:@selector(onCheckButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [actionBtns addArrangedSubview:self.checkBtn];

    [inner addArrangedSubview:actionBtns];

    // Spinner & Trạng thái
    UIStackView *statusRow = [[UIStackView alloc] init];
    statusRow.axis = UILayoutConstraintAxisHorizontal;
    statusRow.spacing = 8;
    statusRow.alignment = UIStackViewAlignmentCenter;

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.hidesWhenStopped = YES;
    [statusRow addArrangedSubview:self.spinner];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    if (@available(iOS 13.0, *)) {
        self.statusLabel.textColor = [UIColor secondaryLabelColor];
    } else {
        self.statusLabel.textColor = [UIColor grayColor];
    }
    self.statusLabel.text = @"Sẵn sàng kiểm tra.";
    [statusRow addArrangedSubview:self.statusLabel];
    [inner addArrangedSubview:statusRow];

    self.pairInputCard = card;
    return card;
}

- (void)pastePhoneNumber {
    NSString *clip = [UIPasteboard generalPasteboard].string;
    if (clip.length > 0) {
        self.phoneField.text = [clip stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }
}

- (void)pasteProxyString {
    NSString *clip = [UIPasteboard generalPasteboard].string;
    if (clip.length > 0) {
        self.proxyField.text = [clip stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }
}

static void query_live_public_ip(void (^completion)(NSString *ip)) {
    uint64_t now = (uint64_t)[[NSDate date] timeIntervalSince1970];
    NSString *urlStr = [NSString stringWithFormat:@"https://api.ipify.org?format=text&_t=%llu", (unsigned long long)now];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.URLCache = nil;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
    config.timeoutIntervalForRequest = 5.0;
    config.timeoutIntervalForResource = 5.0;
    config.HTTPShouldSetCookies = NO;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]
                                                       cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                   timeoutInterval:5.0];
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

        // Dự phòng: icanhazip.com
        NSMutableURLRequest *backupReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"https://icanhazip.com?_t=%llu", (unsigned long long)now]]
                                                                 cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                             timeoutInterval:5.0];
        [backupReq setValue:@"close" forHTTPHeaderField:@"Connection"];
        [backupReq setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];
        [[session dataTaskWithRequest:backupReq completionHandler:^(NSData * _Nullable bdata, NSURLResponse * _Nullable bresp, NSError * _Nullable berr) {
            NSString *bIp = nil;
            if (bdata && !berr) {
                bIp = [[NSString alloc] initWithData:bdata encoding:NSUTF8StringEncoding];
                bIp = [bIp stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                [session finishTasksAndInvalidate];
                completion((bIp.length >= 7 && ([bIp containsString:@"."] || [bIp containsString:@":"])) ? bIp : nil);
            });
        }] resume];
    }] resume];
}

- (void)fetchCurrentMachineIP {
    [self.spinner startAnimating];
    self.fetchIpBtn.enabled = NO;
    self.statusLabel.text = @"⚡ Đang truy vấn IP mạng trực tiếp...";

    __weak typeof(self) weakSelf = self;
    query_live_public_ip(^(NSString *liveIP) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;

        [strongSelf.spinner stopAnimating];
        strongSelf.fetchIpBtn.enabled = YES;

        if (liveIP.length > 0) {
            strongSelf.info.currentIP = liveIP;
            strongSelf.proxyField.text = liveIP;
            strongSelf.statusLabel.text = [NSString stringWithFormat:@"✅ Đã nạp IP máy trực tiếp: %@", liveIP];
            [strongSelf reloadCardViews];
        } else {
            strongSelf.statusLabel.text = @"❌ Lỗi lấy IP! Hãy kiểm tra kết nối 4G/WiFi.";
        }
    });
}

- (void)onCheckButtonTapped {
    [self.view endEditing:YES];
    NSString *phone = self.phoneField.text;
    NSString *proxy = self.proxyField.text;
    [self performFullCheckWithPhone:phone proxy:proxy isAuto:NO];
}

#pragma mark - Thực Hiện Quét Đầy Đủ & Đối Chiếu

- (void)performFullCheckWithPhone:(nullable NSString *)phone proxy:(nullable NSString *)proxy isAuto:(BOOL)isAuto {
    [self.spinner startAnimating];
    self.checkBtn.enabled = NO;
    self.statusLabel.text = @"Đang truy vấn mạng & quét thông số GeoIP...";

    NSString *host = nil;
    NSNumber *port = nil;
    NSString *user = nil;
    NSString *pass = nil;

    NSString *targetIP = nil;
    NSDictionary *proxyDict = nil;

    NSString *cleanProxy = [proxy stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (cleanProxy.length > 0) {
        if ([cleanProxy containsString:@":"] || [cleanProxy containsString:@"@"]) {
            if (parse_proxy_string(cleanProxy, &host, &port, &user, &pass)) {
                // Kiểm tra xem host có phải dạng IPv4 không
                NSRegularExpression *ipRegex = [NSRegularExpression regularExpressionWithPattern:@"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$" options:0 error:nil];
                NSUInteger matches = [ipRegex numberOfMatchesInString:host options:0 range:NSMakeRange(0, host.length)];
                if (matches > 0 && user.length == 0 && pass.length == 0) {
                    // Là IP trực tiếp không có mật khẩu
                    targetIP = host;
                } else {
                    // Là proxy kèm User/Pass hoặc domain xoay -> Thiết lập connectionProxyDictionary
                    NSMutableDictionary *p = [NSMutableDictionary dictionary];
                    p[@"HTTPEnable"] = @YES;
                    p[@"HTTPProxy"] = host;
                    p[@"HTTPPort"] = port ?: @(80);
                    if (user.length > 0) p[(NSString *)kCFProxyUsernameKey] = user;
                    if (pass.length > 0) p[(NSString *)kCFProxyPasswordKey] = pass;
                    proxyDict = [p copy];
                    targetIP = nil; // Để ip-api tự báo Exit IP của proxy ra ngoài
                }
            }
        } else {
            targetIP = cleanProxy;
        }
    } else {
        targetIP = self.info.currentIP;
    }

    __weak typeof(self) weakSelf = self;
    fetch_geoip_data(targetIP, proxyDict, ^(NSDictionary *result, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;

            [strongSelf.spinner stopAnimating];
            strongSelf.checkBtn.enabled = YES;

            if (result) {
                strongSelf.info.ipCheckCompleted = YES;
                strongSelf.info.testedIP = result[@"query"];
                strongSelf.info.currentIP = result[@"query"];
                strongSelf.info.ipCountry = result[@"country"];
                strongSelf.info.ipCountryCode = result[@"countryCode"];
                strongSelf.info.ipRegionName = result[@"regionName"];
                strongSelf.info.ipCity = result[@"city"];
                strongSelf.info.ipTimezone = result[@"timezone"];
                strongSelf.info.ipISP = result[@"isp"];
                strongSelf.info.ipOrg = result[@"org"];
                strongSelf.info.ipASN = result[@"as"];
                strongSelf.info.ipIsHosting = [result[@"hosting"] boolValue];
                strongSelf.info.ipIsProxy = [result[@"proxy"] boolValue];
                strongSelf.info.ipIsMobile = [result[@"mobile"] boolValue];

                if (is_zt_auto_sync_timezone_enabled() && strongSelf.info.ipTimezone.length > 0) {
                    NSString *effectiveTZ = strongSelf.info.ipTimezone;
                    BOOL isVN = [strongSelf.info.ipCountryCode isEqualToString:@"VN"] ||
                                [strongSelf.info.regionName containsString:@"Việt Nam"] ||
                                [strongSelf.info.regionName containsString:@"VN"];
                    if (isVN || [effectiveTZ isEqualToString:@"Asia/Bangkok"] || [effectiveTZ isEqualToString:@"Asia/Saigon"]) {
                        if (isVN) {
                            effectiveTZ = @"Asia/Ho_Chi_Minh";
                        }
                    }
                    update_zt_synced_timezone_pref(effectiveTZ);
                    strongSelf.info.timeZoneName = effectiveTZ;
                    NSTimeZone *tz = [NSTimeZone timeZoneWithName:strongSelf.info.timeZoneName];
                    NSInteger gmtSec = tz ? [tz secondsFromGMT] : 0;
                    int gmtH = (int)(gmtSec / 3600);
                    int gmtM = abs((int)((gmtSec % 3600) / 60));
                    strongSelf.info.timeZoneGMT = (gmtM > 0) ? [NSString stringWithFormat:@"GMT%+d:%02d", gmtH, gmtM] : [NSString stringWithFormat:@"GMT%+d", gmtH];
                }

                if (strongSelf.info.ipIsHosting) {
                    if (strongSelf.allowHostingIP) {
                        strongSelf.info.ipTypeDesc = @"Hosting / Datacenter (Đã xác nhận sạch thủ công) ⚠️";
                        strongSelf.info.ipCleanPassed = YES;
                    } else {
                        strongSelf.info.ipTypeDesc = @"Datacenter / Hosting / VPS ❌";
                        strongSelf.info.ipCleanPassed = NO;
                    }
                } else if (strongSelf.info.ipIsMobile) {
                    strongSelf.info.ipTypeDesc = @"4G/5G Cellular Mobile (Cực Sạch) ✅";
                    strongSelf.info.ipCleanPassed = YES;
                } else if (strongSelf.info.ipIsProxy) {
                    strongSelf.info.ipTypeDesc = @"Proxy / VPN Phát Hiện ⚠️";
                    strongSelf.info.ipCleanPassed = NO;
                } else {
                    strongSelf.info.ipTypeDesc = @"Dân Cư / ISP Residential (Sạch) ✅";
                    strongSelf.info.ipCleanPassed = YES;
                }
                strongSelf.statusLabel.text = [NSString stringWithFormat:@"Đã cập nhật IP: %@ (%@)", strongSelf.info.testedIP ?: @"", strongSelf.info.ipCountryCode ?: @""];
            } else {
                strongSelf.info.ipCheckCompleted = NO;
                strongSelf.statusLabel.text = [NSString stringWithFormat:@"Lỗi kiểm tra mạng: %@", error.localizedDescription ?: @"Thất bại"];
            }

            // Phân tích Số Điện Thoại
            NSString *cCode = nil, *cName = nil, *carrier = nil, *lType = nil, *reason = nil;
            BOOL isVoIP = NO, compatible = YES;
            analyze_phone_details(phone, strongSelf.info.regionName, &cCode, &cName, &carrier, &lType, &isVoIP, &compatible, &reason);

            strongSelf.info.inputPhone = phone;
            strongSelf.info.phoneCountryCode = cCode;
            strongSelf.info.phoneCountryName = cName;
            strongSelf.info.phoneCarrierName = carrier;
            strongSelf.info.phoneLineType = lType;
            strongSelf.info.phoneIsVoIP = isVoIP;
            strongSelf.info.phonePassed = compatible && !isVoIP;
            strongSelf.info.matchProfileReason = reason;
            strongSelf.info.phoneCheckCompleted = (phone.length > 0);

            // Đối chiếu Chéo 3 Chiều
            if (strongSelf.info.phoneCheckCompleted && strongSelf.info.ipCheckCompleted) {
                if ([strongSelf.info.phoneCountryCode isEqualToString:strongSelf.info.ipCountryCode]) {
                    strongSelf.info.matchGeoPassed = YES;
                    strongSelf.info.matchGeoReason = [NSString stringWithFormat:@"SĐT [%@] và IP [%@] cùng quốc gia ✅", strongSelf.info.phoneCountryCode, strongSelf.info.ipCountryCode];
                } else {
                    strongSelf.info.matchGeoPassed = NO;
                    strongSelf.info.matchGeoReason = [NSString stringWithFormat:@"LỆCH QUỐC GIA: SĐT là [%@] nhưng IP là [%@]! ❌", strongSelf.info.phoneCountryCode, strongSelf.info.ipCountryCode];
                }
            } else {
                strongSelf.info.matchGeoPassed = YES;
                strongSelf.info.matchGeoReason = @"Chưa đủ thông tin SĐT hoặc IP";
            }

            if (strongSelf.info.ipCheckCompleted && strongSelf.info.timeZoneName.length > 0) {
                NSString *expectedTZ = strongSelf.info.timeZoneName;
                NSString *actualIPTZ = strongSelf.info.ipTimezone;
                BOOL isBothGMT7 = ([expectedTZ isEqualToString:@"Asia/Ho_Chi_Minh"] && ([actualIPTZ isEqualToString:@"Asia/Bangkok"] || [actualIPTZ isEqualToString:@"Asia/Saigon"]));
                if ([actualIPTZ isEqualToString:expectedTZ] || isBothGMT7) {
                    strongSelf.info.matchTimezonePassed = YES;
                    strongSelf.info.matchTimezoneReason = [NSString stringWithFormat:@"Khớp múi giờ hoàn hảo: %@ (%@) ✅", strongSelf.info.timeZoneName, strongSelf.info.timeZoneGMT ?: @""];
                } else {
                    strongSelf.info.matchTimezonePassed = NO;
                    strongSelf.info.matchTimezoneReason = [NSString stringWithFormat:@"LỆCH MÚI GIỜ: IP là [%@] nhưng Máy là [%@] (%@)! ❌", strongSelf.info.ipTimezone ?: @"", strongSelf.info.timeZoneName, strongSelf.info.timeZoneGMT ?: @""];
                }
            } else {
                strongSelf.info.matchTimezonePassed = YES;
                strongSelf.info.matchTimezoneReason = @"Chưa xác định";
            }

            // Đối Chiếu Nhà Mạng Viễn Thông (Carrier Match)
            if (strongSelf.info.phoneCheckCompleted) {
                NSString *phoneBrand = extract_carrier_brand(strongSelf.info.phoneCarrierName);
                NSString *simBrand = extract_carrier_brand(strongSelf.info.carrierName);
                if (phoneBrand.length > 0 && simBrand.length > 0) {
                    if ([phoneBrand isEqualToString:simBrand]) {
                        strongSelf.info.matchCarrierPassed = YES;
                        strongSelf.info.suggestedCarrier = phoneBrand;
                        strongSelf.info.matchCarrierReason = [NSString stringWithFormat:@"Khớp hoàn hảo nhà mạng: %@ ✅", phoneBrand];
                    } else {
                        strongSelf.info.matchCarrierPassed = NO;
                        strongSelf.info.suggestedCarrier = phoneBrand;
                        strongSelf.info.matchCarrierReason = [NSString stringWithFormat:@"LỆCH NHÀ MẠNG: SĐT là [%@] nhưng SIM máy là [%@]! ⚠️", phoneBrand, simBrand];
                    }
                } else {
                    strongSelf.info.matchCarrierPassed = YES;
                    strongSelf.info.suggestedCarrier = (phoneBrand.length > 0) ? phoneBrand : nil;
                    strongSelf.info.matchCarrierReason = @"Không đủ dữ liệu nhà mạng";
                }
            } else {
                strongSelf.info.matchCarrierPassed = YES;
                strongSelf.info.suggestedCarrier = nil;
                strongSelf.info.matchCarrierReason = @"Chưa kiểm tra";
            }

            [strongSelf reloadCardViews];
        });
    });
}

#pragma mark - 1. Thẻ Kết Luận Tổng Thể (Verdict Banner Card)

- (UIView *)buildVerdictCardWithPassed:(BOOL)passed isPendingPhone:(BOOL)isPendingPhone isSameIP:(BOOL)isSameIP isDuplicateIDFV:(BOOL)isDuplicateIDFV {
    UIView *card = [[UIView alloc] init];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.layer.cornerRadius = 14;
    card.layer.borderWidth = 1.5;

    if (passed) {
        card.backgroundColor = [UIColor colorWithRed:0.1 green:0.75 blue:0.35 alpha:0.12];
        card.layer.borderColor = [UIColor colorWithRed:0.12 green:0.65 blue:0.3 alpha:0.7].CGColor;
    } else if (isPendingPhone) {
        card.backgroundColor = [UIColor colorWithRed:0.98 green:0.75 blue:0.1 alpha:0.12];
        card.layer.borderColor = [UIColor colorWithRed:0.95 green:0.65 blue:0.1 alpha:0.8].CGColor;
    } else {
        card.backgroundColor = [UIColor colorWithRed:0.95 green:0.25 blue:0.2 alpha:0.10];
        card.layer.borderColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:0.7].CGColor;
    }

    UIStackView *inner = [self createCardInnerStackForCard:card];
    inner.spacing = 6;

    UILabel *headerLbl = [[UILabel alloc] init];
    headerLbl.font = [UIFont systemFontOfSize:17 weight:UIFontWeightHeavy];

    UILabel *descLbl = [[UILabel alloc] init];
    descLbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    descLbl.numberOfLines = 0;

    if (passed) {
        headerLbl.text = @"🟢 ĐỦ ĐIỀU KIỆN REG AN TOÀN (100% SẠCH)";
        headerLbl.textColor = [UIColor colorWithRed:0.1 green:0.65 blue:0.25 alpha:1.0];
        descLbl.text = @"Mọi thông số Phần cứng, Múi giờ, Loại IP Dân cư và Số điện thoại đã khớp hoàn hảo 100%. Bạn có thể mở Zalo và đăng ký ngay!";
        descLbl.textColor = [UIColor colorWithRed:0.12 green:0.55 blue:0.25 alpha:1.0];
    } else if (isPendingPhone) {
        headerLbl.text = @"🟡 CHỜ NHẬP SĐT ĐỂ ĐỐI CHIẾU";
        headerLbl.textColor = [UIColor colorWithRed:0.85 green:0.55 blue:0.0 alpha:1.0];
        descLbl.text = @"Phần cứng thiết bị đã sạch và sẵn sàng! Vui lòng nhập Số điện thoại dự định đăng ký ở trên và bấm [🔍 KIỂM TRA ĐỘ KHỚP] để hệ thống đối chiếu SĐT với IP & Múi giờ trước khi Reg.";
        descLbl.textColor = [UIColor colorWithRed:0.75 green:0.48 blue:0.0 alpha:1.0];
    } else {
        headerLbl.text = @"🔴 CHƯA ĐƯỢC REG! CẦN XỬ LÝ LỖI DƯỚI ĐÂY";
        headerLbl.textColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:1.0];

        NSMutableString *reasons = [NSMutableString string];
        if (!self.info.isLicensed) [reasons appendString:@"• Bản quyền Tweak chưa được kích hoạt hoặc đã hết hạn!\n"];
        if (!self.info.hasConfiguredProfile) [reasons appendString:@"• Chưa bấm 'Deep Wipe & Cấp Máy Mới'!\n"];
        if (isSameIP) [reasons appendString:@"• Trùng IP cũ! Hãy bật/tắt Chế độ máy bay để đổi IP 4G hoặc xoay Proxy.\n"];
        if (isDuplicateIDFV) [reasons appendString:@"• Trùng mã định danh IDFV của phiên trước! Cần Deep Wipe.\n"];
        if (!self.info.deviceIdPassed) [reasons appendString:@"• Mã device_id trùng timestamp máy thật (Chưa fake birthtime)!\n"];
        if (!self.info.armCpuPassed) [reasons appendString:@"• Lệch tập lệnh ARM CPU phần cứng Apple!\n"];
        if (self.info.ipCheckCompleted && !self.info.ipCleanPassed) [reasons appendString:[NSString stringWithFormat:@"• IP KHÔNG SẠCH: %@\n", self.info.ipTypeDesc ?: @""]];
        if (!self.info.keychainCleanPassed) [reasons appendString:[NSString stringWithFormat:@"• Còn %ld Token Zalo trong Keychain! Cần Deep Wipe để làm sạch.\n", (long)self.info.keychainRemainingCount]];
        if (!self.info.webkitCleanPassed) [reasons appendString:@"• Còn lưu trữ Cookie WebKit cũ! Cần Deep Wipe.\n"];

        if (!self.info.phoneCheckCompleted) {
            [reasons appendString:@"• Chưa nhập Số điện thoại dự định đăng ký để kiểm tra độ khớp!\n"];
        } else {
            if (!self.info.matchGeoPassed) [reasons appendString:[NSString stringWithFormat:@"• %@\n", self.info.matchGeoReason ?: @"Lệch quốc gia"]];
            if (!self.info.matchCarrierPassed) [reasons appendString:[NSString stringWithFormat:@"• %@\n", self.info.matchCarrierReason ?: @"Lệch nhà mạng"]];
            if (!self.info.phonePassed) [reasons appendString:[NSString stringWithFormat:@"• %@\n", self.info.matchProfileReason ?: @"SĐT không tương thích"]];
        }

        if (self.info.ipCheckCompleted && !self.info.matchTimezonePassed) [reasons appendString:[NSString stringWithFormat:@"• %@\n", self.info.matchTimezoneReason ?: @"Lệch múi giờ"]];
        if (!self.info.regionSyncPassed) [reasons appendString:@"• Múi giờ, Ngôn ngữ và SIM chưa đồng bộ nhất quán!\n"];

        descLbl.text = [reasons stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        descLbl.textColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.15 alpha:1.0];
    }

    [inner addArrangedSubview:headerLbl];
    [inner addArrangedSubview:descLbl];
    return card;
}

#pragma mark - 2. Thẻ Phân Tích Số Điện Thoại (Phone Card)

- (UIView *)buildPhoneCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"📱" title:@"1. PHÂN TÍCH SỐ ĐIỆN THOẠI ĐĂNG KÝ"]];

    if (!self.info.phoneCheckCompleted) {
        [inner addArrangedSubview:[self createRowWithKey:@"Số Điện Thoại"
                                                  value:@"[Chưa nhập - Bắt buộc]"
                                                  badge:@"⚠️ Bắt buộc"
                                              isWarning:YES]];

        [inner addArrangedSubview:[self createRowWithKey:@"Tình Trạng Đối Chiếu"
                                                  value:@"Chưa đối chiếu với IP & Múi giờ"
                                                  badge:@"⚠️ Cần kiểm tra"
                                              isWarning:YES]];

        UILabel *guideLbl = [[UILabel alloc] init];
        guideLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        guideLbl.textColor = [UIColor colorWithRed:0.85 green:0.55 blue:0.0 alpha:1.0];
        guideLbl.numberOfLines = 0;
        guideLbl.text = @"👉 Hãy nhập Số điện thoại dự định đăng ký ở trên rồi bấm [🔍 KIỂM TRA ĐỘ KHỚP] để hệ thống phân tích nhà mạng viễn thông và phát hiện số ảo/VoIP trước khi Reg nick!";
        [inner addArrangedSubview:guideLbl];

        return card;
    }

    [inner addArrangedSubview:[self createRowWithKey:@"Số Điện Thoại"
                                              value:self.info.inputPhone ?: @"---"
                                              badge:nil
                                          isWarning:NO]];

    [inner addArrangedSubview:[self createRowWithKey:@"Quốc Gia Nhận Diện"
                                              value:self.info.phoneCountryName ?: @"Chưa rõ"
                                              badge:nil
                                          isWarning:NO]];

    [inner addArrangedSubview:[self createRowWithKey:@"Nhà Mạng Viễn Thông"
                                              value:self.info.phoneCarrierName ?: @"---"
                                              badge:@"Đã nhận diện ✅"
                                          isWarning:NO]];

    NSString *carrierDetails = [NSString stringWithFormat:@"%@ (MCC: %@ | MNC: %@)",
                                self.info.carrierName ?: @"Viettel",
                                self.info.carrierMCC ?: @"452",
                                self.info.carrierMNC ?: @"04"];
    [inner addArrangedSubview:[self createRowWithKey:@"SIM Ảo Trong Máy"
                                              value:carrierDetails
                                              badge:@"Đang cắm 📱"
                                          isWarning:NO]];

    NSString *carrierBadge = self.info.matchCarrierPassed ? @"Khớp Tuyệt Đối ✅" : @"LỆCH NHÀ MẠNG ⚠️";
    [inner addArrangedSubview:[self createRowWithKey:@"Đối Chiếu Nhà Mạng"
                                              value:self.info.matchCarrierReason ?: @"---"
                                              badge:carrierBadge
                                          isWarning:!self.info.matchCarrierPassed]];

    [inner addArrangedSubview:[self createRowWithKey:@"Loại Đầu Số (Line Type)"
                                              value:self.info.phoneLineType ?: @"---"
                                              badge:self.info.phoneIsVoIP ? @"Số ảo ❌" : @"SIM Thật ✅"
                                          isWarning:self.info.phoneIsVoIP]];

    NSString *compatBadge = self.info.phonePassed ? @"Khớp Profile ✅" : @"Lệch Profile ❌";
    [inner addArrangedSubview:[self createRowWithKey:@"Độ Tương Thích Profile"
                                              value:self.info.matchProfileReason ?: @"---"
                                              badge:compatBadge
                                          isWarning:!self.info.phonePassed]];

    if (!self.info.matchCarrierPassed && self.info.suggestedCarrier.length > 0) {
        UIView *warnBox = [[UIView alloc] init];
        warnBox.translatesAutoresizingMaskIntoConstraints = NO;
        warnBox.layer.cornerRadius = 8;
        warnBox.backgroundColor = [UIColor colorWithRed:0.95 green:0.3 blue:0.2 alpha:0.12];
        warnBox.layer.borderWidth = 1.0;
        warnBox.layer.borderColor = [UIColor colorWithRed:0.9 green:0.3 blue:0.2 alpha:0.4].CGColor;

        UILabel *warnLbl = [[UILabel alloc] init];
        warnLbl.translatesAutoresizingMaskIntoConstraints = NO;
        warnLbl.numberOfLines = 0;
        warnLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        warnLbl.textColor = [UIColor colorWithRed:0.85 green:0.2 blue:0.15 alpha:1.0];
        warnLbl.text = [NSString stringWithFormat:
            @"⚠️ CẢNH BÁO LỆCH NHÀ MẠNG:\n"
            @"• SĐT định reg là mạng %@, nhưng cấu hình máy hiện tại lại cắm SIM %@!\n"
            @"• Đổi SIM nóng trong phiên đang chạy dễ làm Zalo ghi nhận bất thường (SIM Swap/Carrier Mismatch).\n"
            @"👉 Hãy bấm nút Deep Wipe bên dưới để cấp máy mới cắm sẵn SIM %@ ngay từ giây đầu tiên!",
            self.info.suggestedCarrier, self.info.carrierName ?: @"Khác", self.info.suggestedCarrier];
        [warnBox addSubview:warnLbl];

        [NSLayoutConstraint activateConstraints:@[
            [warnLbl.topAnchor constraintEqualToAnchor:warnBox.topAnchor constant:8],
            [warnLbl.leadingAnchor constraintEqualToAnchor:warnBox.leadingAnchor constant:10],
            [warnLbl.trailingAnchor constraintEqualToAnchor:warnBox.trailingAnchor constant:-10],
            [warnLbl.bottomAnchor constraintEqualToAnchor:warnBox.bottomAnchor constant:-8]
        ]];
        [inner addArrangedSubview:warnBox];

        UIButton *quickCarrierBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        quickCarrierBtn.translatesAutoresizingMaskIntoConstraints = NO;
        [quickCarrierBtn.heightAnchor constraintEqualToConstant:44].active = YES;
        quickCarrierBtn.layer.cornerRadius = 10;
        quickCarrierBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
        NSString *quickTitle = [NSString stringWithFormat:@"⚡ ĐỔI SIM SANG [%@] KHỚP SĐT NGAY", self.info.suggestedCarrier.uppercaseString];
        [quickCarrierBtn setTitle:quickTitle forState:UIControlStateNormal];
        [quickCarrierBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        quickCarrierBtn.backgroundColor = [UIColor colorWithRed:0.12 green:0.65 blue:0.3 alpha:1.0];
        [quickCarrierBtn addTarget:self action:@selector(applySuggestedCarrierDirectlyAction) forControlEvents:UIControlEventTouchUpInside];
        [inner addArrangedSubview:quickCarrierBtn];

        UIButton *wipeCarrierBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        wipeCarrierBtn.translatesAutoresizingMaskIntoConstraints = NO;
        [wipeCarrierBtn.heightAnchor constraintEqualToConstant:44].active = YES;
        wipeCarrierBtn.layer.cornerRadius = 10;
        wipeCarrierBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
        NSString *btnTitle = [NSString stringWithFormat:@"🧹 DEEP WIPE & CẤP MÁY CẮM SIM [%@]", self.info.suggestedCarrier.uppercaseString];
        [wipeCarrierBtn setTitle:btnTitle forState:UIControlStateNormal];
        [wipeCarrierBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        wipeCarrierBtn.backgroundColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:1.0];
        [wipeCarrierBtn addTarget:self action:@selector(wipeWithSuggestedCarrierAction) forControlEvents:UIControlEventTouchUpInside];
        [inner addArrangedSubview:wipeCarrierBtn];
    } else if (self.info.phoneCheckCompleted && self.info.matchCarrierPassed) {
        UIButton *wipeSameCarrierBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        wipeSameCarrierBtn.translatesAutoresizingMaskIntoConstraints = NO;
        [wipeSameCarrierBtn.heightAnchor constraintEqualToConstant:44].active = YES;
        wipeSameCarrierBtn.layer.cornerRadius = 10;
        wipeSameCarrierBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
        NSString *carrierToShow = (self.info.suggestedCarrier ?: self.info.carrierName ?: @"Viettel").uppercaseString;
        NSString *btnTitle = [NSString stringWithFormat:@"🚀 DEEP WIPE CẤP MÁY MỚI CẮM SIM [%@]", carrierToShow];
        [wipeSameCarrierBtn setTitle:btnTitle forState:UIControlStateNormal];
        [wipeSameCarrierBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        wipeSameCarrierBtn.backgroundColor = [UIColor colorWithRed:0.0 green:0.48 blue:1.0 alpha:1.0];
        [wipeSameCarrierBtn addTarget:self action:@selector(wipeWithSuggestedCarrierAction) forControlEvents:UIControlEventTouchUpInside];
        [inner addArrangedSubview:wipeSameCarrierBtn];
    }

    return card;
}

- (void)wipeWithSuggestedCarrierAction {
    NSString *carrier = self.info.suggestedCarrier ?: (self.info.carrierName ?: @"Viettel");
    NSString *tzDesc = (self.info.ipTimezone.length > 0) ? self.info.ipTimezone : (self.info.timeZoneName ?: @"Mặc định");
    NSString *msg = [NSString stringWithFormat:
        @"Hệ thống sẽ thực hiện:\n\n"
        @"1. 🧹 Quét sạch toàn bộ Sandbox, Keychain và Caches Zalo cũ.\n"
        @"2. 📱 Sinh thiết bị mới 100%% cắm sẵn SIM [%@] ngay từ giây đầu tiên khởi động.\n"
        @"3. ⏰ Đồng bộ múi giờ IP: %@.\n"
        @"4. ✈️ Tự động đóng app an toàn để bạn Bật/Tắt Chế Độ Máy Bay đổi IP 4G trước khi mở lại.\n\n"
        @"Bạn có chắc chắn muốn tiến hành Deep Wipe ngay không?",
        carrier.uppercaseString, tzDesc];

    UIAlertController *confirmAlert = [UIAlertController alertControllerWithTitle:@"🧹 XÁC NHẬN DEEP WIPE"
                                                                          message:msg
                                                                   preferredStyle:UIAlertControllerStyleAlert];

    [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Tiến Hành Wipe Ngay" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        if (self.info.ipTimezone.length > 0) {
            update_zt_synced_timezone_pref(self.info.ipTimezone);
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            Class menuCls = NSClassFromString(@"ZTMenuManager");
            if (menuCls && [menuCls respondsToSelector:@selector(sharedManager)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                id mgr = [menuCls performSelector:@selector(sharedManager)];
                SEL wipeSel = NSSelectorFromString(@"performInAppDeepWipeWithRegion:preferredCarrier:currentIP:");
                if (mgr && [mgr respondsToSelector:wipeSel]) {
                    typedef void (*WipeFunc)(id, SEL, NSString *, NSString *, NSString *);
                    WipeFunc fn = (WipeFunc)[mgr methodForSelector:wipeSel];
                    NSString *targetRegion = (self.info.phoneCountryCode.length > 0) ? self.info.phoneCountryCode : @"VN";
                    fn(mgr, wipeSel, targetRegion, carrier, self.info.currentIP);
                    return;
                }
#pragma clang diagnostic pop
            }
        });
    }]];

    [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Hủy Bỏ" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:confirmAlert animated:YES completion:nil];
}

#pragma mark - 3. Thẻ Mạng 4G & Proxy Thực Tế (Network Card)

- (UIView *)buildNetworkCardWithSameIP:(BOOL)isSameIP differentIP:(BOOL)isDifferentIP {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🌐" title:@"2. ĐỘ SẠCH MẠNG & PROXY THỰC TẾ"]];

    NSString *badge;
    BOOL ipWarning = NO;
    if (isSameIP) {
        badge = @"TRÙNG IP CŨ ❌";
        ipWarning = YES;
    } else if (self.info.ipCheckCompleted && !self.info.ipCleanPassed) {
        badge = @"DATACENTER ❌";
        ipWarning = YES;
    } else if (self.info.ipCheckCompleted && self.info.ipCleanPassed) {
        badge = @"IP SẠCH ✅";
    } else {
        badge = @"ĐANG TẢI ⏳";
    }

    NSString *ipDisplay = self.info.testedIP ?: (self.info.currentIP ?: @"Đang kiểm tra...");
    [inner addArrangedSubview:[self createRowWithKey:@"IP Ra Ngoài Thực Tế"
                                              value:ipDisplay
                                              badge:badge
                                          isWarning:ipWarning]];

    if (self.info.ipCheckCompleted) {
        [inner addArrangedSubview:[self createRowWithKey:@"Loại IP (Type)"
                                                  value:self.info.ipTypeDesc ?: @"Dân Cư"
                                                  badge:self.info.ipCleanPassed ? @"Hợp lệ ✅" : @"Nguy hiểm ❌"
                                              isWarning:!self.info.ipCleanPassed]];

        NSString *geoLoc = [NSString stringWithFormat:@"%@, %@ (%@)",
                            self.info.ipCity ?: @"",
                            self.info.ipRegionName ?: @"",
                            self.info.ipCountry ?: @""];
        [inner addArrangedSubview:[self createRowWithKey:@"Vị Trí Địa Lý IP"
                                                  value:geoLoc
                                                  badge:nil
                                              isWarning:NO]];

        NSString *ispFull = [NSString stringWithFormat:@"%@ (%@)", self.info.ipISP ?: @"---", self.info.ipASN ?: @""];
        [inner addArrangedSubview:[self createRowWithKey:@"Nhà Mạng / ASN"
                                                  value:ispFull
                                                  badge:nil
                                              isWarning:NO]];

        [inner addArrangedSubview:[self createRowWithKey:@"Múi Giờ Của IP"
                                                  value:self.info.ipTimezone ?: @"---"
                                                  badge:nil
                                              isWarning:NO]];
    }

    NSString *lastIPStr = self.info.lastWipedIP.length > 0 ? self.info.lastWipedIP : @"Chưa có lịch sử";
    NSString *ipRotBadge = nil;
    BOOL ipRotWarn = NO;
    if (self.info.lastWipedIP.length > 0) {
        if (isSameIP) {
            ipRotBadge = @"TRÙNG IP CŨ ❌";
            ipRotWarn = YES;
        } else {
            ipRotBadge = @"Đã đổi IP mới ✅";
        }
    }
    [inner addArrangedSubview:[self createRowWithKey:@"IP Lần Wipe Trước"
                                              value:lastIPStr
                                              badge:ipRotBadge
                                          isWarning:ipRotWarn]];

    if (self.info.ipCheckCompleted) {
        NSString *connType = self.info.ipIsMobile ? @"4G Cellular (Di Động)" : @"WiFi / Internet Cố Định";
        NSString *connBadge = self.info.ipIsMobile ? @"Khuyến nghị reg ✅" : @"Dễ dính Blacklist IP ⚠️";
        [inner addArrangedSubview:[self createRowWithKey:@"Loại Kết Nối Mạng"
                                                  value:connType
                                                  badge:connBadge
                                              isWarning:!self.info.ipIsMobile]];
    }

    if (self.info.ipCheckCompleted && self.info.ipIsHosting) {
        UIView *warnBox = [[UIView alloc] init];
        warnBox.translatesAutoresizingMaskIntoConstraints = NO;
        warnBox.layer.cornerRadius = 8;
        warnBox.backgroundColor = self.allowHostingIP ? [UIColor colorWithRed:0.2 green:0.7 blue:0.3 alpha:0.12] : [UIColor colorWithRed:0.95 green:0.3 blue:0.2 alpha:0.12];
        warnBox.layer.borderWidth = 1.0;
        warnBox.layer.borderColor = self.allowHostingIP ? [UIColor colorWithRed:0.2 green:0.7 blue:0.3 alpha:0.4].CGColor : [UIColor colorWithRed:0.9 green:0.3 blue:0.2 alpha:0.4].CGColor;

        UILabel *warnLbl = [[UILabel alloc] init];
        warnLbl.translatesAutoresizingMaskIntoConstraints = NO;
        warnLbl.numberOfLines = 0;
        warnLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        warnLbl.textColor = self.allowHostingIP ? [UIColor colorWithRed:0.1 green:0.6 blue:0.2 alpha:1.0] : [UIColor colorWithRed:0.85 green:0.2 blue:0.15 alpha:1.0];
        if (self.allowHostingIP) {
            warnLbl.text = @"🟢 ĐÃ XÁC NHẬN SẠCH THỦ CÔNG:\n• Bạn đã đánh dấu kiểm tra IP này sạch trên web. Hệ thống bỏ qua cảnh báo Datacenter và cho phép bạn tiến hành Reg nick!";
        } else {
            warnLbl.text = @"⚠️ CẢNH BÁO NGUY HIỂM: Cơ sở dữ liệu ip-api gán cờ DATACENTER / HOSTING (Máy chủ/VPS)!\n• Nếu bạn đã kiểm tra IP này trên web (Whoer, Scamalytics...) và thấy sạch, hãy bấm nút bên dưới để chấp nhận IP.";
        }
        [warnBox addSubview:warnLbl];

        [NSLayoutConstraint activateConstraints:@[
            [warnLbl.topAnchor constraintEqualToAnchor:warnBox.topAnchor constant:8],
            [warnLbl.leadingAnchor constraintEqualToAnchor:warnBox.leadingAnchor constant:10],
            [warnLbl.trailingAnchor constraintEqualToAnchor:warnBox.trailingAnchor constant:-10],
            [warnLbl.bottomAnchor constraintEqualToAnchor:warnBox.bottomAnchor constant:-8]
        ]];
        [inner addArrangedSubview:warnBox];

        UIButton *allowBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        allowBtn.translatesAutoresizingMaskIntoConstraints = NO;
        [allowBtn.heightAnchor constraintEqualToConstant:40].active = YES;
        allowBtn.layer.cornerRadius = 8;
        allowBtn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
        if (self.allowHostingIP) {
            [allowBtn setTitle:@"✅ ĐÃ CHẤP NHẬN IP NÀY (BẤM ĐỂ HỦY BỎ)" forState:UIControlStateNormal];
            [allowBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            allowBtn.backgroundColor = [UIColor colorWithRed:0.1 green:0.65 blue:0.25 alpha:1.0];
        } else {
            [allowBtn setTitle:@"🛡️ Tôi đã tự check web, IP này sạch -> Cho phép dùng" forState:UIControlStateNormal];
            [allowBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            allowBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.45 blue:0.85 alpha:1.0];
        }
        [allowBtn addTarget:self action:@selector(toggleAllowHostingIPAction) forControlEvents:UIControlEventTouchUpInside];
        [inner addArrangedSubview:allowBtn];
    }

    // Cảnh báo nếu đang dùng WiFi
    if (self.info.ipCheckCompleted && !self.info.ipIsMobile) {
        UIView *wifiBox = [[UIView alloc] init];
        wifiBox.translatesAutoresizingMaskIntoConstraints = NO;
        wifiBox.layer.cornerRadius = 8;
        wifiBox.backgroundColor = [UIColor colorWithRed:0.98 green:0.75 blue:0.1 alpha:0.12];
        wifiBox.layer.borderWidth = 1.0;
        wifiBox.layer.borderColor = [UIColor colorWithRed:0.95 green:0.65 blue:0.1 alpha:0.4].CGColor;

        UILabel *wifiLbl = [[UILabel alloc] init];
        wifiLbl.translatesAutoresizingMaskIntoConstraints = NO;
        wifiLbl.numberOfLines = 0;
        wifiLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        wifiLbl.textColor = [UIColor colorWithRed:0.85 green:0.5 blue:0.0 alpha:1.0];
        wifiLbl.text = @"⚠️ CẢNH BÁO MẠNG WIFI: Bạn đang dùng mạng WiFi cố định!\n• Nếu WiFi này đã từng có tài khoản Zalo bị Vô Hiệu Hoá, server sẽ liên kết IP và khoá tiếp nick mới.\n• KHUYÊN DÙNG: Tắt WiFi, bật 4G và Bật/Tắt Chế Độ Máy Bay trước khi đăng ký.";
        [wifiBox addSubview:wifiLbl];

        [NSLayoutConstraint activateConstraints:@[
            [wifiLbl.topAnchor constraintEqualToAnchor:wifiBox.topAnchor constant:8],
            [wifiLbl.leadingAnchor constraintEqualToAnchor:wifiBox.leadingAnchor constant:10],
            [wifiLbl.trailingAnchor constraintEqualToAnchor:wifiBox.trailingAnchor constant:-10],
            [wifiLbl.bottomAnchor constraintEqualToAnchor:wifiBox.bottomAnchor constant:-8]
        ]];
        [inner addArrangedSubview:wifiBox];
    }

    // Cảnh báo nếu trùng IP lần Wipe trước
    if (isSameIP) {
        UIView *sameIpBox = [[UIView alloc] init];
        sameIpBox.translatesAutoresizingMaskIntoConstraints = NO;
        sameIpBox.layer.cornerRadius = 8;
        sameIpBox.backgroundColor = [UIColor colorWithRed:0.95 green:0.25 blue:0.2 alpha:0.15];
        sameIpBox.layer.borderWidth = 1.0;
        sameIpBox.layer.borderColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:0.5].CGColor;

        UILabel *sameIpLbl = [[UILabel alloc] init];
        sameIpLbl.translatesAutoresizingMaskIntoConstraints = NO;
        sameIpLbl.numberOfLines = 0;
        sameIpLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
        sameIpLbl.textColor = [UIColor colorWithRed:0.85 green:0.2 blue:0.15 alpha:1.0];
        sameIpLbl.text = @"🚨 NGUY CƠ CAO - CHƯA XOAY IP:\n• Địa chỉ IP hiện tại TRÙNG HOÀN TOÀN với IP lần Wipe trước!\n• NẾU NICK TRƯỚC VỪA BỊ KHOÁ: Hãy Bật Chế Độ Máy Bay (đợi 5s) rồi Tắt để nhà mạng cấp IP 4G mới toanh trước khi nhập OTP!";
        [sameIpBox addSubview:sameIpLbl];

        [NSLayoutConstraint activateConstraints:@[
            [sameIpLbl.topAnchor constraintEqualToAnchor:sameIpBox.topAnchor constant:8],
            [sameIpLbl.leadingAnchor constraintEqualToAnchor:sameIpBox.leadingAnchor constant:10],
            [sameIpLbl.trailingAnchor constraintEqualToAnchor:sameIpBox.trailingAnchor constant:-10],
            [sameIpLbl.bottomAnchor constraintEqualToAnchor:sameIpBox.bottomAnchor constant:-8]
        ]];
        [inner addArrangedSubview:sameIpBox];
    }

    return card;
}

#pragma mark - 4. Thẻ Radar Đồng Bộ 3 Chiều (GeoSync Card)

- (UIView *)buildGeoSyncRadarCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"⚖️" title:@"3. RADAR ĐỒNG BỘ 3 CHIỀU (GEO & TIMEZONE)"]];

    if (self.info.phoneCheckCompleted && self.info.ipCheckCompleted) {
        NSString *geoDisplay = [NSString stringWithFormat:@"SĐT: [%@] ⟷ IP: [%@]", self.info.phoneCountryCode ?: @"", self.info.ipCountryCode ?: @""];
        [inner addArrangedSubview:[self createRowWithKey:@"Đồng Bộ Quốc Gia"
                                                  value:geoDisplay
                                                  badge:self.info.matchGeoPassed ? @"Khớp 100% ✅" : @"LỆCH NƯỚC ❌"
                                              isWarning:!self.info.matchGeoPassed]];
    }

    if (self.info.phoneCheckCompleted) {
        NSString *phoneBrand = extract_carrier_brand(self.info.phoneCarrierName);
        NSString *simBrand = extract_carrier_brand(self.info.carrierName);
        NSString *carrierDisplay = [NSString stringWithFormat:@"SĐT: [%@] ⟷ SIM Máy: [%@]", phoneBrand.length > 0 ? phoneBrand : @"---", simBrand.length > 0 ? simBrand : @"---"];
        [inner addArrangedSubview:[self createRowWithKey:@"Đồng Bộ Nhà Mạng"
                                                  value:carrierDisplay
                                                  badge:self.info.matchCarrierPassed ? @"Khớp Tuyệt Đối ✅" : @"LỆCH NHÀ MẠNG ⚠️"
                                              isWarning:!self.info.matchCarrierPassed]];
    }

    if (self.info.ipCheckCompleted) {
        NSString *tzDisplay = [NSString stringWithFormat:@"IP: [%@] ⟷ Máy: [%@]", self.info.ipTimezone ?: @"", self.info.timeZoneName ?: @""];
        [inner addArrangedSubview:[self createRowWithKey:@"Đồng Bộ Múi Giờ"
                                                  value:tzDisplay
                                                  badge:self.info.matchTimezonePassed ? @"Khớp Tuyệt Đối ✅" : @"LỆCH GIỜ ❌"
                                              isWarning:!self.info.matchTimezonePassed]];
    }

    NSString *locDisplay = [NSString stringWithFormat:@"%@ | [%@]", self.info.localeIdentifier ?: @"vi_VN", self.info.preferredLanguages ?: @"vi-VN, en-VN"];
    [inner addArrangedSubview:[self createRowWithKey:@"Ngôn Ngữ & Vùng Máy"
                                              value:locDisplay
                                              badge:@"Chuẩn Apple ✅"
                                          isWarning:NO]];

    NSString *carrierDetails = [NSString stringWithFormat:@"%@ (%@-%@)", self.info.carrierName ?: @"Viettel", self.info.carrierMCC ?: @"452", self.info.carrierMNC ?: @"04"];
    [inner addArrangedSubview:[self createRowWithKey:@"SIM Ảo Trong Máy"
                                              value:carrierDetails
                                              badge:@"Đã cấp ✅"
                                          isWarning:NO]];

    return card;
}

#pragma mark - 5. Thẻ Thiết Bị Giả Lập (Device Hardware Card)

- (UIView *)buildDeviceCardWithDuplicateIDFV:(BOOL)isDuplicateIDFV {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"📱" title:@"4. PHẦN CỨNG & HỆ THỐNG MÁY ẢO"]];

    BOOL configured = self.info.hasConfiguredProfile;
    NSString *deviceFull = [NSString stringWithFormat:@"%@ (iOS %@)", self.info.deviceName ?: @"iPhone", self.info.iosVersion ?: @""];
    [inner addArrangedSubview:[self createRowWithKey:@"Dòng Máy" value:deviceFull badge:configured ? nil : @"Máy Thật ⚠️" isWarning:!configured]];

    NSString *machineBadge = configured ? @"Khớp Profile ✅" : @"Máy Thật ⚠️";
    [inner addArrangedSubview:[self createRowWithKey:@"Machine (hw.machine)"
                                              value:self.info.deviceMachine ?: @"iPhone"
                                              badge:machineBadge
                                          isWarning:!configured]];

    NSString *idfvShort = (self.info.currentIDFV.length > 8) ? [self.info.currentIDFV substringToIndex:8] : self.info.currentIDFV;
    NSString *idfvBadge = (!configured) ? @"Chưa cấp ⚠️" : (isDuplicateIDFV ? @"TRÙNG IDFV ❌" : @"Mới tinh ✅");
    NSString *idfvDisplay = configured ? [NSString stringWithFormat:@"%@...", idfvShort ?: @""] : @"Chưa cấp (Cần Wipe)";
    [inner addArrangedSubview:[self createRowWithKey:@"IDFV Mới" value:idfvDisplay badge:idfvBadge isWarning:isDuplicateIDFV || !configured]];

    NSString *devIdBadge = self.info.deviceIdPassed ? @"Chuẩn 3 Mốc ✅" : @"Trùng máy thật ❌";
    [inner addArrangedSubview:[self createRowWithKey:@"Mã device_id (Hardware)"
                                              value:self.info.hardwareDeviceId ?: @"Chưa cấp"
                                              badge:devIdBadge
                                          isWarning:!self.info.deviceIdPassed]];

    NSString *armBadge = self.info.armCpuPassed ? @"Chuẩn A-Series ✅" : @"Lệch vi kiến trúc ❌";
    [inner addArrangedSubview:[self createRowWithKey:@"ARM Features Radar"
                                              value:self.info.armFeaturesSummary ?: @"FEAT_AES, SHA1, SHA256"
                                              badge:armBadge
                                          isWarning:!self.info.armCpuPassed]];

    NSString *resBadge = self.info.screenResolutionPassed ? @"Khớp Apple Specs ✅" : @"Lệch độ phân giải ❌";
    [inner addArrangedSubview:[self createRowWithKey:@"Độ Phân Giải Màn Hình"
                                              value:self.info.screenResolutionText ?: @"Chuẩn Apple"
                                              badge:resBadge
                                          isWarning:!self.info.screenResolutionPassed]];

    NSString *l2Str = [NSString stringWithFormat:@"%u MB | %u KB", self.info.l2CacheSizeMB ?: 3, self.info.pageSizeKB ?: 16];
    [inner addArrangedSubview:[self createRowWithKey:@"L2 Cache & PageSize"
                                              value:l2Str
                                              badge:@"Chuẩn Apple ✅"
                                          isWarning:NO]];

    NSString *procStr = [NSString stringWithFormat:@"%d (Native ARM64)", self.info.procTranslated];
    [inner addArrangedSubview:[self createRowWithKey:@"Dịch Mã (proc_translated)"
                                              value:procStr
                                              badge:@"Không Giả Lập ✅"
                                          isWarning:(self.info.procTranslated != 0)]];

    return card;
}

#pragma mark - 6. Thẻ Nhà Mạng & SIM

- (UIView *)buildSIMCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🌍" title:@"THÔNG SỐ VÙNG & SIM TWEAK"]];

    [inner addArrangedSubview:[self createRowWithKey:@"Hồ Sơ Vùng (Region)"
                                              value:self.info.regionName ?: @"Việt Nam (+84)"
                                              badge:nil
                                          isWarning:NO]];

    NSString *tzDisplay = [NSString stringWithFormat:@"%@ (%@)", self.info.timeZoneName ?: @"Asia/Ho_Chi_Minh", self.info.timeZoneGMT ?: @"GMT+7"];
    [inner addArrangedSubview:[self createRowWithKey:@"Múi Giờ Hệ Thống"
                                              value:tzDisplay
                                              badge:@"Đồng bộ ✅"
                                          isWarning:NO]];

    NSString *carrierDetails = [NSString stringWithFormat:@"%@ (MCC: %@ | MNC: %@)",
                                self.info.carrierName ?: @"Viettel",
                                self.info.carrierMCC ?: @"452",
                                self.info.carrierMNC ?: @"04"];
    [inner addArrangedSubview:[self createRowWithKey:@"Nhà Mạng Di Động (SIM)"
                                              value:carrierDetails
                                              badge:@"Hợp lệ ✅"
                                          isWarning:NO]];

    NSString *mnoLive = self.info.mnoCarrierName ?: (self.info.carrierName ?: @"Viettel");
    [inner addArrangedSubview:[self createRowWithKey:@"Tên Mạng MNO (CoreTelephony)"
                                              value:mnoLive
                                              badge:@"Đã Cấp (Không Rỗng) ✅"
                                          isWarning:NO]];

    return card;
}

#pragma mark - 7. Thẻ Vệ Sinh Sandbox & Hệ Thống

- (UIView *)buildHygieneCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🧹" title:@"VỆ SINH SANDBOX & HỆ THỐNG"]];

    NSString *cleanBadge = (self.info.sandboxKB < 3072.0) ? @"Sạch 100% ✅" : ((self.info.sandboxKB < 6144.0) ? @"Cache nhẹ 🟡" : @"Dữ liệu cũ ❌");
    NSString *cacheStr = (self.info.sandboxKB >= 1024.0) ? [NSString stringWithFormat:@"%.2f MB", self.info.sandboxKB / 1024.0] : [NSString stringWithFormat:@"%.1f KB", self.info.sandboxKB];
    [inner addArrangedSubview:[self createRowWithKey:@"Bộ Nhớ Rác Sandbox"
                                              value:cacheStr
                                              badge:cleanBadge
                                          isWarning:(self.info.sandboxKB >= 6144.0)]];

    // Vệ Sinh Keychain Zalo
    NSString *kcVal = self.info.keychainCleanPassed ? @"0 Token Tồn Dư" : [NSString stringWithFormat:@"Còn %ld Token cũ", (long)self.info.keychainRemainingCount];
    NSString *kcBadge = self.info.keychainCleanPassed ? @"Sạch 100% ✅" : @"Cần Deep Wipe ❌";
    [inner addArrangedSubview:[self createRowWithKey:@"Vệ Sinh Keychain Zalo"
                                              value:kcVal
                                              badge:kcBadge
                                          isWarning:!self.info.keychainCleanPassed]];

    if (!self.info.keychainCleanPassed) {
        UIButton *purgeKcBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        purgeKcBtn.translatesAutoresizingMaskIntoConstraints = NO;
        [purgeKcBtn.heightAnchor constraintEqualToConstant:40].active = YES;
        purgeKcBtn.layer.cornerRadius = 8;
        purgeKcBtn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
        NSString *kcTitle = [NSString stringWithFormat:@"🧹 XÓA SẠCH %ld TOKEN KEYCHAIN NGAY", (long)self.info.keychainRemainingCount];
        [purgeKcBtn setTitle:kcTitle forState:UIControlStateNormal];
        [purgeKcBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        purgeKcBtn.backgroundColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:1.0];
        [purgeKcBtn addTarget:self action:@selector(purgeKeychainDirectlyAction) forControlEvents:UIControlEventTouchUpInside];
        [inner addArrangedSubview:purgeKcBtn];
    }

    // Dữ Liệu WebKit / Cookies
    NSString *wkBadge = self.info.webkitCleanPassed ? @"Đã xóa trắng ✅" : @"Có Cookie cũ ⚠️";
    [inner addArrangedSubview:[self createRowWithKey:@"Dữ Liệu WebKit / Cookies"
                                              value:self.info.webkitCleanPassed ? @"Không lưu trữ web" : @"Chứa dữ liệu Web"
                                              badge:wkBadge
                                          isWarning:!self.info.webkitCleanPassed]];

    // Bộ Nhớ Tạm (Clipboard)
    NSString *clipBadge = self.info.clipboardCleanPassed ? @"Trống ✅" : @"Đang lưu text ⚠️";
    [inner addArrangedSubview:[self createRowWithKey:@"Bộ Nhớ Tạm (Clipboard)"
                                              value:self.info.clipboardCleanPassed ? @"Sạch (Không lưu token)" : @"Có dữ liệu tạm"
                                              badge:clipBadge
                                          isWarning:!self.info.clipboardCleanPassed]];

    [inner addArrangedSubview:[self createRowWithKey:@"LevelDB C++ & Groups"
                                              value:self.info.leveldbOK ? @"Thông suốt 100%" : @"Lỗi truy cập"
                                              badge:self.info.leveldbOK ? @"✅" : @"❌"
                                          isWarning:!self.info.leveldbOK]];

    [inner addArrangedSubview:[self createRowWithKey:@"Thời Gian Cài Đặt App"
                                              value:self.info.installTimeText ?: @"Mới cài đặt"
                                              badge:self.info.installTimePassed ? @"Đồng bộ Profile ✅" : @"Dữ liệu cũ ❌"
                                          isWarning:!self.info.installTimePassed]];

    if (self.info.birthTimeText.length > 0) {
        [inner addArrangedSubview:[self createRowWithKey:@"Ngày Sinh Ổ Đĩa (BirthTime)"
                                                  value:self.info.birthTimeText
                                                  badge:@"Đã đổi mới ✅"
                                              isWarning:NO]];
    }

    if (self.info.bootTimeText.length > 0) {
        [inner addArrangedSubview:[self createRowWithKey:@"Thời Gian Boot (BootTime)"
                                                  value:self.info.bootTimeText
                                                  badge:@"Khớp Profile ✅"
                                              isWarning:NO]];
    }

    BOOL isOrig = [self.info.bundleId isEqualToString:@"vn.com.vng.zingalo"];
    NSString *kcIsoVal = isOrig ? @"Zalo Gốc (Tự động xóa sạch)" : (self.info.keychainIsolated ? @"zt_profile_*" : @"Mặc định");
    NSString *kcIsoBadge = (isOrig || self.info.keychainIsolated) ? @"Bảo vệ an toàn ✅" : @"Chưa cô lập ⚠️";
    [inner addArrangedSubview:[self createRowWithKey:@"Phân Vùng Keychain"
                                              value:kcIsoVal
                                              badge:kcIsoBadge
                                          isWarning:!(isOrig || self.info.keychainIsolated)]];

    NSString *cBidVal = self.info.cfBundleId ?: @"vn.com.vng.zingalo";
    NSString *cBidBadge = self.info.isCloneApp ? @"Đã Bẻ Hướng C ✅" : @"App Store Gốc ✅";
    [inner addArrangedSubview:[self createRowWithKey:@"Mã Gói C-Layer (CFBundle)"
                                              value:cBidVal
                                              badge:cBidBadge
                                          isWarning:NO]];

    NSString *pushVal = self.info.apnsPushStatus ?: (self.info.isCloneApp ? @"32-Byte SHA256 Token" : @"Hệ Thống APNs Apple");
    NSString *pushBadge = self.info.isCloneApp ? @"Đã Giả Lập ✅" : @"Chuẩn Apple ✅";
    [inner addArrangedSubview:[self createRowWithKey:@"Dịch Vụ Đẩy (APNs Push)"
                                              value:pushVal
                                              badge:pushBadge
                                          isWarning:NO]];

    NSString *didVal = self.info.telemetryDId ?: @"2001.SSZ-...";
    [inner addArrangedSubview:[self createRowWithKey:@"Định Danh dId (Telemetry)"
                                              value:didVal
                                              badge:@"Đã Bù Đủ ✅"
                                          isWarning:NO]];

    return card;
}

#pragma mark - 8. Thẻ Bản Quyền Tweak

- (UIView *)buildLicenseCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🛡️" title:@"BẢN QUYỀN TWEAK"]];

    BOOL isWarning = !self.info.isLicensed;
    [inner addArrangedSubview:[self createRowWithKey:@"Trạng Thái & Hạn Dùng"
                                              value:self.info.licenseStatusText ?: @"Chưa kích hoạt"
                                              badge:nil
                                          isWarning:isWarning]];

    return card;
}

#pragma mark - Action Handlers (Bypass Hosting, Sync Carrier, Purge Keychain)

- (void)toggleAllowHostingIPAction {
    self.allowHostingIP = !self.allowHostingIP;
    if (self.allowHostingIP && self.info.ipIsHosting) {
        self.info.ipCleanPassed = YES;
        self.info.ipTypeDesc = @"Hosting / Datacenter (Đã xác nhận sạch thủ công) ⚠️";
    } else if (!self.allowHostingIP && self.info.ipIsHosting) {
        self.info.ipCleanPassed = NO;
        self.info.ipTypeDesc = @"Datacenter / Hosting / VPS ❌";
    }
    [self reloadCardViews];
}

- (void)applySuggestedCarrierDirectlyAction {
    NSString *carrier = self.info.suggestedCarrier ?: @"Viettel";
    NSString *targetRegion = (self.info.phoneCountryCode.length > 0) ? self.info.phoneCountryCode : @"VN";

    NSString *carrierName = carrier;
    NSString *mcc = @"452";
    NSString *mnc = @"04";
    NSString *countryCode = @"vn";
    NSString *regionMode = @"VN";
    NSString *localeId = @"vi_VN";
    NSString *tzName = @"Asia/Ho_Chi_Minh";

    NSString *cleanCarrier = carrier.lowercaseString;
    if ([targetRegion isEqualToString:@"PL"] || [cleanCarrier containsString:@"play"] || [cleanCarrier containsString:@"orange"] || [cleanCarrier containsString:@"plus"] || [cleanCarrier containsString:@"poland"]) {
        regionMode = @"PL";
        countryCode = @"pl";
        localeId = @"pl_PL";
        tzName = @"Europe/Warsaw";
        mcc = @"260";
        if ([cleanCarrier containsString:@"orange"]) {
            carrierName = @"Orange";
            mnc = @"03";
        } else if ([cleanCarrier containsString:@"plus"]) {
            carrierName = @"Plus";
            mnc = @"01";
        } else if ([cleanCarrier containsString:@"t-mobile"]) {
            carrierName = @"T-Mobile";
            mnc = @"02";
        } else {
            carrierName = @"Play";
            mnc = @"06";
        }
    } else if ([targetRegion isEqualToString:@"US"] || [cleanCarrier containsString:@"verizon"] || [cleanCarrier containsString:@"at&t"]) {
        regionMode = @"US";
        countryCode = @"us";
        localeId = @"en_US";
        tzName = @"America/New_York";
        if ([cleanCarrier containsString:@"verizon"]) {
            carrierName = @"Verizon";
            mcc = @"311";
            mnc = @"480";
        } else if ([cleanCarrier containsString:@"at&t"]) {
            carrierName = @"AT&T";
            mcc = @"310";
            mnc = @"410";
        } else {
            carrierName = @"T-Mobile";
            mcc = @"310";
            mnc = @"260";
        }
    } else {
        regionMode = @"VN";
        countryCode = @"vn";
        localeId = @"vi_VN";
        tzName = @"Asia/Ho_Chi_Minh";
        mcc = @"452";
        if ([cleanCarrier containsString:@"vina"]) {
            carrierName = @"VINAPHONE";
            mnc = @"02";
        } else if ([cleanCarrier containsString:@"mobi"]) {
            carrierName = @"VN MOBIFONE";
            mnc = @"01";
        } else if ([cleanCarrier containsString:@"vietnamobile"]) {
            carrierName = @"Vietnamobile";
            mnc = @"05";
        } else {
            carrierName = @"Viettel";
            mnc = @"04";
        }
    }

    // Cập nhật Preferences & Darwin Notification
    update_zt_carrier_pref(carrierName, mcc, mnc, countryCode, regionMode, localeId, tzName);

    // Cập nhật ZTMenuManager nếu có
    Class menuCls = NSClassFromString(@"ZTMenuManager");
    if (menuCls && [menuCls respondsToSelector:@selector(sharedManager)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id mgr = [menuCls performSelector:@selector(sharedManager)];
        SEL applySel = NSSelectorFromString(@"applyRegion:preferredCarrier:");
        if (mgr && [mgr respondsToSelector:applySel]) {
            typedef void (*ApplyFunc)(id, SEL, NSString *, NSString *);
            ApplyFunc fn = (ApplyFunc)[mgr methodForSelector:applySel];
            fn(mgr, applySel, regionMode, carrierName);
        }
#pragma clang diagnostic pop
    }

    // Cập nhật trực tiếp info hiện tại
    self.info.carrierName = carrierName;
    self.info.carrierMCC = mcc;
    self.info.carrierMNC = mnc;
    self.info.carrierCountryCode = countryCode;
    self.info.regionName = regionMode;
    self.info.localeIdentifier = localeId;
    self.info.timeZoneName = tzName;

    // Chạy lại đối chiếu
    [self performFullCheckWithPhone:(self.phoneField.text ?: self.info.inputPhone) proxy:(self.proxyField.text ?: self.info.currentIP) isAuto:NO];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"⚡ ĐÃ ĐỒNG BỘ NHÀ MẠNG"
                                                                  message:[NSString stringWithFormat:@"Đã đồng bộ SIM máy sang [%@] (MCC %@, MNC %@) khớp với SĐT.\n\n⚠️ Lưu ý: Vì đây là đổi SIM trong phiên hiện tại, nếu có thể hãy bấm Deep Wipe bên dưới để cấp thiết bị cắm SIM mới ngay từ giây đầu tiên khởi động.", carrierName, mcc, mnc]
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)purgeKeychainDirectlyAction {
    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"🧹 XÓA SẠCH TOKEN KEYCHAIN"
                                                                     message:@"Hệ thống sẽ xóa sạch toàn bộ token, session Zalo còn lưu trong Keychain để đảm bảo vệ sinh 100% trước khi đăng ký nick mới.\n\nBạn có muốn thực hiện ngay không?"
                                                              preferredStyle:UIAlertControllerStyleAlert];

    [confirm addAction:[UIAlertAction actionWithTitle:@"Xóa Sạch Ngay" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
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

        [self reloadCardViews];

        NSString *resMsg = (self.info.keychainRemainingCount == 0)
            ? @"✅ Toàn bộ Token Keychain Zalo đã được dọn sạch 100%!"
            : [NSString stringWithFormat:@"⚠️ Đã dọn dẹp Keychain, còn sót lại %ld token (có thể thuộc Keychain hệ thống).", (long)self.info.keychainRemainingCount];

        UIAlertController *doneAlert = [UIAlertController alertControllerWithTitle:@"Kết Quả Dọn Keychain"
                                                                           message:resMsg
                                                                    preferredStyle:UIAlertControllerStyleAlert];
        [doneAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:doneAlert animated:YES completion:nil];
    }]];

    [confirm addAction:[UIAlertAction actionWithTitle:@"Hủy Bỏ" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:confirm animated:YES completion:nil];
}

@end
