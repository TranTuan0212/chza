#import "ZTRootListController.h"
#import "SecurityManager.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <signal.h>
#import <sys/stat.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>

#define PREFS_PATH @"/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"
static inline NSArray<NSString *> *get_known_zalo_bundle_ids(void) {
    return @[
        @"vn.com.vng.zingalo",
        @"cn.com.vng.zingalo",
        @"com.zing.zalo",
        @"com.vng.zalo",
        @"vn.com.vng.zingalo.clone",
        @"com.vng.zalo.clone"
    ];
}

static void save_dict_to_all_locations(NSDictionary *dict);
static void kill_all_zalo_processes(void);

static NSString *get_prefs_real_machine(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    sysctlbyname("hw.machine", buf, &size, NULL, 0);
    return (strlen(buf) > 0) ? [NSString stringWithUTF8String:buf] : @"iPhone";
}

static NSString *get_prefs_real_model(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    sysctlbyname("hw.model", buf, &size, NULL, 0);
    return (strlen(buf) > 0) ? [NSString stringWithUTF8String:buf] : @"";
}

static NSString *get_prefs_real_os_version(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    sysctlbyname("kern.osversion", buf, &size, NULL, 0);
    return (strlen(buf) > 0) ? [NSString stringWithUTF8String:buf] : @"";
}

static NSString *generate_random_serial_prefs(void) {
    const char chars[] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    char serial[13] = {0};
    serial[0] = 'F';
    serial[1] = (arc4random_uniform(2) == 0) ? '1' : '2';
    serial[2] = '7';
    for (int i = 3; i < 12; i++) {
        serial[i] = chars[arc4random_uniform(sizeof(chars) - 1)];
    }
    return [NSString stringWithUTF8String:serial];
}

static NSString *generate_random_mac_prefs(void) {
    const char *ouis[] = {"f0:18:98", "ac:de:48", "88:66:5a", "dc:a9:04", "a4:83:e7"};
    const char *oui = ouis[arc4random_uniform(5)];
    return [NSString stringWithFormat:@"%s:%02x:%02x:%02x", oui, arc4random_uniform(256), arc4random_uniform(256), arc4random_uniform(256)];
}

static void fetch_public_ip_prefs(void (^completion)(NSString *ip)) {
    NSURL *url = [NSURL URLWithString:@"https://api.ipify.org"];
    NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:3.5];
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

@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
- (NSURL *)containerURL;
- (NSURL *)dataContainerURL;
- (NSDictionary *)groupContainerURLs;
@end

@implementation ZTRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        [self initDefaultSettingsIfNeeded];
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

- (void)initDefaultSettingsIfNeeded {
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    BOOL needSave = NO;
    if (!dict) {
        dict = [NSMutableDictionary dictionary];
        needSave = YES;
    }
    if (!dict[@"enabled"]) {
        dict[@"enabled"] = @(YES);
        needSave = YES;
    }
    if (!dict[@"showFloatingMenu"]) {
        dict[@"showFloatingMenu"] = @(NO);
        needSave = YES;
    }
    if (!dict[@"deviceMachine"]) {
        dict[@"deviceMachine"] = get_prefs_real_machine();
        dict[@"deviceModel"] = get_prefs_real_model();
        dict[@"systemVersion"] = [[UIDevice currentDevice] systemVersion];
        dict[@"kernOsVersion"] = get_prefs_real_os_version();
        dict[@"ncpu"] = @((uint32_t)[[NSProcessInfo processInfo] activeProcessorCount]);
        dict[@"memsize"] = @([[NSProcessInfo processInfo] physicalMemory]);
        CGRect bounds = [UIScreen mainScreen].bounds;
        dict[@"screenWidth"] = @(bounds.size.width);
        dict[@"screenHeight"] = @(bounds.size.height);
        dict[@"screenScale"] = @([UIScreen mainScreen].scale);
        needSave = YES;
    }
    if (!dict[@"spoofedSerial"] || [dict[@"spoofedSerial"] length] == 0) {
        dict[@"spoofedSerial"] = generate_random_serial_prefs();
        dict[@"spoofedWifiMAC"] = generate_random_mac_prefs();
        dict[@"spoofedBluetoothMAC"] = generate_random_mac_prefs();
        needSave = YES;
    }
    if (!dict[@"spoofedIDFV"] || [dict[@"spoofedIDFV"] length] == 0) {
        dict[@"spoofedIDFV"] = [[NSUUID UUID] UUIDString];
        needSave = YES;
    }
    if (!dict[@"profileId"] || [dict[@"profileId"] length] == 0) {
        dict[@"profileId"] = [[NSUUID UUID] UUIDString];
        needSave = YES;
    }
    if (!dict[@"bootTimeSec"] || [dict[@"bootTimeSec"] unsignedLongLongValue] == 0) {
        uint32_t randomOffset = 86400 + (arc4random_uniform(345600));
        dict[@"bootTimeSec"] = @((uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset);
        dict[@"bootSessionUUID"] = [[NSUUID UUID] UUIDString];
        needSave = YES;
    }
    if (needSave) {
        save_dict_to_all_locations(dict);
    }
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    NSString *key = [specifier propertyForKey:@"key"];
    id value = dict[key];
    if (!value) {
        value = [specifier propertyForKey:@"default"];
    }
    return value;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:PREFS_PATH] ?: [NSMutableDictionary dictionary];
    NSString *key = [specifier propertyForKey:@"key"];
    dict[key] = value;

    if ([key isEqualToString:@"regionMode"]) {
        [self syncCarrierForRegion:(NSString *)value inDict:dict];
    }

    save_dict_to_all_locations(dict);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.sonhu.zalotweak/settingschanged"), NULL, NULL, YES);
}

- (void)syncCarrierForRegion:(NSString *)region inDict:(NSMutableDictionary *)dict {
    if ([region isEqualToString:@"US_STUDENT"]) {
        NSArray *carriers = @[
            @{@"name": @"T-Mobile", @"mcc": @"310", @"mnc": @"260"},
            @{@"name": @"AT&T", @"mcc": @"310", @"mnc": @"410"},
            @{@"name": @"Mint Mobile", @"mcc": @"310", @"mnc": @"260"}
        ];
        NSDictionary *c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        dict[@"carrierName"] = c[@"name"];
        dict[@"carrierMCC"] = c[@"mcc"];
        dict[@"carrierMNC"] = c[@"mnc"];
        dict[@"carrierCountryCode"] = @"us";

        NSArray *studentNames = @[
            @"Huy's iPhone", @"Nam's iPhone", @"Trang's iPhone", @"Alex's iPhone",
            @"Minh's iPhone", @"Linh's iPhone", @"Kevin's iPhone", @"Ha's iPhone",
            @"Duc's iPhone", @"Vy's iPhone", @"Phong's iPhone", @"Chi's iPhone"
        ];
        dict[@"deviceName"] = studentNames[arc4random_uniform((uint32_t)studentNames.count)];
    } else if ([region isEqualToString:@"US"]) {
        NSArray *carriers = @[
            @{@"name": @"Verizon", @"mcc": @"311", @"mnc": @"480"},
            @{@"name": @"AT&T", @"mcc": @"310", @"mnc": @"410"},
            @{@"name": @"T-Mobile", @"mcc": @"310", @"mnc": @"260"}
        ];
        NSDictionary *c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        dict[@"carrierName"] = c[@"name"];
        dict[@"carrierMCC"] = c[@"mcc"];
        dict[@"carrierMNC"] = c[@"mnc"];
        dict[@"carrierCountryCode"] = @"us";

        NSArray *usNames = @[
            @"David's iPhone", @"Michael's iPhone", @"iPhone", @"Sarah's iPhone",
            @"John's iPhone", @"Daniel's iPhone", @"Chris's iPhone", @"Jessica's iPhone"
        ];
        dict[@"deviceName"] = usNames[arc4random_uniform((uint32_t)usNames.count)];
    } else {
        NSArray *carriers = @[
            @{@"name": @"Viettel", @"mcc": @"452", @"mnc": @"04"},
            @{@"name": @"VINAPHONE", @"mcc": @"452", @"mnc": @"02"},
            @{@"name": @"VN MOBIFONE", @"mcc": @"452", @"mnc": @"01"}
        ];
        NSDictionary *c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        dict[@"carrierName"] = c[@"name"];
        dict[@"carrierMCC"] = c[@"mcc"];
        dict[@"carrierMNC"] = c[@"mnc"];
        dict[@"carrierCountryCode"] = @"vn";

        NSArray *vnNames = @[
            @"iPhone", @"iPhone của Tuấn", @"iPhone của Linh", @"iPhone (2)",
            @"iPhone của Huy", @"iPhone 13 Pro", @"iPhone của Nam", @"iPhone của Trang",
            @"iPhone của Hoàng", @"iPhone của Mai", @"iPhone của Lan", @"iPhone của Minh"
        ];
        dict[@"deviceName"] = vnNames[arc4random_uniform((uint32_t)vnNames.count)];
    }
}

#pragma mark - Helper Functions: Dọn dẹp dữ liệu Sandbox & Ghi cấu hình xuyên Sandbox

static BOOL is_valid_zalo_sandbox_path(NSString *path) {
    if (!path || path.length < 35) return NO;
    // BẮT BUỘC đường dẫn phải nằm trong Data Application hoặc Shared AppGroup của Sandbox
    if ([path containsString:@"/Containers/Data/Application/"] ||
        [path containsString:@"/Containers/Shared/AppGroup/"]) {
        // Tuyệt đối không được là các thư mục gốc
        if ([path isEqualToString:@"/var/mobile/Containers/Data/Application"] ||
            [path isEqualToString:@"/var/mobile/Containers/Shared/AppGroup"] ||
            [path isEqualToString:@"/private/var/mobile/Containers/Data/Application"] ||
            [path isEqualToString:@"/private/var/mobile/Containers/Shared/AppGroup"] ||
            [path isEqualToString:@"/var/mobile"] ||
            [path isEqualToString:@"/private/var/mobile"]) {
            return NO;
        }
        return YES;
    }
    return NO;
}

static void kill_all_zalo_processes(void) {
    // 1. Tắt chuẩn qua FBSSystemService của SpringBoard
    Class fbsClass = objc_getClass("FBSSystemService");
    if (fbsClass) {
        SEL sharedSel = sel_registerName("sharedService");
        if ([fbsClass respondsToSelector:sharedSel]) {
            id service = ((id (*)(id, SEL))objc_msgSend)(fbsClass, sharedSel);
            SEL termSel = sel_registerName("terminateApplication:forReason:andReport:withDescription:");
            if (service && [service respondsToSelector:termSel]) {
                for (NSString *bid in get_known_zalo_bundle_ids()) {
                    ((void (*)(id, SEL, id, long long, BOOL, id))objc_msgSend)(service, termSel, bid, 1, NO, @"ZaloTweak Wipe");
                }
            }
        }
    }

    // 2. Chỉ kill đúng tiến trình có tên là "Zalo" (TUYỆT ĐỐI KHÔNG DÙNG "zing" LÀM CHẾT TIẾN TRÌNH HỆ THỐNG)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) == 0 && size > 0) {
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
        if (procs) {
            if (sysctl(mib, 4, procs, &size, NULL, 0) == 0) {
                int count = (int)(size / sizeof(struct kinfo_proc));
                for (int i = 0; i < count; i++) {
                    const char *name = procs[i].kp_proc.p_comm;
                    if (name && (strcasecmp(name, "Zalo") == 0 ||
                                 strcmp(name, "vn.com.vng.zingalo") == 0)) {
                        kill(procs[i].kp_proc.p_pid, SIGKILL);
                    }
                }
            }
            free(procs);
        }
    }
    [NSThread sleepForTimeInterval:0.3];
}

static void wipe_directory_contents(NSString *dirPath) {
    // CHỐT CHẶN AN TOÀN TUYỆT ĐỐI: Từ chối xóa ngay nếu không phải thư mục sandbox Zalo!
    if (!is_valid_zalo_sandbox_path(dirPath)) {
        return;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dirPath]) return;

    NSError *error = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:dirPath error:&error];
    if (error || !items) return;

    for (NSString *item in items) {
        if ([item hasPrefix:@".com.apple.mobile_container_manager"]) {
            continue;
        }
        // BẢO VỆ TUYỆT ĐỐI FILE BACKUP .adbk CỦA APPS MANAGER, FILE AUDIT LOG VÀ CẤU HÌNH TWEAK
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
}

static NSArray<NSString *> *get_zalo_data_container_paths(void) {
    NSMutableArray *paths = [NSMutableArray array];

    // Quét trực tiếp qua metadata trong thư mục Sandbox thực tế (Không dùng LSApplicationProxy containerURL)
    NSArray *baseDirs = @[@"/var/mobile/Containers/Data/Application", @"/private/var/mobile/Containers/Data/Application"];
    for (NSString *baseDir in baseDirs) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
        for (NSString *uuid in subdirs) {
            NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
            NSString *ident = meta[@"MCMMetadataIdentifier"];
            if (ident && [get_known_zalo_bundle_ids() containsObject:ident]) {
                NSString *fullP = [baseDir stringByAppendingPathComponent:uuid];
                if (is_valid_zalo_sandbox_path(fullP) && ![paths containsObject:fullP]) {
                    [paths addObject:fullP];
                }
            }
        }
        if (paths.count > 0) break;
    }
    return paths;
}

static NSArray<NSString *> *get_zalo_group_container_paths(void) {
    NSMutableArray *paths = [NSMutableArray array];

    NSArray *baseDirs = @[@"/var/mobile/Containers/Shared/AppGroup", @"/private/var/mobile/Containers/Shared/AppGroup"];
    for (NSString *baseDir in baseDirs) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
        for (NSString *uuid in subdirs) {
            NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
            NSString *identifier = meta[@"MCMMetadataIdentifier"];
            if (identifier && ([identifier containsString:@"zingalo"] ||
                               [identifier containsString:@"com.zing.zalo"] ||
                               [identifier containsString:@"com.vng.zalo"])) {
                NSString *fullP = [baseDir stringByAppendingPathComponent:uuid];
                if (is_valid_zalo_sandbox_path(fullP) && ![paths containsObject:fullP]) {
                    [paths addObject:fullP];
                }
            }
        }
        if (paths.count > 0) break;
    }
    return paths;
}

static void save_dict_to_all_locations(NSDictionary *dict) {
    [dict writeToFile:PREFS_PATH atomically:YES];
    chmod([PREFS_PATH UTF8String], 0644);

    NSArray *dataContainers = get_zalo_data_container_paths();
    for (NSString *dataContainer in dataContainers) {
        NSString *prefDir = [dataContainer stringByAppendingPathComponent:@"Library/Preferences"];
        [[NSFileManager defaultManager] createDirectoryAtPath:prefDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *p1 = [prefDir stringByAppendingPathComponent:@"com.sonhu.zalotweak.plist"];
        [dict writeToFile:p1 atomically:YES];
        chmod([p1 UTF8String], 0666);

        NSString *docDir = [dataContainer stringByAppendingPathComponent:@"Documents"];
        [[NSFileManager defaultManager] createDirectoryAtPath:docDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *p2 = [docDir stringByAppendingPathComponent:@"com.sonhu.zalotweak.plist"];
        [dict writeToFile:p2 atomically:YES];
        chmod([p2 UTF8String], 0666);
    }

    NSArray *groups = get_zalo_group_container_paths();
    for (NSString *grp in groups) {
        NSString *p3 = [grp stringByAppendingPathComponent:@"com.sonhu.zalotweak.plist"];
        [dict writeToFile:p3 atomically:YES];
        chmod([p3 UTF8String], 0666);
    }
}

#pragma mark - Actions

- (void)applyAndWipeCleanSequence:(PSSpecifier *)specifier {
    if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Chưa Kích Hoạt Bản Quyền"
                                                                       message:@"Vui lòng kích hoạt License Key hợp lệ ở phía trên trước khi sử dụng tính năng Đổi Máy & Wipe."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    UIAlertController *confirmAlert = [UIAlertController alertControllerWithTitle:@"Xác Nhận Wipe Sạch Toàn Diện"
                                                                          message:@"Hệ thống sẽ:\n1. Tắt triệt để Zalo & tiến trình ngầm\n2. Xóa sạch Container, Cache, WebKit, Cookies\n3. Xóa Clipboard\n4. Cấp IDFV, Boot Time & Keychain Profile mới 100%\n\nBạn có muốn tiếp tục?"
                                                                    preferredStyle:UIAlertControllerStyleAlert];

    [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Hủy" style:UIAlertActionStyleCancel handler:nil]];
    [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Tiến Hành Wipe" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self performWipeAndApply];
        });
    }]];

    [self presentViewController:confirmAlert animated:YES completion:nil];
}

- (void)performWipeAndApply {
    // 1. Tắt toàn bộ tiến trình
    kill_all_zalo_processes();

    // 2. Xóa sạch App Data Containers (Tất cả thư mục con trong Library, Documents, tmp - bảo vệ tuyệt đối file .adbk)
    NSArray *dataContainers = get_zalo_data_container_paths();
    for (NSString *dataContainer in dataContainers) {
        if (!is_valid_zalo_sandbox_path(dataContainer)) continue;

        wipe_directory_contents([dataContainer stringByAppendingPathComponent:@"Documents"]);
        wipe_directory_contents([dataContainer stringByAppendingPathComponent:@"tmp"]);

        NSString *libraryDir = [dataContainer stringByAppendingPathComponent:@"Library"];
        wipe_directory_contents(libraryDir);

        // Tái tạo sẵn khung thư mục rỗng chuẩn để Zalo không bị lỗi đọc/ghi khi vừa khởi động
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:[libraryDir stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:[libraryDir stringByAppendingPathComponent:@"Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:[libraryDir stringByAppendingPathComponent:@"Application Support"] withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:[dataContainer stringByAppendingPathComponent:@"Documents"] withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:[dataContainer stringByAppendingPathComponent:@"tmp"] withIntermediateDirectories:YES attributes:nil error:nil];
    }

    // 3. Xóa sạch Shared App Group
    NSArray *groupContainers = get_zalo_group_container_paths();
    for (NSString *groupPath in groupContainers) {
        if (!is_valid_zalo_sandbox_path(groupPath)) continue;
        wipe_directory_contents(groupPath);

        // Tái tạo khung thư mục rỗng chuẩn bên trong App Group để NSUserDefaults và SQLite của Zalo không bị crash
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *grpLib = [groupPath stringByAppendingPathComponent:@"Library"];
        [fm createDirectoryAtPath:[grpLib stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:[grpLib stringByAppendingPathComponent:@"Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
        [fm createDirectoryAtPath:[grpLib stringByAppendingPathComponent:@"Application Support"] withIntermediateDirectories:YES attributes:nil error:nil];
    }

    // 4. Xóa sạch Clipboard hệ thống để tránh tracking token
    [UIPasteboard generalPasteboard].items = @[];
    [UIPasteboard generalPasteboard].string = @"";

    // 5. Tạo định danh mới (New IDFV + New ProfileId + New BootTime + New DiskFree + New Serial + New MAC)
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:PREFS_PATH] ?: [NSMutableDictionary dictionary];

    NSString *oldIDFV = dict[@"spoofedIDFV"];
    if (oldIDFV && oldIDFV.length > 0) {
        dict[@"lastWipedIDFV"] = oldIDFV;
    }
    dict[@"lastWipedTimestamp"] = @((uint64_t)[[NSDate date] timeIntervalSince1970]);

    NSString *newIDFV = [[NSUUID UUID] UUIDString];
    NSString *newProfileId = [[NSUUID UUID] UUIDString];
    uint32_t randomOffset = 86400 + (arc4random_uniform(345600));
    uint64_t newBootTime = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;
    NSString *newBootUUID = [[NSUUID UUID] UUIDString];

    dict[@"enabled"] = @(YES);
    dict[@"spoofedIDFV"] = newIDFV;
    dict[@"spoofedIDFA"] = [[NSUUID UUID] UUIDString];
    dict[@"profileId"] = newProfileId;
    dict[@"bootTimeSec"] = @(newBootTime);
    dict[@"bootSessionUUID"] = newBootUUID;

    // Giữ nguyên 100% phần cứng máy thật
    dict[@"deviceMachine"] = get_prefs_real_machine();
    dict[@"deviceModel"] = get_prefs_real_model();
    dict[@"systemVersion"] = [[UIDevice currentDevice] systemVersion];
    dict[@"kernOsVersion"] = get_prefs_real_os_version();
    dict[@"ncpu"] = @((uint32_t)[[NSProcessInfo processInfo] activeProcessorCount]);
    dict[@"memsize"] = @([[NSProcessInfo processInfo] physicalMemory]);

    CGRect bounds = [UIScreen mainScreen].bounds;
    dict[@"screenWidth"] = @(bounds.size.width);
    dict[@"screenHeight"] = @(bounds.size.height);
    dict[@"screenScale"] = @([UIScreen mainScreen].scale);

    // Cấp Serial Number & MAC Address mới ngẫu nhiên mỗi lần Wipe
    dict[@"spoofedSerial"] = generate_random_serial_prefs();
    dict[@"spoofedWifiMAC"] = generate_random_mac_prefs();
    dict[@"spoofedBluetoothMAC"] = generate_random_mac_prefs();

    dict[@"batteryLevel"] = @(0.55f + ((float)arc4random_uniform(40)) / 100.0f);
    dict[@"batteryState"] = @(1);

    NSString *currentRegion = dict[@"regionMode"] ?: @"VN";
    [self syncCarrierForRegion:currentRegion inDict:dict];

    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    uint64_t totalDisk = [attrs[NSFileSystemSize] unsignedLongLongValue] ?: 128000000000ULL;
    dict[@"diskTotalSize"] = @(totalDisk);
    uint64_t randomUsed = 35000000000ULL + ((uint64_t)arc4random_uniform(45000000)) * 1000ULL;
    dict[@"diskFreeSize"] = @(totalDisk > randomUsed ? (totalDisk - randomUsed) : (totalDisk / 2));

    dict[@"wipePending"] = @(YES);

    // Ghi đồng thời ra tất cả các vùng nhớ để sandbox luôn đọc được
    save_dict_to_all_locations(dict);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.sonhu.zalotweak/settingschanged"), NULL, NULL, YES);

    // Truy vấn và lưu IP hiện tại để đối chiếu checklist
    fetch_public_ip_prefs(^(NSString *ip) {
        if (ip.length > 0 && ![ip isEqualToString:@"Không xác định"]) {
            NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfFile:PREFS_PATH] ?: [NSMutableDictionary dictionary];
            d[@"lastWipedIP"] = ip;
            save_dict_to_all_locations(d);
        }
    });

    // Cập nhật giao diện Settings
    [self reloadSpecifiers];

    // Thông báo hoàn tất
    NSString *msg = [NSString stringWithFormat:@"Đã làm sạch 100%% dữ liệu Zalo!\n\n- IDFV Mới: %@\n- Serial Number: %@\n- MAC Wi-Fi: %@\n- Keychain & WebKit: Phân vùng mới riêng biệt\n- Uptime: Cấp Boot Time ngẫu nhiên\n\n⚠️ BẮT BUỘC: Bật và Tắt Chế Độ Máy Bay (Airplane Mode) để đổi IP 4G trước khi mở lại Zalo.", newIDFV, dict[@"spoofedSerial"], dict[@"spoofedWifiMAC"]];

    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *doneAlert = [UIAlertController alertControllerWithTitle:@"🎉 Hoàn Tất Tuyệt Đối"
                                                                           message:msg
                                                                    preferredStyle:UIAlertControllerStyleAlert];
        [doneAlert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:doneAlert animated:YES completion:nil];
    });
}

- (id)getHardwareMachineValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    NSString *machine = dict[@"deviceMachine"] ?: get_prefs_real_machine();
    NSString *model = dict[@"deviceModel"] ?: get_prefs_real_model();
    if (model.length > 0) {
        return [NSString stringWithFormat:@"%@ (%@)", machine, model];
    }
    return machine;
}

- (id)getHardwareOSValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    NSString *sysVer = dict[@"systemVersion"] ?: [[UIDevice currentDevice] systemVersion];
    NSString *kernVer = dict[@"kernOsVersion"] ?: get_prefs_real_os_version();
    return [NSString stringWithFormat:@"iOS %@ (%@)", sysVer, kernVer];
}

- (id)getHardwareSpecsValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    uint32_t ncpu = [dict[@"ncpu"] unsignedIntValue] ?: (uint32_t)[[NSProcessInfo processInfo] activeProcessorCount];
    uint64_t ram = [dict[@"memsize"] unsignedLongLongValue] ?: [[NSProcessInfo processInfo] physicalMemory];
    double ramGB = (double)ram / (1024.0 * 1024.0 * 1024.0);
    return [NSString stringWithFormat:@"%u Cores | %.1f GB RAM", ncpu, ramGB];
}

- (id)getHardwareScreenValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    double w = [dict[@"screenWidth"] doubleValue] ?: [UIScreen mainScreen].bounds.size.width;
    double h = [dict[@"screenHeight"] doubleValue] ?: [UIScreen mainScreen].bounds.size.height;
    double s = [dict[@"screenScale"] doubleValue] ?: [UIScreen mainScreen].scale;
    return [NSString stringWithFormat:@"%.0f × %.0f (@%.0fx)", w, h, s];
}

- (id)getSpoofedSerialValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    return dict[@"spoofedSerial"] ?: @"Chưa cấp (Bấm Wipe)";
}

- (id)getSpoofedWifiMACValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    return dict[@"spoofedWifiMAC"] ?: @"Chưa cấp (Bấm Wipe)";
}

- (id)getSpoofedIDFVValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    NSString *idfv = dict[@"spoofedIDFV"];
    if (idfv.length > 18) {
        return [NSString stringWithFormat:@"%@...%@", [idfv substringToIndex:8], [idfv substringFromIndex:idfv.length - 6]];
    }
    return idfv ?: @"Chưa cấp";
}

- (id)getSpoofedProfileIdValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    NSString *pid = dict[@"profileId"];
    if (pid.length > 18) {
        return [NSString stringWithFormat:@"%@...%@", [pid substringToIndex:8], [pid substringFromIndex:pid.length - 6]];
    }
    return pid ?: @"Chưa cấp";
}

- (void)killZalo:(PSSpecifier *)specifier {
    kill_all_zalo_processes();

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Đã Đóng Zalo"
                                                                   message:@"Toàn bộ tiến trình Zalo đã được tắt."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - DRM License Actions

- (id)getRuntimeEnvironmentDisplayValue:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    NSString *envFromApp = dict[@"runtimeEnvironment"];
    if (envFromApp && envFromApp.length > 0) {
        return envFromApp;
    }
    
    // Nếu Zalo chưa mở, tự phát hiện môi trường nạp của chính PreferenceBundle
    Dl_info info;
    if (dladdr((const void *)save_dict_to_all_locations, &info) && info.dli_fname) {
        NSString *dpath = [NSString stringWithUTF8String:info.dli_fname];
        if ([dpath containsString:@"/jb-"] || [dpath containsString:@"roothide"]) {
            return @"🛡️ Roothide (DEB)";
        } else if ([dpath containsString:@"/var/jb/"] || [dpath containsString:@"/var/jb"]) {
            return @"⚡ Rootless (DEB)";
        } else if ([dpath containsString:@"/Library/PreferenceBundles/"]) {
            return @"👑 Rootful (DEB)";
        }
    }
    return @"🟢 Hoạt động (Chờ Zalo khởi động)";
}

- (id)getRealHardwareUDIDValue:(PSSpecifier *)specifier {
    return [[ZTSecurityManager sharedManager] getRealHardwareUDID];
}

- (void)copyRealUDIDAction:(PSSpecifier *)specifier {
    NSString *udid = [[ZTSecurityManager sharedManager] getRealHardwareUDID];
    [UIPasteboard generalPasteboard].string = udid;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Đã Sao Chép UDID"
                                                                   message:[NSString stringWithFormat:@"Đã sao chép mã UDID vào bộ nhớ tạm:\n\n%@", udid]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (id)getLicenseStatusDisplayValue:(PSSpecifier *)specifier {
    return [[ZTSecurityManager sharedManager] getLicenseStatusText];
}

- (void)activateLicenseAction:(PSSpecifier *)specifier {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    NSString *key = dict[@"licenseKeyInput"];
    if (!key || key.length == 0) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Chưa Nhập Key"
                                                                       message:@"Vui lòng nhập License Key vào ô bên trên trước khi bấm kích hoạt."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"Đang Xác Thực..."
                                                                     message:@"Đang kết nối tới Supabase để kiểm tra bản quyền và khóa máy..."
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:loading animated:YES completion:nil];

    [[ZTSecurityManager sharedManager] verifyLicenseWithKey:key completion:^(BOOL success, NSString *message) {
        [loading dismissViewControllerAnimated:YES completion:^{
            UIAlertController *result = [UIAlertController alertControllerWithTitle:success ? @"🎉 Kích Hoạt Thành Công" : @"❌ Kích Hoạt Thất Bại"
                                                                            message:message
                                                                     preferredStyle:UIAlertControllerStyleAlert];
            [result addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [self reloadSpecifiers];
            }]];
            [self presentViewController:result animated:YES completion:nil];
        }];
    }];
}

#pragma mark - Audit Log Actions

static NSString *findAuditLogPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *doc = [home stringByAppendingPathComponent:@"Documents/ZaloAudit.log"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:doc]) {
            return doc;
        }
    }
    for (NSString *zaloData in get_zalo_data_container_paths()) {
        NSString *zaloDoc = [zaloData stringByAppendingPathComponent:@"Documents/ZaloAudit.log"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:zaloDoc]) {
            return zaloDoc;
        }
    }
    return @"/var/mobile/Library/Preferences/ZaloAudit.log";
}

- (void)viewAuditLogAction:(PSSpecifier *)specifier {
    NSString *logPath = findAuditLogPath();
    NSError *err = nil;
    NSString *content = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:&err];

    if (!content || content.length == 0) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Chưa Có Dữ Liệu Log"
                                                                       message:@"Chưa có nhật ký nào được ghi lại.\n\nVui lòng đảm bảo bạn đã: \n1. Bật công tắc 'Bật Soi Log (Audit Mode)' ở trên\n2. Mở ứng dụng Zalo lên hoạt động trong 10-20 giây để tweak ghi nhận các truy vấn."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"📋 Nhật Ký Kiểm Toán Zalo"
                                                                   message:[content length] > 1500 ? [NSString stringWithFormat:@"%@\n\n... (và nhiều dòng khác)", [content substringToIndex:1500]] : content
                                                            preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"📤 Chia Sẻ / Lưu File" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSURL *fileURL = [NSURL fileURLWithPath:logPath];
        UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL] applicationActivities:nil];
        [self presentViewController:activityVC animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Diagnostic Checklist Actions

- (void)checkCleanlinessAction:(PSSpecifier *)specifier {
    UIAlertController *loading = [UIAlertController alertControllerWithTitle:@"🔍 Đang Kiểm Tra..."
                                                                     message:@"Đang truy vấn IP mạng công khai và rà soát độ sạch của hệ thống..."
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:loading animated:YES completion:^{
        fetch_public_ip_prefs(^(NSString *currentIP) {
            [loading dismissViewControllerAnimated:YES completion:^{
                [self renderDiagnosticReportWithIP:currentIP];
            }];
        });
    }];
}

- (void)renderDiagnosticReportWithIP:(NSString *)currentIP {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    
    NSString *lastIP = dict[@"lastWipedIP"] ?: @"";
    NSString *lastIDFV = dict[@"lastWipedIDFV"] ?: @"";
    NSString *currentIDFV = dict[@"spoofedIDFV"] ?: @"";
    NSString *machine = dict[@"deviceMachine"] ?: get_prefs_real_machine();
    NSString *model = dict[@"deviceModel"] ?: get_prefs_real_model();
    NSString *serial = dict[@"spoofedSerial"] ?: @"";
    NSString *mac = dict[@"spoofedWifiMAC"] ?: @"";
    
    BOOL isSameIP = (lastIP.length > 0 && [currentIP isEqualToString:lastIP]);
    BOOL isDifferentIP = (lastIP.length > 0 && ![currentIP isEqualToString:lastIP]);
    
    NSString *ipStatus = @"";
    if (isSameIP) {
        ipStatus = @"⚠️ TRÙNG IP LẦN WIPE TRƯỚC! (Cần gạt Airplane Mode)";
    } else if (isDifferentIP) {
        ipStatus = @"✅ ĐÃ ĐỔI IP MỚI";
    } else {
        ipStatus = @"✅ IP HIỆN TẠI HỢP LỆ";
    }
    
    BOOL isDuplicateIDFV = (lastIDFV.length > 0 && [currentIDFV isEqualToString:lastIDFV]);
    NSString *idfvStatus = isDuplicateIDFV ? @"❌ TRÙNG LẶP IDFV CŨ (Cần Wipe lại)" : @"✅ MỚI TINH";
    
    BOOL isLicensed = [[ZTSecurityManager sharedManager] isLicenseValid];
    NSString *licStatus = isLicensed ? @"✅ HỢP LỆ (BẢN QUYỀN MÁY)" : @"❌ CHƯA KÍCH HOẠT";
    
    // Kiểm tra dung lượng thư mục Sandbox Zalo
    uint64_t sandboxTotalBytes = 0;
    NSArray *zaloContainers = get_zalo_data_container_paths();
    for (NSString *container in zaloContainers) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *subpaths = [fm subpathsAtPath:container];
        for (NSString *sub in subpaths) {
            NSString *lower = [sub lowercaseString];
            if ([lower hasSuffix:@".adbk"] || [lower containsString:@"appsmanager"]) continue;
            NSDictionary *attrs = [fm attributesOfItemAtPath:[container stringByAppendingPathComponent:sub] error:nil];
            sandboxTotalBytes += [attrs fileSize];
        }
    }
    double sandboxMB = (double)sandboxTotalBytes / (1024.0 * 1024.0);
    
    NSMutableString *report = [NSMutableString string];
    if (!isSameIP && !isDuplicateIDFV && isLicensed) {
        [report appendString:@"🟢 ĐẠT CHUẨN AN TOÀN TUYỆT ĐỐI (SẴN SÀNG REG ACC)\n\n"];
    } else {
        [report appendString:@"🔴 PHÁT HIỆN CẢNH BÁO TRƯỚC KHI REG ACC:\n\n"];
    }
    
    [report appendFormat:@"• Địa chỉ IP mạng: %@ (%@)\n", currentIP, ipStatus];
    if (lastIP.length > 0) {
        [report appendFormat:@"• IP lần Wipe trước: %@\n", lastIP];
    }
    [report appendFormat:@"• IDFV: %@... (%@)\n", [currentIDFV substringToIndex:MIN((NSUInteger)8, currentIDFV.length)], idfvStatus];
    [report appendFormat:@"• Bản Quyền Tweak: %@\n", licStatus];
    [report appendFormat:@"• Dòng Máy Thật: %@ (%@)\n", machine, model];
    [report appendFormat:@"• Serial Number Ảo: %@\n", serial.length > 0 ? serial : @"Chưa cấp"];
    [report appendFormat:@"• MAC Wi-Fi Ảo: %@\n", mac.length > 0 ? mac : @"Chưa cấp"];
    [report appendFormat:@"• Dữ Liệu Sandbox Còn Lại: %.2f MB\n", sandboxMB];
    
    if (isSameIP) {
        [report appendString:@"\n⚠️ LƯU Ý BẮT BUỘC: Bạn chưa đổi IP mạng 4G. Hãy vuốt Control Center, bật Chế Độ Máy Bay trong 5 giây rồi tắt đi, sau đó kiểm tra lại!"];
    }
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🔍 Báo Cáo Kiểm Tra Độ Sạch"
                                                                   message:report
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

static NSString *findHarPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *doc = [home stringByAppendingPathComponent:@"Documents/ZaloTraffic.har"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:doc]) {
            return doc;
        }
    }
    for (NSString *zaloData in get_zalo_data_container_paths()) {
        NSString *zaloDoc = [zaloData stringByAppendingPathComponent:@"Documents/ZaloTraffic.har"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:zaloDoc]) {
            return zaloDoc;
        }
    }
    return @"/var/mobile/Library/Preferences/ZaloTraffic.har";
}

- (void)exportHarAction:(PSSpecifier *)specifier {
    NSString *harPath = findHarPath();
    if (![[NSFileManager defaultManager] fileExistsAtPath:harPath]) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Chưa Có Dữ Liệu HAR"
                                                                       message:@"Chưa có gói tin mạng HTTP/HTTPS nào được ghi lại.\n\nVui lòng đảm bảo bạn đã: \n1. Bật công tắc 'Bật Soi Log (Audit & HAR Mode)' ở trên\n2. Mở ứng dụng Zalo lên hoạt động trong 10-20 giây để tweak ghi nhận lưu lượng mạng."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    NSURL *fileURL = [NSURL fileURLWithPath:harPath];
    UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL] applicationActivities:nil];
    [self presentViewController:activityVC animated:YES completion:nil];
}

- (void)clearAuditLogAction:(PSSpecifier *)specifier {
    NSString *logPath = findAuditLogPath();
    [[NSFileManager defaultManager] removeItemAtPath:logPath error:nil];

    NSString *harPath = findHarPath();
    [[NSFileManager defaultManager] removeItemAtPath:harPath error:nil];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Đã Xóa Sạch"
                                                                   message:@"Toàn bộ lịch sử nhật ký kiểm toán (ZaloAudit.log) và gói tin mạng (ZaloTraffic.har) đã được xóa."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
