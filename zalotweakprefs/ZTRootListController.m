#import "ZTRootListController.h"
#import "SecurityManager.h"
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <signal.h>
#import <sys/stat.h>
#import <string.h>
#import <stdlib.h>

#define PREFS_PATH @"/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"
#define ZALO_BUNDLE_ID @"com.vng.zalo"

static void save_dict_to_all_locations(NSDictionary *dict);
static void kill_all_zalo_processes(void);

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
    if (!dict[@"deviceMachine"]) {
        dict[@"deviceMachine"] = @"iPhone14,2";
        [self syncHardwareSpecsForMachine:@"iPhone14,2" inDict:dict];
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

    if ([key isEqualToString:@"deviceMachine"]) {
        [self syncHardwareSpecsForMachine:(NSString *)value inDict:dict];
    }

    save_dict_to_all_locations(dict);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.sonhu.zalotweak/settingschanged"), NULL, NULL, YES);
}

- (void)syncHardwareSpecsForMachine:(NSString *)machine inDict:(NSMutableDictionary *)dict {
    if ([machine isEqualToString:@"iPhone14,2"]) { // 13 Pro
        dict[@"deviceModel"] = @"D63AP";
        dict[@"ncpu"] = @(6);
        dict[@"memsize"] = @(6442450944ULL);
        dict[@"systemVersion"] = @"16.5";
        dict[@"kernOsVersion"] = @"20F66";
        dict[@"screenWidth"] = @(390.0);
        dict[@"screenHeight"] = @(844.0);
        dict[@"screenScale"] = @(3.0);
        dict[@"diskTotalSize"] = @(128000000000ULL);
    } else if ([machine isEqualToString:@"iPhone15,2"]) { // 14 Pro
        dict[@"deviceModel"] = @"D73AP";
        dict[@"ncpu"] = @(6);
        dict[@"memsize"] = @(6442450944ULL);
        dict[@"systemVersion"] = @"16.6";
        dict[@"kernOsVersion"] = @"20G75";
        dict[@"screenWidth"] = @(393.0);
        dict[@"screenHeight"] = @(852.0);
        dict[@"screenScale"] = @(3.0);
        dict[@"diskTotalSize"] = @(256000000000ULL);
    } else if ([machine isEqualToString:@"iPhone16,2"]) { // 15 Pro Max
        dict[@"deviceModel"] = @"D84AP";
        dict[@"ncpu"] = @(6);
        dict[@"memsize"] = @(8589934592ULL);
        dict[@"systemVersion"] = @"17.4";
        dict[@"kernOsVersion"] = @"21E219";
        dict[@"screenWidth"] = @(430.0);
        dict[@"screenHeight"] = @(932.0);
        dict[@"screenScale"] = @(3.0);
        dict[@"diskTotalSize"] = @(256000000000ULL);
    } else if ([machine isEqualToString:@"iPhone13,2"]) { // iPhone 12
        dict[@"deviceModel"] = @"D53gAP";
        dict[@"ncpu"] = @(6);
        dict[@"memsize"] = @(4294967296ULL);
        dict[@"systemVersion"] = @"16.5";
        dict[@"kernOsVersion"] = @"20F66";
        dict[@"screenWidth"] = @(390.0);
        dict[@"screenHeight"] = @(844.0);
        dict[@"screenScale"] = @(3.0);
        dict[@"diskTotalSize"] = @(128000000000ULL);
    }

    uint64_t total = [dict[@"diskTotalSize"] unsignedLongLongValue] ?: 128000000000ULL;
    uint64_t randomUsed = 38000000000ULL + ((uint64_t)arc4random_uniform(25000000)) * 1000ULL;
    dict[@"diskFreeSize"] = @(total > randomUsed ? (total - randomUsed) : (total / 2));
}

#pragma mark - Helper Functions: Dọn dẹp dữ liệu Sandbox & Ghi cấu hình xuyên Sandbox

static void kill_all_zalo_processes(void) {
    // 1. Thử gọi FBSSystemService của SpringBoard để đóng app chính thức
    Class fbsClass = NSClassFromString(@"FBSSystemService");
    if (fbsClass && [fbsClass respondsToSelector:@selector(sharedService)]) {
        id service = [fbsClass sharedService];
        if ([service respondsToSelector:@selector(terminateApplication:forReason:andReport:withDescription:)]) {
            [service terminateApplication:ZALO_BUNDLE_ID forReason:1 andReport:NO withDescription:@"ZaloTweak Wipe"];
        }
    }

    // 2. Quét toàn bộ tiến trình qua POSIX sysctl để tiêu diệt sạch kể cả app extensions
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) == 0 && size > 0) {
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
        if (procs) {
            if (sysctl(mib, 4, procs, &size, NULL, 0) == 0) {
                int count = (int)(size / sizeof(struct kinfo_proc));
                for (int i = 0; i < count; i++) {
                    const char *name = procs[i].kp_proc.p_comm;
                    if (name && (strcasestr(name, "zalo") != NULL ||
                                 strcmp(name, "NotificationSer") == 0 ||
                                 strcmp(name, "NotificationCon") == 0)) {
                        kill(procs[i].kp_proc.p_pid, SIGKILL);
                    }
                }
            }
            free(procs);
        }
    }
    [NSThread sleepForTimeInterval:0.4];
}

static void wipe_directory_contents(NSString *dirPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dirPath]) return;

    NSError *error = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:dirPath error:&error];
    if (error || !items) return;

    for (NSString *item in items) {
        if ([item hasPrefix:@".com.apple.mobile_container_manager"]) {
            continue;
        }
        NSString *fullPath = [dirPath stringByAppendingPathComponent:item];
        [fm removeItemAtPath:fullPath error:nil];
    }
}

static NSString *get_zalo_data_container_path(void) {
    Class LSAppProxyClass = NSClassFromString(@"LSApplicationProxy");
    if (LSAppProxyClass && [LSAppProxyClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        LSApplicationProxy *proxy = [LSAppProxyClass applicationProxyForIdentifier:ZALO_BUNDLE_ID];
        if (proxy) {
            if ([proxy respondsToSelector:@selector(dataContainerURL)] && proxy.dataContainerURL) {
                return proxy.dataContainerURL.path;
            }
            if ([proxy respondsToSelector:@selector(containerURL)] && proxy.containerURL) {
                return proxy.containerURL.path;
            }
        }
    }

    NSString *baseDir = @"/var/mobile/Containers/Data/Application";
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
    for (NSString *uuid in subdirs) {
        NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        if ([meta[@"MCMMetadataIdentifier"] isEqualToString:ZALO_BUNDLE_ID]) {
            return [baseDir stringByAppendingPathComponent:uuid];
        }
    }
    return nil;
}

static NSArray<NSString *> *get_zalo_group_container_paths(void) {
    NSMutableArray *paths = [NSMutableArray array];
    Class LSAppProxyClass = NSClassFromString(@"LSApplicationProxy");
    if (LSAppProxyClass && [LSAppProxyClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        LSApplicationProxy *proxy = [LSAppProxyClass applicationProxyForIdentifier:ZALO_BUNDLE_ID];
        if (proxy && proxy.groupContainerURLs) {
            for (NSURL *url in proxy.groupContainerURLs.allValues) {
                if (url.path) [paths addObject:url.path];
            }
            return paths;
        }
    }

    NSString *baseDir = @"/var/mobile/Containers/Shared/AppGroup";
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
    for (NSString *uuid in subdirs) {
        NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        NSString *identifier = meta[@"MCMMetadataIdentifier"];
        if ([identifier containsString:@"zalo"] || [identifier containsString:@"vng"]) {
            [paths addObject:[baseDir stringByAppendingPathComponent:uuid]];
        }
    }
    return paths;
}

static void save_dict_to_all_locations(NSDictionary *dict) {
    [dict writeToFile:PREFS_PATH atomically:YES];
    chmod([PREFS_PATH UTF8String], 0644);

    NSString *dataContainer = get_zalo_data_container_path();
    if (dataContainer) {
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

    // 2. Xóa sạch App Data Container (Tất cả thư mục con trong Library, Documents, tmp)
    NSString *dataContainer = get_zalo_data_container_path();
    if (dataContainer) {
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
        wipe_directory_contents(groupPath);
    }

    // 4. Xóa sạch Clipboard hệ thống để tránh tracking token
    [UIPasteboard generalPasteboard].items = @[];
    [UIPasteboard generalPasteboard].string = @"";

    // 5. Tạo định danh mới (New IDFV + New ProfileId + New BootTime + New DiskFree)
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:PREFS_PATH] ?: [NSMutableDictionary dictionary];

    NSString *newIDFV = [[NSUUID UUID] UUIDString];
    NSString *newProfileId = [[NSUUID UUID] UUIDString];
    uint32_t randomOffset = 86400 + (arc4random_uniform(345600));
    uint64_t newBootTime = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;
    NSString *newBootUUID = [[NSUUID UUID] UUIDString];

    dict[@"enabled"] = @(YES);
    dict[@"spoofedIDFV"] = newIDFV;
    dict[@"profileId"] = newProfileId;
    dict[@"bootTimeSec"] = @(newBootTime);
    dict[@"bootSessionUUID"] = newBootUUID;

    NSString *currentMachine = dict[@"deviceMachine"] ?: @"iPhone14,2";
    [self syncHardwareSpecsForMachine:currentMachine inDict:dict];

    uint64_t totalDisk = [dict[@"diskTotalSize"] unsignedLongLongValue] ?: 128000000000ULL;
    uint64_t randomUsed = 42000000000ULL + ((uint64_t)arc4random_uniform(25000000)) * 1000ULL;
    dict[@"diskFreeSize"] = @(totalDisk > randomUsed ? (totalDisk - randomUsed) : 60000000000ULL);

    // Ghi đồng thời ra tất cả các vùng nhớ để sandbox luôn đọc được
    save_dict_to_all_locations(dict);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.sonhu.zalotweak/settingschanged"), NULL, NULL, YES);

    // Cập nhật giao diện Settings
    [self reloadSpecifiers];

    // Thông báo hoàn tất
    NSString *msg = [NSString stringWithFormat:@"Đã làm sạch 100%% dữ liệu Zalo!\n\n- IDFV Mới: %@\n- Keychain & WebKit: Phân vùng mới riêng biệt\n- Uptime: Cấp Boot Time ngẫu nhiên\n- Ổ cứng: Cấp dung lượng trống ngẫu nhiên\n\n⚠️ BẮT BUỘC: Bật và Tắt Chế Độ Máy Bay (Airplane Mode) để đổi IP 4G trước khi mở lại Zalo.", newIDFV];

    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *doneAlert = [UIAlertController alertControllerWithTitle:@"🎉 Hoàn Tất Tuyệt Đối"
                                                                           message:msg
                                                                    preferredStyle:UIAlertControllerStyleAlert];
        [doneAlert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:doneAlert animated:YES completion:nil];
    });
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

@end
