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

#define PREFS_PATH @"/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"
static inline NSArray<NSString *> *get_known_zalo_bundle_ids(void) {
    return @[
        @"vn.com.vng.zingalo",
        @"cn.com.vng.zingalo",
        @"com.zing.zalo",
        @"com.vng.zalo"
    ];
}

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
    // 1. Thử gọi FBSSystemService của SpringBoard qua dynamic messaging để đóng app
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
                                 strcasestr(name, "zing") != NULL ||
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
        // BẢO VỆ TUYỆT ĐỐI FILE BACKUP .adbk CỦA APPS MANAGER VÀ CÁC FOLDER BACKUP
        NSString *lower = [item lowercaseString];
        if ([lower hasSuffix:@".adbk"] ||
            [lower containsString:@"appsmanager"] ||
            [lower containsString:@"adbk"]) {
            continue;
        }
        NSString *fullPath = [dirPath stringByAppendingPathComponent:item];
        [fm removeItemAtPath:fullPath error:nil];
    }
}

static NSArray<NSString *> *get_zalo_data_container_paths(void) {
    NSMutableArray *paths = [NSMutableArray array];
    Class LSAppProxyClass = NSClassFromString(@"LSApplicationProxy");
    if (LSAppProxyClass && [LSAppProxyClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        for (NSString *bid in get_known_zalo_bundle_ids()) {
            LSApplicationProxy *proxy = [LSAppProxyClass applicationProxyForIdentifier:bid];
            if (proxy) {
                if ([proxy respondsToSelector:@selector(dataContainerURL)] && proxy.dataContainerURL) {
                    NSString *p = proxy.dataContainerURL.path;
                    if (p && ![paths containsObject:p]) [paths addObject:p];
                } else if ([proxy respondsToSelector:@selector(containerURL)] && proxy.containerURL) {
                    NSString *p = proxy.containerURL.path;
                    if (p && ![paths containsObject:p]) [paths addObject:p];
                }
            }
        }
    }

    NSString *baseDir = @"/var/mobile/Containers/Data/Application";
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
    for (NSString *uuid in subdirs) {
        NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        NSString *ident = meta[@"MCMMetadataIdentifier"];
        if (ident && ([ident containsString:@"zalo"] || [ident containsString:@"zingalo"] || [get_known_zalo_bundle_ids() containsObject:ident])) {
            NSString *fullP = [baseDir stringByAppendingPathComponent:uuid];
            if (![paths containsObject:fullP]) {
                [paths addObject:fullP];
            }
        }
    }
    return paths;
}

static NSArray<NSString *> *get_zalo_group_container_paths(void) {
    NSMutableArray *paths = [NSMutableArray array];
    Class LSAppProxyClass = NSClassFromString(@"LSApplicationProxy");
    if (LSAppProxyClass && [LSAppProxyClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        for (NSString *bid in get_known_zalo_bundle_ids()) {
            LSApplicationProxy *proxy = [LSAppProxyClass applicationProxyForIdentifier:bid];
            if (proxy && proxy.groupContainerURLs) {
                for (NSURL *url in proxy.groupContainerURLs.allValues) {
                    if (url.path && ![paths containsObject:url.path]) {
                        [paths addObject:url.path];
                    }
                }
            }
        }
    }

    NSString *baseDir = @"/var/mobile/Containers/Shared/AppGroup";
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
    for (NSString *uuid in subdirs) {
        NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        NSString *identifier = meta[@"MCMMetadataIdentifier"];
        if ([identifier containsString:@"zalo"] || [identifier containsString:@"zing"] || [identifier containsString:@"vng"]) {
            NSString *fullP = [baseDir stringByAppendingPathComponent:uuid];
            if (![paths containsObject:fullP]) {
                [paths addObject:fullP];
            }
        }
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

    dict[@"wipePending"] = @(YES);

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

- (void)clearAuditLogAction:(PSSpecifier *)specifier {
    NSString *logPath = findAuditLogPath();
    [[NSFileManager defaultManager] removeItemAtPath:logPath error:nil];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Đã Xóa Sạch"
                                                                   message:@"Toàn bộ lịch sử nhật ký kiểm toán ZaloAudit.log đã được xóa."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
