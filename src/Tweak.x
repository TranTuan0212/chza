#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Security/Security.h>
#import <CFNetwork/CFNetwork.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/attr.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <errno.h>
#import <stdarg.h>
#import <stdio.h>
#import <dlfcn.h>
#import "fishhook.h"
#import "Config.h"
#import "SecurityManager.h"
#import "FloatingMenu.h"
#import "DeviceProfilePool.h"

static void (*dynamic_MSHookFunction)(void *symbol, void *replace, void **result) = NULL;

static inline void universal_hook_c_function(const char *name, void *symbol, void *replace, void **result) {
    if (dynamic_MSHookFunction && symbol) {
        dynamic_MSHookFunction(symbol, replace, result);
    } else if (name) {
        struct rebinding r = { name, replace, result };
        rebind_symbols(&r, 1);
    }
}

static inline BOOL is_tweak_active(void) {
    static __thread BOOL s_in_active_check = NO;
    if (s_in_active_check) return NO;
    s_in_active_check = YES;
    // Chỉ fake khi tweak bật VÀ đã từng cấu hình profile (đã có key và đã từng bấm wipe)
    // Khi hết hạn, profile vẫn được đóng băng giữ nguyên để bảo vệ tài khoản, không rớt về máy thật!
    BOOL active = [ZTSettings sharedSettings].enabled && [ZTSettings sharedSettings].hasConfiguredProfile;
    s_in_active_check = NO;
    return active;
}

static int s_is_orig = -1;
static inline BOOL is_original_zalo_app(void) {
    if (s_is_orig != -1) return (s_is_orig == 1);
    s_is_orig = 0; // Guard tạm thời tránh đệ quy
    CFBundleRef mb = CFBundleGetMainBundle();
    if (mb) {
        CFStringRef bid = CFBundleGetIdentifier(mb);
        if (bid) {
            if (CFStringCompare(bid, CFSTR("vn.com.vng.zingalo"), 0) == kCFCompareEqualTo ||
                CFStringCompare(bid, CFSTR("com.vng.zalo"), 0) == kCFCompareEqualTo ||
                CFStringCompare(bid, CFSTR("com.zing.zalo"), 0) == kCFCompareEqualTo) {
                s_is_orig = 1;
                return YES;
            }
        }
    }
    return NO;
}

static inline __attribute__((unused)) BOOL has_system_preferenceloader(void) {
    static int s_has_pl = -1;
    if (s_has_pl != -1) return (s_has_pl == 1);
    const char *paths[] = {
        "/Library/PreferenceLoader/Preferences",
        "/var/jb/Library/PreferenceLoader/Preferences",
        "/var/jb/usr/lib",
        NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        if (access(paths[i], F_OK) == 0) {
            s_has_pl = 1;
            return YES;
        }
    }
    s_has_pl = 0;
    return NO;
}

static inline BOOL is_device_jailbroken(void) {
#if defined(THEOS_PACKAGE_SCHEME_ROOTHIDE) || defined(THEOS_PACKAGE_SCHEME_ROOTLESS)
    return YES;
#endif
    if (dlsym(RTLD_DEFAULT, "jbrand") != NULL ||
        dlsym(RTLD_DEFAULT, "jbroot") != NULL ||
        dlsym(RTLD_DEFAULT, "roothide_check_path") != NULL ||
        dlsym(RTLD_DEFAULT, "MSHookFunction") != NULL ||
        dlsym(RTLD_DEFAULT, "ellekit_hook_c_function") != NULL ||
        dlsym(RTLD_DEFAULT, "cydia_substitute_hook_functions") != NULL ||
        getenv("JB_ROOT_PATH") != NULL ||
        getenv("ROOTHIDE_JB_ROOT_PATH") != NULL ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
        return YES;
    }

    Dl_info info;
    if (dladdr((const void *)is_device_jailbroken, &info) && info.dli_fname) {
        NSString *dpath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *appBundle = [[NSBundle mainBundle] bundlePath];
        if (appBundle && ![dpath hasPrefix:appBundle]) {
            return YES; // Nạp từ ngoài App Bundle -> Chắc chắn là môi trường Jailbreak!
        }
    }
    return NO;
}

static inline BOOL is_system_caller(void *addr0, void *addr1) {
    // 1. Nếu trực tiếp người gọi (addr0) là code nằm trong Zalo.app (chính app Zalo gọi):
    if (addr0) {
        Dl_info info0;
        if (dladdr(addr0, &info0) && info0.dli_fname) {
            const char *f0 = info0.dli_fname;
            if ((strstr(f0, ".app/") != NULL || strstr(f0, "/Zalo.app") != NULL) && strstr(f0, "Zalotweak") == NULL) {
                return NO; // Chắc chắn là code thực thi của Zalo, không phải hệ thống
            }
        }
    }

    // 2. Kiểm tra nếu là các framework/daemon hệ thống của Apple
    void *addrs[2] = {addr0, addr1};
    for (int i = 0; i < 2; i++) {
        if (!addrs[i]) continue;
        Dl_info info;
        if (dladdr(addrs[i], &info) && info.dli_fname) {
            const char *fname = info.dli_fname;
            if (strstr(fname, "/System/Library/") != NULL ||
                strstr(fname, "/usr/lib/") != NULL ||
                strstr(fname, "CFNetwork") != NULL ||
                strstr(fname, "Network") != NULL ||
                strstr(fname, "libnetwork") != NULL ||
                strstr(fname, "CoreTelephony") != NULL ||
                strstr(fname, "UserNotifications") != NULL ||
                strstr(fname, "CoreFoundation") != NULL ||
                strstr(fname, "Security") != NULL ||
                strstr(fname, "SystemConfiguration") != NULL ||
                strstr(fname, "Substrate") != NULL ||
                strstr(fname, "ellekit") != NULL ||
                strstr(fname, "ElleKit") != NULL ||
                strstr(fname, "roothide") != NULL ||
                strstr(fname, "Zalotweak") != NULL) {
                return YES;
            }
        }
    }
    return NO;
}

#define GLOBAL_PREFS_PATH @"/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"
#define GLOBAL_AUDIT_LOG_PATH @"/var/mobile/Library/Preferences/ZaloAudit.log"

static NSString *get_roothide_prefs_path(void) {
    typedef const char* (*jbroot_fn_t)(const char*);
    jbroot_fn_t jbroot_fn = (jbroot_fn_t)dlsym(RTLD_DEFAULT, "jbroot");
    if (jbroot_fn) {
        const char *p = jbroot_fn("/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist");
        if (p) return [NSString stringWithUTF8String:p];
    }
    return GLOBAL_PREFS_PATH;
}

// Tìm đường dẫn file cấu hình tối ưu để vượt rào Sandbox
static NSString *getConfigPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *containerPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        NSFileManager *fm = [NSFileManager defaultManager];

        // Luôn kiểm tra các ứng viên toàn cục từ Cài Đặt (Roothide / Rootless / jbroot) xem có bản ghi mới hơn không
        NSString *rhPath = get_roothide_prefs_path();
        NSArray *globalCandidates = @[
            rhPath,
            GLOBAL_PREFS_PATH,
            @"/var/jb/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist",
            @"/private/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"
        ];

        NSDate *localDate = nil;
        if ([fm fileExistsAtPath:containerPref]) {
            NSDictionary *localAttrs = [fm attributesOfItemAtPath:containerPref error:nil];
            localDate = localAttrs[NSFileModificationDate];
        }

        for (NSString *candidate in globalCandidates) {
            if ([fm fileExistsAtPath:candidate]) {
                NSDictionary *candAttrs = [fm attributesOfItemAtPath:candidate error:nil];
                NSDate *candDate = candAttrs[NSFileModificationDate];
                // Nếu file Sandbox chưa có HOẶC file Cài Đặt toàn cục mới hơn file Sandbox:
                if (!localDate || (candDate && [candDate compare:localDate] == NSOrderedDescending)) {
                    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:candidate];
                    if (d && d.count > 0) {
                        [fm createDirectoryAtPath:[containerPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
                        [d writeToFile:containerPref atomically:YES];
                        chmod([containerPref UTF8String], 0666);
                        return containerPref;
                    }
                }
            }
        }

        if ([fm fileExistsAtPath:containerPref]) {
            return containerPref;
        }

        NSString *containerDoc = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        if ([fm fileExistsAtPath:containerDoc]) {
            return containerDoc;
        }

        // Khi file chưa tồn tại (lần đầu chạy), luôn trả về containerPref
        return containerPref;
    }

    NSString *groupBase = @"/var/mobile/Containers/Shared/AppGroup";
    NSArray *subdirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:groupBase error:nil];
    for (NSString *uuid in subdirs) {
        NSString *metaPath = [groupBase stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        NSString *identifier = meta[@"MCMMetadataIdentifier"];
        if ([identifier containsString:@"zalo"] || [identifier containsString:@"vng"]) {
            NSString *groupPref = [groupBase stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/com.sonhu.zalotweak.plist", uuid]];
            if ([[NSFileManager defaultManager] fileExistsAtPath:groupPref]) {
                return groupPref;
            }
        }
    }

    return GLOBAL_PREFS_PATH;
}

static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;

static NSString *get_real_hardware_machine(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    if (orig_sysctlbyname) {
        orig_sysctlbyname("hw.machine", buf, &size, NULL, 0);
    } else {
        sysctlbyname("hw.machine", buf, &size, NULL, 0);
    }
    if (strlen(buf) > 0) {
        return [NSString stringWithUTF8String:buf];
    }
    struct utsname u;
    if (uname(&u) == 0 && strlen(u.machine) > 0) {
        return [NSString stringWithUTF8String:u.machine];
    }
    return @"iPhone14,5";
}

static NSString *get_real_hardware_model(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    if (orig_sysctlbyname) {
        orig_sysctlbyname("hw.model", buf, &size, NULL, 0);
    } else {
        sysctlbyname("hw.model", buf, &size, NULL, 0);
    }
    if (strlen(buf) > 0) {
        return [NSString stringWithUTF8String:buf];
    }
    return @"D17AP";
}

static NSString *get_real_os_version(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    if (orig_sysctlbyname) {
        orig_sysctlbyname("kern.osversion", buf, &size, NULL, 0);
    } else {
        sysctlbyname("kern.osversion", buf, &size, NULL, 0);
    }
    if (strlen(buf) > 0) {
        return [NSString stringWithUTF8String:buf];
    }
    return @"21F90";
}

static uint64_t get_real_disk_total_size(void) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    NSNumber *total = attrs[NSFileSystemSize];
    if (total && [total unsignedLongLongValue] > 0) {
        return [total unsignedLongLongValue];
    }
    return 128000000000ULL;
}
// Forward declaration - hàm logAudit được định nghĩa ở phần sau
static void logAudit(NSString *category, NSString *detail);

@implementation ZTSettings

+ (instancetype)sharedSettings {
    static ZTSettings *instance = nil;
    if (instance) return instance;
    static BOOL s_initializing = NO;
    if (s_initializing) return instance;
    s_initializing = YES;
    instance = [[ZTSettings alloc] init];
    [instance loadSettings];
    s_initializing = NO;
    return instance;
}

static void purge_directory_recursively_safely(NSString *targetPath) {
    if (!targetPath || targetPath.length == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:targetPath isDirectory:&isDir]) return;

    NSString *lower = [targetPath lowercaseString];
    if ([lower hasSuffix:@".adbk"] ||
        [lower containsString:@"appsmanager"] ||
        [lower containsString:@"com.sonhu.zalotweak"] ||
        [lower containsString:@"zaloaudit.log"] ||
        [lower containsString:@"zalotraffic.har"]) {
        return;
    }

    if (!isDir) {
        [fm removeItemAtPath:targetPath error:nil];
        return;
    }

    NSArray *contents = [fm contentsOfDirectoryAtPath:targetPath error:nil];
    for (NSString *sub in contents) {
        NSString *subLower = [sub lowercaseString];
        if ([subLower hasSuffix:@".adbk"] ||
            [subLower containsString:@"appsmanager"] ||
            [subLower containsString:@"com.sonhu.zalotweak"] ||
            [subLower isEqualToString:@"zaloaudit.log"] ||
            [subLower isEqualToString:@"zalotraffic.har"]) {
            continue;
        }
        NSString *fullSub = [targetPath stringByAppendingPathComponent:sub];
        purge_directory_recursively_safely(fullSub);
    }
    // Không xoá chính thư mục gốc Library hoặc Documents
    NSString *lastComp = [targetPath lastPathComponent];
    if (![lastComp isEqualToString:@"Library"] && ![lastComp isEqualToString:@"Documents"] && ![lastComp isEqualToString:@"tmp"]) {
        [fm removeItemAtPath:targetPath error:nil];
    }
}

static BOOL s_is_cold_boot_phase = YES;

static void clear_all_network_caches(void) {
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
    NSHTTPCookieStorage *cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (NSHTTPCookie *cookie in [cookieStorage cookies]) {
        [cookieStorage deleteCookie:cookie];
    }
    if ([NSURLSessionConfiguration respondsToSelector:@selector(defaultSessionConfiguration)]) {
        NSURLSessionConfiguration *def = [NSURLSessionConfiguration defaultSessionConfiguration];
        [def.URLCache removeAllCachedResponses];
        if (def.HTTPCookieStorage) {
            for (NSHTTPCookie *c in [def.HTTPCookieStorage cookies]) {
                [def.HTTPCookieStorage deleteCookie:c];
            }
        }
    }
}

static void reset_audit_log_on_wipe(NSString *machine, NSString *idfv) {
    NSString *home = NSHomeDirectory();
    if (!home) return;
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *auditPath = [docDir stringByAppendingPathComponent:@"ZaloAudit.log"];
    NSString *harPath = [docDir stringByAppendingPathComponent:@"ZaloTraffic.har"];

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:harPath error:nil];

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    NSString *timeStr = [df stringFromDate:[NSDate date]];

    NSString *header = [NSString stringWithFormat:
        @"================================================================================\n"
        @"🚀 [SYSTEM-INIT] === BẮT ĐẦU PHIÊN AUDIT MỚI SAU DEEP WIPE ===\n"
        @"🕒 Thời gian kích hoạt: %@\n"
        @"📱 Thiết bị: %@ | IDFV: %@\n"
        @"================================================================================\n\n",
        timeStr, machine ?: @"iPhone", idfv ?: @"N/A"];

    [header writeToFile:auditPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    chmod([auditPath UTF8String], 0666);

    if (is_device_jailbroken()) {
        [header writeToFile:GLOBAL_AUDIT_LOG_PATH atomically:YES encoding:NSUTF8StringEncoding error:nil];
        chmod([GLOBAL_AUDIT_LOG_PATH UTF8String], 0666);
    }
}

static void purge_all_zalo_keychain_safely(void) {
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    NSArray *groups = @[
        @"",
        @"group.vn.com.vng.zingalo",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo",
        @"vn.com.vng.zingalo"
    ];

    for (id secClass in secClasses) {
        for (NSString *grp in groups) {
            NSMutableDictionary *query = [NSMutableDictionary dictionary];
            query[(__bridge id)kSecClass] = secClass;
            if (grp.length > 0) {
                query[(__bridge id)kSecAttrAccessGroup] = grp;
            }
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
    }
    NSLog(@"[ZaloAudit] [COLD-BOOT] 🔑 Đã dọn dẹp sạch toàn bộ Keychain của Zalo!");
}

static void purge_webkit_data_safely(void) {
    Class wkClass = NSClassFromString(@"WKWebsiteDataStore");
    if (wkClass && [wkClass respondsToSelector:@selector(allWebsiteDataTypes)] && [wkClass respondsToSelector:@selector(defaultDataStore)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id types = [wkClass performSelector:@selector(allWebsiteDataTypes)];
        id dataStore = [wkClass performSelector:@selector(defaultDataStore)];
        if (dataStore && [dataStore respondsToSelector:@selector(removeDataOfTypes:modifiedSince:completionHandler:)]) {
            NSDate *dateFrom = [NSDate dateWithTimeIntervalSince1970:0];
            typedef void (*RemoveDataFunc)(id, SEL, id, NSDate *, void (^)(void));
            SEL sel = @selector(removeDataOfTypes:modifiedSince:completionHandler:);
            RemoveDataFunc fn = (RemoveDataFunc)[dataStore methodForSelector:sel];
            if (fn) {
                fn(dataStore, sel, types, dateFrom, ^{});
            }
        }
#pragma clang diagnostic pop
    }
}

static void purge_entire_sandbox_safely(void) {
    NSString *home = NSHomeDirectory();
    if (!home || home.length < 5) return;
    NSFileManager *fm = [NSFileManager defaultManager];

    NSLog(@"[ZaloAudit] [COLD-BOOT] 🧹 Bắt đầu dọn dẹp sạch toàn bộ Sandbox tại Cold-Boot (App chưa khóa file)...");

    // 1. Quét sạch toàn bộ Keychain của Zalo để không bị dính vết vi phạm của tài khoản cũ
    purge_all_zalo_keychain_safely();

    // 2. Xóa sạch Pasteboard / Clipboard
    @try {
        [UIPasteboard generalPasteboard].items = @[];
        [UIPasteboard generalPasteboard].string = @"";
    } @catch (__unused NSException *e) {}

    // 3. Xóa sạch WebKit DataStore (Cookies, LocalStorage, IndexedDB)
    purge_webkit_data_safely();

    // 4. Xóa sạch dữ liệu in-memory của NSUserDefaults các App Suites
    NSArray *suitesToPurge = @[
        @"group.vn.com.vng.zingalo",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo",
        @"com.zing.zalo.chatMigrateStore",
        @"vn.com.vng.zingalo.zalosdk",
        @"com.zing.zalo",
        @"vn.com.vng.zingalo"
    ];
    for (NSString *suite in suitesToPurge) {
        NSUserDefaults *ud = [[NSUserDefaults alloc] initWithSuiteName:suite];
        if (ud) {
            NSDictionary *d = [ud dictionaryRepresentation];
            for (NSString *k in d.allKeys) {
                [ud removeObjectForKey:k];
            }
            [ud synchronize];
        }
    }

    // 5. Xả sạch cache mạng bộ nhớ RAM
    clear_all_network_caches();

    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *libDir = [home stringByAppendingPathComponent:@"Library"];
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];

    // 6. Quét dọn triệt để Documents và tmp
    purge_directory_recursively_safely(docDir);
    purge_directory_recursively_safely(tmpDir);

    // 7. Quét dọn toàn bộ các thư mục con trong Library (WebKit, Caches, Application Support, HTTPStorages, Cookies...)
    NSArray *libItems = [fm contentsOfDirectoryAtPath:libDir error:nil];
    for (NSString *item in libItems) {
        NSString *lower = [item lowercaseString];
        if ([lower containsString:@"com.sonhu.zalotweak"]) continue;

        NSString *subDir = [libDir stringByAppendingPathComponent:item];
        if ([lower isEqualToString:@"preferences"]) {
            // Preferences: chỉ xóa các file plist của app và zalo, giữ lại cấu hình tweak
            NSArray *pItems = [fm contentsOfDirectoryAtPath:subDir error:nil];
            for (NSString *pItem in pItems) {
                if ([pItem.lowercaseString containsString:@"com.sonhu.zalotweak"]) continue;
                [fm removeItemAtPath:[subDir stringByAppendingPathComponent:pItem] error:nil];
            }
        } else {
            purge_directory_recursively_safely(subDir);
        }
    }

    // 8. Quét dọn Shared App Groups (nếu có quyền truy cập nhóm)
    NSArray *groupNames = @[@"group.vn.com.vng.zingalo", @"group.com.vng.zalo", @"group.com.zing.zalo"];
    for (NSString *grp in groupNames) {
        NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:grp];
        if (groupURL) {
            NSString *groupPath = [groupURL path];
            purge_directory_recursively_safely(groupPath);
        }
    }

    // 9. Tái tạo sẵn khung thư mục rỗng chuẩn để Zalo không bị crash I/O khi nạp
    [fm createDirectoryAtPath:docDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"WebKit"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"HTTPStorages"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Application Support/KVCore/Device"] withIntermediateDirectories:YES attributes:nil error:nil];

    NSLog(@"[ZaloAudit] [COLD-BOOT] ✅ Hoàn tất dọn dẹp sạch toàn bộ Sandbox, Keychain & WebKit!");
}

- (void)loadSettings {
    NSString *path = getConfigPath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!dict) {
        CFPreferencesAppSynchronize(CFSTR("com.sonhu.zalotweak"));
        CFDictionaryRef cfDict = CFPreferencesCopyMultiple(NULL, CFSTR("com.sonhu.zalotweak"), kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        if (cfDict) {
            dict = [NSDictionary dictionaryWithDictionary:(__bridge NSDictionary *)cfDict];
            CFRelease(cfDict);
            if (dict.count > 0) {
                // Tự động lưu bản sao vào container Sandbox để các lần sau đọc siêu tốc
                NSString *home = NSHomeDirectory();
                if (home) {
                    NSString *localPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
                    [[NSFileManager defaultManager] createDirectoryAtPath:[localPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
                    [dict writeToFile:localPref atomically:YES];
                }
            }
        }
    }
    if (dict) {
        self.enabled = [dict[@"enabled"] boolValue];
        self.hasConfiguredProfile = [dict[@"hasConfiguredProfile"] boolValue];
        self.proxyEnabled = [dict[@"proxyEnabled"] boolValue];
        self.proxyType = dict[@"proxyType"] ?: @"HTTP";
        self.proxyHost = dict[@"proxyHost"] ?: @"";
        self.proxyPort = [dict[@"proxyPort"] unsignedShortValue];
        self.proxyUser = dict[@"proxyUser"] ?: @"";
        self.proxyPass = dict[@"proxyPass"] ?: @"";

        self.deviceMachine = dict[@"deviceMachine"] ?: get_real_hardware_machine();
        self.deviceModel = dict[@"deviceModel"] ?: get_real_hardware_model();
        self.deviceName = dict[@"deviceName"] ?: @"iPhone";
        self.systemVersion = dict[@"systemVersion"] ?: [[UIDevice currentDevice] systemVersion];
        self.kernOsVersion = dict[@"kernOsVersion"] ?: get_real_os_version();
        self.ncpu = [dict[@"ncpu"] unsignedIntValue] ?: (uint32_t)[[NSProcessInfo processInfo] activeProcessorCount];
        self.memsize = [dict[@"memsize"] unsignedLongLongValue] ?: [[NSProcessInfo processInfo] physicalMemory];
        self.screenWidth = [dict[@"screenWidth"] doubleValue] ?: [UIScreen mainScreen].bounds.size.width;
        self.screenHeight = [dict[@"screenHeight"] doubleValue] ?: [UIScreen mainScreen].bounds.size.height;
        self.screenScale = [dict[@"screenScale"] doubleValue] ?: [UIScreen mainScreen].scale;
        self.bootTimeSec = [dict[@"bootTimeSec"] unsignedLongLongValue] ?: 0;
        self.birthTimeSec = [dict[@"birthTimeSec"] unsignedLongLongValue] ?: 0;
        self.autoSyncTimezoneWithIP = dict[@"autoSyncTimezoneWithIP"] != nil ? [dict[@"autoSyncTimezoneWithIP"] boolValue] : YES;
        self.bootSessionUUID = dict[@"bootSessionUUID"] ?: @"";
        self.spoofedIDFV = dict[@"spoofedIDFV"] ?: (self.hasConfiguredProfile ? [[NSUUID UUID] UUIDString] : @"");
        self.spoofedIDFA = dict[@"spoofedIDFA"] ?: @"00000000-0000-0000-0000-000000000000";
        self.profileId = dict[@"profileId"] ?: (self.hasConfiguredProfile ? [[NSUUID UUID] UUIDString] : @"");
        self.diskTotalSize = [dict[@"diskTotalSize"] unsignedLongLongValue] ?: get_real_disk_total_size();
        self.diskFreeSize = [dict[@"diskFreeSize"] unsignedLongLongValue] ?: 74218940000ULL;
        self.enableAuditLog = [dict[@"enableAuditLog"] boolValue];
        self.lastWipedIDFV = dict[@"lastWipedIDFV"] ?: @"";
        self.lastWipedIP = dict[@"lastWipedIP"] ?: @"";
        self.lastWipedTimestamp = [dict[@"lastWipedTimestamp"] unsignedLongLongValue] ?: 0;
        self.carrierName = dict[@"carrierName"] ?: @"Viettel";
        self.carrierMCC = dict[@"carrierMCC"] ?: @"452";
        self.carrierMNC = dict[@"carrierMNC"] ?: @"04";
        self.carrierCountryCode = dict[@"carrierCountryCode"] ?: @"vn";
        self.batteryLevel = [dict[@"batteryLevel"] floatValue] ?: 0.85f;
        self.batteryState = [dict[@"batteryState"] integerValue] ?: 1;
        self.regionMode = dict[@"regionMode"] ?: @"VN";
        self.preferredCarrier = dict[@"preferredCarrier"] ?: @"";
        self.l2cacheSize = [dict[@"l2cacheSize"] unsignedLongLongValue] ?: 3145728ULL;
        self.localeIdentifier = dict[@"localeIdentifier"] ?: ([self.regionMode isEqualToString:@"US"] ? @"en_US" : @"vi_VN");
        self.timeZoneName = dict[@"timeZoneName"] ?: ([self.regionMode isEqualToString:@"US"] ? @"America/New_York" : @"Asia/Ho_Chi_Minh");
        if ([self.regionMode isEqualToString:@"VN"] && ([self.timeZoneName isEqualToString:@"Asia/Bangkok"] || [self.timeZoneName isEqualToString:@"Asia/Saigon"])) {
            self.timeZoneName = @"Asia/Ho_Chi_Minh";
        }
        self.preferredLanguages = dict[@"preferredLanguages"] ?: ([self.regionMode isEqualToString:@"US"] ? @[@"en-US"] : @[@"vi-VN", @"en-VN"]);
        self.spoofedSerial = dict[@"spoofedSerial"] ?: @"";
        self.spoofedWifiMAC = dict[@"spoofedWifiMAC"] ?: @"";
        self.spoofedBluetoothMAC = dict[@"spoofedBluetoothMAC"] ?: @"";

        BOOL isAppExtension = [[NSBundle mainBundle].bundlePath containsString:@".appex"];
        if (isAppExtension) {
            self.showFloatingMenu = NO;
        } else if (dict[@"showFloatingMenu"] != nil) {
            self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
        } else {
            self.showFloatingMenu = is_device_jailbroken() ? NO : YES; // Jailbreak (Roothide): Mặc định NO để tàng hình tuyệt đối khỏi Zalo UI audit; Non-JB: Mặc định YES
        }

        self.needsNewProfile = [dict[@"needsNewProfile"] boolValue];
        self.needsSandboxPurge = [dict[@"needsSandboxPurge"] boolValue];
        if (self.needsNewProfile || self.needsSandboxPurge) {
            if (s_is_cold_boot_phase) {
                if ([[ZTSecurityManager sharedManager] isLicenseValid]) {
                    logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] 🧹 Phát hiện cờ yêu cầu máy mới / dọn sạch sau Deep Wipe -> Khởi động dọn sạch Sandbox...");
                    purge_entire_sandbox_safely();
                    self.needsNewProfile = NO;
                    self.needsSandboxPurge = NO;
                    self.justGeneratedColdBoot = YES;
                    if (dict[@"showFloatingMenu"] != nil) {
                        self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
                    } else {
                        self.showFloatingMenu = is_device_jailbroken() ? NO : YES;
                    }
                    self.regionMode = dict[@"regionMode"] ?: (self.regionMode ?: @"VN");
                    self.preferredCarrier = dict[@"preferredCarrier"] ?: @"";
                    [self generateNewProfile];
                    reset_audit_log_on_wipe(self.deviceMachine, self.spoofedIDFV);
                    return;
                } else {
                    logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] Chưa có bản quyền hợp lệ -> Từ chối cấp Profile mới!");
                    self.needsNewProfile = NO;
                    self.needsSandboxPurge = NO;
                    [self saveSettings];
                }
            } else {
                // Đang trong runtime của app, bảo toàn cờ để dành cho Cold-Boot thực sự khi khởi động lại!
                return;
            }
        }

        if (self.hasConfiguredProfile && (!dict[@"spoofedIDFV"] || !dict[@"spoofedIDFA"] || !dict[@"profileId"] || self.bootTimeSec == 0 || self.birthTimeSec == 0 || self.spoofedSerial.length == 0)) {
            if (self.spoofedSerial.length == 0) {
                extern NSString *generate_random_serial(void);
                extern NSString *generate_random_mac(void);
                self.spoofedSerial = generate_random_serial();
                self.spoofedWifiMAC = generate_random_mac();
                self.spoofedBluetoothMAC = generate_random_mac();
            }
            if (self.bootTimeSec == 0) {
                uint32_t randomOffset = 86400 + (arc4random_uniform(345600)) + arc4random_uniform(59);
                self.bootTimeSec = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;
                self.bootSessionUUID = [[NSUUID UUID] UUIDString];
            }
            if (self.birthTimeSec == 0) {
                uint64_t launch = 1632441600ULL;
                self.birthTimeSec = launch + arc4random_uniform(90000000ULL);
                if (self.birthTimeSec >= self.bootTimeSec) {
                    self.birthTimeSec = self.bootTimeSec - (86400ULL * 30ULL + arc4random_uniform(86400 * 180) + arc4random_uniform(3599));
                }
            }
            [self saveSettings];
        }
    } else {
        self.enabled = YES;
        self.showFloatingMenu = is_device_jailbroken() ? NO : YES;
        self.hasConfiguredProfile = NO; // MỚI CÀI ĐẶT: CHƯA CẤU HÌNH -> KHÔNG FAKE MÁY NGAY!
        self.enableAuditLog = NO;
        self.lastWipedIDFV = @"";
        self.lastWipedIP = @"";
        self.lastWipedTimestamp = 0;
        self.regionMode = @"VN";
        self.needsNewProfile = NO;
        self.needsSandboxPurge = NO;
        self.proxyEnabled = NO;
        self.proxyType = @"HTTP";
        self.proxyHost = @"";
        self.proxyPort = 0;
        self.proxyUser = @"";
        self.proxyPass = @"";
        self.spoofedSerial = @"";
        self.spoofedWifiMAC = @"";
        self.spoofedBluetoothMAC = @"";
        self.spoofedIDFV = @"";
        self.profileId = @"";
        // Giữ 100% thông số máy thật:
        self.deviceMachine = get_real_hardware_machine();
        self.deviceModel = get_real_hardware_model();
        self.deviceName = @"iPhone";
        self.systemVersion = [[UIDevice currentDevice] systemVersion];
        self.kernOsVersion = get_real_os_version();
        self.ncpu = (uint32_t)[[NSProcessInfo processInfo] activeProcessorCount];
        self.memsize = [[NSProcessInfo processInfo] physicalMemory];
        CGRect bounds = [UIScreen mainScreen].bounds;
        self.screenWidth = bounds.size.width;
        self.screenHeight = bounds.size.height;
        self.screenScale = [UIScreen mainScreen].scale;
        self.bootTimeSec = 0;
        self.birthTimeSec = 0;
        self.autoSyncTimezoneWithIP = YES;
        self.bootSessionUUID = @"";
        self.carrierName = @"Viettel";
        self.carrierMCC = @"452";
        self.carrierMNC = @"04";
        self.carrierCountryCode = @"vn";
        self.batteryLevel = 0.85f;
        self.batteryState = 1;
        BOOL isAppExtension = [[NSBundle mainBundle].bundlePath containsString:@".appex"];
        if (isAppExtension) {
            self.showFloatingMenu = NO;
        }
        [self saveSettings];
    }
}

- (void)saveSettings {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"enabled"] = @(self.enabled);
    dict[@"enableAuditLog"] = @(self.enableAuditLog);
    dict[@"hasConfiguredProfile"] = @(self.hasConfiguredProfile);
    dict[@"proxyEnabled"] = @(self.proxyEnabled);
    dict[@"proxyType"] = self.proxyType ?: @"HTTP";
    dict[@"proxyHost"] = self.proxyHost ?: @"";
    dict[@"proxyPort"] = @(self.proxyPort);
    dict[@"proxyUser"] = self.proxyUser ?: @"";
    dict[@"proxyPass"] = self.proxyPass ?: @"";
    dict[@"deviceMachine"] = self.deviceMachine;
    dict[@"deviceModel"] = self.deviceModel;
    dict[@"deviceName"] = self.deviceName;
    dict[@"systemVersion"] = self.systemVersion;
    dict[@"kernOsVersion"] = self.kernOsVersion;
    dict[@"ncpu"] = @(self.ncpu);
    dict[@"memsize"] = @(self.memsize);
    dict[@"screenWidth"] = @(self.screenWidth);
    dict[@"screenHeight"] = @(self.screenHeight);
    dict[@"screenScale"] = @(self.screenScale);
    dict[@"bootTimeSec"] = @(self.bootTimeSec);
    dict[@"birthTimeSec"] = @(self.birthTimeSec);
    dict[@"autoSyncTimezoneWithIP"] = @(self.autoSyncTimezoneWithIP);
    dict[@"bootSessionUUID"] = self.bootSessionUUID ?: @"";
    dict[@"spoofedIDFV"] = self.spoofedIDFV;
    dict[@"spoofedIDFA"] = self.spoofedIDFA ?: @"00000000-0000-0000-0000-000000000000";
    dict[@"profileId"] = self.profileId;
    dict[@"diskTotalSize"] = @(self.diskTotalSize);
    dict[@"diskFreeSize"] = @(self.diskFreeSize);
    dict[@"carrierName"] = self.carrierName ?: @"Viettel";
    dict[@"carrierMCC"] = self.carrierMCC ?: @"452";
    dict[@"carrierMNC"] = self.carrierMNC ?: @"04";
    dict[@"carrierCountryCode"] = self.carrierCountryCode ?: @"vn";
    dict[@"batteryLevel"] = @(self.batteryLevel);
    dict[@"batteryState"] = @(self.batteryState);
    dict[@"regionMode"] = self.regionMode ?: @"VN";
    if (self.preferredCarrier) dict[@"preferredCarrier"] = self.preferredCarrier;
    dict[@"l2cacheSize"] = @(self.l2cacheSize);
    dict[@"localeIdentifier"] = self.localeIdentifier ?: @"vi_VN";
    dict[@"timeZoneName"] = self.timeZoneName ?: @"Asia/Ho_Chi_Minh";
    if (self.preferredLanguages) dict[@"preferredLanguages"] = self.preferredLanguages;
    dict[@"showFloatingMenu"] = @(self.showFloatingMenu);
    dict[@"needsNewProfile"] = @(self.needsNewProfile);
    dict[@"needsSandboxPurge"] = @(self.needsSandboxPurge);
    if (self.spoofedSerial) dict[@"spoofedSerial"] = self.spoofedSerial;
    if (self.spoofedWifiMAC) dict[@"spoofedWifiMAC"] = self.spoofedWifiMAC;
    if (self.spoofedBluetoothMAC) dict[@"spoofedBluetoothMAC"] = self.spoofedBluetoothMAC;
    if (self.lastWipedIDFV) dict[@"lastWipedIDFV"] = self.lastWipedIDFV;
    if (self.lastWipedIP) dict[@"lastWipedIP"] = self.lastWipedIP;
    dict[@"lastWipedTimestamp"] = @(self.lastWipedTimestamp);

    NSString *path = getConfigPath();
    [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    [dict writeToFile:path atomically:YES];
    chmod([path UTF8String], 0666);

    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *localPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[localPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:localPref atomically:YES];
        chmod([localPref UTF8String], 0666);
        NSString *localDoc = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[localDoc stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:localDoc atomically:YES];
        chmod([localDoc UTF8String], 0666);
    }

    if (is_device_jailbroken()) {
        NSString *rhPath = get_roothide_prefs_path();
        if (rhPath) {
            [[NSFileManager defaultManager] createDirectoryAtPath:[rhPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
            [dict writeToFile:rhPath atomically:YES];
            chmod([rhPath UTF8String], 0666);
        }
        [dict writeToFile:GLOBAL_PREFS_PATH atomically:YES];
        chmod([GLOBAL_PREFS_PATH UTF8String], 0666);
    }

    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         CFSTR("com.sonhu.zalotweak/settingschanged"),
                                         NULL, NULL, YES);
}

NSString *generate_random_serial(void) {
    return generate_apple_serial();
}

NSString *generate_random_mac(void) {
    return generate_apple_mac();
}

- (void)generateNewProfile {
    self.enabled = YES;
    self.hasConfiguredProfile = YES; // Kích hoạt cờ đã cấu hình profile
    // 1. Sinh profile thiết bị từ ngân hàng mẫu iPhone chuẩn phần cứng Apple khớp dòng máy thực tế
    ZTDeviceProfile *p = [ZTDeviceProfile generateRandomProfileForRegion:self.regionMode ?: @"VN"
                                                             baseMachine:get_real_hardware_machine()
                                                        preferredCarrier:self.preferredCarrier];

    self.deviceMachine = p.deviceMachine;
    self.deviceModel = p.deviceModel;
    self.ncpu = p.ncpu;
    self.memsize = p.memsize;
    self.screenWidth = p.screenWidth;
    self.screenHeight = p.screenHeight;
    self.screenScale = p.screenScale;
    self.systemVersion = p.systemVersion;
    self.kernOsVersion = p.kernOsVersion;
    self.diskTotalSize = p.diskTotalSize;
    self.diskFreeSize = p.diskFreeSize;
    self.deviceName = p.deviceName;
    self.carrierName = p.carrierName;
    self.carrierMCC = p.carrierMCC;
    self.carrierMNC = p.carrierMNC;
    self.carrierCountryCode = p.carrierCountryCode;
    self.l2cacheSize = p.l2cacheSize;
    self.localeIdentifier = p.localeIdentifier;
    self.preferredLanguages = p.preferredLanguages;
    self.timeZoneName = p.timeZoneName;
    self.batteryLevel = p.batteryLevel;
    self.batteryState = p.batteryState;
    self.bootTimeSec = p.bootTimeSec;
    self.birthTimeSec = p.birthTimeSec;
    self.autoSyncTimezoneWithIP = YES;
    self.bootSessionUUID = p.bootSessionUUID;
    self.spoofedIDFV = p.spoofedIDFV;
    self.spoofedIDFA = p.spoofedIDFA;
    self.profileId = p.profileId;
    self.spoofedSerial = p.spoofedSerial;
    self.spoofedWifiMAC = p.spoofedWifiMAC;
    self.spoofedBluetoothMAC = p.spoofedBluetoothMAC;

    logAudit(@"DEVICE-GEN", [NSString stringWithFormat:@"Đã sinh máy ngẫu nhiên mới: %@ (%@) | iOS: %@ (%@) | RAM: %.1fGB | L2: %lluMB | Màn: %.0fx%.0f@%.0fx | Vùng: %@ (%@) | Tên: %@",
              self.deviceMachine, self.deviceModel, self.systemVersion, self.kernOsVersion,
              (double)self.memsize / (1024.0 * 1024.0 * 1024.0),
              self.l2cacheSize / (1024ULL * 1024ULL),
              self.screenWidth, self.screenHeight, self.screenScale,
              self.regionMode, self.localeIdentifier, self.deviceName]);

    [self saveSettings];
}

@end

// ==========================================
// HỆ THỐNG AUDIT LOG (KIỂM TOÁN HÀNH VI ZALO)
// ==========================================

static NSString *getAuditLogPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *doc = [home stringByAppendingPathComponent:@"Documents/ZaloAudit.log"];
        return doc;
    }
    return GLOBAL_AUDIT_LOG_PATH;
}

static NSMutableSet *loggedAuditKeys = nil;
static dispatch_queue_t auditQueue = nil;

static NSString *mask_sensitive_data(NSString *input) {
    if (!input || input.length == 0) return input;
    NSMutableString *str = [input mutableCopy];

    // Mask JSON tokens & keys: "(token|authToken|refreshToken|privateKey|sdkId|zaId)":"..."
    NSRegularExpression *jwtRegex = [NSRegularExpression regularExpressionWithPattern:@"\"(token|authToken|refreshToken|privateKey|sdkId|zaId)\"\\s*:\\s*\"([^\"]+)\"" options:0 error:nil];
    if (jwtRegex) {
        NSArray *matches = [jwtRegex matchesInString:str options:0 range:NSMakeRange(0, str.length)];
        for (NSTextCheckingResult *match in [matches reverseObjectEnumerator]) {
            NSRange valRange = [match rangeAtIndex:2];
            NSString *val = [str substringWithRange:valRange];
            if (val.length > 8) {
                NSString *masked = [NSString stringWithFormat:@"%@***%@", [val substringToIndex:4], [val substringFromIndex:val.length - 4]];
                [str replaceCharactersInRange:valRange withString:masked];
            }
        }
    }

    // Mask query & header params: (api_key|sig|sdkId|X-Goog-Api-Key)
    NSRegularExpression *paramRegex = [NSRegularExpression regularExpressionWithPattern:@"(api_key|sig|sdkId|X-Goog-Api-Key)[=:\\s]+([a-zA-Z0-9_-]{12,})" options:0 error:nil];
    if (paramRegex) {
        NSArray *matches = [paramRegex matchesInString:str options:0 range:NSMakeRange(0, str.length)];
        for (NSTextCheckingResult *match in [matches reverseObjectEnumerator]) {
            NSRange valRange = [match rangeAtIndex:2];
            NSString *val = [str substringWithRange:valRange];
            if (val.length > 8) {
                NSString *masked = [NSString stringWithFormat:@"%@***", [val substringToIndex:6]];
                [str replaceCharactersInRange:valRange withString:masked];
            }
        }
    }

    return str;
}

static void logAudit(NSString *category, NSString *detail) {
    NSString *safeDetail = mask_sensitive_data(detail);

    // 1. Luôn in trực tiếp ra System Console để soi trực tiếp trên 3uTools Device Console
    NSLog(@"[ZaloAudit] [%@] %@", category, safeDetail);

    if (![ZTSettings sharedSettings].enableAuditLog) return;

    if (!auditQueue) {
        loggedAuditKeys = [[NSMutableSet alloc] init];
        auditQueue = dispatch_queue_create("com.sonhu.zalotweak.auditQueue", DISPATCH_QUEUE_SERIAL);
    }

    NSString *dedupKey = [NSString stringWithFormat:@"%@:%@", category, safeDetail];
    dispatch_async(auditQueue, ^{
        BOOL isNetworkEvent = [category containsString:@"HTTP"] || [category containsString:@"HAR"] || [category containsString:@"NET"];
        if (!isNetworkEvent) {
            if ([loggedAuditKeys containsObject:dedupKey]) {
                return;
            }
            [loggedAuditKeys addObject:dedupKey];
        }

        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"HH:mm:ss"];
        NSString *timeStr = [df stringFromDate:[NSDate date]];

        NSString *line = [NSString stringWithFormat:@"[%@] [PID:%d] [%@] %@\n", timeStr, getpid(), category, safeDetail];
        NSString *path = getAuditLogPath();

        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!handle) {
            [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
            handle = [NSFileHandle fileHandleForWritingAtPath:path];
        }
        if (handle) {
            [handle seekToEndOfFile];
            [handle writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [handle closeFile];
        }
    });
}

// ==========================================
// 1. TẦNG C API: sysctl, sysctlbyname & uname HOOKING
// ==========================================

static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name || namelen < 2 || !is_tweak_active()) {
        return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }

    ZTSettings *settings = [ZTSettings sharedSettings];

    if (name[0] == CTL_HW) {
        if (name[1] == HW_MACHINE) {
            const char *val = settings.deviceMachine.length > 0 ? [settings.deviceMachine UTF8String] : "iPhone";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            return 0;
        }
        if (name[1] == HW_MODEL) {
            const char *val = settings.deviceModel.length > 0 ? [settings.deviceModel UTF8String] : "D10AP";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            return 0;
        }
        if (name[1] == HW_NCPU || name[1] == HW_AVAILCPU) {
            uint32_t cpu = settings.ncpu;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &cpu, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            return 0;
        }
        if (name[1] == HW_MEMSIZE) {
            uint64_t ram = settings.memsize;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
                memcpy(oldp, &ram, sizeof(uint64_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint64_t);
            return 0;
        }
        if (name[1] == HW_PHYSMEM) {
            uint32_t ram32 = (uint32_t)(settings.memsize > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : settings.memsize);
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &ram32, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            return 0;
        }
        if (name[1] == HW_PAGESIZE) {
            uint32_t pagesize = 16384;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &pagesize, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            return 0;
        }
#ifdef HW_L2CACHESIZE
        if (name[1] == HW_L2CACHESIZE) {
            uint64_t l2 = settings.l2cacheSize > 0 ? settings.l2cacheSize : 3145728ULL;
            if (oldp && oldlenp) {
                if (*oldlenp >= sizeof(uint64_t)) {
                    memcpy(oldp, &l2, sizeof(uint64_t));
                } else if (*oldlenp >= sizeof(uint32_t)) {
                    uint32_t l2_32 = (uint32_t)l2;
                    memcpy(oldp, &l2_32, sizeof(uint32_t));
                }
            }
            if (oldlenp) *oldlenp = sizeof(uint64_t);
            return 0;
        }
#endif
    } else if (name[0] == CTL_KERN) {
        if (name[1] == KERN_BOOTTIME && settings.bootTimeSec > 0) {
            struct timeval bt;
            bt.tv_sec = (time_t)settings.bootTimeSec;
            bt.tv_usec = 345678;
            if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                memcpy(oldp, &bt, sizeof(struct timeval));
            }
            if (oldlenp) *oldlenp = sizeof(struct timeval);
            return 0;
        }
        if (name[1] == KERN_OSVERSION && settings.kernOsVersion.length > 0) {
            const char *val = [settings.kernOsVersion UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            return 0;
        }
        if (name[1] == KERN_HOSTNAME && settings.deviceName.length > 0) {
            const char *val = [settings.deviceName UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            return 0;
        }
    }

    return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name || !is_tweak_active()) {
        return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    logAudit(@"DETECTION-RADAR", [NSString stringWithFormat:@"sysctlbyname('%s')", name]);

    ZTSettings *settings = [ZTSettings sharedSettings];

    if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.product") == 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"%s -> [ĐÃ FAKE] %@", name, settings.deviceMachine]);
        const char *val = settings.deviceMachine.length > 0 ? [settings.deviceMachine UTF8String] : "iPhone";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        return 0;
    }

    if (strcmp(name, "hw.model") == 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"hw.model -> [ĐÃ FAKE] %@", settings.deviceModel]);
        const char *val = settings.deviceModel.length > 0 ? [settings.deviceModel UTF8String] : "D10AP";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        return 0;
    }

    if (strcmp(name, "kern.osproductversion") == 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"kern.osproductversion -> [ĐÃ FAKE] %@", settings.systemVersion]);
        const char *val = settings.systemVersion.length > 0 ? [settings.systemVersion UTF8String] : "15.7.2";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        return 0;
    }

    if (strcmp(name, "kern.osversion") == 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"kern.osversion -> [ĐÃ FAKE] %@", settings.kernOsVersion]);
        const char *val = settings.kernOsVersion.length > 0 ? [settings.kernOsVersion UTF8String] : "19H218";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        return 0;
    }

    if (strcmp(name, "hw.ncpu") == 0 ||
        strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.activecpu") == 0 ||
        strcmp(name, "hw.logicalcpu_max") == 0 ||
        strcmp(name, "hw.physicalcpu_max") == 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"%s -> [ĐÃ FAKE] %u core", name, settings.ncpu]);
        uint32_t cpu = settings.ncpu;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &cpu, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        return 0;
    }

    if (strcmp(name, "hw.memsize") == 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"hw.memsize -> [ĐÃ FAKE] %llu bytes (%llu GB)", settings.memsize, settings.memsize / (1024*1024*1024ULL)]);
        uint64_t ram = settings.memsize;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
            memcpy(oldp, &ram, sizeof(uint64_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint64_t);
        return 0;
    }

    if (strcmp(name, "hw.physmem") == 0) {
        uint32_t ram32 = (uint32_t)(settings.memsize > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : settings.memsize);
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &ram32, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        return 0;
    }

    if (strcmp(name, "hw.pagesize") == 0) {
        logAudit(@"SYSCTL", @"hw.pagesize -> [ĐÃ FAKE] 16384 bytes");
        uint32_t pagesize = 16384;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &pagesize, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        return 0;
    }

    if (strcmp(name, "hw.l2cachesize") == 0) {
        uint64_t l2 = settings.l2cacheSize > 0 ? settings.l2cacheSize : 3145728ULL;
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"hw.l2cachesize -> [ĐÃ FAKE] %llu bytes", l2]);
        if (oldp && oldlenp) {
            if (*oldlenp >= sizeof(uint64_t)) {
                memcpy(oldp, &l2, sizeof(uint64_t));
            } else if (*oldlenp >= sizeof(uint32_t)) {
                uint32_t l2_32 = (uint32_t)l2;
                memcpy(oldp, &l2_32, sizeof(uint32_t));
            }
        }
        if (oldlenp) *oldlenp = sizeof(uint64_t);
        return 0;
    }

    if (strcmp(name, "sysctl.proc_translated") == 0) {
        logAudit(@"SYSCTL", @"sysctl.proc_translated -> [ĐÃ FAKE] 0 (Native ARM)");
        int translated = 0;
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            memcpy(oldp, &translated, sizeof(int));
        }
        if (oldlenp) *oldlenp = sizeof(int);
        return 0;
    }

    if (strcmp(name, "kern.boottime") == 0 && settings.bootTimeSec > 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"kern.boottime -> [ĐÃ FAKE] Timestamp: %llu", settings.bootTimeSec]);
        struct timeval bt;
        bt.tv_sec = (time_t)settings.bootTimeSec;
        bt.tv_usec = (suseconds_t)((settings.bootTimeSec * 2654435761ULL) % 1000000ULL);
        if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
            memcpy(oldp, &bt, sizeof(struct timeval));
        }
        if (oldlenp) *oldlenp = sizeof(struct timeval);
        return 0;
    }

    if (strcmp(name, "kern.bootsessionuuid") == 0 && settings.bootSessionUUID.length > 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"kern.bootsessionuuid -> [ĐÃ FAKE] %@", settings.bootSessionUUID]);
        const char *val = settings.bootSessionUUID.length > 0 ? [settings.bootSessionUUID UTF8String] : "00000000-0000-0000-0000-000000000000";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        return 0;
    }

    if (strcmp(name, "kern.hostname") == 0 && settings.deviceName.length > 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"kern.hostname -> [ĐÃ FAKE] %@", settings.deviceName]);
        const char *val = settings.deviceName.length > 0 ? [settings.deviceName UTF8String] : "iPhone";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        return 0;
    }

    if (strncmp(name, "hw.optional.arm.FEAT_", 21) == 0) {
        uint32_t supported = 0;
        if (strcmp(name, "hw.optional.arm.FEAT_AES") == 0 ||
            strcmp(name, "hw.optional.arm.FEAT_PMULL") == 0 ||
            strcmp(name, "hw.optional.arm.FEAT_SHA1") == 0 ||
            strcmp(name, "hw.optional.arm.FEAT_SHA256") == 0) {
            supported = 1;
        } else if (settings.ncpu >= 6) {
            if (strcmp(name, "hw.optional.arm.FEAT_DotProd") == 0 ||
                strcmp(name, "hw.optional.arm.FEAT_FP16") == 0) {
                supported = 1;
            }
        }
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"%s -> [ĐÃ FAKE THEO CHIP] %u", name, supported]);
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &supported, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        return 0;
    }

    logAudit(@"SYSCTL", [NSString stringWithFormat:@"%s -> [CHƯA HOOK - LẤY TỰ NHIÊN TỪ MÁY]", name]);
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int (*orig_uname)(struct utsname *buf);
static int my_uname(struct utsname *buf) {
    int ret = orig_uname ? orig_uname(buf) : uname(buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        if (settings.deviceMachine.length > 0) {
            strlcpy(buf->machine, [settings.deviceMachine UTF8String], sizeof(buf->machine));
        }
    }
    return ret;
}

// ==========================================
// 2. TẦNG OBJECTIVE-C: UIDevice, UIScreen, NSProcessInfo, NSFileManager & UIApplication
// ==========================================

%hook UIDevice

- (NSUUID *)identifierForVendor {
    if (!is_tweak_active()) {
        NSUUID *origUUID = %orig;
        logAudit(@"IDFV-CHECK", [NSString stringWithFormat:@"identifierForVendor -> [CHƯA KÍCH HOẠT KEY / HẾT HẠN - TRẢ VỀ IDFV THẬT] %@", [origUUID UUIDString]]);
        return origUUID;
    }
    NSString *fake = [ZTSettings sharedSettings].spoofedIDFV;
    if (fake && fake.length > 0) {
        logAudit(@"IDFV-CHECK", [NSString stringWithFormat:@"identifierForVendor -> [ĐÃ FAKE IDFV AN TOÀN] %@", fake]);
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:fake];
        if (uuid) return uuid;
    }
    return %orig;
}

- (NSString *)systemVersion {
    if (!is_tweak_active()) {
        return %orig;
    }
    return [ZTSettings sharedSettings].systemVersion;
}

- (NSString *)name {
    if (!is_tweak_active()) {
        return %orig;
    }
    return [ZTSettings sharedSettings].deviceName;
}

- (NSString *)model {
    if (!is_tweak_active()) {
        return %orig;
    }
    return @"iPhone";
}

- (NSString *)localizedModel {
    if (!is_tweak_active()) {
        return %orig;
    }
    return @"iPhone";
}

- (float)batteryLevel {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].batteryLevel;
}

- (UIDeviceBatteryState)batteryState {
    if (!is_tweak_active()) return %orig;
    return (UIDeviceBatteryState)[ZTSettings sharedSettings].batteryState;
}

- (BOOL)isBatteryMonitoringEnabled {
    return YES;
}

%end

// ==========================================
// ĐỒNG BỘ OS VERSION & BUILD: NSProcessInfo
// ==========================================
%hook NSProcessInfo

- (NSString *)operatingSystemVersionString {
    if (!is_tweak_active()) return %orig;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.systemVersion.length > 0 && s.kernOsVersion.length > 0) {
        return [NSString stringWithFormat:@"Version %@ (Build %@)", s.systemVersion, s.kernOsVersion];
    }
    return %orig;
}

- (NSOperatingSystemVersion)operatingSystemVersion {
    if (!is_tweak_active()) return %orig;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.systemVersion.length > 0) {
        NSArray *components = [s.systemVersion componentsSeparatedByString:@"."];
        NSOperatingSystemVersion v;
        v.majorVersion = components.count > 0 ? [components[0] integerValue] : 18;
        v.minorVersion = components.count > 1 ? [components[1] integerValue] : 1;
        v.patchVersion = components.count > 2 ? [components[2] integerValue] : 0;
        return v;
    }
    return %orig;
}

%end

// ==========================================
// CHẶN ĐỌC FILE HỆ THỐNG SystemVersion.plist
// ==========================================
%hook NSDictionary

+ (NSDictionary *)dictionaryWithContentsOfFile:(NSString *)path {
    if (is_tweak_active() && path && [path isEqualToString:@"/System/Library/CoreServices/SystemVersion.plist"]) {
        ZTSettings *s = [ZTSettings sharedSettings];
        NSDictionary *orig = %orig;
        NSMutableDictionary *dict = orig ? [orig mutableCopy] : [NSMutableDictionary dictionary];
        if (s.systemVersion.length > 0) {
            dict[@"ProductVersion"] = s.systemVersion;
            dict[@"ProductUserVisibleVersion"] = s.systemVersion;
        }
        if (s.kernOsVersion.length > 0) {
            dict[@"ProductBuildVersion"] = s.kernOsVersion;
        }
        dict[@"ProductName"] = @"iPhone OS";
        return dict;
    }
    return %orig;
}

- (NSDictionary *)initWithContentsOfFile:(NSString *)path {
    if (is_tweak_active() && path && [path isEqualToString:@"/System/Library/CoreServices/SystemVersion.plist"]) {
        ZTSettings *s = [ZTSettings sharedSettings];
        NSDictionary *orig = %orig;
        NSMutableDictionary *dict = orig ? [orig mutableCopy] : [NSMutableDictionary dictionary];
        if (s.systemVersion.length > 0) {
            dict[@"ProductVersion"] = s.systemVersion;
            dict[@"ProductUserVisibleVersion"] = s.systemVersion;
        }
        if (s.kernOsVersion.length > 0) {
            dict[@"ProductBuildVersion"] = s.kernOsVersion;
        }
        dict[@"ProductName"] = @"iPhone OS";
        return dict;
    }
    return %orig;
}

%end

// ==========================================
// BẢO VỆ DANH TÍNH QUẢNG CÁO: IDFA & APP TRACKING
// ==========================================
%hook ASIdentifierManager

- (NSUUID *)advertisingIdentifier {
    if (!is_tweak_active()) {
        return %orig;
    }
    logAudit(@"IDFA-CHECK", @"advertisingIdentifier -> [CHUẨN APPLE ATT DENIED] 00000000-0000-0000-0000-000000000000");
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}

- (BOOL)isAdvertisingTrackingEnabled {
    if (!is_tweak_active()) {
        return %orig;
    }
    return NO;
}

%end

%hook ATTrackingManager

+ (NSInteger)trackingAuthorizationStatus {
    if (!is_tweak_active()) {
        return %orig;
    }
    logAudit(@"TRACKING-CHECK", @"trackingAuthorizationStatus -> [ĐÃ CHẶN THEO DÕI - TRẢ VỀ DENIED (2)]");
    return 2; // ATTrackingManagerAuthorizationStatusDenied
}

+ (void)requestTrackingAuthorizationWithCompletionHandler:(void (^)(NSInteger status))completion {
    if (!is_tweak_active()) {
        %orig(completion);
        return;
    }
    logAudit(@"TRACKING-CHECK", @"requestTrackingAuthorization -> [TỰ ĐỘNG TRẢ VỀ DENIED (2)]");
    if (completion) {
        completion(2);
    }
}

%end

// ==========================================
// BẢO VỆ CHỐNG CRASH SIRI INTENTS TRÊN APP CLONE / SIDELOAD
// (Khắc phục triệt để lỗi thiếu Entitlement com.apple.developer.siri)
// ==========================================
@interface INPreferences : NSObject
@end

%hook INPreferences

+ (NSInteger)siriAuthorizationStatus {
    logAudit(@"SIRI-FIX", @"[INPreferences siriAuthorizationStatus] -> [CHẶN CRASH: TRẢ VỀ DENIED (2)]");
    return 2; // INSiriAuthorizationStatusDenied
}

+ (void)requestSiriAuthorization:(void (^)(NSInteger status))completion {
    logAudit(@"SIRI-FIX", @"[INPreferences requestSiriAuthorization] -> [CHẶN CRASH: TỰ ĐỘNG DENIED (2)]");
    if (completion) {
        completion(2);
    }
}

+ (NSString *)siriLanguageCode {
    return @"vi-VN";
}

- (id)init {
    logAudit(@"SIRI-FIX", @"[INPreferences init] -> [CHẶN CRASH: TRẢ VỀ NIL]");
    return nil;
}

%end

@interface INVocabulary : NSObject
@end

%hook INVocabulary

+ (id)sharedVocabulary {
    logAudit(@"SIRI-FIX", @"[INVocabulary sharedVocabulary] -> [CHẶN CRASH: TRẢ VỀ NIL]");
    return nil;
}

- (void)setVocabularyStrings:(NSOrderedSet *)vocabularyStrings ofType:(NSInteger)type {
    // Bỏ qua để tránh crash
}

- (void)removeAllVocabularyStrings {
    // Bỏ qua để tránh crash
}

%end

// ==========================================
// GIẢ LẬP NHÀ MẠNG VIỄN THÔNG (CARRIER INFO)
// ==========================================
%hook CTCarrier

- (NSString *)carrierName {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].carrierName ?: @"Viettel";
}

- (NSString *)mobileCountryCode {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].carrierMCC ?: @"452";
}

- (NSString *)mobileNetworkCode {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].carrierMNC ?: @"04";
}

- (NSString *)isoCountryCode {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].carrierCountryCode ?: @"vn";
}

- (BOOL)allowsVOIP {
    return YES;
}

%end

%hook CTTelephonyNetworkInfo

- (CTCarrier *)subscriberCellularProvider {
    if (!is_tweak_active()) return %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"CARRIER-CHECK", [NSString stringWithFormat:@"Zalo đọc SIM -> [%@ | MCC:%@ MNC:%@ ISO:%@]",
                  [ZTSettings sharedSettings].carrierName ?: @"Viettel",
                  [ZTSettings sharedSettings].carrierMCC ?: @"452",
                  [ZTSettings sharedSettings].carrierMNC ?: @"04",
                  [ZTSettings sharedSettings].carrierCountryCode ?: @"vn"]);
    }
    CTCarrier *origCarrier = %orig;
    return origCarrier ?: [[CTCarrier alloc] init];
}

- (NSDictionary *)serviceSubscriberCellularProviders {
    if (!is_tweak_active()) return %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"CARRIER-CHECK", [NSString stringWithFormat:@"Zalo đọc Multi-SIM -> [%@ | MCC:%@ MNC:%@ ISO:%@]",
                  [ZTSettings sharedSettings].carrierName ?: @"Viettel",
                  [ZTSettings sharedSettings].carrierMCC ?: @"452",
                  [ZTSettings sharedSettings].carrierMNC ?: @"04",
                  [ZTSettings sharedSettings].carrierCountryCode ?: @"vn"]);
    }
    NSDictionary *origDict = %orig;
    if (origDict && origDict.count > 0) return origDict;
    CTCarrier *carrier = [[CTCarrier alloc] init];
    return @{@"0000000100000001": carrier};
}

- (NSDictionary *)serviceCurrentRadioAccessTechnology {
    if (!is_tweak_active()) return %orig;
    NSDictionary *origDict = %orig;
    if (origDict && origDict.count > 0) return origDict;
    return @{@"0000000100000001": @"CTRadioAccessTechnologyLTE"};
}

- (NSString *)currentRadioAccessTechnology {
    if (!is_tweak_active()) return %orig;
    NSString *origTech = %orig;
    return origTech ?: @"CTRadioAccessTechnologyLTE";
}

%end

// ==========================================
// ĐỒNG BỘ VÙNG / QUỐC GIA: NSLocale & NSTimeZone
// ==========================================

static NSLocale *s_cachedLocale = nil;
static NSTimeZone *s_cachedTimeZone = nil;
static __thread BOOL s_in_locale_hook = NO;
static __thread BOOL s_in_tz_hook = NO;

static void update_cached_locale_and_tz(void) {
    if (s_in_locale_hook || s_in_tz_hook) return;
    s_in_locale_hook = YES;
    s_in_tz_hook = YES;
    NSString *locId = [ZTSettings sharedSettings].localeIdentifier ?: @"vi_VN";
    NSString *tzName = [ZTSettings sharedSettings].timeZoneName ?: @"Asia/Ho_Chi_Minh";
    if ([[ZTSettings sharedSettings].regionMode isEqualToString:@"VN"] && ([tzName isEqualToString:@"Asia/Bangkok"] || [tzName isEqualToString:@"Asia/Saigon"])) {
        tzName = @"Asia/Ho_Chi_Minh";
    }
    s_cachedLocale = [NSLocale localeWithLocaleIdentifier:locId];
    s_cachedTimeZone = [NSTimeZone timeZoneWithName:tzName];
    s_in_tz_hook = NO;
    s_in_locale_hook = NO;
}

%hook NSLocale

+ (NSLocale *)currentLocale {
    if (!is_tweak_active() || s_in_locale_hook) return %orig;
    if (!s_cachedLocale) {
        update_cached_locale_and_tz();
    }
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc NSLocale currentLocale -> [TRẢ VỀ %@]", [ZTSettings sharedSettings].localeIdentifier ?: @"vi_VN"]);
    }
    return s_cachedLocale ?: %orig;
}

+ (NSArray<NSString *> *)preferredLanguages {
    if (!is_tweak_active()) return %orig;
    NSArray *langs = [ZTSettings sharedSettings].preferredLanguages;
    NSArray *res = (langs && langs.count > 0) ? langs : @[@"vi-VN", @"en-VN"];
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc preferredLanguages -> [TRẢ VỀ %@]", [res componentsJoinedByString:@", "]]);
    }
    return res;
}

%end

%hook NSTimeZone

+ (NSTimeZone *)systemTimeZone {
    if (!is_tweak_active() || s_in_tz_hook) return %orig;
    if (!s_cachedTimeZone) {
        update_cached_locale_and_tz();
    }
    if ([ZTSettings sharedSettings].enableAuditLog) {
        NSInteger gmtSec = s_cachedTimeZone ? [s_cachedTimeZone secondsFromGMT] : 25200;
        int hours = (int)(gmtSec / 3600);
        int mins = abs((int)((gmtSec % 3600) / 60));
        NSString *gmtStr = mins > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", hours, mins] : [NSString stringWithFormat:@"GMT%+d", hours];
        logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc systemTimeZone -> [TRẢ VỀ %@ (%@)]", [ZTSettings sharedSettings].timeZoneName ?: @"Asia/Ho_Chi_Minh", gmtStr]);
    }
    return s_cachedTimeZone ?: %orig;
}

+ (NSTimeZone *)localTimeZone {
    if (!is_tweak_active() || s_in_tz_hook) return %orig;
    if (!s_cachedTimeZone) {
        update_cached_locale_and_tz();
    }
    if ([ZTSettings sharedSettings].enableAuditLog) {
        NSInteger gmtSec = s_cachedTimeZone ? [s_cachedTimeZone secondsFromGMT] : 25200;
        int hours = (int)(gmtSec / 3600);
        int mins = abs((int)((gmtSec % 3600) / 60));
        NSString *gmtStr = mins > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", hours, mins] : [NSString stringWithFormat:@"GMT%+d", hours];
        logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc localTimeZone -> [TRẢ VỀ %@ (%@)]", [ZTSettings sharedSettings].timeZoneName ?: @"Asia/Ho_Chi_Minh", gmtStr]);
    }
    return s_cachedTimeZone ?: %orig;
}

+ (NSTimeZone *)defaultTimeZone {
    if (!is_tweak_active() || s_in_tz_hook) return %orig;
    if (!s_cachedTimeZone) {
        update_cached_locale_and_tz();
    }
    if ([ZTSettings sharedSettings].enableAuditLog) {
        NSInteger gmtSec = s_cachedTimeZone ? [s_cachedTimeZone secondsFromGMT] : 25200;
        int hours = (int)(gmtSec / 3600);
        int mins = abs((int)((gmtSec % 3600) / 60));
        NSString *gmtStr = mins > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", hours, mins] : [NSString stringWithFormat:@"GMT%+d", hours];
        logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc defaultTimeZone -> [TRẢ VỀ %@ (%@)]", [ZTSettings sharedSettings].timeZoneName ?: @"Asia/Ho_Chi_Minh", gmtStr]);
    }
    return s_cachedTimeZone ?: %orig;
}

%end

%hook UIScreen

// Giữ nguyên bounds vật lý để UIWindow và cảm ứng hiển thị vừa vặn màn hình thực tế, không bị vỡ bố cục
- (CGRect)bounds {
    return %orig;
}

- (CGRect)nativeBounds {
    if (!is_tweak_active()) {
        return %orig;
    }
    CGFloat w = [ZTSettings sharedSettings].screenWidth;
    CGFloat h = [ZTSettings sharedSettings].screenHeight;
    CGFloat s = [ZTSettings sharedSettings].screenScale;
    if (w > 0 && h > 0 && s > 0) {
        CGRect orig = %orig;
        CGFloat pw = w * s;
        CGFloat ph = h * s;
        if (orig.size.width > orig.size.height) {
            return CGRectMake(0, 0, MAX(pw, ph), MIN(pw, ph));
        }
        return CGRectMake(0, 0, MIN(pw, ph), MAX(pw, ph));
    }
    return %orig;
}

- (CGFloat)scale {
    if (!is_tweak_active()) {
        return %orig;
    }
    CGFloat s = [ZTSettings sharedSettings].screenScale;
    if (s > 0) return s;
    return %orig;
}

- (CGFloat)nativeScale {
    if (!is_tweak_active()) {
        return %orig;
    }
    CGFloat s = [ZTSettings sharedSettings].screenScale;
    if (s > 0) return s;
    return %orig;
}

%end

// Đồng bộ Uptime với kern.boottime tuyệt đối
%hook NSProcessInfo

- (NSTimeInterval)systemUptime {
    if (!is_tweak_active()) {
        return %orig;
    }
    uint64_t bootSec = [ZTSettings sharedSettings].bootTimeSec;
    if (bootSec > 0) {
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        if (now > (NSTimeInterval)bootSec) {
            NSTimeInterval baseUptime = now - (NSTimeInterval)bootSec;
            NSTimeInterval origVal = %orig;
            NSTimeInterval subsecond = origVal - floor(origVal);
            return floor(baseUptime) + subsecond;
        }
    }
    return %orig;
}

%end

// ==========================================
// 3. TẦNG KEYCHAIN: ISOLATION & REDIRECTION
// ==========================================

static NSMutableDictionary *modify_keychain_query(CFDictionaryRef query) {
    if (!query) return nil;
    NSMutableDictionary *dict = [(__bridge NSDictionary *)query mutableCopy];

    // BẢO VỆ TUYỆT ĐỐI CHO APPS MANAGER KHI BACKUP ZALO GỐC:
    // Nếu là Zalo gốc, giữ nguyên 100% kSecAttrAccessGroup (group.vn.com.vng.zingalo)
    // và Service/Account để Apps Manager dump Keychain chính xác vào file .adbk!
    if (is_original_zalo_app()) {
        return dict;
    }

    NSString *profile = [ZTSettings sharedSettings].profileId;
    if (!profile || profile.length == 0) return dict;

    // Chỉ áp dụng cho mật khẩu Generic & Internet trên Zalo Clone để không xung đột Zalo gốc
    id secClass = dict[(__bridge id)kSecClass];
    if (secClass) {
        if (![secClass isEqual:(__bridge id)kSecClassGenericPassword] &&
            ![secClass isEqual:(__bridge id)kSecClassInternetPassword]) {
            return dict;
        }
    }

    NSString *prefix = [NSString stringWithFormat:@"%@_", profile];

    // Cách ly kSecAttrAccessGroup của Zalo Clone
    if (dict[(__bridge id)kSecAttrAccessGroup]) {
        [dict removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
    }

    // Chỉ prefix khi service thực sự có trong truy vấn
    id service = dict[(__bridge id)kSecAttrService];
    if (service && [service isKindOfClass:[NSString class]]) {
        if (![service hasPrefix:prefix]) {
            dict[(__bridge id)kSecAttrService] = [NSString stringWithFormat:@"%@%@", prefix, service];
        }
    }

    // Tương tự cho account
    id account = dict[(__bridge id)kSecAttrAccount];
    if (account && [account isKindOfClass:[NSString class]]) {
        if (![account hasPrefix:prefix]) {
            dict[(__bridge id)kSecAttrAccount] = [NSString stringWithFormat:@"%@%@", prefix, account];
        }
    }

    if (service || account) {
        logAudit(@"KEYCHAIN", [NSString stringWithFormat:@"Query Service: '%@', Account: '%@' -> [ĐÃ CÔ LẬP THEO PROFILE]", service ?: @"(null)", account ?: @"(null)"]);
    }

    return dict;
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (!is_tweak_active()) {
        return orig_SecItemCopyMatching ? orig_SecItemCopyMatching(query, result) : SecItemCopyMatching(query, result);
    }
    if ([ZTSettings sharedSettings].enableAuditLog && query) {
        NSDictionary *qDict = (__bridge NSDictionary *)query;
        id s = qDict[(__bridge id)kSecAttrService];
        id a = qDict[(__bridge id)kSecAttrAccount];
        id g = qDict[(__bridge id)kSecAttrAccessGroup];
        if (s || a) {
            logAudit(@"KEYCHAIN-READ", [NSString stringWithFormat:@"🔍 Zalo truy vấn Keychain: Service='%@' | Account='%@' | Group='%@'", s ?: @"*", a ?: @"*", g ?: @"default"]);
        }
    }
    NSMutableDictionary *isolatedQuery = modify_keychain_query(query);
    CFDictionaryRef targetQuery = isolatedQuery ? (__bridge CFDictionaryRef)isolatedQuery : query;
    return orig_SecItemCopyMatching ? orig_SecItemCopyMatching(targetQuery, result) : SecItemCopyMatching(targetQuery, result);
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    if (!is_tweak_active()) {
        return orig_SecItemAdd ? orig_SecItemAdd(attributes, result) : SecItemAdd(attributes, result);
    }
    NSMutableDictionary *isolatedAttrs = modify_keychain_query(attributes);
    CFDictionaryRef targetAttrs = isolatedAttrs ? (__bridge CFDictionaryRef)isolatedAttrs : attributes;
    return orig_SecItemAdd ? orig_SecItemAdd(targetAttrs, result) : SecItemAdd(targetAttrs, result);
}

static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    if (!is_tweak_active()) {
        return orig_SecItemDelete ? orig_SecItemDelete(query) : SecItemDelete(query);
    }
    NSMutableDictionary *isolatedQuery = modify_keychain_query(query);
    CFDictionaryRef targetQuery = isolatedQuery ? (__bridge CFDictionaryRef)isolatedQuery : query;
    return orig_SecItemDelete ? orig_SecItemDelete(targetQuery) : SecItemDelete(targetQuery);
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    if (!is_tweak_active()) {
        return orig_SecItemUpdate ? orig_SecItemUpdate(query, attributesToUpdate) : SecItemUpdate(query, attributesToUpdate);
    }
    NSMutableDictionary *isolatedQuery = modify_keychain_query(query);
    NSMutableDictionary *isolatedAttrs = modify_keychain_query(attributesToUpdate);
    CFDictionaryRef targetQuery = isolatedQuery ? (__bridge CFDictionaryRef)isolatedQuery : query;
    CFDictionaryRef targetAttrs = isolatedAttrs ? (__bridge CFDictionaryRef)isolatedAttrs : attributesToUpdate;
    return orig_SecItemUpdate ? orig_SecItemUpdate(targetQuery, targetAttrs) : SecItemUpdate(targetQuery, targetAttrs);
}

// ==========================================
// 4. TẦNG BẢO VỆ CHỐNG PHÁT HIỆN JAILBREAK TOÀN DIỆN & FAKE DUNG LƯỢNG Ổ CỨNG
// ==========================================

static BOOL is_jailbreak_path(const char *path) {
    if (!path) return NO;
    static const char *jb_indicators[] = {
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Cydia.app",
        "/Applications/Filza.app",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/sh",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/stash",
        "MobileSubstrate.dylib",
        "test_jb",
        "jailbreak.txt",
        NULL
    };
    for (int i = 0; jb_indicators[i] != NULL; i++) {
        if (strstr(path, jb_indicators[i]) != NULL) {
            return YES;
        }
    }
    return NO;
}



// Chuyển hướng CFPreferences App Groups sang container an toàn của clone (Zalo gốc giữ nguyên chuẩn hệ thống)
static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef key, CFStringRef applicationID);
static CFPropertyListRef my_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef applicationID) {
    if (!is_original_zalo_app() && applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
        NSString *appID = (__bridge NSString *)applicationID;
        if ([appID containsString:@"group.vn.com.vng.zingalo"] || [appID containsString:@"group.zsettings"]) {
            NSString *safeAppID = [NSString stringWithFormat:@"com.sonhu.zaloclone.%@", appID];
            return orig_CFPreferencesCopyAppValue ? orig_CFPreferencesCopyAppValue(key, (__bridge CFStringRef)safeAppID) : NULL;
        }
    }
    return orig_CFPreferencesCopyAppValue ? orig_CFPreferencesCopyAppValue(key, applicationID) : NULL;
}

static void (*orig_CFPreferencesSetAppValue)(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID);
static void my_CFPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID) {
    if (!is_original_zalo_app() && applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
        NSString *appID = (__bridge NSString *)applicationID;
        if ([appID containsString:@"group.vn.com.vng.zingalo"] || [appID containsString:@"group.zsettings"]) {
            NSString *safeAppID = [NSString stringWithFormat:@"com.sonhu.zaloclone.%@", appID];
            if (orig_CFPreferencesSetAppValue) orig_CFPreferencesSetAppValue(key, value, (__bridge CFStringRef)safeAppID);
            return;
        }
    }
    if (orig_CFPreferencesSetAppValue) orig_CFPreferencesSetAppValue(key, value, applicationID);
}

static Boolean (*orig_CFPreferencesAppSynchronize)(CFStringRef applicationID);
static Boolean my_CFPreferencesAppSynchronize(CFStringRef applicationID) {
    if (!is_original_zalo_app() && applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
        NSString *appID = (__bridge NSString *)applicationID;
        if ([appID containsString:@"group.vn.com.vng.zingalo"] || [appID containsString:@"group.zsettings"]) {
            NSString *safeAppID = [NSString stringWithFormat:@"com.sonhu.zaloclone.%@", appID];
            return orig_CFPreferencesAppSynchronize ? orig_CFPreferencesAppSynchronize((__bridge CFStringRef)safeAppID) : true;
        }
    }
    return orig_CFPreferencesAppSynchronize ? orig_CFPreferencesAppSynchronize(applicationID) : true;
}


// Ẩn BSSID của trạm phát WiFi (tránh phát hiện chung router)
static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName);
static CFDictionaryRef my_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    if (is_tweak_active()) {
        logAudit(@"WIFI-CHECK", @"Zalo cố đọc WiFi SSID/BSSID trạm phát -> [ĐÃ CHẶN ẨN HOÀN TOÀN]");
        return NULL;
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

// Lọc các giao diện mạng ảo (VPN, Tunnel, utun, ppp) để Zalo không quét được
static int (*orig_getifaddrs)(struct ifaddrs **ifap);
static int my_getifaddrs(struct ifaddrs **ifap) {
    int ret = orig_getifaddrs ? orig_getifaddrs(ifap) : getifaddrs(ifap);
    if (ret != 0 || !ifap || !*ifap || !is_tweak_active()) {
        return ret;
    }

    // TUYỆT ĐỐI BẢO VỆ TẦNG MẠNG HỆ THỐNG: Nếu caller là Network.framework, CFNetwork, libsystem:
    // giữ nguyên toàn bộ interface (kể cả utun) để socket không bị lỗi EINVAL 22 / Status -1000!
    if (is_system_caller(__builtin_return_address(0), __builtin_return_address(1))) {
        return 0;
    }

    logAudit(@"VPN-CHECK", @"Zalo quét getifaddrs tìm giao diện VPN -> [ĐÃ ẨN TUN/UTUN]");

    struct ifaddrs *curr = *ifap;
    while (curr) {
        if (curr->ifa_name) {
            const char *n = curr->ifa_name;
            if (strncmp(n, "tun", 3) == 0 ||
                strncmp(n, "tap", 3) == 0 ||
                strncmp(n, "ppp", 3) == 0 ||
                strncmp(n, "ipsec", 5) == 0 ||
                strncmp(n, "utun", 4) == 0) {
                // Không ngắt con trỏ danh sách liên kết để bảo vệ bộ nhớ malloc của freeifaddrs
                // Thay vào đó, đổi tên interface thành pdp_ip để Zalo không nhận diện ra VPN
                curr->ifa_name = "pdp_ip9";
            }
        }
        curr = curr->ifa_next;
    }
    return 0;
}



// Giả lập dung lượng ổ cứng ở tầng POSIX C (statfs, fstatfs)
static int (*orig_statfs)(const char *path, struct statfs *buf);
static int my_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs ? orig_statfs(path, buf) : statfs(path, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL;
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = settings.diskTotalSize / bsize;
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = settings.diskFreeSize / bsize;
            buf->f_bfree = buf->f_bavail;
        }
    }
    return ret;
}

static int (*orig_fstatfs)(int fd, struct statfs *buf);
static int my_fstatfs(int fd, struct statfs *buf) {
    int ret = orig_fstatfs ? orig_fstatfs(fd, buf) : -1;
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL;
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = settings.diskTotalSize / bsize;
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = settings.diskFreeSize / bsize;
            buf->f_bfree = buf->f_bavail;
        }
    }
    return ret;
}

// Hook CacheDeleteCopyAvailableSpaceForVolume để chống Zalo đọc dung lượng thật từ daemon 'deleted'
static CFNumberRef (*orig_CacheDeleteCopyAvailableSpaceForVolume)(CFStringRef volume);
static CFNumberRef my_CacheDeleteCopyAvailableSpaceForVolume(CFStringRef volume) {
    if (is_tweak_active()) {
        uint64_t fakeFree = [ZTSettings sharedSettings].diskFreeSize;
        if (fakeFree > 0) {
            logAudit(@"DISK-CHECK", [NSString stringWithFormat:@"CacheDeleteCopyAvailableSpaceForVolume -> [ĐÃ FAKE DUNG LƯỢNG TRỐNG %.1f GB]", (double)fakeFree / (1000.0 * 1000.0 * 1000.0)]);
            return CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &fakeFree);
        }
    }
    return orig_CacheDeleteCopyAvailableSpaceForVolume ? orig_CacheDeleteCopyAvailableSpaceForVolume(volume) : NULL;
}

// Hook _CFCopySystemVersionDictionary & _CFCopyServerVersionDictionary để đồng bộ OS Build Version cho Firebase / Crashlytics
static CFDictionaryRef (*orig_CFCopySystemVersionDictionary)(void) = NULL;
static CFDictionaryRef my_CFCopySystemVersionDictionary(void) {
    if (!is_tweak_active()) {
        return orig_CFCopySystemVersionDictionary ? orig_CFCopySystemVersionDictionary() : NULL;
    }
    CFDictionaryRef origDict = orig_CFCopySystemVersionDictionary ? orig_CFCopySystemVersionDictionary() : NULL;
    NSMutableDictionary *dict = origDict ? [(__bridge NSDictionary *)origDict mutableCopy] : [NSMutableDictionary dictionary];
    if (origDict) CFRelease(origDict);

    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.systemVersion.length > 0) {
        dict[@"ProductVersion"] = s.systemVersion;
        dict[@"ProductUserVisibleVersion"] = s.systemVersion;
    }
    if (s.kernOsVersion.length > 0) {
        dict[@"ProductBuildVersion"] = s.kernOsVersion;
    }
    dict[@"ProductName"] = @"iPhone OS";
    return (__bridge_retained CFDictionaryRef)dict;
}

static CFDictionaryRef (*orig_CFCopyServerVersionDictionary)(void) = NULL;
static CFDictionaryRef my_CFCopyServerVersionDictionary(void) {
    if (!is_tweak_active()) {
        return orig_CFCopyServerVersionDictionary ? orig_CFCopyServerVersionDictionary() : NULL;
    }
    return my_CFCopySystemVersionDictionary();
}

// Hook POSIX stat, lstat, fstat & getattrlist để làm mới device_id và st_birthtimespec
static inline BOOL should_fake_stat_path(const char *path) {
    if (!path) return NO;
    if (strstr(path, "zaloaudit.log") || strstr(path, "zalotraffic.har") || strstr(path, "zalotweak")) {
        return NO;
    }
    if (strstr(path, "/var") ||
        strstr(path, "Containers") ||
        strstr(path, "Documents") ||
        strstr(path, "Library") ||
        strstr(path, "Application") ||
        strstr(path, "mobile") ||
        strstr(path, "/private") ||
        strcmp(path, "/") == 0 ||
        strcmp(path, "/private") == 0 ||
        strcmp(path, "/private/var") == 0 ||
        strcmp(path, "/private/var/mobile") == 0 ||
        strcmp(path, ".") == 0 ||
        strcmp(path, "..") == 0) {
        return YES;
    }
    return NO;
}

static inline void get_consistent_stat_times(uint64_t fake_birth, time_t *out_mtime, time_t *out_ctime, long *out_nsec_b, long *out_nsec_m, long *out_nsec_c) {
    uint64_t delta_m = 180ULL + ((fake_birth * 104729ULL) % 1800ULL) + (fake_birth % 59ULL);
    uint64_t delta_c = delta_m + 30ULL + ((fake_birth * 1299709ULL) % 600ULL) + ((fake_birth / 13ULL) % 43ULL);
    if (out_mtime) *out_mtime = (time_t)(fake_birth + delta_m);
    if (out_ctime) *out_ctime = (time_t)(fake_birth + delta_c);
    if (out_nsec_b) *out_nsec_b = (long)(((fake_birth * 2654435761ULL) % 850ULL + 100ULL) * 1000000L);
    if (out_nsec_m) *out_nsec_m = (long)((((fake_birth + delta_m) * 2246822519ULL) % 850ULL + 100ULL) * 1000000L);
    if (out_nsec_c) *out_nsec_c = (long)((((fake_birth + delta_c) * 3266489917ULL) % 850ULL + 100ULL) * 1000000L);
}

static inline void fake_stat_timespec(struct stat *buf, uint64_t btime) {
    if (!buf) return;
    ZTSettings *s = [ZTSettings sharedSettings];
    time_t fake_birth = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL));
    time_t fake_mtime = 0, fake_ctime = 0;
    long nsec_birth = 0, nsec_mtime = 0, nsec_ctime = 0;
    get_consistent_stat_times((uint64_t)fake_birth, &fake_mtime, &fake_ctime, &nsec_birth, &nsec_mtime, &nsec_ctime);
    buf->st_birthtimespec.tv_sec = fake_birth;
    buf->st_birthtimespec.tv_nsec = nsec_birth;
    buf->st_mtimespec.tv_sec = fake_mtime;
    buf->st_mtimespec.tv_nsec = nsec_mtime;
    buf->st_ctimespec.tv_sec = fake_ctime;
    buf->st_ctimespec.tv_nsec = nsec_ctime;
}

static int (*orig_stat)(const char *path, struct stat *buf);
static int my_stat(const char *path, struct stat *buf) {
    static __thread BOOL s_in_stat = NO;
    if (s_in_stat) return orig_stat ? orig_stat(path, buf) : stat(path, buf);
    s_in_stat = YES;

    int ret = orig_stat ? orig_stat(path, buf) : stat(path, buf);
    if (ret == 0 && is_tweak_active() && buf && path) {
        if (should_fake_stat_path(path)) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec(buf, btime);
            }
        }
    }
    s_in_stat = NO;
    return ret;
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int my_lstat(const char *path, struct stat *buf) {
    static __thread BOOL s_in_lstat = NO;
    if (s_in_lstat) return orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
    s_in_lstat = YES;

    int ret = orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
    if (ret == 0 && is_tweak_active() && buf && path) {
        if (should_fake_stat_path(path)) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec(buf, btime);
            }
        }
    }
    s_in_lstat = NO;
    return ret;
}

static int (*orig_fstat)(int fd, struct stat *buf);
static int my_fstat(int fd, struct stat *buf) {
    static __thread BOOL s_in_fstat = NO;
    if (s_in_fstat) return orig_fstat ? orig_fstat(fd, buf) : fstat(fd, buf);
    s_in_fstat = YES;

    int ret = orig_fstat ? orig_fstat(fd, buf) : fstat(fd, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        char filePath[1024];
        BOOL shouldFake = NO;
        if (fcntl(fd, F_GETPATH, filePath) >= 0) {
            shouldFake = should_fake_stat_path(filePath);
        } else {
            shouldFake = S_ISDIR(buf->st_mode) || (buf->st_birthtimespec.tv_sec > 1400000000);
        }
        if (shouldFake) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec(buf, btime);
            }
        }
    }
    s_in_fstat = NO;
    return ret;
}

static int (*orig_getattrlist)(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options);
static int my_getattrlist(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) {
    int ret = orig_getattrlist ? orig_getattrlist(path, attrList, attrBuf, attrBufSize, options) : getattrlist(path, attrList, attrBuf, attrBufSize, options);
    if (ret == 0 && is_tweak_active() && attrList && attrBuf && path) {
        if (should_fake_stat_path(path) && (attrList->commonattr & (ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME))) {
            ZTSettings *s = [ZTSettings sharedSettings];
            uint64_t birthSec = s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
            size_t words = attrBufSize / sizeof(uint64_t);
            uint64_t *ptr64 = (uint64_t *)attrBuf;
            int timeIdx = 0;
            for (size_t i = 0; i < words; ++i) {
                if (ptr64[i] >= 1400000000ULL && ptr64[i] <= 2500000000ULL) {
                    if (timeIdx == 0) {
                        ptr64[i] = birthSec;
                        if (i + 1 < words && ptr64[i + 1] < 1000000000ULL) {
                            ptr64[i + 1] = ((birthSec * 2654435761ULL) % 900ULL + 100ULL) * 1000000ULL;
                        }
                    } else if (timeIdx == 1) {
                        uint64_t mSec = birthSec + 1435ULL;
                        ptr64[i] = mSec;
                        if (i + 1 < words && ptr64[i + 1] < 1000000000ULL) {
                            ptr64[i + 1] = ((mSec * 2246822519ULL) % 900ULL + 100ULL) * 1000000ULL;
                        }
                    } else {
                        uint64_t cSec = birthSec + 1555ULL;
                        ptr64[i] = cSec;
                        if (i + 1 < words && ptr64[i + 1] < 1000000000ULL) {
                            ptr64[i + 1] = ((cSec * 3266489917ULL) % 900ULL + 100ULL) * 1000000ULL;
                        }
                    }
                    timeIdx++;
                }
            }
        }
    }
    return ret;
}

// ==========================================
// HOOK POSIX open & openat: Chuyển hướng LevelDB KVCore/Device về Sandbox an toàn
// ==========================================
static NSString *get_kvcore_sandbox_base_path(void) {
    NSString *home = NSHomeDirectory();
    if (!home) return nil;
    NSString *appSupport = [home stringByAppendingPathComponent:@"Library/Application Support"];
    [[NSFileManager defaultManager] createDirectoryAtPath:[appSupport stringByAppendingPathComponent:@"KVCore/Device"]
                              withIntermediateDirectories:YES attributes:nil error:nil];
    return appSupport;
}

static int (*orig_open)(const char *path, int oflag, ...);
static int my_open(const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    static __thread BOOL s_in_open = NO;
    if (s_in_open) return orig_open ? orig_open(path, oflag, mode) : open(path, oflag, mode);
    s_in_open = YES;

    if (path && strncmp(path, "KVCore/", 7) == 0) {
        NSString *base = get_kvcore_sandbox_base_path();
        if (base) {
            NSString *rel = [NSString stringWithUTF8String:path];
            NSString *absPath = [base stringByAppendingPathComponent:rel];
            logAudit(@"LEVELDB-C", [NSString stringWithFormat:@"open('%s') -> [BẺ HƯỚNG SANDBOX] %@", path, absPath]);
            int r = orig_open ? orig_open([absPath UTF8String], oflag, mode) : open([absPath UTF8String], oflag, mode);
            s_in_open = NO;
            return r;
        }
    }

    int ret = orig_open ? orig_open(path, oflag, mode) : open(path, oflag, mode);
    s_in_open = NO;
    return ret;
}

static int (*orig_openat)(int fd, const char *path, int oflag, ...);
static int my_openat(int fd, const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    static __thread BOOL s_in_openat = NO;
    if (s_in_openat) return orig_openat ? orig_openat(fd, path, oflag, mode) : openat(fd, path, oflag, mode);
    s_in_openat = YES;

    if (path && (fd == AT_FDCWD || fd >= 0) && strncmp(path, "KVCore/", 7) == 0) {
        NSString *base = get_kvcore_sandbox_base_path();
        if (base) {
            NSString *rel = [NSString stringWithUTF8String:path];
            NSString *absPath = [base stringByAppendingPathComponent:rel];
            logAudit(@"LEVELDB-C", [NSString stringWithFormat:@"openat('%s') -> [BẺ HƯỚNG SANDBOX] %@", path, absPath]);
            int r = orig_openat ? orig_openat(AT_FDCWD, [absPath UTF8String], oflag, mode) : openat(AT_FDCWD, [absPath UTF8String], oflag, mode);
            s_in_openat = NO;
            return r;
        }
    }

    int ret = orig_openat ? orig_openat(fd, path, oflag, mode) : openat(fd, path, oflag, mode);
    s_in_openat = NO;
    return ret;
}

// ==========================================
// HOOK MOBILEGESTALT (MGCOPYANSWER) & HARDWARE RADAR
// ==========================================
static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef property) = NULL;
static CFTypeRef my_MGCopyAnswer(CFStringRef property) {
    if (!property || CFGetTypeID(property) != CFStringGetTypeID() || !is_tweak_active()) {
        return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
    }
    NSString *prop = (__bridge NSString *)property;
    ZTSettings *settings = [ZTSettings sharedSettings];

    // Ghi nhận radar toàn bộ truy vấn MobileGestalt phần cứng của Zalo
    logAudit(@"DETECTION-RADAR", [NSString stringWithFormat:@"MobileGestalt MGCopyAnswer('%@')", prop]);

    if (YES) {
        if ([prop isEqualToString:@"SerialNumber"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"SerialNumber -> [ĐÃ FAKE] %@", settings.spoofedSerial]);
            return settings.spoofedSerial ? (__bridge_retained CFTypeRef)[settings.spoofedSerial copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
        if ([prop isEqualToString:@"UniqueDeviceID"]) {
            NSString *udid = [[settings.spoofedIDFV stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"UniqueDeviceID -> [ĐÃ FAKE] %@", udid]);
            return (__bridge_retained CFTypeRef)[udid copy];
        }
        if ([prop isEqualToString:@"WifiAddress"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"WifiAddress -> [ĐÃ FAKE] %@", settings.spoofedWifiMAC]);
            return settings.spoofedWifiMAC ? (__bridge_retained CFTypeRef)[settings.spoofedWifiMAC copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
        if ([prop isEqualToString:@"BluetoothAddress"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"BluetoothAddress -> [ĐÃ FAKE] %@", settings.spoofedBluetoothMAC]);
            return settings.spoofedBluetoothMAC ? (__bridge_retained CFTypeRef)[settings.spoofedBluetoothMAC copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
        if ([prop isEqualToString:@"UserAssignedDeviceName"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"UserAssignedDeviceName -> [ĐÃ FAKE] %@", settings.deviceName]);
            return settings.deviceName ? (__bridge_retained CFTypeRef)[settings.deviceName copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
        if ([prop isEqualToString:@"ProductType"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"ProductType -> [ĐÃ FAKE] %@", settings.deviceMachine]);
            return settings.deviceMachine ? (__bridge_retained CFTypeRef)[settings.deviceMachine copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
        if ([prop isEqualToString:@"ProductVersion"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"ProductVersion -> [ĐÃ FAKE] %@", settings.systemVersion]);
            return settings.systemVersion ? (__bridge_retained CFTypeRef)[settings.systemVersion copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
        if ([prop isEqualToString:@"BuildVersion"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"BuildVersion -> [ĐÃ FAKE] %@", settings.kernOsVersion]);
            return settings.kernOsVersion ? (__bridge_retained CFTypeRef)[settings.kernOsVersion copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
        if ([prop isEqualToString:@"HWModelStr"] || [prop isEqualToString:@"HardwarePlatform"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"%@ -> [ĐÃ FAKE] %@", prop, settings.deviceModel]);
            return settings.deviceModel ? (__bridge_retained CFTypeRef)[settings.deviceModel copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
        }
    }

    return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
}

static inline BOOL is_sideload_provision_path(NSString *path) {
    if (!path) return NO;
    NSString *lower = [path lowercaseString];
    return [lower containsString:@"embedded.mobileprovision"] ||
           [lower containsString:@"embedded.provisionprofile"];
}

static inline NSString *redirect_kvcore_nsstring(NSString *path) {
    if (!path || path.length == 0) return path;
    NSString *trimmed = [path hasPrefix:@"/"] ? [path substringFromIndex:1] : path;
    if ([trimmed isEqualToString:@"KVCore"] || [trimmed hasPrefix:@"KVCore/"]) {
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *sub = [trimmed substringFromIndex:6];
            return [home stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Application Support/KVCore%@", sub]];
        }
    }
    // Chống lỗi lưu đường dẫn tương đối (relative path) làm hỏng quyền Sandbox
    if (![path hasPrefix:@"/"] && ![path containsString:@":"]) {
        NSString *home = NSHomeDirectory();
        if (home) {
            return [home stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Application Support/%@", path]];
        }
    }
    return path;
}

%hook NSFileManager

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary *)attributes error:(NSError **)error {
    if (path) {
        NSString *safePath = redirect_kvcore_nsstring(path);
        if (![safePath isEqualToString:path]) {
            logAudit(@"KVCORE-FIX", [NSString stringWithFormat:@"Điều hướng tạo thư mục an toàn: '%@' -> '%@'", path, safePath]);
            return %orig(safePath, createIntermediates, attributes, error);
        }
    }
    return %orig;
}

- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary *)attributes error:(NSError **)error {
    if (url && [url isFileURL]) {
        NSString *path = [url path];
        NSString *safePath = redirect_kvcore_nsstring(path);
        if (![safePath isEqualToString:path]) {
            logAudit(@"KVCORE-FIX", [NSString stringWithFormat:@"Điều hướng tạo thư mục URL an toàn: '%@' -> '%@'", path, safePath]);
            return %orig([NSURL fileURLWithPath:safePath isDirectory:YES], createIntermediates, attributes, error);
        }
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path) {
        NSString *safePath = redirect_kvcore_nsstring(path);
        if (![safePath isEqualToString:path]) {
            return %orig(safePath);
        }
        if (is_sideload_provision_path(path)) {
            logAudit(@"SIDELOAD-CHECK", [NSString stringWithFormat:@"Zalo quét chứng chỉ '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
        if (is_tweak_active() && is_jailbreak_path([path UTF8String])) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo quét file Jailbreak '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path) {
        NSString *safePath = redirect_kvcore_nsstring(path);
        if (![safePath isEqualToString:path]) {
            return %orig(safePath, isDirectory);
        }
        if (is_sideload_provision_path(path)) {
            if (isDirectory) *isDirectory = NO;
            logAudit(@"SIDELOAD-CHECK", [NSString stringWithFormat:@"Zalo quét chứng chỉ '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
        if (is_tweak_active() && is_jailbreak_path([path UTF8String])) {
            if (isDirectory) *isDirectory = NO;
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo quét file Jailbreak '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
    }
    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError **)error {
    NSDictionary *attrs = %orig;
    if (!is_tweak_active()) {
        return attrs;
    }
    NSMutableDictionary *fakeAttrs = attrs ? [attrs mutableCopy] : [NSMutableDictionary dictionary];
    ZTSettings *settings = [ZTSettings sharedSettings];
    if (settings.diskTotalSize > 0) {
        fakeAttrs[NSFileSystemSize] = @(settings.diskTotalSize);
    }
    if (settings.diskFreeSize > 0) {
        fakeAttrs[NSFileSystemFreeSize] = @(settings.diskFreeSize);
    }
    return fakeAttrs;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    NSDictionary *attrs = %orig;
    if (is_tweak_active() && attrs && path) {
        NSString *lower = [path lowercaseString];
        if ([lower containsString:@"container"] ||
            [lower containsString:@"document"] ||
            [lower containsString:@"library"] ||
            [lower containsString:@"mobile"] ||
            [lower containsString:@"var"] ||
            [lower containsString:@"application"] ||
            [lower isEqualToString:@"/"] ||
            [lower isEqualToString:@"/private"]) {
            ZTSettings *s = [ZTSettings sharedSettings];
            uint64_t btime = s.bootTimeSec;
            if (btime > 0 || s.birthTimeSec > 0) {
                time_t fake_ctime = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL));
                NSDate *fakeDate = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)fake_ctime];
                NSDate *fakeModDate = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)(fake_ctime + 1435)];
                NSMutableDictionary *m = [attrs mutableCopy];
                m[NSFileCreationDate] = fakeDate;
                m[NSFileModificationDate] = fakeModDate;
                return m;
            }
        }
    }
    return attrs;
}

// Cách ly Shared App Groups cho bản Clone khi thiếu quyền (Zalo gốc dùng App Group thật để Apps Manager backup)
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    NSURL *origURL = %orig;
    if (origURL) {
        // Zalo gốc có App Group chuẩn từ iOS -> Dùng URL gốc này để Apps Manager sao lưu chuẩn 100%!
        return origURL;
    }
    if (groupIdentifier && ([groupIdentifier containsString:@"zalo"] || [groupIdentifier containsString:@"zingalo"] || [groupIdentifier containsString:@"vng"])) {
        logAudit(@"APP-GROUP", [NSString stringWithFormat:@"Zalo truy vấn App Group '%@' (nil) -> [ĐÃ CÁCH LY VỀ THƯ MỤC RIÊNG]", groupIdentifier]);
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *isolatedGroup = [home stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Application Support/IsolatedAppGroups/%@", groupIdentifier]];
            [[NSFileManager defaultManager] createDirectoryAtPath:isolatedGroup withIntermediateDirectories:YES attributes:nil error:nil];
            [[NSFileManager defaultManager] createDirectoryAtPath:[isolatedGroup stringByAppendingPathComponent:@"Library/Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
            [[NSFileManager defaultManager] createDirectoryAtPath:[isolatedGroup stringByAppendingPathComponent:@"Library/Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
            return [NSURL fileURLWithPath:isolatedGroup isDirectory:YES];
        }
    }
    return origURL;
}

// Chặn không cho quét danh sách các container ứng dụng khác trên máy
- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path) {
        NSString *lower = [path lowercaseString];
        if ([lower containsString:@"/containers/data/application"] && ![lower containsString:[NSHomeDirectory() lowercaseString]]) {
            logAudit(@"SCAN-CONTAINER", [NSString stringWithFormat:@"Zalo quét thư mục container '%@' -> [ĐÃ CHẶN - TRẢ VỀ RỖNG]", path]);
            return @[];
        }
        if ([lower containsString:@"/containers/shared/appgroup"]) {
            logAudit(@"SCAN-GROUP", [NSString stringWithFormat:@"Zalo quét danh mục App Group '%@' -> [ĐÃ CHẶN - TRẢ VỀ RỖNG]", path]);
            return @[];
        }
    }
    return %orig;
}

%end

// ==========================================
// HOOK NSURL: Trả về ngày tạo file theo thời gian BootTime giả lập
// ==========================================
%hook NSURL

- (BOOL)getResourceValue:(id *)value forKey:(NSURLResourceKey)key error:(NSError **)error {
    BOOL ret = %orig;
    if (is_tweak_active() && value && key) {
        if ([key isEqualToString:NSURLCreationDateKey] || [key isEqualToString:NSURLContentModificationDateKey] || [key isEqualToString:NSURLAttributeModificationDateKey]) {
            ZTSettings *s = [ZTSettings sharedSettings];
            uint64_t btime = s.bootTimeSec;
            if (btime > 0 || s.birthTimeSec > 0) {
                time_t fake_ctime = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL));
                *value = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)fake_ctime];
                return YES;
            }
        }
    }
    return ret;
}

- (NSDictionary<NSURLResourceKey, id> *)resourceValuesForKeys:(NSArray<NSURLResourceKey> *)keys error:(NSError **)error {
    NSDictionary<NSURLResourceKey, id> *values = %orig;
    if (is_tweak_active() && values && keys) {
        ZTSettings *s = [ZTSettings sharedSettings];
        uint64_t btime = s.bootTimeSec;
        if (btime > 0 || s.birthTimeSec > 0) {
            time_t fake_ctime = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL));
            NSDate *fakeDate = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)fake_ctime];
            NSMutableDictionary *m = [values mutableCopy];
            BOOL changed = NO;
            if ([keys containsObject:NSURLCreationDateKey]) {
                m[NSURLCreationDateKey] = fakeDate;
                changed = YES;
            }
            if ([keys containsObject:NSURLContentModificationDateKey]) {
                m[NSURLContentModificationDateKey] = fakeDate;
                changed = YES;
            }
            if ([keys containsObject:NSURLAttributeModificationDateKey]) {
                m[NSURLAttributeModificationDateKey] = fakeDate;
                changed = YES;
            }
            if (changed) return m;
        }
    }
    return values;
}

%end

// ==========================================
// HOOK NSBundle: ĐẢM BẢO ZALO CLONE ĐƯỢC NHẬN DIỆN LÀ BẢN GỐC APP STORE
// ==========================================

static BOOL s_in_bundle_hook = NO;

%hook NSBundle

- (NSString *)bundleIdentifier {
    if (self == [NSBundle mainBundle]) {
        if (!is_tweak_active()) return %orig;
        if (s_in_bundle_hook) return %orig;
        s_in_bundle_hook = YES;
        BOOL isOrig = is_original_zalo_app();
        s_in_bundle_hook = NO;
        if (isOrig) {
            return %orig;
        }

        // BẢO VỆ TẦNG MẠNG & KERNEL IOS:
        // Nếu caller là các daemon/framework hệ thống (CFNetwork, Network, Security...), trả về Bundle ID gốc của bản clone
        // để Kernel NECP cấp quyền mở socket 4G/Wifi bình thường, tránh lỗi EINVAL 22 / Status -1000
        if (is_system_caller(__builtin_return_address(0), __builtin_return_address(1))) {
            return %orig;
        }

        logAudit(@"BUNDLE-ID", @"Zalo truy vấn bundleIdentifier -> [ĐÃ BẺ HƯỚNG TRẢ VỀ vn.com.vng.zingalo]");
        return @"vn.com.vng.zingalo";
    }
    return %orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if (self == [NSBundle mainBundle] && key && [key isEqualToString:@"CFBundleIdentifier"]) {
        if (!is_tweak_active()) return %orig;
        if (s_in_bundle_hook) return %orig;
        s_in_bundle_hook = YES;
        BOOL isOrig = is_original_zalo_app();
        s_in_bundle_hook = NO;
        if (isOrig) {
            return %orig;
        }
        if (is_system_caller(__builtin_return_address(0), __builtin_return_address(1))) {
            return %orig;
        }
        logAudit(@"BUNDLE-ID", @"Zalo đọc InfoDictionary(CFBundleIdentifier) -> [ĐÃ BẺ HƯỚNG TRẢ VỀ vn.com.vng.zingalo]");
        return @"vn.com.vng.zingalo";
    }
    return %orig;
}

- (NSDictionary *)infoDictionary {
    NSDictionary *dict = %orig;
    if (self == [NSBundle mainBundle] && dict) {
        if (!is_tweak_active()) return dict;
        if (s_in_bundle_hook) return dict;
        s_in_bundle_hook = YES;
        BOOL isOrig = is_original_zalo_app();
        s_in_bundle_hook = NO;
        if (isOrig) {
            return dict;
        }
        if (is_system_caller(__builtin_return_address(0), __builtin_return_address(1))) {
            return dict;
        }
        NSMutableDictionary *mDict = [dict mutableCopy];
        mDict[@"CFBundleIdentifier"] = @"vn.com.vng.zingalo";
        return mDict;
    }
    return dict;
}

%end

%hook NSUserDefaults

- (instancetype)initWithSuiteName:(NSString *)suitename {
    id orig = %orig;
    if (orig) {
        if (suitename && ([suitename containsString:@"zalo"] || [suitename containsString:@"zingalo"] || [suitename containsString:@"vng"])) {
            @try {
                [orig setObject:@"__zt_probe__" forKey:@"__zt_probe_key__"];
                if (![orig stringForKey:@"__zt_probe_key__"]) {
                    logAudit(@"PREFS-FIX", [NSString stringWithFormat:@"SuiteName '%@' không có quyền ghi cfprefsd -> Điều hướng an toàn về standardUserDefaults", suitename]);
                    return [NSUserDefaults standardUserDefaults];
                }
                [orig removeObjectForKey:@"__zt_probe_key__"];
            } @catch (NSException *e) {
                return [NSUserDefaults standardUserDefaults];
            }
        }
        return orig;
    }
    // Nếu ứng dụng (như bản Clone com.sonhu.zaloclone hoặc Sideload) không có App Group entitlement,
    // iOS sẽ trả về nil gây lỗi đọc ghi Groups hoặc LevelDB. Điều hướng an toàn về standardUserDefaults!
    logAudit(@"PREFS-FIX", [NSString stringWithFormat:@"SuiteName '%@' trả về nil (thiếu App Group) -> Điều hướng an toàn về standardUserDefaults", suitename ?: @"(null)"]);
    return [NSUserDefaults standardUserDefaults];
}

- (id)objectForKey:(NSString *)defaultName {
    id val = %orig;
    if ([ZTSettings sharedSettings].enableAuditLog && defaultName && [defaultName isKindOfClass:[NSString class]]) {
        NSString *lower = [defaultName lowercaseString];
        if ([lower containsString:@"device"] ||
            [lower containsString:@"token"] ||
            [lower containsString:@"session"] ||
            [lower containsString:@"auth"] ||
            [lower containsString:@"uuid"] ||
            [lower containsString:@"did"] ||
            [lower containsString:@"zaid"] ||
            [lower containsString:@"login"] ||
            [lower containsString:@"risk"] ||
            [lower containsString:@"banned"]) {
            logAudit(@"DEFAULTS-READ", [NSString stringWithFormat:@"⚙️ Zalo đọc UserDefaults: '%@' -> %@", defaultName, val ? [NSString stringWithFormat:@"[Độ dài %lu]", (unsigned long)[val description].length] : @"(nil)"]);
        }
    }
    return val;
}

%end

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    if (url) {
        NSString *scheme = [[url scheme] lowercaseString];
        // 1. Chặn phát hiện Jailbreak qua schemes
        if ([scheme isEqualToString:@"cydia"] ||
            [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] ||
            [scheme isEqualToString:@"filza"] ||
            [scheme isEqualToString:@"undecimus"]) {
            logAudit(@"SCHEME-CHECK", [NSString stringWithFormat:@"canOpenURL('%@') -> [ĐÃ CHẶN JAILBREAK - TRẢ VỀ NO]", [url absoluteString]]);
            return NO;
        }
        // 2. Cách ly tuyệt đối: Chặn phát hiện các app Zalo khác trên máy
        if ([scheme hasPrefix:@"zalo"] ||
            [scheme isEqualToString:@"zingalo"] ||
            [scheme isEqualToString:@"vng"] ||
            [scheme hasPrefix:@"vng-"] ||
            [scheme isEqualToString:@"vngconnect"]) {
            logAudit(@"INTER-APP-CHECK", [NSString stringWithFormat:@"canOpenURL('%@') -> [ĐÃ CÁCH LY CHẶN DÒ TÌM APP ZALO KHÁC - TRẢ VỀ NO]", [url absoluteString]]);
            return NO;
        }
    }
    return %orig;
}

%end

%hook UIPasteboard

+ (UIPasteboard *)pasteboardWithName:(UIPasteboardName)pasteboardName create:(BOOL)create {
    if (pasteboardName) {
        NSString *lower = [pasteboardName lowercaseString];
        if ([lower containsString:@"zalo"] || [lower containsString:@"zingalo"] || [lower containsString:@"vng"]) {
            logAudit(@"PASTEBOARD", [NSString stringWithFormat:@"Zalo truy vấn pasteboard '%@' -> [ĐÃ CÁCH LY CHẶN ĐỌC]", pasteboardName]);
            return nil;
        }
    }
    return %orig;
}

%end

// ==========================================
// 8. TẦNG MẠNG: HAR NETWORK INSPECTOR TOÀN DIỆN (REQUEST & RESPONSE CHUẨN HAR 1.2)
// ==========================================

static NSString *getHarPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        return [home stringByAppendingPathComponent:@"Documents/ZaloTraffic.har"];
    }
    return @"/var/mobile/Library/Preferences/ZaloTraffic.har";
}

static dispatch_queue_t harQueue = nil;

static void append_to_har_file(NSDictionary *entryDict) {
    if (!harQueue) {
        harQueue = dispatch_queue_create("com.sonhu.zalotweak.harQueue", DISPATCH_QUEUE_SERIAL);
    }

    dispatch_async(harQueue, ^{
        NSString *harPath = getHarPath();
        NSMutableDictionary *harRoot = nil;
        if ([[NSFileManager defaultManager] fileExistsAtPath:harPath]) {
            NSData *existingData = [NSData dataWithContentsOfFile:harPath];
            if (existingData) {
                harRoot = [NSJSONSerialization JSONObjectWithData:existingData options:NSJSONReadingMutableContainers error:nil];
            }
        }

        if (!harRoot || ![harRoot isKindOfClass:[NSMutableDictionary class]] || !harRoot[@"log"]) {
            harRoot = [NSMutableDictionary dictionary];
            NSMutableDictionary *logDict = [NSMutableDictionary dictionary];
            logDict[@"version"] = @"1.2";
            logDict[@"creator"] = @{
                @"name": @"ZaloTweak HAR Inspector",
                @"version": @"1.0"
            };
            logDict[@"entries"] = [NSMutableArray array];
            harRoot[@"log"] = logDict;
        }

        NSMutableArray *entries = harRoot[@"log"][@"entries"];
        if (entries) {
            [entries addObject:entryDict];
            // Giới hạn 500 request gần nhất
            if (entries.count > 500) {
                [entries removeObjectsInRange:NSMakeRange(0, entries.count - 500)];
            }
        }

        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:harRoot options:NSJSONWritingPrettyPrinted error:nil];
        if (jsonData) {
            [jsonData writeToFile:harPath atomically:YES];
        }
    });
}

static void record_har_traffic(NSURLRequest *request, NSData *reqBody, NSURLResponse *response, NSData *respData, NSError *error, NSDate *startDate, NSDate *finishDate) {
    if (![ZTSettings sharedSettings].enableAuditLog) return;
    if (!request || !request.URL) return;

    NSURL *url = request.URL;
    NSString *urlStr = url.absoluteString ?: @"";
    NSString *method = request.HTTPMethod ?: @"GET";

    NSTimeInterval duration = finishDate ? [finishDate timeIntervalSinceDate:startDate] : 0;
    uint64_t durationMs = (uint64_t)(duration * 1000.0);

    NSHTTPURLResponse *httpResp = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
    NSInteger statusCode = httpResp ? httpResp.statusCode : (error ? error.code : 0);
    NSString *statusText = httpResp ? [NSHTTPURLResponse localizedStringForStatusCode:statusCode] : (error ? [error localizedDescription] : @"Pending/Unknown");

    // Diễn giải mục đích nghiệp vụ của request Zalo
    NSString *purpose = @"";
    if ([urlStr containsString:@"centralized.zaloapp.com/sdk/mobile/ios"]) {
        purpose = @"📲 [Zalo SDK: Khởi tạo phiên SDK & gửi cấu hình màn hình/thiết bị]";
    } else if ([urlStr containsString:@"centralized.zaloapp.com/id/mobile/ios"]) {
        purpose = @"🆔 [Zalo Định Danh: Gửi IDFA, IDFV, Hardware Model lên hệ thống Device Fingerprint]";
    } else if ([urlStr containsString:@"centralized.zaloapp.com/apps/mobile/ios"]) {
        purpose = @"🔍 [Zalo Version Check: Kiểm tra phiên bản ứng dụng]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/consents"]) {
        purpose = @"📜 [Zalo Đăng Ký: Tải chính sách & điều khoản đồng ý người dùng]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/login/phone/verify"]) {
        purpose = @"🔑 [Zalo Xác Thực: Gửi số điện thoại yêu cầu mã OTP đăng nhập/đăng ký]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/accounts"]) {
        purpose = @"👤 [Zalo Đăng Ký: Gửi thông tin hoàn tất tạo tài khoản mới]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/login/otp/verify"]) {
        purpose = @"🔢 [Zalo OTP: Xác thực mã OTP người dùng nhập]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v2/login/otp"]) {
        purpose = @"📩 [Zalo OTP: Yêu cầu máy chủ gửi mã OTP về máy]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/verify/name"]) {
        purpose = @"🏷️ [Zalo Đăng Ký: Xác thực tên hiển thị tài khoản]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/verify/dob"]) {
        purpose = @"🎂 [Zalo Đăng Ký: Xác thực ngày sinh & giới tính]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/settings/common"]) {
        purpose = @"⚙️ [Zalo Cấu Hình: Tải tham số hệ thống & máy chủ]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/register/getSupportCountry"]) {
        purpose = @"🌍 [Zalo Quốc Gia: Tải danh sách mã quốc gia hỗ trợ đăng ký]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/helper/getDefaultCountry"]) {
        purpose = @"📍 [Zalo Vị Trí: Lấy quốc gia mặc định của thiết bị]";
    } else if ([urlStr containsString:@"firebase-settings.crashlytics.com"]) {
        purpose = @"🛡️ [Crashlytics: Kiểm tra cấu hình Crashlytics Firebase]";
    } else if ([urlStr containsString:@"firebaselogging-pa.googleapis.com"]) {
        purpose = @"📊 [Firebase Analytics: Gửi log phân tích người dùng]";
    } else if ([urlStr containsString:@"app-analytics-services.com"]) {
        purpose = @"📈 [Analytics: Gửi dữ liệu thống kê ứng dụng]";
    }

    // 1. Format Human-Readable Text Log (In ra Console & ZaloAudit.log)
    NSMutableString *logText = [NSMutableString string];
    [logText appendString:@"\n================================================================================"];
    [logText appendFormat:@"\n🌐 [HAR] %@ %@", method, urlStr];
    if (purpose.length > 0) {
        [logText appendFormat:@"\n👉 Hành động: %@", purpose];
    }
    [logText appendFormat:@"\n⏱ Thời gian: %llums | Status: %ld %@", durationMs, (long)statusCode, statusText];
    if (error) {
        [logText appendFormat:@"\n⚠️ Chi tiết lỗi mạng: Domain=%@ | Code=%ld (%@)", error.domain, (long)error.code, [error localizedDescription]];
        if (error.userInfo && error.userInfo.count > 0) {
            [logText appendFormat:@"\n   • UserInfo: %@", error.userInfo];
        }
    }
    
    // Request Headers
    [logText appendString:@"\n--------------------------------- REQUEST HEADERS ------------------------------"];
    NSDictionary *reqHeaders = request.allHTTPHeaderFields;
    if (reqHeaders.count > 0) {
        for (NSString *hKey in reqHeaders) {
            [logText appendFormat:@"\n   • %@: %@", hKey, reqHeaders[hKey]];
        }
    } else {
        [logText appendString:@"\n   (Không có headers)"];
    }

    // Request Body
    [logText appendString:@"\n--------------------------------- REQUEST BODY ---------------------------------"];
    NSString *reqBodyStr = nil;
    if (reqBody && reqBody.length > 0) {
        reqBodyStr = [[NSString alloc] initWithData:reqBody encoding:NSUTF8StringEncoding];
        if (reqBodyStr) {
            [logText appendFormat:@"\n%@", reqBodyStr];
            if ([reqBodyStr containsString:@"%"]) {
                NSString *decoded = [reqBodyStr stringByRemovingPercentEncoding];
                if (decoded && ![decoded isEqualToString:reqBodyStr]) {
                    [logText appendFormat:@"\n   [ĐÃ GIẢI MÃ NỘI DUNG URL-ENCODED]:\n%@", decoded];
                }
            }
        } else {
            [logText appendFormat:@"\n(Dữ liệu nhị phân %lu bytes)", (unsigned long)reqBody.length];
        }
    } else {
        [logText appendString:@"\n(Không có body)"];
    }

    // Response Headers
    [logText appendString:@"\n--------------------------------- RESPONSE HEADERS -----------------------------"];
    NSDictionary *respHeaders = httpResp.allHeaderFields;
    if (respHeaders.count > 0) {
        for (NSString *hKey in respHeaders) {
            [logText appendFormat:@"\n   • %@: %@", hKey, respHeaders[hKey]];
        }
    } else {
        [logText appendString:@"\n   (Không có headers)"];
    }

    // Response Body
    [logText appendString:@"\n--------------------------------- RESPONSE BODY --------------------------------"];
    NSString *respBodyStr = nil;
    if (respData && respData.length > 0) {
        respBodyStr = [[NSString alloc] initWithData:respData encoding:NSUTF8StringEncoding];
        if (respBodyStr) {
            [logText appendFormat:@"\n%@", respBodyStr];
            if ([respBodyStr containsString:@"error"]) {
                NSData *jd = [respBodyStr dataUsingEncoding:NSUTF8StringEncoding];
                if (jd) {
                    id jObj = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
                    if ([jObj isKindOfClass:[NSDictionary class]]) {
                        NSInteger errCode = [jObj[@"error"] integerValue];
                        NSString *errMsg = jObj[@"errorMsg"] ?: @"";
                        if (errCode != 0) {
                            [logText appendFormat:@"\n🚨 [MÁY CHỦ BÁO LỖI NGHIỆP VỤ] ErrorCode: %ld | Thông báo: \"%@\"", (long)errCode, errMsg];
                        }
                    }
                }
            }
        } else {
            [logText appendFormat:@"\n(Dữ liệu nhị phân %lu bytes)", (unsigned long)respData.length];
        }
    } else {
        [logText appendString:@"\n(Không có body phản hồi)"];
    }
    [logText appendString:@"\n================================================================================"];

    logAudit(@"HAR-INSPECTOR", logText);

    // 2. Tạo đối tượng HAR Entry chuẩn JSON 1.2
    NSISO8601DateFormatter *isoDF = [[NSISO8601DateFormatter alloc] init];
    NSString *startedISO = [isoDF stringFromDate:startDate];

    NSMutableArray *reqHeadersArray = [NSMutableArray array];
    for (NSString *k in reqHeaders) {
        [reqHeadersArray addObject:@{@"name": k, @"value": [NSString stringWithFormat:@"%@", reqHeaders[k]]}];
    }

    NSMutableDictionary *postDataDict = nil;
    if (reqBodyStr) {
        postDataDict = [NSMutableDictionary dictionary];
        postDataDict[@"mimeType"] = reqHeaders[@"Content-Type"] ?: @"application/octet-stream";
        postDataDict[@"text"] = reqBodyStr;
    }

    NSMutableArray *respHeadersArray = [NSMutableArray array];
    for (NSString *k in respHeaders) {
        [respHeadersArray addObject:@{@"name": k, @"value": [NSString stringWithFormat:@"%@", respHeaders[k]]}];
    }

    NSMutableDictionary *contentDict = [NSMutableDictionary dictionary];
    contentDict[@"size"] = @(respData ? respData.length : 0);
    contentDict[@"mimeType"] = respHeaders[@"Content-Type"] ?: @"application/octet-stream";
    if (respBodyStr) {
        contentDict[@"text"] = respBodyStr;
    }

    NSDictionary *harEntry = @{
        @"startedDateTime": startedISO ?: @"",
        @"time": @(durationMs),
        @"request": @{
            @"method": method,
            @"url": urlStr,
            @"httpVersion": @"HTTP/1.1",
            @"cookies": @[],
            @"headers": reqHeadersArray,
            @"queryString": @[],
            @"postData": postDataDict ?: [NSNull null],
            @"headersSize": @(-1),
            @"bodySize": @(reqBody ? reqBody.length : 0)
        },
        @"response": @{
            @"status": @(statusCode),
            @"statusText": statusText ?: @"",
            @"httpVersion": @"HTTP/1.1",
            @"cookies": @[],
            @"headers": respHeadersArray,
            @"content": contentDict,
            @"redirectURL": respHeaders[@"Location"] ?: @"",
            @"headersSize": @(-1),
            @"bodySize": @(respData ? respData.length : 0)
        },
        @"cache": @{},
        @"timings": @{
            @"send": @(0),
            @"wait": @(durationMs),
            @"receive": @(0)
        }
    };

    append_to_har_file(harEntry);
}

// ==========================================
// HOOK NSJSONSerialization: Khử rò rỉ device_id phần cứng trong Payload JSON gửi lên ZAID
// ==========================================
%hook NSJSONSerialization

+ (NSData *)dataWithJSONObject:(id)obj options:(NSJSONWritingOptions)opt error:(NSError **)error {
    if (is_tweak_active() && [obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)obj;
        if (dict[@"device_id"]) {
            NSString *devId = [NSString stringWithFormat:@"%@", dict[@"device_id"]];
            ZTSettings *s = [ZTSettings sharedSettings];
            uint64_t fakeBirth = s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
            time_t fake_mtime = 0, fake_ctime = 0;
            long nsec_b = 0, nsec_m = 0, nsec_c = 0;
            get_consistent_stat_times(fakeBirth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
            uint64_t ms1 = fakeBirth * 1000ULL + (uint64_t)(nsec_b / 1000000L);
            uint64_t ms2 = (uint64_t)fake_mtime * 1000ULL + (uint64_t)(nsec_m / 1000000L);
            uint64_t ms3 = (uint64_t)fake_ctime * 1000ULL + (uint64_t)(nsec_c / 1000000L);
            NSString *cleanDeviceId = [NSString stringWithFormat:@"%llu-%llu-%llu", ms1, ms2, ms3];
            
            NSMutableDictionary *m = [dict mutableCopy];
            m[@"device_id"] = cleanDeviceId;
            logAudit(@"ZAID-RADAR", [NSString stringWithFormat:@"[NSJSONSerialization] Đã chuẩn hoá device_id tự nhiên: %@ (gốc: %@)", cleanDeviceId, devId]);
            return %orig(m, opt, error);
        }
    }
    return %orig;
}

%end

// ==========================================
// BỘ ĐỊNH TUYẾN, LÀM SẠCH VÀ REWRITE GÓI TIN MẠNG ZALO
// ==========================================

static NSURLRequest *sanitize_outbound_zalo_request(NSURLRequest *origReq, NSData **ioBodyData) {
    if (!origReq || !is_tweak_active()) return origReq;
    ZTSettings *settings = [ZTSettings sharedSettings];
    if (settings.deviceMachine.length == 0) return origReq;

    NSMutableURLRequest *mutReq = [origReq mutableCopy];
    BOOL modified = NO;

    // 1. Kiểm tra và bẻ lái Header extInfo
    NSString *extInfo = [mutReq valueForHTTPHeaderField:@"extInfo"];
    if (extInfo) {
        NSMutableString *newExt = [extInfo mutableCopy];
        BOOL extModified = NO;
        NSString *realM = get_real_hardware_machine();
        if (realM.length > 0 && settings.deviceMachine.length > 0 && [newExt containsString:realM]) {
            if (![realM isEqualToString:settings.deviceMachine]) {
                [newExt replaceOccurrencesOfString:realM withString:settings.deviceMachine options:0 range:NSMakeRange(0, newExt.length)];
                extModified = YES;
            }
        }
        if (extModified) {
            [mutReq setValue:newExt forHTTPHeaderField:@"extInfo"];
            modified = YES;
        }
    }

    // 2. Khử rò rỉ OS Build Version trong Crashlytics Header
    NSString *crashBuild = [mutReq valueForHTTPHeaderField:@"X-Crashlytics-OS-Build-Version"];
    if (crashBuild && settings.kernOsVersion.length > 0 && ![crashBuild isEqualToString:settings.kernOsVersion]) {
        [mutReq setValue:settings.kernOsVersion forHTTPHeaderField:@"X-Crashlytics-OS-Build-Version"];
        modified = YES;
    }
    NSString *crashDisplay = [mutReq valueForHTTPHeaderField:@"X-Crashlytics-OS-Display-Version"];
    if (crashDisplay && settings.systemVersion.length > 0 && ![crashDisplay isEqualToString:settings.systemVersion]) {
        [mutReq setValue:settings.systemVersion forHTTPHeaderField:@"X-Crashlytics-OS-Display-Version"];
        modified = YES;
    }

    // 3. Khử rò rỉ model máy thật trong Body nếu gửi lên centralized.zaloapp.com
    NSString *urlStr = origReq.URL.absoluteString ?: @"";
    if ([urlStr containsString:@"centralized.zaloapp.com"]) {
        NSData *body = (ioBodyData && *ioBodyData) ? *ioBodyData : mutReq.HTTPBody;
        if (body && body.length > 0) {
            NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            // TUYỆT ĐỐI KHÔNG sửa body nếu request đã ký chữ ký điện tử (chứa sig= hoặc "sig":)
            // Việc thay đổi bất kỳ ký tự nào sau khi Zalo đã ký sẽ làm hỏng hash -> server trả về error -31 "Invalid signature"
            if (bodyStr && bodyStr.length > 0 && ![bodyStr containsString:@"sig="] && ![bodyStr containsString:@"\"sig\":"]) {
                NSString *realM = get_real_hardware_machine();
                BOOL bodyModified = NO;
                NSMutableString *mutBody = [bodyStr mutableCopy];
                if (realM.length > 0 && [mutBody containsString:realM]) {
                    if (![realM isEqualToString:settings.deviceMachine]) {
                        [mutBody replaceOccurrencesOfString:realM withString:settings.deviceMachine options:0 range:NSMakeRange(0, mutBody.length)];
                        bodyModified = YES;
                        logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã khử rò rỉ model máy thật '%@' trong body -> [ĐÃ FAKE] %@", realM, settings.deviceMachine]);
                    }
                }
                if (bodyModified) {
                    NSData *newBody = [mutBody dataUsingEncoding:NSUTF8StringEncoding];
                    if (ioBodyData && *ioBodyData) {
                        *ioBodyData = newBody;
                    } else {
                        mutReq.HTTPBody = newBody;
                    }
                    modified = YES;
                }
            }
        }
    }

    return modified ? mutReq : origReq;
}

static NSData *rewrite_getDefaultCountry_response_if_needed(NSURLRequest *req, NSData *origRespData) {
    if (!origRespData || origRespData.length == 0 || !is_tweak_active()) return origRespData;
    NSString *url = req.URL.absoluteString ?: @"";
    if (![url containsString:@"register.zaloapp.com/api/helper/getDefaultCountry"]) return origRespData;

    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.carrierMCC.length == 0 || s.carrierMNC.length == 0) return origRespData;

    NSError *err = nil;
    id jsonObj = [NSJSONSerialization JSONObjectWithData:origRespData options:NSJSONReadingMutableContainers error:&err];
    if ([jsonObj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *root = [jsonObj isKindOfClass:[NSMutableDictionary class]] ? (NSMutableDictionary *)jsonObj : [jsonObj mutableCopy];
        id dataObj = root[@"data"];
        if ([dataObj isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *dataDict = [dataObj isKindOfClass:[NSMutableDictionary class]] ? (NSMutableDictionary *)dataObj : [dataObj mutableCopy];
            id mccObj = dataDict[@"mcc_mnc"];
            NSMutableDictionary *mccDict = [mccObj isKindOfClass:[NSDictionary class]] ? [mccObj mutableCopy] : [NSMutableDictionary dictionary];

            NSString *oldMnc = mccDict[@"mnc"] ?: @"";
            mccDict[@"mcc"] = s.carrierMCC;
            mccDict[@"mnc"] = s.carrierMNC;

            if ([s.regionMode isEqualToString:@"US"] || [s.regionMode isEqualToString:@"US_STUDENT"]) {
                mccDict[@"isocountrycodes"] = @"US/USA";
                mccDict[@"countrycode"] = @(1);
                mccDict[@"country"] = @"United States";
            } else {
                mccDict[@"isocountrycodes"] = @"VN/VNM";
                mccDict[@"countrycode"] = @(84);
                mccDict[@"country"] = @"Viet Nam";
            }
            dataDict[@"mcc_mnc"] = mccDict;
            root[@"data"] = dataDict;

            NSData *newData = [NSJSONSerialization dataWithJSONObject:root options:0 error:nil];
            if (newData) {
                logAudit(@"MNC-NORMALIZER", [NSString stringWithFormat:@"getDefaultCountry GeoIP mnc '%@' -> [ĐÃ ÉP KHỚP SIM PROFILE] %@/%@ (%@)", oldMnc, s.carrierMCC, s.carrierMNC, s.carrierName]);
                return newData;
            }
        }
    }
    return origRespData;
}

typedef void (*zt_didReceiveData_imp)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *);
typedef void (*zt_didCompleteWithError_imp)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *);

static NSMutableDictionary<NSString *, NSValue *> *s_orig_didReceiveData_map = nil;
static NSMutableDictionary<NSString *, NSValue *> *s_orig_didCompleteWithError_map = nil;
static __thread BOOL s_in_did_receive_data = NO;
static __thread BOOL s_in_did_complete = NO;

static void zt_didReceiveData_handler(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *dataTask, NSData *data) {
    if (s_in_did_receive_data) return;
    s_in_did_receive_data = YES;

    if (dataTask && data) {
        NSURLRequest *origReq = objc_getAssociatedObject(dataTask, "zt_orig_req") ?: (dataTask.currentRequest ?: dataTask.originalRequest);
        data = rewrite_getDefaultCountry_response_if_needed(origReq, data);
        NSMutableData *accum = objc_getAssociatedObject(dataTask, "zt_resp_data");
        if (accum) {
            @synchronized(accum) {
                [accum appendData:data];
            }
        }
    }
    Class cur = [self class];
    NSValue *val = nil;
    while (cur && !val) {
        val = s_orig_didReceiveData_map[NSStringFromClass(cur)];
        if (!val) cur = class_getSuperclass(cur);
    }
    if (val) {
        zt_didReceiveData_imp origFunc = (zt_didReceiveData_imp)[val pointerValue];
        if (origFunc && (IMP)origFunc != (IMP)zt_didReceiveData_handler) {
            origFunc(self, _cmd, session, dataTask, data);
        }
    }
    s_in_did_receive_data = NO;
}

static void zt_didCompleteWithError_handler(id self, SEL _cmd, NSURLSession *session, NSURLSessionTask *task, NSError *error) {
    if (s_in_did_complete) return;
    s_in_did_complete = YES;

    if (task) {
        NSNumber *alreadyRecorded = objc_getAssociatedObject(task, "zt_har_recorded");
        if (![alreadyRecorded boolValue]) {
            objc_setAssociatedObject(task, "zt_har_recorded", @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            NSURLRequest *origReq = objc_getAssociatedObject(task, "zt_orig_req") ?: (task.currentRequest ?: task.originalRequest);
            NSDate *startDate = objc_getAssociatedObject(task, "zt_start_date") ?: [NSDate date];
            NSData *respData = objc_getAssociatedObject(task, "zt_resp_data");
            NSURLResponse *response = task.response;
            NSData *reqBody = origReq.HTTPBody ?: objc_getAssociatedObject(task, "zt_body_data");

            if (origReq && [ZTSettings sharedSettings].enableAuditLog) {
                record_har_traffic(origReq, reqBody, response, respData, error, startDate, [NSDate date]);
            }
        }
    }
    Class cur = [self class];
    NSValue *val = nil;
    while (cur && !val) {
        val = s_orig_didCompleteWithError_map[NSStringFromClass(cur)];
        if (!val) cur = class_getSuperclass(cur);
    }
    if (val) {
        zt_didCompleteWithError_imp origFunc = (zt_didCompleteWithError_imp)[val pointerValue];
        if (origFunc && (IMP)origFunc != (IMP)zt_didCompleteWithError_handler) {
            origFunc(self, _cmd, session, task, error);
        }
    }
    s_in_did_complete = NO;
}

static void swizzle_session_delegate_class(Class cls) {
    if (!cls) return;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_orig_didReceiveData_map = [[NSMutableDictionary alloc] init];
        s_orig_didCompleteWithError_map = [[NSMutableDictionary alloc] init];
    });

    NSString *clsName = NSStringFromClass(cls);
    @synchronized(s_orig_didReceiveData_map) {
        if (s_orig_didReceiveData_map[clsName] || s_orig_didCompleteWithError_map[clsName]) return;
    }

    SEL selData = @selector(URLSession:dataTask:didReceiveData:);
    Method mData = class_getInstanceMethod(cls, selData);
    if (mData) {
        IMP currentImp = method_getImplementation(mData);
        if (currentImp != (IMP)zt_didReceiveData_handler) {
            const char *types = method_getTypeEncoding(mData);
            if (class_addMethod(cls, selData, (IMP)zt_didReceiveData_handler, types)) {
                @synchronized(s_orig_didReceiveData_map) {
                    s_orig_didReceiveData_map[clsName] = [NSValue valueWithPointer:(void *)currentImp];
                }
            } else {
                IMP origImp = method_setImplementation(mData, (IMP)zt_didReceiveData_handler);
                if (origImp && origImp != (IMP)zt_didReceiveData_handler) {
                    @synchronized(s_orig_didReceiveData_map) {
                        s_orig_didReceiveData_map[clsName] = [NSValue valueWithPointer:(void *)origImp];
                    }
                }
            }
        }
    }

    SEL selComplete = @selector(URLSession:task:didCompleteWithError:);
    Method mComplete = class_getInstanceMethod(cls, selComplete);
    if (mComplete) {
        IMP currentImp = method_getImplementation(mComplete);
        if (currentImp != (IMP)zt_didCompleteWithError_handler) {
            const char *types = method_getTypeEncoding(mComplete);
            if (class_addMethod(cls, selComplete, (IMP)zt_didCompleteWithError_handler, types)) {
                @synchronized(s_orig_didCompleteWithError_map) {
                    s_orig_didCompleteWithError_map[clsName] = [NSValue valueWithPointer:(void *)currentImp];
                }
            } else {
                IMP origImp = method_setImplementation(mComplete, (IMP)zt_didCompleteWithError_handler);
                if (origImp && origImp != (IMP)zt_didCompleteWithError_handler) {
                    @synchronized(s_orig_didCompleteWithError_map) {
                        s_orig_didCompleteWithError_map[clsName] = [NSValue valueWithPointer:(void *)origImp];
                    }
                }
            }
        }
    }
}

%hook NSURLSession

+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration delegate:(id<NSURLSessionDelegate>)delegate delegateQueue:(NSOperationQueue *)queue {
    if (delegate) {
        swizzle_session_delegate_class([delegate class]);
    }
    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    request = sanitize_outbound_zalo_request(request, NULL);
    NSURLSessionDataTask *task = %orig(request);
    if (task && request) {
        objc_setAssociatedObject(task, "zt_orig_req", request, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_start_date", [NSDate date], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_resp_data", [NSMutableData data], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
        NSString *urlStr = request.URL.absoluteString ?: @"";
        NSString *method = request.HTTPMethod ?: @"GET";
        NSString *desc = @"";
        if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/consents"]) {
            desc = @" 👉 [Zalo tải điều khoản đăng ký/sử dụng]";
        } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/login/phone/verify"]) {
            desc = @" 👉 [Zalo xác thực SĐT đăng nhập/OTP]";
        } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/accounts"]) {
            desc = @" 👉 [Zalo tạo tài khoản mới]";
        } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/login/otp/verify"]) {
            desc = @" 👉 [Zalo xác thực mã OTP]";
        } else if ([urlStr containsString:@"register.zaloapp.com/api/v2/login/otp"]) {
            desc = @" 👉 [Zalo gửi mã xác thực OTP về máy]";
        } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/verify/name"]) {
            desc = @" 👉 [Zalo xác thực tên hiển thị]";
        } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/verify/dob"]) {
            desc = @" 👉 [Zalo xác thực ngày sinh/giới tính]";
        } else if ([urlStr containsString:@"centralized.zaloapp.com"]) {
            desc = @" 👉 [Zalo gửi định danh thiết bị]";
        }
        logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [ASYNC DELEGATE] %@ %@%@", method, urlStr, desc]);
    }
    return task;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    request = sanitize_outbound_zalo_request(request, NULL);
    NSDate *startDate = [NSDate date];
    NSData *reqBody = request.HTTPBody;

    if (!completionHandler) {
        if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [TASK-NO-HANDLER] %@ %@", request.HTTPMethod ?: @"GET", request.URL.absoluteString ?: @""]);
        }
        return %orig(request, nil);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        data = rewrite_getDefaultCountry_response_if_needed(request, data);
        NSDate *finishDate = [NSDate date];
        record_har_traffic(request, reqBody, response, data, error, startDate, finishDate);
        completionHandler(data, response, error);
    };

    return %orig(request, wrappedHandler);
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData {
    request = sanitize_outbound_zalo_request(request, &bodyData);
    NSURLSessionUploadTask *task = %orig(request, bodyData);
    if (task && request) {
        objc_setAssociatedObject(task, "zt_orig_req", request, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_start_date", [NSDate date], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_resp_data", [NSMutableData data], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        if (bodyData) {
            objc_setAssociatedObject(task, "zt_body_data", bodyData, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
    }
    if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
        logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [UPLOAD-DELEGATE] %@ %@", request.HTTPMethod ?: @"POST", request.URL.absoluteString ?: @""]);
    }
    return task;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    request = sanitize_outbound_zalo_request(request, &bodyData);
    NSDate *startDate = [NSDate date];

    if (!completionHandler) {
        if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [UPLOAD-NO-HANDLER] %@ %@", request.HTTPMethod ?: @"POST", request.URL.absoluteString ?: @""]);
        }
        return %orig(request, bodyData, nil);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        data = rewrite_getDefaultCountry_response_if_needed(request, data);
        NSDate *finishDate = [NSDate date];
        record_har_traffic(request, bodyData, response, data, error, startDate, finishDate);
        completionHandler(data, response, error);
    };

    return %orig(request, bodyData, wrappedHandler);
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromFile:(NSURL *)fileURL completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    NSDate *startDate = [NSDate date];
    NSData *fileData = fileURL ? [NSData dataWithContentsOfURL:fileURL options:NSDataReadingMappedIfSafe error:nil] : nil;

    if (!completionHandler) {
        if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [UPLOAD-FILE-NO-HANDLER] %@ %@", request.HTTPMethod ?: @"POST", request.URL.absoluteString ?: @""]);
        }
        return %orig(request, fileURL, nil);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDate *finishDate = [NSDate date];
        record_har_traffic(request, fileData, response, data, error, startDate, finishDate);
        completionHandler(data, response, error);
    };

    return %orig(request, fileURL, wrappedHandler);
}

- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler {
    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request {
    return %orig;
}

%end

%hook NSURLConnection

+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse **)response error:(NSError **)error {
    NSDate *startDate = [NSDate date];
    NSURLResponse *resp = nil;
    NSError *err = nil;
    NSData *data = %orig(request, &resp, &err);
    NSDate *finishDate = [NSDate date];

    if (response) *response = resp;
    if (error) *error = err;

    record_har_traffic(request, request.HTTPBody, resp, data, err, startDate, finishDate);
    return data;
}

+ (void)sendAsynchronousRequest:(NSURLRequest *)request queue:(NSOperationQueue *)queue completionHandler:(void (^)(NSURLResponse *response, NSData *data, NSError *connectionError))handler {
    NSDate *startDate = [NSDate date];

    if (!handler) {
        record_har_traffic(request, request.HTTPBody, nil, nil, nil, startDate, nil);
        %orig;
        return;
    }

    void (^wrappedHandler)(NSURLResponse *, NSData *, NSError *) = ^(NSURLResponse *response, NSData *data, NSError *connectionError) {
        NSDate *finishDate = [NSDate date];
        record_har_traffic(request, request.HTTPBody, response, data, connectionError, startDate, finishDate);
        handler(response, data, connectionError);
    };

    %orig(request, queue, wrappedHandler);
}

- (id)initWithRequest:(NSURLRequest *)request delegate:(id)delegate {
    record_har_traffic(request, request.HTTPBody, nil, nil, nil, [NSDate date], nil);
    return %orig;
}

+ (NSURLConnection *)connectionWithRequest:(NSURLRequest *)request delegate:(id)delegate {
    record_har_traffic(request, request.HTTPBody, nil, nil, nil, [NSDate date], nil);
    return %orig;
}

%end

%hook UIViewController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
        if ([ZTSettings sharedSettings].showFloatingMenu) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[ZTMenuManager sharedManager] tryAttachFloatingButton];
            });
        }
        if ([ZTSettings sharedSettings].justGeneratedColdBoot) {
            [ZTSettings sharedSettings].justGeneratedColdBoot = NO;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                ZTSettings *s = [ZTSettings sharedSettings];
                NSString *rDesc = [s.regionMode isEqualToString:@"US_STUDENT"] ? @"Du Học Sinh Mỹ (+1)" :
                                  ([s.regionMode isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" : @"Việt Nam (+84)");
                NSString *welcomeMsg = [NSString stringWithFormat:
                    @"🎉 THIẾT BỊ MỚI TINH ĐÃ KÍCH HOẠT!\n\n"
                    @"• Tên máy: %@\n"
                    @"• SIM & Vùng: %@ (%@ - MCC %@)\n"
                    @"• IDFV Mới: %@\n"
                    @"• IDFA: 00000000-0000-0000-0000-000000000000 (Apple ATT Denied)\n\n"
                    @"🟢 Môi trường sạch sẽ 100%%, sẵn sàng Reg Acc an toàn!",
                    s.deviceName, rDesc, s.carrierName, s.carrierMCC, s.spoofedIDFV];
                
                UIAlertController *wAlert = [UIAlertController alertControllerWithTitle:@"⚡ ZALOTWEAK COLD-BOOT"
                                                                                message:welcomeMsg
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                [wAlert addAction:[UIAlertAction actionWithTitle:@"Bắt Đầu Sử Dụng" style:UIAlertActionStyleDefault handler:nil]];
                [self presentViewController:wAlert animated:YES completion:nil];
            });
        }
    }
}

%end

%hook UIWindow

- (void)makeKeyAndVisible {
    %orig;
    if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
        if ([ZTSettings sharedSettings].showFloatingMenu) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[ZTMenuManager sharedManager] tryAttachFloatingButton];
            });
        }
    }
}

%end

%hook UIResponder

- (void)motionEnded:(UIEventSubtype)motion withEvent:(UIEvent *)event {
    if (motion == UIEventSubtypeMotionShake) {
        if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[ZTMenuManager sharedManager] presentMainMenuFrom:nil];
            });
        }
    }
    %orig;
}

%end

static NSString *get_runtime_environment_desc(void) {
    Dl_info info;
    NSString *dpath = nil;
    NSString *dname = @"Zalotweak.dylib";
    if (dladdr((const void *)get_runtime_environment_desc, &info) && info.dli_fname) {
        dpath = [NSString stringWithUTF8String:info.dli_fname];
        dname = [dpath lastPathComponent] ?: @"Zalotweak.dylib";
    }

#if defined(THEOS_PACKAGE_SCHEME_ROOTHIDE)
    return [NSString stringWithFormat:@"🛡️ Roothide (DEB) [%@]", dname];
#elif defined(THEOS_PACKAGE_SCHEME_ROOTLESS)
    return [NSString stringWithFormat:@"⚡ Rootless (DEB) [%@]", dname];
#endif

    if (dlsym(RTLD_DEFAULT, "jbrand") != NULL ||
        dlsym(RTLD_DEFAULT, "jbroot") != NULL ||
        dlsym(RTLD_DEFAULT, "roothide_check_path") != NULL ||
        (dpath && ([dpath containsString:@"/jb-"] || [dpath containsString:@"roothide"]))) {
        return [NSString stringWithFormat:@"🛡️ Roothide (DEB) [%@]", dname];
    }

    if (dpath && [dpath containsString:@".app/"]) {
        return [NSString stringWithFormat:@"📱 Sideload / Clone [%@]", dname];
    }

    if (dlsym(RTLD_DEFAULT, "ellekit_hook_c_function") != NULL ||
        (dpath && ([dpath containsString:@"/var/jb/"] || [dpath containsString:@"/var/jb"]))) {
        return [NSString stringWithFormat:@"⚡ Rootless (DEB) [%@]", dname];
    }

    if (dpath && ([dpath containsString:@"/Library/MobileSubstrate/"] || [dpath containsString:@"/usr/lib/TweakInject/"])) {
        return [NSString stringWithFormat:@"👑 Rootful (DEB) [%@]", dname];
    }

    if (is_device_jailbroken()) {
        return [NSString stringWithFormat:@"🛡️ Roothide (DEB) [%@]", dname];
    }

    return [NSString stringWithFormat:@"🔌 Custom Dylib [%@]", dname];
}

static void settingsChangedCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    if ([ZTSettings sharedSettings].isShuttingDownForDeepWipe) {
        return;
    }
    [[ZTSettings sharedSettings] loadSettings];
    update_cached_locale_and_tz();
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([ZTSettings sharedSettings].showFloatingMenu) {
            [[ZTMenuManager sharedManager] setupInAppMenu];
            [[ZTFloatingButton sharedButton] show];
        } else {
            [[ZTFloatingButton sharedButton] hide];
        }
    });
}

static void scan_zalo_security_modules_async(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool {
            // Đợi 2 giây để Zalo hoàn tất nạp các dynamic frameworks vào bộ nhớ
            [NSThread sleepForTimeInterval:2.0];

            int numClasses = objc_getClassList(NULL, 0);
            if (numClasses <= 0) return;
            Class *classes = (Class *)malloc(sizeof(Class) * numClasses);
            if (!classes) return;
            numClasses = objc_getClassList(classes, numClasses);

            NSMutableArray *foundModules = [NSMutableArray array];

            for (int i = 0; i < numClasses; i++) {
                Class cls = classes[i];
                const char *clsName = class_getName(cls);
                if (!clsName) continue;

                const char *imgName = class_getImageName(cls);
                if (!imgName) continue;
                // Chỉ quét các class thuộc Zalo hoặc Frameworks nhúng của Zalo
                if (!strstr(imgName, "Zalo") && !strstr(imgName, "ZDK") && !strstr(imgName, "vn.com.vng.zingalo")) {
                    continue;
                }

                if (strcasestr(clsName, "Security") ||
                    strcasestr(clsName, "Fingerprint") ||
                    strcasestr(clsName, "Integrity") ||
                    strcasestr(clsName, "Jailbreak") ||
                    strcasestr(clsName, "Detector") ||
                    strcasestr(clsName, "Anti") ||
                    strcasestr(clsName, "Risk") ||
                    strcasestr(clsName, "ZShield") ||
                    strcasestr(clsName, "DeviceID") ||
                    strcasestr(clsName, "DeviceInfo") ||
                    strcasestr(clsName, "Hardware") ||
                    strcasestr(clsName, "Biometric") ||
                    strcasestr(clsName, "Telemetry")) {
                    [foundModules addObject:[NSString stringWithUTF8String:clsName]];
                }
            }
            free(classes);

            if (foundModules.count > 0) {
                [foundModules sortUsingSelector:@selector(compare:)];
                logAudit(@"ZALO-SECURITY-RADAR", [NSString stringWithFormat:@"🛡️ [RADAR TOÀN DIỆN] Phát hiện %lu module bảo mật/định danh của Zalo:\n   • %@", (unsigned long)foundModules.count, [foundModules componentsJoinedByString:@"\n   • "]]);
            } else {
                logAudit(@"ZALO-SECURITY-RADAR", @"🛡️ [RADAR TOÀN DIỆN] Đã quét toàn bộ binary Zalo nhưng không phát hiện module bảo mật riêng biệt.");
            }
        }
    });
}

%ctor {
    @autoreleasepool {
        s_is_cold_boot_phase = YES;
        // 1. Khởi tạo toàn bộ dữ liệu cấu hình, bộ nhớ hàng đợi và xác thực bản quyền TRƯỚC KHI BẬT HOOK
        // Đảm bảo không bị deadlock re-entrant
        loggedAuditKeys = [[NSMutableSet alloc] init];
        auditQueue = dispatch_queue_create("com.sonhu.zalotweak.auditQueue", DISPATCH_QUEUE_SERIAL);
        harQueue = dispatch_queue_create("com.sonhu.zalotweak.harQueue", DISPATCH_QUEUE_SERIAL);

        [ZTSettings sharedSettings];
        update_cached_locale_and_tz();
        [[ZTSecurityManager sharedManager] isLicenseValid];
        s_is_cold_boot_phase = NO;

        // 2. Kích hoạt toàn bộ hook Objective-C của Logos sau khi cấu hình đã sẵn sàng
        %init;

        if ([ZTSettings sharedSettings].enableAuditLog) {
            scan_zalo_security_modules_async();
        }

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            settingsChangedCallback,
            CFSTR("com.sonhu.zalotweak/settingschanged"),
            NULL,
            CFNotificationSuspensionBehaviorCoalesce
        );

        // 3. Cài đặt các hook C an toàn (tương thích 100% cả Jailbreak lẫn Sideload/LARA qua Fishhook)
        dynamic_MSHookFunction = (void (*)(void *, void *, void **))dlsym(RTLD_DEFAULT, "MSHookFunction");

        universal_hook_c_function("sysctl", (void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
        universal_hook_c_function("sysctlbyname", (void *)sysctlbyname, (void *)my_sysctlbyname, (void **)&orig_sysctlbyname);
        universal_hook_c_function("uname", (void *)uname, (void *)my_uname, (void **)&orig_uname);
        universal_hook_c_function("statfs", (void *)statfs, (void *)my_statfs, (void **)&orig_statfs);
        void *fstatfs_ptr = (void *)fstatfs;
        if (fstatfs_ptr) {
            universal_hook_c_function("fstatfs", fstatfs_ptr, (void *)my_fstatfs, (void **)&orig_fstatfs);
        }
        universal_hook_c_function("stat", (void *)stat, (void *)my_stat, (void **)&orig_stat);
        universal_hook_c_function("lstat", (void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
        universal_hook_c_function("fstat", (void *)fstat, (void *)my_fstat, (void **)&orig_fstat);
        universal_hook_c_function("getattrlist", (void *)getattrlist, (void *)my_getattrlist, (void **)&orig_getattrlist);
        if (!dynamic_MSHookFunction) {
            struct rebinding inode64_rebs[] = {
                { "stat$INODE64", (void *)my_stat, NULL },
                { "lstat$INODE64", (void *)my_lstat, NULL },
                { "fstat$INODE64", (void *)my_fstat, NULL }
            };
            rebind_symbols(inode64_rebs, 3);
        }
        void *cdFunc = dlsym(RTLD_DEFAULT, "CacheDeleteCopyAvailableSpaceForVolume");
        if (cdFunc) {
            universal_hook_c_function("CacheDeleteCopyAvailableSpaceForVolume", cdFunc, (void *)my_CacheDeleteCopyAvailableSpaceForVolume, (void **)&orig_CacheDeleteCopyAvailableSpaceForVolume);
        }

        // Hook POSIX open & openat (Bẻ hướng LevelDB KVCore/Device về Sandbox an toàn)
        universal_hook_c_function("open", (void *)open, (void *)my_open, (void **)&orig_open);
        universal_hook_c_function("openat", (void *)openat, (void *)my_openat, (void **)&orig_openat);

        // Hook CoreFoundation Preferences (App Groups Redirection)
        universal_hook_c_function("CFPreferencesCopyAppValue", (void *)CFPreferencesCopyAppValue, (void *)my_CFPreferencesCopyAppValue, (void **)&orig_CFPreferencesCopyAppValue);
        universal_hook_c_function("CFPreferencesSetAppValue", (void *)CFPreferencesSetAppValue, (void *)my_CFPreferencesSetAppValue, (void **)&orig_CFPreferencesSetAppValue);
        universal_hook_c_function("CFPreferencesAppSynchronize", (void *)CFPreferencesAppSynchronize, (void *)my_CFPreferencesAppSynchronize, (void **)&orig_CFPreferencesAppSynchronize);

        // Hook Security Framework (Keychain Isolation)
        universal_hook_c_function("SecItemCopyMatching", (void *)SecItemCopyMatching, (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        universal_hook_c_function("SecItemAdd", (void *)SecItemAdd, (void *)my_SecItemAdd, (void **)&orig_SecItemAdd);
        universal_hook_c_function("SecItemDelete", (void *)SecItemDelete, (void *)my_SecItemDelete, (void **)&orig_SecItemDelete);
        universal_hook_c_function("SecItemUpdate", (void *)SecItemUpdate, (void *)my_SecItemUpdate, (void **)&orig_SecItemUpdate);

        // Hook WiFi BSSID Anonymization
        void *cnFunc = (void *)CNCopyCurrentNetworkInfo;
        if (cnFunc) {
            universal_hook_c_function("CNCopyCurrentNetworkInfo", cnFunc, (void *)my_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
        }

        // Hook getifaddrs (Lọc bỏ interface VPN, tap, tun, utun)
        universal_hook_c_function("getifaddrs", (void *)getifaddrs, (void *)my_getifaddrs, (void **)&orig_getifaddrs);

        // Hook MobileGestalt MGCopyAnswer (Radar bắt toàn bộ điểm check phần cứng của Zalo)
        void *mgFunc = dlsym(RTLD_DEFAULT, "MGCopyAnswer");
        if (mgFunc) {
            universal_hook_c_function("MGCopyAnswer", mgFunc, (void *)my_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        }

        // Hook CoreFoundation SystemVersion Dictionary (Khử rò rỉ OS Build Version lên Crashlytics/GoogleUtilities)
        void *cfSysVer = dlsym(RTLD_DEFAULT, "_CFCopySystemVersionDictionary");
        if (cfSysVer) {
            universal_hook_c_function("_CFCopySystemVersionDictionary", cfSysVer, (void *)my_CFCopySystemVersionDictionary, (void **)&orig_CFCopySystemVersionDictionary);
        }
        void *cfSrvVer = dlsym(RTLD_DEFAULT, "_CFCopyServerVersionDictionary");
        if (cfSrvVer) {
            universal_hook_c_function("_CFCopyServerVersionDictionary", cfSrvVer, (void *)my_CFCopyServerVersionDictionary, (void **)&orig_CFCopyServerVersionDictionary);
        }

        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            NSLog(@"[ZaloTweak] ❌ BẢN QUYỀN CHƯA KÍCH HOẠT HOẶC ĐÃ HẾT HẠN! Vui lòng vào Cài đặt để kích hoạt.");
        } else {
            NSLog(@"[ZaloTweak] 🟢 Bản quyền hợp lệ: %@", [[ZTSecurityManager sharedManager] getLicenseStatusText]);
        }

        NSLog(@"[ZaloTweak] Đã khởi tạo hoàn chỉnh - Model: %@ | Res: %.0fx%.0f@%.0fx | IDFV: %@ | Disk: %llu GB",
              [ZTSettings sharedSettings].deviceMachine,
              [ZTSettings sharedSettings].screenWidth,
              [ZTSettings sharedSettings].screenHeight,
              [ZTSettings sharedSettings].screenScale,
              [ZTSettings sharedSettings].spoofedIDFV,
              [ZTSettings sharedSettings].diskTotalSize / (1000000000ULL));

        NSString *envDesc = get_runtime_environment_desc();
        NSLog(@"[ZaloTweak] 🚀 Môi trường: %@", envDesc);

        // Lưu thông tin môi trường vào cấu hình để mục Cài đặt Settings hiển thị
        NSString *cfgPath = getConfigPath();
        NSMutableDictionary *cfgDict = [NSMutableDictionary dictionaryWithContentsOfFile:cfgPath] ?: [NSMutableDictionary dictionary];
        cfgDict[@"runtimeEnvironment"] = envDesc;
        [cfgDict writeToFile:cfgPath atomically:YES];
        chmod([cfgPath UTF8String], 0666);
        if (is_device_jailbroken()) {
            NSString *rhPath = get_roothide_prefs_path();
            if (rhPath) {
                [cfgDict writeToFile:rhPath atomically:YES];
                chmod([rhPath UTF8String], 0666);
            }
            [cfgDict writeToFile:GLOBAL_PREFS_PATH atomically:YES];
            chmod([GLOBAL_PREFS_PATH UTF8String], 0666);
        }

        // Khởi tạo In-App Floating Menu (Chỉ hiện khi là Zalo Clone/Sideload hoặc người dùng bật trong Cài đặt, và KHÔNG PHẢI App Extension)
        if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
            if ([ZTSettings sharedSettings].showFloatingMenu) {
                [[ZTMenuManager sharedManager] setupInAppMenu];
            }
        }

        // Ghi nhận dòng kiểm toán khởi động ban đầu
        if ([ZTSettings sharedSettings].enableAuditLog) {
            ZTSettings *s = [ZTSettings sharedSettings];
            logAudit(@"SYSTEM-INIT", [NSString stringWithFormat:@"Khởi động ZaloTweak v1.0 | Môi trường: %@ | App: %@ | Model: %@ | Res: %.0fx%.0f@%.0fx | IDFV: %@ | Bản quyền: %@",
                      envDesc,
                      [[NSBundle mainBundle] bundleIdentifier],
                      s.deviceMachine,
                      s.screenWidth,
                      s.screenHeight,
                      s.screenScale,
                      s.spoofedIDFV,
                      [[ZTSecurityManager sharedManager] getLicenseStatusText]]);

            // 1. Đồng bộ Vùng, Ngôn ngữ & Múi giờ
            NSString *langStr = [s.preferredLanguages componentsJoinedByString:@", "] ?: @"vi-VN, en-VN";
            NSInteger gmtSec = s_cachedTimeZone ? [s_cachedTimeZone secondsFromGMT] : 25200;
            int gmtH = (int)(gmtSec / 3600);
            int gmtM = abs((int)((gmtSec % 3600) / 60));
            NSString *gmtStr = gmtM > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", gmtH, gmtM] : [NSString stringWithFormat:@"GMT%+d", gmtH];
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"🌍 [VÙNG / MÚI GIỜ] Region: %@ | Locale: %@ | TimeZone: %@ (%@) | Ngôn ngữ: [%@]",
                      s.regionMode ?: @"VN",
                      s.localeIdentifier ?: @"vi_VN",
                      s.timeZoneName ?: @"Asia/Ho_Chi_Minh",
                      gmtStr,
                      langStr]);

            // 2. Nhà mạng di động & Cellular
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"📶 [NHÀ MẠNG SIM] Mạng: %@ | MCC: %@ | MNC: %@ | ISO: %@ | Radio: LTE",
                      s.carrierName ?: @"Viettel",
                      s.carrierMCC ?: @"452",
                      s.carrierMNC ?: @"04",
                      s.carrierCountryCode ?: @"vn"]);

            // 3. Phần cứng & Radar tập lệnh / Cache
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"⚙️ [RADAR PHẦN CỨNG] hw.product: %@ | L2Cache: %u MB | PageSize: 16KB | ProcTranslated: 0",
                      s.deviceMachine ?: @"iPhone9,1",
                      (unsigned int)(s.l2cacheSize / (1024 * 1024))]);

            // 4. Thời gian khởi tạo hệ thống file & Boot Time
            time_t fake_ctime = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL));
            struct tm b_tm, boot_tm;
            gmtime_r(&fake_ctime, &b_tm);
            time_t btime_sec = (time_t)s.bootTimeSec;
            gmtime_r(&btime_sec, &boot_tm);
            char bTimeBuf[32] = {0};
            char bootBuf[32] = {0};
            snprintf(bTimeBuf, sizeof(bTimeBuf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
                     b_tm.tm_year + 1900, b_tm.tm_mon + 1, b_tm.tm_mday,
                     b_tm.tm_hour, b_tm.tm_min, b_tm.tm_sec);
            snprintf(bootBuf, sizeof(bootBuf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
                     boot_tm.tm_year + 1900, boot_tm.tm_mon + 1, boot_tm.tm_mday,
                     boot_tm.tm_hour, boot_tm.tm_min, boot_tm.tm_sec);

            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"🕒 [THỜI GIAN/Ổ ĐĨA] st_birthtime: %s (%llu) | BootTime: %s | Disk: %llu GB",
                      bTimeBuf,
                      (unsigned long long)fake_ctime,
                      bootBuf,
                      s.diskTotalSize / (1000000000ULL)]);
        }
    }
}
