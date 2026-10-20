#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>
#import <objc/runtime.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CFNetwork/CFNetwork.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
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
#import <time.h>
#import <mach/mach_time.h>
#import <pthread.h>
#import "fishhook.h"
#import "Config.h"
#import "SecurityManager.h"
#import "FloatingMenu.h"
#import "DeviceProfilePool.h"

__attribute__((visibility("default"))) void zt_reset_runtime_counters(void);
__attribute__((visibility("default"))) NSInteger zt_get_last_centralized_status(void);
__attribute__((visibility("default"))) NSString *zt_get_last_centralized_did(void);
__attribute__((visibility("default"))) NSInteger zt_get_qos_error_count(void);
__attribute__((visibility("default"))) int zt_get_masked_ifaddrs(struct ifaddrs **ifap);
__attribute__((visibility("default"))) void zt_log_audit(NSString *category, NSString *detail);

static void (*dynamic_MSHookFunction)(void *symbol, void *replace, void **result) = NULL;
#if __has_feature(ptrauth_calls)
#import <ptrauth.h>
#endif

static inline void *strip_pac_ptr(const void *ptr) {
    if (!ptr) return NULL;
#if __has_feature(ptrauth_calls)
    return ptrauth_strip((void *)ptr, ptrauth_key_asia);
#elif defined(__arm64e__)
    void *ret = (void *)ptr;
    asm volatile("xpaci %0" : "+r"(ret));
    return ret;
#else
    return (void *)((uintptr_t)ptr & 0x00007FFFFFFFFFFFULL);
#endif
}

static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;

static inline int raw_dladdr(const void *addr, Dl_info *info) {
    if (!addr) return 0;
    const void *clean_addr = strip_pac_ptr(addr);
    return orig_dladdr ? orig_dladdr(clean_addr, info) : dladdr(clean_addr, info);
}

static inline void universal_hook_c_function(const char *name, void *symbol, void *replace, void **result) {
    void *ms_orig = NULL;
    if (dynamic_MSHookFunction && symbol) {
        dynamic_MSHookFunction(symbol, replace, &ms_orig);
    }
    if (ms_orig != NULL) {
        if (result) *result = ms_orig;
        // MSHookFunction đã patch trực tiếp prologue của symbol.
        // Khi chạy bổ sung rebind_symbols cho các bảng GOT/LAZY, truyền NULL cho replaced
        // để fishhook KHÔNG ghi đè *result bằng địa chỉ symbol đã bị patch (tránh đệ quy vô tận)!
        if (name) {
            struct rebinding r = { name, replace, NULL };
            rebind_symbols(&r, 1);
        }
    } else {
        // MSHookFunction không có sẵn (Sideload/Clone) hoặc từ chối patch syscall stub 12-byte (stat/lstat/fstat/getattrlist trên arm64 & arm64e):
        // Giữ nguyên *result = symbol gốc trong libsystem_kernel.dylib và dùng fishhook rebind toàn bộ GOT/PLT!
        if (result && symbol) {
            *result = symbol;
        }
        if (name) {
            void *fh_orig = NULL;
            struct rebinding r = { name, replace, &fh_orig };
            rebind_symbols(&r, 1);
            if (result && *result == NULL && fh_orig != NULL && fh_orig != replace) {
                *result = fh_orig;
            }
        }
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
    
    NSString *bundleId = nil;
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    if (info && [info isKindOfClass:[NSDictionary class]]) {
        bundleId = info[@"CFBundleIdentifier"];
    }
    if (!bundleId) {
        CFBundleRef mb = CFBundleGetMainBundle();
        if (mb) {
            CFStringRef cbid = CFBundleGetIdentifier(mb);
            if (cbid) bundleId = (__bridge NSString *)cbid;
        }
    }
    if (bundleId && bundleId.length > 0) {
        if ([bundleId isEqualToString:@"vn.com.vng.zingalo"] ||
            [bundleId isEqualToString:@"com.vng.zalo"] ||
            [bundleId isEqualToString:@"com.zing.zalo"]) {
            s_is_orig = 1;
            return YES;
        } else {
            s_is_orig = 0;
            return NO;
        }
    }
    
    const char *pname = getprogname();
    if (pname && (strstr(pname, "Zalo") != NULL || strstr(pname, "zingalo") != NULL)) {
        return YES; // Tạm thời coi là bản gốc trong lúc runtime đang khởi tạo
    }
    return YES; // Mặc định an toàn bảo vệ APNs thật
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
    if (raw_dladdr((const void *)is_device_jailbroken, &info) && info.dli_fname) {
        NSString *dpath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *appBundle = [[NSBundle mainBundle] bundlePath];
        if (appBundle && ![dpath hasPrefix:appBundle]) {
            return YES; // Nạp từ ngoài App Bundle -> Chắc chắn là môi trường Jailbreak!
        }
    }
    return NO;
}

static inline BOOL is_zalo_caller(const void *addr0) {
    if (!addr0) return NO;
    Dl_info info0;
    if (raw_dladdr(addr0, &info0) && info0.dli_fname) {
        const char *f0 = info0.dli_fname;
        if ((strstr(f0, ".app/") != NULL || strstr(f0, "/Zalo.app") != NULL) &&
            strstr(f0, "Zalotweak") == NULL &&
            strstr(f0, "roothide") == NULL &&
            strstr(f0, "Substrate") == NULL &&
            strstr(f0, "ellekit") == NULL) {
            return YES;
        }
    }
    return NO;
}

static inline BOOL __attribute__((unused)) is_zalo_or_tweak_caller(const void *addr0, const void *addr1) {
    if (is_zalo_caller(addr0) || is_zalo_caller(addr1)) return YES;
    const void *addrs[2] = {addr0, addr1};
    for (int i = 0; i < 2; i++) {
        if (!addrs[i]) continue;
        Dl_info info0;
        if (raw_dladdr(addrs[i], &info0) && info0.dli_fname) {
            const char *f0 = info0.dli_fname;
            if (strstr(f0, "Zalotweak") != NULL) {
                return YES;
            }
        }
    }
    return NO;
}

static inline BOOL is_network_system_caller(const void *addr) {
    if (!addr) return NO;
    Dl_info info;
    if (raw_dladdr(addr, &info) && info.dli_fname) {
        const char *f = info.dli_fname;
        if (strstr(f, "CFNetwork") != NULL ||
            strstr(f, "libnetwork") != NULL ||
            strstr(f, "Network.framework") != NULL ||
            strstr(f, "CoreTelephony") != NULL ||
            strstr(f, "SystemConfiguration") != NULL) {
            return YES;
        }
    }
    return NO;
}

static inline BOOL __attribute__((unused)) is_system_caller(const void *addr0, const void *addr1) {
    const void *addrs[2] = {addr0, addr1};
    for (int i = 0; i < 2; i++) {
        if (!addrs[i]) continue;
        Dl_info info;
        if (raw_dladdr(addrs[i], &info) && info.dli_fname) {
            const char *fname = info.dli_fname;
            if (strstr(fname, "/System/Library/") != NULL ||
                strstr(fname, "/usr/lib/") != NULL ||
                strstr(fname, "CFNetwork") != NULL ||
                strstr(fname, "Network") != NULL ||
                strstr(fname, "libnetwork") != NULL ||
                strstr(fname, "CoreTelephony") != NULL ||
                strstr(fname, "UserNotifications") != NULL ||
                strstr(fname, "CoreFoundation") != NULL ||
                strstr(fname, "Foundation") != NULL ||
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

#define MAX_RADAR_CALLERS 256
static void *s_radar_logged_addrs[MAX_RADAR_CALLERS];
static int s_radar_logged_count = 0;
static pthread_mutex_t s_radar_lock = PTHREAD_MUTEX_INITIALIZER;

static BOOL should_log_radar_caller(void *addr) {
    if (!addr) return NO;
    pthread_mutex_lock(&s_radar_lock);
    for (int i = 0; i < s_radar_logged_count; i++) {
        if (s_radar_logged_addrs[i] == addr) {
            pthread_mutex_unlock(&s_radar_lock);
            return NO;
        }
    }
    if (s_radar_logged_count < MAX_RADAR_CALLERS) {
        s_radar_logged_addrs[s_radar_logged_count++] = addr;
    }
    pthread_mutex_unlock(&s_radar_lock);
    return YES;
}

static NSString *format_caller_info(void *addr) {
    if (!addr) return @"(unknown)";
    Dl_info info;
    if (raw_dladdr(addr, &info)) {
        const char *fname = info.dli_fname ? (strrchr(info.dli_fname, '/') ? strrchr(info.dli_fname, '/') + 1 : info.dli_fname) : "unknown";
        const char *sname = info.dli_sname ?: "unknown_sym";
        ptrdiff_t offset = (const char *)addr - (const char *)(info.dli_saddr ?: info.dli_fbase);
        return [NSString stringWithFormat:@"%s`%s + 0x%lx (%p)", fname, sname, (long)offset, addr];
    }
    return [NSString stringWithFormat:@"%p", addr];
}

static void zt_reset_radar_cache(void) {
    pthread_mutex_lock(&s_radar_lock);
    s_radar_logged_count = 0;
    pthread_mutex_unlock(&s_radar_lock);
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

static inline BOOL has_active_session_in_sandbox(void) {
    NSString *home = NSHomeDirectory();
    if (!home) return NO;
    NSString *zaloPref = [home stringByAppendingPathComponent:@"Library/Preferences/vn.com.vng.zingalo.plist"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:zaloPref]) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:zaloPref];
        if (d && (d[@"kSessionUid"] || d[@"kSessionKey"])) {
            return YES;
        }
    }
    return NO;
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
        NSDictionary *localDict = nil;
        uint64_t localWipeTS = 0;
        BOOL localNeedsWipe = NO;
        if ([fm fileExistsAtPath:containerPref]) {
            NSDictionary *localAttrs = [fm attributesOfItemAtPath:containerPref error:nil];
            localDate = localAttrs[NSFileModificationDate];
            localDict = [NSDictionary dictionaryWithContentsOfFile:containerPref];
            localWipeTS = [localDict[@"lastWipedTimestamp"] unsignedLongLongValue];
            localNeedsWipe = [localDict[@"needsNewProfile"] boolValue] || [localDict[@"needsSandboxPurge"] boolValue];
        }

        // BẢO VỆ TUYỆT ĐỐI CHO TÀI KHOẢN KHI RESTORE:
        // Nếu phát hiện trong Sandbox ĐÃ CÓ tài khoản Zalo hợp lệ (vừa restore từ Apps Manager / Backup),
        // tuyệt đối KHÔNG cho file global ngoài hệ thống có cờ wipe đè vào!
        BOOL hasSession = has_active_session_in_sandbox();
        if (hasSession && [fm fileExistsAtPath:containerPref]) {
            NSMutableDictionary *m = [NSMutableDictionary dictionaryWithContentsOfFile:containerPref];
            if (m && ([m[@"needsNewProfile"] boolValue] || [m[@"needsSandboxPurge"] boolValue])) {
                m[@"needsNewProfile"] = @(NO);
                m[@"needsSandboxPurge"] = @(NO);
                [m writeToFile:containerPref atomically:YES];
                [m writeToFile:GLOBAL_PREFS_PATH atomically:YES];
            }
            return containerPref;
        }

        // Nếu containerPref đang giữ cờ chờ Cold-Boot Wipe, tuyệt đối không lấy bản global cũ đè lên!
        if (!localNeedsWipe) {
            for (NSString *candidate in globalCandidates) {
                if ([fm fileExistsAtPath:candidate]) {
                    NSDictionary *candAttrs = [fm attributesOfItemAtPath:candidate error:nil];
                    NSDate *candDate = candAttrs[NSFileModificationDate];
                    if (!localDate || (candDate && [candDate compare:localDate] == NSOrderedDescending)) {
                        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:candidate];
                        uint64_t candWipeTS = [d[@"lastWipedTimestamp"] unsignedLongLongValue];
                        if (d && d.count > 0 && candWipeTS >= localWipeTS) {
                            [fm createDirectoryAtPath:[containerPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
                            [d writeToFile:containerPref atomically:YES];
                            chmod([containerPref UTF8String], 0666);
                            return containerPref;
                        }
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

static NSString *get_real_product_version(void) {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    if (dict && dict[@"ProductVersion"]) {
        return [dict[@"ProductVersion"] copy];
    }
    return @"15.8.3";
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
        [lower containsString:@"splashboard"] ||
        [lower containsString:@"saved application state"] ||
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
            [subLower containsString:@"splashboard"] ||
            [subLower containsString:@"saved application state"] ||
            [subLower isEqualToString:@"zaloaudit.log"] ||
            [subLower isEqualToString:@"zalotraffic.har"]) {
            continue;
        }
        NSString *fullSub = [targetPath stringByAppendingPathComponent:sub];
        purge_directory_recursively_safely(fullSub);
    }
    // Không xoá chính thư mục gốc Library, Documents, tmp hoặc Application Support
    NSString *lastComp = [targetPath lastPathComponent];
    if (![lastComp isEqualToString:@"Library"] &&
        ![lastComp isEqualToString:@"Documents"] &&
        ![lastComp isEqualToString:@"tmp"] &&
        ![lastComp isEqualToString:@"Application Support"]) {
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

static BOOL s_logged_c_bid = NO;
static BOOL s_logged_c_info_bid = NO;

static void reset_audit_log_on_wipe(NSString *machine, NSString *idfv) {
    s_logged_c_bid = NO;
    s_logged_c_info_bid = NO;
    zt_reset_runtime_counters();
    zt_reset_radar_cache();

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

    NSString *appType = is_original_zalo_app() ? @"Zalo Gốc (vn.com.vng.zingalo)" : @"Zalo Clone (Đã bẻ hướng C-layer & APNs Token)";

    NSString *header = [NSString stringWithFormat:
        @"================================================================================\n"
        @"🚀 [SYSTEM-INIT] === BẮT ĐẦU PHIÊN AUDIT MỚI SAU DEEP WIPE ===\n"
        @"🕒 Thời gian kích hoạt: %@\n"
        @"📱 Thiết bị: %@ | IDFV: %@\n"
        @"📦 Gói Ứng Dụng: %@\n"
        @"================================================================================\n\n",
        timeStr, machine ?: @"iPhone", idfv ?: @"N/A", appType];

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
        @"CVB6BX97VM.group.keychain.vn.com.vng.zalo",
        @"group.keychain.vn.com.vng.zalo",
        @"group.vn.com.vng.zingalo",
        @"group.noti.vn.com.vng.zingalo",
        @"group.zcontacts.vn.com.vng.zingalo",
        @"group.zfriends.vn.com.vng.zingalo",
        @"group.zsettings.vn.com.vng.zingalo",
        @"group.zgroups.vn.com.vng.zingalo",
        @"group.zsettings",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo",
        @"vn.com.vng.zingalo"
    ];

    for (id secClass in secClasses) {
        NSMutableDictionary *baseQuery = [NSMutableDictionary dictionary];
        baseQuery[(__bridge id)kSecClass] = secClass;
        SecItemDelete((__bridge CFDictionaryRef)baseQuery);

        for (NSString *grp in groups) {
            NSMutableDictionary *query = [NSMutableDictionary dictionary];
            query[(__bridge id)kSecClass] = secClass;
            if (grp.length > 0) {
                query[(__bridge id)kSecAttrAccessGroup] = grp;
            }
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
    }
    NSLog(@"[ZaloAudit] [COLD-BOOT] 🔑 Đã dọn dẹp sạch toàn bộ Keychain (bao gồm CVB6BX97VM.group.keychain.vn.com.vng.zalo) của Zalo!");
}

static void __attribute__((unused)) purge_webkit_data_safely(void) {
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

    // 2. Tuyệt đối KHÔNG gọi [UIPasteboard generalPasteboard] và purge_webkit_data_safely() tại %ctor!
    // Vì %ctor chạy trước hàm main() và UIApplicationMain(), việc gọi UIKit UI Server hoặc WebKit
    // Process Pool lúc này là nguyên nhân hàng đầu gây crash SIGABRT/SIGSEGV!
    // Việc xóa Clipboard và WebKit DataStore đã được thực hiện an toàn ngay lúc bấm Deep Wipe trong app.

    // 3. Xóa sạch dữ liệu in-memory của NSUserDefaults các App Suites
    NSArray *suitesToPurge = @[
        @"group.vn.com.vng.zingalo",
        @"group.noti.vn.com.vng.zingalo",
        @"group.zsettings",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo",
        @"com.zing.zalo.chatMigrateStore",
        @"vn.com.vng.zingalo.zalosdk",
        @"com.zing.zalo",
        @"vn.com.vng.zingalo"
    ];
    for (NSString *suite in suitesToPurge) {
        NSUserDefaults *ud = [[NSUserDefaults alloc] initWithSuiteName:suite];
        if (ud && ud != [NSUserDefaults standardUserDefaults]) {
            NSDictionary *d = [ud dictionaryRepresentation];
            for (NSString *k in d.allKeys) {
                if ([k.lowercaseString containsString:@"zalotweak"]) continue;
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
        if ([lower containsString:@"splashboard"] || [lower containsString:@"saved application state"]) continue;

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
    NSArray *groupNames = @[
        @"group.vn.com.vng.zingalo",
        @"group.noti.vn.com.vng.zingalo",
        @"group.zsettings",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo"
    ];
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
        self.centralizedDid = dict[@"centralizedDid"] ?: @"";
        self.currentAPNsToken = dict[@"currentAPNsToken"] ?: @"";
        self.lastWipedAPNsToken = dict[@"lastWipedAPNsToken"] ?: @"";
        self.lastKnownAPNsToken = dict[@"lastKnownAPNsToken"] ?: @"";
        self.apnsRotatedStatus = dict[@"apnsRotatedStatus"] ?: @"";

        self.deviceMachine = dict[@"deviceMachine"] ?: get_real_hardware_machine();
        self.deviceModel = dict[@"deviceModel"] ?: get_real_hardware_model();
        self.deviceName = dict[@"deviceName"] ?: @"iPhone";
        self.systemVersion = dict[@"systemVersion"] ?: get_real_product_version();
        self.kernOsVersion = dict[@"kernOsVersion"] ?: get_real_os_version();
        self.ncpu = [dict[@"ncpu"] unsignedIntValue] ?: (uint32_t)[[NSProcessInfo processInfo] activeProcessorCount];
        self.memsize = [dict[@"memsize"] unsignedLongLongValue] ?: [[NSProcessInfo processInfo] physicalMemory];
        CGFloat defW = 375.0, defH = 667.0, defS = 2.0;
        [ZTDeviceProfile getScreenDimensionsForMachine:self.deviceMachine width:&defW height:&defH scale:&defS];
        self.screenWidth = [dict[@"screenWidth"] doubleValue] ?: defW;
        self.screenHeight = [dict[@"screenHeight"] doubleValue] ?: defH;
        self.screenScale = [dict[@"screenScale"] doubleValue] ?: defS;
        self.bootTimeSec = [dict[@"bootTimeSec"] unsignedLongLongValue] ?: 0;
        self.birthTimeSec = [dict[@"birthTimeSec"] unsignedLongLongValue] ?: 0;
        self.autoSyncTimezoneWithIP = dict[@"autoSyncTimezoneWithIP"] != nil ? [dict[@"autoSyncTimezoneWithIP"] boolValue] : YES;
        self.enableFakeTimeZone = dict[@"enableFakeTimeZone"] != nil ? [dict[@"enableFakeTimeZone"] boolValue] : YES;
        self.bootSessionUUID = dict[@"bootSessionUUID"] ?: @"";
        self.spoofedIDFV = dict[@"spoofedIDFV"] ?: (self.hasConfiguredProfile ? [[NSUUID UUID] UUIDString] : @"");
        self.spoofedIDFA = dict[@"spoofedIDFA"] ?: @"00000000-0000-0000-0000-000000000000";
        self.profileId = dict[@"profileId"] ?: (self.hasConfiguredProfile ? [[NSUUID UUID] UUIDString] : @"");
        self.diskTotalSize = [dict[@"diskTotalSize"] unsignedLongLongValue] ?: get_real_disk_total_size();
        uint64_t defFree = (self.diskTotalSize > 0) ? (uint64_t)(self.diskTotalSize * 0.65) : 20000000000ULL;
        self.diskFreeSize = [dict[@"diskFreeSize"] unsignedLongLongValue] ?: defFree;
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
        if ([self.regionMode isEqualToString:@"US"] || [self.regionMode isEqualToString:@"US_STUDENT"]) {
            self.localeIdentifier = dict[@"localeIdentifier"] ?: @"en_US";
            self.timeZoneName = dict[@"timeZoneName"] ?: @"America/New_York";
            self.preferredLanguages = dict[@"preferredLanguages"] ?: @[@"en-US"];
        } else if ([self.regionMode isEqualToString:@"PL"]) {
            self.localeIdentifier = dict[@"localeIdentifier"] ?: @"pl_PL";
            self.timeZoneName = dict[@"timeZoneName"] ?: @"Europe/Warsaw";
            self.preferredLanguages = dict[@"preferredLanguages"] ?: @[@"pl-PL", @"en-PL"];
        } else {
            self.localeIdentifier = dict[@"localeIdentifier"] ?: @"vi_VN";
            self.timeZoneName = dict[@"timeZoneName"] ?: @"Asia/Ho_Chi_Minh";
            if ([self.timeZoneName isEqualToString:@"Asia/Bangkok"] || [self.timeZoneName isEqualToString:@"Asia/Saigon"]) {
                self.timeZoneName = @"Asia/Ho_Chi_Minh";
            }
            self.preferredLanguages = dict[@"preferredLanguages"] ?: @[@"vi-VN", @"en-VN"];
        }
        self.spoofedSerial = dict[@"spoofedSerial"] ?: @"";
        self.spoofedWifiMAC = dict[@"spoofedWifiMAC"] ?: @"";
        self.spoofedBluetoothMAC = dict[@"spoofedBluetoothMAC"] ?: @"";
        self.spoofedScreenSize = dict[@"spoofedScreenSize"] ?: @"";
        self.currentZCID = dict[@"currentZCID"] ?: @"";
        self.lastWipedZCID = dict[@"lastWipedZCID"] ?: @"";
        self.currentVoIPToken = dict[@"currentVoIPToken"] ?: @"";
        self.lastWipedVoIPToken = dict[@"lastWipedVoIPToken"] ?: @"";

        BOOL isAppExtension = [[NSBundle mainBundle].bundlePath containsString:@".appex"];
        if (isAppExtension) {
            self.showFloatingMenu = NO;
        } else if (dict[@"showFloatingMenu"] != nil) {
            self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
        } else {
            self.showFloatingMenu = YES; // Mặc định luôn hiện nút nổi để thuận tiện thao tác
        }

        self.needsNewProfile = [dict[@"needsNewProfile"] boolValue];
        self.needsSandboxPurge = [dict[@"needsSandboxPurge"] boolValue];
        if (self.needsNewProfile || self.needsSandboxPurge) {
            if (s_is_cold_boot_phase) {
                if (has_active_session_in_sandbox()) {
                    logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] 🛡️ Phát hiện tài khoản Zalo hợp lệ đang tồn tại trong Sandbox (vừa Restore từ Backup) -> HỦY BỎ LỆNH XÓA ĐỂ BẢO VỆ NICK!");
                    self.needsNewProfile = NO;
                    self.needsSandboxPurge = NO;
                    [self saveSettings];
                } else if (ZTSecurityCheckLicenseFast()) {
                    logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] 🧹 Phát hiện cờ yêu cầu máy mới / dọn sạch sau Deep Wipe -> Khởi động dọn sạch Sandbox...");
                    purge_entire_sandbox_safely();
                    BOOL willGenProfile = self.needsNewProfile;
                    self.needsNewProfile = NO;
                    self.needsSandboxPurge = NO;
                    self.justGeneratedColdBoot = YES;
                    if (dict[@"showFloatingMenu"] != nil) {
                        self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
                    } else {
                        self.showFloatingMenu = YES;
                    }
                    self.regionMode = dict[@"regionMode"] ?: (self.regionMode ?: @"VN");
                    self.preferredCarrier = dict[@"preferredCarrier"] ?: @"";
                    if (self.currentZCID.length > 0) {
                        self.lastWipedZCID = self.currentZCID;
                    }
                    if (self.currentVoIPToken.length > 0) {
                        self.lastWipedVoIPToken = self.currentVoIPToken;
                    }
                    self.currentZCID = @"";
                    self.currentVoIPToken = @"";
                    self.centralizedDid = @"";
                    if (willGenProfile) {
                        // Cấp ngay Profile mới tinh đồng bộ theo vòng đời máy và vùng địa lý (chỉ khi được yêu cầu)
                        [self generateNewProfile];
                    }
                    [self saveSettings];
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
        self.showFloatingMenu = YES;
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
        self.centralizedDid = @"";
        self.currentAPNsToken = @"";
        self.lastWipedAPNsToken = @"";
        self.lastKnownAPNsToken = @"";
        self.apnsRotatedStatus = @"";
        self.spoofedSerial = @"";
        self.spoofedWifiMAC = @"";
        self.spoofedBluetoothMAC = @"";
        self.spoofedIDFV = @"";
        self.profileId = @"";
        // Giữ 100% thông số máy thật:
        self.deviceMachine = get_real_hardware_machine();
        self.deviceModel = get_real_hardware_model();
        self.deviceName = @"iPhone";
        self.systemVersion = get_real_product_version();
        self.kernOsVersion = get_real_os_version();
        self.ncpu = (uint32_t)[[NSProcessInfo processInfo] activeProcessorCount];
        self.memsize = [[NSProcessInfo processInfo] physicalMemory];
        CGFloat defW = 375.0, defH = 667.0, defS = 2.0;
        [ZTDeviceProfile getScreenDimensionsForMachine:self.deviceMachine width:&defW height:&defH scale:&defS];
        self.screenWidth = defW;
        self.screenHeight = defH;
        self.screenScale = defS;
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
    NSString *path = getConfigPath();
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:path] ?: [NSMutableDictionary dictionary];
    dict[@"enabled"] = @(self.enabled);
    dict[@"enableAuditLog"] = @(self.enableAuditLog);
    dict[@"hasConfiguredProfile"] = @(self.hasConfiguredProfile);
    dict[@"proxyEnabled"] = @(self.proxyEnabled);
    dict[@"proxyType"] = self.proxyType ?: @"HTTP";
    dict[@"proxyHost"] = self.proxyHost ?: @"";
    dict[@"proxyPort"] = @(self.proxyPort);
    dict[@"proxyUser"] = self.proxyUser ?: @"";
    dict[@"proxyPass"] = self.proxyPass ?: @"";
    if (self.centralizedDid) dict[@"centralizedDid"] = self.centralizedDid;
    if (self.currentAPNsToken) dict[@"currentAPNsToken"] = self.currentAPNsToken;
    if (self.lastWipedAPNsToken) dict[@"lastWipedAPNsToken"] = self.lastWipedAPNsToken;
    if (self.lastKnownAPNsToken) dict[@"lastKnownAPNsToken"] = self.lastKnownAPNsToken;
    if (self.apnsRotatedStatus) dict[@"apnsRotatedStatus"] = self.apnsRotatedStatus;
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
    dict[@"enableFakeTimeZone"] = @(self.enableFakeTimeZone);
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
    if (self.spoofedScreenSize) dict[@"spoofedScreenSize"] = self.spoofedScreenSize;
    if (self.currentZCID) dict[@"currentZCID"] = self.currentZCID;
    if (self.lastWipedZCID) dict[@"lastWipedZCID"] = self.lastWipedZCID;
    if (self.currentVoIPToken) dict[@"currentVoIPToken"] = self.currentVoIPToken;
    if (self.lastWipedVoIPToken) dict[@"lastWipedVoIPToken"] = self.lastWipedVoIPToken;
    if (self.lastWipedIDFV) dict[@"lastWipedIDFV"] = self.lastWipedIDFV;
    if (self.lastWipedIP) dict[@"lastWipedIP"] = self.lastWipedIP;
    dict[@"lastWipedTimestamp"] = @(self.lastWipedTimestamp);

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
    if (!ZTSecurityCheckLicenseFast()) {
        logAudit(@"SECURITY", @"[AUTH] ❌ Từ chối cấp Profile: Chưa kích hoạt bản quyền hợp lệ hoặc phát hiện can thiệp nhị phân!");
        return;
    }
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
    if (p.actualCarrier.length > 0) {
        self.preferredCarrier = p.actualCarrier;
    }
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
    self.spoofedScreenSize = p.spoofedScreenSize ?: [NSString stringWithFormat:@"%.0fx%.0f", self.screenWidth * self.screenScale, self.screenHeight * self.screenScale];

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

static __attribute__((unused)) NSString *getAuditLogPath(void) {
    return @"/var/mobile/Documents/ZaloAudit.log";
}

static void append_data_to_file_safely(NSString *path, NSData *data) {
    if (!path || !data || data.length == 0) return;
    @try {
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!handle) {
            NSString *parentDir = [path stringByDeletingLastPathComponent];
            [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
            [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
            chmod([path UTF8String], 0666);
            handle = [NSFileHandle fileHandleForWritingAtPath:path];
        }
        if (handle) {
            [handle seekToEndOfFile];
            [handle writeData:data];
            [handle closeFile];
        }
    } @catch (NSException *e) {}
}

static NSMutableSet *loggedAuditKeys = nil;
static dispatch_queue_t auditQueue = nil;
static dispatch_queue_t harQueue = nil;

static void flush_audit_and_har_queues_sync(void) {
    if (auditQueue) {
        dispatch_sync(auditQueue, ^{});
    }
    if (harQueue) {
        dispatch_sync(harQueue, ^{});
    }
}

__attribute__((visibility("default"))) void zt_flush_audit_and_har_queues_sync(void) {
    flush_audit_and_har_queues_sync();
}

static void handle_app_termination_event(const char *reason) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *msg = [NSString stringWithFormat:@"⚠️ [LIFECYCLE-GUARD] Tiến trình đang đóng / thoát (%s) -> Đang xả toàn bộ dữ liệu log & HAR xuống ổ đĩa an toàn ✅", reason];
        logAudit(@"APP-LIFECYCLE", msg);
        flush_audit_and_har_queues_sync();
    });
}

static void zt_sig_handler(int sig) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Signal %d", sig);
    handle_app_termination_event(buf);
    signal(sig, SIG_DFL);
    raise(sig);
}

static void zt_atexit_handler(void) {
    handle_app_termination_event("atexit");
}

static UIBackgroundTaskIdentifier s_bg_task_id;
static void renew_background_task_assertion(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        static dispatch_once_t s_bg_once;
        dispatch_once(&s_bg_once, ^{
            s_bg_task_id = UIBackgroundTaskInvalid;
        });
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        if (s_bg_task_id != UIBackgroundTaskInvalid) {
            [app endBackgroundTask:s_bg_task_id];
            s_bg_task_id = UIBackgroundTaskInvalid;
        }
        s_bg_task_id = [app beginBackgroundTaskWithName:@"ZTBackgroundKeepAlive" expirationHandler:^{
            logAudit(@"BACKGROUND-GUARD", @"⏱️ Hết hạn Background Task -> Tự động gia hạn giữ tiến trình sống...");
            renew_background_task_assertion();
        }];
    });
}

static NSString *mask_sensitive_data(NSString *input) {
    if (!input || input.length == 0) return input;
    NSMutableString *str = [input mutableCopy];

    static NSRegularExpression *jwtRegex = nil;
    static NSRegularExpression *paramRegex = nil;
    static dispatch_once_t s_regexToken;
    dispatch_once(&s_regexToken, ^{
        jwtRegex = [NSRegularExpression regularExpressionWithPattern:@"\"(token|authToken|refreshToken|privateKey|sdkId|zaId)\"\\s*:\\s*\"([^\"]+)\"" options:0 error:nil];
        paramRegex = [NSRegularExpression regularExpressionWithPattern:@"(api_key|sig|sdkId|X-Goog-Api-Key)[=:\\s]+([a-zA-Z0-9_-]{12,})" options:0 error:nil];
    });

    // Mask JSON tokens & keys
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

    // Mask query & header params
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
        NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];

        // 1. Luôn ghi vào /var/mobile/Documents/ZaloAudit.log (vị trí toàn cục dễ kéo từ 3uTools/Filza)
        append_data_to_file_safely(@"/var/mobile/Documents/ZaloAudit.log", lineData);

        // 2. Ghi song song vào Documents của Sandbox hiện tại (đảm bảo không bao giờ mất log dù Sandbox chặn)
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *containerDoc = [home stringByAppendingPathComponent:@"Documents/ZaloAudit.log"];
            if (![containerDoc isEqualToString:@"/var/mobile/Documents/ZaloAudit.log"]) {
                append_data_to_file_safely(containerDoc, lineData);
            }
        }
    });
}

// ==========================================
// 1. TẦNG C API: sysctl, sysctlbyname & uname HOOKING
// ==========================================

static NSString *get_darwin_kernel_release(NSString *sysVer) {
    if (!sysVer || sysVer.length == 0) return @"21.6.0";
    NSArray<NSString *> *components = [sysVer componentsSeparatedByString:@"."];
    if (components.count == 0) return @"21.6.0";
    NSInteger major = [components[0] integerValue];
    NSInteger minor = components.count > 1 ? [components[1] integerValue] : 0;
    NSInteger darwinMajor = major + 6;
    NSInteger darwinMinor = minor;
    return [NSString stringWithFormat:@"%ld.%ld.0", (long)darwinMajor, (long)darwinMinor];
}

static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    static __thread BOOL s_in_sysctl = NO;
    if (s_in_sysctl || !name || namelen < 2 || !is_tweak_active()) {
        return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    s_in_sysctl = YES;

    ZTSettings *settings = [ZTSettings sharedSettings];

    if (name[0] == CTL_HW) {
        if (name[1] == HW_MACHINE) {
            const char *val = settings.deviceMachine.length > 0 ? [settings.deviceMachine UTF8String] : "iPhone9,3";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
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
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_NCPU || name[1] == HW_AVAILCPU) {
            uint32_t cpu = settings.ncpu;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &cpu, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_MEMSIZE) {
            uint64_t ram = settings.memsize;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
                memcpy(oldp, &ram, sizeof(uint64_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint64_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_PHYSMEM) {
            uint32_t ram32 = (uint32_t)(settings.memsize > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : settings.memsize);
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &ram32, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_PAGESIZE) {
            uint32_t pagesize = 16384;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &pagesize, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            s_in_sysctl = NO;
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
            s_in_sysctl = NO;
            return 0;
        }
#endif
    } else if (name[0] == CTL_KERN) {
        if (name[1] == KERN_BOOTTIME && settings.bootTimeSec > 0) {
            struct timeval bt;
            bt.tv_sec = (time_t)settings.bootTimeSec;
            bt.tv_usec = (suseconds_t)((settings.bootTimeSec * 2654435761ULL) % 1000000ULL);
            if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                memcpy(oldp, &bt, sizeof(struct timeval));
            }
            if (oldlenp) *oldlenp = sizeof(struct timeval);
            s_in_sysctl = NO;
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
            s_in_sysctl = NO;
            return 0;
        }
#ifdef KERN_OSRELEASE
        if (name[1] == KERN_OSRELEASE) {
            NSString *releaseStr = get_darwin_kernel_release(settings.systemVersion);
            const char *val = [releaseStr UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
#endif
        if (name[1] == KERN_HOSTNAME && settings.deviceName.length > 0) {
            const char *val = [settings.deviceName UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
        if (namelen >= 3 && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
            int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
            if (ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
                kp->kp_proc.p_flag &= ~P_TRACED;
            }
            s_in_sysctl = NO;
            return ret;
        }
    }

    s_in_sysctl = NO;
    return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    static __thread BOOL s_in_sysctlbyname = NO;
    if (s_in_sysctlbyname || !name || !is_tweak_active()) {
        return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }
    s_in_sysctlbyname = YES;

    ZTSettings *settings = [ZTSettings sharedSettings];

    if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.product") == 0) {
        const char *val = settings.deviceMachine.length > 0 ? [settings.deviceMachine UTF8String] : "iPhone9,3";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.model") == 0) {
        const char *val = settings.deviceModel.length > 0 ? [settings.deviceModel UTF8String] : "D10AP";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.osproductversion") == 0) {
        const char *val = settings.systemVersion.length > 0 ? [settings.systemVersion UTF8String] : "15.7.2";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.osversion") == 0) {
        const char *val = settings.kernOsVersion.length > 0 ? [settings.kernOsVersion UTF8String] : "19H218";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.osrelease") == 0) {
        NSString *releaseStr = get_darwin_kernel_release(settings.systemVersion);
        const char *val = [releaseStr UTF8String];
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.ncpu") == 0 ||
        strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.activecpu") == 0 ||
        strcmp(name, "hw.logicalcpu_max") == 0 ||
        strcmp(name, "hw.physicalcpu_max") == 0) {
        uint32_t cpu = settings.ncpu;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &cpu, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.memsize") == 0) {
        uint64_t ram = settings.memsize;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
            memcpy(oldp, &ram, sizeof(uint64_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint64_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.physmem") == 0) {
        uint32_t ram32 = (uint32_t)(settings.memsize > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : settings.memsize);
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &ram32, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.pagesize") == 0) {
        uint32_t pagesize = 16384;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &pagesize, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.l2cachesize") == 0) {
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
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "sysctl.proc_translated") == 0) {
        int translated = 0;
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            memcpy(oldp, &translated, sizeof(int));
        }
        if (oldlenp) *oldlenp = sizeof(int);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.boottime") == 0 && settings.bootTimeSec > 0) {
        struct timeval bt;
        bt.tv_sec = (time_t)settings.bootTimeSec;
        bt.tv_usec = (suseconds_t)((settings.bootTimeSec * 2654435761ULL) % 1000000ULL);
        if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
            memcpy(oldp, &bt, sizeof(struct timeval));
        }
        if (oldlenp) *oldlenp = sizeof(struct timeval);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.bootsessionuuid") == 0 && settings.bootSessionUUID.length > 0) {
        const char *val = settings.bootSessionUUID.length > 0 ? [settings.bootSessionUUID UTF8String] : "00000000-0000-0000-0000-000000000000";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.hostname") == 0 && settings.deviceName.length > 0) {
        const char *val = settings.deviceName.length > 0 ? [settings.deviceName UTF8String] : "iPhone";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
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
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &supported, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    s_in_sysctlbyname = NO;
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int (*orig_uname)(struct utsname *buf);
static int my_uname(struct utsname *buf) {
    static __thread BOOL s_in_uname = NO;
    if (s_in_uname) return orig_uname ? orig_uname(buf) : uname(buf);
    s_in_uname = YES;
    int ret = orig_uname ? orig_uname(buf) : uname(buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        if (settings.deviceMachine.length > 0) {
            strlcpy(buf->machine, [settings.deviceMachine UTF8String], sizeof(buf->machine));
        }
        NSString *releaseStr = get_darwin_kernel_release(settings.systemVersion);
        if (releaseStr.length > 0) {
            strlcpy(buf->release, [releaseStr UTF8String], sizeof(buf->release));
        }
    }
    s_in_uname = NO;
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
    NSString *sysVer = [ZTSettings sharedSettings].systemVersion;
    if (sysVer.length > 0) {
        NSInteger major = [[sysVer componentsSeparatedByString:@"."].firstObject integerValue];
        if (major >= 16) {
            return @"iPhone";
        }
    }
    return [ZTSettings sharedSettings].deviceName ?: @"iPhone";
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

static uint64_t s_battery_ref_time = 0;
static float s_battery_ref_level = 0.0f;
static dispatch_source_t s_battery_timer = NULL;

static float compute_live_battery_level(void) {
    ZTSettings *s = [ZTSettings sharedSettings];
    float base = s.batteryLevel;
    if (base <= 0.05f || base > 1.0f) {
        base = 0.85f;
        s.batteryLevel = base;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t nowSec = (uint64_t)tv.tv_sec;

    if (s_battery_ref_time == 0 || s_battery_ref_level <= 0.0f || fabsf(s_battery_ref_level - base) > 0.05f) {
        s_battery_ref_time = nowSec;
        s_battery_ref_level = base;
    }

    uint64_t elapsed = (nowSec >= s_battery_ref_time) ? (nowSec - s_battery_ref_time) : 0;
    // Tốc độ tiêu hao thực tế khi app Zalo đang chạy: ~6.5% mỗi giờ (tương đương 1% mỗi ~9.2 phút)
    float drain = (float)elapsed * (0.065f / 3600.0f);
    float current = s_battery_ref_level - drain;
    if (current < 0.15f) current = 0.15f; // Chặn đáy 15%, không xả sập nguồn
    if (current > 1.0f) current = 1.0f;
    current = roundf(current * 100.0f) / 100.0f;

    return current;
}

static void check_and_update_battery_drain(void) {
    if (!is_tweak_active()) return;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.batteryState != 1) return; // Chỉ xả khi không cắm sạc (UIDeviceBatteryStateUnplugged = 1)

    float current = compute_live_battery_level();
    if (current < s.batteryLevel) {
        float oldLevel = s.batteryLevel;
        s.batteryLevel = current;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        s_battery_ref_time = (uint64_t)tv.tv_sec;
        s_battery_ref_level = current;
        [s saveSettings];

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:UIDeviceBatteryLevelDidChangeNotification
                                                                object:[UIDevice currentDevice]];
        });

        logAudit(@"BATTERY-DRAIN", [NSString stringWithFormat:@"🔋 [PIN TỰ NHIÊN] Tụt: %.0f%% -> %.0f%% (Xả ~6.5%%/h) | Đã phát UIDeviceBatteryLevelDidChangeNotification", oldLevel * 100.0f, current * 100.0f]);
    }
}

static void start_battery_drain_timer_if_needed(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        s_battery_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        if (s_battery_timer) {
            // Kiểm tra đều đặn mỗi 30 giây
            dispatch_source_set_timer(s_battery_timer,
                                      dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC),
                                      30 * NSEC_PER_SEC,
                                      5 * NSEC_PER_SEC);
            dispatch_source_set_event_handler(s_battery_timer, ^{
                check_and_update_battery_drain();
            });
            dispatch_resume(s_battery_timer);
        }
    });
}

- (float)batteryLevel {
    if (!is_tweak_active()) return %orig;
    start_battery_drain_timer_if_needed();
    check_and_update_battery_drain();
    float current = compute_live_battery_level();

    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
        logAudit(@"RADAR-SENSOR", [NSString stringWithFormat:@"🔋 Zalo đọc UIDevice.batteryLevel (%.2f) từ %@", current, format_caller_info(c0)]);
    }
    return current;
}

- (UIDeviceBatteryState)batteryState {
    if (!is_tweak_active()) return %orig;
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
        logAudit(@"RADAR-SENSOR", [NSString stringWithFormat:@"🔋 Zalo đọc UIDevice.batteryState (%ld) từ %@", (long)[ZTSettings sharedSettings].batteryState, format_caller_info(c0)]);
    }
    return (UIDeviceBatteryState)[ZTSettings sharedSettings].batteryState;
}

- (BOOL)isBatteryMonitoringEnabled {
    return YES;
}

- (void)setBatteryMonitoringEnabled:(BOOL)enabled {
    %orig(YES);
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
    NSString *iso = [ZTSettings sharedSettings].carrierCountryCode;
    return (iso.length > 0) ? iso : nil;
}

- (BOOL)allowsVOIP {
    return YES;
}

%end

@interface ZTFakeCarrier : NSObject
@property (nonatomic, copy) NSString *carrierName;
@property (nonatomic, copy) NSString *mobileCountryCode;
@property (nonatomic, copy) NSString *mobileNetworkCode;
@property (nonatomic, copy) NSString *isoCountryCode;
@property (nonatomic, assign) BOOL allowsVOIP;
@end

@implementation ZTFakeCarrier
@dynamic carrierName, mobileCountryCode, mobileNetworkCode, isoCountryCode, allowsVOIP;

- (NSString *)carrierName {
    return [ZTSettings sharedSettings].carrierName ?: @"Viettel";
}
- (NSString *)mobileCountryCode {
    return [ZTSettings sharedSettings].carrierMCC ?: @"452";
}
- (NSString *)mobileNetworkCode {
    return [ZTSettings sharedSettings].carrierMNC ?: @"04";
}
- (NSString *)isoCountryCode {
    NSString *iso = [ZTSettings sharedSettings].carrierCountryCode;
    return (iso.length > 0) ? iso : nil;
}
- (BOOL)allowsVOIP {
    return YES;
}
- (BOOL)isKindOfClass:(Class)aClass {
    if (aClass == NSClassFromString(@"CTCarrier")) return YES;
    return [super isKindOfClass:aClass];
}
- (BOOL)respondsToSelector:(SEL)aSelector {
    if (aSelector == @selector(carrierName) ||
        aSelector == @selector(mobileCountryCode) ||
        aSelector == @selector(mobileNetworkCode) ||
        aSelector == @selector(isoCountryCode) ||
        aSelector == @selector(allowsVOIP)) {
        return YES;
    }
    return [super respondsToSelector:aSelector];
}
@end

static CTCarrier *get_fake_carrier(void) {
    static CTCarrier *s_fake = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class ctCls = NSClassFromString(@"CTCarrier");
        if (ctCls) {
            @try {
                s_fake = (CTCarrier *)class_createInstance(ctCls, 0);
            } @catch (NSException *e) {}
        }
        if (!s_fake) {
            s_fake = (CTCarrier *)[[ZTFakeCarrier alloc] init];
        }
    });
    return s_fake;
}

%hook CTTelephonyNetworkInfo

- (NSString *)dataServiceIdentifier {
    if (!is_tweak_active()) return %orig;
    return @"0000000100000001";
}

- (CTCarrier *)subscriberCellularProvider {
    if (!is_tweak_active()) return %orig;
    CTCarrier *c = get_fake_carrier();
    return c ?: %orig;
}

- (NSDictionary *)serviceSubscriberCellularProviders {
    if (!is_tweak_active()) return %orig;
    CTCarrier *c = get_fake_carrier();
    if (c) {
        NSDictionary *origDict = %orig;
        if (origDict && origDict.count > 0) {
            NSMutableDictionary *mut = [NSMutableDictionary dictionaryWithCapacity:origDict.count + 1];
            for (id key in origDict.allKeys) {
                mut[key] = c;
            }
            mut[@"0000000100000001"] = c;
            return mut;
        }
        return @{@"0000000100000001": c};
    }
    return %orig;
}

- (NSDictionary *)serviceCurrentRadioAccessTechnology {
    if (!is_tweak_active()) return %orig;
    NSDictionary *origDict = %orig;
    if (origDict && origDict.count > 0) {
        NSMutableDictionary *mut = [NSMutableDictionary dictionaryWithCapacity:origDict.count + 1];
        for (id key in origDict.allKeys) {
            mut[key] = @"CTRadioAccessTechnologyLTE";
        }
        mut[@"0000000100000001"] = @"CTRadioAccessTechnologyLTE";
        return mut;
    }
    return @{@"0000000100000001": @"CTRadioAccessTechnologyLTE"};
}

- (NSString *)currentRadioAccessTechnology {
    if (!is_tweak_active()) return %orig;
    return @"CTRadioAccessTechnologyLTE";
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
    if ([ZTSettings sharedSettings].enableFakeTimeZone) {
        s_cachedTimeZone = [NSTimeZone timeZoneWithName:tzName];
    } else {
        s_cachedTimeZone = nil;
    }
    s_in_tz_hook = NO;
    s_in_locale_hook = NO;
}

%hook NSLocale

+ (NSLocale *)currentLocale {
    if (!is_tweak_active() || s_in_locale_hook) return %orig;
    s_in_locale_hook = YES;
    if (!s_cachedLocale) {
        update_cached_locale_and_tz();
    }
    NSLocale *res = s_cachedLocale ?: %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc NSLocale currentLocale -> [TRẢ VỀ %@]", [ZTSettings sharedSettings].localeIdentifier ?: @"vi_VN"]);
    }
    s_in_locale_hook = NO;
    return res;
}

+ (NSLocale *)autoupdatingCurrentLocale {
    if (!is_tweak_active() || s_in_locale_hook) return %orig;
    s_in_locale_hook = YES;
    if (!s_cachedLocale) {
        update_cached_locale_and_tz();
    }
    NSLocale *res = s_cachedLocale ?: %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc NSLocale autoupdatingCurrentLocale -> [TRẢ VỀ %@]", [ZTSettings sharedSettings].localeIdentifier ?: @"vi_VN"]);
    }
    s_in_locale_hook = NO;
    return res;
}

+ (NSArray<NSString *> *)preferredLanguages {
    if (!is_tweak_active() || s_in_locale_hook) return %orig;
    s_in_locale_hook = YES;
    NSArray *langs = [ZTSettings sharedSettings].preferredLanguages;
    NSArray *res = (langs && langs.count > 0) ? langs : @[@"vi-VN", @"en-VN"];
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc preferredLanguages -> [TRẢ VỀ %@]", [res componentsJoinedByString:@", "]]);
    }
    s_in_locale_hook = NO;
    return res;
}

%end

%hook NSTimeZone

+ (NSTimeZone *)systemTimeZone {
    if (!is_tweak_active() || s_in_tz_hook) return %orig;
    s_in_tz_hook = YES;
    NSTimeZone *result = nil;
    if (![ZTSettings sharedSettings].enableFakeTimeZone) {
        result = %orig;
        if ([ZTSettings sharedSettings].enableAuditLog) {
            logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc systemTimeZone -> [TRẢ VỀ GIỜ THẬT MÁY: %@] (Đang Tắt Fake Múi Giờ)", result ? result.name : @"(null)"]);
        }
    } else {
        if (!s_cachedTimeZone) {
            update_cached_locale_and_tz();
        }
        result = s_cachedTimeZone ?: %orig;
        if ([ZTSettings sharedSettings].enableAuditLog) {
            NSInteger gmtSec = result ? [result secondsFromGMT] : 25200;
            int hours = (int)(gmtSec / 3600);
            int mins = abs((int)((gmtSec % 3600) / 60));
            NSString *gmtStr = mins > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", hours, mins] : [NSString stringWithFormat:@"GMT%+d", hours];
            logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc systemTimeZone -> [TRẢ VỀ %@ (%@)]", [ZTSettings sharedSettings].timeZoneName ?: @"Asia/Ho_Chi_Minh", gmtStr]);
        }
    }
    s_in_tz_hook = NO;
    return result;
}

+ (NSTimeZone *)localTimeZone {
    if (!is_tweak_active() || s_in_tz_hook) return %orig;
    s_in_tz_hook = YES;
    NSTimeZone *result = nil;
    if (![ZTSettings sharedSettings].enableFakeTimeZone) {
        result = %orig;
        if ([ZTSettings sharedSettings].enableAuditLog) {
            logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc localTimeZone -> [TRẢ VỀ GIỜ THẬT MÁY: %@] (Đang Tắt Fake Múi Giờ)", result ? result.name : @"(null)"]);
        }
    } else {
        if (!s_cachedTimeZone) {
            update_cached_locale_and_tz();
        }
        result = s_cachedTimeZone ?: %orig;
        if ([ZTSettings sharedSettings].enableAuditLog) {
            NSInteger gmtSec = result ? [result secondsFromGMT] : 25200;
            int hours = (int)(gmtSec / 3600);
            int mins = abs((int)((gmtSec % 3600) / 60));
            NSString *gmtStr = mins > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", hours, mins] : [NSString stringWithFormat:@"GMT%+d", hours];
            logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc localTimeZone -> [TRẢ VỀ %@ (%@)]", [ZTSettings sharedSettings].timeZoneName ?: @"Asia/Ho_Chi_Minh", gmtStr]);
        }
    }
    s_in_tz_hook = NO;
    return result;
}

+ (NSTimeZone *)defaultTimeZone {
    if (!is_tweak_active() || s_in_tz_hook) return %orig;
    s_in_tz_hook = YES;
    NSTimeZone *result = nil;
    if (![ZTSettings sharedSettings].enableFakeTimeZone) {
        result = %orig;
        if ([ZTSettings sharedSettings].enableAuditLog) {
            logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc defaultTimeZone -> [TRẢ VỀ GIỜ THẬT MÁY: %@] (Đang Tắt Fake Múi Giờ)", result ? result.name : @"(null)"]);
        }
    } else {
        if (!s_cachedTimeZone) {
            update_cached_locale_and_tz();
        }
        result = s_cachedTimeZone ?: %orig;
        if ([ZTSettings sharedSettings].enableAuditLog) {
            NSInteger gmtSec = result ? [result secondsFromGMT] : 25200;
            int hours = (int)(gmtSec / 3600);
            int mins = abs((int)((gmtSec % 3600) / 60));
            NSString *gmtStr = mins > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", hours, mins] : [NSString stringWithFormat:@"GMT%+d", hours];
            logAudit(@"TIMEZONE-CHECK", [NSString stringWithFormat:@"Zalo đọc defaultTimeZone -> [TRẢ VỀ %@ (%@)]", [ZTSettings sharedSettings].timeZoneName ?: @"Asia/Ho_Chi_Minh", gmtStr]);
        }
    }
    s_in_tz_hook = NO;
    return result;
}

%end

// ==========================================
// ĐỒNG BỘ BÀN PHÍM / INPUT MODES: UITextInputMode
// ==========================================

%hook UITextInputMode

- (NSString *)primaryLanguage {
    if (!is_tweak_active()) return %orig;
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0)) {
        NSArray *langs = [ZTSettings sharedSettings].preferredLanguages;
        if (!langs || langs.count == 0) {
            langs = @[@"vi-VN", @"en-US"];
        }
        NSArray *modes = [UITextInputMode activeInputModes];
        NSUInteger idx = [modes indexOfObject:self];
        if (idx != NSNotFound && idx < langs.count) {
            return langs[idx];
        }
        return langs.firstObject;
    }
    return %orig;
}

+ (NSArray *)activeInputModes {
    NSArray *orig = %orig;
    if (!is_tweak_active()) return orig;
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0) && [ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"RADAR-KEYBOARD", [NSString stringWithFormat:@"Zalo đọc UITextInputMode activeInputModes (count=%lu)", (unsigned long)(orig ? orig.count : 0)]);
    }
    return orig;
}

%end

// Bảo toàn 100% thuộc tính hiển thị vật lý của UIScreen (bounds, nativeBounds, scale) để UIKit & Metal
// render chuẩn xác, không bị lỗi buffer mismatch. Thông số màn hình fake được cung cấp qua MGCopyAnswer & Headers.

static __attribute__((unused)) uint64_t seconds_to_mach_ticks(double seconds) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    if (tb.numer == 0 || tb.denom == 0) {
        tb.numer = 1;
        tb.denom = 1;
    }
    double nanos = seconds * 1000000000.0;
    return (uint64_t)((nanos * (double)tb.denom) / (double)tb.numer);
}

static inline double mach_ticks_to_signed_seconds(int64_t ticks) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    if (tb.numer == 0 || tb.denom == 0) {
        tb.numer = 1;
        tb.denom = 1;
    }
    return ((double)ticks * (double)tb.numer) / ((double)tb.denom * 1000000000.0);
}

static __attribute__((unused)) inline double mach_ticks_to_seconds(uint64_t ticks) {
    return mach_ticks_to_signed_seconds((int64_t)ticks);
}

// Đồng bộ Uptime với kern.boottime tự nhiên (now - boottime >= systemUptime, chênh lệch là thời gian máy ngủ)
static void get_consistent_uptimes(double *outContUptime, double *outAwakeUptime) {
    uint64_t bootSec = [ZTSettings sharedSettings].bootTimeSec;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double now = (double)tv.tv_sec + ((double)tv.tv_usec / 1000000.0);

    double contSec = 0.0;
    if (bootSec > 0 && now > (double)bootSec) {
        contSec = now - (double)bootSec;
    } else {
        contSec = 43200.0; // 12h mặc định
    }

    // Thời gian ngủ tự nhiên của máy phân bổ đa dạng theo thói quen người dùng (từ 25% đến 68% tổng thời gian máy bật)
    double sleepRatio = 0.25 + (double)((bootSec * 2654435761ULL) % 430ULL) / 1000.0;
    double awakeSec = contSec * (1.0 - sleepRatio);
    if (awakeSec < 60.0) awakeSec = 60.0;

    if (outContUptime) *outContUptime = contSec;
    if (outAwakeUptime) *outAwakeUptime = awakeSec;
}

static int (*orig_clock_gettime)(clockid_t clk_id, struct timespec *tp);
static int my_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    return orig_clock_gettime ? orig_clock_gettime(clk_id, tp) : clock_gettime(clk_id, tp);
}

static uint64_t (*orig_mach_continuous_time)(void);
static uint64_t my_mach_continuous_time(void) {
    return orig_mach_continuous_time ? orig_mach_continuous_time() : mach_continuous_time();
}

static uint64_t (*orig_mach_absolute_time)(void);
static uint64_t my_mach_absolute_time(void) {
    return orig_mach_absolute_time ? orig_mach_absolute_time() : mach_absolute_time();
}


#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH && is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        logAudit(@"RADAR-SECURITY", [NSString stringWithFormat:@"🛡️ Zalo gọi ptrace(PT_DENY_ATTACH) từ %@ -> [ĐÃ CHẶN AN TOÀN]", format_caller_info(c0)]);
        return 0;
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}

static pid_t (*orig_getppid)(void);
static pid_t my_getppid(void) {
    pid_t ret = orig_getppid ? orig_getppid() : getppid();
    if (is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
            logAudit(@"RADAR-SECURITY", [NSString stringWithFormat:@"🛡️ Zalo kiểm tra PID tiến trình cha (getppid=%d) từ %@ -> [CHUẨN HOÁ 1 (launchd)]", (int)ret, format_caller_info(c0)]);
            return 1;
        }
    }
    return ret;
}

static int (*orig_gethostname)(char *name, size_t len);
static int my_gethostname(char *name, size_t len) {
    int ret = orig_gethostname ? orig_gethostname(name, len) : gethostname(name, len);
    if (ret == 0 && name && is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
            logAudit(@"RADAR-SYS", [NSString stringWithFormat:@"🏷️ Zalo đọc gethostname ('%s') từ %@", name, format_caller_info(c0)]);
        }
    }
    return ret;
}

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

- (NSTimeInterval)systemUptime {
    if (!is_tweak_active()) {
        return %orig;
    }
    double awakeUp = 0;
    get_consistent_uptimes(NULL, &awakeUp);
    return awakeUp;
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
        "/var/jb",
        "/var/lib/apt",
        "/var/lib/dpkg",
        "/var/log/dpkg",
        "/Library/MobileSubstrate",
        "/private/preboot",
        "MobileSubstrate.dylib",
        "cydia_substitute",
        "libsubstitute",
        "substitute",
        "ellekit",
        "libhooker",
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

static int (*orig_access)(const char *path, int mode);
static int my_access(const char *path, int mode) {
    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi access('%s') -> [ĐÃ ẨN - TRẢ VỀ ENOENT]", path]);
        }
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : access(path, mode);
}

static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsiz);
static ssize_t my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi readlink('%s') -> [ĐÃ ẨN - TRẢ VỀ ENOENT]", path]);
        }
        errno = ENOENT;
        return -1;
    }
    return orig_readlink ? orig_readlink(path, buf, bufsiz) : readlink(path, buf, bufsiz);
}

static ssize_t (*orig_readlinkat)(int fd, const char *path, char *buf, size_t bufsiz);
static ssize_t my_readlinkat(int fd, const char *path, char *buf, size_t bufsiz) {
    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi readlinkat('%s') -> [ĐÃ ẨN - TRẢ VỀ ENOENT]", path]);
        }
        errno = ENOENT;
        return -1;
    }
    return orig_readlinkat ? orig_readlinkat(fd, path, buf, bufsiz) : readlinkat(fd, path, buf, bufsiz);
}

static pid_t (*orig_fork)(void);
static pid_t my_fork(void) {
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0)) {
        logAudit(@"RADAR-SECURITY", @"🛡️ Zalo gọi fork() -> [GIẢ LẬP LỖI SANDBOX ENOSYS (-1)]");
    }
    errno = ENOSYS;
    return -1;
}



// Chuyển hướng CFPreferences App Groups sang container an toàn của clone (Zalo gốc giữ nguyên chuẩn hệ thống)
static inline BOOL is_zalo_group_or_bundle_cfprefs_id(NSString *appID) {
    if (!appID) return NO;
    return ([appID containsString:@"group.vn.com.vng.zingalo"] ||
            [appID containsString:@"group.noti.vn.com.vng.zingalo"] ||
            [appID containsString:@"group.zsettings"] ||
            [appID containsString:@"group.com.vng.zalo"] ||
            [appID containsString:@"group.com.zing.zalo"] ||
            [appID isEqualToString:@"vn.com.vng.zingalo"]);
}

static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef key, CFStringRef applicationID);
static CFPropertyListRef my_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef applicationID) {
    if (!is_original_zalo_app() && applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
        NSString *appID = (__bridge NSString *)applicationID;
        if (is_zalo_group_or_bundle_cfprefs_id(appID)) {
            return orig_CFPreferencesCopyAppValue ? orig_CFPreferencesCopyAppValue(key, kCFPreferencesCurrentApplication) : NULL;
        }
    }
    return orig_CFPreferencesCopyAppValue ? orig_CFPreferencesCopyAppValue(key, applicationID) : NULL;
}

static void (*orig_CFPreferencesSetAppValue)(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID);
static void my_CFPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID) {
    if (!is_original_zalo_app() && applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
        NSString *appID = (__bridge NSString *)applicationID;
        if (is_zalo_group_or_bundle_cfprefs_id(appID)) {
            if (orig_CFPreferencesSetAppValue) orig_CFPreferencesSetAppValue(key, value, kCFPreferencesCurrentApplication);
            return;
        }
    }
    if (orig_CFPreferencesSetAppValue) orig_CFPreferencesSetAppValue(key, value, applicationID);
}

static Boolean (*orig_CFPreferencesAppSynchronize)(CFStringRef applicationID);
static Boolean my_CFPreferencesAppSynchronize(CFStringRef applicationID) {
    if (!is_original_zalo_app() && applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
        NSString *appID = (__bridge NSString *)applicationID;
        if (is_zalo_group_or_bundle_cfprefs_id(appID)) {
            return orig_CFPreferencesAppSynchronize ? orig_CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication) : true;
        }
    }
    return orig_CFPreferencesAppSynchronize ? orig_CFPreferencesAppSynchronize(applicationID) : true;
}

// Bẻ hướng hàm C CoreFoundation CFBundleGetIdentifier & CFBundleGetValueForInfoDictionaryKey cho Zalo Clone
static CFStringRef (*orig_CFBundleGetIdentifier)(CFBundleRef bundle) = NULL;
static __thread BOOL s_in_c_bundle_hook = NO;
static CFStringRef my_CFBundleGetIdentifier(CFBundleRef bundle) {
    if (s_in_c_bundle_hook) {
        return orig_CFBundleGetIdentifier ? orig_CFBundleGetIdentifier(bundle) : (bundle ? CFBundleGetIdentifier(bundle) : NULL);
    }
    s_in_c_bundle_hook = YES;
    if (is_tweak_active() && !is_original_zalo_app()) {
        CFBundleRef mb = CFBundleGetMainBundle();
        if (bundle == mb || !bundle) {
            void *caller0 = __builtin_return_address(0);
            if (!is_network_system_caller(caller0)) {
                void *caller1 = __builtin_return_address(1);
                if (is_zalo_caller(caller0) || is_zalo_caller(caller1)) {
                    if (!s_logged_c_bid) {
                        s_logged_c_bid = YES;
                        logAudit(@"BUNDLE-ID", @"Zalo gọi C-Layer CFBundleGetIdentifier() -> [BẺ HƯỚNG TẦNG C VỀ vn.com.vng.zingalo]");
                    }
                    s_in_c_bundle_hook = NO;
                    return CFSTR("vn.com.vng.zingalo");
                }
            }
        }
    }
    CFStringRef res = orig_CFBundleGetIdentifier ? orig_CFBundleGetIdentifier(bundle) : (bundle ? CFBundleGetIdentifier(bundle) : NULL);
    s_in_c_bundle_hook = NO;
    return res;
}

static CFTypeRef (*orig_CFBundleGetValueForInfoDictionaryKey)(CFBundleRef bundle, CFStringRef key) = NULL;
static CFTypeRef my_CFBundleGetValueForInfoDictionaryKey(CFBundleRef bundle, CFStringRef key) {
    if (s_in_c_bundle_hook) {
        return orig_CFBundleGetValueForInfoDictionaryKey ? orig_CFBundleGetValueForInfoDictionaryKey(bundle, key) : (bundle ? CFBundleGetValueForInfoDictionaryKey(bundle, key) : NULL);
    }
    s_in_c_bundle_hook = YES;
    if (is_tweak_active() && !is_original_zalo_app() && key) {
        if (CFEqual(key, kCFBundleIdentifierKey) || CFStringCompare(key, CFSTR("CFBundleIdentifier"), 0) == kCFCompareEqualTo) {
            CFBundleRef mb = CFBundleGetMainBundle();
            if (bundle == mb || !bundle) {
                void *caller0 = __builtin_return_address(0);
                if (!is_network_system_caller(caller0)) {
                    void *caller1 = __builtin_return_address(1);
                    if (is_zalo_caller(caller0) || is_zalo_caller(caller1)) {
                        if (!s_logged_c_info_bid) {
                            s_logged_c_info_bid = YES;
                            logAudit(@"BUNDLE-ID", @"Zalo gọi C-Layer CFBundleGetValueForInfoDictionaryKey(CFBundleIdentifier) -> [BẺ HƯỚNG TẦNG C VỀ vn.com.vng.zingalo]");
                        }
                        s_in_c_bundle_hook = NO;
                        return CFSTR("vn.com.vng.zingalo");
                    }
                }
            }
        } else if (CFStringCompare(key, CFSTR("NSLocalNetworkUsageDescription"), 0) == kCFCompareEqualTo) {
            CFBundleRef mb = CFBundleGetMainBundle();
            if (bundle == mb || !bundle) {
                CFTypeRef res = orig_CFBundleGetValueForInfoDictionaryKey ? orig_CFBundleGetValueForInfoDictionaryKey(bundle, key) : NULL;
                if (res) {
                    s_in_c_bundle_hook = NO;
                    return res;
                }
                s_in_c_bundle_hook = NO;
                return CFSTR("Zalo cần truy cập mạng cục bộ để kết nối và truyền dữ liệu");
            }
        }
    }
    CFTypeRef res = orig_CFBundleGetValueForInfoDictionaryKey ? orig_CFBundleGetValueForInfoDictionaryKey(bundle, key) : (bundle ? CFBundleGetValueForInfoDictionaryKey(bundle, key) : NULL);
    s_in_c_bundle_hook = NO;
    return res;
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

    struct ifaddrs *prev = NULL;
    struct ifaddrs *curr = *ifap;
    BOOL modified = NO;
    while (curr) {
        BOOL is_vpn = NO;
        if (curr->ifa_name) {
            const char *n = curr->ifa_name;
            if (strncmp(n, "tun", 3) == 0 ||
                strncmp(n, "tap", 3) == 0 ||
                strncmp(n, "ppp", 3) == 0 ||
                strncmp(n, "ipsec", 5) == 0 ||
                strncmp(n, "utun", 4) == 0 ||
                strncmp(n, "pdp_ip9", 7) == 0) {
                is_vpn = YES;
            }
        }
        if (is_vpn) {
            modified = YES;
            if (prev) {
                // Node nằm sau: Unlink an toàn khỏi linked-list!
                // Con trỏ gốc *ifap không bị thay đổi nên freeifaddrs(*ifap) giải phóng nguyên vẹn khối malloc.
                prev->ifa_next = curr->ifa_next;
                curr = curr->ifa_next;
                continue;
            } else {
                // Trường hợp hy hữu nếu node đầu tiên là VPN: Đổi tên thành card Apple nội bộ awdl0
                curr->ifa_name = "awdl0";
                if (curr->ifa_flags) curr->ifa_flags &= ~(IFF_POINTOPOINT | IFF_LOOPBACK);
            }
        }
        prev = curr;
        curr = curr->ifa_next;
    }
    if (modified) {
        logAudit(@"VPN-CHECK", @"Quét danh sách getifaddrs -> [ĐÃ LỌC BỎ HOÀN TOÀN CARD MẠNG ẢO VPN/UTUN]");
    }
    return 0;
}

__attribute__((visibility("default"))) int zt_get_masked_ifaddrs(struct ifaddrs **ifap) {
    return my_getifaddrs(ifap);
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

static int (*orig_statvfs)(const char *path, struct statvfs *buf);
static int my_statvfs(const char *path, struct statvfs *buf) {
    int ret = orig_statvfs ? orig_statvfs(path, buf) : statvfs(path, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_frsize ? (uint64_t)buf->f_frsize : (buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL);
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = (fsblkcnt_t)(settings.diskTotalSize / bsize);
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = (fsblkcnt_t)(settings.diskFreeSize / bsize);
            buf->f_bfree = buf->f_bavail;
        }
    }
    return ret;
}

static int (*orig_fstatvfs)(int fd, struct statvfs *buf);
static int my_fstatvfs(int fd, struct statvfs *buf) {
    int ret = orig_fstatvfs ? orig_fstatvfs(fd, buf) : fstatvfs(fd, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_frsize ? (uint64_t)buf->f_frsize : (buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL);
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = (fsblkcnt_t)(settings.diskTotalSize / bsize);
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = (fsblkcnt_t)(settings.diskFreeSize / bsize);
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

static inline uint64_t get_effective_birth_for_path(const char *path, uint64_t base_birth) {
    if (!path || base_birth == 0) return base_birth;
    uint64_t delta_m = 180ULL + ((base_birth * 104729ULL) % 1800ULL) + (base_birth % 59ULL);
    uint64_t delta_c = delta_m + 30ULL + ((base_birth * 1299709ULL) % 600ULL) + ((base_birth / 13ULL) % 43ULL);
    if (strstr(path, "/Library") != NULL || strstr(path, "/Caches") != NULL || strstr(path, "/tmp") != NULL || strstr(path, "/Preferences") != NULL) {
        return base_birth + delta_c;
    }
    if (strstr(path, "/Documents") != NULL || strstr(path, "/Containers/") != NULL || strstr(path, "/Application/") != NULL) {
        return base_birth + delta_m;
    }
    return base_birth;
}

static inline void get_consistent_stat_times(uint64_t fake_birth, time_t *out_mtime, time_t *out_ctime, long *out_nsec_b, long *out_nsec_m, long *out_nsec_c) {
    uint64_t delta_m = 180ULL + ((fake_birth * 104729ULL) % 1800ULL) + (fake_birth % 59ULL);
    uint64_t delta_c = delta_m + 30ULL + ((fake_birth * 1299709ULL) % 600ULL) + ((fake_birth / 13ULL) % 43ULL);
    if (out_mtime) *out_mtime = (time_t)(fake_birth + delta_m);
    if (out_ctime) *out_ctime = (time_t)(fake_birth + delta_c);
    if (out_nsec_b) *out_nsec_b = (long)(((fake_birth * 2654435761ULL) % 850ULL + 100ULL) * 1000000L);
    if (out_nsec_m) *out_nsec_m = (long)((((fake_birth + delta_m) * 2654435761ULL) % 850ULL + 100ULL) * 1000000L);
    if (out_nsec_c) *out_nsec_c = (long)((((fake_birth + delta_c) * 2654435761ULL) % 850ULL + 100ULL) * 1000000L);
}

static inline void fake_stat_timespec_for_path(const char *path, struct stat *buf, uint64_t btime) {
    if (!buf) return;
    ZTSettings *s = [ZTSettings sharedSettings];
    uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
    time_t fake_birth = (time_t)get_effective_birth_for_path(path, base_birth);
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

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        s_in_stat = NO;
        errno = ENOENT;
        return -1;
    }

    int ret = orig_stat ? orig_stat(path, buf) : stat(path, buf);
    if (ret == 0 && is_tweak_active() && buf && path) {
        if (should_fake_stat_path(path)) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec_for_path(path, buf, btime);
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

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        s_in_lstat = NO;
        errno = ENOENT;
        return -1;
    }

    int ret = orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
    if (ret == 0 && is_tweak_active() && buf && path) {
        if (should_fake_stat_path(path)) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec_for_path(path, buf, btime);
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
        char filePath[1024] = {0};
        BOOL shouldFake = NO;
        if (fcntl(fd, F_GETPATH, filePath) >= 0) {
            shouldFake = should_fake_stat_path(filePath);
        } else {
            shouldFake = S_ISDIR(buf->st_mode) || (buf->st_birthtimespec.tv_sec > 1400000000);
        }
        if (shouldFake) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec_for_path(filePath[0] ? filePath : NULL, buf, btime);
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
            uint64_t baseBirth = s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
            uint64_t effBirth = get_effective_birth_for_path(path, baseBirth);
            time_t fake_mtime = 0, fake_ctime = 0;
            long nsec_b = 0, nsec_m = 0, nsec_c = 0;
            get_consistent_stat_times(effBirth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
            size_t words = attrBufSize / sizeof(uint64_t);
            uint64_t *ptr64 = (uint64_t *)attrBuf;
            int timeIdx = 0;
            for (size_t i = 0; i < words; ++i) {
                if (ptr64[i] >= 1400000000ULL && ptr64[i] <= 2500000000ULL) {
                    if (timeIdx == 0) {
                        ptr64[i] = effBirth;
                        if (i + 1 < words && ptr64[i + 1] < 1000000000ULL) {
                            ptr64[i + 1] = (uint64_t)nsec_b;
                        }
                    } else if (timeIdx == 1) {
                        ptr64[i] = (uint64_t)fake_mtime;
                        if (i + 1 < words && ptr64[i + 1] < 1000000000ULL) {
                            ptr64[i + 1] = (uint64_t)nsec_m;
                        }
                    } else {
                        ptr64[i] = (uint64_t)fake_ctime;
                        if (i + 1 < words && ptr64[i + 1] < 1000000000ULL) {
                            ptr64[i + 1] = (uint64_t)nsec_c;
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
// HOOK DYLD & DLADDR: Ẩn hoàn toàn Zalotweak.dylib, Substrate, ElleKit, RootHide khỏi bộ quét của Zalo
// ==========================================
static BOOL is_sensitive_image_path_cstr(const char *name) {
    if (!name) return NO;
    return (strstr(name, "Zalotweak") != NULL ||
            strstr(name, "zalotweak") != NULL ||
            strstr(name, "Substrate") != NULL ||
            strstr(name, "substitute") != NULL ||
            strstr(name, "ellekit") != NULL ||
            strstr(name, "roothide") != NULL ||
            strstr(name, "jbroot") != NULL ||
            strstr(name, "TweakInject") != NULL ||
            strstr(name, "MobileSafety") != NULL);
}

static const char *(*orig_dyld_get_image_name)(uint32_t image_index);
static const char *my_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : _dyld_get_image_name(image_index);
    if (name && is_tweak_active() && is_sensitive_image_path_cstr(name)) {
        if (is_zalo_caller(__builtin_return_address(0))) {
            static const char *s_safe_fallback_images[] = {
                "/usr/lib/libobjc.A.dylib",
                "/usr/lib/system/libsystem_c.dylib",
                "/usr/lib/system/libsystem_kernel.dylib",
                "/usr/lib/system/libsystem_m.dylib",
                "/usr/lib/system/libdispatch.dylib"
            };
            return s_safe_fallback_images[image_index % 5];
        }
    }
    return name;
}

static int my_dladdr(const void *addr, Dl_info *info) {
    int ret = raw_dladdr(addr, info);
    if (ret != 0 && info && is_tweak_active()) {
        BOOL sensitiveImg = (info->dli_fname && is_sensitive_image_path_cstr(info->dli_fname));
        BOOL sensitiveSym = (info->dli_sname && (strncmp(info->dli_sname, "ZT", 2) == 0 ||
                                                 strncmp(info->dli_sname, "my_", 3) == 0 ||
                                                 strncmp(info->dli_sname, "_logos_", 7) == 0));
        if ((sensitiveImg || sensitiveSym) && is_zalo_caller(__builtin_return_address(0))) {
            info->dli_fname = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
            info->dli_sname = NULL;
            info->dli_saddr = NULL;
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

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        s_in_open = NO;
        errno = ENOENT;
        return -1;
    }

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

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        s_in_openat = NO;
        errno = ENOENT;
        return -1;
    }

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
    static __thread BOOL s_in_mg = NO;
    if (s_in_mg || !property || CFGetTypeID(property) != CFStringGetTypeID() || !is_tweak_active()) {
        return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
    }
    s_in_mg = YES;

    NSString *prop = (__bridge NSString *)property;
    ZTSettings *settings = [ZTSettings sharedSettings];

    if ([prop isEqualToString:@"SerialNumber"]) {
        s_in_mg = NO;
        // App Store apps không có quyền đọc SerialNumber qua MGCopyAnswer -> Trả NULL chuẩn Apple Sandbox
        return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
    }
    if ([prop isEqualToString:@"UniqueDeviceID"]) {
        NSString *udid = [[settings.spoofedIDFV stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
        s_in_mg = NO;
        return (__bridge_retained CFTypeRef)[udid copy];
    }
    if ([prop isEqualToString:@"WifiAddress"]) {
        s_in_mg = NO;
        // Chuẩn iOS 7+: Third-party apps luôn nhận 02:00:00:00:00:00
        return (__bridge_retained CFTypeRef)[@"02:00:00:00:00:00" copy];
    }
    if ([prop isEqualToString:@"BluetoothAddress"]) {
        s_in_mg = NO;
        return NULL;
    }
    if ([prop isEqualToString:@"UserAssignedDeviceName"]) {
        s_in_mg = NO;
        NSString *sysVer = settings.systemVersion;
        if (sysVer.length > 0 && [[sysVer componentsSeparatedByString:@"."].firstObject integerValue] >= 16) {
            return (__bridge_retained CFTypeRef)[@"iPhone" copy];
        }
        return settings.deviceName ? (__bridge_retained CFTypeRef)[settings.deviceName copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"ProductType"]) {
        s_in_mg = NO;
        return settings.deviceMachine ? (__bridge_retained CFTypeRef)[settings.deviceMachine copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"ProductVersion"]) {
        s_in_mg = NO;
        return settings.systemVersion ? (__bridge_retained CFTypeRef)[settings.systemVersion copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"BuildVersion"]) {
        s_in_mg = NO;
        return settings.kernOsVersion ? (__bridge_retained CFTypeRef)[settings.kernOsVersion copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"HWModelStr"] || [prop isEqualToString:@"HardwarePlatform"]) {
        s_in_mg = NO;
        return settings.deviceModel ? (__bridge_retained CFTypeRef)[settings.deviceModel copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"TotalDiskCapacity"] || [prop isEqualToString:@"TotalDataCapacity"]) {
        s_in_mg = NO;
        uint64_t total = settings.diskTotalSize > 0 ? settings.diskTotalSize : 64000000000ULL;
        if (settings.enableAuditLog) {
            logAudit(@"RADAR-MG", [NSString stringWithFormat:@"MobileGestalt MGCopyAnswer(%@) -> [ĐÃ FAKE TOTAL DISK %llu bytes]", prop, total]);
        }
        return CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &total);
    }
    if ([prop isEqualToString:@"TotalDataAvailable"]) {
        s_in_mg = NO;
        uint64_t free = settings.diskFreeSize > 0 ? settings.diskFreeSize : 32000000000ULL;
        if (settings.enableAuditLog) {
            logAudit(@"RADAR-MG", [NSString stringWithFormat:@"MobileGestalt MGCopyAnswer(TotalDataAvailable) -> [ĐÃ FAKE FREE DISK %llu bytes]", free]);
        }
        return CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &free);
    }
    if ([prop isEqualToString:@"DiskUsage"]) {
        s_in_mg = NO;
        uint64_t total = settings.diskTotalSize > 0 ? settings.diskTotalSize : 64000000000ULL;
        uint64_t free = settings.diskFreeSize > 0 ? settings.diskFreeSize : 32000000000ULL;
        if (settings.enableAuditLog) {
            logAudit(@"RADAR-MG", [NSString stringWithFormat:@"MobileGestalt MGCopyAnswer(DiskUsage) -> [ĐÃ FAKE DISK DICTIONARY]"]);
        }
        NSDictionary *usage = @{
            @"TotalDiskCapacity": @(total),
            @"TotalDataCapacity": @(total),
            @"TotalDataAvailable": @(free),
            @"AmountDataReserved": @(1024ULL * 1024ULL * 512ULL)
        };
        return (__bridge_retained CFTypeRef)usage;
    }

    s_in_mg = NO;
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
        if ([lower containsString:@"zalotweak"] ||
            [lower containsString:@".adbk"] ||
            [lower containsString:@"appsmanager"] ||
            [lower containsString:@"zaloaudit.log"] ||
            [lower containsString:@"zalotraffic.har"]) {
            return attrs;
        }
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
                uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
                uint64_t fake_birth = get_effective_birth_for_path([path UTF8String], base_birth);
                time_t fake_mtime = 0, fake_ctime = 0;
                long nsec_b = 0, nsec_m = 0, nsec_c = 0;
                get_consistent_stat_times(fake_birth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
                NSDate *fakeDate = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_birth + (NSTimeInterval)nsec_b / 1000000000.0)];
                NSDate *fakeModDate = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_mtime + (NSTimeInterval)nsec_m / 1000000000.0)];
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

// Chặn không cho quét danh sách các container ứng dụng khác và lọc sạch app Jailbreak trong /Applications
- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path) {
        NSString *lower = [path lowercaseString];
        if ([lower isEqualToString:@"/applications"] || [lower isEqualToString:@"/applications/"]) {
            NSArray<NSString *> *items = %orig;
            if (items && items.count > 0) {
                NSMutableArray<NSString *> *filtered = [NSMutableArray arrayWithCapacity:items.count];
                for (NSString *item in items) {
                    NSString *itemLower = [item lowercaseString];
                    if ([itemLower containsString:@"sileo"] ||
                        [itemLower containsString:@"cydia"] ||
                        [itemLower containsString:@"zebra"] ||
                        [itemLower containsString:@"filza"] ||
                        [itemLower containsString:@"substitute"] ||
                        [itemLower containsString:@"ellekit"]) {
                        continue;
                    }
                    [filtered addObject:item];
                }
                return filtered;
            }
        }
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

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError **)error {
    if (url && [url isFileURL]) {
        NSString *path = [url path];
        NSString *lower = [path lowercaseString];
        if ([lower isEqualToString:@"/applications"] || [lower isEqualToString:@"/applications/"]) {
            NSArray<NSURL *> *items = %orig;
            if (items && items.count > 0) {
                NSMutableArray<NSURL *> *filtered = [NSMutableArray arrayWithCapacity:items.count];
                for (NSURL *u in items) {
                    NSString *uLower = [[u lastPathComponent] lowercaseString];
                    if ([uLower containsString:@"sileo"] ||
                        [uLower containsString:@"cydia"] ||
                        [uLower containsString:@"zebra"] ||
                        [uLower containsString:@"filza"] ||
                        [uLower containsString:@"substitute"] ||
                        [uLower containsString:@"ellekit"]) {
                        continue;
                    }
                    [filtered addObject:u];
                }
                return filtered;
            }
        }
    }
    return %orig;
}

%end

// ==========================================
// HOOK NSURL: Trả về ngày tạo file đồng bộ chính xác tới nano-giây với stat/getattrlist
// ==========================================
%hook NSURL

- (BOOL)getResourceValue:(id *)value forKey:(NSURLResourceKey)key error:(NSError **)error {
    BOOL ret = %orig;
    if (is_tweak_active() && value && key) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if ([key isEqualToString:NSURLVolumeTotalCapacityKey] && s.diskTotalSize > 0) {
            *value = @(s.diskTotalSize);
            return YES;
        }
        if ([key isEqualToString:NSURLVolumeAvailableCapacityKey] && s.diskFreeSize > 0) {
            *value = @(s.diskFreeSize);
            return YES;
        }
        if ([key isEqualToString:NSURLVolumeAvailableCapacityForImportantUsageKey] && s.diskFreeSize > 0) {
            uint64_t purgeable = 1450000000ULL + ((s.diskFreeSize * 104729ULL) % 1500000000ULL);
            *value = @(s.diskFreeSize + purgeable);
            return YES;
        }
        if ([key isEqualToString:NSURLVolumeAvailableCapacityForOpportunisticUsageKey] && s.diskFreeSize > 0) {
            uint64_t reserve = 450000000ULL + ((s.diskFreeSize * 2654435761ULL) % 450000000ULL);
            uint64_t oppFree = (s.diskFreeSize > reserve) ? (s.diskFreeSize - reserve) : s.diskFreeSize;
            *value = @(oppFree);
            return YES;
        }
        if ([key isEqualToString:NSURLCreationDateKey] || [key isEqualToString:NSURLContentModificationDateKey] || [key isEqualToString:NSURLAttributeModificationDateKey]) {
            uint64_t btime = s.bootTimeSec;
            if (btime > 0 || s.birthTimeSec > 0) {
                uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
                NSString *urlPath = [self isFileURL] ? [self path] : nil;
                uint64_t fake_birth = get_effective_birth_for_path(urlPath ? [urlPath UTF8String] : NULL, base_birth);
                time_t fake_mtime = 0, fake_ctime = 0;
                long nsec_b = 0, nsec_m = 0, nsec_c = 0;
                get_consistent_stat_times(fake_birth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
                if ([key isEqualToString:NSURLCreationDateKey]) {
                    *value = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_birth + (NSTimeInterval)nsec_b / 1000000000.0)];
                } else if ([key isEqualToString:NSURLContentModificationDateKey]) {
                    *value = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_mtime + (NSTimeInterval)nsec_m / 1000000000.0)];
                } else {
                    *value = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_ctime + (NSTimeInterval)nsec_c / 1000000000.0)];
                }
                return YES;
            }
        }
    }
    return ret;
}

- (NSDictionary<NSURLResourceKey, id> *)resourceValuesForKeys:(NSArray<NSURLResourceKey> *)keys error:(NSError **)error {
    NSDictionary<NSURLResourceKey, id> *values = %orig;
    if (is_tweak_active() && keys) {
        ZTSettings *s = [ZTSettings sharedSettings];
        NSMutableDictionary *m = values ? [values mutableCopy] : [NSMutableDictionary dictionary];
        BOOL changed = NO;
        if ([keys containsObject:NSURLVolumeTotalCapacityKey] && s.diskTotalSize > 0) {
            m[NSURLVolumeTotalCapacityKey] = @(s.diskTotalSize);
            changed = YES;
        }
        if ([keys containsObject:NSURLVolumeAvailableCapacityKey] && s.diskFreeSize > 0) {
            m[NSURLVolumeAvailableCapacityKey] = @(s.diskFreeSize);
            changed = YES;
        }
        if ([keys containsObject:NSURLVolumeAvailableCapacityForImportantUsageKey] && s.diskFreeSize > 0) {
            uint64_t purgeable = 1450000000ULL + ((s.diskFreeSize * 104729ULL) % 1500000000ULL);
            m[NSURLVolumeAvailableCapacityForImportantUsageKey] = @(s.diskFreeSize + purgeable);
            changed = YES;
        }
        if ([keys containsObject:NSURLVolumeAvailableCapacityForOpportunisticUsageKey] && s.diskFreeSize > 0) {
            uint64_t reserve = 450000000ULL + ((s.diskFreeSize * 2654435761ULL) % 450000000ULL);
            uint64_t oppFree = (s.diskFreeSize > reserve) ? (s.diskFreeSize - reserve) : s.diskFreeSize;
            m[NSURLVolumeAvailableCapacityForOpportunisticUsageKey] = @(oppFree);
            changed = YES;
        }
        uint64_t btime = s.bootTimeSec;
        if (btime > 0 || s.birthTimeSec > 0) {
            uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
            NSString *urlPath = [self isFileURL] ? [self path] : nil;
            uint64_t fake_birth = get_effective_birth_for_path(urlPath ? [urlPath UTF8String] : NULL, base_birth);
            time_t fake_mtime = 0, fake_ctime = 0;
            long nsec_b = 0, nsec_m = 0, nsec_c = 0;
            get_consistent_stat_times(fake_birth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
            if ([keys containsObject:NSURLCreationDateKey]) {
                m[NSURLCreationDateKey] = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_birth + (NSTimeInterval)nsec_b / 1000000000.0)];
                changed = YES;
            }
            if ([keys containsObject:NSURLContentModificationDateKey]) {
                m[NSURLContentModificationDateKey] = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_mtime + (NSTimeInterval)nsec_m / 1000000000.0)];
                changed = YES;
            }
            if ([keys containsObject:NSURLAttributeModificationDateKey]) {
                m[NSURLAttributeModificationDateKey] = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_ctime + (NSTimeInterval)nsec_c / 1000000000.0)];
                changed = YES;
            }
        }
        if (changed) return m;
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
        // CHỈ BẺ HƯỚNG KHI VÀ CHỈ KHI CALLER THỰC SỰ LÀ CODE CỦA ZALO APP
        void *caller0 = __builtin_return_address(0);
        if (!is_network_system_caller(caller0)) {
            void *caller1 = __builtin_return_address(1);
            if (is_zalo_caller(caller0) || is_zalo_caller(caller1)) {
                logAudit(@"BUNDLE-ID", @"Zalo truy vấn bundleIdentifier -> [ĐÃ BẺ HƯỚNG TRẢ VỀ vn.com.vng.zingalo]");
                return @"vn.com.vng.zingalo";
            }
        }

        return %orig;
    }
    return %orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if (self == [NSBundle mainBundle] && key) {
        if (!is_tweak_active()) return %orig;
        if (s_in_bundle_hook) return %orig;
        s_in_bundle_hook = YES;
        BOOL isOrig = is_original_zalo_app();
        s_in_bundle_hook = NO;
        if (!isOrig) {
            if ([key isEqualToString:@"CFBundleIdentifier"]) {
                void *caller0 = __builtin_return_address(0);
                if (!is_network_system_caller(caller0)) {
                    void *caller1 = __builtin_return_address(1);
                    if (is_zalo_caller(caller0) || is_zalo_caller(caller1)) {
                        logAudit(@"BUNDLE-ID", @"Zalo đọc InfoDictionary(CFBundleIdentifier) -> [ĐÃ BẺ HƯỚNG TRẢ VỀ vn.com.vng.zingalo]");
                        return @"vn.com.vng.zingalo";
                    }
                }
            } else if ([key isEqualToString:@"NSLocalNetworkUsageDescription"]) {
                id origVal = %orig;
                return origVal ?: @"Zalo cần truy cập mạng cục bộ để kết nối và truyền dữ liệu";
            }
        }
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
        void *caller0 = __builtin_return_address(0);
        if (!is_network_system_caller(caller0)) {
            void *caller1 = __builtin_return_address(1);
            if (is_zalo_caller(caller0) || is_zalo_caller(caller1)) {
                NSMutableDictionary *mDict = [dict mutableCopy];
                mDict[@"CFBundleIdentifier"] = @"vn.com.vng.zingalo";
                if (!mDict[@"NSLocalNetworkUsageDescription"]) {
                    mDict[@"NSLocalNetworkUsageDescription"] = @"Zalo cần truy cập mạng cục bộ để kết nối và truyền dữ liệu";
                }
                return mDict;
            }
        }
        return dict;
    }
    return dict;
}

%end

static inline __attribute__((unused)) NSData *get_clone_fake_apns_token_data(void) {
    NSString *seed = [ZTSettings sharedSettings].spoofedIDFV ?: @"E7EECB78CDF44E5E8C98BD140A2FEED6";
    NSString *apnsSeed = [NSString stringWithFormat:@"APNS:%@", seed];
    const char *cStr = [apnsSeed UTF8String];
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, (CC_LONG)strlen(cStr), hash);
    return [NSData dataWithBytes:hash length:32];
}

static inline __attribute__((unused)) NSData *get_clone_fake_voip_token_data(void) {
    NSString *seed = [ZTSettings sharedSettings].spoofedIDFV ?: @"E7EECB78CDF44E5E8C98BD140A2FEED6";
    NSString *voipSeed = [NSString stringWithFormat:@"VOIP:%@", seed];
    const char *cStr = [voipSeed UTF8String];
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, (CC_LONG)strlen(cStr), hash);
    return [NSData dataWithBytes:hash length:32];
}

static inline __attribute__((unused)) NSString *hex_string_from_data(NSData *data) {
    if (!data || data.length == 0) return @"";
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

@interface NSObject (ZTPKPushRegistrySupport)
- (void)pushRegistry:(id)registry didUpdatePushCredentials:(id)credentials forType:(NSString *)type;
- (NSData *)token;
@end

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

- (void)setObject:(id)value forKey:(NSString *)defaultName {
    if (defaultName && [defaultName isKindOfClass:[NSString class]]) {
        if ([defaultName isEqualToString:@"kTimeDeviceChangedKey"] ||
            [defaultName isEqualToString:@"kOldSessionKey"] ||
            [defaultName isEqualToString:@"kOldLoginIndentifierKey"]) {
            if (is_tweak_active()) {
                return;
            }
        }
        if (is_tweak_active() && [ZTSettings sharedSettings].enableAuditLog) {
            void *c0 = __builtin_return_address(0);
            if ([defaultName containsString:@"Authen"] || [defaultName containsString:@"UpTick"] || [defaultName containsString:@"BootTime"]) {
                logAudit(@"RADAR-AUTH", [NSString stringWithFormat:@"💾 Zalo ghi UserDefaults: '%@' = %@ từ %@", defaultName, value, format_caller_info(c0)]);
            }
        }
    }
    %orig;
}

- (id)objectForKey:(NSString *)defaultName {
    if (defaultName && [defaultName isKindOfClass:[NSString class]]) {
        if ([defaultName isEqualToString:@"kTimeDeviceChangedKey"] ||
            [defaultName isEqualToString:@"kOldSessionKey"] ||
            [defaultName isEqualToString:@"kOldLoginIndentifierKey"]) {
            if (is_tweak_active()) {
                if ([ZTSettings sharedSettings].enableAuditLog) {
                    logAudit(@"DEFAULTS-READ", [NSString stringWithFormat:@"⚙️ Zalo đọc UserDefaults: '%@' -> (nil) [ĐÃ CHẶN DẤU VẾT ĐỔI MÁY CŨ]", defaultName]);
                }
                return nil;
            }
        }
    }
    id val = %orig;
    if (is_tweak_active() && !is_original_zalo_app() && defaultName && [defaultName isKindOfClass:[NSString class]]) {
        if ([defaultName hasPrefix:@"kApnsTokenKey"] || [defaultName isEqualToString:@"apns_token_cache_key"]) {
            val = nil;
            logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"[PUSH-PROTECT] Zalo Clone: Không cấp APNs Token fake cho '%@' (Tránh BadDeviceToken Apple) ✅", defaultName]);
        } else if ([defaultName hasPrefix:@"kVoIPTokenKey"]) {
            val = nil;
            logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"[PUSH-PROTECT] Zalo Clone: Không cấp VoIP PushKit Token fake cho '%@' ✅", defaultName]);
        }
    }

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

- (NSString *)stringForKey:(NSString *)defaultName {
    if (is_tweak_active() && !is_original_zalo_app() && defaultName && [defaultName isKindOfClass:[NSString class]]) {
        if ([defaultName hasPrefix:@"kApnsTokenKey"] || [defaultName isEqualToString:@"apns_token_cache_key"]) {
            return nil;
        } else if ([defaultName hasPrefix:@"kVoIPTokenKey"]) {
            return nil;
        }
    }
    return %orig;
}

%end

static void deliver_clone_apns_token_to_delegate(UIApplication *app, id<UIApplicationDelegate> delegate) {
    if (!app || !delegate || !is_tweak_active() || is_original_zalo_app()) return;
    SEL failSel = @selector(application:didFailToRegisterForRemoteNotificationsWithError:);
    if ([delegate respondsToSelector:failSel]) {
        NSError *err = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:3010 userInfo:@{NSLocalizedDescriptionKey: @"User denied notification permissions"}];
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [delegate application:app didFailToRegisterForRemoteNotificationsWithError:err];
        #pragma clang diagnostic pop
        logAudit(@"PUSH-TOKEN", @"[PUSH-PROTECT] Zalo Clone: Báo lỗi từ chối thông báo didFailToRegister (Triệt tiêu 100% BadDeviceToken Apple) ✅");
    }
}

%hook UNUserNotificationCenter

- (void)requestAuthorizationWithOptions:(NSUInteger)options completionHandler:(void (^)(BOOL granted, NSError * _Nullable error))completionHandler {
    if (is_tweak_active() && !is_original_zalo_app()) {
        if (completionHandler) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completionHandler(NO, nil);
                logAudit(@"PUSH-TOKEN", @"[PUSH-PROTECT] Zalo Clone: Giả lập người dùng bấm 'Từ chối thông báo' (granted=NO)");
            });
        }
        return;
    }
    %orig;
}

%end

static const void *kZTVoIPTokenAssocKey = &kZTVoIPTokenAssocKey;
static const void *kZTVoIPTypeAssocKey  = &kZTVoIPTypeAssocKey;

%hook PKPushCredentials

- (NSData *)token {
    if (is_tweak_active() && !is_original_zalo_app()) {
        return nil;
    }
    NSData *orig = %orig;
    if (orig) return orig;
    NSData *assoc = objc_getAssociatedObject(self, kZTVoIPTokenAssocKey);
    if (assoc) return assoc;
    return orig;
}

- (NSString *)type {
    NSString *orig = %orig;
    if (orig) return orig;
    NSString *assoc = objc_getAssociatedObject(self, kZTVoIPTypeAssocKey);
    if (assoc) return assoc;
    return orig;
}

%end

static __attribute__((unused)) void deliver_clone_voip_token_to_registry(id registry, id delegate) {
    // Không nạp token fake cho Zalo Clone
    return;
}

%hook PKPushRegistry

- (NSData *)pushTokenForType:(NSString *)type {
    if (is_tweak_active() && !is_original_zalo_app()) {
        return nil;
    }
    return %orig;
}

- (void)setDesiredPushTypes:(NSSet *)types {
    if (is_tweak_active() && is_original_zalo_app() && [ZTSettings sharedSettings].justGeneratedColdBoot) {
        logAudit(@"PUSH-REGISTRY", @"[VOIP-RESET] Đã hủy đăng ký phiên VoIP cũ với apsd để bắt Apple cấp lại Token mới cho Profile mới 🔄");
        %orig([NSSet set]);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            %orig(types);
        });
        return;
    }
    %orig;
}

- (void)setDelegate:(id)delegate {
    if (delegate && is_tweak_active()) {
        static Class s_swappedPKDelClass = nil;
        Class delClass = [delegate class];
        if (delClass && delClass != s_swappedPKDelClass) {
            s_swappedPKDelClass = delClass;
            SEL credSel = @selector(pushRegistry:didUpdatePushCredentials:forType:);
            Method credMethod = class_getInstanceMethod(delClass, credSel);
            if (credMethod) {
                typedef void (*OrigCredIMP)(id, SEL, id, id, NSString *);
                OrigCredIMP origImp = (OrigCredIMP)method_getImplementation(credMethod);
                IMP customCredImp = imp_implementationWithBlock(^(id self_del, id registry, id creds, NSString *type) {
                    if (creds && [creds respondsToSelector:@selector(token)]) {
                        NSData *tokData = [creds valueForKey:@"token"];
                        if (tokData && tokData.length > 0) {
                            const unsigned char *b = (const unsigned char *)[tokData bytes];
                            NSUInteger len = [tokData length];
                            NSMutableString *hex = [NSMutableString stringWithCapacity:(len * 2)];
                            for (NSUInteger i = 0; i < len; i++) {
                                [hex appendFormat:@"%02x", b[i]];
                            }
                            ZTSettings *st = [ZTSettings sharedSettings];
                            st.currentVoIPToken = hex;
                            [st saveSettings];
                            logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"📞 [PUSHKIT CREDENTIALS] Đã bắt Token VoIP trực tiếp từ PushKit: %@", hex]);
                        }
                    }
                    if (origImp) {
                        origImp(self_del, credSel, registry, creds, type);
                    }
                });
                method_setImplementation(credMethod, customCredImp);
            }
        }
    }
    %orig;
}

%end

%hook UIApplication

- (BOOL)isRegisteredForRemoteNotifications {
    if (is_tweak_active()) {
        if (!is_original_zalo_app()) {
            return NO;
        }
        return %orig;
    }
    return %orig;
}

- (void)registerForRemoteNotifications {
    if (is_tweak_active()) {
        if (!is_original_zalo_app()) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                deliver_clone_apns_token_to_delegate(self, self.delegate);
            });
            return;
        }

        static BOOL s_unregisteredOnceAfterWipe = NO;
        if (!s_unregisteredOnceAfterWipe) {
            NSString *prefPath = getConfigPath();
            NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:prefPath];
            if (!dict) dict = [NSDictionary dictionaryWithContentsOfFile:GLOBAL_PREFS_PATH];
            if ([dict[@"wipePending"] boolValue] || [dict[@"needsAPNsUnregister"] boolValue]) {
                s_unregisteredOnceAfterWipe = YES;
                logAudit(@"APNS-ROTATE", @"🔄 [WIPE-ACTIVE] Phát hiện phiên mở app đầu tiên sau Wipe -> Hủy đăng ký topic cũ với apsd và xả RunLoop...");
                if ([self respondsToSelector:@selector(unregisterForRemoteNotifications)]) {
                    [self unregisterForRemoteNotifications];
                    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
                }
                NSMutableDictionary *m = [dict mutableCopy];
                m[@"wipePending"] = @(NO);
                m[@"needsAPNsUnregister"] = @(NO);
                [m writeToFile:prefPath atomically:YES];
                [m writeToFile:GLOBAL_PREFS_PATH atomically:YES];

                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    logAudit(@"APNS-ROTATE", @"🚀 [WIPE-ACTIVE] Kích hoạt đăng ký mới với Apple Gateway để nhận Token mới...");
                    %orig;
                });
                return;
            }
        }
    }
    %orig;
}

- (void)setDelegate:(id<UIApplicationDelegate>)delegate {
    if (delegate && is_tweak_active()) {
        static Class s_swappedDelClass = nil;
        Class delClass = [delegate class];
        if (delClass && delClass != s_swappedDelClass) {
            s_swappedDelClass = delClass;
            SEL regSel = @selector(application:didRegisterForRemoteNotificationsWithDeviceToken:);
            Method regMethod = class_getInstanceMethod(delClass, regSel);
            if (regMethod) {
                typedef void (*OrigDidRegIMP)(id, SEL, UIApplication *, NSData *);
                OrigDidRegIMP origImp = (OrigDidRegIMP)method_getImplementation(regMethod);
                IMP customRegImp = imp_implementationWithBlock(^(id self_del, UIApplication *app, NSData *realToken) {
                    if (!is_original_zalo_app()) {
                        SEL failSel = @selector(application:didFailToRegisterForRemoteNotificationsWithError:);
                        if ([self_del respondsToSelector:failSel]) {
                            NSError *err = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:3010 userInfo:@{NSLocalizedDescriptionKey: @"User denied notification permissions"}];
                            [self_del application:app didFailToRegisterForRemoteNotificationsWithError:err];
                        }
                        return;
                    }
                    if (realToken && [realToken length] > 0) {
                        const unsigned char *tokenBytes = (const unsigned char *)[realToken bytes];
                        NSUInteger tokenLen = [realToken length];
                        NSMutableString *tokenHex = [NSMutableString stringWithCapacity:(tokenLen * 2)];
                        for (NSUInteger i = 0; i < tokenLen; i++) {
                            [tokenHex appendFormat:@"%02x", tokenBytes[i]];
                        }

                        ZTSettings *s = [ZTSettings sharedSettings];
                        NSString *lastWiped = s.lastWipedAPNsToken;
                        if (!lastWiped || lastWiped.length == 0) {
                            NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:getConfigPath()];
                            if (!dict) dict = [NSDictionary dictionaryWithContentsOfFile:GLOBAL_PREFS_PATH];
                            lastWiped = dict[@"lastWipedAPNsToken"];
                        }
                        NSString *statusStr = @"INITIAL_CAPTURED";

                        if (lastWiped && lastWiped.length > 0) {
                            if ([tokenHex isEqualToString:lastWiped]) {
                                statusStr = @"DUPLICATE";
                                logAudit(@"APNS-STATUS", [NSString stringWithFormat:@"🔴 [CẢNH BÁO TRÙNG] Token APNs nhận từ Apple TRÙNG 100%% với Token trước Wipe: %@ -> TUYỆT ĐỐI CHƯA ĐĂNG KÝ ACC MỚI! Vui lòng bật/tắt Airplane Mode 5s hoặc Wipe lại!", tokenHex]);
                            } else {
                                statusStr = @"ROTATED_NEW";
                                logAudit(@"APNS-STATUS", [NSString stringWithFormat:@"🟢 [THÀNH CÔNG] Token APNs ĐÃ ĐỔI MỚI HOÀN TOÀN!\n- Token Mới: %@\n- Token Cũ trước Wipe: %@\n-> AN TOÀN TUYỆT ĐỐI ĐỂ ĐĂNG KÝ ACC MỚI!", tokenHex, lastWiped]);
                            }
                        } else {
                            logAudit(@"APNS-STATUS", [NSString stringWithFormat:@"ℹ️ [ĐÃ BẮT TOKEN ĐẦU TIÊN] Token APNs hiện tại của máy: %@ (Đã lưu làm mốc. Hãy vào Settings bấm Wipe để bắt đầu chu trình đổi token).", tokenHex]);
                        }

                        s.currentAPNsToken = tokenHex;
                        s.lastKnownAPNsToken = tokenHex;
                        s.apnsRotatedStatus = statusStr;
                        [s saveSettings];
                        chmod([GLOBAL_PREFS_PATH UTF8String], 0666);
                        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.sonhu.zalotweak/settingschanged"), NULL, NULL, YES);

                        static NSString *s_lastAlertedAPNsToken = nil;
                        static BOOL s_isAlertPresenting = NO;
                        if (!s_isAlertPresenting && (!s_lastAlertedAPNsToken || ![s_lastAlertedAPNsToken isEqualToString:tokenHex])) {
                            s_isAlertPresenting = YES;
                            s_lastAlertedAPNsToken = [tokenHex copy];
                            NSString *capturedHex = [tokenHex copy];
                            NSString *capturedLastWiped = [lastWiped copy];
                            NSString *capturedStatus = [statusStr copy];

                            dispatch_async(dispatch_get_main_queue(), ^{

                                NSString *tokenShort = (capturedHex.length > 14) ? [NSString stringWithFormat:@"%@...%@", [capturedHex substringToIndex:7], [capturedHex substringFromIndex:capturedHex.length - 7]] : capturedHex;
                                NSString *oldShort = (capturedLastWiped.length > 14) ? [NSString stringWithFormat:@"%@...%@", [capturedLastWiped substringToIndex:7], [capturedLastWiped substringFromIndex:capturedLastWiped.length - 7]] : (capturedLastWiped ?: @"(Trống)");

                                ZTSettings *st = [ZTSettings sharedSettings];
                                NSString *curVoip = st.currentVoIPToken;
                                NSString *curZcid = st.currentZCID;
                                NSString *voipShort = (curVoip.length > 14) ? [NSString stringWithFormat:@"%@...%@", [curVoip substringToIndex:7], [curVoip substringFromIndex:curVoip.length - 7]] : (curVoip.length > 0 ? curVoip : @"Chờ Zalo đăng ký cuộc gọi...");
                                NSString *zcidShort = (curZcid.length > 14) ? [NSString stringWithFormat:@"%@...", [curZcid substringToIndex:14]] : (curZcid.length > 0 ? curZcid : @"Tự sinh khi gửi gói tin đầu");

                                UIAlertController *alert = nil;
                                if ([capturedStatus isEqualToString:@"ROTATED_NEW"]) {
                                    NSString *alertMsg = [NSString stringWithFormat:@"Apple đã cấp Token Push mới hoàn toàn!\n\n"
                                                          @"• APNs Token Mới: %@\n"
                                                          @"• APNs Token Cũ: %@\n"
                                                          @"• PushKit VoIP: %@\n"
                                                          @"• Định Danh zcid: %@\n\n"
                                                          @"✅ AN TOÀN TUYỆT ĐỐI ĐỂ ĐĂNG KÝ TÀI KHOẢN MỚI!", tokenShort, oldShort, voipShort, zcidShort];
                                    alert = [UIAlertController alertControllerWithTitle:@"🟢 APNs TOKEN MỚI (100% SẠCH)"
                                                                                message:alertMsg
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                                    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                                        s_isAlertPresenting = NO;
                                    }]];
                                } else if ([capturedStatus isEqualToString:@"DUPLICATE"]) {
                                    NSString *alertMsg = [NSString stringWithFormat:@"Token Push nhận từ Apple TRÙNG 100%% với nick trước!\n\n"
                                                          @"• APNs Trùng: %@\n"
                                                          @"• PushKit VoIP: %@\n\n"
                                                          @"⚠️ TUYỆT ĐỐI CHƯA ĐĂNG KÝ TÀI KHOẢN MỚI!\n"
                                                          @"Apple vẫn lưu cache push của máy. Vui lòng bật và tắt Chế Độ Máy Bay trong 5 giây, sau đó vào Cài đặt (Settings) -> ZaloTweak bấm Wipe lại!", tokenShort, voipShort];
                                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🔴 CẢNH BÁO: TOKEN APNs BỊ TRÙNG!"
                                                                                                   message:alertMsg
                                                                                            preferredStyle:UIAlertControllerStyleAlert];
                                    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Rõ (Tôi sẽ Wipe lại)" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
                                        s_isAlertPresenting = NO;
                                    }]];
                                } else {
                                    NSString *alertMsg = [NSString stringWithFormat:@"Đã ghi nhận Token Push ban đầu của thiết bị làm mốc đối chiếu:\n\n"
                                                          @"• APNs Token: %@\n"
                                                          @"• PushKit VoIP: %@\n"
                                                          @"• Định Danh zcid: %@\n\n"
                                                          @"ℹ️ Hãy vào Cài Đặt (Settings) -> ZaloTweak bấm Wipe để cấp máy mới và đổi Token Push.", tokenShort, voipShort, zcidShort];
                                    alert = [UIAlertController alertControllerWithTitle:@"ℹ️ ĐÃ LƯU TOKEN APNs BAN ĐẦU"
                                                                                message:alertMsg
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                                    [alert addAction:[UIAlertAction actionWithTitle:@"Đã Hiểu" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                                        s_isAlertPresenting = NO;
                                    }]];
                                }
                                __block void (^tryPresentAlert)(void) = nil;
                                __block int retryCount = 0;
                                tryPresentAlert = ^{
                                    UIViewController *topVC = ZTGetTopViewController();
                                    while (topVC.presentedViewController) {
                                        topVC = topVC.presentedViewController;
                                    }

                                    BOOL canPresent = NO;
                                    if (topVC && topVC.view.window && !topVC.isBeingPresented && !topVC.isBeingDismissed) {
                                        if (![topVC isKindOfClass:[UIAlertController class]]) {
                                            canPresent = YES;
                                        }
                                    }

                                    if (canPresent) {
                                        @try {
                                            [topVC presentViewController:alert animated:YES completion:nil];
                                            tryPresentAlert = nil;
                                        } @catch (NSException *ex) {
                                            NSLog(@"[ZaloTweak-APNs] Bắt exception khi present alert: %@", ex.reason);
                                            if (retryCount < 15) {
                                                retryCount++;
                                                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), tryPresentAlert);
                                            } else {
                                                s_isAlertPresenting = NO;
                                                tryPresentAlert = nil;
                                            }
                                        }
                                    } else if (retryCount < 15) {
                                        retryCount++;
                                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), tryPresentAlert);
                                    } else {
                                        s_isAlertPresenting = NO;
                                        tryPresentAlert = nil;
                                    }
                                };
                                tryPresentAlert();
                            });
                        }
                    }
                    if (origImp) {
                        origImp(self_del, regSel, app, realToken);
                    }
                });
                method_setImplementation(regMethod, customRegImp);
            }

            SEL bgSel = @selector(applicationDidEnterBackground:);
            Method bgMethod = class_getInstanceMethod(delClass, bgSel);
            if (bgMethod) {
                typedef void (*OrigBgIMP)(id, SEL, UIApplication *);
                OrigBgIMP origBg = (OrigBgIMP)method_getImplementation(bgMethod);
                IMP customBg = imp_implementationWithBlock(^(id self_del, UIApplication *app) {
                    logAudit(@"APP-LIFECYCLE", @"⏸️ [BACKGROUND] Zalo chuyển vào chạy ngầm (DidEnterBackground) -> Đang gia hạn Task & xả buffer log...");
                    renew_background_task_assertion();
                    flush_audit_and_har_queues_sync();
                    if (origBg) origBg(self_del, bgSel, app);
                });
                method_setImplementation(bgMethod, customBg);
            }

            SEL termSel = @selector(applicationWillTerminate:);
            Method termMethod = class_getInstanceMethod(delClass, termSel);
            if (termMethod) {
                typedef void (*OrigTermIMP)(id, SEL, UIApplication *);
                OrigTermIMP origTerm = (OrigTermIMP)method_getImplementation(termMethod);
                IMP customTerm = imp_implementationWithBlock(^(id self_del, UIApplication *app) {
                    handle_app_termination_event("applicationWillTerminate");
                    if (origTerm) origTerm(self_del, termSel, app);
                });
                method_setImplementation(termMethod, customTerm);
            }
        }
        if (!is_original_zalo_app()) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                deliver_clone_apns_token_to_delegate(self, delegate);
            });
        } else {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if ([self respondsToSelector:@selector(registerForRemoteNotifications)]) {
                    logAudit(@"APNS-INIT", @"🚀 [PRE-CHECK] Chủ động kích hoạt registerForRemoteNotifications để kiểm tra Token Push trước khi đăng ký...");
                    [self registerForRemoteNotifications];
                }
            });
        }
    }
    %orig;
}

- (void)_handleApplicationSuspend:(id)arg1 eventType:(int)arg2 {
    logAudit(@"APP-LIFECYCLE", @"⏸️ [SUSPEND] Zalo nhận sự kiện tạm dừng hệ thống -> Đã xả buffer log an toàn ✅");
    flush_audit_and_har_queues_sync();
    %orig;
}

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

%hook UNNotificationServiceExtension

- (void)didReceiveNotificationRequest:(UNNotificationRequest *)request withContentHandler:(void (^)(UNNotificationContent *contentToDeliver))contentHandler {
    if (request && request.content) {
        NSDictionary *userInfo = request.content.userInfo;
        NSString *title = request.content.title ?: @"";
        NSString *body = request.content.body ?: @"";
        NSString *jsonStr = @"";
        if (userInfo) {
            @try {
                NSData *jd = [NSJSONSerialization dataWithJSONObject:userInfo options:0 error:nil];
                if (jd) jsonStr = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding];
            } @catch (NSException *e) {}
        }
        logAudit(@"PUSH-EXTENSION", [NSString stringWithFormat:@"📬 [PUSH-ON-TERMINATED] Nhận Push Notification khi app đóng: Title='%@' Body='%@' Payload=%@", title, body, jsonStr]);
        flush_audit_and_har_queues_sync();
    }
    %orig;
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
            chmod([harPath UTF8String], 0666);
            if (![harPath isEqualToString:@"/var/mobile/Documents/ZaloTraffic.har"]) {
                @try {
                    [jsonData writeToFile:@"/var/mobile/Documents/ZaloTraffic.har" atomically:YES];
                    chmod("/var/mobile/Documents/ZaloTraffic.har", 0666);
                } @catch (NSException *e) {}
            }
        }
    });
}

static NSInteger s_runtime_last_centralized_status = 0;
static NSString *s_runtime_last_centralized_did = nil;
static NSInteger s_runtime_qos_error_count = 0;

__attribute__((visibility("default"))) NSInteger zt_get_last_centralized_status(void) {
    return s_runtime_last_centralized_status;
}

__attribute__((visibility("default"))) NSString *zt_get_last_centralized_did(void) {
    if (s_runtime_last_centralized_did && s_runtime_last_centralized_did.length > 0) {
        return s_runtime_last_centralized_did;
    }
    return [ZTSettings sharedSettings].centralizedDid;
}

__attribute__((visibility("default"))) NSInteger zt_get_qos_error_count(void) {
    return s_runtime_qos_error_count;
}

__attribute__((visibility("default"))) void zt_reset_runtime_counters(void) {
    s_runtime_last_centralized_status = 0;
    s_runtime_last_centralized_did = nil;
    s_runtime_qos_error_count = 0;
}

__attribute__((visibility("default"))) void zt_log_audit(NSString *category, NSString *detail) {
    logAudit(category, detail);
}

static void record_har_traffic(NSURLRequest *request, NSData *reqBody, NSURLResponse *response, NSData *respData, NSError *error, NSDate *startDate, NSDate *finishDate) {
    if (!request || !request.URL) return;
    if ([request valueForHTTPHeaderField:@"X-ZT-Diagnostic"]) return;

    NSURL *url = request.URL;
    NSString *urlStr = url.absoluteString ?: @"";

    NSInteger statusCode = 0;
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        statusCode = ((NSHTTPURLResponse *)response).statusCode;
    } else if (error) {
        statusCode = error.code;
    }

    if ([urlStr containsString:@"centralized.zaloapp.com"]) {
        s_runtime_last_centralized_status = statusCode;
        if (respData && respData.length > 0) {
            @try {
                id jObj = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
                if ([jObj isKindOfClass:[NSDictionary class]]) {
                    id dataObj = jObj[@"data"];
                    if ([dataObj isKindOfClass:[NSDictionary class]]) {
                        NSString *did = dataObj[@"deviceId"] ?: (dataObj[@"dId"] ?: dataObj[@"did"]);
                        if (did && did.length > 0) {
                            s_runtime_last_centralized_did = [did copy];
                            if (![[ZTSettings sharedSettings].centralizedDid isEqualToString:did]) {
                                [ZTSettings sharedSettings].centralizedDid = [did copy];
                                [[ZTSettings sharedSettings] saveSettings];
                            }
                        }
                    }
                }
            } @catch (NSException *e) {}
        }
    }
    if ([urlStr containsString:@"qos-talk.123c.vn"]) {
        s_runtime_qos_error_count++;
    }

    if (![ZTSettings sharedSettings].enableAuditLog) return;
    NSString *method = request.HTTPMethod ?: @"GET";

    NSTimeInterval duration = finishDate ? [finishDate timeIntervalSinceDate:startDate] : 0;
    uint64_t durationMs = (uint64_t)(duration * 1000.0);

    NSHTTPURLResponse *httpResp = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
    statusCode = httpResp ? httpResp.statusCode : (error ? error.code : 0);
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
            NSArray<NSString *> *parts = [devId componentsSeparatedByString:@"-"];
            BOOL alreadyClean = NO;
            if (parts.count == 3) {
                NSString *p0 = parts[0], *p1 = parts[1], *p2 = parts[2];
                uint64_t sec0 = (uint64_t)strtoull([p0 UTF8String], NULL, 10) / 1000ULL;
                if (![p0 isEqualToString:p1] && ![p1 isEqualToString:p2] && ![p0 isEqualToString:p2] &&
                    ![p0 hasSuffix:@"000"] && ![p1 hasSuffix:@"000"] && ![p2 hasSuffix:@"000"] &&
                    sec0 >= fakeBirth && sec0 <= fakeBirth + 86400ULL) {
                    alreadyClean = YES;
                }
            }
            if (alreadyClean) {
                logAudit(@"ZAID-RADAR", [NSString stringWithFormat:@"[NSJSONSerialization] device_id từ ZAM3914 đã đồng bộ chuẩn 100%%: %@", devId]);
                return %orig;
            }
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

    // 1. Kiểm tra và bẻ lái Header extInfo (chỉ khử tên mã phần cứng thật nếu bị lọt, KHÔNG tự bịa dId hay sửa lệch mno với Body đã ký sig)
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
        NSString *mnoCode = (settings.carrierMCC.length > 0 && settings.carrierMNC.length > 0) ?
            [NSString stringWithFormat:@"%@%@", settings.carrierMCC, settings.carrierMNC] : @"45204";
        if ([newExt containsString:@"\"mno\":\"\""]) {
            NSString *mnoStr = [NSString stringWithFormat:@"\"mno\":\"%@\"", mnoCode];
            [newExt replaceOccurrencesOfString:@"\"mno\":\"\"" withString:mnoStr options:0 range:NSMakeRange(0, newExt.length)];
            extModified = YES;
            logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã điền MNO chuẩn ITU vào Header extInfo: %@", mnoCode]);
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

    // 3. Khử rò rỉ ngôn ngữ Tiếng Việt trong Header Accept-Language nếu Profile là Mỹ / Quốc tế
    NSString *acceptLang = [mutReq valueForHTTPHeaderField:@"Accept-Language"];
    if (acceptLang) {
        BOOL isUSRegion = [settings.regionMode isEqualToString:@"US"] || [settings.regionMode isEqualToString:@"US_STUDENT"];
        BOOL isPLRegion = [settings.regionMode isEqualToString:@"PL"];
        if (isUSRegion && ([acceptLang containsString:@"vi-VN"] || [acceptLang containsString:@"vi;"] || [acceptLang containsString:@"vi,"])) {
            [mutReq setValue:@"en-US,en;q=0.9" forHTTPHeaderField:@"Accept-Language"];
            modified = YES;
            logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã khử rò rỉ tiếng Việt trong Accept-Language: '%@' -> [ĐÃ CHUẨN HOÁ] en-US,en;q=0.9", acceptLang]);
        } else if (isPLRegion && ([acceptLang containsString:@"vi-VN"] || [acceptLang containsString:@"vi;"])) {
            [mutReq setValue:@"pl-PL,pl;q=0.9,en;q=0.8" forHTTPHeaderField:@"Accept-Language"];
            modified = YES;
            logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã khử rò rỉ tiếng Việt trong Accept-Language: '%@' -> [ĐÃ CHUẨN HOÁ] pl-PL,pl;q=0.9,en;q=0.8", acceptLang]);
        }
    }

    // 4. Giám sát & đối chiếu Header zcid do Zalo tự đọc thông số máy mới sinh ra
    NSString *hdrZcid = [mutReq valueForHTTPHeaderField:@"zcid"];
    if (hdrZcid && hdrZcid.length > 0) {
        if (settings.lastWipedZCID.length > 0 && [settings.lastWipedZCID isEqualToString:hdrZcid]) {
            logAudit(@"ZCID-AUDIT", [NSString stringWithFormat:@"⚠️ [CẢNH BÁO DEBUG] zcid BỊ TRÙNG VỚI NICK TRƯỚC: %@... (Chưa xoay được zcid)", [hdrZcid substringToIndex:MIN(24, (int)hdrZcid.length)]]);
        } else if (![settings.currentZCID isEqualToString:hdrZcid]) {
            settings.currentZCID = hdrZcid;
            [settings saveSettings];
            logAudit(@"ZCID-AUDIT", [NSString stringWithFormat:@"✨ [ZCID CHÍNH HÃNG MỚI] Zalo đã tự đọc thông số máy mới & tự sinh zcid: %@... (Độ dài: %lu hex chars) ✅", [hdrZcid substringToIndex:MIN(24, (int)hdrZcid.length)], (unsigned long)hdrZcid.length]);
        }
    }

    // 5. Khử rò rỉ model máy thật, múi giờ và ngôn ngữ trong Body nếu gửi lên centralized.zaloapp.com
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

                // Chuẩn hoá múi giờ gửi lên centralized.zaloapp.com telemetry
                BOOL isUSRegion = [settings.regionMode isEqualToString:@"US"] || [settings.regionMode isEqualToString:@"US_STUDENT"];
                if ((settings.enableFakeTimeZone || isUSRegion) && settings.timeZoneName.length > 0) {
                    NSString *targetTZ = settings.timeZoneName;
                    NSString *escapedTargetTZ = [targetTZ stringByReplacingOccurrencesOfString:@"/" withString:@"\\/"];
                    // 1. Raw JSON
                    if ([mutBody containsString:@"\"tz\":\"Asia\\/Ho_Chi_Minh\""] || [mutBody containsString:@"\"tz\":\"Asia/Ho_Chi_Minh\""]) {
                        [mutBody replaceOccurrencesOfString:@"\"tz\":\"Asia\\/Ho_Chi_Minh\"" withString:[NSString stringWithFormat:@"\"tz\":\"%@\"", escapedTargetTZ] options:0 range:NSMakeRange(0, mutBody.length)];
                        [mutBody replaceOccurrencesOfString:@"\"tz\":\"Asia/Ho_Chi_Minh\"" withString:[NSString stringWithFormat:@"\"tz\":\"%@\"", targetTZ] options:0 range:NSMakeRange(0, mutBody.length)];
                        bodyModified = YES;
                        logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã khử rò rỉ múi giờ VN 'Asia/Ho_Chi_Minh' trong centralized telemetry -> [ĐÃ FAKE] %@", targetTZ]);
                    }
                    // 2. URL-encoded (%22tz%22%3A%22...%22)
                    NSRange encTzRange = [mutBody rangeOfString:@"%22tz%22%3A%22(.*?)%22" options:NSRegularExpressionSearch];
                    if (encTzRange.location != NSNotFound) {
                        NSString *matchedTzParam = [mutBody substringWithRange:encTzRange];
                        if ([matchedTzParam containsString:@"Asia"] || [matchedTzParam containsString:@"Ho%5FChi%5FMinh"] || [matchedTzParam containsString:@"Ho_Chi_Minh"]) {
                            NSString *encTargetTZ = [targetTZ stringByReplacingOccurrencesOfString:@"/" withString:@"%5C%2F"];
                            NSString *repTzParam = [NSString stringWithFormat:@"%%22tz%%22%%3A%%22%@%%22", encTargetTZ];
                            [mutBody replaceOccurrencesOfString:matchedTzParam withString:repTzParam options:0 range:NSMakeRange(0, mutBody.length)];
                            bodyModified = YES;
                            logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã chuẩn hóa múi giờ URL-encoded trong centralized -> [ĐÃ FAKE] %@", targetTZ]);
                        }
                    }
                }

                // Đồng bộ độ phân giải màn hình (ss / screenSize)
                if (settings.spoofedScreenSize.length > 0) {
                    NSRange ssFormRange = [mutBody rangeOfString:@"screenSize=\\d+x\\d+" options:NSRegularExpressionSearch];
                    if (ssFormRange.location != NSNotFound) {
                        NSString *oldSs = [mutBody substringWithRange:ssFormRange];
                        NSString *newSs = [NSString stringWithFormat:@"screenSize=%@", settings.spoofedScreenSize];
                        if (![oldSs isEqualToString:newSs]) {
                            [mutBody replaceOccurrencesOfString:oldSs withString:newSs options:0 range:NSMakeRange(0, mutBody.length)];
                            bodyModified = YES;
                        }
                    }
                    NSRange ssEncRange = [mutBody rangeOfString:@"%22ss%22%3A%22\\d+x\\d+%22" options:NSRegularExpressionSearch];
                    if (ssEncRange.location != NSNotFound) {
                        NSString *oldSs = [mutBody substringWithRange:ssEncRange];
                        NSString *newSs = [NSString stringWithFormat:@"%%22ss%%22%%3A%%22%@%%22", settings.spoofedScreenSize];
                        if (![oldSs isEqualToString:newSs]) {
                            [mutBody replaceOccurrencesOfString:oldSs withString:newSs options:0 range:NSMakeRange(0, mutBody.length)];
                            bodyModified = YES;
                        }
                    }
                }

                // Chuẩn hóa device_id trong centralized zaid telemetry
                if ([mutBody containsString:@"1674575222"] || (settings.birthTimeSec > 0 && [mutBody containsString:@"device_id"])) {
                    uint64_t bTime = (settings.birthTimeSec > 1400000000ULL) ? settings.birthTimeSec : 1690000000ULL;
                    uint64_t ts1 = bTime * 1000ULL + (uint64_t)arc4random_uniform(999);
                    uint64_t ts2 = ts1 + 1600000ULL + (uint64_t)arc4random_uniform(800000);
                    uint64_t ts3 = ts2 + 400000ULL + (uint64_t)arc4random_uniform(400000);
                    NSString *newDevId = [NSString stringWithFormat:@"%llu-%llu-%llu", ts1, ts2, ts3];

                    NSRange devIdEncRange = [mutBody rangeOfString:@"%22device(?:%5F|_)id%22%3A%22(.*?)%22" options:NSRegularExpressionSearch];
                    if (devIdEncRange.location != NSNotFound) {
                        NSString *oldDevIdParam = [mutBody substringWithRange:devIdEncRange];
                        NSString *encNewDevId = [newDevId stringByReplacingOccurrencesOfString:@"-" withString:@"%2D"];
                        NSString *repDevIdParam = [NSString stringWithFormat:@"%%22device%%5Fid%%22%%3A%%22%@%%22", encNewDevId];
                        [mutBody replaceOccurrencesOfString:oldDevIdParam withString:repDevIdParam options:0 range:NSMakeRange(0, mutBody.length)];
                        bodyModified = YES;
                        logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã chuẩn hóa device_id trong centralized telemetry -> [ĐỒNG BỘ THEO MÁY MỚI] %@", newDevId]);
                    }
                    NSRange devIdRawRange = [mutBody rangeOfString:@"\"device_id\":\"(.*?)\"" options:NSRegularExpressionSearch];
                    if (devIdRawRange.location != NSNotFound) {
                        NSString *oldDevIdParam = [mutBody substringWithRange:devIdRawRange];
                        NSString *repDevIdParam = [NSString stringWithFormat:@"\"device_id\":\"%@\"", newDevId];
                        [mutBody replaceOccurrencesOfString:oldDevIdParam withString:repDevIdParam options:0 range:NSMakeRange(0, mutBody.length)];
                        bodyModified = YES;
                        logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã chuẩn hóa device_id trong centralized telemetry -> [ĐỒNG BỘ THEO MÁY MỚI] %@", newDevId]);
                    }
                }

                if (isUSRegion) {
                    if ([mutBody containsString:@"\"lang\":\"vi-VN\""] || [mutBody containsString:@"\"lang\":\"vi_VN\""]) {
                        [mutBody replaceOccurrencesOfString:@"\"lang\":\"vi-VN\"" withString:@"\"lang\":\"en-US\"" options:0 range:NSMakeRange(0, mutBody.length)];
                        [mutBody replaceOccurrencesOfString:@"\"lang\":\"vi_VN\"" withString:@"\"lang\":\"en-US\"" options:0 range:NSMakeRange(0, mutBody.length)];
                        bodyModified = YES;
                        logAudit(@"OUTBOUND-SANITIZE", @"Đã khử rò rỉ ngôn ngữ vi-VN trong centralized telemetry -> [ĐÃ FAKE] en-US");
                    }
                }

                NSString *mnoCode = (settings.carrierMCC.length > 0 && settings.carrierMNC.length > 0) ?
                    [NSString stringWithFormat:@"%@%@", settings.carrierMCC, settings.carrierMNC] : @"45204";
                if ([mutBody containsString:@"\"mno\":\"\""]) {
                    NSString *mnoStr = [NSString stringWithFormat:@"\"mno\":\"%@\"", mnoCode];
                    [mutBody replaceOccurrencesOfString:@"\"mno\":\"\"" withString:mnoStr options:0 range:NSMakeRange(0, mutBody.length)];
                    bodyModified = YES;
                    logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã điền MNO chuẩn ITU vào centralized telemetry body: %@", mnoCode]);
                }

                // Tạo độ trễ tự nhiên giữa firstTimeInstallApp và firstTimeOpenApp nếu chúng trùng khít ms
                if ([mutBody containsString:@"\"firstTimeInstallApp\""] && [mutBody containsString:@"\"firstTimeOpenApp\""]) {
                    NSRange rOpen = [mutBody rangeOfString:@"\"firstTimeOpenApp\":\"(\\d+)\"" options:NSRegularExpressionSearch];
                    NSRange rInst = [mutBody rangeOfString:@"\"firstTimeInstallApp\":\"(\\d+)\"" options:NSRegularExpressionSearch];
                    if (rOpen.location != NSNotFound && rInst.location != NSNotFound) {
                        NSString *sOpen = [mutBody substringWithRange:rOpen];
                        NSString *sInst = [mutBody substringWithRange:rInst];
                        NSScanner *scanO = [NSScanner scannerWithString:sOpen];
                        NSScanner *scanI = [NSScanner scannerWithString:sInst];
                        [scanO scanUpToCharactersFromSet:[NSCharacterSet decimalDigitCharacterSet] intoString:nil];
                        [scanI scanUpToCharactersFromSet:[NSCharacterSet decimalDigitCharacterSet] intoString:nil];
                        unsigned long long tOpen = 0, tInst = 0;
                        if ([scanO scanUnsignedLongLong:&tOpen] && [scanI scanUnsignedLongLong:&tInst]) {
                            if (tOpen == tInst && tOpen > 1000000000000ULL) {
                                unsigned long long offset = 35000ULL + (unsigned long long)arc4random_uniform(40000);
                                unsigned long long naturalInstall = tOpen - offset;
                                NSString *oldInstField = [NSString stringWithFormat:@"\"firstTimeInstallApp\":\"%llu\"", tInst];
                                NSString *newInstField = [NSString stringWithFormat:@"\"firstTimeInstallApp\":\"%llu\"", naturalInstall];
                                [mutBody replaceOccurrencesOfString:oldInstField withString:newInstField options:0 range:NSMakeRange(0, mutBody.length)];
                                bodyModified = YES;
                                logAudit(@"OUTBOUND-SANITIZE", [NSString stringWithFormat:@"Đã tạo độ trễ tự nhiên: firstTimeInstallApp lùi %llus so với firstTimeOpenApp", offset / 1000ULL]);
                            }
                        }
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

            NSString *oldMcc = [NSString stringWithFormat:@"%@", mccDict[@"mcc"] ?: @""];
            NSString *oldMnc = [NSString stringWithFormat:@"%@", mccDict[@"mnc"] ?: @""];

            // Nếu đang Tắt Fake Múi Giờ và GeoIP máy chủ báo khác quốc gia với SIM Profile,
            // giữ nguyên phản hồi gốc của Server để tránh xung đột cờ quốc gia giữa Client và Server!
            if (oldMcc.length > 0 && ![oldMcc isEqualToString:s.carrierMCC] && !s.enableFakeTimeZone) {
                logAudit(@"MNC-NORMALIZER", [NSString stringWithFormat:@"⚠️ GeoIP Server trả về MCC '%@' (MNC '%@') khác SIM Profile %@/%@ -> [GIỮ NGUYÊN GEOIP SERVER ĐỂ TRÁNH LỆCH PHA]", oldMcc, oldMnc, s.carrierMCC, s.carrierMNC]);
                return origRespData;
            }

            mccDict[@"mcc"] = s.carrierMCC;
            mccDict[@"mnc"] = s.carrierMNC;

            if ([s.regionMode isEqualToString:@"US"] || [s.regionMode isEqualToString:@"US_STUDENT"]) {
                mccDict[@"isocountrycodes"] = @"US/USA";
                mccDict[@"countrycode"] = @(1);
                mccDict[@"country"] = @"United States";
            } else if ([s.regionMode isEqualToString:@"PL"]) {
                mccDict[@"isocountrycodes"] = @"PL/POL";
                mccDict[@"countrycode"] = @(48);
                mccDict[@"country"] = @"Poland";
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
    if (request && request.URL) {
        NSString *absUrl = request.URL.absoluteString;
        if ([absUrl containsString:@"talk-m.zaloapp.com/api/fcm"] && [absUrl containsString:@"method=submitToken"]) {
            NSString *curVoipToken = @"";
            NSURLComponents *components = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
            for (NSURLQueryItem *item in components.queryItems) {
                if ([item.name isEqualToString:@"token"]) {
                    curVoipToken = item.value ?: @"";
                    break;
                }
            }
            if (curVoipToken.length > 0) {
                ZTSettings *st = [ZTSettings sharedSettings];
                NSString *status = @"";
                if (st.lastWipedVoIPToken.length > 0 && [st.lastWipedVoIPToken isEqualToString:curVoipToken]) {
                    status = @"⚠️ [TRÙNG LẶP VỚI LẦN TRƯỚC - ĐANG DÙNG CHUNG PHẦN CỨNG]";
                    logAudit(@"PUSH-TOKEN-DEBUG", [NSString stringWithFormat:@"⚠️ [DEBUG] VoIP Token trùng lặp với nick trước: %@ (Đang gửi lên VNG)", curVoipToken]);
                } else {
                    status = @"✨ [TOKEN MỚI TỪ APPLE / ĐƯỢC CẤP LẠI]";
                    logAudit(@"PUSH-TOKEN-DEBUG", [NSString stringWithFormat:@"✅ [DEBUG] VoIP Token mới độc nhất: %@ (Đang gửi lên VNG)", curVoipToken]);
                }
                st.currentVoIPToken = curVoipToken;
                [st saveSettings];
                logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"📞 [VOIP PUSH SUBMIT] %@ Token: %@ (Đang gửi lên server VNG tự nhiên)", status, curVoipToken]);
            }
            if (is_tweak_active() && !is_original_zalo_app()) {
                logAudit(@"PUSH-TOKEN", @"[PUSH-PROTECT] Đã chặn submitToken của Zalo Clone gửi ra Internet (Triệt tiêu 100% BadDeviceToken Apple) ✅");
                return %orig([NSURLRequest requestWithURL:[NSURL URLWithString:@"about:blank"]]);
            }
        }
    }
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
    if (is_tweak_active() && !is_original_zalo_app() && request && request.URL) {
        NSString *absUrl = request.URL.absoluteString;
        if ([absUrl containsString:@"talk-m.zaloapp.com/api/fcm"] && [absUrl containsString:@"method=submitToken"]) {
            logAudit(@"PUSH-TOKEN", @"[PUSH-PROTECT] Đã chặn submitToken của Zalo Clone gửi ra Internet (Triệt tiêu 100% BadDeviceToken Apple) ✅");
            NSData *mockResp = [@"{\"error_code\":0,\"error_message\":\"Successful.\",\"data\":1}" dataUsingEncoding:NSUTF8StringEncoding];
            NSHTTPURLResponse *mockHttp = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Content-Type": @"application/json"}];
            if (completionHandler) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completionHandler(mockResp, mockHttp, nil);
                });
            }
            return %orig([NSURLRequest requestWithURL:[NSURL URLWithString:@"about:blank"]], nil);
        }
    }
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
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                UIViewController *presenter = ZTGetTopViewController() ?: self;
                if (!presenter || !presenter.view.window) return;
                ZTSettings *s = [ZTSettings sharedSettings];
                NSString *rDesc = [s.regionMode isEqualToString:@"US_STUDENT"] ? @"Du Học Sinh Mỹ (+1)" :
                                  ([s.regionMode isEqualToString:@"US"] ? @"Hoa Kỳ (+1)" :
                                  ([s.regionMode isEqualToString:@"PL"] ? @"Ba Lan (+48)" : @"Việt Nam (+84)"));
                NSString *welcomeMsg = [NSString stringWithFormat:
                    @"🎉 THIẾT BỊ MỚI TINH ĐÃ KÍCH HOẠT!\n\n"
                    @"• Tên máy: %@\n"
                    @"• SIM & Vùng: %@ (%@ - MCC %@)\n"
                    @"• IDFV Mới: %@\n"
                    @"• IDFA: 00000000-0000-0000-0000-000000000000 (Apple ATT Denied)\n"
                    @"• PushKit VoIP: Sẵn sàng nhận token cuộc gọi ⏳\n"
                    @"• Định Danh zcid: Tự sinh mới khi gửi gói tin đầu ⏳\n\n"
                    @"🟢 Môi trường sạch sẽ 100%%, sẵn sàng Reg Acc an toàn!",
                    s.deviceName, rDesc, s.carrierName, s.carrierMCC, s.spoofedIDFV];
                
                UIAlertController *wAlert = [UIAlertController alertControllerWithTitle:@"⚡ ZALOTWEAK COLD-BOOT"
                                                                                message:welcomeMsg
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                [wAlert addAction:[UIAlertAction actionWithTitle:@"Bắt Đầu Sử Dụng" style:UIAlertActionStyleDefault handler:nil]];
                [presenter presentViewController:wAlert animated:YES completion:nil];
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
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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

static void pushUnregisterCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([[UIApplication sharedApplication] respondsToSelector:@selector(unregisterForRemoteNotifications)]) {
            logAudit(@"APNS-ROTATE", @"📡 [SETTINGS-WIPE] Nhận tín hiệu từ Cài đặt -> Hủy đăng ký push với Apple và xả RunLoop Mach IPC...");
            [[UIApplication sharedApplication] unregisterForRemoteNotifications];
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.18]];
        }
        exit(0);
    });
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

static NSArray<NSString *> *s_discovered_security_modules = nil;

static NSArray<NSString *> *perform_zalo_security_modules_scan_now(void) {
    if (!ZTSecurityCheckLicenseFast()) {
        return @[@"🔒 Yêu cầu kích hoạt bản quyền để sử dụng tính năng Quét Module Bảo Mật!"];
    }
    int numClasses = objc_getClassList(NULL, 0);
    if (numClasses <= 0) return @[];
    Class *classes = (Class *)malloc(sizeof(Class) * numClasses);
    if (!classes) return @[];
    numClasses = objc_getClassList(classes, numClasses);

    NSMutableArray *foundModules = [NSMutableArray array];

    for (int i = 0; i < numClasses; i++) {
        Class cls = classes[i];
        const char *clsName = class_getName(cls);
        if (!clsName) continue;

        const char *imgName = class_getImageName(cls);
        if (!imgName) continue;
        // Chỉ quét các class thuộc Zalo hoặc Frameworks nhúng của Zalo
        if (!strcasestr(imgName, "Zalo") && !strcasestr(imgName, "ZDK") && !strcasestr(imgName, "zingalo")) {
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
            strcasestr(clsName, "Telemetry") ||
            strcasestr(clsName, "Fraud") ||
            strcasestr(clsName, "Tamper") ||
            strcasestr(clsName, "Hook")) {
            [foundModules addObject:[NSString stringWithUTF8String:clsName]];
        }
    }
    free(classes);

    [foundModules sortUsingSelector:@selector(compare:)];
    return [foundModules copy];
}

static void scan_zalo_security_modules_async(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool {
            // Đợi 2 giây để Zalo hoàn tất nạp các dynamic frameworks vào bộ nhớ
            [NSThread sleepForTimeInterval:2.0];

            NSArray<NSString *> *modules = perform_zalo_security_modules_scan_now();
            s_discovered_security_modules = modules;

            if (modules.count > 0) {
                logAudit(@"ZALO-SECURITY-RADAR", [NSString stringWithFormat:@"🛡️ [RADAR TOÀN DIỆN] Phát hiện %lu module bảo mật/định danh của Zalo:\n   • %@", (unsigned long)modules.count, [modules componentsJoinedByString:@"\n   • "]]);
            } else {
                logAudit(@"ZALO-SECURITY-RADAR", @"🛡️ [RADAR TOÀN DIỆN] Đã quét toàn bộ binary Zalo nhưng không phát hiện module bảo mật riêng biệt.");
            }
        }
    });
}

__attribute__((visibility("default"))) NSArray<NSString *> *zt_get_discovered_security_modules(void) {
    if (s_discovered_security_modules && s_discovered_security_modules.count > 0) {
        return s_discovered_security_modules;
    }
    s_discovered_security_modules = perform_zalo_security_modules_scan_now();
    return s_discovered_security_modules;
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

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            settingsChangedCallback,
            CFSTR("com.sonhu.zalotweak/settingschanged"),
            NULL,
            CFNotificationSuspensionBehaviorCoalesce
        );

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            pushUnregisterCallback,
            CFSTR("com.sonhu.zalotweak/perform_push_unregister"),
            NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately
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
        universal_hook_c_function("statvfs", (void *)statvfs, (void *)my_statvfs, (void **)&orig_statvfs);
        universal_hook_c_function("fstatvfs", (void *)fstatvfs, (void *)my_fstatvfs, (void **)&orig_fstatvfs);
        universal_hook_c_function("access", (void *)access, (void *)my_access, (void **)&orig_access);
        universal_hook_c_function("readlink", (void *)readlink, (void *)my_readlink, (void **)&orig_readlink);
        universal_hook_c_function("readlinkat", (void *)readlinkat, (void *)my_readlinkat, (void **)&orig_readlinkat);
        universal_hook_c_function("fork", (void *)fork, (void *)my_fork, (void **)&orig_fork);
        universal_hook_c_function("stat", (void *)stat, (void *)my_stat, (void **)&orig_stat);
        universal_hook_c_function("lstat", (void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
        universal_hook_c_function("fstat", (void *)fstat, (void *)my_fstat, (void **)&orig_fstat);
        universal_hook_c_function("getattrlist", (void *)getattrlist, (void *)my_getattrlist, (void **)&orig_getattrlist);
        {
            struct rebinding inode64_rebs[] = {
                { "stat$INODE64", (void *)my_stat, NULL },
                { "lstat$INODE64", (void *)my_lstat, NULL },
                { "fstat$INODE64", (void *)my_fstat, NULL },
                { "statfs$INODE64", (void *)my_statfs, (void **)&orig_statfs },
                { "fstatfs$INODE64", (void *)my_fstatfs, (void **)&orig_fstatfs },
                { "statvfs", (void *)my_statvfs, (void **)&orig_statvfs },
                { "fstatvfs", (void *)my_fstatvfs, (void **)&orig_fstatvfs },
                { "readlink", (void *)my_readlink, (void **)&orig_readlink },
                { "readlinkat", (void *)my_readlinkat, (void **)&orig_readlinkat },
                { "fork", (void *)my_fork, (void **)&orig_fork }
            };
            rebind_symbols(inode64_rebs, 10);
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

        // Hook CoreFoundation Bundle Identifier (C-Layer Redirection cho Zalo Clone)
        universal_hook_c_function("CFBundleGetIdentifier", (void *)CFBundleGetIdentifier, (void *)my_CFBundleGetIdentifier, (void **)&orig_CFBundleGetIdentifier);
        universal_hook_c_function("CFBundleGetValueForInfoDictionaryKey", (void *)CFBundleGetValueForInfoDictionaryKey, (void *)my_CFBundleGetValueForInfoDictionaryKey, (void **)&orig_CFBundleGetValueForInfoDictionaryKey);

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

        // Hook Hardware Uptime Clocks Radar (Chế độ Radar Giám Sát, bảo vệ 100% socket mạng khỏi lỗi EINVAL 22)
        universal_hook_c_function("clock_gettime", (void *)clock_gettime, (void *)my_clock_gettime, (void **)&orig_clock_gettime);
        universal_hook_c_function("mach_continuous_time", (void *)mach_continuous_time, (void *)my_mach_continuous_time, (void **)&orig_mach_continuous_time);
        universal_hook_c_function("mach_absolute_time", (void *)mach_absolute_time, (void *)my_mach_absolute_time, (void **)&orig_mach_absolute_time);

        // Hook Anti-Debug & Process Security Radar
        void *ptrace_ptr = dlsym(RTLD_DEFAULT, "ptrace");
        if (ptrace_ptr) {
            universal_hook_c_function("ptrace", ptrace_ptr, (void *)my_ptrace, (void **)&orig_ptrace);
        }
        universal_hook_c_function("getppid", (void *)getppid, (void *)my_getppid, (void **)&orig_getppid);
        universal_hook_c_function("gethostname", (void *)gethostname, (void *)my_gethostname, (void **)&orig_gethostname);

        // Hook Dyld & dladdr (Ẩn tuyệt đối Zalotweak.dylib, Substrate, ElleKit, RootHide khỏi bộ quét anti-tamper của Zalo)
        universal_hook_c_function("_dyld_get_image_name", (void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        universal_hook_c_function("dladdr", (void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);

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

        // Khởi tạo In-App Floating Menu (Chỉ nạp khi app đã nạp xong UIKit và nhận thông báo DidFinishLaunching)
        if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
            [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                              object:nil
                                                               queue:[NSOperationQueue mainQueue]
                                                          usingBlock:^(NSNotification * _Nonnull note) {
                if ([ZTSettings sharedSettings].showFloatingMenu) {
                    [[ZTMenuManager sharedManager] setupInAppMenu];
                }
                start_battery_drain_timer_if_needed();
            }];
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

            if (!is_original_zalo_app()) {
                logAudit(@"CLONE-SYNC", @"[ZALO CLONE] Kích hoạt cơ chế chuẩn App Store: 1) Bẻ hướng C-layer CFBundleGetIdentifier & InfoDictionary -> vn.com.vng.zingalo | 2) Bẻ hướng NSBundle mainBundle -> vn.com.vng.zingalo | 3) Nạp APNs Device Token 32-byte SHA-256 | 4) Bỏ qua lỗi APNs iOS");
            }

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

            double contUp = 0, awakeUp = 0;
            get_consistent_uptimes(&contUp, &awakeUp);
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"🕒 [THỜI GIAN/Ổ ĐĨA] st_birthtime: %s (%llu) | BootTime: %s | ContCPU: %.0fs (%.1fh) | AwakeCPU: %.0fs (%.1fh) | Disk: %llu GB",
                      bTimeBuf,
                      (unsigned long long)fake_ctime,
                      bootBuf,
                      contUp, contUp / 3600.0,
                      awakeUp, awakeUp / 3600.0,
                      s.diskTotalSize / (1000000000ULL)]);

            if (!is_original_zalo_app()) {
                logAudit(@"PROFILE-SYNC", @"🛡️ [CHỐNG LIÊN KẾT NÂNG CAO] Zalo Clone: Đã chặn Token APNs Fake & Triệt tiêu submitToken (Chống Apple BadDeviceToken ban 3h) | Anti-Dyld/dladdr: Đã ẩn Zalotweak.dylib | SIM Slot: 0000000100000001");
            } else {
                logAudit(@"PROFILE-SYNC", @"🛡️ [CHỐNG LIÊN KẾT NÂNG CAO] Zalo Gốc: Bảo toàn Token Apple Gateway | Anti-Dyld/dladdr: Đã ẩn Zalotweak.dylib | SIM Slot: 0000000100000001");
            }
        }

        // Tự động quét và lập danh mục các module bảo mật nội bộ của Zalo
        scan_zalo_security_modules_async();

        s_bg_task_id = UIBackgroundTaskInvalid;

        // Đăng ký bộ bảo vệ dữ liệu khi tiến trình bị tắt / kết thúc đột ngột
        atexit(zt_atexit_handler);
        signal(SIGTERM, zt_sig_handler);
        signal(SIGINT, zt_sig_handler);
        signal(SIGABRT, zt_sig_handler);
    }
}
