#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <ifaddrs.h>
#import <net/if.h>
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
    }
    if (name) {
        struct rebinding r = { name, replace, result };
        rebind_symbols(&r, 1);
    }
}

static inline BOOL is_tweak_active(void) {
    static __thread BOOL s_in_active_check = NO;
    if (s_in_active_check) return NO;
    s_in_active_check = YES;
    BOOL active = [ZTSettings sharedSettings].enabled && [[ZTSecurityManager sharedManager] isLicenseValid];
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

static inline BOOL has_system_preferenceloader(void) {
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

// Tìm đường dẫn file cấu hình tối ưu để vượt rào Sandbox
static NSString *getConfigPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *containerPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:containerPref]) {
            return containerPref;
        }
        NSString *containerDoc = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:containerDoc]) {
            return containerDoc;
        }
        // Khi file chưa tồn tại (lần đầu chạy), luôn tạo trong Sandbox Library/Preferences
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

- (void)loadSettings {
    NSString *path = getConfigPath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (dict) {
        self.enabled = [dict[@"enabled"] boolValue];
        self.needsNewProfile = [dict[@"needsNewProfile"] boolValue];
        if (self.needsNewProfile) {
            if ([[ZTSecurityManager sharedManager] isLicenseValid]) {
                logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] Phát hiện cờ yêu cầu máy mới sau Deep Wipe -> Khởi tạo Profile mới tinh...");
                self.needsNewProfile = NO;
                self.justGeneratedColdBoot = YES;
                self.regionMode = dict[@"regionMode"] ?: @"VN";
                [self generateNewProfile];
                return;
            } else {
                logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] Chưa có bản quyền hợp lệ -> Từ chối cấp Profile mới!");
                self.needsNewProfile = NO;
            }
        }

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
        self.bootSessionUUID = dict[@"bootSessionUUID"] ?: @"";
        self.spoofedIDFV = dict[@"spoofedIDFV"] ?: [[NSUUID UUID] UUIDString];
        self.spoofedIDFA = dict[@"spoofedIDFA"] ?: @"00000000-0000-0000-0000-000000000000";
        self.profileId = dict[@"profileId"] ?: [[NSUUID UUID] UUIDString];
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
        self.spoofedSerial = dict[@"spoofedSerial"] ?: @"";
        self.spoofedWifiMAC = dict[@"spoofedWifiMAC"] ?: @"";
        self.spoofedBluetoothMAC = dict[@"spoofedBluetoothMAC"] ?: @"";

        BOOL isAppExtension = [[NSBundle mainBundle].bundlePath containsString:@".appex"];
        if (isAppExtension) {
            self.showFloatingMenu = NO;
        } else {
            // Mặc định luôn BẬT nút nổi để người dùng có icon điều khiển và fake máy (dù là JB hay Tiêm IPA)
            // Nếu người dùng chủ động tắt trong cài đặt thì mới tắt
            if (dict[@"showFloatingMenu"] != nil) {
                self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
            } else {
                self.showFloatingMenu = YES;
            }
        }

        if (!dict[@"spoofedIDFV"] || !dict[@"spoofedIDFA"] || !dict[@"profileId"] || self.bootTimeSec == 0 || self.spoofedSerial.length == 0) {
            if (self.spoofedSerial.length == 0) {
                extern NSString *generate_random_serial(void);
                extern NSString *generate_random_mac(void);
                self.spoofedSerial = generate_random_serial();
                self.spoofedWifiMAC = generate_random_mac();
                self.spoofedBluetoothMAC = generate_random_mac();
            }
            if (self.bootTimeSec == 0) {
                uint32_t randomOffset = 86400 + (arc4random_uniform(345600));
                self.bootTimeSec = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;
                self.bootSessionUUID = [[NSUUID UUID] UUIDString];
            }
            [self saveSettings];
        }
    } else {
        self.enabled = YES;
        self.enableAuditLog = NO;
        self.lastWipedIDFV = @"";
        self.lastWipedIP = @"";
        self.lastWipedTimestamp = 0;
        self.regionMode = @"VN";
        BOOL isAppExtension = [[NSBundle mainBundle].bundlePath containsString:@".appex"];
        if (!isAppExtension) {
            [self generateNewProfile];
        }
    }
}

- (void)saveSettings {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"enabled"] = @(self.enabled);
    dict[@"enableAuditLog"] = @(self.enableAuditLog);
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
    dict[@"showFloatingMenu"] = @(self.showFloatingMenu);
    dict[@"needsNewProfile"] = @(self.needsNewProfile);
    if (self.spoofedSerial) dict[@"spoofedSerial"] = self.spoofedSerial;
    if (self.spoofedWifiMAC) dict[@"spoofedWifiMAC"] = self.spoofedWifiMAC;
    if (self.spoofedBluetoothMAC) dict[@"spoofedBluetoothMAC"] = self.spoofedBluetoothMAC;
    if (self.lastWipedIDFV) dict[@"lastWipedIDFV"] = self.lastWipedIDFV;
    if (self.lastWipedIP) dict[@"lastWipedIP"] = self.lastWipedIP;
    dict[@"lastWipedTimestamp"] = @(self.lastWipedTimestamp);

    NSString *path = getConfigPath();
    [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    [dict writeToFile:path atomically:YES];

    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *localPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[localPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:localPref atomically:YES];
        NSString *localDoc = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[localDoc stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:localDoc atomically:YES];
    }
}

NSString *generate_random_serial(void) {
    return generate_apple_serial();
}

NSString *generate_random_mac(void) {
    return generate_apple_mac();
}

- (void)generateNewProfile {
    // 1. Sinh profile thiết bị từ ngân hàng 25 mẫu iPhone chuẩn phần cứng Apple
    ZTDeviceProfile *p = [ZTDeviceProfile generateRandomProfileForRegion:self.regionMode ?: @"VN"];

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
    self.batteryLevel = p.batteryLevel;
    self.batteryState = p.batteryState;
    self.bootTimeSec = p.bootTimeSec;
    self.bootSessionUUID = p.bootSessionUUID;
    self.spoofedIDFV = p.spoofedIDFV;
    self.spoofedIDFA = p.spoofedIDFA;
    self.profileId = p.profileId;
    self.spoofedSerial = p.spoofedSerial;
    self.spoofedWifiMAC = p.spoofedWifiMAC;
    self.spoofedBluetoothMAC = p.spoofedBluetoothMAC;

    logAudit(@"DEVICE-GEN", [NSString stringWithFormat:@"Đã sinh máy ngẫu nhiên mới: %@ (%@) | iOS: %@ (%@) | RAM: %.1fGB | Màn: %.0fx%.0f@%.0fx | Tên: %@",
              self.deviceMachine, self.deviceModel, self.systemVersion, self.kernOsVersion,
              (double)self.memsize / (1024.0 * 1024.0 * 1024.0),
              self.screenWidth, self.screenHeight, self.screenScale, self.deviceName]);

    [self saveSettings];
}

@end

// ==========================================
// HỆ THỐNG AUDIT LOG (KIỂM TOÁN HÀNH VI ZALO)
// ==========================================
#define GLOBAL_AUDIT_LOG_PATH @"/var/mobile/Library/Preferences/ZaloAudit.log"

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

static void logAudit(NSString *category, NSString *detail) {
    // 1. Luôn in trực tiếp ra System Console để soi trực tiếp trên 3uTools Device Console
    NSLog(@"[ZaloAudit] [%@] %@", category, detail);

    if (![ZTSettings sharedSettings].enableAuditLog) return;

    if (!auditQueue) {
        loggedAuditKeys = [[NSMutableSet alloc] init];
        auditQueue = dispatch_queue_create("com.sonhu.zalotweak.auditQueue", DISPATCH_QUEUE_SERIAL);
    }

    NSString *dedupKey = [NSString stringWithFormat:@"%@:%@", category, detail];
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

        NSString *line = [NSString stringWithFormat:@"[%@] [PID:%d] [%@] %@\n", timeStr, getpid(), category, detail];
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
            const char *val = [settings.deviceMachine UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            return 0;
        }
        if (name[1] == HW_MODEL) {
            const char *val = [settings.deviceModel UTF8String];
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

    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name || !is_tweak_active()) {
        return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    logAudit(@"DETECTION-RADAR", [NSString stringWithFormat:@"sysctlbyname('%s')", name]);

    ZTSettings *settings = [ZTSettings sharedSettings];

    if (strcmp(name, "hw.machine") == 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"hw.machine -> [ĐÃ FAKE] %@", settings.deviceMachine]);
        const char *val = [settings.deviceMachine UTF8String];
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
        const char *val = [settings.deviceModel UTF8String];
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
        const char *val = [settings.systemVersion UTF8String];
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
        const char *val = [settings.kernOsVersion UTF8String];
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

    if (strcmp(name, "kern.boottime") == 0 && settings.bootTimeSec > 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"kern.boottime -> [ĐÃ FAKE] Timestamp: %llu", settings.bootTimeSec]);
        struct timeval bt;
        bt.tv_sec = (time_t)settings.bootTimeSec;
        bt.tv_usec = 345678;
        if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
            memcpy(oldp, &bt, sizeof(struct timeval));
        }
        if (oldlenp) *oldlenp = sizeof(struct timeval);
        return 0;
    }

    if (strcmp(name, "kern.bootsessionuuid") == 0 && settings.bootSessionUUID.length > 0) {
        logAudit(@"SYSCTL", [NSString stringWithFormat:@"kern.bootsessionuuid -> [ĐÃ FAKE] %@", settings.bootSessionUUID]);
        const char *val = [settings.bootSessionUUID UTF8String];
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
        const char *val = [settings.deviceName UTF8String];
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        return 0;
    }

    logAudit(@"SYSCTL", [NSString stringWithFormat:@"%s -> [CHƯA HOOK - LẤY TỰ NHIÊN TỪ MÁY]", name]);
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int (*orig_uname)(struct utsname *buf);
static int my_uname(struct utsname *buf) {
    int ret = orig_uname(buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        strlcpy(buf->machine, [settings.deviceMachine UTF8String], sizeof(buf->machine));
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
        return orig_SecItemCopyMatching(query, result);
    }
    NSMutableDictionary *isolatedQuery = modify_keychain_query(query);
    return orig_SecItemCopyMatching((__bridge CFDictionaryRef)isolatedQuery, result);
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    if (!is_tweak_active()) {
        return orig_SecItemAdd(attributes, result);
    }
    NSMutableDictionary *isolatedAttrs = modify_keychain_query(attributes);
    return orig_SecItemAdd((__bridge CFDictionaryRef)isolatedAttrs, result);
}

static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    if (!is_tweak_active()) {
        return orig_SecItemDelete(query);
    }
    NSMutableDictionary *isolatedQuery = modify_keychain_query(query);
    return orig_SecItemDelete((__bridge CFDictionaryRef)isolatedQuery);
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    if (!is_tweak_active()) {
        return orig_SecItemUpdate(query, attributesToUpdate);
    }
    NSMutableDictionary *isolatedQuery = modify_keychain_query(query);
    NSMutableDictionary *isolatedAttrs = modify_keychain_query(attributesToUpdate);
    return orig_SecItemUpdate((__bridge CFDictionaryRef)isolatedQuery, (__bridge CFDictionaryRef)isolatedAttrs);
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
    int ret = orig_statfs(path, buf);
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

    if (path && strncmp(path, "KVCore/", 7) == 0) {
        NSString *base = get_kvcore_sandbox_base_path();
        if (base) {
            NSString *rel = [NSString stringWithUTF8String:path];
            NSString *absPath = [base stringByAppendingPathComponent:rel];
            logAudit(@"LEVELDB-C", [NSString stringWithFormat:@"open('%s') -> [BẺ HƯỚNG SANDBOX] %@", path, absPath]);
            return orig_open ? orig_open([absPath UTF8String], oflag, mode) : open([absPath UTF8String], oflag, mode);
        }
    }

    return orig_open ? orig_open(path, oflag, mode) : open(path, oflag, mode);
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

    if (path && (fd == AT_FDCWD || fd >= 0) && strncmp(path, "KVCore/", 7) == 0) {
        NSString *base = get_kvcore_sandbox_base_path();
        if (base) {
            NSString *rel = [NSString stringWithUTF8String:path];
            NSString *absPath = [base stringByAppendingPathComponent:rel];
            logAudit(@"LEVELDB-C", [NSString stringWithFormat:@"openat('%s') -> [BẺ HƯỚNG SANDBOX] %@", path, absPath]);
            return orig_openat ? orig_openat(AT_FDCWD, [absPath UTF8String], oflag, mode) : openat(AT_FDCWD, [absPath UTF8String], oflag, mode);
        }
    }

    return orig_openat ? orig_openat(fd, path, oflag, mode) : openat(fd, path, oflag, mode);
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
            return settings.spoofedSerial ? (__bridge_retained CFTypeRef)[settings.spoofedSerial copy] : orig_MGCopyAnswer(property);
        }
        if ([prop isEqualToString:@"UniqueDeviceID"]) {
            NSString *udid = [[settings.spoofedIDFV stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"UniqueDeviceID -> [ĐÃ FAKE] %@", udid]);
            return (__bridge_retained CFTypeRef)[udid copy];
        }
        if ([prop isEqualToString:@"WifiAddress"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"WifiAddress -> [ĐÃ FAKE] %@", settings.spoofedWifiMAC]);
            return settings.spoofedWifiMAC ? (__bridge_retained CFTypeRef)[settings.spoofedWifiMAC copy] : orig_MGCopyAnswer(property);
        }
        if ([prop isEqualToString:@"BluetoothAddress"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"BluetoothAddress -> [ĐÃ FAKE] %@", settings.spoofedBluetoothMAC]);
            return settings.spoofedBluetoothMAC ? (__bridge_retained CFTypeRef)[settings.spoofedBluetoothMAC copy] : orig_MGCopyAnswer(property);
        }
        if ([prop isEqualToString:@"UserAssignedDeviceName"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"UserAssignedDeviceName -> [ĐÃ FAKE] %@", settings.deviceName]);
            return settings.deviceName ? (__bridge_retained CFTypeRef)[settings.deviceName copy] : orig_MGCopyAnswer(property);
        }
        if ([prop isEqualToString:@"ProductType"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"ProductType -> [ĐÃ FAKE] %@", settings.deviceMachine]);
            return settings.deviceMachine ? (__bridge_retained CFTypeRef)[settings.deviceMachine copy] : orig_MGCopyAnswer(property);
        }
        if ([prop isEqualToString:@"ProductVersion"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"ProductVersion -> [ĐÃ FAKE] %@", settings.systemVersion]);
            return settings.systemVersion ? (__bridge_retained CFTypeRef)[settings.systemVersion copy] : orig_MGCopyAnswer(property);
        }
        if ([prop isEqualToString:@"BuildVersion"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"BuildVersion -> [ĐÃ FAKE] %@", settings.kernOsVersion]);
            return settings.kernOsVersion ? (__bridge_retained CFTypeRef)[settings.kernOsVersion copy] : orig_MGCopyAnswer(property);
        }
        if ([prop isEqualToString:@"HWModelStr"] || [prop isEqualToString:@"HardwarePlatform"]) {
            logAudit(@"MGCopyAnswer", [NSString stringWithFormat:@"%@ -> [ĐÃ FAKE] %@", prop, settings.deviceModel]);
            return settings.deviceModel ? (__bridge_retained CFTypeRef)[settings.deviceModel copy] : orig_MGCopyAnswer(property);
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
    if (is_original_zalo_app()) {
        return %orig;
    }
    if (suitename && ([suitename containsString:@"zingalo"] || [suitename containsString:@"zalo"] || [suitename containsString:@"vng"])) {
        logAudit(@"PREFS-FIX", [NSString stringWithFormat:@"Điều hướng SuiteName '%@' vào Sandbox an toàn", suitename]);
        NSString *safeSuite = [NSString stringWithFormat:@"com.sonhu.zaloclone.%@", suitename];
        return %orig(safeSuite);
    }
    return %orig;
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

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
        NSString *urlStr = request.URL.absoluteString ?: @"";
        NSString *method = request.HTTPMethod ?: @"GET";
        NSString *desc = @"";
        if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/consents"]) {
            desc = @" 👉 [Zalo tải điều khoản đăng ký/sử dụng]";
        } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/login/phone/verify"]) {
            desc = @" 👉 [Zalo xác thực SĐT đăng nhập/OTP]";
        } else if ([urlStr containsString:@"centralized.zaloapp.com"]) {
            desc = @" 👉 [Zalo gửi định danh thiết bị]";
        }
        logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [ASYNC DELEGATE] %@ %@%@", method, urlStr, desc]);
    }
    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    NSDate *startDate = [NSDate date];
    NSData *reqBody = request.HTTPBody;

    if (!completionHandler) {
        if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [TASK-NO-HANDLER] %@ %@", request.HTTPMethod ?: @"GET", request.URL.absoluteString ?: @""]);
        }
        return %orig(request, nil);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDate *finishDate = [NSDate date];
        record_har_traffic(request, reqBody, response, data, error, startDate, finishDate);
        completionHandler(data, response, error);
    };

    return %orig(request, wrappedHandler);
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData {
    if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
        logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [UPLOAD-DELEGATE] %@ %@", request.HTTPMethod ?: @"POST", request.URL.absoluteString ?: @""]);
    }
    return %orig;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    NSDate *startDate = [NSDate date];

    if (!completionHandler) {
        if ([ZTSettings sharedSettings].enableAuditLog && request && request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [UPLOAD-NO-HANDLER] %@ %@", request.HTTPMethod ?: @"POST", request.URL.absoluteString ?: @""]);
        }
        return %orig(request, bodyData, nil);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
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
    if (dladdr((const void *)get_runtime_environment_desc, &info) && info.dli_fname) {
        NSString *dpath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *dname = [dpath lastPathComponent] ?: @"Zalotweak.dylib";
        if ([dpath containsString:@"/jb-"] || [dpath containsString:@"roothide"]) {
            return [NSString stringWithFormat:@"🛡️ Roothide (DEB) [%@]", dname];
        } else if ([dpath containsString:@"/var/jb/"] || [dpath containsString:@"/var/jb"]) {
            return [NSString stringWithFormat:@"⚡ Rootless (DEB) [%@]", dname];
        } else if ([dpath containsString:@"/Library/MobileSubstrate/"] || [dpath containsString:@"/usr/lib/TweakInject/"]) {
            return [NSString stringWithFormat:@"👑 Rootful (DEB) [%@]", dname];
        } else if ([dpath containsString:@".app/"]) {
            return [NSString stringWithFormat:@"📱 Sideload / Clone [%@]", dname];
        }
        return [NSString stringWithFormat:@"🔌 Custom Dylib [%@]", dname];
    }
    return @"❓ Không xác định";
}

static void settingsChangedCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    [[ZTSettings sharedSettings] loadSettings];
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([ZTSettings sharedSettings].showFloatingMenu) {
            [[ZTMenuManager sharedManager] setupInAppMenu];
            [[ZTFloatingButton sharedButton] show];
        } else {
            [[ZTFloatingButton sharedButton] hide];
        }
    });
}

%ctor {
    @autoreleasepool {
        // 1. Khởi tạo toàn bộ dữ liệu cấu hình, bộ nhớ hàng đợi và xác thực bản quyền TRƯỚC KHI BẬT HOOK
        // Đảm bảo không bị deadlock re-entrant
        loggedAuditKeys = [[NSMutableSet alloc] init];
        auditQueue = dispatch_queue_create("com.sonhu.zalotweak.auditQueue", DISPATCH_QUEUE_SERIAL);
        harQueue = dispatch_queue_create("com.sonhu.zalotweak.harQueue", DISPATCH_QUEUE_SERIAL);

        [ZTSettings sharedSettings];
        [[ZTSecurityManager sharedManager] isLicenseValid];

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
        [cfgDict writeToFile:GLOBAL_PREFS_PATH atomically:YES];

        // Khởi tạo In-App Floating Menu (Chỉ hiện khi là Zalo Clone/Sideload hoặc người dùng bật trong Cài đặt, và KHÔNG PHẢI App Extension)
        if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
            if ([ZTSettings sharedSettings].showFloatingMenu) {
                [[ZTMenuManager sharedManager] setupInAppMenu];
            }
        }

        // Ghi nhận dòng kiểm toán khởi động ban đầu
        if ([ZTSettings sharedSettings].enableAuditLog) {
            logAudit(@"SYSTEM-INIT", [NSString stringWithFormat:@"Khởi động ZaloTweak v1.0 | Môi trường: %@ | App: %@ | Model: %@ | Res: %.0fx%.0f@%.0fx | IDFV: %@ | Bản quyền: %@",
                      envDesc,
                      [[NSBundle mainBundle] bundleIdentifier],
                      [ZTSettings sharedSettings].deviceMachine,
                      [ZTSettings sharedSettings].screenWidth,
                      [ZTSettings sharedSettings].screenHeight,
                      [ZTSettings sharedSettings].screenScale,
                      [ZTSettings sharedSettings].spoofedIDFV,
                      [[ZTSecurityManager sharedManager] getLicenseStatusText]]);
        }
    }
}
