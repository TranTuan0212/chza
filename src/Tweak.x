#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <errno.h>
#import <stdarg.h>
#import <stdio.h>
#import <substrate.h>
#import "Config.h"
#import "SecurityManager.h"

static inline BOOL is_tweak_active(void) {
    return [ZTSettings sharedSettings].enabled && [[ZTSecurityManager sharedManager] isLicenseValid];
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

@implementation ZTSettings

+ (instancetype)sharedSettings {
    static ZTSettings *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[ZTSettings alloc] init];
        [instance loadSettings];
    });
    return instance;
}

- (void)loadSettings {
    NSString *path = getConfigPath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (dict) {
        self.enabled = [dict[@"enabled"] boolValue];
        self.deviceMachine = dict[@"deviceMachine"] ?: @"iPhone14,2";
        self.deviceModel = dict[@"deviceModel"] ?: @"D63AP";
        self.deviceName = dict[@"deviceName"] ?: @"iPhone";
        self.systemVersion = dict[@"systemVersion"] ?: @"16.5";
        self.kernOsVersion = dict[@"kernOsVersion"] ?: @"20F66";
        self.ncpu = [dict[@"ncpu"] unsignedIntValue] ?: 6;
        self.memsize = [dict[@"memsize"] unsignedLongLongValue] ?: 6442450944ULL;
        self.screenWidth = [dict[@"screenWidth"] doubleValue] ?: 390.0;
        self.screenHeight = [dict[@"screenHeight"] doubleValue] ?: 844.0;
        self.screenScale = [dict[@"screenScale"] doubleValue] ?: 3.0;
        self.bootTimeSec = [dict[@"bootTimeSec"] unsignedLongLongValue] ?: 0;
        self.bootSessionUUID = dict[@"bootSessionUUID"] ?: @"";
        self.spoofedIDFV = dict[@"spoofedIDFV"] ?: [[NSUUID UUID] UUIDString];
        self.profileId = dict[@"profileId"] ?: [[NSUUID UUID] UUIDString];
        self.diskTotalSize = [dict[@"diskTotalSize"] unsignedLongLongValue] ?: 128000000000ULL;
        self.diskFreeSize = [dict[@"diskFreeSize"] unsignedLongLongValue] ?: 74218940000ULL;
        self.enableAuditLog = [dict[@"enableAuditLog"] boolValue];

        if (!dict[@"spoofedIDFV"] || !dict[@"profileId"] || self.bootTimeSec == 0) {
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
        [self generateNewProfile];
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
    dict[@"profileId"] = self.profileId;
    dict[@"diskTotalSize"] = @(self.diskTotalSize);
    dict[@"diskFreeSize"] = @(self.diskFreeSize);

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

- (void)generateNewProfile {
    self.deviceMachine = @"iPhone14,2"; // iPhone 13 Pro
    self.deviceModel = @"D63AP";
    self.deviceName = @"iPhone";
    self.systemVersion = @"16.5";
    self.kernOsVersion = @"20F66";
    self.ncpu = 6;
    self.memsize = 6442450944ULL;
    self.screenWidth = 390.0;
    self.screenHeight = 844.0;
    self.screenScale = 3.0;
    self.diskTotalSize = 128000000000ULL;
    self.diskFreeSize = 65000000000ULL + ((uint64_t)arc4random_uniform(15000000)) * 1000ULL;

    // Giả lập uptime từ 1 đến 5 ngày trước
    uint32_t randomOffset = 86400 + (arc4random_uniform(345600));
    self.bootTimeSec = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;
    self.bootSessionUUID = [[NSUUID UUID] UUIDString];
    self.spoofedIDFV = [[NSUUID UUID] UUIDString];
    self.profileId = [[NSUUID UUID] UUIDString];
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
    if (![ZTSettings sharedSettings].enableAuditLog) return;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        loggedAuditKeys = [[NSMutableSet alloc] init];
        auditQueue = dispatch_queue_create("com.sonhu.zalotweak.auditQueue", DISPATCH_QUEUE_SERIAL);
    });

    NSString *dedupKey = [NSString stringWithFormat:@"%@:%@", category, detail];
    dispatch_async(auditQueue, ^{
        if ([loggedAuditKeys containsObject:dedupKey]) {
            return;
        }
        [loggedAuditKeys addObject:dedupKey];

        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"HH:mm:ss"];
        NSString *timeStr = [df stringFromDate:[NSDate date]];

        NSString *line = [NSString stringWithFormat:@"[%@] [%@] %@\n", timeStr, category, detail];
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

static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name || namelen < 2 || !is_tweak_active()) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
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

static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name || !is_tweak_active()) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

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
        return %orig;
    }
    NSString *fake = [ZTSettings sharedSettings].spoofedIDFV;
    if (fake && fake.length > 0) {
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
    NSString *profile = [ZTSettings sharedSettings].profileId;
    if (!profile || profile.length == 0) return dict;

    // Chỉ áp dụng cho mật khẩu Generic & Internet, KHÔNG làm hỏng Certificate / TLS / Keys
    id secClass = dict[(__bridge id)kSecClass];
    if (secClass) {
        if (![secClass isEqual:(__bridge id)kSecClassGenericPassword] &&
            ![secClass isEqual:(__bridge id)kSecClassInternetPassword]) {
            return dict;
        }
    }

    NSString *prefix = [NSString stringWithFormat:@"%@_", profile];

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
        "/var/jb",
        "/private/var/jb",
        "/var/binpack",
        "/basebin",
        "jbroot",
        "dopamine",
        "roothide",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Cydia.app",
        "/Applications/Filza.app",
        "/Library/MobileSubstrate",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/sh",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/stash",
        "/Library/PreferenceBundles",
        "/Library/PreferenceLoader",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/substrate",
        "/usr/lib/TweakInject",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/ellekit",
        "MobileSubstrate",
        "ElleKit",
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
    if (is_tweak_active() && is_jailbreak_path(path)) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"access('%s') -> [ĐÃ CHẶN - BÁO KHÔNG TỒN TẠI]", path]);
        errno = ENOENT;
        return -1;
    }
    if (path && (strstr(path, "Library") || strstr(path, "Applications") || strstr(path, "var") || strstr(path, "etc") || strstr(path, "bin"))) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"access('%s') -> [CHO PHÉP]", path]);
    }
    return orig_access(path, mode);
}

static int (*orig_stat)(const char *path, struct stat *buf);
static int my_stat(const char *path, struct stat *buf) {
    if (is_tweak_active() && is_jailbreak_path(path)) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"stat('%s') -> [ĐÃ CHẶN - BÁO KHÔNG TỒN TẠI]", path]);
        errno = ENOENT;
        return -1;
    }
    if (path && (strstr(path, "Library") || strstr(path, "Applications") || strstr(path, "var") || strstr(path, "etc") || strstr(path, "bin"))) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"stat('%s') -> [CHO PHÉP]", path]);
    }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int my_lstat(const char *path, struct stat *buf) {
    if (is_tweak_active() && is_jailbreak_path(path)) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"lstat('%s') -> [ĐÃ CHẶN - BÁO KHÔNG TỒN TẠI]", path]);
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(path, buf);
}

static int (*orig_open)(const char *path, int oflag, ...);
static int my_open(const char *path, int oflag, ...) {
    if (is_tweak_active() && is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    return orig_open(path, oflag, mode);
}

static FILE *(*orig_fopen)(const char *path, const char *mode);
static FILE *my_fopen(const char *path, const char *mode) {
    if (is_tweak_active() && is_jailbreak_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen(path, mode);
}

static char *(*orig_getenv)(const char *name);
static char *my_getenv(const char *name) {
    if (is_tweak_active() && name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) {
            return NULL;
        }
    }
    return orig_getenv(name);
}

// Ẩn các dylib của jailbreak và tweak trong RAM
static const char *(*orig_dyld_get_image_name)(uint32_t image_index);
static const char *my_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name(image_index);
    if (is_tweak_active() && name) {
        if (is_jailbreak_path(name) ||
            strstr(name, "Zalotweak") != NULL ||
            strstr(name, "ElleKit") != NULL ||
            strstr(name, "MobileSubstrate") != NULL ||
            strstr(name, "libhooker") != NULL ||
            strstr(name, "substitute") != NULL ||
            strstr(name, "TweakInject") != NULL ||
            strstr(name, "PreferenceLoader") != NULL ||
            strstr(name, "dopamine") != NULL ||
            strstr(name, "roothide") != NULL) {
            return "/System/Library/Frameworks/Foundation.framework/Foundation";
        }
    }
    return name;
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

// Giả lập dung lượng ổ cứng ở tầng POSIX C (statfs)
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

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (is_tweak_active() && path && is_jailbreak_path([path UTF8String])) {
        return NO;
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (is_tweak_active() && path && is_jailbreak_path([path UTF8String])) {
        if (isDirectory) *isDirectory = NO;
        return NO;
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

%end

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    if (is_tweak_active() && url) {
        NSString *scheme = [[url scheme] lowercaseString];
        if ([scheme isEqualToString:@"cydia"] ||
            [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] ||
            [scheme isEqualToString:@"filza"] ||
            [scheme isEqualToString:@"undecimus"]) {
            logAudit(@"SCHEME-CHECK", [NSString stringWithFormat:@"canOpenURL('%@') -> [ĐÃ CHẶN - TRẢ VỀ NO]", [url absoluteString]]);
            return NO;
        }
        logAudit(@"SCHEME-CHECK", [NSString stringWithFormat:@"canOpenURL('%@') -> [CHO PHÉP]", [url absoluteString]]);
    }
    return %orig;
}

%end

// ==========================================
// CONSTRUCTOR: KHỞI TẠO VÀ HOOK CÁC HÀM C
// ==========================================

static void settingsChangedCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    [[ZTSettings sharedSettings] loadSettings];
}

static void cleanDirectoryPreservingAdbk(NSString *dirPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dirPath]) return;

    NSError *err = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:dirPath error:&err];
    if (err || !items) return;

    for (NSString *item in items) {
        if ([item hasPrefix:@".com.apple.mobile_container_manager"]) continue;
        NSString *lower = [item lowercaseString];
        if ([lower hasSuffix:@".adbk"] || [lower containsString:@"appsmanager"] || [lower containsString:@"adbk"]) {
            continue;
        }
        if ([item isEqualToString:@"com.sonhu.zalotweak.plist"]) continue;
        NSString *subPath = [dirPath stringByAppendingPathComponent:item];
        [fm removeItemAtPath:subPath error:nil];
    }
}

static void performInAppSelfWipeIfNeeded(void) {
    NSString *cpath = getConfigPath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:cpath];
    if (![dict[@"wipePending"] boolValue]) {
        return;
    }

    NSLog(@"[ZaloTweak] ⚠️ Phát hiện lệnh wipePending -> Tiến hành tự động Deep Wipe sạch bóng từ bên trong!");

    // 1. Xóa sạch mọi mục Keychain thuộc về Zalo
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    for (id secClass in secClasses) {
        NSDictionary *query = @{(__bridge id)kSecClass: secClass};
        SecItemDelete((__bridge CFDictionaryRef)query);
    }

    // 2. Dọn sạch các thư mục Sandbox trong Home Directory (BẢO VỆ TUYỆT ĐỐI FILE .adbk)
    NSString *home = NSHomeDirectory();
    if (home) {
        cleanDirectoryPreservingAdbk([home stringByAppendingPathComponent:@"Documents"]);
        cleanDirectoryPreservingAdbk([home stringByAppendingPathComponent:@"tmp"]);
        cleanDirectoryPreservingAdbk([home stringByAppendingPathComponent:@"Library/Caches"]);
        cleanDirectoryPreservingAdbk([home stringByAppendingPathComponent:@"Library/Application Support"]);
        cleanDirectoryPreservingAdbk([home stringByAppendingPathComponent:@"Library/WebKit"]);
        cleanDirectoryPreservingAdbk([home stringByAppendingPathComponent:@"Library/Cookies"]);

        // Xóa sạch các file plist của Zalo để Zalo reset về màn hình chọn ngôn ngữ ban đầu
        NSString *prefDir = [home stringByAppendingPathComponent:@"Library/Preferences"];
        NSArray *prefs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:prefDir error:nil];
        for (NSString *p in prefs) {
            if ([p hasPrefix:@"com.zing.zalo"] || [p hasPrefix:@"com.vng.zalo"]) {
                [[NSFileManager defaultManager] removeItemAtPath:[prefDir stringByAppendingPathComponent:p] error:nil];
            }
        }
    }

    // 3. Reset cờ wipePending = NO để những lần mở app sau không bị wipe lại
    NSMutableDictionary *mdict = [NSMutableDictionary dictionaryWithContentsOfFile:cpath] ?: [NSMutableDictionary dictionary];
    mdict[@"wipePending"] = @(NO);
    [mdict writeToFile:cpath atomically:YES];
    if (home) {
        NSString *localPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        [mdict writeToFile:localPref atomically:YES];
        NSString *localDoc = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        [mdict writeToFile:localDoc atomically:YES];
    }
    NSLog(@"[ZaloTweak] 🟢 In-App Deep Wipe hoàn tất. Zalo sẽ bắt đầu như cài đặt mới tinh.");
}

%ctor {
    @autoreleasepool {
        performInAppSelfWipeIfNeeded();
        [[ZTSettings sharedSettings] loadSettings];

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            settingsChangedCallback,
            CFSTR("com.sonhu.zalotweak/settingschanged"),
            NULL,
            CFNotificationSuspensionBehaviorCoalesce
        );

        // Hook C POSIX API
        MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)sysctlbyname, (void *)my_sysctlbyname, (void **)&orig_sysctlbyname);
        MSHookFunction((void *)uname, (void *)my_uname, (void **)&orig_uname);
        MSHookFunction((void *)statfs, (void *)my_statfs, (void **)&orig_statfs);

        // Hook Anti-Jailbreak File & Dylib Checks
        MSHookFunction((void *)open, (void *)my_open, (void **)&orig_open);
        MSHookFunction((void *)fopen, (void *)my_fopen, (void **)&orig_fopen);
        MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
        MSHookFunction((void *)stat, (void *)my_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)getenv, (void *)my_getenv, (void **)&orig_getenv);
        MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);

        // Hook Security Framework (Keychain Isolation)
        MSHookFunction((void *)SecItemCopyMatching, (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        MSHookFunction((void *)SecItemAdd, (void *)my_SecItemAdd, (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemDelete, (void *)my_SecItemDelete, (void **)&orig_SecItemDelete);
        MSHookFunction((void *)SecItemUpdate, (void *)my_SecItemUpdate, (void **)&orig_SecItemUpdate);

        // Hook WiFi BSSID Anonymization
        void *cnFunc = (void *)CNCopyCurrentNetworkInfo;
        if (cnFunc) {
            MSHookFunction(cnFunc, (void *)my_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
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
    }
}
