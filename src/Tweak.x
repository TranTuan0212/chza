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
#import <dlfcn.h>
#import <substrate.h>
#import "Config.h"
#import "SecurityManager.h"
#import "FloatingMenu.h"

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
        self.spoofedIDFA = dict[@"spoofedIDFA"] ?: [[NSUUID UUID] UUIDString];
        self.profileId = dict[@"profileId"] ?: [[NSUUID UUID] UUIDString];
        self.diskTotalSize = [dict[@"diskTotalSize"] unsignedLongLongValue] ?: 128000000000ULL;
        self.diskFreeSize = [dict[@"diskFreeSize"] unsignedLongLongValue] ?: 74218940000ULL;
        self.enableAuditLog = [dict[@"enableAuditLog"] boolValue];
        self.lastWipedIDFV = dict[@"lastWipedIDFV"] ?: @"";
        self.lastWipedIP = dict[@"lastWipedIP"] ?: @"";
        self.lastWipedTimestamp = [dict[@"lastWipedTimestamp"] unsignedLongLongValue] ?: 0;

        if (!dict[@"spoofedIDFV"] || !dict[@"spoofedIDFA"] || !dict[@"profileId"] || self.bootTimeSec == 0) {
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
    dict[@"spoofedIDFA"] = self.spoofedIDFA ?: [[NSUUID UUID] UUIDString];
    dict[@"profileId"] = self.profileId;
    dict[@"diskTotalSize"] = @(self.diskTotalSize);
    dict[@"diskFreeSize"] = @(self.diskFreeSize);
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

- (void)generateNewProfile {
    self.deviceMachine = @"iPhone14,2"; // iPhone 13 Pro
    self.deviceModel = @"D63AP";
    self.ncpu = 6;
    self.memsize = 6442450944ULL;
    self.screenWidth = 390.0;
    self.screenHeight = 844.0;
    self.screenScale = 3.0;

    // 1. Tên thiết bị người dùng đời thực ngẫu nhiên
    NSArray *userNames = @[
        @"iPhone",
        @"iPhone của Tuấn",
        @"iPhone của Linh",
        @"iPhone (2)",
        @"iPhone của Huy",
        @"iPhone 13 Pro",
        @"iPhone của Nam",
        @"iPhone của Trang",
        @"iPhone của Hoàng",
        @"iPhone của Mai",
        @"iPhone của Lan",
        @"iPhone của Minh"
    ];
    self.deviceName = userNames[arc4random_uniform((uint32_t)userNames.count)];

    // 2. Phiên bản iOS & Build Number chuẩn Apple tương ứng
    NSArray *iosProfiles = @[
        @{@"ver": @"16.6", @"build": @"20G75"},
        @{@"ver": @"16.6.1", @"build": @"20G81"},
        @{@"ver": @"16.7.2", @"build": @"20H115"},
        @{@"ver": @"17.2.1", @"build": @"21C66"},
        @{@"ver": @"17.4.1", @"build": @"21E236"},
        @{@"ver": @"17.5.1", @"build": @"21F90"},
        @{@"ver": @"17.6.1", @"build": @"21G93"},
        @{@"ver": @"18.0", @"build": @"22A3354"}
    ];
    NSDictionary *chosenOS = iosProfiles[arc4random_uniform((uint32_t)iosProfiles.count)];
    self.systemVersion = chosenOS[@"ver"];
    self.kernOsVersion = chosenOS[@"build"];

    // 3. Phân khúc dung lượng ổ cứng (128GB hoặc 256GB) kèm dung lượng trống thực tế ngẫu nhiên
    BOOL is256 = (arc4random_uniform(2) == 1);
    if (is256) {
        self.diskTotalSize = 256000000000ULL;
        self.diskFreeSize = 95000000000ULL + ((uint64_t)arc4random_uniform(90000000)) * 1000ULL;
    } else {
        self.diskTotalSize = 128000000000ULL;
        self.diskFreeSize = 35000000000ULL + ((uint64_t)arc4random_uniform(50000000)) * 1000ULL;
    }

    // 4. Giả lập uptime từ 8 giờ đến 6 ngày trước
    uint32_t randomOffset = 28800 + (arc4random_uniform(489600));
    self.bootTimeSec = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;
    self.bootSessionUUID = [[NSUUID UUID] UUIDString];
    self.spoofedIDFV = [[NSUUID UUID] UUIDString];
    self.spoofedIDFA = [[NSUUID UUID] UUIDString];
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
    // 1. Luôn in trực tiếp ra System Console để soi trực tiếp trên 3uTools Device Console
    NSLog(@"[ZaloAudit] [%@] %@", category, detail);

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
    // Luôn ưu tiên trả về IDFV spoofed của profile để Zalo tuyệt đối không bao giờ tóm được IDFV thật của máy!
    NSString *fake = [ZTSettings sharedSettings].spoofedIDFV;
    if (fake && fake.length > 0) {
        logAudit(@"IDFV-CHECK", [NSString stringWithFormat:@"identifierForVendor -> [ĐÃ FAKE IDFV AN TOÀN] %@", fake]);
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:fake];
        if (uuid) return uuid;
    }
    if (!is_tweak_active()) {
        NSUUID *origUUID = %orig;
        logAudit(@"IDFV-CHECK", [NSString stringWithFormat:@"identifierForVendor -> [CHƯA KÍCH HOẠT KEY - TRẢ VỀ IDFV THẬT] %@", [origUUID UUIDString]]);
        return origUUID;
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

// ==========================================
// BẢO VỆ DANH TÍNH QUẢNG CÁO: IDFA & APP TRACKING
// ==========================================
%hook ASIdentifierManager

- (NSUUID *)advertisingIdentifier {
    NSString *fake = [ZTSettings sharedSettings].spoofedIDFA;
    if (fake && fake.length > 0) {
        logAudit(@"IDFA-CHECK", [NSString stringWithFormat:@"advertisingIdentifier -> [ĐÃ FAKE IDFA MỚI] %@", fake]);
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:fake];
        if (uuid) return uuid;
    }
    logAudit(@"IDFA-CHECK", @"advertisingIdentifier -> [TRẢ VỀ ZERO UUID]");
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}

- (BOOL)isAdvertisingTrackingEnabled {
    return NO;
}

%end

%hook ATTrackingManager

+ (NSInteger)trackingAuthorizationStatus {
    logAudit(@"TRACKING-CHECK", @"trackingAuthorizationStatus -> [ĐÃ CHẶN THEO DÕI - TRẢ VỀ DENIED (2)]");
    return 2; // ATTrackingManagerAuthorizationStatusDenied
}

+ (void)requestTrackingAuthorizationWithCompletionHandler:(void (^)(NSInteger status))completion {
    logAudit(@"TRACKING-CHECK", @"requestTrackingAuthorization -> [TỰ ĐỘNG TRẢ VỀ DENIED (2)]");
    if (completion) {
        completion(2);
    }
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

    // Cách ly kSecAttrAccessGroup để không bao giờ đọc chung Keychain với Zalo chính
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

static inline const char *redirect_kvcore_cpath(const char *path, char *buffer, size_t buf_len) {
    if (!path || buf_len == 0) return path;
    const char *p = path;
    if (p[0] == '/') p++;
    if (strncmp(p, "KVCore", 6) == 0 && (p[6] == '\0' || p[6] == '/')) {
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *sub = [NSString stringWithUTF8String:p + 6];
            NSString *safe = [home stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Application Support/KVCore%@", sub]];
            const char *safeC = [safe UTF8String];
            strncpy(buffer, safeC, buf_len - 1);
            buffer[buf_len - 1] = '\0';
            return buffer;
        }
    }
    return path;
}

static int (*orig_access)(const char *path, int mode);
static int my_access(const char *path, int mode) {
    char pbuf[1024];
    const char *safePath = redirect_kvcore_cpath(path, pbuf, sizeof(pbuf));
    if (is_tweak_active() && is_jailbreak_path(safePath)) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"access('%s') -> [ĐÃ CHẶN - BÁO KHÔNG TỒN TẠI]", safePath]);
        errno = ENOENT;
        return -1;
    }
    if (safePath && (strstr(safePath, "Library") || strstr(safePath, "Applications") || strstr(safePath, "var") || strstr(safePath, "etc") || strstr(safePath, "bin"))) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"access('%s') -> [CHO PHÉP]", safePath]);
    }
    return orig_access(safePath, mode);
}

static int (*orig_stat)(const char *path, struct stat *buf);
static int my_stat(const char *path, struct stat *buf) {
    char pbuf[1024];
    const char *safePath = redirect_kvcore_cpath(path, pbuf, sizeof(pbuf));
    if (is_tweak_active() && is_jailbreak_path(safePath)) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"stat('%s') -> [ĐÃ CHẶN - BÁO KHÔNG TỒN TẠI]", safePath]);
        errno = ENOENT;
        return -1;
    }
    if (safePath && (strstr(safePath, "Library") || strstr(safePath, "Applications") || strstr(safePath, "var") || strstr(safePath, "etc") || strstr(safePath, "bin"))) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"stat('%s') -> [CHO PHÉP]", safePath]);
    }
    return orig_stat(safePath, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int my_lstat(const char *path, struct stat *buf) {
    char pbuf[1024];
    const char *safePath = redirect_kvcore_cpath(path, pbuf, sizeof(pbuf));
    if (is_tweak_active() && is_jailbreak_path(safePath)) {
        logAudit(@"FILE-CHECK", [NSString stringWithFormat:@"lstat('%s') -> [ĐÃ CHẶN - BÁO KHÔNG TỒN TẠI]", safePath]);
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(safePath, buf);
}

static int (*orig_open)(const char *path, int oflag, ...);
static int my_open(const char *path, int oflag, ...) {
    char pbuf[1024];
    const char *safePath = redirect_kvcore_cpath(path, pbuf, sizeof(pbuf));
    if (is_tweak_active() && is_jailbreak_path(safePath)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);

        // Tự động tạo thư mục cha đệ quy để LevelDB / SQLite / MMKV không bao giờ bị lỗi ENOENT
        if (safePath) {
            NSString *safeStr = [NSString stringWithUTF8String:safePath];
            NSString *parentDir = [safeStr stringByDeletingLastPathComponent];
            if (parentDir && parentDir.length > 0 && ![[NSFileManager defaultManager] fileExistsAtPath:parentDir]) {
                [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
            }
        }
        return orig_open(safePath, oflag, mode);
    }
    return orig_open(safePath, oflag);
}

static int (*orig_openat)(int fd, const char *path, int oflag, ...);
static int my_openat(int fd, const char *path, int oflag, ...) {
    char pbuf[1024];
    const char *safePath = redirect_kvcore_cpath(path, pbuf, sizeof(pbuf));
    if (is_tweak_active() && is_jailbreak_path(safePath)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);

        if (safePath) {
            NSString *safeStr = [NSString stringWithUTF8String:safePath];
            NSString *parentDir = [safeStr stringByDeletingLastPathComponent];
            if (parentDir && parentDir.length > 0 && ![[NSFileManager defaultManager] fileExistsAtPath:parentDir]) {
                [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
            }
        }
        return orig_openat ? orig_openat(fd, safePath, oflag, mode) : -1;
    }
    return orig_openat ? orig_openat(fd, safePath, oflag) : -1;
}

static FILE *(*orig_fopen)(const char *path, const char *mode);
static FILE *my_fopen(const char *path, const char *mode) {
    char pbuf[1024];
    const char *safePath = redirect_kvcore_cpath(path, pbuf, sizeof(pbuf));
    if (is_tweak_active() && is_jailbreak_path(safePath)) {
        errno = ENOENT;
        return NULL;
    }
    if (mode && (strchr(mode, 'w') || strchr(mode, 'a')) && safePath) {
        NSString *safeStr = [NSString stringWithUTF8String:safePath];
        NSString *parentDir = [safeStr stringByDeletingLastPathComponent];
        if (parentDir && parentDir.length > 0 && ![[NSFileManager defaultManager] fileExistsAtPath:parentDir]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
        }
    }
    return orig_fopen(safePath, mode);
}

static int (*orig_mkdir)(const char *path, mode_t mode);
static int my_mkdir(const char *path, mode_t mode) {
    char pbuf[1024];
    const char *safePath = redirect_kvcore_cpath(path, pbuf, sizeof(pbuf));
    if (safePath) {
        NSString *safeStr = [NSString stringWithUTF8String:safePath];
        if (![[NSFileManager defaultManager] fileExistsAtPath:safeStr]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:safeStr withIntermediateDirectories:YES attributes:nil error:nil];
            return 0;
        }
    }
    return orig_mkdir ? orig_mkdir(safePath, mode) : 0;
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

// Chuyển hướng CFPreferences App Groups sang container an toàn của clone
static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef key, CFStringRef applicationID);
static CFPropertyListRef my_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef applicationID) {
    if (applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
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
    if (applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
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
    if (applicationID && CFGetTypeID(applicationID) == CFStringGetTypeID()) {
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

// Cách ly hoàn toàn Shared App Groups: Chuyển hướng về thư mục riêng trong Sandbox Zalo Clone
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    if (groupIdentifier && ([groupIdentifier containsString:@"zalo"] || [groupIdentifier containsString:@"zingalo"] || [groupIdentifier containsString:@"vng"])) {
        logAudit(@"APP-GROUP", [NSString stringWithFormat:@"Zalo truy vấn App Group '%@' -> [ĐÃ CÁCH LY VỀ THƯ MỤC RIÊNG]", groupIdentifier]);
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *isolatedGroup = [home stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Application Support/IsolatedAppGroups/%@", groupIdentifier]];
            [[NSFileManager defaultManager] createDirectoryAtPath:isolatedGroup withIntermediateDirectories:YES attributes:nil error:nil];
            [[NSFileManager defaultManager] createDirectoryAtPath:[isolatedGroup stringByAppendingPathComponent:@"Library/Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
            [[NSFileManager defaultManager] createDirectoryAtPath:[isolatedGroup stringByAppendingPathComponent:@"Library/Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
            return [NSURL fileURLWithPath:isolatedGroup isDirectory:YES];
        }
    }
    return %orig;
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

%hook NSBundle

- (NSString *)bundleIdentifier {
    if (self == [NSBundle mainBundle]) {
        void *retAddr = __builtin_return_address(0);
        Dl_info info;
        if (dladdr(retAddr, &info) && info.dli_fname) {
            const char *fname = info.dli_fname;
            if (strstr(fname, "/System/Library/") != NULL ||
                strstr(fname, "/usr/lib/") != NULL ||
                strstr(fname, "UserNotifications") != NULL ||
                strstr(fname, "CoreFoundation") != NULL) {
                return %orig;
            }
        }
        logAudit(@"BUNDLE-ID", @"Zalo truy vấn bundleIdentifier -> [ĐÃ BẺ HƯỚNG TRẢ VỀ vn.com.vng.zingalo]");
        return @"vn.com.vng.zingalo";
    }
    return %orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if (self == [NSBundle mainBundle] && key && [key isEqualToString:@"CFBundleIdentifier"]) {
        void *retAddr = __builtin_return_address(0);
        Dl_info info;
        if (dladdr(retAddr, &info) && info.dli_fname) {
            const char *fname = info.dli_fname;
            if (strstr(fname, "/System/Library/") != NULL ||
                strstr(fname, "/usr/lib/") != NULL ||
                strstr(fname, "UserNotifications") != NULL ||
                strstr(fname, "CoreFoundation") != NULL) {
                return %orig;
            }
        }
        logAudit(@"BUNDLE-ID", @"Zalo đọc InfoDictionary(CFBundleIdentifier) -> [ĐÃ BẺ HƯỚNG TRẢ VỀ vn.com.vng.zingalo]");
        return @"vn.com.vng.zingalo";
    }
    return %orig;
}

- (NSDictionary *)infoDictionary {
    NSDictionary *dict = %orig;
    if (self == [NSBundle mainBundle] && dict) {
        void *retAddr = __builtin_return_address(0);
        Dl_info info;
        if (dladdr(retAddr, &info) && info.dli_fname) {
            const char *fname = info.dli_fname;
            if (strstr(fname, "/System/Library/") != NULL ||
                strstr(fname, "/usr/lib/") != NULL ||
                strstr(fname, "UserNotifications") != NULL ||
                strstr(fname, "CoreFoundation") != NULL) {
                return dict;
            }
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
// CONSTRUCTOR: KHỞI TẠO VÀ HOOK CÁC HÀM C
// ==========================================

static void settingsChangedCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    [[ZTSettings sharedSettings] loadSettings];
}

%ctor {
    @autoreleasepool {
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
        void *fstatfs_ptr = (void *)fstatfs;
        if (fstatfs_ptr) {
            MSHookFunction(fstatfs_ptr, (void *)my_fstatfs, (void **)&orig_fstatfs);
        }
        void *cdFunc = dlsym(RTLD_DEFAULT, "CacheDeleteCopyAvailableSpaceForVolume");
        if (cdFunc) {
            MSHookFunction(cdFunc, (void *)my_CacheDeleteCopyAvailableSpaceForVolume, (void **)&orig_CacheDeleteCopyAvailableSpaceForVolume);
        }

        // Đổi Current Working Directory (CWD) sang Sandbox Library/Application Support
        // để mọi đường dẫn tương đối của LevelDB C++ ("KVCore/Device/...") tự động trỏ đúng vào Sandbox
        NSString *homeDir = NSHomeDirectory();
        if (homeDir) {
            NSString *appSupportDir = [homeDir stringByAppendingPathComponent:@"Library/Application Support"];
            [[NSFileManager defaultManager] createDirectoryAtPath:appSupportDir withIntermediateDirectories:YES attributes:nil error:nil];
            chdir([appSupportDir UTF8String]);

            NSString *kvCoreDir = [appSupportDir stringByAppendingPathComponent:@"KVCore"];
            [[NSFileManager defaultManager] createDirectoryAtPath:kvCoreDir withIntermediateDirectories:YES attributes:nil error:nil];
            NSString *kvDeviceDir = [kvCoreDir stringByAppendingPathComponent:@"Device"];
            [[NSFileManager defaultManager] createDirectoryAtPath:kvDeviceDir withIntermediateDirectories:YES attributes:nil error:nil];
            NSString *isoGroupsDir = [appSupportDir stringByAppendingPathComponent:@"IsolatedAppGroups"];
            [[NSFileManager defaultManager] createDirectoryAtPath:isoGroupsDir withIntermediateDirectories:YES attributes:nil error:nil];

            // Tạo Symlinks dự phòng để dù tìm ở Home hay Documents đều trỏ về KVCore
            NSString *homeKV = [homeDir stringByAppendingPathComponent:@"KVCore"];
            if (![[NSFileManager defaultManager] fileExistsAtPath:homeKV]) {
                symlink([kvCoreDir UTF8String], [homeKV UTF8String]);
            }
            NSString *docKV = [homeDir stringByAppendingPathComponent:@"Documents/KVCore"];
            if (![[NSFileManager defaultManager] fileExistsAtPath:docKV]) {
                symlink([kvCoreDir UTF8String], [docKV UTF8String]);
            }
        }

        // Hook Anti-Jailbreak File & Dylib Checks
        MSHookFunction((void *)open, (void *)my_open, (void **)&orig_open);
        void *openatPtr = dlsym(RTLD_DEFAULT, "openat");
        if (openatPtr) {
            MSHookFunction(openatPtr, (void *)my_openat, (void **)&orig_openat);
        }
        void *openNocancelPtr = dlsym(RTLD_DEFAULT, "open$NOCANCEL");
        if (openNocancelPtr) {
            MSHookFunction(openNocancelPtr, (void *)my_open, NULL);
        }
        void *openatNocancelPtr = dlsym(RTLD_DEFAULT, "openat$NOCANCEL");
        if (openatNocancelPtr) {
            MSHookFunction(openatNocancelPtr, (void *)my_openat, NULL);
        }
        MSHookFunction((void *)fopen, (void *)my_fopen, (void **)&orig_fopen);
        MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
        MSHookFunction((void *)stat, (void *)my_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)mkdir, (void *)my_mkdir, (void **)&orig_mkdir);
        MSHookFunction((void *)getenv, (void *)my_getenv, (void **)&orig_getenv);

        // Hook CoreFoundation Preferences (App Groups Redirection)
        MSHookFunction((void *)CFPreferencesCopyAppValue, (void *)my_CFPreferencesCopyAppValue, (void **)&orig_CFPreferencesCopyAppValue);
        MSHookFunction((void *)CFPreferencesSetAppValue, (void *)my_CFPreferencesSetAppValue, (void **)&orig_CFPreferencesSetAppValue);
        MSHookFunction((void *)CFPreferencesAppSynchronize, (void *)my_CFPreferencesAppSynchronize, (void **)&orig_CFPreferencesAppSynchronize);

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

        // Khởi tạo In-App Floating Menu (Hỗ trợ Zalo Clone / Sideload không cần Jailbreak)
        [[ZTMenuManager sharedManager] setupInAppMenu];

        // Ghi nhận dòng kiểm toán khởi động ban đầu
        if ([ZTSettings sharedSettings].enableAuditLog) {
            logAudit(@"SYSTEM-INIT", [NSString stringWithFormat:@"Khởi động ZaloTweak v1.0 | Model: %@ | Res: %.0fx%.0f@%.0fx | IDFV: %@ | Bản quyền: %@",
                      [ZTSettings sharedSettings].deviceMachine,
                      [ZTSettings sharedSettings].screenWidth,
                      [ZTSettings sharedSettings].screenHeight,
                      [ZTSettings sharedSettings].screenScale,
                      [ZTSettings sharedSettings].spoofedIDFV,
                      [[ZTSecurityManager sharedManager] getLicenseStatusText]]);
        }
    }
}
