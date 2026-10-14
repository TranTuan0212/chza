#import "DeviceProfilePool.h"
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

typedef struct {
    const char *machine;        // hw.machine, vd: "iPhone14,5"
    const char *model;          // hw.model, vd: "D17AP"
    uint32_t ncpu;              // 2, 6
    uint64_t ramBytes;          // 2GB, 3GB, 4GB, 6GB, 8GB
    uint64_t l2cacheBytes;      // hw.l2cachesize: 3MB, 8MB, 12MB, 16MB
    CGFloat width;              // pt width
    CGFloat height;             // pt height
    CGFloat scale;              // 2.0 hoặc 3.0
    uint64_t supportedDisks[5]; // Danh sách bộ nhớ hợp lệ (bytes), kết thúc bằng 0
    int minIOS;                 // Phiên bản iOS tối thiểu (Tối thiểu 15 để tương thích Zalo 26+)
    int maxIOS;                 // Phiên bản iOS tối đa (iPhone 7 = 15, iPhone 8/X = 16, iPhone 11+ = 18)
    const char *family;         // Nhóm nhận diện: "iPhone 7", "iPhone 7 Plus", "iPhone 8", ...
    uint64_t launchTimestamp;   // Thời điểm phát hành của dòng máy (Unix epoch sec)
    uint64_t eolTimestamp;      // Thời điểm ngừng sản xuất/khai tử (Unix epoch sec)
} AppleDeviceSpec;

// Ngân hàng thiết bị iPhone chuẩn xác 100% phần cứng của Apple kèm vòng đời sản xuất
static const AppleDeviceSpec kAppleDeviceSpecs[] = {
    // iPhone 6 Series (A8, 2 Cores, 1GB RAM) [09/2014 - 09/2016]
    {"iPhone7,2",  "N61AP",   2, 1073741824ULL, 2097152ULL,  375.0, 667.0, 2.0, {16000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6", 1410998400ULL, 1473984000ULL},
    {"iPhone7,1",  "N56AP",   2, 1073741824ULL, 2097152ULL,  414.0, 736.0, 3.0, {16000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6 Plus", 1410998400ULL, 1473984000ULL},

    // iPhone 6s Series & SE 1 (A9, 2 Cores, 2GB RAM, L2: 3MB) [09/2015 - 09/2018]
    {"iPhone8,1",  "N71AP",   2, 2147483648ULL, 3145728ULL,  375.0, 667.0, 2.0, {16000000000ULL, 32000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6s", 1442361600ULL, 1536710400ULL},
    {"iPhone8,2",  "N66AP",   2, 2147483648ULL, 3145728ULL,  414.0, 736.0, 3.0, {16000000000ULL, 32000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6s Plus", 1442361600ULL, 1536710400ULL},
    {"iPhone8,4",  "N69AP",   2, 2147483648ULL, 3145728ULL,  320.0, 568.0, 2.0, {16000000000ULL, 32000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone SE (1st gen)", 1458518400ULL, 1536710400ULL},

    // iPhone 7 Series (A10 Fusion, 2 Cores, L2: 3MB, 375x667 @2x) [09/2016 - 09/2019]
    {"iPhone9,1",  "D10AP",   2, 2147483648ULL, 3145728ULL,  375.0, 667.0, 2.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7", 1473984000ULL, 1568160000ULL},
    {"iPhone9,3",  "D101AP",  2, 2147483648ULL, 3145728ULL,  375.0, 667.0, 2.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7", 1473984000ULL, 1568160000ULL},

    // iPhone 7 Plus Series (A10 Fusion, 2 Cores, 3GB RAM, L2: 3MB, 414x736 @3x) [09/2016 - 09/2019]
    {"iPhone9,2",  "D11AP",   2, 3221225472ULL, 3145728ULL,  414.0, 736.0, 3.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7 Plus", 1473984000ULL, 1568160000ULL},
    {"iPhone9,4",  "D111AP",  2, 3221225472ULL, 3145728ULL,  414.0, 736.0, 3.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7 Plus", 1473984000ULL, 1568160000ULL},

    // iPhone 8 Series (A11 Bionic, 6 Cores, 2GB RAM, L2: 8MB, 375x667 @2x) [09/2017 - 04/2020]
    {"iPhone10,1", "D20AP",   6, 2147483648ULL, 8388608ULL,  375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8", 1505952000ULL, 1586908800ULL},
    {"iPhone10,4", "D201AP",  6, 2147483648ULL, 8388608ULL,  375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8", 1505952000ULL, 1586908800ULL},

    // iPhone 8 Plus Series (A11 Bionic, 6 Cores, 3GB RAM, L2: 8MB, 414x736 @3x) [09/2017 - 04/2020]
    {"iPhone10,2", "D21AP",   6, 3221225472ULL, 8388608ULL,  414.0, 736.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8 Plus", 1505952000ULL, 1586908800ULL},
    {"iPhone10,5", "D211AP",  6, 3221225472ULL, 8388608ULL,  414.0, 736.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8 Plus", 1505952000ULL, 1586908800ULL},

    // iPhone X (A11 Bionic, 6 Cores, 3GB RAM, L2: 8MB, 375x812 @3x) [09/2017 - 09/2018]
    {"iPhone10,3", "D22AP",   6, 3221225472ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 0, 0},              15, 16, "iPhone X", 1505952000ULL, 1536710400ULL},
    {"iPhone10,6", "D221AP",  6, 3221225472ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 0, 0},              15, 16, "iPhone X", 1505952000ULL, 1536710400ULL},

    // iPhone XR / XS / XS Max Series (A12 Bionic, L2: 8MB) [09/2018 - 09/2021]
    {"iPhone11,8", "N841AP",  6, 3221225472ULL, 8388608ULL,  414.0, 896.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone XR", 1536710400ULL, 1631577600ULL},
    {"iPhone11,2", "D321AP",  6, 4294967296ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone XS", 1536710400ULL, 1568160000ULL},
    {"iPhone11,6", "D331pAP", 6, 4294967296ULL, 8388608ULL,  414.0, 896.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone XS Max", 1536710400ULL, 1568160000ULL},

    // iPhone 11 Series (A13 Bionic, 4GB RAM, L2: 8MB) [09/2019 - 09/2022]
    {"iPhone12,1", "N104AP",  6, 4294967296ULL, 8388608ULL,  414.0, 896.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone 11", 1568160000ULL, 1662508800ULL},
    {"iPhone12,3", "D421AP",  6, 4294967296ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 11 Pro", 1568160000ULL, 1602547200ULL},
    {"iPhone12,5", "D431AP",  6, 4294967296ULL, 8388608ULL,  414.0, 896.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 11 Pro Max", 1568160000ULL, 1602547200ULL},
    {"iPhone12,8", "D79AP",   6, 3221225472ULL, 8388608ULL,  375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone SE 2", 1587686400ULL, 1646784000ULL},

    // iPhone 12 Series (A14 Bionic, L2: 8MB) [10/2020 - 09/2023]
    {"iPhone13,1", "D52gAP",  6, 4294967296ULL, 8388608ULL,  360.0, 780.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone 12 mini", 1603411200ULL, 1662508800ULL},
    {"iPhone13,2", "D53gAP",  6, 4294967296ULL, 8388608ULL,  390.0, 844.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone 12", 1603411200ULL, 1694563200ULL},
    {"iPhone13,3", "D53pAP",  6, 6442450944ULL, 8388608ULL,  390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 12 Pro", 1603411200ULL, 1631577600ULL},
    {"iPhone13,4", "D54pAP",  6, 6442450944ULL, 8388608ULL,  428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 12 Pro Max", 1603411200ULL, 1631577600ULL},

    // iPhone 13 Series (A15 Bionic, L2: 12MB) [09/2021 - 09/2024]
    {"iPhone14,4", "D16AP",   6, 4294967296ULL, 12582912ULL, 360.0, 780.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 13 mini", 1632441600ULL, 1694563200ULL},
    {"iPhone14,5", "D17AP",   6, 4294967296ULL, 12582912ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 13", 1632441600ULL, 1725840000ULL},
    {"iPhone14,2", "D63AP",   6, 6442450944ULL, 12582912ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 15, 18, "iPhone 13 Pro", 1632441600ULL, 1662508800ULL},
    {"iPhone14,3", "D64AP",   6, 6442450944ULL, 12582912ULL, 428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 15, 18, "iPhone 13 Pro Max", 1632441600ULL, 1662508800ULL},
    {"iPhone14,6", "D49AP",   6, 4294967296ULL, 12582912ULL, 375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone SE 3", 1646784000ULL, 1725840000ULL},

    // iPhone 14 Series (A15 / A16 Bionic, L2: 16MB) [09/2022 - 09/2025]
    {"iPhone14,7", "D27AP",   6, 6442450944ULL, 16777216ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 16, 18, "iPhone 14", 1663286400ULL, 1757376000ULL},
    {"iPhone14,8", "D28AP",   6, 6442450944ULL, 16777216ULL, 428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 16, 18, "iPhone 14 Plus", 1663286400ULL, 1725840000ULL},
    {"iPhone15,2", "D73AP",   6, 6442450944ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 16, 18, "iPhone 14 Pro", 1663286400ULL, 1694563200ULL},
    {"iPhone15,3", "D74AP",   6, 6442450944ULL, 16777216ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 16, 18, "iPhone 14 Pro Max", 1663286400ULL, 1694563200ULL},

    // iPhone 15 Series (A16 / A17 Pro, L2: 16MB) [09/2023 - 09/2026]
    {"iPhone15,4", "D37AP",   6, 6442450944ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 15", 1694736000ULL, 1788739200ULL},
    {"iPhone15,5", "D38AP",   6, 6442450944ULL, 16777216ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 15 Plus", 1694736000ULL, 1757376000ULL},
    {"iPhone16,1", "D83AP",   6, 8589934592ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 15 Pro", 1694736000ULL, 1725840000ULL},
    {"iPhone16,2", "D84AP",   6, 8589934592ULL, 16777216ULL, 430.0, 932.0, 3.0, {256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 15 Pro Max", 1694736000ULL, 1725840000ULL},

    // iPhone 16 Series (A18 / A18 Pro, 8GB RAM, L2: 16MB, chỉ chạy iOS 18+) [09/2024 - 10/2026]
    {"iPhone17,3", "D47AP",   6, 8589934592ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 18, 18, "iPhone 16", 1726790400ULL, 1792000000ULL},
    {"iPhone17,4", "D48AP",   6, 8589934592ULL, 16777216ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 18, 18, "iPhone 16 Plus", 1726790400ULL, 1792000000ULL},
    {"iPhone17,1", "D93AP",   6, 8589934592ULL, 16777216ULL, 402.0, 874.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 18, 18, "iPhone 16 Pro", 1726790400ULL, 1792000000ULL},
    {"iPhone17,2", "D94AP",   6, 8589934592ULL, 16777216ULL, 440.0, 956.0, 3.0, {256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 18, 18, "iPhone 16 Pro Max", 1726790400ULL, 1792000000ULL}
};

typedef struct {
    const char *version; // "15.8.3", "17.6.1"
    const char *build;   // "19H386", "21G93"
    int major;           // 15, 16, 17, 18
} AppleOSRelease;

// Bảng phiên bản iOS thực tế & Build ID chính xác của Apple (Tối thiểu 15.1+ để Zalo hoạt động chuẩn)
static const AppleOSRelease kAppleOSReleases[] = {
    // iOS 15 Releases (iPhone 6s / 6s Plus / SE 1 / iPhone 7 / 7 Plus)
    {"15.4.1", "19E258",  15},
    {"15.5",   "19F77",   15},
    {"15.6",   "19G69",   15},
    {"15.6.1", "19G82",   15},
    {"15.7",   "19H12",   15},
    {"15.7.1", "19H117",  15},
    {"15.7.2", "19H218",  15},
    {"15.7.5", "19H332",  15},
    {"15.8",   "19H370",  15},
    {"15.8.1", "19H380",  15},
    {"15.8.2", "19H384",  15},
    {"15.8.3", "19H386",  15},

    // iOS 16 Releases (iPhone 8 / 8 Plus / X)
    {"16.5",    "20F66",  16},
    {"16.6",    "20G75",  16},
    {"16.6.1",  "20G81",  16},
    {"16.7.2",  "20H115", 16},
    {"16.7.5",  "20H307", 16},
    {"16.7.10", "20H350", 16},

    // iOS 17 Releases
    {"17.4",   "21E219",  17},
    {"17.4.1", "21E236",  17},
    {"17.5",   "21F79",   17},
    {"17.5.1", "21F90",   17},
    {"17.6",   "21G80",   17},
    {"17.6.1", "21G93",   17},
    {"17.7",   "21H16",   17},
    {"17.7.1", "21H216",  17},
    {"17.7.2", "21H221",  17},

    // iOS 18 Releases
    {"18.0",   "22A3354", 18},
    {"18.0.1", "22A3370", 18},
    {"18.1",   "22B83",   18},
    {"18.1.1", "22B91",   18},
    {"18.2",   "22C152",  18},
    {"18.2.1", "22C161",  18},
    {"18.3",   "22D63",   18},
    {"18.3.1", "22D72",   18}
};

NSString *generate_apple_serial(void) {
    const char chars[] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    char serial[13] = {0};
    // Tiền tố xuất xưởng Apple phổ biến (F17, F2L, DX3, G6T, H0V, C39, G0N...)
    const char *prefixes[] = {"F17", "F2L", "DX3", "G6T", "H0V", "C39", "G0N", "FK1", "DN6", "DLX"};
    const char *p = prefixes[arc4random_uniform(10)];
    serial[0] = p[0];
    serial[1] = p[1];
    serial[2] = p[2];
    for (int i = 3; i < 12; i++) {
        serial[i] = chars[arc4random_uniform(sizeof(chars) - 1)];
    }
    return [NSString stringWithUTF8String:serial];
}

NSString *generate_apple_mac(void) {
    // Các tiền tố OUI thực tế thuộc sở hữu của Apple Inc.
    const char *ouis[] = {
        "f0:18:98", "ac:de:48", "88:66:5a", "dc:a9:04", "a4:83:e7",
        "e0:c7:67", "bc:d1:1f", "f4:34:f0", "70:3e:ac", "38:f9:d3",
        "40:6c:8f", "5c:96:9d", "64:a3:cb", "8c:85:90", "a8:5b:78"
    };
    const char *oui = ouis[arc4random_uniform(15)];
    return [NSString stringWithFormat:@"%s:%02x:%02x:%02x", oui, arc4random_uniform(256), arc4random_uniform(256), arc4random_uniform(256)];
}

static NSString *detect_real_system_machine(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    sysctlbyname("hw.machine", buf, &size, NULL, 0);
    if (strlen(buf) > 0) {
        return [NSString stringWithUTF8String:buf];
    }
    struct utsname u;
    if (uname(&u) == 0 && strlen(u.machine) > 0) {
        return [NSString stringWithUTF8String:u.machine];
    }
    // Đối chiếu theo độ phân giải màn hình vật lý thực tế của thiết bị
    CGRect b = [UIScreen mainScreen].bounds;
    CGFloat s = [UIScreen mainScreen].scale;
    if (b.size.width == 375 && b.size.height == 667 && s == 2.0) {
        return @"iPhone9,1"; // Màn iPhone 7 / 8 / SE 2 / SE 3
    } else if (b.size.width == 390 && b.size.height == 844 && s == 3.0) {
        return @"iPhone14,5"; // Màn iPhone 12 / 12 Pro / 13 / 13 Pro / 14
    } else if (b.size.width == 414 && b.size.height == 896 && s == 2.0) {
        return @"iPhone12,1"; // Màn iPhone 11 / XR
    } else if (b.size.width == 414 && b.size.height == 736 && s == 3.0) {
        return @"iPhone10,2"; // Màn iPhone 7 Plus / 8 Plus
    } else if (b.size.width == 428 && b.size.height == 926 && s == 3.0) {
        return @"iPhone14,3"; // Màn iPhone 13 Pro Max / 14 Plus
    }
    return @"iPhone9,1";
}

@implementation ZTDeviceProfile

+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region {
    return [self generateRandomProfileForRegion:region baseMachine:nil];
}

+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region baseMachine:(NSString *)baseMachine {
    ZTDeviceProfile *profile = [[ZTDeviceProfile alloc] init];

    NSString *physicalMachine = baseMachine ?: detect_real_system_machine();
    size_t specCount = sizeof(kAppleDeviceSpecs) / sizeof(kAppleDeviceSpecs[0]);

    // 1. TÌM THÔNG SỐ VÀ DÒNG MÁY THỰC TẾ
    const AppleDeviceSpec *matchedBaseSpec = NULL;
    for (size_t i = 0; i < specCount; i++) {
        if ([physicalMachine isEqualToString:[NSString stringWithUTF8String:kAppleDeviceSpecs[i].machine]]) {
            matchedBaseSpec = &kAppleDeviceSpecs[i];
            break;
        }
    }

    // Nếu không khớp trực tiếp theo tên machine, dò theo kích thước màn hình vật lý
    if (matchedBaseSpec == NULL) {
        CGRect scrBounds = [UIScreen mainScreen].bounds;
        CGFloat scrScale = [UIScreen mainScreen].scale;
        for (size_t i = 0; i < specCount; i++) {
            if (fabs(kAppleDeviceSpecs[i].width - scrBounds.size.width) < 1.0 &&
                fabs(kAppleDeviceSpecs[i].height - scrBounds.size.height) < 1.0 &&
                fabs(kAppleDeviceSpecs[i].scale - scrScale) < 0.1) {
                matchedBaseSpec = &kAppleDeviceSpecs[i];
                break;
            }
        }
    }

    NSMutableArray *candidateSpecs = [NSMutableArray array];
    if (matchedBaseSpec != NULL) {
        // Khóa chặt: Chỉ fake sang các biến thể CÙNG FAMILY dòng máy với thiết bị vật lý
        // (vd: iPhone 8 chỉ fake sang iPhone 8 khác; iPhone 13 chỉ fake sang iPhone 13 khác)
        for (size_t i = 0; i < specCount; i++) {
            if (strcmp(kAppleDeviceSpecs[i].family, matchedBaseSpec->family) == 0) {
                [candidateSpecs addObject:[NSValue valueWithPointer:&kAppleDeviceSpecs[i]]];
            }
        }
    }

    // Tuyệt đối không fallback sang danh sách máy thuộc dòng khác!
    if (candidateSpecs.count == 0) {
        if (matchedBaseSpec != NULL) {
            [candidateSpecs addObject:[NSValue valueWithPointer:matchedBaseSpec]];
        } else {
            // Mặc định an toàn cho máy iPhone 7
            [candidateSpecs addObject:[NSValue valueWithPointer:&kAppleDeviceSpecs[0]]];
        }
    }

    // Tuyệt đối không fallback sang danh sách máy khác thông số màn hình!
    if (candidateSpecs.count == 0) {
        if (matchedBaseSpec != NULL) {
            [candidateSpecs addObject:[NSValue valueWithPointer:matchedBaseSpec]];
        } else {
            // Mặc định an toàn cho máy iPhone 7
            [candidateSpecs addObject:[NSValue valueWithPointer:&kAppleDeviceSpecs[0]]];
        }
    }

    NSValue *chosenSpecVal = candidateSpecs[arc4random_uniform((uint32_t)candidateSpecs.count)];
    const AppleDeviceSpec *chosenSpec = (const AppleDeviceSpec *)[chosenSpecVal pointerValue];
    AppleDeviceSpec spec = *chosenSpec;

    profile.deviceMachine = [NSString stringWithUTF8String:spec.machine];
    profile.deviceModel = [NSString stringWithUTF8String:spec.model];
    profile.ncpu = spec.ncpu;
    profile.memsize = spec.ramBytes;
    profile.l2cacheSize = spec.l2cacheBytes;
    profile.screenWidth = spec.width;
    profile.screenHeight = spec.height;
    profile.screenScale = spec.scale;

    // 2. CHỌN BẢN iOS TƯƠNG THÍCH VỚI DÒNG MÁY (iPhone 7: 15.x, iPhone 16: 18+)
    size_t osCount = sizeof(kAppleOSReleases) / sizeof(kAppleOSReleases[0]);
    NSMutableArray *validOSList = [NSMutableArray array];
    for (size_t i = 0; i < osCount; i++) {
        if (kAppleOSReleases[i].major >= spec.minIOS && kAppleOSReleases[i].major <= spec.maxIOS) {
            [validOSList addObject:[NSValue valueWithPointer:&kAppleOSReleases[i]]];
        }
    }
    if (validOSList.count == 0) {
        for (size_t i = 0; i < osCount; i++) {
            if (kAppleOSReleases[i].major >= spec.minIOS) {
                [validOSList addObject:[NSValue valueWithPointer:&kAppleOSReleases[i]]];
            }
        }
    }
    NSValue *chosenVal = validOSList[arc4random_uniform((uint32_t)validOSList.count)];
    const AppleOSRelease *chosenOS = (const AppleOSRelease *)[chosenVal pointerValue];

    profile.systemVersion = [NSString stringWithUTF8String:chosenOS->version];
    profile.kernOsVersion = [NSString stringWithUTF8String:chosenOS->build];

    // 3. CHỌN BỘ NHỚ Ổ CỨNG HỢP LỆ VỚI DÒNG MÁY ĐÓ
    int diskCount = 0;
    while (spec.supportedDisks[diskCount] != 0 && diskCount < 5) {
        diskCount++;
    }
    uint64_t totalDisk = spec.supportedDisks[arc4random_uniform((uint32_t)diskCount)];
    profile.diskTotalSize = totalDisk;

    // Dung lượng trống tự nhiên (từ 25% đến 75% tổng ổ cứng)
    double freeRatio = 0.25 + (((double)arc4random_uniform(50)) / 100.0);
    profile.diskFreeSize = (uint64_t)(totalDisk * freeRatio);

    // 4. KHO HƠN 100 TÊN THIẾT BỊ TỰ NHIÊN THEO VÙNG
    NSString *curRegion = region ?: @"VN";
    if ([curRegion isEqualToString:@"US_STUDENT"]) {
        NSArray *names = @[
            @"Alex's iPhone", @"Nam's iPhone", @"Huy's iPhone", @"Kevin's iPhone",
            @"Minh's iPhone", @"Trang's iPhone", @"Linh's iPhone", @"Duc's iPhone",
            @"Vy's iPhone", @"Phong's iPhone", @"Dan's iPhone", @"Jenny's iPhone",
            @"Brian's iPhone", @"Eric's iPhone", @"Jason's iPhone", @"Ryan's iPhone",
            @"Justin's iPhone", @"Andrew's iPhone", @"Matthew's iPhone", @"Brandon's iPhone",
            @"Tyler's iPhone", @"Emily's iPhone", @"Hannah's iPhone", @"Rachel's iPhone",
            @"Megan's iPhone", @"Lauren's iPhone", @"iPhone", @"iPhone (1)", @"iPhone (2)",
            @"Nam", @"Huy", @"Kevin", @"Alex", @"Alex's Phone"
        ];
        profile.deviceName = names[arc4random_uniform((uint32_t)names.count)];

        NSArray *carriers = @[
            @{@"name": @"T-Mobile",    @"mcc": @"310", @"mnc": @"260"},
            @{@"name": @"AT&T",        @"mcc": @"310", @"mnc": @"410"},
            @{@"name": @"Mint Mobile", @"mcc": @"310", @"mnc": @"260"},
            @{@"name": @"Verizon",     @"mcc": @"311", @"mnc": @"480"},
            @{@"name": @"Cricket",     @"mcc": @"310", @"mnc": @"150"}
        ];
        NSDictionary *c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        profile.carrierName = c[@"name"];
        profile.carrierMCC = c[@"mcc"];
        profile.carrierMNC = c[@"mnc"];
        profile.carrierCountryCode = @"us";
        profile.localeIdentifier = @"en_US";
        profile.preferredLanguages = @[@"en-US"];
        NSArray *usTimezones = @[@"America/New_York", @"America/Chicago", @"America/Los_Angeles", @"America/Denver"];
        profile.timeZoneName = usTimezones[arc4random_uniform((uint32_t)usTimezones.count)];
    } else if ([curRegion isEqualToString:@"US"]) {
        NSArray *names = @[
            @"David's iPhone", @"Michael's iPhone", @"Sarah's iPhone", @"John's iPhone",
            @"Daniel's iPhone", @"Chris's iPhone", @"Jessica's iPhone", @"James's iPhone",
            @"Robert's iPhone", @"William's iPhone", @"Joseph's iPhone", @"Thomas's iPhone",
            @"Charles's iPhone", @"Christopher's iPhone", @"Anthony's iPhone", @"Mark's iPhone",
            @"Donald's iPhone", @"Steven's iPhone", @"Paul's iPhone", @"Andrew's iPhone",
            @"Joshua's iPhone", @"Kenneth's iPhone", @"Kevin's iPhone", @"Brian's iPhone",
            @"George's iPhone", @"Timothy's iPhone", @"Ronald's iPhone", @"Jason's iPhone",
            @"Edward's iPhone", @"Jeffrey's iPhone", @"iPhone", @"iPhone (1)", @"iPhone (2)", @"iPhone (3)"
        ];
        profile.deviceName = names[arc4random_uniform((uint32_t)names.count)];

        NSArray *carriers = @[
            @{@"name": @"Verizon",  @"mcc": @"311", @"mnc": @"480"},
            @{@"name": @"AT&T",     @"mcc": @"310", @"mnc": @"410"},
            @{@"name": @"T-Mobile", @"mcc": @"310", @"mnc": @"260"}
        ];
        NSDictionary *c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        profile.carrierName = c[@"name"];
        profile.carrierMCC = c[@"mcc"];
        profile.carrierMNC = c[@"mnc"];
        profile.carrierCountryCode = @"us";
        profile.localeIdentifier = @"en_US";
        profile.preferredLanguages = @[@"en-US"];
        NSArray *usTimezones = @[@"America/New_York", @"America/Chicago", @"America/Los_Angeles", @"America/Denver"];
        profile.timeZoneName = usTimezones[arc4random_uniform((uint32_t)usTimezones.count)];
    } else {
        NSArray *names = @[
            @"iPhone", @"iPhone (1)", @"iPhone (2)", @"iPhone (3)",
            @"iPhone của Tuấn", @"iPhone của Linh", @"iPhone của Huy", @"iPhone của Nam",
            @"iPhone của Trang", @"iPhone của Hoàng", @"iPhone của Mai", @"iPhone của Lan",
            @"iPhone của Minh", @"iPhone của Đức", @"iPhone của Hùng", @"iPhone của Thảo",
            @"iPhone của Dũng", @"iPhone của Ngọc", @"iPhone của Phong", @"iPhone của Hương",
            @"iPhone của Long", @"iPhone của Quỳnh", @"iPhone của Khánh", @"iPhone của Vy",
            @"iPhone của An", @"iPhone của Quân", @"iPhone của Sơn", @"iPhone của Hà",
            @"iPhone của Tiến", @"iPhone của Duy", @"iPhone của Phương", @"iPhone của Kiên",
            @"iPhone của Trâm", @"iPhone của Đạt", @"iPhone của Giang", @"iPhone của Việt",
            @"iPhone của Huyền", @"iPhone của Tâm", @"iPhone của Ly", @"iPhone của Bình",
            @"iPhone của Hằng", @"iPhone của Thành", @"iPhone của Yến", @"iPhone của Thắng",
            @"iPhone của Khoa", @"iPhone của Nhung", @"iPhone của Trung", @"iPhone của Hiếu",
            @"Tuấn", @"Linh", @"Huy", @"Nam", @"Trang", @"Hoàng", @"Mai", @"Đức",
            [NSString stringWithUTF8String:spec.family] ?: @"iPhone"
        ];
        profile.deviceName = names[arc4random_uniform((uint32_t)names.count)];

        NSArray *carriers = @[
            @{@"name": @"Viettel",       @"mcc": @"452", @"mnc": @"04"},
            @{@"name": @"VINAPHONE",     @"mcc": @"452", @"mnc": @"02"},
            @{@"name": @"VN MOBIFONE",   @"mcc": @"452", @"mnc": @"01"},
            @{@"name": @"Vietnamobile",  @"mcc": @"452", @"mnc": @"05"}
        ];
        NSDictionary *c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        profile.carrierName = c[@"name"];
        profile.carrierMCC = c[@"mcc"];
        profile.carrierMNC = c[@"mnc"];
        profile.carrierCountryCode = @"vn";
        profile.localeIdentifier = @"vi_VN";
        profile.preferredLanguages = @[@"vi-VN", @"en-VN"];
        profile.timeZoneName = @"Asia/Ho_Chi_Minh";
    }

    // 5. CÁC THÔNG SỐ ĐỊNH DANH DUY NHẤT & MÃ BẢO VỆ
    profile.spoofedIDFV = [[NSUUID UUID] UUIDString];
    profile.spoofedIDFA = @"00000000-0000-0000-0000-000000000000"; // Chuẩn Apple ATT Denied
    profile.profileId = [[NSUUID UUID] UUIDString];
    profile.bootSessionUUID = [[NSUUID UUID] UUIDString];

    // Uptime ngẫu nhiên (từ 6 giờ đến 12 ngày trước) kèm jitter giây lẻ
    uint32_t randomOffset = 21600 + (arc4random_uniform(1036800)) + arc4random_uniform(59);
    profile.bootTimeSec = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;

    // Ngày sinh ổ đĩa chuẩn xác theo vòng đời sản xuất của Apple
    uint64_t launch = spec.launchTimestamp ?: 1568160000ULL;
    uint64_t eol = spec.eolTimestamp ?: (launch + 94608000ULL);
    uint64_t span = (eol > launch) ? (eol - launch) : 86400ULL;
    profile.birthTimeSec = launch + arc4random_uniform((uint32_t)span);
    // Đảm bảo ngày xuất xưởng / cài đặt luôn xảy ra trước BootTime ít nhất vài tuần và không trùng giây
    if (profile.birthTimeSec >= profile.bootTimeSec) {
        profile.birthTimeSec = profile.bootTimeSec - (86400ULL * 30ULL + arc4random_uniform(86400 * 180) + arc4random_uniform(3599));
    }

    // Pin ngẫu nhiên (50% - 96%) và không cắm sạc
    profile.batteryLevel = 0.50f + ((float)arc4random_uniform(46)) / 100.0f;
    profile.batteryState = 1; // UIDeviceBatteryStateUnplugged

    // Serial & MAC chuẩn Apple
    profile.spoofedSerial = generate_apple_serial();
    profile.spoofedWifiMAC = generate_apple_mac();
    profile.spoofedBluetoothMAC = generate_apple_mac();

    return profile;
}

@end
