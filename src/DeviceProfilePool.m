#import "DeviceProfilePool.h"
#import <UIKit/UIKit.h>

typedef struct {
    const char *machine;        // hw.machine, vd: "iPhone14,5"
    const char *model;          // hw.model, vd: "D17AP"
    uint32_t ncpu;              // 6
    uint64_t ramBytes;          // 4GB, 6GB, 8GB
    CGFloat width;              // pt width
    CGFloat height;             // pt height
    CGFloat scale;              // 2.0 hoặc 3.0
    uint64_t supportedDisks[5]; // Danh sách bộ nhớ hợp lệ (bytes), kết thúc bằng 0
    int minIOS;                 // 17 hoặc 18 (vd: iPhone 16 chỉ từ 18 trở lên)
} AppleDeviceSpec;

// Ngân hàng 25 dòng iPhone chuẩn xác 100% phần cứng của Apple
static const AppleDeviceSpec kAppleDeviceSpecs[] = {
    // iPhone 11 Series (A13 Bionic, 4GB RAM)
    {"iPhone12,1", "N104AP", 6, 4294967296ULL, 414.0, 896.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 17},
    {"iPhone12,3", "D421AP", 6, 4294967296ULL, 375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17},
    {"iPhone12,5", "D431AP", 6, 4294967296ULL, 414.0, 896.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17},
    {"iPhone12,8", "D79AP",  6, 3221225472ULL, 375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 17}, // SE 2

    // iPhone 12 Series (A14 Bionic)
    {"iPhone13,1", "D52gAP", 6, 4294967296ULL, 360.0, 780.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 17}, // 12 mini
    {"iPhone13,2", "D53gAP", 6, 4294967296ULL, 390.0, 844.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 17}, // 12
    {"iPhone13,3", "D53pAP", 6, 6442450944ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 12 Pro
    {"iPhone13,4", "D54pAP", 6, 6442450944ULL, 428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 12 Pro Max

    // iPhone 13 Series (A15 Bionic)
    {"iPhone14,4", "D16AP",  6, 4294967296ULL, 360.0, 780.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 13 mini
    {"iPhone14,5", "D17AP",  6, 4294967296ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 13
    {"iPhone14,2", "D63AP",  6, 6442450944ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17}, // 13 Pro
    {"iPhone14,3", "D64AP",  6, 6442450944ULL, 428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17}, // 13 Pro Max
    {"iPhone14,6", "D49AP",  6, 4294967296ULL, 375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 17}, // SE 3

    // iPhone 14 Series (A15 / A16 Bionic)
    {"iPhone14,7", "D27AP",  6, 6442450944ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 14
    {"iPhone14,8", "D28AP",  6, 6442450944ULL, 428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 14 Plus
    {"iPhone15,2", "D73AP",  6, 6442450944ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17}, // 14 Pro
    {"iPhone15,3", "D74AP",  6, 6442450944ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17}, // 14 Pro Max

    // iPhone 15 Series (A16 / A17 Pro)
    {"iPhone15,4", "D37AP",  6, 6442450944ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 15
    {"iPhone15,5", "D38AP",  6, 6442450944ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17}, // 15 Plus
    {"iPhone16,1", "D83AP",  6, 8589934592ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17}, // 15 Pro
    {"iPhone16,2", "D84AP",  6, 8589934592ULL, 430.0, 932.0, 3.0, {256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17}, // 15 Pro Max (Từ 256GB)

    // iPhone 16 Series (A18 / A18 Pro, 8GB RAM, chỉ chạy iOS 18+)
    {"iPhone17,3", "D47AP",  6, 8589934592ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 18}, // 16
    {"iPhone17,4", "D48AP",  6, 8589934592ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 18}, // 16 Plus
    {"iPhone17,1", "D93AP",  6, 8589934592ULL, 402.0, 874.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 18}, // 16 Pro
    {"iPhone17,2", "D94AP",  6, 8589934592ULL, 440.0, 956.0, 3.0, {256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 18}  // 16 Pro Max
};

typedef struct {
    const char *version; // "17.6.1"
    const char *build;   // "21G93"
    int major;           // 17 hoặc 18
} AppleOSRelease;

// Bảng phiên bản iOS thực tế & Build ID chính xác của Apple
static const AppleOSRelease kAppleOSReleases[] = {
    {"17.4",   "21E219",  17},
    {"17.4.1", "21E236",  17},
    {"17.5",   "21F79",   17},
    {"17.5.1", "21F90",   17},
    {"17.6",   "21G80",   17},
    {"17.6.1", "21G93",   17},
    {"17.7",   "21H16",   17},
    {"17.7.1", "21H216",  17},
    {"17.7.2", "21H221",  17},
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

@implementation ZTDeviceProfile

+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region {
    ZTDeviceProfile *profile = [[ZTDeviceProfile alloc] init];

    // 1. CHỌN NGẪU NHIÊN 1 DÒNG IPHONE TRONG 25 MẪU PHẦN CỨNG CHUẨN
    size_t specCount = sizeof(kAppleDeviceSpecs) / sizeof(kAppleDeviceSpecs[0]);
    AppleDeviceSpec spec = kAppleDeviceSpecs[arc4random_uniform((uint32_t)specCount)];

    profile.deviceMachine = [NSString stringWithUTF8String:spec.machine];
    profile.deviceModel = [NSString stringWithUTF8String:spec.model];
    profile.ncpu = spec.ncpu;
    profile.memsize = spec.ramBytes;
    profile.screenWidth = spec.width;
    profile.screenHeight = spec.height;
    profile.screenScale = spec.scale;

    // 2. CHỌN BẢN iOS TƯƠNG THÍCH VỚI DÒNG MÁY (iPhone 16 chỉ chạy iOS 18+)
    size_t osCount = sizeof(kAppleOSReleases) / sizeof(kAppleOSReleases[0]);
    NSMutableArray *validOSList = [NSMutableArray array];
    for (size_t i = 0; i < osCount; i++) {
        if (kAppleOSReleases[i].major >= spec.minIOS) {
            [validOSList addObject:[NSValue valueWithPointer:&kAppleOSReleases[i]]];
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
            @"iPhone 13", @"iPhone 14", @"iPhone 15", @"iPhone Pro"
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
    }

    // 5. CÁC THÔNG SỐ ĐỊNH DANH DUY NHẤT & MÃ BẢO VỆ
    profile.spoofedIDFV = [[NSUUID UUID] UUIDString];
    profile.spoofedIDFA = @"00000000-0000-0000-0000-000000000000"; // Chuẩn Apple ATT Denied
    profile.profileId = [[NSUUID UUID] UUIDString];
    profile.bootSessionUUID = [[NSUUID UUID] UUIDString];

    // Uptime ngẫu nhiên (từ 6 giờ đến 12 ngày trước)
    uint32_t randomOffset = 21600 + (arc4random_uniform(1036800));
    profile.bootTimeSec = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;

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
