#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

@interface ZTSettings : NSObject

@property (nonatomic, assign) BOOL enabled;
@property (nonatomic, strong) NSString *deviceMachine;     // hw.machine: vd "iPhone14,2"
@property (nonatomic, strong) NSString *deviceModel;       // hw.model: vd "D63AP"
@property (nonatomic, strong) NSString *deviceName;        // UIDevice.name: vd "iPhone"
@property (nonatomic, strong) NSString *systemVersion;     // UIDevice.systemVersion: vd "16.5"
@property (nonatomic, strong) NSString *kernOsVersion;     // kern.osversion: vd "20F66"
@property (nonatomic, assign) uint32_t ncpu;               // hw.ncpu: 6
@property (nonatomic, assign) uint64_t memsize;            // hw.memsize: 6GB RAM
@property (nonatomic, assign) CGFloat screenWidth;         // pt width (vd: 390.0)
@property (nonatomic, assign) CGFloat screenHeight;        // pt height (vd: 844.0)
@property (nonatomic, assign) CGFloat screenScale;         // scale (vd: 3.0)
@property (nonatomic, assign) uint64_t bootTimeSec;        // kern.boottime sec
@property (nonatomic, strong) NSString *bootSessionUUID;   // kern.bootsessionuuid
@property (nonatomic, strong) NSString *spoofedIDFV;       // identifierForVendor UUID
@property (nonatomic, strong) NSString *spoofedIDFA;       // advertisingIdentifier IDFA
@property (nonatomic, strong) NSString *profileId;         // Dùng để cách ly Keychain theo profile
@property (nonatomic, assign) uint64_t diskTotalSize;      // Dung lượng tổng ổ cứng (bytes)
@property (nonatomic, assign) uint64_t diskFreeSize;       // Dung lượng trống ổ cứng (bytes)
@property (nonatomic, assign) BOOL enableAuditLog;         // Bật ghi nhật ký kiểm toán Zalo (Audit Mode)
@property (nonatomic, strong) NSString *lastWipedIDFV;     // IDFV lần wipe trước
@property (nonatomic, strong) NSString *lastWipedIP;       // IP mạng lần wipe trước
@property (nonatomic, assign) uint64_t lastWipedTimestamp; // Thời điểm wipe lần trước
@property (nonatomic, strong) NSString *carrierName;        // Tên nhà mạng (vd: "Viettel", "VN MOBIFONE", "VINAPHONE")
@property (nonatomic, strong) NSString *carrierMCC;         // Mobile Country Code (vd: "452")
@property (nonatomic, strong) NSString *carrierMNC;         // Mobile Network Code (vd: "04", "01", "02")
@property (nonatomic, strong) NSString *carrierCountryCode; // Country Code ISO (vd: "vn")
@property (nonatomic, assign) float batteryLevel;           // Mức pin (vd: 0.82)
@property (nonatomic, assign) NSInteger batteryState;       // Trạng thái pin (UIDeviceBatteryStateUnplugged = 1)
@property (nonatomic, strong) NSString *regionMode;        // Khu vực: @"VN", @"US_STUDENT", @"US"
@property (nonatomic, strong) NSString *spoofedSerial;      // Serial Number (vd: "F17X892JK9L")
@property (nonatomic, strong) NSString *spoofedWifiMAC;     // Wi-Fi MAC Address
@property (nonatomic, strong) NSString *spoofedBluetoothMAC;// Bluetooth MAC Address
@property (nonatomic, assign) BOOL showFloatingMenu;        // Hiện nút nổi trong app (Mặc định NO cho Zalo gốc, YES cho Clone)

+ (instancetype)sharedSettings;
- (void)loadSettings;
- (void)saveSettings;
- (void)generateNewProfile;

@end
