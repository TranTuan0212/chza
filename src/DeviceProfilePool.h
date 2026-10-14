#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZTDeviceProfile : NSObject

@property (nonatomic, copy) NSString *deviceMachine;     // hw.machine: "iPhone14,5"
@property (nonatomic, copy) NSString *deviceModel;       // hw.model: "D17AP"
@property (nonatomic, assign) uint32_t ncpu;             // hw.ncpu: 6
@property (nonatomic, assign) uint64_t memsize;          // hw.memsize: RAM (bytes)
@property (nonatomic, assign) CGFloat screenWidth;       // pt width
@property (nonatomic, assign) CGFloat screenHeight;      // pt height
@property (nonatomic, assign) CGFloat screenScale;       // scale (2.0 hoặc 3.0)
@property (nonatomic, copy) NSString *systemVersion;     // "17.6.1"
@property (nonatomic, copy) NSString *kernOsVersion;     // "21G93"
@property (nonatomic, assign) uint64_t diskTotalSize;    // Tổng dung lượng ổ cứng (bytes)
@property (nonatomic, assign) uint64_t diskFreeSize;     // Dung lượng trống (bytes)
@property (nonatomic, copy) NSString *deviceName;        // Tên máy: "iPhone của Linh"
@property (nonatomic, copy) NSString *spoofedSerial;     // Apple Serial Number
@property (nonatomic, copy) NSString *spoofedWifiMAC;    // Wi-Fi MAC Address
@property (nonatomic, copy) NSString *spoofedBluetoothMAC;// Bluetooth MAC Address
@property (nonatomic, copy) NSString *carrierName;        // Nhà mạng (Viettel, T-Mobile...)
@property (nonatomic, copy) NSString *carrierMCC;         // Mobile Country Code (452, 310...)
@property (nonatomic, copy) NSString *carrierMNC;         // Mobile Network Code (04, 260...)
@property (nonatomic, copy) NSString *carrierCountryCode; // Country ISO ("vn", "us"...)
@property (nonatomic, assign) float batteryLevel;         // Mức pin (0.50 - 0.95)
@property (nonatomic, assign) NSInteger batteryState;     // 1 (Unplugged)
@property (nonatomic, assign) uint64_t bootTimeSec;        // Uptime timestamp
@property (nonatomic, copy) NSString *bootSessionUUID;   // Boot session UUID
@property (nonatomic, copy) NSString *spoofedIDFV;       // IDFV duy nhất
@property (nonatomic, copy) NSString *spoofedIDFA;       // "00000000-0000-0000-0000-000000000000"
@property (nonatomic, assign) uint64_t l2cacheSize;      // hw.l2cachesize (bytes)
@property (nonatomic, copy) NSString *localeIdentifier;  // "vi_VN", "en_US"
@property (nonatomic, copy) NSString *timeZoneName;      // "Asia/Ho_Chi_Minh", "America/New_York"
@property (nonatomic, strong) NSArray<NSString *> *preferredLanguages; // @[@"vi-VN"]
@property (nonatomic, copy) NSString *profileId;         // Profile UUID

+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region;
+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region baseMachine:(nullable NSString *)baseMachine;

@end

NSString *generate_apple_serial(void);
NSString *generate_apple_mac(void);

NS_ASSUME_NONNULL_END
