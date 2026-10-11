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
@property (nonatomic, strong) NSString *profileId;         // Dùng để cách ly Keychain theo profile
@property (nonatomic, assign) uint64_t diskTotalSize;      // Dung lượng tổng ổ cứng (bytes)
@property (nonatomic, assign) uint64_t diskFreeSize;       // Dung lượng trống ổ cứng (bytes)

+ (instancetype)sharedSettings;
- (void)loadSettings;
- (void)saveSettings;
- (void)generateNewProfile;

@end
