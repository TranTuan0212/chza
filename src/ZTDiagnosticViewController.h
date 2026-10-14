#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZTDiagnosticInfo : NSObject

@property (nonatomic, copy) NSString *currentIP;
@property (nonatomic, copy, nullable) NSString *lastWipedIP;
@property (nonatomic, copy) NSString *currentIDFV;
@property (nonatomic, copy, nullable) NSString *lastWipedIDFV;
@property (nonatomic, copy) NSString *deviceName;
@property (nonatomic, copy) NSString *deviceMachine;
@property (nonatomic, copy) NSString *iosVersion;
@property (nonatomic, copy) NSString *bundleId;
@property (nonatomic, copy) NSString *idfa;
@property (nonatomic, copy) NSString *serial;
@property (nonatomic, copy) NSString *wifiMAC;
@property (nonatomic, copy) NSString *regionName;
@property (nonatomic, copy) NSString *carrierName;
@property (nonatomic, copy) NSString *carrierMCC;
@property (nonatomic, copy) NSString *carrierMNC;
@property (nonatomic, assign) double sandboxKB;
@property (nonatomic, assign) BOOL leveldbOK;
@property (nonatomic, assign) BOOL isHiddenProv;
@property (nonatomic, assign) BOOL isLicensed;
@property (nonatomic, copy) NSString *licenseStatusText;
@property (nonatomic, assign) double diskFreeGB;
@property (nonatomic, assign) double diskTotalGB;
@property (nonatomic, assign) uint64_t uptimeHours;
@property (nonatomic, assign) BOOL hasConfiguredProfile;

@property (nonatomic, copy) NSString *hardwareDeviceId;
@property (nonatomic, assign) BOOL deviceIdPassed;

@property (nonatomic, copy) NSString *armFeaturesSummary;
@property (nonatomic, assign) BOOL armCpuPassed;

@property (nonatomic, copy) NSString *installTimeText;
@property (nonatomic, assign) BOOL installTimePassed;

@property (nonatomic, copy) NSString *screenResolutionText;
@property (nonatomic, assign) BOOL screenResolutionPassed;

@property (nonatomic, assign) BOOL keychainIsolated;
@property (nonatomic, copy) NSString *runtimeEnvDesc;

// Đồng bộ Vùng, Múi Giờ & Ngôn Ngữ
@property (nonatomic, copy) NSString *localeIdentifier;
@property (nonatomic, copy) NSString *timeZoneName;
@property (nonatomic, copy) NSString *timeZoneGMT;
@property (nonatomic, copy) NSString *preferredLanguages;
@property (nonatomic, assign) BOOL regionSyncPassed;

// Phần cứng Radar mới
@property (nonatomic, copy) NSString *hwProduct;
@property (nonatomic, assign) uint32_t l2CacheSizeMB;
@property (nonatomic, assign) uint32_t pageSizeKB;
@property (nonatomic, assign) int procTranslated;
@property (nonatomic, assign) BOOL sysctlPassed;

// Ngày giờ cụ thể cho Ổ đĩa & Boot Time
@property (nonatomic, copy) NSString *birthTimeText;
@property (nonatomic, copy) NSString *bootTimeText;

@end

@interface ZTDiagnosticViewController : UIViewController

- (instancetype)initWithInfo:(ZTDiagnosticInfo *)info;
+ (void)presentFrom:(UIViewController *)presenter info:(ZTDiagnosticInfo *)info;

@end

NS_ASSUME_NONNULL_END
