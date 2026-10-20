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
@property (nonatomic, copy, nullable) NSString *cfBundleId;
@property (nonatomic, copy, nullable) NSString *realBundleId;
@property (nonatomic, copy, nullable) NSString *apnsPushStatus;
@property (nonatomic, assign) BOOL isCloneApp;
@property (nonatomic, copy, nullable) NSString *mnoCarrierName;
@property (nonatomic, copy, nullable) NSString *telemetryDId;
@property (nonatomic, copy) NSString *idfa;
@property (nonatomic, copy) NSString *serial;
@property (nonatomic, copy) NSString *wifiMAC;
@property (nonatomic, copy) NSString *regionName;
@property (nonatomic, copy) NSString *carrierName;
@property (nonatomic, copy, nullable) NSString *preferredCarrier;
@property (nonatomic, copy) NSString *carrierMCC;
@property (nonatomic, copy) NSString *carrierMNC;
@property (nonatomic, copy, nullable) NSString *carrierCountryCode;
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
@property (nonatomic, assign) BOOL keychainCleanPassed;
@property (nonatomic, assign) NSInteger keychainRemainingCount;
@property (nonatomic, assign) BOOL webkitCleanPassed;
@property (nonatomic, assign) BOOL clipboardCleanPassed;
@property (nonatomic, copy) NSString *runtimeEnvDesc;

// Đồng bộ Vùng, Múi Giờ & Ngôn Ngữ
@property (nonatomic, copy) NSString *localeIdentifier;
@property (nonatomic, copy) NSString *timeZoneName;
@property (nonatomic, copy) NSString *timeZoneGMT;
@property (nonatomic, copy) NSString *preferredLanguages;
@property (nonatomic, copy, nullable) NSString *keyboardInputModeText;
@property (nonatomic, assign) BOOL regionSyncPassed;

// Phần cứng Radar mới
@property (nonatomic, copy) NSString *hwProduct;
@property (nonatomic, assign) uint32_t l2CacheSizeMB;
@property (nonatomic, assign) uint32_t pageSizeKB;
@property (nonatomic, assign) int procTranslated;
@property (nonatomic, copy, nullable) NSString *darwinKernelRelease;
@property (nonatomic, copy, nullable) NSString *batteryStatusText;
@property (nonatomic, copy, nullable) NSString *mgDiskCapacityText;
@property (nonatomic, copy, nullable) NSString *liveInterfacesText;
@property (nonatomic, assign) BOOL sysctlPassed;

// Ngày giờ cụ thể cho Ổ đĩa, Boot Time & Đồng bộ 3 Đồng Hồ Uptime
@property (nonatomic, copy) NSString *birthTimeText;
@property (nonatomic, copy) NSString *bootTimeText;
@property (nonatomic, copy, nullable) NSString *uptimeSyncText;
@property (nonatomic, assign) BOOL uptimeSyncPassed;

// Ẩn Dylib (dyld / dladdr) & Push Token (APNs / VoIP)
@property (nonatomic, copy, nullable) NSString *dyldHideText;
@property (nonatomic, assign) BOOL dyldHidePassed;
@property (nonatomic, copy, nullable) NSString *voipPushStatus;
@property (nonatomic, assign) BOOL pushTokenPassed;
@property (nonatomic, copy, nullable) NSString *zcidAuditText;
@property (nonatomic, assign) BOOL zcidAuditPassed;

// Thông tin Kiểm Tra Mạng & IP Nâng Cao
@property (nonatomic, copy, nullable) NSString *testedIP;
@property (nonatomic, copy, nullable) NSString *ipCountry;
@property (nonatomic, copy, nullable) NSString *ipCountryCode;
@property (nonatomic, copy, nullable) NSString *ipRegionName;
@property (nonatomic, copy, nullable) NSString *ipCity;
@property (nonatomic, copy, nullable) NSString *ipTimezone;
@property (nonatomic, copy, nullable) NSString *ipISP;
@property (nonatomic, copy, nullable) NSString *ipOrg;
@property (nonatomic, copy, nullable) NSString *ipASN;
@property (nonatomic, assign) BOOL ipIsHosting;
@property (nonatomic, assign) BOOL ipIsProxy;
@property (nonatomic, assign) BOOL ipIsMobile;
@property (nonatomic, copy, nullable) NSString *ipTypeDesc;
@property (nonatomic, assign) BOOL ipCheckCompleted;
@property (nonatomic, assign) BOOL ipCleanPassed;

// Thông tin Đối Chiếu Số Điện Thoại
@property (nonatomic, copy, nullable) NSString *inputPhone;
@property (nonatomic, copy, nullable) NSString *phoneCountryCode;
@property (nonatomic, copy, nullable) NSString *phoneCountryName;
@property (nonatomic, copy, nullable) NSString *phoneCarrierName;
@property (nonatomic, copy, nullable) NSString *phoneLineType;
@property (nonatomic, assign) BOOL phoneIsVoIP;
@property (nonatomic, assign) BOOL phoneCheckCompleted;
@property (nonatomic, assign) BOOL phonePassed;

// Kết quả Đối Chiếu Chéo 3 Chiều & Nhà Mạng
@property (nonatomic, assign) BOOL matchGeoPassed;
@property (nonatomic, copy, nullable) NSString *matchGeoReason;
@property (nonatomic, assign) BOOL matchTimezonePassed;
@property (nonatomic, copy, nullable) NSString *matchTimezoneReason;
@property (nonatomic, assign) BOOL matchProfilePassed;
@property (nonatomic, copy, nullable) NSString *matchProfileReason;
@property (nonatomic, assign) BOOL matchCarrierPassed;
@property (nonatomic, copy, nullable) NSString *matchCarrierReason;
@property (nonatomic, copy, nullable) NSString *suggestedCarrier;

// ==========================================
// PRE-FLIGHT AUDIT 8/8 NHÓM CHỈ SỐ CỐT LÕI
// ==========================================
// Nhóm 1: Kết Nối Mạng & Socket (Cellular / Wifi)
@property (nonatomic, assign) BOOL socketCellularPassed;
@property (nonatomic, copy, nullable) NSString *socketCellularText;
@property (nonatomic, assign) BOOL countryApiPassed;
@property (nonatomic, copy, nullable) NSString *countryApiText;
@property (nonatomic, assign) BOOL ifaddrsCleanPassed;
@property (nonatomic, copy, nullable) NSString *ifaddrsCleanText;
@property (nonatomic, copy, nullable) NSString *networkBundleIdText;

// Nhóm 2: Định Danh Máy Chủ Zalo (Centralized ID & Telemetry)
@property (nonatomic, assign) BOOL dIdReceivedPassed;
@property (nonatomic, copy, nullable) NSString *dIdStatusText;
@property (nonatomic, assign) BOOL zagidReceivedPassed;
@property (nonatomic, copy, nullable) NSString *zagidStatusText;
@property (nonatomic, assign) BOOL qosPassed;
@property (nonatomic, copy, nullable) NSString *qosStatusText;

// Nhóm 3: Thông Tin SIM & Nhà Mạng (MNO)
@property (nonatomic, assign) BOOL mnoCleanPassed;
@property (nonatomic, copy, nullable) NSString *mnoStatusText;

// Nhóm 4: Đồng Bộ 3 Tầng Đồng Hồ Uptime
@property (nonatomic, copy, nullable) NSString *uptime3ClockDetails;

// Nhóm 5: Bộ 3 Timestamp device_id (/var/mobile)
@property (nonatomic, copy, nullable) NSString *deviceIdDetails;

// Nhóm 6: Phần Cứng & Hệ Điều Hành
@property (nonatomic, copy, nullable) NSString *hardwareSummaryText;

// Nhóm 7: Ẩn Dấu Vết Jailbreak & PAC Stripping
@property (nonatomic, assign) BOOL pacStripPassed;
@property (nonatomic, copy, nullable) NSString *pacStripText;
@property (nonatomic, assign) BOOL jbHidePassed;
@property (nonatomic, copy, nullable) NSString *jbHideText;

// Nhóm 8: Push Notification Tokens (APNs & VoIP)
@property (nonatomic, copy, nullable) NSString *pushTokensSummary;

// Nhóm 9: Bộ Kiểm Tra Chống Ban 3 Giờ (Anti-Detection Live Tests)
@property (nonatomic, assign) BOOL nsurlDiskPassed;
@property (nonatomic, copy, nullable) NSString *nsurlDiskText;
@property (nonatomic, assign) BOOL statvfsPassed;
@property (nonatomic, copy, nullable) NSString *statvfsText;
@property (nonatomic, assign) BOOL readlinkPassed;
@property (nonatomic, copy, nullable) NSString *readlinkText;
@property (nonatomic, assign) BOOL forkPassed;
@property (nonatomic, copy, nullable) NSString *forkText;
@property (nonatomic, assign) BOOL antiDebugPassed;
@property (nonatomic, copy, nullable) NSString *antiDebugText;
@property (nonatomic, assign) BOOL appsDirCleanPassed;
@property (nonatomic, copy, nullable) NSString *appsDirCleanText;
@property (nonatomic, assign) BOOL mnoFormatPassed;
@property (nonatomic, copy, nullable) NSString *mnoFormatText;
@property (nonatomic, assign) BOOL apnsGenuinePassed;
@property (nonatomic, copy, nullable) NSString *apnsGenuineText;
@property (nonatomic, assign) BOOL voipAuditPassed;
@property (nonatomic, copy, nullable) NSString *voipAuditText;
@property (nonatomic, assign) BOOL lifecycleLogPassed;
@property (nonatomic, copy, nullable) NSString *lifecycleLogText;

// Tổng kết Pre-flight
@property (nonatomic, assign) BOOL preflightCompleted;
@property (nonatomic, assign) BOOL preflightAllPassed;
@property (nonatomic, copy, nullable) NSString *preflightScoreText;
@property (nonatomic, copy, nullable) NSString *preflightVerdictTitle;
@property (nonatomic, copy, nullable) NSString *preflightVerdictDesc;

@end

FOUNDATION_EXPORT void ZTRun8AntiBanTests(ZTDiagnosticInfo *info);

@interface ZTDiagnosticViewController : UIViewController

- (instancetype)initWithInfo:(ZTDiagnosticInfo *)info;
+ (void)presentFrom:(UIViewController *)presenter info:(ZTDiagnosticInfo *)info;
- (void)runPreflightLiveAuditWithCompletion:(nullable void (^)(void))completion;

@end

NS_ASSUME_NONNULL_END
