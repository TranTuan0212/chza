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

@end

@interface ZTDiagnosticViewController : UIViewController

- (instancetype)initWithInfo:(ZTDiagnosticInfo *)info;
+ (void)presentFrom:(UIViewController *)presenter info:(ZTDiagnosticInfo *)info;

@end

NS_ASSUME_NONNULL_END
