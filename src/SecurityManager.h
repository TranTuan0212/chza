#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZTSecurityManager : NSObject

@property (nonatomic, copy, readonly) NSString *realUDID;
@property (nonatomic, copy, readonly, nullable) NSString *currentLicenseKey;
@property (nonatomic, copy, readonly, nullable) NSDate *expiryDate;
@property (nonatomic, assign, readonly) BOOL isLicenseActive;

+ (instancetype)sharedManager;

// Lấy định danh UDID phần cứng thật của iPhone
- (NSString *)getRealHardwareUDID;

// Kiểm tra bản quyền thời gian thực (nhanh, an toàn, có cache chữ ký số)
- (BOOL)isLicenseValid;

// Chuỗi mô tả trạng thái bản quyền hiển thị trên giao diện Settings
- (NSString *)getLicenseStatusText;

// Gọi Supabase RPC để xác thực key và khóa máy
- (void)verifyLicenseWithKey:(NSString *)licenseKey completion:(void (^)(BOOL success, NSString *message))completion;

// Xóa thông tin bản quyền (đổi key)
- (void)resetLicense;

// Đường dẫn lưu file bản quyền
- (NSString *)getLicenseFilePath;

// Lưu thông tin bản quyền và đồng bộ
- (void)saveLicenseWithKey:(NSString *)key expiresAt:(NSString *)expiryStr token:(NSString *)token;

@end

#ifdef __cplusplus
extern "C" {
#endif

// Kiểm tra bản quyền thời gian thực ở tầng C (Bypass qua Objective-C runtime, miễn nhiễm Flex 3 / Frida)
BOOL ZTSecurityCheckLicenseFast(void);

// Kiểm tra phát hiện can thiệp/bẻ khóa (Debug, Swizzle, ARM64 Hook)
BOOL ZTSecurityDetectTampering(void);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
