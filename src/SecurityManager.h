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

@end

NS_ASSUME_NONNULL_END
