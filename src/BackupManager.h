#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZTBackupManager : NSObject <UIDocumentPickerDelegate>

+ (instancetype)sharedManager;

// Khởi chạy trình chọn file của iOS để người dùng chọn file (.adbk / .zip)
- (void)presentRestorePickerFrom:(UIViewController *)presentingVC completion:(nullable void (^)(BOOL success, NSString *message))completion;

// Khôi phục tài khoản trực tiếp từ file backup (.adbk / .zip)
- (void)restoreFromBackupFile:(NSString *)filePath completion:(void (^)(BOOL success, NSString *message, NSDictionary * _Nullable restoredInfo))completion;

// Khôi phục tài khoản kèm hiển thị tiến trình trên UI (UIProgressView)
- (void)restoreFromBackupFile:(NSString *)filePath presentingVC:(nullable UIViewController *)presentingVC completion:(void (^)(BOOL success, NSString *message, NSDictionary * _Nullable restoredInfo))completion;

// Tạo bản sao lưu 1-chạm (.adbk) cho tài khoản đang đăng nhập kèm hiển thị tiến trình
- (void)createBackupFrom:(UIViewController *)presentingVC completion:(nullable void (^)(BOOL success, NSString *message, NSString * _Nullable backupPath))completion;

// Chia sẻ file backup qua iOS Share Sheet (Lưu Tệp, AirDrop, Tin nhắn...)
- (void)shareFileAtPath:(NSString *)filePath from:(UIViewController *)presentingVC;

@end

NS_ASSUME_NONNULL_END
