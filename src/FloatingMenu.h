#import <UIKit/UIKit.h>

@interface ZTFloatingButton : UIButton
+ (instancetype)sharedButton;
- (void)attachToWindow:(UIWindow *)window;
- (void)show;
- (void)hide;
@end

@interface ZTFloatingWindow : UIWindow
+ (instancetype)sharedWindow;
- (void)show;
- (void)hide;
@end

@interface ZTMenuManager : NSObject
+ (instancetype)sharedManager;
- (void)setupInAppMenu;
- (void)tryAttachFloatingButton;
- (void)presentMainMenuFrom:(UIViewController *)presentingVC;
- (void)showPreRegDiagnosticFrom:(UIViewController *)top;
- (void)showAdvancedSettingsFrom:(UIViewController *)top;
- (void)confirmDeepWipeFrom:(UIViewController *)top;
- (void)performInAppDeepWipe;
- (void)performInAppDeepWipeWithRegion:(NSString *)region;
- (void)performInAppDeepWipeWithRegion:(NSString *)region preferredCarrier:(nullable NSString *)preferredCarrier currentIP:(nullable NSString *)currentIP;
- (void)startInAppDeepWipeSequenceWithRegion:(NSString *)targetRegion preferredCarrier:(nullable NSString *)preferredCarrier from:(UIViewController *)top;
@end

#ifdef __cplusplus
extern "C" {
#endif

UIViewController *ZTGetTopViewController(void);

#ifdef __cplusplus
}
#endif
