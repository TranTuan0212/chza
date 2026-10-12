#import <UIKit/UIKit.h>

@interface ZTFloatingButton : UIButton
+ (instancetype)sharedButton;
- (void)attachToWindow:(UIWindow *)window;
- (void)show;
- (void)hide;
@end

@interface ZTMenuManager : NSObject
+ (instancetype)sharedManager;
- (void)setupInAppMenu;
- (void)tryAttachFloatingButton;
- (void)presentMainMenuFrom:(UIViewController *)presentingVC;
- (void)showPreRegDiagnosticFrom:(UIViewController *)top;
- (void)performInAppDeepWipe;
@end
