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
- (void)presentMainMenuFrom:(UIViewController *)presentingVC;
- (void)performInAppDeepWipe;
@end
