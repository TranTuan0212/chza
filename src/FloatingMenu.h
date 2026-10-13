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
- (void)showProxySettingsFrom:(UIViewController *)top;
- (void)performInAppDeepWipe;
- (void)performInAppDeepWipeWithRegion:(NSString *)region;
@end

#ifdef __cplusplus
extern "C" {
#endif

UIViewController *ZTGetTopViewController(void);
void ZTCheckProxyHealth(void (^completion)(BOOL alive, NSString *ip, NSString *errorMessage));
void ZTAutoCheckProxyAndWarnIfDead(void);
BOOL ZTParseProxyString(NSString *str, NSString **outHost, uint16_t *outPort, NSString **outUser, NSString **outPass);

#ifdef __cplusplus
}
#endif
