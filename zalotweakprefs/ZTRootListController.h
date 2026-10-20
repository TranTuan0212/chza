#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>

@interface ZTRootListController : PSListController

- (void)applyAndWipeCleanSequence:(PSSpecifier *)specifier;
- (void)killZalo:(PSSpecifier *)specifier;

@end
