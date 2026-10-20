#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>

@interface ZTRootListController : PSListController

- (void)applyAndWipeCleanSequence:(PSSpecifier *)specifier;
- (void)killZalo:(PSSpecifier *)specifier;
- (void)exportZaloIPAAction:(PSSpecifier *)specifier;
- (void)automatedReinstallSequence:(PSSpecifier *)specifier;

@end
