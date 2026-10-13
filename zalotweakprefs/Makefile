TARGET := iphone:clang:16.5:15.0
ARCHS := arm64 arm64e

THEOS_PACKAGE_SCHEME ?= rootless

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ZaloTweakPrefs

ZaloTweakPrefs_FILES = ZTRootListController.m ../src/SecurityManager.m
ZaloTweakPrefs_FRAMEWORKS = UIKit Foundation Security
ZaloTweakPrefs_PRIVATE_FRAMEWORKS = Preferences
ZaloTweakPrefs_INSTALL_PATH = /Library/PreferenceBundles
ZaloTweakPrefs_CFLAGS = -fobjc-arc -I../src

include $(THEOS_MAKE_PATH)/bundle.mk

internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences$(ECHO_END)
	$(ECHO_NOTHING)cp entry.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/ZaloTweakPrefs.plist$(ECHO_END)
