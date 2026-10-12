TARGET := iphone:clang:16.5:15.0
ARCHS := arm64 arm64e

# Hỗ trợ Roothide & Rootless
THEOS_PACKAGE_SCHEME ?= roothide

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Zalotweak

Zalotweak_FILES = src/Tweak.x src/SecurityManager.m src/FloatingMenu.m
Zalotweak_CFLAGS = -fobjc-arc -Isrc
Zalotweak_FRAMEWORKS = UIKit Foundation Security SystemConfiguration
Zalotweak_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

SUBPROJECTS += zalotweakprefs
include $(THEOS_MAKE_PATH)/aggregate.mk
