#!/bin/bash
set -e

# ==============================================================================
# Script đóng gói Zalo Clone IPA (Tích hợp sẵn Zalotweak.dylib)
# Hướng dẫn sử dụng:
# ./package_clone_ipa.sh <duong_dan_file_Zalo_goc.ipa> [duong_dan_Zalotweak.dylib]
# ==============================================================================

INPUT_IPA="$1"
DYLIB_PATH="$2"

if [ -z "$INPUT_IPA" ] || [ ! -f "$INPUT_IPA" ]; then
    echo "❌ Lỗi: Vui lòng cung cấp file Zalo IPA đã decrypted!"
    echo "Ví dụ: ./package_clone_ipa.sh Zalo.ipa packages/Zalotweak.dylib"
    exit 1
fi

CLONE_BUNDLE_ID="vn.com.vng.zingalo.clone"
CLONE_DISPLAY_NAME="Zalo Clone"
WORK_DIR=$(mktemp -d /tmp/zalo_clone_build.XXXXXX)

echo "==> 1. Giải nén IPA..."
unzip -q "$INPUT_IPA" -d "$WORK_DIR"

APP_PATH=$(find "$WORK_DIR/Payload" -maxdepth 1 -name "*.app" | head -n 1)
if [ -z "$APP_PATH" ]; then
    echo "❌ Lỗi: Không tìm thấy thư mục .app bên trong Payload!"
    rm -rf "$WORK_DIR"
    exit 1
fi

APP_NAME=$(basename "$APP_PATH")
BINARY_NAME="${APP_NAME%.app}"
BINARY_PATH="$APP_PATH/$BINARY_NAME"
INFO_PLIST="$APP_PATH/Info.plist"

echo "==> Đã tìm thấy App: $APP_NAME, Binary: $BINARY_NAME"

echo "==> 2. Đổi Bundle Identifier sang $CLONE_BUNDLE_ID..."
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $CLONE_BUNDLE_ID" "$INFO_PLIST" 2>/dev/null || \
plutil -replace CFBundleIdentifier -string "$CLONE_BUNDLE_ID" "$INFO_PLIST"

echo "==> 3. Đổi App Display Name sang '$CLONE_DISPLAY_NAME'..."
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName $CLONE_DISPLAY_NAME" "$INFO_PLIST" 2>/dev/null || \
plutil -replace CFBundleDisplayName -string "$CLONE_DISPLAY_NAME" "$INFO_PLIST"

/usr/libexec/PlistBuddy -c "Set :CFBundleName $CLONE_DISPLAY_NAME" "$INFO_PLIST" 2>/dev/null || \
plutil -replace CFBundleName -string "$CLONE_DISPLAY_NAME" "$INFO_PLIST"

# Xóa các App Extensions/WatchApp/PlugIns để tránh xung đột bundle identifier phụ
if [ -d "$APP_PATH/PlugIns" ]; then
    echo "==> Xóa các App Extensions phụ (PlugIns) để tránh lỗi ký..."
    rm -rf "$APP_PATH/PlugIns"
fi
if [ -d "$APP_PATH/Watch" ]; then
    rm -rf "$APP_PATH/Watch"
fi

if [ -n "$DYLIB_PATH" ] && [ -f "$DYLIB_PATH" ]; then
    echo "==> 4. Chích dylib vào Mach-O binary..."
    mkdir -p "$APP_PATH/Frameworks"
    cp "$DYLIB_PATH" "$APP_PATH/Frameworks/Zalotweak.dylib"
    
    # Dùng optool hoặc insert_dylib nếu có
    if command -v optool >/dev/null 2>&1; then
        optool install -c load -p "@executable_path/Frameworks/Zalotweak.dylib" -t "$BINARY_PATH"
    elif command -v insert_dylib >/dev/null 2>&1; then
        insert_dylib --inplace "@executable_path/Frameworks/Zalotweak.dylib" "$BINARY_PATH"
    else
        echo "⚠️ Cảnh báo: Không tìm thấy optool hoặc insert_dylib. Bạn có thể dùng Sideloadly / TrollStore tự động inject dylib."
    fi
fi

echo "==> 5. Đóng gói lại thành ZaloClone_Tweak.ipa..."
OUTPUT_IPA="ZaloClone_Tweak.ipa"
cd "$WORK_DIR"
zip -qry "$OUTPUT_IPA" Payload
cd - >/dev/null
mv "$WORK_DIR/$OUTPUT_IPA" "./$OUTPUT_IPA"

rm -rf "$WORK_DIR"

echo "=========================================================="
echo "🎉 XUẤT THÀNH CÔNG: ./$OUTPUT_IPA"
echo "Bạn có thể cài đặt trực tiếp qua Sideloadly, TrollStore hoặc AltStore."
echo "Bundle ID: $CLONE_BUNDLE_ID (Không đè lên Zalo gốc)"
echo "=========================================================="
