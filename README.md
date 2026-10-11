# Hướng dẫn Build & Sử dụng ZaloTweak

Tweak chuyên dụng cho **Dopamine (Rootless)** và **Roothide**, hỗ trợ fake toàn diện thông số phần cứng, màn hình, uptime, cô lập Keychain, vượt rào Sandbox và **Wipe dữ liệu siêu sạch 1-Click** để Zalo nhận diện chuẩn như một chiếc máy mới vừa bóc hộp, chống bị khóa hay quét cờ gian lận.

---

### 1. Tính năng nổi bật & Cơ chế bảo vệ chống khóa
* **Vượt rào Sandbox iOS (Zero-Fail Config)**: Tự động đồng bộ và nạp cấu hình trực tiếp trong Data Container và Shared App Group của Zalo, khắc phục triệt để lỗi Sandbox chặn đọc `/var/mobile/Library/Preferences` làm nhảy IDFV liên tục.
* **Fake Đồng Bộ Màn Hình & Ổ Cứng (Coherent Hardware & Storage Specs)**: 
  - Fake `hw.machine`, `hw.model`, RAM, CPU, `[UIScreen bounds]`, `nativeBounds`, `scale`, `nativeScale` khớp tuyệt đối với model máy đã chọn.
  - Tự động fake tổng dung lượng ổ cứng (`NSFileSystemSize` 128GB / 256GB) và dung lượng trống (`NSFileSystemFreeSize`) ngẫu nhiên theo từng profile, xóa bỏ hoàn toàn dấu vân tay ổ đĩa vật lý.
* **Đồng Bộ Tuyệt Đối Uptime (`kern.boottime` & `NSProcessInfo.systemUptime`)**: Giả lập thời điểm khởi động máy ngẫu nhiên và đồng bộ `systemUptime` khớp chuẩn từng giây, ngăn chặn triệt để thuật toán so sánh uptime phát hiện giả mạo.
* **Deep Wipe Siêu Sạch (1-Click)**:
  - Tắt triệt để tiến trình chính (`Zalo`) và tiến trình ngầm (`NotificationService`, `NotificationContent`).
  - Quét sạch toàn bộ thư mục `Library` (bao gồm `Preferences`, `Caches`, `Application Support`, `WebKit`, `HTTPStorages`, `Cookies`, `Saved Application State`), `Documents`, `tmp`.
  - Xóa sạch toàn bộ dữ liệu trong Shared App Groups.
  - Tự động xóa Clipboard (`UIPasteboard`) hệ thống để triệt tiêu tracking token lưu tạm.
* **Keychain Isolation An Toàn Tuyệt Đối**: Tách biệt hoàn toàn phân vùng lưu trữ Generic Password giữa các profile, bảo lưu nguyên vẹn chứng chỉ SSL/TLS và mã hóa mạng của Apple để không gây lỗi `errSecParam (-50)` hoặc cờ can thiệp.
* **Anti-Jailbreak Toàn Diện (Full Cloaking)**:
  - Chặn Zalo phát hiện file bẻ khóa qua `stat()`, `access()`, `lstat()`, `open()`, `fopen()` và `[NSFileManager fileExistsAtPath:]`.
  - Chặn kiểm tra scheme bẻ khóa qua `[UIApplication canOpenURL:]` (`cydia://`, `sileo://`, `zbra://`,...).
  - Ẩn dylib của jailbreak và tweak trong RAM (`_dyld_get_image_name`).
  - Vô hiệu hóa rò rỉ WiFi BSSID qua `CNCopyCurrentNetworkInfo` để chống liên kết thiết bị qua modem router WiFi.

---

### 2. Cấu trúc dự án
* `Makefile`: Cấu hình Theos biên dịch `Tweak.x` và subproject `zalotweakprefs`.
* `control`: Metadata gói deb (phụ thuộc: `mobilesubstrate | ellekit`, `preferenceloader`).
* `Zalotweak.plist`: Bộ lọc inject, nạp vào `com.vng.zalo`, `NotificationService`, `NotificationContent`.
* `src/`:
  - `Config.h`: Định nghĩa các thuộc tính phần cứng, màn hình, uptime, IDFV, Keychain profile.
  - `Tweak.x`: Mã nguồn hook C API (`sysctl`, `sysctlbyname`, `uname`, `stat`, `access`), Objective-C (`UIDevice`, `UIScreen`) và Keychain Isolation.
* `zalotweakprefs/`: Module menu cấu hình trong **Cài đặt (Settings.app)** của iOS.

---

### 3. Biên dịch (Build) với Theos

#### Dành cho Dopamine Roothide:
```bash
make clean
make package THEOS_PACKAGE_SCHEME=roothide
```
Gói `.deb` sẽ xuất hiện trong thư mục `packages/`. Chuyển file `.deb` vào iPhone và cài qua Sileo / Zebra.

#### Dành cho Dopamine Rootless:
```bash
make clean
make package THEOS_PACKAGE_SCHEME=rootless
```

---

### 4. Quy trình đổi máy mới 100% chuẩn chống khóa

1. Mở **Cài đặt (Settings.app)** trên iPhone $\rightarrow$ Kéo xuống chọn **ZaloTweak**.
2. **Chọn dòng máy mong muốn**: (iPhone 13 Pro, iPhone 14 Pro, iPhone 15 Pro Max, iPhone 12,...). Tweak sẽ tự động đồng bộ RAM, CPU, Kernel Version và phân giải màn hình tương ứng.
3. **Bấm nút**: `🚀 ÁP DỤNG & WIPE SẠCH DỮ LIỆU (1-CLICK)`.
4. **Đổi IP mạng (BẮT BUỘC & CỰC KỲ QUAN TRỌNG)**:
   * Bật **Chế độ máy bay (Airplane Mode)** trong 5 - 10 giây rồi tắt đi để nhà mạng cấp lại địa chỉ IP 4G/5G mới toanh.
   * *Lưu ý: Không dùng chung 1 địa chỉ IP Wi-Fi/4G cũ cho nhiều tài khoản mới liên tiếp.*
5. **Mở Zalo**:
   * Zalo sẽ khởi động như trên một chiếc điện thoại hoàn toàn mới, sạch 100% dữ liệu và không thể bị nhận diện máy cũ.
