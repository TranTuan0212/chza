#import "ZTDiagnosticViewController.h"

@implementation ZTDiagnosticInfo
@end

@interface ZTDiagnosticViewController ()
@property (nonatomic, strong) ZTDiagnosticInfo *info;
@end

@implementation ZTDiagnosticViewController

- (instancetype)initWithInfo:(ZTDiagnosticInfo *)info {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _info = info;
    }
    return self;
}

+ (void)presentFrom:(UIViewController *)presenter info:(ZTDiagnosticInfo *)info {
    if (!presenter) return;
    ZTDiagnosticViewController *vc = [[ZTDiagnosticViewController alloc] initWithInfo:info];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    [presenter presentViewController:nav animated:YES completion:nil];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"🔍 KIỂM TRA ĐỘ SẠCH";
    if (@available(iOS 13.0, *)) {
        self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    } else {
        self.view.backgroundColor = [UIColor colorWithRed:0.95 green:0.95 blue:0.97 alpha:1.0];
    }

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Đóng"
                                                                              style:UIBarButtonItemStyleDone
                                                                             target:self
                                                                             action:@selector(dismissSelf)];

    [self setupScrollViewAndCards];
}

- (void)dismissSelf {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)setupScrollViewAndCards {
    UIScrollView *scrollView = [[UIScrollView alloc] init];
    scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    scrollView.alwaysBounceVertical = YES;
    [self.view addSubview:scrollView];

    UIStackView *contentStack = [[UIStackView alloc] init];
    contentStack.translatesAutoresizingMaskIntoConstraints = NO;
    contentStack.axis = UILayoutConstraintAxisVertical;
    contentStack.spacing = 14;
    contentStack.alignment = UIStackViewAlignmentFill;
    contentStack.distribution = UIStackViewDistributionFill;
    contentStack.layoutMarginsRelativeArrangement = YES;
    contentStack.layoutMargins = UIEdgeInsetsMake(16, 16, 28, 16);
    [scrollView addSubview:contentStack];

    [NSLayoutConstraint activateConstraints:@[
        [scrollView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [scrollView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [scrollView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [scrollView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

        [contentStack.topAnchor constraintEqualToAnchor:scrollView.topAnchor],
        [contentStack.leadingAnchor constraintEqualToAnchor:scrollView.leadingAnchor],
        [contentStack.trailingAnchor constraintEqualToAnchor:scrollView.trailingAnchor],
        [contentStack.bottomAnchor constraintEqualToAnchor:scrollView.bottomAnchor],
        [contentStack.widthAnchor constraintEqualToAnchor:scrollView.widthAnchor]
    ]];

    // Kiểm tra các tiêu chuẩn an toàn
    BOOL hasWipedHistory = (self.info.lastWipedIP.length > 0);
    BOOL isSameIP = (hasWipedHistory && [self.info.currentIP isEqualToString:self.info.lastWipedIP]);
    BOOL isDifferentIP = (hasWipedHistory && ![self.info.currentIP isEqualToString:self.info.lastWipedIP]);
    BOOL isDuplicateIDFV = (self.info.lastWipedIDFV.length > 0 && [self.info.currentIDFV isEqualToString:self.info.lastWipedIDFV]);
    
    BOOL isAllPassed = (self.info.hasConfiguredProfile && !isSameIP && !isDuplicateIDFV && self.info.leveldbOK && self.info.isLicensed);

    // 1. Thẻ Kết Luận (Verdict Banner Card)
    [contentStack addArrangedSubview:[self buildVerdictCardWithPassed:isAllPassed isSameIP:isSameIP isDuplicateIDFV:isDuplicateIDFV]];

    // 2. Thẻ Mạng 4G & Internet (Network Card)
    [contentStack addArrangedSubview:[self buildNetworkCardWithSameIP:isSameIP differentIP:isDifferentIP]];

    // 3. Thẻ Thiết Bị Giả Lập (Device Hardware Card)
    [contentStack addArrangedSubview:[self buildDeviceCardWithDuplicateIDFV:isDuplicateIDFV]];

    // 4. Thẻ Nhà Mạng & SIM (SIM / Carrier Card)
    [contentStack addArrangedSubview:[self buildSIMCard]];

    // 5. Thẻ Vệ Sinh Sandbox & Hệ Thống (Hygiene Card)
    [contentStack addArrangedSubview:[self buildHygieneCard]];

    // 6. Thẻ Bản Quyền Tweak (License Card)
    [contentStack addArrangedSubview:[self buildLicenseCard]];

    // 7. Nút Đóng Lớn ở cuối
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [closeBtn.heightAnchor constraintEqualToConstant:48].active = YES;
    closeBtn.layer.cornerRadius = 12;
    closeBtn.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    [closeBtn setTitle:@"ĐÃ HIỂU / ĐÓNG" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.backgroundColor = [UIColor colorWithRed:0.0 green:0.48 blue:1.0 alpha:1.0];
    [closeBtn addTarget:self action:@selector(dismissSelf) forControlEvents:UIControlEventTouchUpInside];
    [contentStack addArrangedSubview:closeBtn];
}

#pragma mark - Helper tạo Khung Card (Framed Card Container)

- (UIView *)createCardContainer {
    UIView *card = [[UIView alloc] init];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.layer.cornerRadius = 14;
    card.layer.borderWidth = 1.0;
    
    if (@available(iOS 13.0, *)) {
        card.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
        card.layer.borderColor = [UIColor separatorColor].CGColor;
    } else {
        card.backgroundColor = [UIColor whiteColor];
        card.layer.borderColor = [UIColor colorWithWhite:0.85 alpha:1.0].CGColor;
    }
    card.layer.masksToBounds = YES;
    return card;
}

- (UIStackView *)createCardInnerStackForCard:(UIView *)card {
    UIStackView *inner = [[UIStackView alloc] init];
    inner.translatesAutoresizingMaskIntoConstraints = NO;
    inner.axis = UILayoutConstraintAxisVertical;
    inner.spacing = 10;
    inner.layoutMarginsRelativeArrangement = YES;
    inner.layoutMargins = UIEdgeInsetsMake(14, 16, 14, 16);
    [card addSubview:inner];

    [NSLayoutConstraint activateConstraints:@[
        [inner.topAnchor constraintEqualToAnchor:card.topAnchor],
        [inner.leadingAnchor constraintEqualToAnchor:card.leadingAnchor],
        [inner.trailingAnchor constraintEqualToAnchor:card.trailingAnchor],
        [inner.bottomAnchor constraintEqualToAnchor:card.bottomAnchor]
    ]];
    return inner;
}

- (UILabel *)createCardTitleLabelWithIcon:(NSString *)icon title:(NSString *)title {
    UILabel *lbl = [[UILabel alloc] init];
    lbl.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    if (@available(iOS 13.0, *)) {
        lbl.textColor = [UIColor labelColor];
    } else {
        lbl.textColor = [UIColor blackColor];
    }
    lbl.text = [NSString stringWithFormat:@"%@  %@", icon, title];
    return lbl;
}

- (UIView *)createRowWithKey:(NSString *)key value:(NSString *)value badge:(nullable NSString *)badge isWarning:(BOOL)isWarning {
    UIView *row = [[UIView alloc] init];
    row.translatesAutoresizingMaskIntoConstraints = NO;

    UILabel *keyLbl = [[UILabel alloc] init];
    keyLbl.translatesAutoresizingMaskIntoConstraints = NO;
    keyLbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    if (@available(iOS 13.0, *)) {
        keyLbl.textColor = [UIColor secondaryLabelColor];
    } else {
        keyLbl.textColor = [UIColor darkGrayColor];
    }
    keyLbl.text = key;
    [row addSubview:keyLbl];

    UILabel *valLbl = [[UILabel alloc] init];
    valLbl.translatesAutoresizingMaskIntoConstraints = NO;
    valLbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    valLbl.textAlignment = NSTextAlignmentRight;
    
    if (isWarning) {
        valLbl.textColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:1.0];
    } else if (badge != nil && ([badge containsString:@"✅"] || [badge containsString:@"Mới"] || [badge containsString:@"Sạch"])) {
        valLbl.textColor = [UIColor colorWithRed:0.1 green:0.65 blue:0.3 alpha:1.0];
    } else {
        if (@available(iOS 13.0, *)) {
            valLbl.textColor = [UIColor labelColor];
        } else {
            valLbl.textColor = [UIColor blackColor];
        }
    }

    if (badge.length > 0) {
        valLbl.text = [NSString stringWithFormat:@"%@ (%@)", value ?: @"", badge];
    } else {
        valLbl.text = value ?: @"";
    }
    [row addSubview:valLbl];

    [NSLayoutConstraint activateConstraints:@[
        [keyLbl.topAnchor constraintEqualToAnchor:row.topAnchor],
        [keyLbl.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
        [keyLbl.bottomAnchor constraintEqualToAnchor:row.bottomAnchor],
        [keyLbl.widthAnchor constraintLessThanOrEqualToAnchor:row.widthAnchor multiplier:0.45],

        [valLbl.topAnchor constraintEqualToAnchor:row.topAnchor],
        [valLbl.trailingAnchor constraintEqualToAnchor:row.trailingAnchor],
        [valLbl.bottomAnchor constraintEqualToAnchor:row.bottomAnchor],
        [valLbl.leadingAnchor constraintGreaterThanOrEqualToAnchor:keyLbl.trailingAnchor constant:8]
    ]];

    return row;
}

#pragma mark - 1. Thẻ Kết Luận (Verdict Banner Card)

- (UIView *)buildVerdictCardWithPassed:(BOOL)passed isSameIP:(BOOL)isSameIP isDuplicateIDFV:(BOOL)isDuplicateIDFV {
    UIView *card = [[UIView alloc] init];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.layer.cornerRadius = 14;
    card.layer.borderWidth = 1.5;

    if (passed) {
        card.backgroundColor = [UIColor colorWithRed:0.1 green:0.75 blue:0.35 alpha:0.12];
        card.layer.borderColor = [UIColor colorWithRed:0.12 green:0.65 blue:0.3 alpha:0.7].CGColor;
    } else {
        card.backgroundColor = [UIColor colorWithRed:0.95 green:0.25 blue:0.2 alpha:0.10];
        card.layer.borderColor = [UIColor colorWithRed:0.9 green:0.25 blue:0.2 alpha:0.7].CGColor;
    }

    UIStackView *inner = [self createCardInnerStackForCard:card];
    inner.spacing = 6;

    UILabel *headerLbl = [[UILabel alloc] init];
    headerLbl.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    headerLbl.numberOfLines = 0;

    UILabel *descLbl = [[UILabel alloc] init];
    descLbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    descLbl.numberOfLines = 0;

    if (passed) {
        headerLbl.text = @"🟢 HỆ THỐNG ĐẠT CHUẨN AN TOÀN TUYỆT ĐỐI";
        headerLbl.textColor = [UIColor colorWithRed:0.08 green:0.55 blue:0.25 alpha:1.0];
        descLbl.text = @"Môi trường 100% sạch sẽ, IP 4G và định danh phần cứng mới tinh. Đã sẵn sàng để tạo tài khoản Zalo an toàn!";
        if (@available(iOS 13.0, *)) {
            descLbl.textColor = [UIColor labelColor];
        } else {
            descLbl.textColor = [UIColor blackColor];
        }
    } else {
        headerLbl.text = @"🔴 CẢNH BÁO: CHƯA ĐẠT CHUẨN REG ACC";
        headerLbl.textColor = [UIColor colorWithRed:0.85 green:0.2 blue:0.15 alpha:1.0];

        NSMutableString *reasons = [NSMutableString string];
        if (!self.info.isLicensed) [reasons appendString:@"• Bản quyền Tweak chưa kích hoạt hoặc đã hết hạn!\n"];
        if (!self.info.hasConfiguredProfile) [reasons appendString:@"• Chưa bấm Deep Wipe! (App đang dùng phần cứng thật, cần bấm Deep Wipe để cấp máy mới)\n"];
        if (isSameIP) [reasons appendString:@"• Trùng IP 4G lần trước! (Cần gạt Chế Độ Máy Bay 5 giây)\n"];
        if (isDuplicateIDFV) [reasons appendString:@"• Trùng IDFV cũ! (Cần bấm Deep Wipe để cấp máy mới)\n"];
        if (!self.info.leveldbOK) [reasons appendString:@"• Lỗi quyền ghi LevelDB C++ hoặc App Group!\n"];
        if (!self.info.isHiddenProv) [reasons appendString:@"• Chưa che giấu mobileprovision (lộ Sideload)!\n"];

        descLbl.text = [reasons stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        descLbl.textColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.15 alpha:1.0];
    }

    [inner addArrangedSubview:headerLbl];
    [inner addArrangedSubview:descLbl];
    return card;
}

#pragma mark - 2. Thẻ Mạng 4G & Internet

- (UIView *)buildNetworkCardWithSameIP:(BOOL)isSameIP differentIP:(BOOL)isDifferentIP {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🌐" title:@"MẠNG 4G & INTERNET"]];

    BOOL hasWipedHistory = (self.info.lastWipedIP.length > 0);
    NSString *badge;
    BOOL ipWarning = NO;
    if (!self.info.hasConfiguredProfile || !hasWipedHistory) {
        badge = @"Chưa lưu IP ⚠️";
        ipWarning = YES;
    } else if (isSameIP) {
        badge = @"TRÙNG IP CŨ ❌";
        ipWarning = YES;
    } else if (isDifferentIP) {
        badge = @"ĐÃ ĐỔI MỚI ✅";
    } else {
        badge = @"HỢP LỆ ✅";
    }

    [inner addArrangedSubview:[self createRowWithKey:@"IP Public Hiện Tại"
                                              value:self.info.currentIP ?: @"Đang tải..."
                                              badge:badge
                                          isWarning:ipWarning]];

    NSString *lastIPStr = self.info.lastWipedIP.length > 0 ? self.info.lastWipedIP : @"Chưa có lịch sử";
    [inner addArrangedSubview:[self createRowWithKey:@"IP Lần Wipe Trước"
                                              value:lastIPStr
                                              badge:nil
                                          isWarning:NO]];

    // Nếu trùng IP: Thêm khung cảnh báo trực quan
    if (isSameIP) {
        UIView *warnBox = [[UIView alloc] init];
        warnBox.translatesAutoresizingMaskIntoConstraints = NO;
        warnBox.layer.cornerRadius = 8;
        warnBox.backgroundColor = [UIColor colorWithRed:0.95 green:0.3 blue:0.2 alpha:0.12];
        warnBox.layer.borderWidth = 1.0;
        warnBox.layer.borderColor = [UIColor colorWithRed:0.9 green:0.3 blue:0.2 alpha:0.4].CGColor;

        UILabel *warnLbl = [[UILabel alloc] init];
        warnLbl.translatesAutoresizingMaskIntoConstraints = NO;
        warnLbl.numberOfLines = 0;
        warnLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        warnLbl.textColor = [UIColor colorWithRed:0.85 green:0.2 blue:0.15 alpha:1.0];
        warnLbl.text = @"⚠️ LƯU Ý BẮT BUỘC: Bạn chưa đổi IP mạng 4G. Hãy vuốt Control Center, bật Chế Độ Máy Bay trong 5 giây rồi tắt đi, sau đó bấm Kiểm Tra lại!";
        [warnBox addSubview:warnLbl];

        [NSLayoutConstraint activateConstraints:@[
            [warnLbl.topAnchor constraintEqualToAnchor:warnBox.topAnchor constant:8],
            [warnLbl.leadingAnchor constraintEqualToAnchor:warnBox.leadingAnchor constant:10],
            [warnLbl.trailingAnchor constraintEqualToAnchor:warnBox.trailingAnchor constant:-10],
            [warnLbl.bottomAnchor constraintEqualToAnchor:warnBox.bottomAnchor constant:-8]
        ]];

        [inner addArrangedSubview:warnBox];
    }

    return card;
}

#pragma mark - 3. Thẻ Thiết Bị Giả Lập

- (UIView *)buildDeviceCardWithDuplicateIDFV:(BOOL)isDuplicateIDFV {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"📱" title:@"THIẾT BỊ GIẢ LẬP (APPLE HARDWARE)"]];

    BOOL configured = self.info.hasConfiguredProfile;
    NSString *deviceFull = [NSString stringWithFormat:@"%@ (iOS %@)", self.info.deviceName ?: @"iPhone", self.info.iosVersion ?: @""];
    [inner addArrangedSubview:[self createRowWithKey:@"Dòng Máy" value:deviceFull badge:configured ? nil : @"Máy Thật ⚠️" isWarning:!configured]];

    NSString *machineBadge = configured ? @"Khớp Profile ✅" : @"Máy Thật ⚠️";
    [inner addArrangedSubview:[self createRowWithKey:@"Machine (hw.machine)"
                                              value:self.info.deviceMachine ?: @"iPhone"
                                              badge:machineBadge
                                          isWarning:!configured]];

    NSString *idfvShort = (self.info.currentIDFV.length > 8) ? [self.info.currentIDFV substringToIndex:8] : self.info.currentIDFV;
    NSString *idfvBadge;
    BOOL idfvWarning = NO;
    if (!configured) {
        idfvBadge = @"Chưa cấp ⚠️ (Cần Wipe)";
        idfvWarning = YES;
    } else if (isDuplicateIDFV) {
        idfvBadge = @"TRÙNG IDFV CŨ ❌";
        idfvWarning = YES;
    } else {
        idfvBadge = @"Mới tinh ✅";
    }
    NSString *idfvDisplay = configured ? [NSString stringWithFormat:@"%@...", idfvShort ?: @""] : @"Chưa cấp (Cần Wipe)";
    [inner addArrangedSubview:[self createRowWithKey:@"IDFV Mới"
                                              value:idfvDisplay
                                              badge:idfvBadge
                                          isWarning:idfvWarning]];

    [inner addArrangedSubview:[self createRowWithKey:@"IDFA Quảng Cáo"
                                              value:@"00000000-0000-0000"
                                              badge:@"Apple ATT Denied ✅"
                                          isWarning:NO]];

    NSString *hwCombo;
    NSString *hwBadge;
    BOOL hwWarning = NO;
    if (configured && (self.info.serial.length > 0 || self.info.wifiMAC.length > 0)) {
        hwCombo = [NSString stringWithFormat:@"%@ | %@", self.info.serial ?: @"---", self.info.wifiMAC ?: @"---"];
        hwBadge = @"Ẩn danh ✅";
    } else {
        hwCombo = @"Chưa cấp (Cần bấm Deep Wipe)";
        hwBadge = @"Chưa cấp ⚠️";
        hwWarning = YES;
    }
    [inner addArrangedSubview:[self createRowWithKey:@"Serial / MAC Wi-Fi"
                                              value:hwCombo
                                              badge:hwBadge
                                          isWarning:hwWarning]];

    return card;
}

#pragma mark - 4. Thẻ Nhà Mạng & SIM

- (UIView *)buildSIMCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"📶" title:@"NHÀ MẠNG & SIM"]];

    [inner addArrangedSubview:[self createRowWithKey:@"Hồ Sơ Vùng"
                                              value:self.info.regionName ?: @"Việt Nam (+84)"
                                              badge:nil
                                          isWarning:NO]];

    NSString *carrierDetails = [NSString stringWithFormat:@"%@ (MCC: %@ | MNC: %@)",
                                self.info.carrierName ?: @"Viettel",
                                self.info.carrierMCC ?: @"452",
                                self.info.carrierMNC ?: @"04"];
    [inner addArrangedSubview:[self createRowWithKey:@"Nhà Mạng"
                                              value:carrierDetails
                                              badge:@"Hợp lệ ✅"
                                          isWarning:NO]];

    return card;
}

#pragma mark - 5. Thẻ Vệ Sinh Sandbox & Hệ Thống

- (UIView *)buildHygieneCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🧹" title:@"VỆ SINH SANDBOX & HỆ THỐNG"]];

    NSString *cleanBadge;
    BOOL isWarning = NO;
    if (self.info.sandboxKB < 3072.0) { // Dưới 3MB là sạch 100% (khung rỗng hệ thống iOS & SQLite WAL)
        cleanBadge = @"Sạch 100% ✅";
    } else if (self.info.sandboxKB < 6144.0) { // 3MB - 6MB: Cache nhẹ
        cleanBadge = @"Cache nhẹ 🟡";
    } else {
        cleanBadge = @"Dữ liệu cũ ❌ (Cần Wipe)";
        isWarning = YES;
    }
    NSString *cacheStr = (self.info.sandboxKB >= 1024.0) ?
        [NSString stringWithFormat:@"%.2f MB", self.info.sandboxKB / 1024.0] :
        [NSString stringWithFormat:@"%.1f KB", self.info.sandboxKB];
    [inner addArrangedSubview:[self createRowWithKey:@"Bộ Nhớ Rác Sandbox"
                                              value:cacheStr
                                              badge:cleanBadge
                                          isWarning:isWarning]];

    [inner addArrangedSubview:[self createRowWithKey:@"LevelDB C++ & Groups"
                                              value:self.info.leveldbOK ? @"Thông suốt 100%" : @"Lỗi truy cập"
                                              badge:self.info.leveldbOK ? @"✅" : @"❌"
                                          isWarning:!self.info.leveldbOK]];

    if (self.info.diskTotalGB > 0) {
        NSString *diskStr = [NSString stringWithFormat:@"%.1f GB / %.1f GB (Uptime: %lluh)",
                             self.info.diskFreeGB, self.info.diskTotalGB, self.info.uptimeHours];
        [inner addArrangedSubview:[self createRowWithKey:@"Ổ Cứng & Uptime"
                                                  value:diskStr
                                                  badge:nil
                                              isWarning:NO]];
    }

    return card;
}

#pragma mark - 6. Thẻ Bản Quyền Tweak

- (UIView *)buildLicenseCard {
    UIView *card = [self createCardContainer];
    UIStackView *inner = [self createCardInnerStackForCard:card];

    [inner addArrangedSubview:[self createCardTitleLabelWithIcon:@"🛡️" title:@"BẢN QUYỀN TWEAK"]];

    BOOL isWarning = !self.info.isLicensed;
    [inner addArrangedSubview:[self createRowWithKey:@"Trạng Thái & Hạn Dùng"
                                              value:self.info.licenseStatusText ?: @"Chưa kích hoạt"
                                              badge:nil
                                          isWarning:isWarning]];

    return card;
}

@end
