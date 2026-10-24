#import "BackupManager.h"
#import "Config.h"
#import "SecurityManager.h"
#import <zlib.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>
#import <signal.h>

#define GLOBAL_PREFS_PATH @"/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"

static BOOL zt_is_running_in_zalo(void) {
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleId) return NO;
    NSString *lower = [bundleId lowercaseString];
    return [lower containsString:@"zingalo"] || [lower containsString:@"zalo"];
}

static NSArray<NSString *> *zt_get_known_zalo_bundle_ids(void) {
    return @[@"vn.com.vng.zingalo", @"com.zing.zalo", @"com.vng.zalo", @"com.sonhu.zaloclone"];
}

static NSDictionary<NSString *, NSString *> *zt_get_all_zalo_group_containers(void) {
    static NSMutableDictionary<NSString *, NSString *> *s_groupMap = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_groupMap = [NSMutableDictionary dictionary];
        NSArray *baseDirs = @[@"/var/mobile/Containers/Shared/AppGroup", @"/private/var/mobile/Containers/Shared/AppGroup"];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *baseDir in baseDirs) {
            NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
            for (NSString *uuid in subdirs) {
                NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
                NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
                NSString *ident = meta[@"MCMMetadataIdentifier"];
                if (ident && ident.length > 0) {
                    NSString *fullP = [baseDir stringByAppendingPathComponent:uuid];
                    BOOL isDir = NO;
                    if ([fm fileExistsAtPath:fullP isDirectory:&isDir] && isDir) {
                        s_groupMap[ident] = fullP;
                    }
                }
            }
            if (s_groupMap.count > 0) break;
        }
    });
    return s_groupMap;
}

static NSString *zt_get_zalo_group_container_path(NSString *groupName) {
    if (!groupName || groupName.length == 0) return nil;

    if (zt_is_running_in_zalo()) {
        NSURL *grpURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:groupName];
        if (grpURL && grpURL.path) return grpURL.path;
    }

    NSDictionary<NSString *, NSString *> *map = zt_get_all_zalo_group_containers();
    if (map[groupName]) {
        return map[groupName];
    }

    for (NSString *key in map) {
        if ([key containsString:groupName] || [groupName containsString:key]) {
            return map[key];
        }
    }
    return nil;
}

static NSString *zt_get_zalo_data_container_path(void) {
    if (zt_is_running_in_zalo()) {
        return NSHomeDirectory();
    }

    static NSString *s_zaloDataContainer = nil;
    if (s_zaloDataContainer && [[NSFileManager defaultManager] fileExistsAtPath:s_zaloDataContainer]) {
        return s_zaloDataContainer;
    }

    NSArray *baseDirs = @[@"/var/mobile/Containers/Data/Application", @"/private/var/mobile/Containers/Data/Application"];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *baseDir in baseDirs) {
        NSArray *subdirs = [fm contentsOfDirectoryAtPath:baseDir error:nil];
        for (NSString *uuid in subdirs) {
            NSString *metaPath = [baseDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
            NSString *ident = meta[@"MCMMetadataIdentifier"];
            if (ident) {
                NSString *lower = [ident lowercaseString];
                if ([lower containsString:@"zingalo"] || [lower containsString:@"zalo"] || [zt_get_known_zalo_bundle_ids() containsObject:ident]) {
                    NSString *fullP = [baseDir stringByAppendingPathComponent:uuid];
                    BOOL isDir = NO;
                    if ([fm fileExistsAtPath:fullP isDirectory:&isDir] && isDir) {
                        s_zaloDataContainer = fullP;
                        return fullP;
                    }
                }
            }
        }
        if (s_zaloDataContainer) break;
    }

    return NSHomeDirectory();
}

static void zt_kill_all_zalo_processes(void) {
    Class fbsClass = objc_getClass("FBSSystemService");
    if (fbsClass) {
        SEL sharedSel = sel_registerName("sharedService");
        if ([fbsClass respondsToSelector:sharedSel]) {
            id service = ((id (*)(id, SEL))objc_msgSend)(fbsClass, sharedSel);
            SEL termSel = sel_registerName("terminateApplication:forReason:andReport:withDescription:");
            if (service && [service respondsToSelector:termSel]) {
                for (NSString *bid in zt_get_known_zalo_bundle_ids()) {
                    ((void (*)(id, SEL, id, long long, BOOL, id))objc_msgSend)(service, termSel, bid, 1, NO, @"ZaloTweak Restore");
                }
            }
        }
    }

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) == 0 && size > 0) {
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
        if (procs) {
            if (sysctl(mib, 4, procs, &size, NULL, 0) == 0) {
                int count = (int)(size / sizeof(struct kinfo_proc));
                for (int i = 0; i < count; i++) {
                    const char *name = procs[i].kp_proc.p_comm;
                    if (name && (strcasecmp(name, "Zalo") == 0 ||
                                 strcmp(name, "vn.com.vng.zingalo") == 0)) {
                        kill(procs[i].kp_proc.p_pid, SIGKILL);
                    }
                }
            }
            free(procs);
        }
    }
    [NSThread sleepForTimeInterval:0.3];
}

static NSString *get_backup_roothide_prefs_path(void) {
    typedef const char* (*jbroot_fn_t)(const char*);
    jbroot_fn_t jbroot_fn = (jbroot_fn_t)dlsym(RTLD_DEFAULT, "jbroot");
    if (jbroot_fn) {
        const char *p = jbroot_fn("/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist");
        if (p) return [NSString stringWithUTF8String:p];
    }
    return nil;
}

// Cấu trúc mô tả một file trong ZIP
typedef struct {
    char filename[512];
    uint16_t method;
    uint32_t csize;
    uint32_t usize;
    uint32_t crc;
    uint32_t local_offset;
} ZTZipEntry;

// Giải nén Deflate raw (-MAX_WBITS)
static NSData *zt_decompress_deflate(const uint8_t *cdata, size_t csize, size_t usize) {
    if (usize == 0) return [NSData data];
    NSMutableData *udata = [NSMutableData dataWithLength:usize];
    if (!udata) return nil;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = (Bytef *)cdata;
    strm.avail_in = (uInt)csize;
    strm.next_out = (Bytef *)udata.mutableBytes;
    strm.avail_out = (uInt)usize;

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
        return nil;
    }

    int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);

    if (ret != Z_STREAM_END && ret != Z_OK) {
        return nil;
    }

    [udata setLength:strm.total_out];
    return udata;
}

// Nén Deflate raw (-MAX_WBITS)
static NSData *zt_compress_deflate(NSData *data) {
    if (!data || data.length == 0) return [NSData data];
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return nil;
    }

    NSMutableData *compressed = [NSMutableData dataWithLength:deflateBound(&strm, (uLong)data.length)];
    strm.next_in = (Bytef *)data.bytes;
    strm.avail_in = (uInt)data.length;
    strm.next_out = (Bytef *)compressed.mutableBytes;
    strm.avail_out = (uInt)compressed.length;

    int ret = deflate(&strm, Z_FINISH);
    deflateEnd(&strm);

    if (ret != Z_STREAM_END) return nil;
    [compressed setLength:strm.total_out];
    return compressed;
}

// Tìm Top ViewController an toàn tuyệt đối, bỏ qua các VC đang bị Dismiss
static UIViewController *zt_get_safe_top_vc(UIViewController *fallbackVC) {
    UIViewController *top = fallbackVC;
    if (!top || top.presentedViewController != nil || top.isBeingDismissed) {
        top = [UIApplication sharedApplication].keyWindow.rootViewController;
        if (!top) {
            if (@available(iOS 13.0, *)) {
                for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState == UISceneActivationStateForegroundActive && [scene isKindOfClass:[UIWindowScene class]]) {
                        UIWindowScene *ws = (UIWindowScene *)scene;
                        for (UIWindow *w in ws.windows) {
                            if (w.isKeyWindow || w.rootViewController != nil) {
                                top = w.rootViewController;
                                break;
                            }
                        }
                        if (top) break;
                    }
                }
            }
        }
    }
    while (top.presentedViewController && !top.presentedViewController.isBeingDismissed) {
        top = top.presentedViewController;
    }
    return top;
}

// Tạo hộp thoại tiến trình UIProgressView
static UIAlertController *zt_create_progress_alert(NSString *title, NSString *initialMessage, UIProgressView **outProgressView) {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:[NSString stringWithFormat:@"%@\n\n\n", initialMessage]
                                                            preferredStyle:UIAlertControllerStyleAlert];

    UIProgressView *pv = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    pv.frame = CGRectMake(20, 85, 230, 4);
    pv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    pv.progress = 0.0f;
    [alert.view addSubview:pv];

    if (outProgressView) {
        *outProgressView = pv;
    }
    return alert;
}

// Cập nhật tiến trình an toàn trên Main Thread
static void zt_update_progress(UIAlertController *alert, UIProgressView *pv, NSString *msg, float progressVal) {
    if (!alert || !pv) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        alert.message = [NSString stringWithFormat:@"%@\n\n\n", msg];
        pv.progress = progressVal;
    });
}

// Đệ quy quét danh sách tệp cần sao lưu (Pass 1 - lọc bỏ file rác & cache)
static void zt_collect_files_recursive(NSFileManager *fm, NSString *diskDir, NSString *zipDirPrefix, NSMutableArray<NSDictionary *> *itemsList) {
    NSArray *items = [fm contentsOfDirectoryAtPath:diskDir error:nil];
    for (NSString *item in items) {
        if ([item isEqualToString:@".DS_Store"] ||
            [item isEqualToString:@"ZaloBackups"] ||
            [item isEqualToString:@"BackupMeta"] ||
            [item isEqualToString:@"zinstant_cache"] ||
            [item isEqualToString:@"web_cache"] ||
            [item isEqualToString:@"vng_ad_cache"] ||
            [item isEqualToString:@"browser_cache"]) {
            continue;
        }

        NSString *fullDisk = [diskDir stringByAppendingPathComponent:item];
        NSString *fullZip = [zipDirPrefix stringByAppendingPathComponent:item];

        NSDictionary *attrs = [fm attributesOfItemAtPath:fullDisk error:nil];
        NSString *fileType = attrs[NSFileType];
        if ([fileType isEqualToString:NSFileTypeSymbolicLink]) {
            // Bỏ qua symlink để tránh vòng lặp đệ quy vô tận
            continue;
        }

        BOOL isDir = NO;
        if ([fm fileExistsAtPath:fullDisk isDirectory:&isDir]) {
            if (isDir) {
                NSString *lower = [item lowercaseString];
                if ([lower isEqualToString:@"tmp"] || [lower isEqualToString:@"temp"] || [lower containsString:@"cache"]) {
                    continue;
                }
                zt_collect_files_recursive(fm, fullDisk, fullZip, itemsList);
            } else {
                NSString *lower = [item lowercaseString];
                if ([lower hasSuffix:@".tmp"] || [lower hasSuffix:@".temp"] || [lower hasSuffix:@".sock"] || [lower isEqualToString:@"lock"]) {
                    continue;
                }
                unsigned long long fSize = [attrs fileSize];
                [itemsList addObject:@{
                    @"disk": fullDisk,
                    @"zip": fullZip,
                    @"size": @(fSize)
                }];
            }
        }
    }
}

// Ghi 1 file vào ZIP với @autoreleasepool chống tràn RAM & an toàn chuỗi UTF-8
static void zt_add_file_to_zip(FILE *zipFp, NSString *diskPath, NSString *zipPath, NSMutableArray<NSValue *> *cdEntries) {
    if (!zipPath || zipPath.length == 0 || !diskPath) return;
    const char *fn = [zipPath UTF8String];
    if (!fn || strlen(fn) == 0) return;

    @autoreleasepool {
        struct stat st;
        if (stat([diskPath UTF8String], &st) != 0 || !S_ISREG(st.st_mode)) {
            return;
        }

        NSData *data = [NSData dataWithContentsOfFile:diskPath options:NSDataReadingMappedIfSafe error:nil];
        if (!data) return;

        uLong crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, (const Bytef *)data.bytes, (uInt)data.length);

        // File quá lớn (> 20MB) lưu ở dạng Store (method 0) để không ngốn RAM và CPU
        NSData *payload = data;
        uint16_t method = 0;
        if (data.length > 0 && data.length < (20 * 1024 * 1024)) {
            NSData *cdata = zt_compress_deflate(data);
            if (cdata && cdata.length < data.length) {
                method = 8;
                payload = cdata;
            }
        }

        long localOffset = ftell(zipFp);
        uint16_t fnLen = (uint16_t)strlen(fn);

        // Ghi Local Header
        uint8_t localHead[30];
        *(uint32_t *)(localHead + 0) = 0x04034b50;
        *(uint16_t *)(localHead + 4) = 20; // Version
        *(uint16_t *)(localHead + 6) = 0;  // Flags
        *(uint16_t *)(localHead + 8) = method;
        *(uint16_t *)(localHead + 10) = 0; // Time
        *(uint16_t *)(localHead + 12) = 0; // Date
        *(uint32_t *)(localHead + 14) = (uint32_t)crc;
        *(uint32_t *)(localHead + 18) = (uint32_t)payload.length;
        *(uint32_t *)(localHead + 22) = (uint32_t)data.length;
        *(uint16_t *)(localHead + 26) = fnLen;
        *(uint16_t *)(localHead + 28) = 0; // Extra len

        fwrite(localHead, 1, 30, zipFp);
        fwrite(fn, 1, fnLen, zipFp);
        if (payload.length > 0) {
            fwrite(payload.bytes, 1, payload.length, zipFp);
        }

        // Lưu mục lục Central Directory
        ZTZipEntry entry;
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.filename, fn, sizeof(entry.filename) - 1);
        entry.method = method;
        entry.csize = (uint32_t)payload.length;
        entry.usize = (uint32_t)data.length;
        entry.crc = (uint32_t)crc;
        entry.local_offset = (uint32_t)localOffset;

        [cdEntries addObject:[NSValue valueWithBytes:&entry objCType:@encode(ZTZipEntry)]];
    }
}

@interface ZTBackupManager ()
@property (nonatomic, copy, nullable) void (^restorePickerCompletion)(BOOL success, NSString *message);
@end

@implementation ZTBackupManager

+ (instancetype)sharedManager {
    static ZTBackupManager *s_instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_instance = [[ZTBackupManager alloc] init];
    });
    return s_instance;
}

// ==============================================================================
// 1. KHÔI PHỤC TÀI KHOẢN TỪ FILE BACKUP (.adbk / .zip) KÈM TIẾN TRÌNH
// ==============================================================================

- (void)restoreFromBackupFile:(NSString *)filePath completion:(void (^)(BOOL success, NSString *message, NSDictionary * _Nullable restoredInfo))completion {
    [self restoreFromBackupFile:filePath presentingVC:nil completion:completion];
}

- (void)restoreFromBackupFile:(NSString *)filePath presentingVC:(nullable UIViewController *)presentingVC completion:(void (^)(BOOL success, NSString *message, NSDictionary * _Nullable restoredInfo))completion {
    if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        if (completion) completion(NO, @"Không tìm thấy file backup trên thiết bị!", nil);
        return;
    }

    FILE *fp = fopen([filePath UTF8String], "rb");
    if (!fp) {
        if (completion) completion(NO, @"Không thể mở file backup để đọc!", nil);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    if (fileSize < 22) {
        fclose(fp);
        if (completion) completion(NO, @"File backup không hợp lệ hoặc bị lỗi kích thước!", nil);
        return;
    }

    // Khởi tạo Progress Alert
    UIProgressView *progressView = nil;
    UIAlertController *progressAlert = zt_create_progress_alert(@"📂 ĐANG KHÔI PHỤC TÀI KHOẢN (.ADBK)",
                                                               @"[0%] Đang bắt đầu phân tích file...",
                                                               &progressView);

    UIViewController *safeTop = zt_get_safe_top_vc(presentingVC);
    if (safeTop) {
        @try {
            [safeTop presentViewController:progressAlert animated:YES completion:nil];
        } @catch (NSException *e) {}
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        // 1. Tìm End of Central Directory (EOCD: 0x06054b50)
        long searchLimit = fileSize > 65536 ? 65536 : fileSize;
        fseek(fp, fileSize - searchLimit, SEEK_SET);
        uint8_t *searchBuf = (uint8_t *)malloc(searchLimit);
        if (!searchBuf) {
            fclose(fp);
            dispatch_async(dispatch_get_main_queue(), ^{
                [progressAlert dismissViewControllerAnimated:YES completion:^{
                    if (completion) completion(NO, @"Không đủ bộ nhớ để phân tích file backup!", nil);
                }];
            });
            return;
        }
        fread(searchBuf, 1, searchLimit, fp);

        long eocdOffset = -1;
        for (long i = searchLimit - 22; i >= 0; i--) {
            if (searchBuf[i] == 0x50 && searchBuf[i+1] == 0x4b &&
                searchBuf[i+2] == 0x05 && searchBuf[i+3] == 0x06) {
                eocdOffset = (fileSize - searchLimit) + i;
                break;
            }
        }
        free(searchBuf);

        if (eocdOffset == -1) {
            fclose(fp);
            dispatch_async(dispatch_get_main_queue(), ^{
                [progressAlert dismissViewControllerAnimated:YES completion:^{
                    if (completion) completion(NO, @"Định dạng file không phải là file ZIP / ADBK hợp lệ!", nil);
                }];
            });
            return;
        }

        // Đọc thông số EOCD
        fseek(fp, eocdOffset + 10, SEEK_SET);
        uint16_t totalEntries = 0;
        fread(&totalEntries, 2, 1, fp);
        fseek(fp, eocdOffset + 16, SEEK_SET);
        uint32_t cdOffset = 0;
        fread(&cdOffset, 4, 1, fp);

        // 2. Quét toàn bộ Central Directory
        fseek(fp, cdOffset, SEEK_SET);
        NSMutableArray<NSValue *> *entriesList = [NSMutableArray arrayWithCapacity:totalEntries];

        for (int i = 0; i < totalEntries; i++) {
            uint32_t sig = 0;
            if (fread(&sig, 4, 1, fp) != 1 || sig != 0x02014b50) {
                break;
            }

            uint8_t cdHead[42];
            if (fread(cdHead, 1, 42, fp) != 42) break;

            ZTZipEntry entry;
            memset(&entry, 0, sizeof(entry));
            entry.method = *(uint16_t *)(cdHead + 6);
            entry.crc = *(uint32_t *)(cdHead + 12);
            entry.csize = *(uint32_t *)(cdHead + 16);
            entry.usize = *(uint32_t *)(cdHead + 20);
            uint16_t fnLen = *(uint16_t *)(cdHead + 24);
            uint16_t extraLen = *(uint16_t *)(cdHead + 26);
            uint16_t commentLen = *(uint16_t *)(cdHead + 28);
            entry.local_offset = *(uint32_t *)(cdHead + 38);

            uint16_t readLen = fnLen < sizeof(entry.filename) - 1 ? fnLen : (sizeof(entry.filename) - 1);
            fread(entry.filename, 1, readLen, fp);
            entry.filename[readLen] = '\0';
            if (fnLen > readLen) {
                fseek(fp, fnLen - readLen, SEEK_CUR);
            }
            fseek(fp, extraLen + commentLen, SEEK_CUR);

            [entriesList addObject:[NSValue valueWithBytes:&entry objCType:@encode(ZTZipEntry)]];
        }

        zt_update_progress(progressAlert, progressView, [NSString stringWithFormat:@"[15%%] 🔍 Đã đọc %lu tệp từ file sao lưu...", (unsigned long)entriesList.count], 0.15f);

        NSString *home = zt_get_zalo_data_container_path();
        NSFileManager *fm = [NSFileManager defaultManager];
        int extractedCount = 0;
        NSUInteger totalItems = entriesList.count;

        // 3. Trích xuất từng file vào đúng vị trí Sandbox với @autoreleasepool
        for (NSUInteger i = 0; i < totalItems; i++) {
            @autoreleasepool {
                NSValue *val = entriesList[i];
                ZTZipEntry entry;
                [val getValue:&entry];

                NSString *fn = [NSString stringWithUTF8String:entry.filename];
                if (!fn || fn.length == 0) continue;

                NSString *targetPath = nil;

                // Phân loại đường dẫn đích
                if ([fn hasPrefix:@"vn.com.vng.zingalo/"]) {
                    NSString *sub = [fn substringFromIndex:[@"vn.com.vng.zingalo/" length]];
                    targetPath = [home stringByAppendingPathComponent:sub];
                } else if ([fn hasPrefix:@"___groups___/"]) {
                    NSString *rest = [fn substringFromIndex:[@"___groups___/" length]];
                    if ([rest hasSuffix:@".plist"] && [rest rangeOfString:@"/"].location == NSNotFound) {
                        NSString *grpName = [rest stringByDeletingPathExtension];
                        NSString *grpPath = zt_get_zalo_group_container_path(grpName);
                        if (grpPath) {
                            targetPath = [grpPath stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Preferences/%@", rest]];
                        }
                    } else {
                        NSRange slashRange = [rest rangeOfString:@"/"];
                        if (slashRange.location != NSNotFound) {
                            NSString *grpName = [rest substringToIndex:slashRange.location];
                            NSString *sub = [rest substringFromIndex:slashRange.location + 1];
                            NSString *grpPath = zt_get_zalo_group_container_path(grpName);
                            if (grpPath) {
                                targetPath = [grpPath stringByAppendingPathComponent:sub];
                            }
                        }
                    }
                } else if ([fn isEqualToString:@"vn.com.vng.zingalo.plist"]) {
                    targetPath = [home stringByAppendingPathComponent:@"Library/Preferences/vn.com.vng.zingalo.plist"];
                } else if ([fn isEqualToString:@"com.sonhu.zalotweak.plist"]) {
                    targetPath = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
                } else if ([fn isEqualToString:@"com.sonhu.zalotweak.license.plist"]) {
                    targetPath = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.license.plist"];
                } else {
                    targetPath = [home stringByAppendingPathComponent:[NSString stringWithFormat:@"Documents/BackupMeta/%@", fn]];
                }

                if (!targetPath) continue;

                if ([fn hasSuffix:@"/"]) {
                    [fm createDirectoryAtPath:targetPath withIntermediateDirectories:YES attributes:nil error:nil];
                    continue;
                }

                // Đọc dữ liệu từ local header offset
                fseek(fp, entry.local_offset, SEEK_SET);
                uint32_t lsig = 0;
                if (fread(&lsig, 4, 1, fp) != 1 || lsig != 0x04034b50) {
                    continue;
                }

                fseek(fp, entry.local_offset + 26, SEEK_SET);
                uint16_t lFnLen = 0, lExtraLen = 0;
                fread(&lFnLen, 2, 1, fp);
                fread(&lExtraLen, 2, 1, fp);

                long dataOffset = entry.local_offset + 30 + lFnLen + lExtraLen;
                fseek(fp, dataOffset, SEEK_SET);

                NSData *fileData = nil;
                if (entry.method == 0) {
                    uint8_t *raw = (uint8_t *)malloc(entry.usize + 1);
                    if (raw) {
                        fread(raw, 1, entry.usize, fp);
                        fileData = [NSData dataWithBytesNoCopy:raw length:entry.usize freeWhenDone:YES];
                    }
                } else if (entry.method == 8) {
                    uint8_t *cbuf = (uint8_t *)malloc(entry.csize);
                    if (cbuf) {
                        fread(cbuf, 1, entry.csize, fp);
                        fileData = zt_decompress_deflate(cbuf, entry.csize, entry.usize);
                        free(cbuf);
                    }
                }

                if (fileData) {
                    [fm createDirectoryAtPath:[targetPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
                    [fileData writeToFile:targetPath atomically:YES];
                    chmod([targetPath UTF8String], 0666);
                    extractedCount++;
                }

                if (i % 8 == 0 || i == totalItems - 1) {
                    float prog = 0.15f + 0.70f * ((float)(i + 1) / (float)totalItems);
                    NSString *uMsg = [NSString stringWithFormat:@"[%.0f%%] 📂 Đang trích xuất: %lu/%lu tệp\n(%@)",
                                     prog * 100.0f,
                                     (unsigned long)(i + 1),
                                     (unsigned long)totalItems,
                                     [fn lastPathComponent]];
                    zt_update_progress(progressAlert, progressView, uMsg, prog);
                }
            }
        }

        fclose(fp);

        zt_update_progress(progressAlert, progressView, @"[90%] ⚙️ Đang khôi phục hồ sơ máy & thông số tài khoản...", 0.90f);

        // 4. ĐỒNG BỘ VÀ KHÔI PHỤC HỒ SƠ MÁY (PROFILE)
        NSString *tweakPrefPath = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        NSString *tweakDocPath = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        NSMutableDictionary *tweakDict = nil;

        if ([fm fileExistsAtPath:tweakPrefPath]) {
            tweakDict = [NSMutableDictionary dictionaryWithContentsOfFile:tweakPrefPath];
        } else if ([fm fileExistsAtPath:tweakDocPath]) {
            tweakDict = [NSMutableDictionary dictionaryWithContentsOfFile:tweakDocPath];
        }

        NSMutableDictionary *restoredInfo = [NSMutableDictionary dictionary];

        if (tweakDict) {
            tweakDict[@"needsNewProfile"] = @(NO);
            tweakDict[@"needsSandboxPurge"] = @(NO);
            tweakDict[@"needsKeychainPurge"] = @(NO);
            tweakDict[@"justRestoredBackup"] = @(YES);
            tweakDict[@"hasConfiguredProfile"] = @(YES);
            tweakDict[@"enabled"] = @(YES);

            [tweakDict writeToFile:tweakPrefPath atomically:YES];
            chmod([tweakPrefPath UTF8String], 0666);
            [tweakDict writeToFile:tweakDocPath atomically:YES];
            chmod([tweakDocPath UTF8String], 0666);

            [tweakDict writeToFile:GLOBAL_PREFS_PATH atomically:YES];
            chmod([GLOBAL_PREFS_PATH UTF8String], 0666);

            NSString *rhPath = get_backup_roothide_prefs_path();
            if (rhPath) {
                [tweakDict writeToFile:rhPath atomically:YES];
                chmod([rhPath UTF8String], 0666);
            }

            NSDictionary<NSString *, NSString *> *groupMap = zt_get_all_zalo_group_containers();
            for (NSString *grpName in groupMap) {
                NSString *grpDir = groupMap[grpName];
                NSString *grpTweakPlist = [grpDir stringByAppendingPathComponent:@"com.sonhu.zalotweak.plist"];
                [tweakDict writeToFile:grpTweakPlist atomically:YES];
                chmod([grpTweakPlist UTF8String], 0666);
            }

            CFPreferencesSetMultiple((__bridge CFDictionaryRef)tweakDict, NULL, CFSTR("com.sonhu.zalotweak"), kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
            CFPreferencesAppSynchronize(CFSTR("com.sonhu.zalotweak"));
            CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.sonhu.zalotweak/settingschanged"), NULL, NULL, YES);

            restoredInfo[@"deviceMachine"] = tweakDict[@"deviceMachine"] ?: @"iPhone";
            restoredInfo[@"spoofedIDFV"] = tweakDict[@"spoofedIDFV"] ?: @"(Không xác định)";
            restoredInfo[@"carrierName"] = tweakDict[@"carrierName"] ?: @"(Mặc định)";
        }

        // 5. Đọc thông tin tài khoản Zalo đã khôi phục
        NSString *zaloPrefPath = [home stringByAppendingPathComponent:@"Library/Preferences/vn.com.vng.zingalo.plist"];
        if ([fm fileExistsAtPath:zaloPrefPath]) {
            NSDictionary *zDict = [NSDictionary dictionaryWithContentsOfFile:zaloPrefPath];
            if (zDict) {
                restoredInfo[@"uid"] = zDict[@"kSessionUid"] ? [NSString stringWithFormat:@"%@", zDict[@"kSessionUid"]] : @"(Không xác định)";
                restoredInfo[@"phone"] = zDict[@"kStoredPhoneNumberLogin"] ?: @"(Không có số)";
            }
        }

        NSString *msg = [NSString stringWithFormat:@"✅ ĐÃ KHÔI PHỤC THÀNH CÔNG %d TẬP TIN!\n\n"
                                                   @"• Tài khoản: %@ (UID: %@)\n"
                                                   @"• Máy ảo: %@\n"
                                                   @"• IDFV: %@\n"
                                                   @"• Nhà mạng: %@\n\n"
                                                   @"👉 Hồ sơ máy đã được nạp chuẩn 100%% khớp với Server.\n"
                                                   @"Vui lòng bấm 'Khởi Động Lại' để vào thẳng tài khoản!",
                         extractedCount,
                         restoredInfo[@"phone"] ?: @"",
                         restoredInfo[@"uid"] ?: @"",
                         restoredInfo[@"deviceMachine"] ?: @"",
                         restoredInfo[@"spoofedIDFV"] ?: @"",
                         restoredInfo[@"carrierName"] ?: @""];

        zt_update_progress(progressAlert, progressView, @"[100%] 🎉 Khôi phục thành công!", 1.0f);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [progressAlert dismissViewControllerAnimated:YES completion:^{
                BOOL inZalo = zt_is_running_in_zalo();
                if (!inZalo) {
                    zt_kill_all_zalo_processes();
                }

                UIAlertController *succAlert = [UIAlertController alertControllerWithTitle:@"🎉 Khôi Phục Hoàn Tất"
                                                                               message:msg
                                                                        preferredStyle:UIAlertControllerStyleAlert];

                if (inZalo) {
                    [succAlert addAction:[UIAlertAction actionWithTitle:@"🚀 Khởi Động Lại Zalo Ngay"
                                                                 style:UIAlertActionStyleDestructive
                                                               handler:^(UIAlertAction *action) {
                        exit(0);
                    }]];
                } else {
                    [succAlert addAction:[UIAlertAction actionWithTitle:@"🚀 Mở Zalo Ngay"
                                                                 style:UIAlertActionStyleDefault
                                                               handler:^(UIAlertAction *action) {
                        NSURL *zUrl = [NSURL URLWithString:@"zalo://"];
                        if (@available(iOS 10.0, *)) {
                            [[UIApplication sharedApplication] openURL:zUrl options:@{} completionHandler:nil];
                        } else {
                            [[UIApplication sharedApplication] openURL:zUrl];
                        }
                    }]];
                }

                [succAlert addAction:[UIAlertAction actionWithTitle:@"Để Sau" style:UIAlertActionStyleCancel handler:nil]];

                UIViewController *targetVC = zt_get_safe_top_vc(presentingVC);
                if (targetVC) {
                    @try {
                        [targetVC presentViewController:succAlert animated:YES completion:nil];
                    } @catch (NSException *e) {
                        NSLog(@"[ZaloTweak-Restore] Lỗi hiển thị Alert: %@", e);
                    }
                }

                if (completion) {
                    completion(YES, msg, restoredInfo);
                }
            }];
        });
    });
}

// ==============================================================================
// 2. GIAO DIỆN CHỌN FILE VÀ KHÔI PHỤC (.adbk / .zip)
// ==============================================================================

- (void)presentRestorePickerFrom:(UIViewController *)presentingVC completion:(nullable void (^)(BOOL success, NSString *message))completion {
    self.restorePickerCompletion = completion;

    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.data", @"public.content", @"public.item", @"public.zip-archive", @"com.pkware.zip-archive"]
                                                                                                    inMode:UIDocumentPickerModeImport];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;

    if (@available(iOS 11.0, *)) {
        picker.modalPresentationStyle = UIModalPresentationFormSheet;
    }

    UIViewController *safeTop = zt_get_safe_top_vc(presentingVC);
    if (safeTop) {
        @try {
            [safeTop presentViewController:picker animated:YES completion:nil];
        } @catch (NSException *e) {
            NSLog(@"[ZaloTweak-Picker] Lỗi mở Document Picker: %@", e);
        }
    }
}

#pragma mark - UIDocumentPickerDelegate

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count == 0) return;
    NSURL *fileURL = urls.firstObject;

    // Đóng Picker trước rồi mới mở Progress Alert để tránh va chạm ViewController
    [controller dismissViewControllerAnimated:YES completion:^{
        [self restoreFromBackupFile:fileURL.path presentingVC:nil completion:^(BOOL success, NSString *message, NSDictionary *restoredInfo) {
            if (self.restorePickerCompletion) {
                self.restorePickerCompletion(success, message);
                self.restorePickerCompletion = nil;
            }
        }];
    }];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    if (self.restorePickerCompletion) {
        self.restorePickerCompletion(NO, @"Đã hủy chọn file.");
        self.restorePickerCompletion = nil;
    }
}

// ==============================================================================
// 3. TẠO BẢN SAO LƯU 1-CHẠM (.adbk) KÈM TIẾN TRÌNH & CHỐNG CRASH
// ==============================================================================

- (void)createBackupFrom:(UIViewController *)presentingVC completion:(nullable void (^)(BOOL success, NSString *message, NSString * _Nullable backupPath))completion {
    // Trì hoãn 0.15s để bất kỳ ActionSheet nào đang mở đóng lại hoàn toàn, chống va chạm present
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (!zt_is_running_in_zalo()) {
            zt_kill_all_zalo_processes();
        }

        NSString *home = zt_get_zalo_data_container_path();
        NSFileManager *fm = [NSFileManager defaultManager];

        // Lấy thông tin tài khoản hiện tại
        NSString *zaloPrefPath = [home stringByAppendingPathComponent:@"Library/Preferences/vn.com.vng.zingalo.plist"];
        NSString *uid = @"unknown";
        NSString *phone = @"backup";
        if ([fm fileExistsAtPath:zaloPrefPath]) {
            NSDictionary *zDict = [NSDictionary dictionaryWithContentsOfFile:zaloPrefPath];
            if (zDict[@"kSessionUid"]) uid = [NSString stringWithFormat:@"%@", zDict[@"kSessionUid"]];
            if (zDict[@"kStoredPhoneNumberLogin"]) phone = zDict[@"kStoredPhoneNumberLogin"];
        }

        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"yyyyMMdd_HHmmss"];
        NSString *dateStr = [df stringFromDate:[NSDate date]];

        NSString *backupDir = [home stringByAppendingPathComponent:@"Documents/ZaloBackups"];
        if (![fm createDirectoryAtPath:backupDir withIntermediateDirectories:YES attributes:nil error:nil] || ![fm isWritableFileAtPath:backupDir]) {
            backupDir = @"/var/mobile/Documents/ZaloBackups";
            [fm createDirectoryAtPath:backupDir withIntermediateDirectories:YES attributes:nil error:nil];
        }
        NSString *destZipPath = [backupDir stringByAppendingPathComponent:[NSString stringWithFormat:@"vn.com.vng.zingalo_%@_%@_%@.adbk", phone, uid, dateStr]];

        // Tạo giao diện tiến trình Progress Alert
        UIProgressView *progressView = nil;
        UIAlertController *progressAlert = zt_create_progress_alert(@"💾 TIẾN TRÌNH SAO LƯU (.ADBK)",
                                                                   @"[0%] Đang quét dữ liệu Sandbox...",
                                                                   &progressView);

        UIViewController *safeTop = zt_get_safe_top_vc(presentingVC);
        if (safeTop) {
            @try {
                [safeTop presentViewController:progressAlert animated:YES completion:nil];
            } @catch (NSException *e) {}
        }

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
            FILE *zipFp = fopen([destZipPath UTF8String], "wb");
            if (!zipFp) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [progressAlert dismissViewControllerAnimated:YES completion:^{
                        if (completion) completion(NO, @"Không thể tạo file sao lưu trong thư mục Documents!", nil);
                    }];
                });
                return;
            }

            NSMutableArray<NSValue *> *cdEntries = [NSMutableArray array];
            NSMutableArray<NSDictionary *> *itemsToBackup = [NSMutableArray array];

            // 1. Tạo Binfo.plist
            NSDictionary *binfo = @{
                @"displayName": @"Zalo",
                @"id": @"vn.com.vng.zingalo",
                @"date": [NSDate date]
            };
            NSString *tmpBinfo = [NSTemporaryDirectory() stringByAppendingPathComponent:@"Binfo.plist"];
            [binfo writeToFile:tmpBinfo atomically:YES];
            zt_add_file_to_zip(zipFp, tmpBinfo, @"Binfo.plist", cdEntries);
            [fm removeItemAtPath:tmpBinfo error:nil];

            // 2. Thu thập Preferences
            if ([fm fileExistsAtPath:zaloPrefPath]) {
                [itemsToBackup addObject:@{@"disk": zaloPrefPath, @"zip": @"vn.com.vng.zingalo.plist"}];
                [itemsToBackup addObject:@{@"disk": zaloPrefPath, @"zip": @"vn.com.vng.zingalo/Library/Preferences/vn.com.vng.zingalo.plist"}];
            }

            NSString *tweakPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
            if ([fm fileExistsAtPath:tweakPref]) {
                [itemsToBackup addObject:@{@"disk": tweakPref, @"zip": @"com.sonhu.zalotweak.plist"}];
                [itemsToBackup addObject:@{@"disk": tweakPref, @"zip": @"vn.com.vng.zingalo/Library/Preferences/com.sonhu.zalotweak.plist"}];
            }

            // 3. Thu thập Documents/ (Pass 1 - Quét lọc file)
            NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
            zt_collect_files_recursive(fm, docDir, @"vn.com.vng.zingalo/Documents", itemsToBackup);

            // 4. Thu thập Library/Application Support/KVCore
            NSString *kvcoreDir = [home stringByAppendingPathComponent:@"Library/Application Support/KVCore"];
            if ([fm fileExistsAtPath:kvcoreDir]) {
                zt_collect_files_recursive(fm, kvcoreDir, @"vn.com.vng.zingalo/Library/Application Support/KVCore", itemsToBackup);
            }

            // 5. Thu thập App Group containers
            NSDictionary<NSString *, NSString *> *groupMap = zt_get_all_zalo_group_containers();
            for (NSString *grpName in groupMap) {
                NSString *grpDir = groupMap[grpName];
                NSString *grpPlist = [grpDir stringByAppendingPathComponent:[NSString stringWithFormat:@"Library/Preferences/%@.plist", grpName]];
                if ([fm fileExistsAtPath:grpPlist]) {
                    [itemsToBackup addObject:@{@"disk": grpPlist, @"zip": [NSString stringWithFormat:@"___groups___/%@.plist", grpName]}];
                }
                zt_collect_files_recursive(fm, grpDir, [NSString stringWithFormat:@"___groups___/%@", grpName], itemsToBackup);
            }

            NSUInteger totalCount = itemsToBackup.count;
            zt_update_progress(progressAlert, progressView, [NSString stringWithFormat:@"[15%%] 📦 Bắt đầu nén %lu tệp dữ liệu...", (unsigned long)totalCount], 0.15f);

            // 6. Thực hiện nén từng tệp với @autoreleasepool chống tràn RAM
            for (NSUInteger i = 0; i < totalCount; i++) {
                @autoreleasepool {
                    NSDictionary *itemDict = itemsToBackup[i];
                    NSString *dPath = itemDict[@"disk"];
                    NSString *zPath = itemDict[@"zip"];

                    zt_add_file_to_zip(zipFp, dPath, zPath, cdEntries);

                    if (i % 8 == 0 || i == totalCount - 1) {
                        float prog = 0.15f + 0.75f * ((float)(i + 1) / (float)totalCount);
                        NSString *uMsg = [NSString stringWithFormat:@"[%.0f%%] 📦 Đang nén: %lu/%lu tệp\n(%@)",
                                         prog * 100.0f,
                                         (unsigned long)(i + 1),
                                         (unsigned long)totalCount,
                                         [zPath lastPathComponent]];
                        zt_update_progress(progressAlert, progressView, uMsg, prog);
                    }
                }
            }

            zt_update_progress(progressAlert, progressView, @"[92%] 📝 Đang ghi mục lục ZIP & hoàn tất...", 0.92f);

            // 7. Ghi Central Directory
            long cdStartOffset = ftell(zipFp);
            for (NSValue *val in cdEntries) {
                ZTZipEntry entry;
                [val getValue:&entry];
                const char *fn = entry.filename;
                uint16_t fnLen = (uint16_t)strlen(fn);

                uint8_t cdHead[46];
                *(uint32_t *)(cdHead + 0) = 0x02014b50;
                *(uint16_t *)(cdHead + 4) = 20; // Version made by
                *(uint16_t *)(cdHead + 6) = 20; // Version needed
                *(uint16_t *)(cdHead + 8) = 0;  // Flags
                *(uint16_t *)(cdHead + 10) = entry.method;
                *(uint16_t *)(cdHead + 12) = 0; // Time
                *(uint16_t *)(cdHead + 14) = 0; // Date
                *(uint32_t *)(cdHead + 16) = entry.crc;
                *(uint32_t *)(cdHead + 20) = entry.csize;
                *(uint32_t *)(cdHead + 24) = entry.usize;
                *(uint16_t *)(cdHead + 28) = fnLen;
                *(uint16_t *)(cdHead + 30) = 0; // Extra len
                *(uint16_t *)(cdHead + 32) = 0; // Comment len
                *(uint16_t *)(cdHead + 34) = 0; // Disk start
                *(uint16_t *)(cdHead + 36) = 0; // Internal attr
                *(uint32_t *)(cdHead + 38) = 0x81A40000; // External attr (0644 in hex)
                *(uint32_t *)(cdHead + 42) = entry.local_offset;

                fwrite(cdHead, 1, 46, zipFp);
                fwrite(fn, 1, fnLen, zipFp);
            }
            long cdSize = ftell(zipFp) - cdStartOffset;

            // 8. Ghi End of Central Directory Record (EOCD)
            uint8_t eocd[22];
            *(uint32_t *)(eocd + 0) = 0x06054b50;
            *(uint16_t *)(eocd + 4) = 0; // Disk number
            *(uint16_t *)(eocd + 6) = 0; // Disk with CD
            *(uint16_t *)(eocd + 8) = (uint16_t)cdEntries.count;
            *(uint16_t *)(eocd + 10) = (uint16_t)cdEntries.count;
            *(uint32_t *)(eocd + 12) = (uint32_t)cdSize;
            *(uint32_t *)(eocd + 16) = (uint32_t)cdStartOffset;
            *(uint16_t *)(eocd + 20) = 0; // Comment len

            fwrite(eocd, 1, 22, zipFp);
            fclose(zipFp);

            zt_update_progress(progressAlert, progressView, @"[100%] 🎉 Đã tạo bản sao lưu thành công!", 1.0f);

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [progressAlert dismissViewControllerAnimated:YES completion:^{
                    NSString *succMsg = [NSString stringWithFormat:@"💾 ĐÃ TẠO BẢN SAO LƯU THÀNH CÔNG!\n\n"
                                                                   @"• Tài khoản: %@ (UID: %@)\n"
                                                                   @"• Tên file: %@\n"
                                                                   @"• Số lượng tệp: %lu tệp\n"
                                                                   @"• Định dạng: Chuẩn Apps Manager (.adbk)\n\n"
                                                                   @"Bạn có thể chia sẻ hoặc lưu vào Tệp (Files) ngay bây giờ.",
                                         phone, uid, [destZipPath lastPathComponent], (unsigned long)totalCount];

                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🎉 Sao Lưu Thành Công"
                                                                                   message:succMsg
                                                                            preferredStyle:UIAlertControllerStyleAlert];

                    [alert addAction:[UIAlertAction actionWithTitle:@"📤 Chia Sẻ / Lưu Tệp"
                                                             style:UIAlertActionStyleDefault
                                                           handler:^(UIAlertAction *action) {
                        UIViewController *topNow = zt_get_safe_top_vc(presentingVC);
                        [self shareFileAtPath:destZipPath from:topNow];
                    }]];

                    [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];

                    UIViewController *targetVC = zt_get_safe_top_vc(presentingVC);
                    if (targetVC) {
                        @try {
                            [targetVC presentViewController:alert animated:YES completion:nil];
                        } @catch (NSException *e) {
                            NSLog(@"[ZaloTweak-Backup] Lỗi hiển thị Alert thành công: %@", e);
                        }
                    }

                    if (completion) completion(YES, succMsg, destZipPath);
                }];
            });
        });
    });
}

// ==============================================================================
// 4. CHIA SẺ FILE QUA SHARE SHEET
// ==============================================================================

- (void)shareFileAtPath:(NSString *)filePath from:(UIViewController *)presentingVC {
    if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) return;
    NSURL *fileURL = [NSURL fileURLWithPath:filePath];

    UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL] applicationActivities:nil];

    UIViewController *safeTop = zt_get_safe_top_vc(presentingVC);
    if (!safeTop) return;

    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        activityVC.popoverPresentationController.sourceView = safeTop.view;
        activityVC.popoverPresentationController.sourceRect = CGRectMake(safeTop.view.bounds.size.width / 2, safeTop.view.bounds.size.height / 2, 0, 0);
        activityVC.popoverPresentationController.permittedArrowDirections = 0;
    }

    @try {
        [safeTop presentViewController:activityVC animated:YES completion:nil];
    } @catch (NSException *e) {
        NSLog(@"[ZaloTweak-Share] Lỗi mở Share Sheet: %@", e);
    }
}

@end
