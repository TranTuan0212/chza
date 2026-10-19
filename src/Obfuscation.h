#ifndef ZT_OBFUSCATION_H
#define ZT_OBFUSCATION_H

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==============================================================================
// 1. CHUỖI MÃ HÓA COMPILE-TIME (XOR 0x5A)
// Giúp binary dylib không chứa bất kỳ URL, Token, Salt hay Key nào ở dạng plaintext.
// Lệnh 'strings' hay IDA Pro / Ghidra chỉ thấy các mảng byte vô nghĩa.
// ==============================================================================

static inline NSString *zt_obf_str(const unsigned char *data, size_t len, unsigned char key) {
    if (!data || len == 0) return @"";
    char *buf = (char *)malloc(len + 1);
    if (!buf) return @"";
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)(data[i] ^ key);
    }
    buf[len] = '\0';
    NSString *str = [[NSString alloc] initWithBytesNoCopy:buf length:len encoding:NSUTF8StringEncoding freeWhenDone:YES];
    return str ?: @"";
}

// 1.1 Supabase RPC URL: "https://litfhujpobscqwpuhzvv.supabase.co/rest/v1/rpc/verify_license"
static const unsigned char OBF_SUPABASE_RPC_URL[] = {
    0x32, 0x2e, 0x2e, 0x2a, 0x29, 0x60, 0x75, 0x75, 0x36, 0x33, 0x2e, 0x3c,
    0x32, 0x2f, 0x30, 0x2a, 0x35, 0x38, 0x29, 0x39, 0x2b, 0x2d, 0x2a, 0x2f,
    0x32, 0x20, 0x2c, 0x2c, 0x74, 0x29, 0x2f, 0x2a, 0x3b, 0x38, 0x3b, 0x29,
    0x3f, 0x74, 0x39, 0x35, 0x75, 0x28, 0x3f, 0x29, 0x2e, 0x75, 0x2c, 0x6b,
    0x75, 0x28, 0x2a, 0x39, 0x75, 0x2c, 0x3f, 0x28, 0x33, 0x3c, 0x23, 0x05,
    0x36, 0x33, 0x39, 0x3f, 0x34, 0x29, 0x3f
};
#define GET_SUPABASE_RPC_URL() zt_obf_str(OBF_SUPABASE_RPC_URL, 67, 0x5A)

// 1.2 Supabase API Key: "sb_publishable_4FuIC_rnNLkbihAIiTLUaA_f15jK9f3"
static const unsigned char OBF_SUPABASE_API_KEY[] = {
    0x29, 0x38, 0x05, 0x2a, 0x2f, 0x38, 0x36, 0x33, 0x29, 0x32, 0x3b, 0x38,
    0x36, 0x3f, 0x05, 0x6e, 0x1c, 0x2f, 0x13, 0x19, 0x05, 0x28, 0x34, 0x14,
    0x16, 0x31, 0x38, 0x33, 0x32, 0x1b, 0x13, 0x33, 0x0e, 0x16, 0x0f, 0x3b,
    0x1b, 0x05, 0x3c, 0x6b, 0x6f, 0x30, 0x11, 0x63, 0x3c, 0x69
};
#define GET_SUPABASE_API_KEY() zt_obf_str(OBF_SUPABASE_API_KEY, 46, 0x5A)

// 1.3 Salt HMAC: "ZaloTweakSecuredSalt2026!@#$"
static const unsigned char OBF_SHARED_SECRET_SALT[] = {
    0x00, 0x3b, 0x36, 0x35, 0x0e, 0x2d, 0x3f, 0x3b, 0x31, 0x09, 0x3f, 0x39,
    0x2f, 0x28, 0x3f, 0x3e, 0x09, 0x3b, 0x36, 0x2e, 0x68, 0x6a, 0x68, 0x6c,
    0x7b, 0x1a, 0x79, 0x7e
};
#define GET_SHARED_SECRET_SALT() zt_obf_str(OBF_SHARED_SECRET_SALT, 28, 0x5A)

// 1.4 Đường dẫn License plist: "/var/mobile/Library/Preferences/com.sonhu.zalotweak.license.plist"
static const unsigned char OBF_LICENSE_STORAGE_PATH[] = {
    0x75, 0x2c, 0x3b, 0x28, 0x75, 0x37, 0x35, 0x38, 0x33, 0x36, 0x3f, 0x75,
    0x16, 0x33, 0x38, 0x28, 0x3b, 0x28, 0x23, 0x75, 0x0a, 0x28, 0x3f, 0x3c,
    0x3f, 0x28, 0x3f, 0x34, 0x39, 0x3f, 0x29, 0x75, 0x39, 0x35, 0x37, 0x74,
    0x29, 0x35, 0x34, 0x32, 0x2f, 0x74, 0x20, 0x3b, 0x36, 0x35, 0x2e, 0x2d,
    0x3f, 0x3b, 0x31, 0x74, 0x36, 0x33, 0x39, 0x3f, 0x34, 0x29, 0x3f, 0x74,
    0x2a, 0x36, 0x33, 0x29, 0x2e
};
#define GET_LICENSE_STORAGE_PATH() zt_obf_str(OBF_LICENSE_STORAGE_PATH, 65, 0x5A)

// 1.5 CFPreferences App ID: "com.sonhu.zalotweak.license"
static const unsigned char OBF_PREFS_ID[] = {
    0x39, 0x35, 0x37, 0x74, 0x29, 0x35, 0x34, 0x32, 0x2f, 0x74, 0x20, 0x3b,
    0x36, 0x35, 0x2e, 0x2d, 0x3f, 0x3b, 0x31, 0x74, 0x36, 0x33, 0x39, 0x3f,
    0x34, 0x29, 0x3f
};
#define GET_PREFS_ID() zt_obf_str(OBF_PREFS_ID, 27, 0x5A)

// 1.6 License Keys
static const unsigned char OBF_KEY_LICENSE_KEY[] = {0x36, 0x33, 0x39, 0x3f, 0x34, 0x29, 0x3f, 0x05, 0x31, 0x3f, 0x23};
#define GET_KEY_LICENSE_KEY() zt_obf_str(OBF_KEY_LICENSE_KEY, 11, 0x5A)

static const unsigned char OBF_KEY_TOKEN[] = {0x2e, 0x35, 0x31, 0x3f, 0x34};
#define GET_KEY_TOKEN() zt_obf_str(OBF_KEY_TOKEN, 5, 0x5A)

static const unsigned char OBF_KEY_EXPIRES_AT[] = {0x3f, 0x22, 0x2a, 0x33, 0x28, 0x3f, 0x29, 0x05, 0x3b, 0x2e};
#define GET_KEY_EXPIRES_AT() zt_obf_str(OBF_KEY_EXPIRES_AT, 10, 0x5A)

static const unsigned char OBF_KEY_REAL_UDID[] = {0x28, 0x3f, 0x3b, 0x36, 0x05, 0x2f, 0x3e, 0x33, 0x3e};
#define GET_KEY_REAL_UDID() zt_obf_str(OBF_KEY_REAL_UDID, 9, 0x5A)

static const unsigned char OBF_KEY_LAST_CHECK[] = {0x36, 0x3b, 0x29, 0x2e, 0x05, 0x39, 0x32, 0x3f, 0x39, 0x31};
#define GET_KEY_LAST_CHECK() zt_obf_str(OBF_KEY_LAST_CHECK, 10, 0x5A)

// 1.7 HTTP Headers
static const unsigned char OBF_APIKEY_HEADER[] = {0x3b, 0x2a, 0x33, 0x31, 0x3f, 0x23};
#define GET_APIKEY_HEADER() zt_obf_str(OBF_APIKEY_HEADER, 6, 0x5A)

static const unsigned char OBF_AUTH_HEADER[] = {0x1b, 0x2f, 0x2e, 0x32, 0x35, 0x28, 0x33, 0x20, 0x3b, 0x2e, 0x33, 0x35, 0x34};
#define GET_AUTH_HEADER() zt_obf_str(OBF_AUTH_HEADER, 13, 0x5A)

static const unsigned char OBF_BEARER_PREFIX[] = {0x18, 0x3f, 0x3b, 0x28, 0x3f, 0x28, 0x7a};
#define GET_BEARER_PREFIX() zt_obf_str(OBF_BEARER_PREFIX, 7, 0x5A)


// ==============================================================================
// 2. ANTI-DEBUGGING (PHÁT HIỆN LLDB, DEBUGSERVER, GDB, IDA PRO ATTACH)
// ==============================================================================

static inline BOOL zt_is_debugger_attached(void) {
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    memset(&info, 0, sizeof(info));
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        return NO;
    }
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}


// ==============================================================================
// 3. ANTI-HOOK & CODE INTEGRITY CHECK (ARM64 PROLOGUE VERIFICATION)
// Phát hiện nếu hàm bị Substrate, ElleKit, Frida Interceptor, Dobby,
// hoặc Hex Patcher chèn lệnh RET, NOP, hoặc B / LDR X16 Trampoline.
// ==============================================================================

static inline BOOL zt_verify_code_prologue(const void *func_ptr) {
#if defined(__arm64__) || defined(__aarch64__)
    if (!func_ptr) return NO;
    uintptr_t clean_ptr = (uintptr_t)func_ptr;

#if defined(__has_feature)
#if __has_feature(ptrauth_calls)
    clean_ptr = (uintptr_t)__builtin_ptrauth_strip((void *)clean_ptr, 0);
#endif
#endif

    clean_ptr &= ~((uintptr_t)0x3);

    const uint32_t *insn = (const uint32_t *)clean_ptr;
    uint32_t insn0 = insn[0];
    uint32_t insn1 = insn[1];

    // 3.1 Phát hiện Hex Patch: RET trực tiếp (0xD65F03C0) hoặc NOP (0x1F2003D5)
    if (insn0 == 0xD65F03C0 || insn0 == 0x1F2003D5) {
        return NO;
    }

    // 3.2 Phát hiện Hex Patch kinh điển: "MOV W0, #1" (0x52800020) + "RET" (0xD65F03C0) -> ép trả về TRUE
    if ((insn0 == 0x52800020 || insn0 == 0xD2800020) && insn1 == 0xD65F03C0) {
        return NO;
    }

    // 3.3 Phát hiện Hook Trampoline Branch B / BL (0x14000000 -> 0x17FFFFFF)
    if ((insn0 & 0xFC000000) == 0x14000000) {
        return NO;
    }

    // 3.4 Phát hiện Substrate / ElleKit / Frida 64-bit jump: LDR X16, #8 hoặc LDR X17, #8
    if (insn0 == 0x58000050 || insn0 == 0x58000051) {
        return NO;
    }

    // 3.5 Phát hiện BR X16 (0xD61F0200) hoặc BR X17 (0xD61F0220)
    if (insn0 == 0xD61F0200 || insn0 == 0xD61F0220) {
        return NO;
    }
#endif
    return YES;
}


// ==============================================================================
// 4. ANTI-SWIZZLE / ANTI-FLEX 3 RUNTIME INTEGRITY CHECK
// Phát hiện nếu phương thức Objective-C bị Flex 3 hoặc Cycript ghi đè IMP runtime.
// ==============================================================================

static inline BOOL zt_verify_imp_integrity(Class cls, SEL sel, IMP expectedImp) {
    if (!cls || !sel || !expectedImp) return YES;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return YES;
    IMP currentImp = method_getImplementation(m);
#if defined(__has_feature)
#if __has_feature(ptrauth_calls)
    currentImp = (IMP)__builtin_ptrauth_strip((void *)currentImp, 0);
    expectedImp = (IMP)__builtin_ptrauth_strip((void *)expectedImp, 0);
#endif
#endif
    return (currentImp == expectedImp);
}

#ifdef __cplusplus
}
#endif

#endif // ZT_OBFUSCATION_H
