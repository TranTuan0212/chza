-- ==============================================================================
-- SUPABASE SCHEMA: HỆ THỐNG QUẢN LÝ BẢN QUYỀN (DRM) ZALOTWEAK
-- Dự án: https://litfhujpobscqwpuhzvv.supabase.co
-- ==============================================================================

-- 1. Bật extension pgcrypto để sinh token chữ ký số HMAC-SHA256
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Tạo bảng lưu trữ danh sách License Key
CREATE TABLE IF NOT EXISTS public.licenses (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    license_key TEXT NOT NULL UNIQUE,                       -- Mã key (VD: ZT-TRIAL-8899, ZT-PRO-1234)
    bound_udid TEXT DEFAULT NULL,                           -- Khóa theo UDID phần cứng thật (NULL: chưa kích hoạt)
    device_model TEXT DEFAULT NULL,                         -- Tên dòng máy kích hoạt (VD: iPhone14,2)
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,           -- Thời điểm hết hạn chính xác
    is_active BOOLEAN DEFAULT TRUE NOT NULL,                -- Cho phép bật/tắt (khóa key khẩn cấp)
    last_verified_at TIMESTAMP WITH TIME ZONE DEFAULT NULL, -- Thời điểm máy ping kiểm tra gần nhất
    note TEXT DEFAULT NULL,                                 -- Ghi chú (VD: Khách Nam - 0988xxx - Gói 30 ngày)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Tạo chỉ mục tìm kiếm nhanh cho license_key và bound_udid
CREATE INDEX IF NOT EXISTS idx_licenses_key ON public.licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_udid ON public.licenses(bound_udid);

-- 3. Thiết lập bảo mật Row Level Security (RLS)
-- Chặn tuyệt đối người dùng lạ đọc trộm bảng licenses qua API REST
ALTER TABLE public.licenses ENABLE ROW LEVEL SECURITY;

-- 4. Tạo hàm RPC Xác Thực & Tự Động Khóa 1 Máy (verify_license)
-- Hàm này có quyền SECURITY DEFINER, chạy trực tiếp từ server Supabase an toàn tuyệt đối
CREATE OR REPLACE FUNCTION public.verify_license(
    p_license_key TEXT,
    p_udid TEXT,
    p_model TEXT DEFAULT 'iPhone'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_rec RECORD;
    v_clean_key TEXT;
    v_clean_udid TEXT;
    v_secret_salt TEXT := 'ZaloTweakSecuredSalt2026!@#$'; -- Chuỗi bí mật chống giả mạo token
    v_token TEXT;
    v_now TIMESTAMP WITH TIME ZONE := NOW();
BEGIN
    -- Chuẩn hóa dữ liệu đầu vào (cắt bỏ khoảng trắng thừa)
    v_clean_key := TRIM(COALESCE(p_license_key, ''));
    v_clean_udid := LOWER(TRIM(COALESCE(p_udid, '')));

    -- Kiểm tra tham số cơ bản
    IF v_clean_key = '' THEN
        RETURN jsonb_build_object(
            'valid', false,
            'error_code', 'EMPTY_KEY',
            'message', 'Vui lòng nhập License Key!'
        );
    END IF;

    IF v_clean_udid = '' OR LENGTH(v_clean_udid) < 16 THEN
        RETURN jsonb_build_object(
            'valid', false,
            'error_code', 'INVALID_UDID',
            'message', 'Không thể nhận diện UDID thiết bị!'
        );
    END IF;

    -- Tìm kiếm key trong Database
    SELECT * INTO v_rec FROM public.licenses WHERE license_key = v_clean_key;

    -- 1. Nếu không tìm thấy Key
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'valid', false,
            'error_code', 'NOT_FOUND',
            'message', 'Mã kích hoạt không tồn tại trên hệ thống!'
        );
    END IF;

    -- 2. Nếu Key đã bị admin khóa
    IF v_rec.is_active = FALSE THEN
        RETURN jsonb_build_object(
            'valid', false,
            'error_code', 'BLOCKED',
            'message', 'Mã kích hoạt đã bị khóa hoặc thu hồi!'
        );
    END IF;

    -- 3. Nếu Key đã hết hạn
    IF v_now > v_rec.expires_at THEN
        RETURN jsonb_build_object(
            'valid', false,
            'error_code', 'EXPIRED',
            'message', 'Mã kích hoạt đã hết hạn sử dụng!',
            'expires_at', to_char(v_rec.expires_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        );
    END IF;

    -- 4. Kiểm tra ràng buộc UDID (Chỉ cho phép duy nhất 1 máy)
    IF v_rec.bound_udid IS NULL OR TRIM(v_rec.bound_udid) = '' THEN
        -- Lần đầu kích hoạt -> Tự động khóa vĩnh viễn vào UDID này!
        UPDATE public.licenses
        SET bound_udid = v_clean_udid,
            device_model = p_model,
            last_verified_at = v_now
        WHERE id = v_rec.id;
    ELSIF LOWER(TRIM(v_rec.bound_udid)) <> v_clean_udid THEN
        -- Key đã bị kích hoạt trên máy khác
        RETURN jsonb_build_object(
            'valid', false,
            'error_code', 'DEVICE_MISMATCH',
            'message', 'Mã này đã được kích hoạt trên một thiết bị iPhone khác!'
        );
    ELSE
        -- Khớp máy -> Cập nhật thời điểm ping gần nhất
        UPDATE public.licenses
        SET last_verified_at = v_now,
            device_model = COALESCE(p_model, device_model)
        WHERE id = v_rec.id;
    END IF;

    -- 5. Ký mã xác thực Token an toàn (HMAC-SHA256)
    -- Token = HMAC(license_key + udid + expires_at, secret_salt)
    v_token := encode(
        hmac(
            v_clean_key || ':' || v_clean_udid || ':' || to_char(v_rec.expires_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            v_secret_salt,
            'sha256'
        ),
        'hex'
    );

    -- Trả về kết quả xác thực thành công
    RETURN jsonb_build_object(
        'valid', true,
        'message', 'Kích hoạt bản quyền thành công!',
        'expires_at', to_char(v_rec.expires_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'token', v_token
    );
END;
$$;

-- 5. Cấp quyền thực thi hàm cho người dùng anonymous (Client Tweak)
GRANT EXECUTE ON FUNCTION public.verify_license(TEXT, TEXT, TEXT) TO anon;
GRANT EXECUTE ON FUNCTION public.verify_license(TEXT, TEXT, TEXT) TO authenticated;

-- ==============================================================================
-- DỮ LIỆU MẪU ĐỂ BẠN TEST NGAY (Gói Dùng Thử 1 Ngày)
-- ==============================================================================

-- Key dùng thử đúng 1 ngày (Hết hạn sau 24 giờ kể từ lúc tạo)
INSERT INTO public.licenses (license_key, expires_at, note)
VALUES ('ZT-TRIAL-1DAY', NOW() + INTERVAL '1 day', 'Key dùng thử nghiệm 1 ngày')
ON CONFLICT (license_key) DO UPDATE
SET expires_at = NOW() + INTERVAL '1 day', bound_udid = NULL, is_active = TRUE;

