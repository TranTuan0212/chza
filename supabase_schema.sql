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
    duration_days INT DEFAULT 1 NOT NULL,                   -- Số ngày sử dụng (tính từ thời điểm kích hoạt)
    activated_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,     -- Thời điểm bắt đầu kích hoạt lần đầu
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,       -- Thời điểm hết hạn (tính tự động khi kích hoạt)
    bound_udid TEXT DEFAULT NULL,                           -- Khóa theo UDID phần cứng thật (NULL: chưa kích hoạt)
    device_model TEXT DEFAULT NULL,                         -- Tên dòng máy kích hoạt (VD: iPhone14,2)
    is_active BOOLEAN DEFAULT TRUE NOT NULL,                -- Cho phép bật/tắt (khóa key khẩn cấp)
    last_verified_at TIMESTAMP WITH TIME ZONE DEFAULT NULL, -- Thời điểm máy ping kiểm tra gần nhất
    note TEXT DEFAULT NULL,                                 -- Ghi chú (VD: Khách Nam - 0988xxx - Gói 30 ngày)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Cập nhật bảng nếu đã tồn tại từ trước (Migration)
ALTER TABLE public.licenses ALTER COLUMN expires_at DROP NOT NULL;
ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS duration_days INT DEFAULT 1;
ALTER TABLE public.licenses ADD COLUMN IF NOT EXISTS activated_at TIMESTAMP WITH TIME ZONE DEFAULT NULL;

-- Tạo chỉ mục tìm kiếm nhanh cho license_key và bound_udid
CREATE INDEX IF NOT EXISTS idx_licenses_key ON public.licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_udid ON public.licenses(bound_udid);

-- 3. Thiết lập bảo mật Row Level Security (RLS)
ALTER TABLE public.licenses ENABLE ROW LEVEL SECURITY;

-- 4. Tạo hàm RPC Xác Thực & Tự Động Kích Hoạt (verify_license)
-- Tự động tính thời hạn sử dụng ngay từ lúc máy đầu tiên nhập key
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

    -- 3. Nếu Key đã từng kích hoạt và đã hết hạn
    IF v_rec.expires_at IS NOT NULL AND v_now > v_rec.expires_at THEN
        RETURN jsonb_build_object(
            'valid', false,
            'error_code', 'EXPIRED',
            'message', 'Mã kích hoạt đã hết hạn sử dụng!',
            'expires_at', to_char(v_rec.expires_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        );
    END IF;

    -- 4. Kiểm tra ràng buộc UDID & Kích hoạt lần đầu
    IF v_rec.bound_udid IS NULL OR TRIM(v_rec.bound_udid) = '' THEN
        -- LẦN ĐẦU KÍCH HOẠT: BẮT ĐẦU TÍNH GIỜ TỪ ĐÂY
        IF v_rec.expires_at IS NULL THEN
            v_rec.expires_at := v_now + (COALESCE(v_rec.duration_days, 1) * INTERVAL '1 day');
        END IF;

        UPDATE public.licenses
        SET bound_udid = v_clean_udid,
            device_model = p_model,
            activated_at = COALESCE(v_rec.activated_at, v_now),
            expires_at = v_rec.expires_at,
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
-- CÁC CÂU LỆNH MẪU QUẢN LÝ KEY (TÍNH GIỜ TỪ LÚC KÍCH HOẠT)
-- ==============================================================================

-- 1. Tạo hoặc Reset Key Dùng Thử 1 Ngày (Chưa tính giờ, khi nào khách nhập máy mới bắt đầu đếm 24h)
INSERT INTO public.licenses (license_key, duration_days, note)
VALUES ('ZT-TRIAL-1DAY', 1, 'Key dùng thử 1 ngày')
ON CONFLICT (license_key) DO UPDATE
SET duration_days = 1,
    activated_at = NULL,
    expires_at = NULL,
    bound_udid = NULL,
    device_model = NULL,
    last_verified_at = NULL,
    is_active = TRUE,
    note = 'Key dùng thử 1 ngày (Đã reset)';

-- 2. Tạo Key VIP 30 ngày (Bắt đầu đếm 30 ngày từ lúc nhập máy)
-- INSERT INTO public.licenses (license_key, duration_days, note)
-- VALUES ('ZT-VIP-30DAYS', 30, 'Key VIP 1 Tháng');
