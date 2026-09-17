# ADR 0004 — Auto-region SigV4, bỏ setting region và telegram_base_url

Ngày: 2026-09-17. Trạng thái: chấp nhận.

## Bối cảnh

- SigV4 verify có tham số `expected_region` so với region trong credential scope; config mặc định `"*"`
  (wildcard) nhưng dashboard vẫn hiển thị ô Region gây nhầm lẫn (người dùng tưởng phải khớp).
- AWS CLI/SDK mặc định ký `us-east-1` (và `aws-global` cho một số lệnh); từ chối region lạ chỉ gây ma sát,
  không thêm bảo mật trên single instance path-style.
- `telegram_base_url` cấu hình nhưng thực tế luôn là hosted URL; Local Bot API chưa có — setting thừa.

## Quyết định

1. **Auto-region**: `verify`/`verify_presigned`/`verify_post_policy` bỏ tham số region, luôn dùng region
   trong credential scope (chỉ kiểm tra service `s3` + region không rỗng). Mọi client region đều pass.
2. **Xóa `region` khỏi Config**: nhãn bucket lấy từ `LocationConstraint` (bất kỳ giá trị nào cũng nhận),
   không constraint → `DEFAULT_REGION = "us-east-1"`. `GetBucketLocation` trả nhãn đã lưu.
   File config cũ còn dòng `region` vẫn parse được (serde bỏ qua field lạ).
3. **Xóa `telegram_base_url` khỏi Config**: hằng `TELEGRAM_API_BASE`. Local Bot API sẽ là transport
   riêng khi có capability test, không phải URL cấu hình.
4. Dashboard bỏ 2 ô nhập tương ứng; modal tạo bucket không hỏi region.

## Hệ quả

- Test `auth_failures_map_to_s3_errors` cập nhật: constraint lạ → 200 + lưu nhãn (thay vì 400).
- Unit test SigV4 bổ sung case ký `eu-west-1` vẫn verify pass.
