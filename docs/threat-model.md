# Threat model TeleCrate (ngắn)

## Tài sản

- Nội dung object, metadata/tags, S3 secret (để kiểm HMAC), admin credential, bot token, content encryption key (nếu bật), DB index, spool.

## Kẻ tấn công & biên

| Kẻ tấn công | Khả năng | Giảm thiểu |
|---|---|---|
| Network attacker | Nghe/gửi request S3/admin | TLS (reverse proxy, tài liệu hóa); SigV4 + clock skew check; admin session + CSRF + rate-limit login |
| Client có key hạn chế | Vượt prefix/action | Bucket policy + deny precedence; Block Public Access mặc định; không anonymous read mặc định |
| Kẻ đọc ổ đĩa local | Đọc spool/DB | User riêng + quyền chặt (0700/0600); khi encryption bật: spool mã hóa, key ngoài Telegram; khi tắt: công bố rõ plaintext tại nơi lưu |
| Kẻ đọc Telegram channel | Đọc blob/message | Không lộ object key trong tên/caption; khi encryption bật: blob là ciphertext AEAD; key không lên Telegram cùng dữ liệu |
| Kẻ ghi log/export | Lấy secret qua log | Không log bot token/S3 secret/presigned query/key; export log có redaction + retention |
| Admin tò mò / xóa ngoài gateway | Đọc/xóa ổ đĩa hoặc Telegram | Công bố rõ: không WORM chống admin ổ đĩa/Telegram xóa ngoài gateway; retention/legal hold chỉ có hiệu lực trong gateway |
| SSRF qua webhook/endpoint cấu hình | Gọi nội bộ | Allowlist + validate URL, timeout, không theo redirect nội bộ |
| Path traversal qua object key | Ghi ra ngoài spool | Không dùng key làm path; map qua hash; validate UTF-8/độ dài |

## Không cam kết

- Không quảng cáo compliance tương đương AWS (Object Lock chỉ ở mức gateway).
- KMS cần provider thật; không gắn nhãn KMS cho khóa local.
- Backup DB đầy đủ có secrets phải mã hóa riêng hoặc loại secrets ra; recovery index khi encryption tắt không chứa secrets và không yêu cầu content key.
