# Compatibility matrix S3 — TeleCrate

> Trạng thái: `implemented-and-tested` | `implemented-unverified` | `partial` | `blocked` | `unsupported`.
> Semantics theo S3 API Reference chính thức (kiểm tra 2026-09-15). Không suy đoán từ tên API.
> M0 (bootstrap, commit này): toàn bộ ở `unsupported` trừ health/config — đúng quy tắc "không mock 200".

## Bucket

| Operation | Trạng thái | Ghi chú |
|---|---|---|
| CreateBucket / DeleteBucket / HeadBucket / ListBuckets | unsupported | M2 |
| GetBucketLocation / naming rules / từ chối xóa bucket không rỗng | unsupported | M2 |
| Bucket config (versioning, policy, CORS, BPA) | unsupported | M3-M4 |

## Object (M2-M3)

| Operation | Trạng thái |
|---|---|
| PutObject / GetObject / HeadObject / DeleteObject / DeleteObjects | unsupported |
| CopyObject / metadata / Content-Type-Disposition-Encoding / tags | unsupported |
| Object rỗng / Unicode & ký tự đặc biệt / prefix-folder | unsupported |

## Listing / Multipart / HTTP / Auth (M2-M4)

ListObjects v1/v2, ListObjectVersions, pagination + concurrent change: unsupported.
Multipart toàn bộ (initiate/upload/list/complete/abort/list-uploads, part-copy, checksum, cleanup): unsupported.
Range, conditional, ETag theo loại upload, request ID, lỗi chuẩn: unsupported.
SigV4 header/query, presigned, POST policy, streaming checksum: unsupported.
Path-style trước; virtual-hosted-style khi có DNS/TLS: unsupported (tài liệu hóa).

## Versioning / Lifecycle / Access / Encryption / Lock / Events (M3-M6)

Tất cả unsupported ở M0. Nguyên tắc đã chốt:
- KMS cần provider thật; SSE tuân thủ mục 3 prompt (áp dụng đúng hoặc từ chối rõ, không âm thầm ghi plaintext).
- Transition chỉ tới tier có thật; không giả Glacier.
- Object Lock: gateway-enforced, không WORM chống admin; lifecycle/GC tôn trọng retention.
- Events/audit/inventory/replication: bền vững + retry + dedup; tách `object-created (accepted-local)` vs `telegram-upload-completed`; at-least-once công bố rõ.

## Nâng cao (website, access points, batch, Express/directory buckets, Tables/Vectors, IAM/STS/SNS/SQS/Lambda, Glacier)

unsupported ở M0; mỗi mục sẽ có gap report bằng chứng + phương án (native / tích hợp ngoài / giới hạn nền tảng) trước khi đánh `unsupported` vĩnh viễn. Không giả nhận tương thích chỉ vì endpoint S3 chạy được.
