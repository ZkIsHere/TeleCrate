# Compatibility matrix S3 — TeleCrate

> Trạng thái: `implemented-and-tested` | `implemented-unverified` | `partial` | `blocked` | `unsupported`.
> Semantics theo S3 API Reference chính thức (kiểm tra 2026-09-15). Không suy đoán từ tên API.
> M0 (bootstrap): toàn bộ S3 ở `unsupported` trừ health/config — đúng quy tắc "không mock 200".
> Cập nhật 2026-09-16 (sau M3.6): Milestone M3 đã hoàn tất (`implemented-and-tested`) bao gồm Multipart Upload API (6 endpoints), CopyObject & Metadata, Conditional Requests & Advanced Range (304/412/206/416), Bucket/Object Versioning & Delete Markers, Spool Reconciliation & 10 ranh giới Crash Injection.

## Telegram transport (ngoài S3 — nền tảng TeleCrate)

| Capability | Trạng thái | Bằng chứng |
|---|---|---|
| Bot API HTTP upload document binary | implemented-and-tested | live probe 8 KiB 2026-09-15: `upload_ok=true` |
| Download byte-identical qua `getFile` | implemented-and-tested | live probe: `download_identical=true` |
| Delete message | implemented-and-tested | live probe: `delete_ok=true` (user chat + basic group) |
| Refresh locator hết hạn / 429-FLOOD_WAIT thực tế | blocked | mới unit-test mapping; cần chạy dài ngày |
| Channel `-100...` admin tối thiểu / `channels.deleteMessages` | blocked | ràng buộc nền tảng: nâng supergroup bất khả thi ở môi trường này — không chặn M2/M3 |
| Local Bot API / MTProto bot | unsupported | chờ capability test |

## Bucket (cập nhật 2026-09-16 — M3.5)

| Operation | Trạng thái | Ghi chú |
|---|---|---|
| CreateBucket (LocationConstraint khớp region) / HeadBucket / DeleteBucket (409 khi không rỗng) / ListBuckets | implemented-and-tested | SigV4 header-auth + unit/integration tests qua HTTP thật |
| GetBucketLocation | implemented-and-tested | integration test |
| Bucket naming rules | implemented-and-tested | 3-63 ký tự, lowercase/số/`.-` |
| Bucket Versioning (`PUT/GET /{bucket}?versioning`) | implemented-and-tested | Hỗ trợ `Enabled` và `Suspended` |
| Bucket policy, CORS, BPA | unsupported | M4 |

## Object (cập nhật 2026-09-16 — M3.5)

| Operation | Trạng thái | Ghi chú |
|---|---|---|
| PutObject / GetObject / HeadObject / DeleteObject | implemented-and-tested | Plaintext & ChaCha20-Poly1305, spool ciphertext, ETag MD5 plaintext; integration test |
| CopyObject (`x-amz-copy-source`, `x-amz-metadata-directive`) | implemented-and-tested | Zero-copy spool reference |
| Metadata (User `x-amz-meta-*` & System headers) | implemented-and-tested | Content-Type, Content-Disposition, Content-Encoding, Cache-Control, Expires |
| Conditional Requests (`If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, `If-Range`) | implemented-and-tested | Trả đúng 304 `NotModified`, 412 `PreconditionFailed`, 206 `PartialContent` |
| Object Versioning & Delete Markers | implemented-and-tested | Versioned GET/HEAD/DELETE (`?versionId=...`), ListObjectVersions (`GET /{bucket}?versions`) |
| Key rotation (đổi id, giữ key cũ) | implemented-and-tested | ghi mới dùng key mới, cũ vẫn đọc (integration) |
| Wrong key / tamper / reorder / truncate | fail-đóng-đã-test | 500 `cannot decrypt`, không lộ key; unit + integration |
| DeleteObjects (≤100 keys, hỗ trợ VersionId & Delete Markers) | implemented-and-tested | integration test |
| Range request (`bytes=a-b/a-/-suffix`, 206/416, If-Range) | implemented-and-tested | Cắt range chính xác across chunk boundaries; 416 `RangeNotSatisfiable` |

## Listing / Multipart / HTTP / Auth (M3.2)

| Operation | Trạng thái | Ghi chú |
|---|---|---|
| ListObjectsV2 (prefix/delimiter/max-keys/continuation/encoding-type=url) | implemented-and-tested | integration test |
| ListObjectVersions (`GET /{bucket}?versions`) | implemented-and-tested | Đánh dấu `IsLatest` chính xác theo version mới nhất |
| S3 Multipart Upload API (Create, UploadPart, ListParts, Complete, Abort, ListUploads) | implemented-and-tested | 6 endpoints tương thích chuẩn XML S3, multipart ETag |
| SigV4 header auth / Unsigned payload | implemented-and-tested | integration tests qua HTTP thật |
| Presigned URL / POST Policy | unsupported | M4 |

## Crash Recovery & Durability (M3.6)

| Capability | Trạng thái | Bằng chứng |
|---|---|---|
| Startup Spool Reconciliation (`reconcile_spool`) | implemented-and-tested | Dọn `.tmp` và `.chunk` mồ côi (cả single-part và multipart) |
| Integration Crash Injection Suite (10 ranh giới) | implemented-and-tested | [`tests/crash_injection.rs`](file:///d:/PersonalProject/TeleCrate/tests/crash_injection.rs) 10/10 pass |

## Nâng cao (website, access points, batch, IAM/STS/SNS/SQS/Lambda, Glacier)

unsupported ở M0-M3; mỗi mục sẽ có gap report bằng chứng trước khi đánh `unsupported` vĩnh viễn.
