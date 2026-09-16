# Compatibility matrix S3 — TeleCrate

> Trạng thái: `implemented-and-tested` | `implemented-unverified` | `partial` | `blocked` | `unsupported`.
> Semantics theo S3 API Reference chính thức (kiểm tra 2026-09-15). Không suy đoán từ tên API.
> M0 (bootstrap): toàn bộ S3 ở `unsupported` trừ health/config — đúng quy tắc "không mock 200".
> Cập nhật 2026-09-16 (sau M6.5): Milestone M6 đã hoàn tất (`implemented-and-tested`) bao gồm Admin REST API & Session Cookie/CSRF Authentication, Embedded Web Dashboard UI, CLI Client API integration (tránh SQLite lock), Systemd Native Hardening Service (`telecrate.service`), Linux Packaging (.deb, .rpm, tarball) và bộ tài liệu vận hành/khôi phục thảm họa đầy đủ.

## Telegram transport (ngoài S3 — nền tảng TeleCrate)

| Capability | Trạng thái | Bằng chứng |
|---|---|---|
| Bot API HTTP upload document binary | implemented-and-tested | live probe 8 KiB 2026-09-15: `upload_ok=true` |
| Download byte-identical qua `getFile` | implemented-and-tested | live probe: `download_identical=true` |
| Delete message | implemented-and-tested | live probe: `delete_ok=true` (user chat + basic group) |
| Refresh locator hết hạn / 429-FLOOD_WAIT thực tế | blocked | mới unit-test mapping; cần chạy dài ngày |
| Channel `-100...` admin tối thiểu / `channels.deleteMessages` | blocked | ràng buộc nền tảng: nâng supergroup bất khả thi ở môi trường này — không chặn M2/M3 |
| Local Bot API / MTProto bot | unsupported | chờ capability test |

## Bucket (cập nhật 2026-09-16 — M4.6)

| Operation | Trạng thái | Ghi chú |
|---|---|---|
| CreateBucket (LocationConstraint khớp region) / HeadBucket / DeleteBucket (409 khi không rỗng) / ListBuckets | implemented-and-tested | SigV4 header-auth + unit/integration tests qua HTTP thật |
| GetBucketLocation | implemented-and-tested | integration test |
| Bucket naming rules | implemented-and-tested | 3-63 ký tự, lowercase/số/`.-` |
| Bucket Versioning (`PUT/GET /{bucket}?versioning`) | implemented-and-tested | Hỗ trợ `Enabled` và `Suspended` |
| Bucket CORS (`PUT/GET/DELETE /{bucket}?cors` & OPTIONS preflight) | implemented-and-tested | Dynamic header reflection & origin/method/header matching |
| Bucket policy & BPA (`PUT/GET/DELETE /{bucket}?policy`, `?publicAccessBlock`) | implemented-and-tested | Evaluator Deny precedence, BPA block public policy/access |
| Bucket Object Lock Config (`PUT/GET /{bucket}?object-lock`) | implemented-and-tested | Enable Object Lock WORM configuration |

## Object (cập nhật 2026-09-16 — M4.6)

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
| SSE-S3 / SSE-C Encryption Validation | implemented-and-tested | Validates `AES256`, 256-bit Base64 customer key & Base64 MD5 checksum |
| Object Lock Retention & Legal Hold (`?retention`, `?legal-hold`) | implemented-and-tested | GOVERNANCE/COMPLIANCE WORM retention, bypass header, Legal Hold guard |

## Listing / Multipart / HTTP / Auth (M4.6)

| Operation | Trạng thái | Ghi chú |
|---|---|---|
| ListObjectsV2 (prefix/delimiter/max-keys/continuation/encoding-type=url) | implemented-and-tested | integration test |
| ListObjectVersions (`GET /{bucket}?versions`) | implemented-and-tested | Đánh dấu `IsLatest` chính xác theo version mới nhất |
| S3 Multipart Upload API (Create, UploadPart, ListParts, Complete, Abort, ListUploads) | implemented-and-tested | 6 endpoints tương thích chuẩn XML S3, multipart ETag |
| SigV4 header auth / Unsigned payload | implemented-and-tested | integration tests qua HTTP thật |
| Presigned URL / POST Policy Upload | implemented-and-tested | Query parameter authentication & HTML Form POST upload validation |
| Multi-Access Keys / Clock Skew | implemented-and-tested | SQLite `access_keys` active check & ±15m timestamp window |

## Maintenance, GC & Disaster Recovery (M5.6)

| Capability | Trạng thái | Bằng chứng |
|---|---|---|
| Database Online Backup & AEAD Restore | implemented-and-tested | `telecrate db backup/restore`, SQLite online backup API + ChaCha20-Poly1305 encryption & `PRAGMA integrity_check` validation |
| Physical Garbage Collection Engine | implemented-and-tested | `telecrate gc`, cleans unreferenced spool chunks & deletes remote Telegram messages with Object Lock WORM retention guard |
| Standalone Recovery Bundle Export/Import | implemented-and-tested | `telecrate recovery export/import`, JSON format with AEAD passphrase encryption for DB-less disaster recovery |
| Integrity Doctor, Verify & Scrub Engine | implemented-and-tested | `telecrate doctor`, `telecrate verify`, `telecrate scrub`, validates local spool SHA256 & remote Telegram message presence |

## Crash Recovery & Durability (M3.6)

| Capability | Trạng thái | Bằng chứng |
|---|---|---|
| Startup Spool Reconciliation (`reconcile_spool`) | implemented-and-tested | Dọn `.tmp` và `.chunk` mồ côi (cả single-part và multipart) |
| Integration Crash Injection Suite (10 ranh giới) | implemented-and-tested | [`tests/crash_injection.rs`](file:///d:/PersonalProject/TeleCrate/tests/crash_injection.rs) 10/10 pass |

## Nâng cao (website, access points, batch, IAM/STS/SNS/SQS/Lambda, Glacier)

unsupported ở M0-M5; mỗi mục sẽ có gap report bằng chứng trước khi đánh `unsupported` vĩnh viễn.
