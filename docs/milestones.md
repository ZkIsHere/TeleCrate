# Milestones TeleCrate (cập nhật 2026-09-15)

- **M0 — Bootstrap: `implemented-and-tested`**. Repo private `ZkIsHere/TeleCrate`, CI self-hosted runner `ci-cd` xanh
  (fmt/clippy/build/test/package-validate). Rust skeleton + migrations v1 + systemd unit + config mẫu.
- **M1 — Capability spike Telegram: `partial` → đóng phần Bot API HTTP**. Changeset 1 (trait + skeleton + mock tests) và 2
  (`BotApiHttpTransport` thật + live probe 8 KiB pass trên user chat và basic group 2026-09-15) đã xong,
  CI có job `live-telegram` riêng. Còn `blocked` có lý do: kiểm tra đặc thù channel/supergroup
  (nâng `-100...` bất khả thi ở môi trường này), locator refresh, FLOOD_WAIT thực tế — không chặn M2.
- **M2 — Vertical slice durable PUT/GET (single-part): `implemented-and-tested` (cập nhật 2026-09-16)**.
  Breakdown: 2.1 (keys + SigV4 + bucket CRUD) → 2.2 (flow durable + worker tối giản) → 2.3 (multi-chunk + worker đủ)
  → 2.4 (mã hóa on/AEAD) → 2.5 (crash injection + AWS CLI + đóng M2).
- **2.1: `implemented-and-tested` (2026-09-16)** — config keys + region, SigV4 verify (vector AWS get-vanilla +
  roundtrip/tamper/skew), bucket CRUD + GetBucketLocation + error XML/request-id, integration HTTP ký thật.
- **2.2: `implemented-and-tested` (2026-09-16)** — PUT/GET/HEAD/DELETE durable single-chunk + ETag MD5,
  ListObjectsV2 + DeleteObjects (≤100), Range đơn, worker lease/backoff + GC spool.
  Live e2e pass trên group thật: PUT → GET (spool) → worker remote → GET (Telegram, byte-identical) → DELETE.
  Sửa 2 lỗi thật: ETag thiếu quote đóng; reqwest blocking cấm dựng/gọi trong async (transport build 1 lần ở
  startup + `spawn_blocking` cho download/delete trong handler). Tiếp theo: 2.3 multi-chunk.
- **2.3: `implemented-and-tested` (2026-09-16)** — PUT split multi-chunk (`chunk_size_bytes`, mặc định 8 MiB,
  giới hạn object 128 MiB), GET/Range ráp nhiều chunk, worker reclaim lease hết hạn + concurrency N luồng
  (`worker_concurrency`, mặc định 2), `busy_timeout=5000` cho multi-connection.
  Live e2e multi-chunk pass (2.5 MiB → 3 messages thật → GC → GET remote → DELETE).
  Sửa 2 lỗi thật: cursor đọc mở + ghi cùng connection gây lock (thu gọn Vec trước khi ghi; thêm regression test
  pragma); claim lease khớp cả `uploading` còn hạn gây double-upload (siết điều kiện reclaim, test 4 workers
  25/25 pass).
- **2.4: `implemented-and-tested` (2026-09-16)** — mã hóa ChaCha20-Poly1305/chunk (nonce duy nhất, AAD=version/idx),
  spool ciphertext khi bật, ETag MD5 plaintext, key file 32 bytes + key_id/chunk, rotation giữ key cũ,
  toggle chỉ áp dụng ghi mới. Fail đóng khi sai key/tamper/reorder. Live e2e mã hóa pass (1.5 MiB → 2 chunks thật).
- **2.5: `implemented-and-tested` (2026-09-16)** — Startup spool reconciliation (`reconcile_spool` dọn `.tmp` + `.chunk` mồ côi),
  integration test suite `tests/crash_injection.rs` kiểm chứng 6 ranh giới bền vững (interrupted tmp write, uncommitted chunk,
  client retry idempotency, accepted-local read fallback & worker resume, worker crash lease reclaim, remote commit before GC),
- **M3 — Multipart, copy, Range, conditional, ETag, versioning, metadata/tags: `implemented-and-tested` (cập nhật 2026-09-16)**.
  Breakdown: 3.1 (Migration 0002 & Schema) → 3.2 (Multipart Upload API) → 3.3 (CopyObject & Metadata) → 3.4 (Conditional & Range) → 3.5 (Versioning & Delete Markers) → 3.6 (Worker Extensions & Crash Injection Suite).
- **3.1: `implemented-and-tested` (2026-09-16)** — Schema Migration 0002 (`multipart_uploads`, `multipart_parts`, metadata JSON) & DAL.
- **3.2: `implemented-and-tested` (2026-09-16)** — Full S3 Multipart Upload API (CreateMultipartUpload, UploadPart, ListParts, CompleteMultipartUpload, AbortMultipartUpload, ListMultipartUploads).
- **3.3: `implemented-and-tested` (2026-09-16)** — CopyObject zero-copy spool reference, x-amz-metadata-directive (COPY/REPLACE), system headers & user metadata persistence.
- **3.4: `implemented-and-tested` (2026-09-16)** — HTTP Conditional Headers (If-Match, If-None-Match 304/412, If-Modified-Since, If-Unmodified-Since), If-Range, 206 Partial Content, 416 Range Not Satisfiable.
- **3.5: `implemented-and-tested` (2026-09-16)** — Bucket Versioning (Enabled/Suspended), Delete Markers, ListObjectVersions, versioned GET/HEAD/DELETE (`?versionId=...`).
- **3.6: `implemented-and-tested` (2026-09-16)** — Spool reconciliation extension for orphaned multipart parts & 10 crash point boundaries in `tests/crash_injection.rs`. Chính thức đóng M3. TIẾP THEO: M4 (Auth, Presigned URLs, Policies, CORS, SSE).
- **M4 — Auth hoàn chỉnh (presigned/POST policy), policies/ACL/BPA/CORS, SSE hành vi đúng, Object Lock gateway**.
- **M5 — GC, recovery bundle, doctor/verify/scrub, backup/restore index**.
- **M6 — CLI + dashboard đầy đủ, packaging Linux, docs install/admin/recovery**.
- **M7 — Conformance (AWS CLI, rclone, SDK), fixture 25k objects/62 GB mô phỏng, live Telegram nhỏ có kiểm soát, gap report advanced**.

Không dừng ở demo upload/download rồi tuyên bố xong. Mỗi milestone chỉ sang tiếp khi required checks của SHA đó xanh.
