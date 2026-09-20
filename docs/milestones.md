# Milestones TeleCrate (cập nhật 2026-09-20)

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
- **M4 — Auth hoàn chỉnh (presigned/POST policy), policies/ACL/BPA/CORS, SSE hành vi đúng, Object Lock gateway: `implemented-and-tested` (cập nhật 2026-09-16)**.
  Breakdown: 4.1 (Migration 0003 & DB DAL) → 4.2 (Presigned URLs, POST Form Policy, Multi-Access Keys, Clock Skew) → 4.3 (CORS Engine, Bucket Policies, BPA) → 4.4 (SSE-S3 & SSE-C Cryptographic Validation) → 4.5 (Object Lock WORM Governance/Compliance & Legal Hold) → 4.6 (Full Suite Verification).
- **4.1: `implemented-and-tested` (2026-09-16)** — Schema Migration 0003 (`access_keys`, `bucket_cors`, `bucket_policies`, `bucket_bpa`, `bucket_object_lock`, `object_locks`) & DB DAL.
- **4.2: `implemented-and-tested` (2026-09-16)** — Presigned URLs (SigV4 query auth), POST Form Policy upload & condition evaluation (`content-length-range`, `eq`, `starts-with`), Multi-Access Keys authorization (`status='active'`), Clock Skew enforcement (±15m).
- **4.3: `implemented-and-tested` (2026-09-16)** — CORS Engine (XML config, OPTIONS preflight matching), Bucket Policy evaluator (Deny precedence, principal matching, action wildcarding), Block Public Access (BPA) enforcement & public policy rejection.
- **4.4: `implemented-and-tested` (2026-09-16)** — SSE-S3 (`AES256` default encryption headers) and SSE-C (256-bit Base64 customer key validation & Base64 MD5 checksum verification).
- **4.5: `implemented-and-tested` (2026-09-16)** — Object Lock WORM Gateway (`?object-lock`, `?retention`, `?legal-hold`), GOVERNANCE/COMPLIANCE mode retention enforcement, bypass header (`x-amz-bypass-governance-retention`), Legal Hold 403 AccessDenied guard.
- **4.6: `implemented-and-tested` (2026-09-16)** — Complete code quality and verification pass (cargo fmt, clippy -D warnings, full test suite pass). Chính thức đóng M4. TIẾP THEO: M5 (GC, recovery bundle, doctor/verify/scrub, backup/restore index).
- **M5 — GC, recovery bundle, doctor/verify/scrub, backup/restore index: `implemented-and-tested` (cập nhật 2026-09-16)**.
  Breakdown: 5.1 (Database Backup & Restore Engine) → 5.2 (Physical GC Engine) → 5.3 (Standalone Recovery Bundle) → 5.4 (Integrity Verification, Doctor & Scrubbing Engine) → 5.5 (Integration Test Suite & CLI Wiring) → 5.6 (Documentation & Quality Assurance).
- **5.1: `implemented-and-tested` (2026-09-16)** — SQLite online backup engine (`rusqlite::backup`), AEAD ChaCha20-Poly1305 database backup encryption, and safe database restore with `PRAGMA integrity_check` validation & automatic safety backups.
- **5.2: `implemented-and-tested` (2026-09-16)** — Physical Garbage Collection Engine (`telecrate gc`), local spool cleanup, orphan chunk removal, aborted/expired multipart cleanup, and remote Telegram message deletion respecting Object Lock WORM retention & legal holds.
- **5.3: `implemented-and-tested` (2026-09-16)** — Standalone Recovery Bundle (`telecrate recovery export/import`), JSON format export/import with optional AEAD passphrase encryption for offline disaster recovery without DB access.
- **5.4: `implemented-and-tested` (2026-09-16)** — Integrity Verification, Doctor & Scrubbing Engine (`telecrate doctor`, `telecrate verify`, `telecrate scrub`), local spool hash validation, remote Telegram presence check, and automatic error detection/fixing.
- **5.5: `implemented-and-tested` (2026-09-16)** — Integration test suites (`tests/backup_restore_api.rs`, `tests/gc_api.rs`, `tests/doctor_recovery_api.rs`) and CLI subcommands wired in `src/main.rs`.
- **5.6: `implemented-and-tested` (2026-09-16)** — Complete code quality and verification pass (`cargo fmt`, `clippy -D warnings`, full test suite pass). Chính thức đóng M5. TIẾP THEO: M6 (CLI + dashboard đầy đủ, packaging Linux, docs install/admin/recovery).
- **M6 — CLI + dashboard đầy đủ, packaging Linux, docs install/admin/recovery: `implemented-and-tested` (cập nhật 2026-09-16)**.
  Breakdown: 6.1 (Admin REST API & Embedded Web Dashboard) → 6.2 (Complete CLI & Socket/API Client) → 6.3 (Linux Packaging & Systemd Hardening) → 6.4 (Operational Documentation) → 6.5 (Integration Testing & Verification).
- **6.1: `implemented-and-tested` (2026-09-16)** — Admin REST API (`src/admin.rs`), Session Cookie protection, CSRF token validation, secret redaction engine, and embedded Web Dashboard HTML/CSS/JS frontend (`src/dashboard/`).
- **6.2: `implemented-and-tested` (2026-09-16)** — CLI client module (`src/cli.rs`) enforcing architectural rule: CLI routes operations via Admin REST API when daemon is running to avoid SQLite lock conflicts.
- **6.3: `implemented-and-tested` (2026-09-16)** — Systemd service unit (`packaging/telecrate.service`) with Linux native security hardening, sample config (`packaging/telecrate.sample.toml`), and packaging scripts (`build-deb.sh`, `build-rpm.sh`).
- **6.4: `implemented-and-tested` (2026-09-16)** — Operational guides: installation (`docs/install.md`), administration (`docs/admin.md`), and disaster recovery (`docs/disaster-recovery.md`).
- **6.5: `implemented-and-tested` (2026-09-16)** — Complete code quality and verification pass (`cargo fmt`, `clippy -D warnings`, full test suite pass including `tests/admin_api.rs`). Chính thức đóng M6. TIẾP THEO: M7 (Conformance AWS CLI/rclone, fixture 25k objects/62 GB mô phỏng, live Telegram nhỏ có kiểm soát, gap report advanced).
- **M7 — Conformance (AWS CLI, rclone, SDK), fixture 25k objects/62 GB mô phỏng, live Telegram nhỏ có kiểm soát, gap report advanced: `implemented-and-tested` (cập nhật 2026-09-16)**.
  Breakdown: 7.1 (S3 Tool Conformance Suite) → 7.2 (High-Density Scale Simulation Fixture 25k Objects / 62 GB) → 7.3 (Controlled Live Telegram Production Verification) → 7.4 (Advanced Features Gap Report) → 7.5 (Final Quality & Project Sign-off).
- **7.1: `implemented-and-tested` (2026-09-16, CI-gated 2026-09-17)** — S3 Tool Conformance Suite (`tests/conformance_api.rs` & `tests/conformance.sh`), validating AWS CLI v2, rclone, and MinIO `mc` compatibility across lifecycle, pagination, multipart, presigned URLs, WORM locks, and delete markers. Chạy thật trong CI: job `awscli-conformance` (AWS CLI thật, STRICT) + job `website` (`tests/website.sh`: assets, auth/CSRF/rate-limit, admin API, audit).
- **7.2: `implemented-and-tested` (2026-09-16)** — High-Density Scale Simulation Fixture (`tests/scale_sim.rs`), generating 25,000 simulated object metadata records (~62 GB virtual payload), verifying sub-20ms query latency for ListObjectsV2 (5.06ms), ListObjectVersions (2.28ms), active_spool_paths (3.67ms), and Batch Deletion (14.86ms).
- **7.3: `implemented-and-tested` (2026-09-16)** — Controlled Live Telegram Production Verification guidelines and automated live test suite integration.
- **7.4: `implemented-and-tested` (2026-09-16)** — Advanced Features Gap Report (`docs/gap-report.md`) documenting unsupported enterprise S3 features (S3 Select, Replication, Lifecycle policies, Glacier, IAM/STS/SNS/SQS, Event Notifications) with rationale and fallback recommendations.
- **7.5: `implemented-and-tested` (2026-09-16)** — Final Code Quality & Project Completion Pass (`cargo fmt`, `clippy -D warnings`, full test suite pass). Chính thức hoàn thành Milestone M7 và hoàn thiện toàn bộ dự án TeleCrate v0.1.0!
- **Postgres backend (ADR 0005, 2026-09-18): `partial`** — Chọn backend `sqlite`/`postgres` qua TOML/CLI/dashboard + validate fail-closed + redaction `database_url`; schema DDL Postgres (`migrations/postgres/0001_0004_schema.sql`, `telecrate db pg-schema`) tương đương SQLite 0001→0004 có test parity. Runtime query DAL vẫn SQLite-only nên `serve/init/doctor` từ chối `postgres` rõ ràng (`blocked`), cấm fallback lén.
- **v0.3.0 (2026-09-18): `implemented-and-tested`** — Cấu hình vị trí spool (dashboard fieldset Lưu trữ + wizard `install.sh` mục 6 + `TELECRATE_SPOOL_DIR`); Admin API batch nguyên tử (`updates`) cho đổi backend; sửa lỗi parse tag release JSON 1 dòng + retry curl + pin `TELECRATE_VERSION`. Không migration SQLite mới; nâng cấp 0.2.0→0.3.0 chỉ thay binary.
- **TLS native (phát hành v0.3.1, `implemented-and-tested`)** — Serve HTTPS mặc định, chưa có cert/key thì tự sinh self-signed lúc khởi động; PEM tay + fail-closed; tự sinh ECDSA + fingerprint SHA-256 cho PBS (`POST /admin/api/tls/generate`, key 0600); fieldset TLS/HTTPS + trạng thái xem bất cứ lúc nào; tab **Kết nối** (endpoint/port/keys/preset PBS/AWS CLI/rclone + nút chép). E2E HTTPS 200 + từ chối plain-HTTP đã kiểm chứng.
- **v0.3.1 (2026-09-20): `implemented-and-tested`** — Phát hành DAL async dual-backend SQLite/Postgres + TLS native; sửa worker lồng runtime (tách `process_one_job_sync`, live-e2e xanh lại), sửa HTTPS-vs-HTTP ở smoke test (`tls_enabled = false` tường minh), CLI hỗ trợ cả HTTP/HTTPS theo `tls_enabled`. Không migration SQLite mới; nâng cấp 0.3.0→0.3.1 chỉ thay binary (lưu ý daemon mặc định HTTPS).
- **v0.3.2 (2026-09-20): `implemented-and-tested`** — Sửa chặn đổi backend Postgres: quote cột `"offset"` (từ khóa reservé Postgres) trong DDL `migrations/postgres/0001_init.sql` + query DAL dùng chung. Không migration SQLite mới; nâng cấp 0.3.1→0.3.2 chỉ thay binary.

Không dừng ở demo upload/download rồi tuyên bố xong. Mỗi milestone chỉ sang tiếp khi required checks của SHA đó xanh.

