# TeleCrate v0.3.3-beta.8 — Release Notes (pre-release)

Phiên bản **beta** dọn schema DB (migration 0005) + 3 bug fix GC/jobs/delete.
**Bản này CÓ migration — đọc kỹ mục nâng cấp trước khi restart daemon.**

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.8

### 1. Migration 0005: dọn bảng/cột chết (audit toàn diện schema)
* Xóa bảng chết `kv`, `recovery_checkpoints` (không code path nào dùng).
* Xóa cột chết: `chunks.nonce`/`offset`, `buckets.encryption_override`,
  `upload_jobs.generation`, `multipart_parts.remote_locator_json`/`state`.
* Thêm index `upload_jobs(state, next_attempt)` cho worker claim poll.

### 2. Ba bug fix đi kèm audit
* GC spool trước đây tìm chunk `telegram-committed` (giá trị không bao giờ được
  set) nên rò rỉ spool khi crash — giờ quét chunk `remote` còn spool.
* Dashboard "Hoàn tất" luôn 0 vì đếm state `completed` không tồn tại — giờ đếm
  `done` thật.
* Xóa bucket còn multipart upload dở dang nổ lỗi FK 500 — giờ chặn 409
  `BucketNotEmpty` đúng S3.

### Nâng cấp từ beta.7 — patches tự áp dụng đúng không?
**Có.** Daemon tự chạy `apply_all_migrations` mỗi lần khởi động: phát hiện DB
đang ở version 4 → apply đúng 0005 → lên version 5. Không cần chạy lệnh migrate
tay. Kiểm chứng sau restart:
```bash
telecrate status   # kỳ vọng: migrations version=5, integrity ok
```
(Muốn migrate tay có backup file tự động: `telecrate migrations apply`.)
An toàn dữ liệu: 0005 chỉ DROP bảng/cột đã chứng minh không dùng (toàn NULL/
default) + CREATE INDEX — không động tới dữ liệu objects/chunks/jobs. Tuy vậy
migration là forward-only (không downgrade về beta.7 sau khi lên 5, vì binary
cũ query cột đã xóa), nên **backup trước khi nâng cấp**:
```bash
sudo systemctl stop telecrate
telecrate db backup --output /var/backups/telecrate-pre-beta8.db
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.3-beta.8/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/
sudo systemctl start telecrate
```
(Postgres: `pg_dump` thay cho `db backup`; migration Postgres tương đương chạy
tự động như SQLite.)

---

# TeleCrate v0.3.3-beta.7 — Release Notes (pre-release)

Phiên bản **beta** migrate toàn bộ DB layer sang SeaORM + SeaQuery (ADR 0006):
entities là single source of truth cho cấu trúc 15 bảng, test parity schema tự
động đối chiếu với DDL thật cả hai backend. API S3/dashboard/worker giữ nguyên.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.7

### 1. SeaORM entities + test parity (Phase 1)
* `src/db/entities/` cho 15 bảng (viết tay, build offline), số nguyên → `i64`,
  datetime TEXT → `String` (zero behavior change).
* `tests/entity_schema_parity.rs`: sinh `CREATE TABLE` từ entities rồi đối chiếu
  tập cột + nhóm kiểu với SQLite sau migrate và text DDL Postgres — lệch là fail CI.
* `rusqlite 0.31 → 0.32` (chung native lib với sqlx 0.8).

### 2. Migrate CRUD → đường nóng → worker → gc/doctor/recovery (Phase 2–4)
* Buckets/keys/policy/cors/bpa/lock, objects/chunks (put/copy/delete + txn
  SeaORM), multipart, jobs, worker lease (claim nguyên tử giữ nguyên), GC guard
  WORM, doctor/scrub, recovery export/import.
* Chỉ còn SQL text cho intrinsic backend (`rowid`/`ctid`, PRAGMA,
  `VACUUM INTO`, `datetime`/`to_char`) và aggregate tương quan.
* Xóa toàn bộ shim cũ (`Val`/`Row`/`Tx`/`fetch`/`exec`/`rebind`) và 3 handlers
  admin v1 chết. Sửa ké: metrics `SUM(size)` trên Postgres (trước đây luôn 0).

### Nâng cấp từ beta.6
Thay binary, giữ DB/spool (không migration mới):
```bash
sudo systemctl stop telecrate
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.3-beta.7/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/
sudo systemctl start telecrate
```

---

# TeleCrate v0.3.3-beta.6 — Release Notes (pre-release)

Phiên bản **beta** sửa loạt lỗi dashboard quản trị: bucket size luôn 0 B, biểu đồ
Tổng quan vẽ sai, access key ID trùng nhau, nhãn postgres "partial" đã lỗi thời,
nhật ký thiếu thao tác S3, và DB size sai khi dùng Postgres.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.6

### 1. Bucket size + DB size hiển thị đúng
* Bảng Buckets đọc đúng field `total_size_bytes` (trước đây đọc nhầm `total_bytes`
  nên luôn hiện 0 B).
* Thẻ DB size: SQLite đo file `index.db` như cũ; Postgres hỏi trực tiếp
  `pg_database_size(current_database())`. Nhãn thẻ tự hiện backend đang dùng
  (`DB size (sqlite)` / `DB size (postgres)`).

### 2. Biểu đồ Tổng quan vẽ đúng
* Task `metrics_sampler` (10s/điểm, giữ ~2.7 giờ) trước đây tồn tại nhưng không nơi
  nào spawn nên history luôn chỉ có 1 điểm → biểu đồ hiện 1 chấm đơn. Đã spawn
  trong `router()`.
* Sửa nhãn trục Y bị cắt (`0.666… B` hiện thành `66666 B`), 1 điểm vẽ đường ngang
  + chấm ở mép phải, thêm nhãn giờ trục X.

### 3. Access keys: ID duy nhất + lưu đầy đủ
* `crypto_random_bytes` không còn lặng lẽ trả buffer toàn 0 khi OS RNG lỗi
  (nguyên nhân gây trùng ID + ghi đè lẫn nhau qua `ON CONFLICT`); sinh ID có kiểm
  tra duy nhất trong DB.
* Lúc tạo key giờ persist thật `allowed_buckets`/`policy` (trước đây lặng lẽ bỏ).
* Sửa badge/nút Tạm dừng-Kích hoạt luôn sai do so sánh `status` phân biệt hoa thường
  (`Active` vs `active`); cột "last used" giờ cập nhật sau mỗi lần auth S3 thành công.

### 4. Nhật ký + nhãn postgres
* Audit thêm thao tác S3 phá hủy: tạo/xóa bucket, xóa 1 object, xóa nhiều objects
  (Put/Get không audit để khỏi flood ring-buffer).
* Dropdown DB backend: `postgres (runnable)` thay cho nhãn `partial` cũ.

### Nâng cấp từ beta.5
Thay binary, giữ DB/spool (không migration mới):
```bash
sudo systemctl stop telecrate
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.3-beta.6/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/
sudo systemctl start telecrate
```
Sau restart đợi vài phút để sampler đủ điểm vẽ biểu đồ đường.

---

# TeleCrate v0.3.3-beta.5 — Release Notes (pre-release)

Phiên bản **beta** sửa bước `s3 check`/tạo datastore của PBS: với endpoint path-style,
PBS gọi `HEAD /pbs/` (trailing slash) nhưng route `/:bucket` của TeleCrate không khớp
→ axum 404 (không log) → PBS báo bucket không tồn tại.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.5

### 1. Route `/:bucket/` + verify đúng path đã ký
* Thêm route `/:bucket/` mirror đủ 6 method bucket (GET/PUT/DELETE/HEAD/POST/OPTIONS).
* Các handler bucket verify theo `OriginalUri` (giữ nguyên trailing slash client đã ký)
  thay vì dựng lại `/{bucket}` — strip slash trước verify sẽ lệch chữ ký.
* Test hồi quy: `HEAD /bucket/`, `GET /bucket/`, `GET /bucket/?list-type=2` đều 200.

### Nâng cấp từ beta.4
Thay binary, giữ DB/spool (không migration mới):
```bash
sudo systemctl stop telecrate
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.3-beta.5/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/
sudo systemctl start telecrate
```
Rồi thử lại trên PBS: `proxmox-backup-manager s3 check telecrate pbs`
(kỳ vọng qua `head`, rồi tới `put/get/delete` probe `.s3-client-test`), sau đó tạo
datastore trên UI.

---

# TeleCrate v0.3.3-beta.4 — Release Notes (pre-release)

Phiên bản **beta** sửa bước `s3 check` của PBS: `HEAD /` (service root) bị 403
`SignatureDoesNotMatch` dù key đúng — axum dồn HEAD vào handler GET mà handler này
hardcode method `"GET"` khi verify, nên chữ ký HEAD luôn lệch.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.4

### 1. Handler HEAD / riêng (`head_root`)
* Route `/` thêm `.head(head_root)`: verify đúng method `"HEAD"`, trả 200 rỗng
  khi auth đúng (không liệt kê bucket như GET).
* Test hồi quy trong `tests/buckets_api.rs`: `HEAD /` ký HEAD phải 200.

### Nâng cấp từ beta.3
Thay binary, giữ DB/spool (không migration mới):
```bash
sudo systemctl stop telecrate
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.3-beta.4/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/
sudo systemctl start telecrate
```
Rồi thử lại trên PBS: `proxmox-backup-manager s3 check telecrate pbs`
(kỳ vọng qua `head object`, rồi tới `put/get/delete` probe `.s3-client-test`).

---

# TeleCrate v0.3.3-beta.3 — Release Notes (pre-release)

Phiên bản **beta** sửa bước ListBuckets với PBS: auth đã qua (400 hết) nhưng PBS báo
`failed to parse response body ... expected last modified timestamp` vì `CreationDate`
của TeleCrate dùng format DB (`YYYY-MM-DD HH:MM:SS`) trong khi parser PBS
(`iso8601::datetime`, strict) đòi ISO-8601.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.3

### 1. CreationDate ISO-8601 strict
* `ListAllMyBucketsResult` giờ trả `<CreationDate>YYYY-MM-DDTHH:MM:SS.000Z</CreationDate>`
  (đúng AWS spec, đúng parser PBS), thay vì format DB. Các `LastModified` khác trong
  XML (objects/parts/copy) vốn đã ISO-8601 nên giữ nguyên.
* Unit test `list_buckets_xml_shape` assert đúng shape mới.

### Nâng cấp từ beta.2
Thay binary, giữ DB/spool (không migration mới):
```bash
sudo systemctl stop telecrate
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.3-beta.3/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/
sudo systemctl start telecrate
```
Rồi thử lại trên PBS: `proxmox-backup-manager s3 endpoint list-buckets telecrate`
(kỳ vọng in ra bucket `pbs`), sau đó mở dropdown trên UI.

---

# TeleCrate v0.3.3-beta.2 — Release Notes (pre-release)

Phiên bản **beta** sửa tương thích PBS S3: `proxmox-backup-manager s3 endpoint
list-buckets` thất bại với `AuthorizationHeaderMalformed` (HTTP 400) dù Region và
key đã đúng.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.2

### 1. Parser Authorization header chịu cả 2 format dấu phẩy
* PBS S3 client gửi `Credential=...,SignedHeaders=...,Signature=...` (phẩy không
  space, theo source `proxmox-s3-client`), còn parser cũ chỉ tách bằng `", "`
  nên mọi request PBS rớt ngay khâu parse. Giờ tách theo `,` + trim, đúng cả 2
  format, kèm unit test mô phỏng header kiểu PBS (gồm `content-length` + `host`
  có port trong SignedHeaders).
* Thêm log `sigv4 auth failed` (chỉ mã lỗi + request-id, không secret/chữ ký) để
  lần sau chẩn đoán client lạ không cần đoán mù.

### Nâng cấp từ beta.1
Thay binary, giữ DB/spool (không migration mới):
```bash
sudo systemctl stop telecrate
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.3-beta.2/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/
sudo systemctl start telecrate
```
Rồi thử lại trên PBS: `proxmox-backup-manager s3 endpoint list-buckets telecrate`.

---

# TeleCrate v0.3.3-beta.1 — Release Notes (pre-release)

Phiên bản **beta** thử nghiệm cho đường Postgres: gồm fix `rebind_pg` (viết lại placeholder
`?` → `$1..$N`, mọi query có tham số trên Postgres trước đó đều lỗi syntax). Đánh dấu
**pre-release** trên GitHub nên không ảnh hưởng kênh stable (`install.sh` mặc định vẫn
lấy v0.3.2).

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.3-beta.1

### 1. Sửa toàn bộ query Postgres có tham số
* Tiếp sau fix quote cột `"offset"` (v0.3.2): `sqlx::query` không tự rebind `?` nên
  `INSERT INTO schema_version(version) VALUES (?)` và mọi query bind khác đều lỗi.
* Thêm `rebind_pg` (bỏ qua `?` trong string literal) dùng ở cả 4 nhánh Postgres,
  kèm unit test. Mục tiêu beta: verify `migrations apply` → `version=4` và pipeline
  PUT/GET/worker thật trên Postgres.

### Cài đặt bản beta (opt-in)
```bash
TELECRATE_VERSION=v0.3.3-beta.1 curl -fsSL https://raw.githubusercontent.com/ZkIsHere/TeleCrate/master/install.sh | bash
```
Hoặc thay binary thủ công từ assets release `v0.3.3-beta.1`. Không khuyến nghị cho dữ
liệu production cho đến khi có bản stable 0.3.3.

---

# TeleCrate v0.3.2 — Release Notes

Phiên bản **TeleCrate v0.3.2** sửa lỗi chặn đổi backend sang Postgres: `telecrate
migrations apply` thất bại với `syntax error at or near "offset"` vì `offset`
(cột bảng `chunks`) là từ khóa reservé của Postgres.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.2

### 1. Quote cột `offset` cho Postgres
* DDL Postgres (`migrations/postgres/0001_init.sql`) và các query DAL dùng chung
  (`put_object`, copy chunk, recovery export) giờ dùng `"offset"` — SQLite vẫn hiểu
  identifier có quote nên một bộ query chạy được cả hai backend.
* Migration Postgres 0001 chưa bao giờ apply thành công ở đâu (lỗi trong transaction,
  chưa ghi version) nên sửa tại chỗ an toàn, không cần migration mới.

---

## 🔄 Hướng dẫn Nâng cấp từ v0.3.1 lên v0.3.2

Không có migration SQLite mới (schema giữ nguyên) — nâng cấp nhị phân, giữ DB/spool:

```bash
# 1. Dừng service
sudo systemctl stop telecrate

# 2. Tải binary v0.3.2 mới nhất và ghi đè
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.2/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/

# 3. Khởi động lại service
sudo systemctl start telecrate

# 4. Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate
```

Đang ở flow đổi sang Postgres mà kẹt ở `migrations apply`: thay binary v0.3.2 rồi
chạy lại `telecrate migrations apply` (lần lỗi trước đã rollback sạch, chạy lại từ
version 0, kỳ vọng `migrations ok: version=4`).

---

# TeleCrate v0.3.1 — Release Notes

Phiên bản **TeleCrate v0.3.1** là bản vá phát hành TLS native + DAL async dual-backend
SQLite/Postgres, đồng thời sửa 3 lỗi thật làm đỏ CI sau v0.3.0: worker lồng runtime
(panic `Cannot drop a runtime...` → live-e2e timeout), daemon mặc định HTTPS trong khi
script test gọi HTTP, và CLI hardcode HTTP.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.1

### 1. DAL async dual-backend SQLite/Postgres + TLS native (phát hành chính thức)
* Toàn bộ DAL chuyển sang `telecrate::db::Db` async trên sqlx, hỗ trợ song song SQLite
  và Postgres (bind `?` một lần, tự rebind `$N`); DDL Postgres tương đương SQLite
  0001→0004 tại `migrations/postgres/`.
* Serve HTTPS mặc định (rustls/ring thuần Rust): chưa có cert/key thì tự sinh self-signed
  lúc khởi động, fingerprint SHA-256 cho client S3 bắt HTTPS; dashboard có fieldset
  TLS/HTTPS + tab **Kết nối** (preset PBS/AWS CLI/rclone).

### 2. Sửa worker lồng runtime gây timeout live-e2e
* `process_one_job` async gọi `transport.upload()` blocking bên trong `block_on`
  `current_thread` → panic và kẹt job ở `pending`. Tách `process_one_job_sync`:
  DB `block_on` từng bước ngắn, upload gọi **ngoài** mọi async context.
* Live Telegram e2e xanh trở lại (PUT → GET spool → worker remote → GET Telegram → DELETE).

### 3. Sửa HTTPS-vs-HTTP làm đỏ CI website/conformance
* `tests/website.sh` và job `awscli-conformance` trong CI tạo config thiếu `tls_enabled`
  nên rơi vào default `true` (HTTPS) trong khi curl/AWS CLI gọi `http://`.
* Đặt `tls_enabled = false` tường minh cho smoke test HTTP; CLI (`status/gc/config`)
  hỗ trợ cả hai scheme theo `tls_enabled`, chấp nhận self-signed local.

---

## 🔄 Hướng dẫn Nâng cấp từ v0.3.0 lên v0.3.1

Không có migration SQLite mới (schema giữ nguyên) — nâng cấp nhị phân, giữ DB/spool:

```bash
# 1. Dừng service
sudo systemctl stop telecrate

# 2. Tải binary v0.3.1 mới nhất và ghi đè
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.1/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/

# 3. Khởi động lại service
sudo systemctl start telecrate

# 4. Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate
```

Lưu ý: daemon mặc định serve **HTTPS** (tự sinh self-signed nếu chưa có cert). Dashboard
mở qua `https://<host>:<port>/` (trình duyệt cảnh báo self-signed lần đầu); smoke test
nội bộ dùng `tls_enabled = false` để giữ HTTP.

---

# TeleCrate v0.3.0 — Release Notes

Phiên bản **TeleCrate v0.3.0** bổ sung cấu hình vị trí spool (dashboard + installer),
hỗ trợ chọn backend metadata DB SQLite/Postgres (partial), Admin API batch nguyên tử,
và sửa lỗi parse tag release trong `install.sh`.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.0

### 1. Cấu hình vị trí Spool
* Dashboard tab Cấu hình → fieldset **Lưu trữ**: ô `Thư mục spool` (đánh dấu ⟳ restart),
  validate absolute + cấm `..` (`src/config.rs`).
* `install.sh` wizard thêm mục **6. Thư mục spool local** (mặc định `/var/lib/telecrate/spool`,
  tự động hóa bằng `TELECRATE_SPOOL_DIR=/mnt/data/spool`), tự tạo thư mục + phân quyền `700`.

### 2. Backend metadata DB: SQLite / Postgres (partial — ADR 0005)
* `db_backend = "sqlite"` (mặc định, runnable duy nhất) | `"postgres"` + `database_url`
  (redact mọi nơi như bot token). Chọn qua TOML / `telecrate config set` / dashboard.
* Schema DDL Postgres đầy đủ tương đương SQLite 0001→0004 tại
  `migrations/postgres/0001_0004_schema.sql`; xem trước bằng `telecrate db pg-schema`.
* Runtime Postgres còn `blocked`: daemon từ chối khởi động rõ ràng thay vì fallback lén.

### 3. Admin API batch nguyên tử (`POST /admin/api/config` + `updates`)
* Lưu toàn bộ tab Cấu hình trong 1 request: đổi `db_backend` cần backend+URL cùng lúc,
  gửi từng key riêng lẻ trước đây kẹt ở trạng thái trung gian. Dashboard đã chuyển sang batch.

### 4. Sửa lỗi `install.sh` parse tag release
* GitHub API trả JSON 1 dòng làm parser cũ (`grep + cut -f4`) trích nhầm field `url`
  thành tag → URL download lồng nhau. Parser mới (ưu tiên `jq` → `python3` → `grep -o`),
  validate tag `vX.Y.Z`, retry curl + hiện lỗi chi tiết, pin version `TELECRATE_VERSION`.

---

## 🔄 Hướng dẫn Nâng cấp từ v0.2.0 lên v0.3.0

Không có migration SQLite mới (schema giữ nguyên) — nâng cấp nhị phân, giữ DB/spool:

```bash
# 1. Dừng service
sudo systemctl stop telecrate

# 2. Tải binary v0.3.0 mới nhất và ghi đè
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.0/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/

# 3. Khởi động lại service
sudo systemctl start telecrate

# 4. Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate
```

---

# TeleCrate v0.2.0 — Release Notes

Phiên bản **TeleCrate v0.2.0** mang đến bản nâng cấp toàn diện về giao diện vận hành (Web Dashboard & Admin Console), trải nghiệm duyệt tệp tin chuẩn AWS S3, quản lý khóa truy cập nâng cao, và script cài đặt tự động 1-line (`install.sh`) cho môi trường Linux native.

---

## 🌟 Điểm nổi bật trong phiên bản v0.2.0

### 1. Kịch bản Cài đặt Tự động 1-Line (`install.sh`)
* Cài đặt toàn diện TeleCrate chỉ với một câu lệnh:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/ZkIsHere/TeleCrate/master/install.sh | bash
  ```
* Tự động phát hiện kiến trúc máy chủ (`amd64` / `arm64`), tải binary release mới nhất từ GitHub Releases.
* Tự động khởi tạo user hệ thống `telecrate`, phân quyền chặt chẽ các thư mục `/var/lib/telecrate` và `/var/lib/telecrate/spool`.
* **Wizard cấu hình thông minh** qua `/dev/tty`: Hướng dẫn nhập bot token Telegram, chat ID, mật khẩu admin (hoặc sinh ngẫu nhiên), cổng lắng nghe, mã hóa nội dung và tự sinh cặp Access Key S3 ban đầu.
* Tự động tạo và kích hoạt dịch vụ **Systemd native** (`telecrate.service`), kiểm tra trạng thái hoạt động và in bảng tóm tắt thông tin kết nối ngay trên terminal.

---

### 2. Giao diện Quản trị Web Dashboard v2 (Restrained Ops Console)
* **Thiết kế chuẩn vận hành (GitHub/AWS/Grafana)**: Typography hệ thống rõ nét, chế độ Sáng/Tối (Dark/Light mode), độ tương phản cao, layout tràn viền toàn màn hình (`fluid full-width`) không góc chết trên màn hình rộng 1080p/2K/4K.
* **100% Offline & Tự lưu trữ**: Không phụ thuộc bất kỳ CDN hoặc font chữ bên ngoài, an toàn và hoạt động hoàn hảo trong mạng nội bộ / homelab.
* **Hệ thống Biểu đồ đường (Line Charts) thời gian thực**:
  * Tự phát triển engine đồ họa trên **HTML5 Canvas 2D thuần**, hỗ trợ khử răng cưa DPI cao.
  * 4 biểu đồ đường trực quan bố trí dạng lưới 2×2 cân đối:
    1. **Objects**: Biến động số lượng đối tượng lưu trữ theo thời gian.
    2. **Spool Usage**: Dung lượng spool cục bộ chiếm dụng trên ổ cứng.
    3. **Storage Growth**: Tăng trưởng dung lượng lưu trữ cơ sở dữ liệu.
    4. **Job Pipeline**: Lưu lượng jobs chờ tải lên và đang tải lên nền.
  * Tự động co giãn mượt mà khi thay đổi kích thước cửa sổ trình duyệt (debounced resize listener).

---

### 3. Trình duyệt Tệp tin Phân cấp Chuẩn AWS S3 (Hierarchical File Browser)
* **Duyệt theo cây thư mục**: Hỗ trợ đầy đủ tiền tố (`prefix`) và dấu phân cách (`delimiter = '/'`), phân biệt rõ ràng giữa thư mục con (common prefixes) và tệp tin.
* **Thanh điều hướng Breadcrumbs**: Dễ dàng click chuyển đổi nhanh giữa các cấp thư mục hoặc quay về danh sách bucket.
* **Slide-out Side Panel**: Bảng trượt bên phải hiển thị toàn diện thông tin metadata của object (Full Key, Bucket, kích thước chính xác đến từng byte, ETag, Version ID, Content-Type, trạng thái spool/remote, thời điểm tạo/sửa đổi và nút xóa).
* **Multi-select & Batch Delete**: Chọn nhiều tệp tin cùng lúc qua hộp kiểm và xóa hàng loạt qua thanh công cụ nổi (sticky batch bar).

---

### 4. Nâng cấp Hệ thống Quản lý Access Keys (v2)
* **Migration `0004_dashboard_enhancements.sql`**: Bổ sung trường `last_used_at` và `allowed_buckets` cho bảng `access_keys`.
* **Phân quyền theo Bucket**: Giới hạn phạm vi truy cập của từng Access Key theo danh sách bucket cụ thể (hoặc `*` cho toàn quyền).
* **Bật/Tắt trạng thái tức thì**: Nút chuyển đổi nhanh `Active` ↔ `Inactive` qua API `PATCH /admin/api/access-keys/:id` mà không cần thu hồi key; client dùng key inactive sẽ bị SigV4 từ chối ngay lập tức.
* **Bảo mật Secret Key**: Secret key được sinh ngẫu nhiên bằng CSPRNG và **chỉ hiển thị duy nhất 1 lần** trong hộp thoại cảnh báo lúc tạo; không bao giờ lưu trữ hoặc render ra DOM bảng danh sách.

---

### 5. Tab Jobs & Giám sát Worker Pipeline
* **Thanh trạng thái Pipeline Bar**: Hiển thị số lượng jobs theo 4 trạng thái (`pending`, `uploading`, `completed`, `failed`), click vào từng ô để lọc nhanh bảng jobs.
* **Bảng theo dõi chi tiết**: Cung cấp Job ID, Bucket/Key, State badge, số lần thử lại (Retries), thời điểm chạy kế tiếp, Worker ID đang giữ lease, và chi tiết lỗi nếu gặp sự cố mạng.
* **Tự động làm mới**: Tự động reload số liệu mỗi 5 giây khi đang mở tab.

---

### 6. Tab Bảo trì & Quản lý Multipart Uploads
* **Giám sát Multipart dở dang**: Bảng liệt kê các phiên upload nhiều phần đang thực hiện (Upload ID, Bucket, Key, Content-Type, Initiated at).
* **Hủy upload một chạm (Abort Multipart)**: Nút hủy gọi trực tiếp `POST /admin/api/multipart/:id/abort` giúp dọn dẹp triệt để các chunk tạm thời trong spool, giải phóng dung lượng đĩa.
* **Công cụ bảo trì một chạm**: Tích hợp sẵn nút chạy Garbage Collection (`/admin/api/gc`), Doctor kiểm tra toàn vẹn DB/spool (`/admin/api/doctor`), và Sao lưu cơ sở dữ liệu (`/admin/api/backup`).

---

### 7. Cải tiến Hạ tầng CI/CD & Runner
* **Tự động cài đặt GitHub CLI (`gh`)**: Script `cd.yml` tự động tải bản static standalone của `gh` nếu máy self-hosted runner chưa cài đặt, khắc phục lỗi `gh: command not found`.
* **Chống nghẽn Runner (Deadlock Prevention)**: Job `gate-ci` trong CD ưu tiên kiểm tra CI run đã pass trước đó cho commit SHA, tránh tình trạng treo hoặc fail khi chạy trên môi trường 1 runner duy nhất.

---

## 📦 Danh sách Gói phát hành (Release Assets)

| Tên tệp tin | Mô tả |
|---|---|
| `telecrate-linux-amd64.tar.gz` | Binary release tối ưu hóa cho Linux x86_64 / amd64 |
| `telecrate-dev-linux-amd64.tar.gz` | Binary build có debuginfo |
| `telecrate_0.2.0_amd64.deb` | Gói cài đặt Debian/Ubuntu native |
| `telecrate-0.2.0-1.x86_64.rpm` | Gói cài đặt RedHat/CentOS/Rocky Linux native |

---

## 🔄 Hướng dẫn Nâng cấp từ v0.1.0 lên v0.2.0

Nếu bạn đang chạy TeleCrate v0.1.0, việc nâng cấp hoàn toàn tự động và an toàn (forward-only migrations):

```bash
# 1. Dừng service
sudo systemctl stop telecrate

# 2. Tải binary v0.2.0 mới nhất và ghi đè
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.2.0/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/

# 3. Khởi động lại service (hệ thống sẽ tự động apply migration 0004)
sudo systemctl start telecrate

# 4. Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate
```
