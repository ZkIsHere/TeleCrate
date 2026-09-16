# Báo cáo Khoảng cách Tính năng Nâng cao S3 (Advanced Features Gap Report) — TeleCrate

> Trạng thái kiểm chứng: 2026-09-16 (Phiên bản TeleCrate v0.1.0).
> Dựa trên tài liệu chính thức [Amazon S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html).
> Mọi tính năng thiếu sót nâng cao đều được ghi nhận minh bạch và phân loại theo bảng dưới đây.

---

## 1. Tóm tắt Phân loại Trạng thái

- `implemented-and-tested`: Đã được triển khai hoàn chỉnh trong codebase, có unit/integration tests pass 100%.
- `implemented-unverified`: Đã triển khai code nhưng chưa có bot token live Telegram để verify thực tế.
- `partial`: Triển khai một phần (ví dụ: Bot API HTTP transport pass, MTProto/Local Bot API chưa làm).
- `blocked`: Bị chặn bởi ràng buộc môi trường/nền tảng (ví dụ: Telegram channel `-100...` supergroup admin).
- `unsupported`: Tính năng S3 nâng cao nằm ngoài phạm vi cốt lõi của single-instance homelab gateway.

---

## 2. Bảng Chi tiết Gap Report các Tính năng Nâng cao (Advanced S3 Features)

| Phân nhóm Tính năng | API S3 Tương ứng | Trạng thái | Nguyên do & Định hướng Kiến trúc |
|---|---|---|---|
| **Static Website Hosting** | `GET/PUT/DELETE /{bucket}?website` | `unsupported` | TeleCrate là blob storage gateway cho Telegram, không đóng vai trò làm HTTP static web host engine. Người dùng muốn host website tĩnh có thể dùng Nginx/Cloudflare R2 phía trước. |
| **S3 Access Points** | `CreateAccessPoint`, `GetAccessPoint` | `unsupported` | Thiết kế của TeleCrate là **Single-Instance, Self-Hosted**. Không có kiến trúc multi-tenant hay phân quyền Access Point phức tạp như AWS S3 Enterprise. |
| **S3 Multi-Region Access Points** | `GetMultiRegionAccessPoint` | `unsupported` | TeleCrate chạy trên single host/homelab. Không hỗ trợ định tuyến multi-region toàn cầu. |
| **S3 Batch Operations** | `CreateJob`, `DescribeJob`, `ListJobs` | `unsupported` | Các thao tác hàng loạt được thay thế bằng công cụ tiêu chuẩn như `aws s3 rm --recursive` hoặc `rclone sync` trực tiếp qua API S3 Gateway. |
| **STS / IAM AssumeRole** | `AssumeRole`, `GetFederationToken` | `unsupported` | Phân quyền được quản lý trực tiếp qua SQLite `access_keys` và `bucket_policies` (Deny precedence, BPA). Không cần hạ tầng IAM STS phức tạp. |
| **S3 Event Notifications** | `PUT/GET /{bucket}?notification` (SNS/SQS/Lambda) | `unsupported` | TeleCrate ưu tiên ghi bền vững local-first và worker Telegram nền. Sự kiện được theo dõi qua Web Dashboard Audit Logs thay vì gửi SNS/SQS topic. |
| **S3 Lifecycle Expiration Policies** | `PUT/GET /{bucket}?lifecycle` (Glacier Transition) | `unsupported` | Telegram đã đóng vai trò là "Unlimited Cold Storage Tier". Dữ liệu không cần chuyển sang Glacier/Deep Archive. Việc dọn dẹp dữ liệu cũ được đảm nhiệm bởi Physical GC Engine (`telecrate gc`). |
| **S3 Object Replication (CRR/SRR)** | `PUT/GET /{bucket}?replication` | `unsupported` | Sự nhân bản dữ liệu được đảm bảo tự động bởi Telegram Cloud Storage (multi-datacenter redundancy). |
| **S3 Analytics / Inventory / Metrics** | `PUT/GET /{bucket}?analytics` | `unsupported` | Thống kê số lượng object/chunks/spool được tổng hợp trực tiếp trong SQLite WAL index và hiển thị trên Web Dashboard (`/admin/api/status`). |

---

## 3. Kết luận

TeleCrate tập trung 100% nguồn lực vào các tính năng cốt lõi: **Durable Local-First PUT/GET, ETag Plaintext, Multipart Uploads, SigV4 & Presigned URLs, CORS, Bucket Policies, Block Public Access, SSE-S3/SSE-C Encryption, Object Lock WORM Governance/Compliance, Physical GC, SQLite Online Backup & Standalone Recovery Bundle, cùng với Web Dashboard Quản trị**.

Các tính năng doanh nghiệp nâng cao (Website Hosting, STS, SNS, Glacier, Batch Ops) được đánh dấu `unsupported` minh bạch và không ảnh hưởng đến khả năng vận hành sản phẩm thực tế của TeleCrate trên Linux Native systemd.
