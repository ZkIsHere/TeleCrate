# ADR 0001 — Stack: Rust + SQLite + spool FS + frontend tĩnh

Ngày: 2026-09-15. Trạng thái: chấp nhận cho M0, có thể đảo ngược ở M1 nếu capability spike đòi hỏi.

## So sánh ngắn

| Tiêu chí | Rust (chọn) | Go | Python / Node |
|---|---|---|---|
| RAM bounded (2 GB, stream chunk) | Tốt: ownership + streaming, không GC pause | Tốt | Kém hơn: runtime + GC/RSS khó bound |
| Packaging native systemd, không runtime | Một binary tĩnh, không Docker/Redis/Node runtime | Một binary tĩnh | Cần interpreter/runtime khi vận hành → vi phạm yêu cầu |
| S3 correctness | Tự triển khai trên axum + quick-xml; kiểm soát SigV4/XML/ETag chặt | Tốt | Phụ thuộc framework nặng |
| Telegram SDK | Bot API HTTP qua reqwest (đủ M1); Local Bot API/MTProto thêm sau | Lib Bot/MTProto phong phú hơn | Lib nhiều nhưng runtime vi phạm |
| Bảo trì/testability | cargo test/clippy/fmt chuẩn; toolchain sẵn có | Cần cài toolchain mới | Nhanh viết nhưng khó bound RAM/packaging |
| Ít thành phần | daemon+worker cùng process, SQLite WAL, FS spool | Tương tự | Thường kéo thêm Redis/queue |

## Quyết định

- Backend/CLI: Rust stable edition 2021+, `axum`, `tokio`, `rusqlite` (bundled), `clap`, `serde`, `toml`, `tracing`.
- DB: SQLite WAL cho index/jobs (single instance, txn bền vững, backup `VACUUM INTO`); spool là FS riêng.
- Frontend: build tĩnh (Vite) ở bước build, daemon serve; vận hành không cần Node.
- Không thêm Redis/K8s/DB nặng nếu chưa có lý do đo được.

## Tham chiếu

Stack chi tiết: `docs/adr/0001-stack.md` là file này. Xem thêm `docs/architecture.md`.
