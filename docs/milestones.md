# Milestones TeleCrate

- **M0 — Bootstrap (commit này)**: Git + AGENTS.md + docs + ADR stack + Rust skeleton + migrations v1 + systemd unit + config mẫu + CI workflow. Cổng: `cargo fmt --check`, clippy `-D warnings`, build, unit test, migrations test, package validate. Trạng thái: `implemented-and-tested` (local) / CI `blocked` (chưa có remote).
- **M1 — Capability spike Telegram**: Bot API HTTP upload/download/delete/refresh trên channel thử nghiệm + đo giới hạn thật. Không chuyển user session. Kết quả vào `docs/telegram-capability.md`. Live test cần secrets → tách khỏi PR checks.
- **M2 — Vertical slice durable PUT/GET/HEAD/DELETE/LIST + SigV4 + spool/index + worker thật + 2 chế độ mã hóa (on/off)**. Crash injection + restart không mất acknowledged object.
- **M3 — Multipart, copy, Range, conditional, ETag, versioning, metadata/tags**.
- **M4 — Auth hoàn chỉnh (presigned/POST policy), policies/ACL/BPA/CORS, SSE hành vi đúng, Object Lock gateway**.
- **M5 — GC, recovery bundle, doctor/verify/scrub, backup/restore index**.
- **M6 — CLI + dashboard đầy đủ, packaging Linux, docs install/admin/recovery**.
- **M7 — Conformance (AWS CLI, rclone, SDK), fixture 25k objects/62 GB mô phỏng, live Telegram nhỏ có kiểm soát, gap report advanced**.

Không dừng ở demo upload/download rồi tuyên bố xong. Mỗi milestone chỉ sang tiếp khi required checks của SHA đó xanh.
