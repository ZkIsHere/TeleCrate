# Milestones TeleCrate (cập nhật 2026-09-15)

- **M0 — Bootstrap: `implemented-and-tested`**. Repo private `ZkIsHere/TeleCrate`, CI self-hosted runner `ci-cd` xanh
  (fmt/clippy/build/test/package-validate). Rust skeleton + migrations v1 + systemd unit + config mẫu.
- **M1 — Capability spike Telegram: `partial` → đóng phần Bot API HTTP**. Changeset 1 (trait + skeleton + mock tests) và 2
  (`BotApiHttpTransport` thật + live probe 8 KiB pass trên user chat và basic group 2026-09-15) đã xong,
  CI có job `live-telegram` riêng. Còn `blocked` có lý do: kiểm tra đặc thù channel/supergroup
  (nâng `-100...` bất khả thi ở môi trường này), locator refresh, FLOOD_WAIT thực tế — không chặn M2.
- **M2 — Vertical slice durable PUT/GET/HEAD/DELETE/LIST + SigV4 + spool/index + worker thật + 2 chế độ mã hóa (on/off)** (tiếp theo). Crash injection + restart không mất acknowledged object.
- **M3 — Multipart, copy, Range, conditional, ETag, versioning, metadata/tags**.
- **M4 — Auth hoàn chỉnh (presigned/POST policy), policies/ACL/BPA/CORS, SSE hành vi đúng, Object Lock gateway**.
- **M5 — GC, recovery bundle, doctor/verify/scrub, backup/restore index**.
- **M6 — CLI + dashboard đầy đủ, packaging Linux, docs install/admin/recovery**.
- **M7 — Conformance (AWS CLI, rclone, SDK), fixture 25k objects/62 GB mô phỏng, live Telegram nhỏ có kiểm soát, gap report advanced**.

Không dừng ở demo upload/download rồi tuyên bố xong. Mỗi milestone chỉ sang tiếp khi required checks của SHA đó xanh.
