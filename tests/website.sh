#!/usr/bin/env bash
set -euo pipefail

# Smoke test website TeleCrate: assets tĩnh, auth/CSRF, admin API shapes, logout.
# Chạy daemon thật trên port tạm, assert bằng curl + grep (không cần browser).
# Biến môi trường: PORT (mặc định 18080), BIN (mặc định ./target/debug/telecrate).

PORT="${PORT:-18080}"
BIN="${BIN:-./target/debug/telecrate}"
BASE="http://127.0.0.1:${PORT}"
ADMIN_PWD="website-test-pwd"
WORK="$(mktemp -d)"
JAR="$WORK/cookies.txt"
DAEMON=""

fail() { echo "WEBSITE FAIL: $*" >&2; if [ -n "$DAEMON" ]; then kill "$DAEMON" 2>/dev/null || true; fi; exit 1; }
pass() { echo "WEBSITE OK: $*"; }

cleanup() {
  if [ -n "$DAEMON" ]; then kill "$DAEMON" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/telecrate.toml" <<EOF
db_path = "$WORK/index.db"
spool_dir = "$WORK/spool"
listen_port = $PORT
tls_enabled = false
encryption = "off"
admin_password = "$ADMIN_PWD"
log_level = "warn"
[[access_keys]]
access_key_id = "AKIAEXAMPLE12345"
secret_key = "secret1234567890secret1234567890"
EOF

[ -x "$BIN" ] || { echo "WEBSITE FAIL: không thấy binary $BIN (chạy cargo build trước)" >&2; exit 1; }
"$BIN" --config "$WORK/telecrate.toml" init >/dev/null
"$BIN" --config "$WORK/telecrate.toml" serve &>/tmp/tc-website.log &
DAEMON=$!

for _ in $(seq 1 50); do
  curl -fsS "$BASE/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "$BASE/health" >/dev/null || fail "daemon không lên"

# 1. Assets tĩnh.
curl -fsS "$BASE/" | grep -q "TeleCrate" || fail "GET / thiếu brand"
curl -fsS "$BASE/dashboard/style.css" | grep -q "auth-card" || fail "CSS thiếu"
curl -fsS "$BASE/dashboard/app.js" | grep -q "audit-logs" || fail "JS thiếu"
pass "assets"

# 2. Session chưa login.
curl -fsS "$BASE/admin/api/session" | grep -q '"authenticated":false' || fail "session ban đầu"
pass "session"

# 3. Rate-limit: 11 lần sai -> lần cuối 429.
last=0
for _ in $(seq 1 11); do
  last=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/api/login" \
    -H 'Content-Type: application/json' -d '{"password":"nope"}')
done
[ "$last" = "429" ] || fail "rate-limit mong đợi 429, thấy $last"
pass "rate-limit"

# 4. Login đúng -> csrf + cookie.
login_body=$(curl -fsS -c "$JAR" -X POST "$BASE/admin/api/login" \
  -H 'Content-Type: application/json' -d "{\"password\":\"$ADMIN_PWD\"}")
echo "$login_body" | grep -q "csrf_token" || fail "login thiếu csrf"
CSRF=$(echo "$login_body" | grep -o '"csrf_token":"[^"]*"' | cut -d'"' -f4)
[ -n "$CSRF" ] || fail "không parse được csrf"
pass "login"

# 5. Status shape.
curl -fsS -b "$JAR" "$BASE/admin/api/status" | grep -q '"counts"' || fail "status thiếu counts"
pass "status"

# 6. Buckets CRUD qua admin API.
curl -fsS -b "$JAR" -H "x-csrf-token: $CSRF" -X POST "$BASE/admin/api/buckets" \
  -H 'Content-Type: application/json' -d '{"name":"web-bkt"}' | grep -q '"ok":true' || fail "mkbucket"
curl -fsS -b "$JAR" "$BASE/admin/api/buckets" | grep -q "web-bkt" || fail "list buckets"
pass "buckets"

# 7. Keys: secret hiện 1 lần lúc tạo, list không lộ.
secret=$(curl -fsS -b "$JAR" -H "x-csrf-token: $CSRF" -X POST "$BASE/admin/api/access-keys" \
  -H 'Content-Type: application/json' -d '{"user_id":"web"}' | grep -o '"secret_key":"[^"]*"' | cut -d'"' -f4)
[ -n "$secret" ] || fail "tạo key thiếu secret"
curl -fsS -b "$JAR" "$BASE/admin/api/access-keys" | grep -q "$secret" && fail "list lộ secret" || true
pass "keys"

# 8. Config có log_level; audit-logs shape mới.
curl -fsS -b "$JAR" "$BASE/admin/api/config" | grep -q '"log_level"' || fail "config thiếu log_level"
curl -fsS -b "$JAR" "$BASE/admin/api/audit-logs?level=info&limit=2" | grep -q '"entries"' || fail "audit shape"
curl -sS -b "$JAR" "$BASE/admin/api/audit-logs?level=nope" -o /dev/null -w "%{http_code}" | grep -q "400" || fail "audit level sai phải 400"
pass "config+audit"

# 9. Logout -> session false.
curl -fsS -b "$JAR" -c "$JAR" -H "x-csrf-token: $CSRF" -X POST "$BASE/admin/api/logout" | grep -q '"ok":true' || fail "logout"
curl -fsS -b "$JAR" "$BASE/admin/api/session" | grep -q '"authenticated":false' || fail "session sau logout"
pass "logout"

echo "== WEBSITE SMOKE PASS =="
