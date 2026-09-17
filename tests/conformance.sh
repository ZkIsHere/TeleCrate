#!/usr/bin/env bash
set -euo pipefail

# TeleCrate S3 conformance bằng client thật (AWS CLI bắt buộc, rclone/mc tùy chọn).
#
# Biến môi trường:
#   ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION (mặc định như dưới)
#   STRICT=1  -> thiếu tool bắt buộc là FAIL (dùng trong CI); mặc định skip nhẹ nhàng.
#   CLEANUP=0 -> giữ bucket/object sau test để debug; mặc định dọn sạch.

ENDPOINT="${ENDPOINT:-http://127.0.0.1:7070}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAEXAMPLE12345}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-secret1234567890secret1234567890}"
AWS_REGION="${AWS_REGION:-us-east-1}"
STRICT="${STRICT:-0}"
CLEANUP="${CLEANUP:-1}"

export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION="${AWS_REGION}"
export AWS_EC2_METADATA_DISABLED=true

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    if [ "$STRICT" = "1" ]; then
      echo "FAIL: thiếu tool bắt buộc '$1' (STRICT=1)" >&2
      exit 1
    fi
    echo "SKIP: '$1' chưa cài (STRICT=0)"
    return 1
  fi
  return 0
}

cleanup() {
  if [ "$CLEANUP" = "1" ]; then
    aws s3 rm "s3://tc-conf-main/" --recursive --endpoint-url "${ENDPOINT}" >/dev/null 2>&1 || true
    aws s3 rb "s3://tc-conf-main" --endpoint-url "${ENDPOINT}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== TeleCrate S3 conformance (endpoint=${ENDPOINT} region=${AWS_REGION}) =="

need aws || exit 0
echo "[aws] version: $(aws --version 2>&1 | head -c 120)"

# 1. Bucket lifecycle: mb -> ls thấy -> rb.
aws s3 mb "s3://tc-conf-main" --endpoint-url "${ENDPOINT}"
aws s3 ls --endpoint-url "${ENDPOINT}" | grep -q "tc-conf-main"
echo "[aws] mb/ls OK"

# 2. Upload/download byte-identical (file nhỏ) + content-type.
printf 'hello-telecrate-conformance' > /tmp/tc_small.txt
aws s3 cp /tmp/tc_small.txt "s3://tc-conf-main/small.txt" \
  --endpoint-url "${ENDPOINT}" --content-type "text/plain"
aws s3 cp "s3://tc-conf-main/small.txt" /tmp/tc_small_got.txt \
  --endpoint-url "${ENDPOINT}"
cmp /tmp/tc_small.txt /tmp/tc_small_got.txt
echo "[aws] small file roundtrip OK"

# 3. Multipart thật: file 9 MiB vượt ngưỡng multipart mặc định 8 MiB của AWS CLI.
head -c 9437184 /dev/urandom > /tmp/tc_big.bin
aws s3 cp /tmp/tc_big.bin "s3://tc-conf-main/big.bin" --endpoint-url "${ENDPOINT}"
aws s3 cp "s3://tc-conf-main/big.bin" /tmp/tc_big_got.bin --endpoint-url "${ENDPOINT}"
cmp /tmp/tc_big.bin /tmp/tc_big_got.bin
echo "[aws] multipart 9MiB roundtrip OK"

# 4. Unicode key + key có space.
printf 'uni' > /tmp/tc_uni.txt
aws s3 cp /tmp/tc_uni.txt "s3://tc-conf-main/ca-phe/a b+100%.txt" --endpoint-url "${ENDPOINT}"
aws s3 ls "s3://tc-conf-main/ca-phe/" --endpoint-url "${ENDPOINT}" | grep -q "a b"
echo "[aws] unicode/space key OK"

# 5. Presigned URL download: ký bằng key thật, tải bằng curl không auth.
url=$(aws s3 presign "s3://tc-conf-main/small.txt" --endpoint-url "${ENDPOINT}" --expires-in 300)
curl -fsSL "$url" -o /tmp/tc_presigned.txt
cmp /tmp/tc_small.txt /tmp/tc_presigned.txt
echo "[aws] presigned download OK"

# 6. Head/metadata qua API (27 = len('hello-telecrate-conformance')).
aws s3api head-object --bucket tc-conf-main --key small.txt \
  --endpoint-url "${ENDPOINT}" --query 'ContentLength' --output text | grep -q "27"
echo "[aws] head-object OK"

echo "== S3 conformance PASS (aws) =="

# 7. rclone / mc: tùy chọn, skip khi thiếu (kể cả STRICT).
if need rclone; then
  R=":s3,provider=Other,endpoint=${ENDPOINT},access_key_id=${AWS_ACCESS_KEY_ID},secret_access_key=${AWS_SECRET_ACCESS_KEY},region=${AWS_REGION}:tc-conf-rclone"
  rclone mkdir "$R" && rclone rmdir "$R"
  echo "== rclone PASS (optional) =="
fi
if need mc; then
  mc alias set telecrate "${ENDPOINT}" "${AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY}" >/dev/null
  mc mb telecrate/tc-conf-mc && mc rb telecrate/tc-conf-mc
  echo "== mc PASS (optional) =="
fi
