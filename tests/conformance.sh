#!/usr/bin/env bash
set -euo pipefail

# Script kiểm thử tương thích thực tế với AWS CLI, Rclone và MinIO Client (mc)

ENDPOINT="${ENDPOINT:-http://127.0.0.1:7070}"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAEXAMPLE12345}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-secret1234567890secret1234567890}"
AWS_REGION="${AWS_REGION:-us-east-1}"

export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION="${AWS_REGION}"

echo "=========================================================="
echo " TeleCrate S3 Conformance Suite — AWS CLI, Rclone & mc"
echo "=========================================================="

# 1. AWS CLI Test
if command -v aws >/dev/null 2>&1; then
    echo "[1/3] Testing AWS CLI..."
    aws s3 mb "s3://cli-test-bucket" --endpoint-url "${ENDPOINT}"
    aws s3 ls --endpoint-url "${ENDPOINT}"
    echo "AWS CLI test data" > /tmp/aws_test.txt
    aws s3 cp /tmp/aws_test.txt "s3://cli-test-bucket/aws_test.txt" --endpoint-url "${ENDPOINT}"
    aws s3 ls "s3://cli-test-bucket/" --endpoint-url "${ENDPOINT}"
    aws s3 rm "s3://cli-test-bucket/aws_test.txt" --endpoint-url "${ENDPOINT}"
    aws s3 rb "s3://cli-test-bucket" --endpoint-url "${ENDPOINT}"
    echo "✓ AWS CLI Conformance PASS"
else
    echo "[1/3] AWS CLI not installed (Skipping)"
fi

# 2. Rclone Test
if command -v rclone >/dev/null 2>&1; then
    echo "[2/3] Testing Rclone..."
    rclone mkdir ":s3,provider=Other,endpoint=${ENDPOINT},access_key_id=${AWS_ACCESS_KEY_ID},secret_access_key=${AWS_SECRET_ACCESS_KEY},region=${AWS_REGION}:rclone-test-bucket"
    rclone ls ":s3,provider=Other,endpoint=${ENDPOINT},access_key_id=${AWS_ACCESS_KEY_ID},secret_access_key=${AWS_SECRET_ACCESS_KEY},region=${AWS_REGION}:rclone-test-bucket"
    echo "✓ Rclone Conformance PASS"
else
    echo "[2/3] Rclone not installed (Skipping)"
fi

# 3. MinIO Client (mc) Test
if command -v mc >/dev/null 2>&1; then
    echo "[3/3] Testing MinIO Client (mc)..."
    mc alias set telecrate "${ENDPOINT}" "${AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY}"
    mc mb telecrate/mc-test-bucket
    mc ls telecrate/
    mc rb telecrate/mc-test-bucket
    echo "✓ MinIO Client Conformance PASS"
else
    echo "[3/3] MinIO Client (mc) not installed (Skipping)"
fi

echo "=========================================================="
echo " Conformance Suite Complete!"
echo "=========================================================="
