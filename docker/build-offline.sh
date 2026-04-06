#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# build-offline.sh
#
# Run on a machine WITH internet access.
# Produces a single .tar.gz that you transfer to the air-gapped EC2 instance
# and load into Docker — no internet needed on the target host.
# No docker-compose required anywhere.
#
# Usage:
#   bash docker/build-offline.sh [image-tag] [s3-bucket]
#
#   image-tag   Docker image tag   (default: latest)
#   s3-bucket   If set, uploads the tar.gz to this S3 bucket after building
#
# Steps performed:
#   1. Download Python wheels for the CORRECT target platform
#      (linux/amd64, Python 3.10, manylinux) regardless of the build machine OS
#   2. Build Docker image from Dockerfile.offline  (wheels baked in)
#   3. Save as a compressed .tar.gz
#   4. Optionally upload to S3
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE_NAME="ec2-troubleshooter"
IMAGE_TAG="${1:-latest}"
S3_BUCKET="${2:-}"
S3_PREFIX="docker"

# Target platform — must match the Dockerfile base image
TARGET_PYTHON="cp310"           # CPython 3.10
TARGET_ABI="cp310"
TARGET_PLATFORM="manylinux_2_17_x86_64 manylinux2014_x86_64 linux_x86_64"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TAR_FILE="${REPO_ROOT}/${IMAGE_NAME}-${IMAGE_TAG}.tar.gz"

cd "$REPO_ROOT"

echo "══════════════════════════════════════════════════════════"
echo "  EC2 Troubleshooter – offline Docker build"
echo "  Python  : 3.10-slim (CPython, linux/amd64)"
echo "  Image   : ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Output  : ${TAR_FILE}"
echo "══════════════════════════════════════════════════════════"

# ── Step 1: Download platform-correct wheels ────────────────────────────────
# --python-version, --platform, and --abi ensure we get linux/amd64 wheels
# even when running this script on macOS or a different Python version.
# --only-binary=:all: prevents downloading sdists that would require a compiler
# on the target host.
echo ""
echo "▶ Step 1/4 – Downloading wheels for linux/amd64 + Python 3.10"
rm -rf docker/wheels
mkdir -p docker/wheels

pip download \
    --dest docker/wheels/ \
    --python-version 3.10 \
    --implementation cp \
    --abi cp310 \
    --platform manylinux_2_17_x86_64 \
    --only-binary=:all: \
    -r requirements.txt \
    --quiet

WHEEL_COUNT=$(ls docker/wheels/ | wc -l | tr -d ' ')
echo "  ✓ ${WHEEL_COUNT} wheel files downloaded (linux/amd64, cp310)"

# ── Step 2: Build Docker image ──────────────────────────────────────────────
echo ""
echo "▶ Step 2/4 – Building Docker image (Python 3.10, wheels baked in)"
docker build \
    --build-arg PYTHON_VERSION=3.10-slim \
    -f docker/Dockerfile.offline \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    .
echo "  ✓ Image built: ${IMAGE_NAME}:${IMAGE_TAG}"

# ── Step 3: Save as tar.gz ──────────────────────────────────────────────────
echo ""
echo "▶ Step 3/4 – Saving image to $(basename "${TAR_FILE}")"
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | gzip > "${TAR_FILE}"
SIZE=$(du -sh "${TAR_FILE}" | cut -f1)
echo "  ✓ Saved: ${SIZE}"

# ── Step 4: Upload to S3 (optional) ─────────────────────────────────────────
if [[ -n "${S3_BUCKET}" ]]; then
    echo ""
    echo "▶ Step 4/4 – Uploading to s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}")"
    aws s3 cp "${TAR_FILE}" "s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}")"
    echo "  ✓ Uploaded"
    TRANSFER_CMD="aws s3 cp s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}") ."
else
    echo ""
    echo "▶ Step 4/4 – Skipped (no S3_BUCKET provided)"
    TRANSFER_CMD="# scp -J bastion-user@bastion $(basename "${TAR_FILE}") ec2-user@<private-ip>:~"
fi

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  Build complete."
echo ""
echo "  On the air-gapped EC2 instance run:"
echo ""
echo "  # 1. Get the image"
echo "  ${TRANSFER_CMD}"
echo ""
echo "  # 2. Load into Docker"
echo "  docker load < $(basename "${TAR_FILE}")"
echo ""
echo "  # 3. Create config"
echo "  sudo mkdir -p /etc/ec2-troubleshooter"
echo "  sudo cp .env.example /etc/ec2-troubleshooter/.env"
echo "  sudo vi /etc/ec2-troubleshooter/.env"
echo ""
echo "  # 4. Run"
echo "  docker run -d \\"
echo "    --name ec2-troubleshooter \\"
echo "    --restart unless-stopped \\"
echo "    --env-file /etc/ec2-troubleshooter/.env \\"
echo "    -p 8080:8080 \\"
echo "    --log-driver json-file \\"
echo "    --log-opt max-size=50m \\"
echo "    --log-opt max-file=5 \\"
echo "    ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "  # 5. Verify"
echo "  curl http://localhost:8080/health"
echo "══════════════════════════════════════════════════════════"
