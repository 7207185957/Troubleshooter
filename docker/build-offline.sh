#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# build-offline.sh
#
# Run this script on a machine WITH internet access.
# It produces a single .tar.gz file that you transfer to the air-gapped EC2
# instance and load into Docker — no internet needed on the target host.
#
# Usage:
#   bash docker/build-offline.sh [image-tag] [s3-bucket]
#
#   image-tag  – Docker image tag to use  (default: latest)
#   s3-bucket  – If provided, uploads the tar.gz to this S3 bucket
#                automatically after building.
#
# What it does:
#   1. Downloads all Python wheels into docker/wheels/
#   2. Builds the Docker image from Dockerfile.offline (wheels baked in)
#   3. Saves the image as a compressed .tar.gz
#   4. Optionally uploads to S3
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE_NAME="ec2-troubleshooter"
IMAGE_TAG="${1:-latest}"
S3_BUCKET="${2:-}"
S3_PREFIX="docker"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TAR_FILE="${REPO_ROOT}/${IMAGE_NAME}-${IMAGE_TAG}.tar.gz"

cd "$REPO_ROOT"

echo "══════════════════════════════════════════════════════════"
echo "  EC2 Troubleshooter – offline Docker build"
echo "  Image  : ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Output : ${TAR_FILE}"
echo "══════════════════════════════════════════════════════════"

# ── Step 1: Download wheels ─────────────────────────────────────────────────
echo ""
echo "▶ Step 1/4 – Downloading Python wheels into docker/wheels/"
mkdir -p docker/wheels
pip download -r requirements.txt -d docker/wheels/ --quiet
WHEEL_COUNT=$(ls docker/wheels/ | wc -l | tr -d ' ')
echo "  ✓ ${WHEEL_COUNT} wheel files downloaded"

# ── Step 2: Build Docker image ─────────────────────────────────────────────
echo ""
echo "▶ Step 2/4 – Building Docker image (wheels baked in, no internet needed)"
docker build \
    -f docker/Dockerfile.offline \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    .
echo "  ✓ Image built: ${IMAGE_NAME}:${IMAGE_TAG}"

# ── Step 3: Save image to tar.gz ───────────────────────────────────────────
echo ""
echo "▶ Step 3/4 – Saving image to ${TAR_FILE}"
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | gzip > "${TAR_FILE}"
SIZE=$(du -sh "${TAR_FILE}" | cut -f1)
echo "  ✓ Saved (${SIZE})"

# ── Step 4: Upload to S3 (optional) ────────────────────────────────────────
if [[ -n "${S3_BUCKET}" ]]; then
    echo ""
    echo "▶ Step 4/4 – Uploading to s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}")"
    aws s3 cp "${TAR_FILE}" "s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}")"
    echo "  ✓ Uploaded"
    echo ""
    echo "On the air-gapped EC2 instance, run:"
    echo "  aws s3 cp s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}") ."
    echo "  docker load < $(basename "${TAR_FILE}")"
else
    echo ""
    echo "▶ Step 4/4 – Skipped (no S3_BUCKET provided)"
    echo ""
    echo "Transfer the image manually, then on the EC2 instance run:"
    echo "  docker load < $(basename "${TAR_FILE}")"
fi

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  Build complete."
echo ""
echo "  On the air-gapped EC2 instance:"
echo "    1. Load:  docker load < ${IMAGE_NAME}-${IMAGE_TAG}.tar.gz"
echo "    2. Copy config: cp .env.example /etc/ec2-troubleshooter/.env && vi /etc/ec2-troubleshooter/.env"
echo "    3. Run:   docker compose -f docker/docker-compose.yml up -d"
echo "    4. Check: docker compose -f docker/docker-compose.yml ps"
echo "    5. Logs:  docker compose -f docker/docker-compose.yml logs -f"
echo "══════════════════════════════════════════════════════════"
