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
#   1. Download all Python wheels into docker/wheels/
#   2. Build Docker image from Dockerfile.offline  (wheels baked in)
#   3. Save as a compressed .tar.gz
#   4. Optionally upload to S3
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
echo "  Python  : 3.10-slim (matches target host Python 3.10.x)"
echo "  Image   : ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Output  : ${TAR_FILE}"
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
echo "▶ Step 2/4 – Building Docker image (Python 3.10, wheels baked in)"
docker build \
    --build-arg PYTHON_VERSION=3.10-slim \
    -f docker/Dockerfile.offline \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    .
echo "  ✓ Image built: ${IMAGE_NAME}:${IMAGE_TAG}"

# ── Step 3: Save as tar.gz ─────────────────────────────────────────────────
echo ""
echo "▶ Step 3/4 – Saving image to $(basename "${TAR_FILE}")"
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | gzip > "${TAR_FILE}"
SIZE=$(du -sh "${TAR_FILE}" | cut -f1)
echo "  ✓ Saved: ${SIZE}"

# ── Step 4: Upload to S3 (optional) ────────────────────────────────────────
if [[ -n "${S3_BUCKET}" ]]; then
    echo ""
    echo "▶ Step 4/4 – Uploading to s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}")"
    aws s3 cp "${TAR_FILE}" "s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}")"
    echo "  ✓ Uploaded"
    TRANSFER_CMD="aws s3 cp s3://${S3_BUCKET}/${S3_PREFIX}/$(basename "${TAR_FILE}") ."
else
    echo ""
    echo "▶ Step 4/4 – Skipped (no S3_BUCKET provided)"
    echo "  Transfer $(basename "${TAR_FILE}") to the EC2 instance manually (SCP via bastion, etc.)"
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
echo "  # 2. Load into Docker (no internet needed)"
echo "  docker load < $(basename "${TAR_FILE}")"
echo ""
echo "  # 3. Create config"
echo "  sudo mkdir -p /etc/ec2-troubleshooter"
echo "  sudo cp .env.example /etc/ec2-troubleshooter/.env"
echo "  sudo vi /etc/ec2-troubleshooter/.env"
echo ""
echo "  # 4. Run (plain docker run — no docker-compose needed)"
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
echo "  docker ps"
echo "  curl http://localhost:8080/health"
echo "  docker logs -f ec2-troubleshooter"
echo "══════════════════════════════════════════════════════════"
