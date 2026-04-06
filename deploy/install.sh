#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# EC2 Troubleshooter – installation script for air-gapped EC2 instances
#
# Usage:
#   sudo bash install.sh [--pip-index-url http://my-mirror/simple]
#
# The script:
#   1. Creates a dedicated system user
#   2. Creates a Python venv under /opt/ec2-troubleshooter
#   3. Installs dependencies (from local mirror if --pip-index-url is set)
#   4. Installs the package
#   5. Registers and starts a systemd service
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="/opt/ec2-troubleshooter"
SERVICE_USER="ec2-troubleshooter"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PIP_INDEX_URL=""
PIP_TRUSTED_HOST=""

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pip-index-url)  PIP_INDEX_URL="$2"; shift 2 ;;
        --pip-trusted-host) PIP_TRUSTED_HOST="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "==> Creating system user: $SERVICE_USER"
id "$SERVICE_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"

echo "==> Creating install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "==> Creating virtual environment"
python3 -m venv "$INSTALL_DIR/venv"

PIP="$INSTALL_DIR/venv/bin/pip"
PYTHON="$INSTALL_DIR/venv/bin/python"

echo "==> Installing dependencies"
PIP_ARGS=(install --no-cache-dir)
if [[ -n "$PIP_INDEX_URL" ]]; then
    PIP_ARGS+=(--index-url "$PIP_INDEX_URL")
fi
if [[ -n "$PIP_TRUSTED_HOST" ]]; then
    PIP_ARGS+=(--trusted-host "$PIP_TRUSTED_HOST")
fi

"$PIP" "${PIP_ARGS[@]}" -r "$REPO_ROOT/requirements.txt"
"$PIP" "${PIP_ARGS[@]}" -e "$REPO_ROOT"

echo "==> Copying default environment file (if missing)"
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    cp "$REPO_ROOT/.env.example" "$INSTALL_DIR/.env" 2>/dev/null || \
    cat > "$INSTALL_DIR/.env" <<'EOF'
AWS_REGION=us-east-1
LOG_LEVEL=INFO
LOG_FORMAT=json
REPORTER_TYPE=log
# Uncomment and fill in for air-gapped VPC:
# USE_VPC_ENDPOINTS=true
# VPC_ENDPOINT_EC2=https://vpce-XXXX.ec2.us-east-1.vpce.amazonaws.com
# VPC_ENDPOINT_SSM=https://vpce-XXXX.ssm.us-east-1.vpce.amazonaws.com
# VPC_ENDPOINT_CLOUDWATCH=https://vpce-XXXX.monitoring.us-east-1.vpce.amazonaws.com
# VPC_ENDPOINT_STS=https://vpce-XXXX.sts.us-east-1.vpce.amazonaws.com
EOF
    echo "  Created default .env at $INSTALL_DIR/.env – edit before starting the service"
fi

echo "==> Fixing permissions"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo "==> Installing systemd service"
cp "$SCRIPT_DIR/systemd/ec2-troubleshooter.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ec2-troubleshooter

echo ""
echo "Installation complete."
echo "Review $INSTALL_DIR/.env then run:"
echo "  sudo systemctl start ec2-troubleshooter"
echo "  sudo systemctl status ec2-troubleshooter"
