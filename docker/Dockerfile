# ──────────────────────────────────────────────────────────────────────────────
# EC2 Troubleshooter – production Docker image
#
# Two-stage build:
#   builder – installs Python dependencies (can use internal PyPI mirror)
#   runtime – minimal image, non-root, no build tools
#
# Build args
#   PYTHON_VERSION   – Python base image tag  (default: 3.12-slim)
#   PIP_INDEX_URL    – pip index URL           (default: https://pypi.org/simple)
#   PIP_TRUSTED_HOST – mark the mirror trusted (default: empty)
#
# Air-gapped usage
#   Build on a machine WITH internet, push to ECR, pull on the air-gapped EC2.
#   The running container never needs outbound internet access – all AWS calls
#   go through VPC Interface Endpoints and Mimir is an internal URL.
#
# Example (standard build, push to ECR)
#   docker build -t ec2-troubleshooter:latest .
#   docker tag  ec2-troubleshooter:latest 123456789.dkr.ecr.us-east-1.amazonaws.com/ec2-troubleshooter:latest
#   docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/ec2-troubleshooter:latest
#
# Example (internal pip mirror)
#   docker build \
#     --build-arg PIP_INDEX_URL=http://pypi.internal/simple \
#     --build-arg PIP_TRUSTED_HOST=pypi.internal \
#     -t ec2-troubleshooter:latest .
# ──────────────────────────────────────────────────────────────────────────────

ARG PYTHON_VERSION=3.12-slim

# ── Stage 1: dependency builder ────────────────────────────────────────────
FROM python:${PYTHON_VERSION} AS builder

ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_TRUSTED_HOST=

WORKDIR /build

COPY requirements.txt .

RUN pip install --upgrade pip --no-cache-dir \
    && pip install \
        --no-cache-dir \
        --prefix=/install \
        ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} \
        ${PIP_TRUSTED_HOST:+--trusted-host "$PIP_TRUSTED_HOST"} \
        -r requirements.txt

# ── Stage 2: runtime image ─────────────────────────────────────────────────
FROM python:${PYTHON_VERSION} AS runtime

# Non-root user for security hardening
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package itself (no deps, already installed above)
RUN pip install --no-cache-dir --no-deps -e . \
    && python -c "import ec2_troubleshooter; print('import OK')"

USER appuser

EXPOSE 8080

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_FORMAT=json \
    LOG_LEVEL=INFO \
    API_HOST=0.0.0.0 \
    API_PORT=8080 \
    REPORTER_TYPE=log

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python", "-m", "ec2_troubleshooter"]
