# ────────────────────────────────────────────────────────────────────────────
# EC2 Troubleshooter – production Docker image
#
# Designed to run air-gapped: no internet access is assumed at runtime.
# All dependencies are installed from a local pip mirror or baked in.
#
# Build args:
#   PIP_INDEX_URL    – override pip index URL (default: PyPI)
#   PIP_TRUSTED_HOST – mark the mirror host as trusted
# ────────────────────────────────────────────────────────────────────────────

ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim AS base

# System hardening: non-root user
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# ── Build stage ────────────────────────────────────────────────────────────
FROM base AS builder

ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_TRUSTED_HOST=

COPY requirements.txt ./

RUN pip install --upgrade pip --no-cache-dir \
    && pip install \
        ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} \
        ${PIP_TRUSTED_HOST:+--trusted-host "$PIP_TRUSTED_HOST"} \
        --no-cache-dir \
        --prefix=/install \
        -r requirements.txt

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM base AS runtime

COPY --from=builder /install /usr/local

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-deps --no-index -e . 2>/dev/null || \
    PYTHONPATH=/app/src python -c "import ec2_troubleshooter"

USER appuser

EXPOSE 8080

# Default env overrides (can be superseded at runtime)
ENV LOG_FORMAT=json \
    LOG_LEVEL=INFO \
    API_HOST=0.0.0.0 \
    API_PORT=8080 \
    REPORTER_TYPE=log \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python", "-m", "ec2_troubleshooter"]
