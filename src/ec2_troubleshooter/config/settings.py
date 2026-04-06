"""
Settings module.

All AWS calls are routed through VPC endpoints when running in an air-gapped
EC2 environment.  Set USE_VPC_ENDPOINTS=true and supply the endpoint URL
overrides so that boto3 never tries to resolve public AWS hostnames.

Environment variables (can also be provided via a .env file):

    AWS_REGION                  – AWS region (default: us-east-1)
    AWS_PROFILE                 – optional named profile
    USE_VPC_ENDPOINTS           – route all SDK calls through VPC endpoints
    VPC_ENDPOINT_EC2            – https://vpce-xxx.ec2.us-east-1.vpce.amazonaws.com
    VPC_ENDPOINT_SSM            – https://vpce-xxx.ssm.us-east-1.vpce.amazonaws.com
    VPC_ENDPOINT_STS            – https://vpce-xxx.sts.us-east-1.vpce.amazonaws.com
    SSM_POLL_INTERVAL_SEC       – seconds between SSM command status polls (default: 3)
    SSM_MAX_WAIT_SEC            – maximum seconds to wait for SSM result (default: 120)

    ── Prometheus / Grafana Mimir (multi-tenant) ──────────────────────────────

    PROMETHEUS_URL              – Base URL shared by all Mimir tenants
                                  e.g. http://mimir.internal:8080/prometheus
    PROMETHEUS_INFRA_ORG_ID     – X-Scope-OrgID for infra/node_exporter metrics
                                  (cpu, memory, disk, network)
    PROMETHEUS_APP_ORG_IDS      – JSON object mapping archetype → org ID for
                                  application metrics.  The archetype is matched
                                  against alert.archetype.  A special key "_default"
                                  is used when no specific match is found.
                                  Example:
                                    {"platform-mimir":"mimir-app","airflow":"airflow-app",
                                     "_default":"app-metrics"}
    PROMETHEUS_USERNAME         – Basic-auth username (optional, applied to all tenants)
    PROMETHEUS_PASSWORD         – Basic-auth password (optional)
    PROMETHEUS_TOKEN            – Bearer token (optional; used instead of basic auth)
    PROMETHEUS_INSTANCE_LABEL   – Label name that identifies an instance by IP in your
                                  metric series (default: instance).  Typically this is
                                  the value node_exporter exposes, e.g. "10.0.1.5:9100".
    PROMETHEUS_LOOKBACK_MINUTES – How many minutes of history to query (default: 60)
    PROMETHEUS_STEP_SECONDS     – Resolution step for range queries in seconds (default: 60)
    PROMETHEUS_VERIFY_SSL       – Verify TLS certificates (default: true).  Set to false
                                  for internal CAs in air-gapped environments.
    PROMETHEUS_CA_CERT          – Path to a custom CA bundle file (optional)
    PROMETHEUS_TIMEOUT_SEC      – HTTP timeout for Prometheus queries (default: 30)

    ── Alert queue ────────────────────────────────────────────────────────────

    ALERT_QUEUE_MAX_SIZE        – Maximum number of pending alerts in the queue
                                  before new arrivals are rejected (default: 1000)
    ALERT_QUEUE_WORKERS         – Number of concurrent investigation workers
                                  consuming from the queue (default: 4)
    ALERT_QUEUE_RETRY_ATTEMPTS  – How many times to retry a failed investigation
                                  before discarding (default: 2)

    ── Reporter ───────────────────────────────────────────────────────────────

    REPORTER_TYPE               – gchat | webhook | log  (default: log)
    REPORTER_GCHAT_WEBHOOK_URL  – GChat incoming webhook URL
    REPORTER_WEBHOOK_URL        – generic webhook URL for custom integrations
    REPORTER_WEBHOOK_HEADERS    – JSON string of extra headers for the webhook
    API_HOST                    – bind host for the alert receiver FastAPI app
    API_PORT                    – bind port (default: 8080)
    API_SECRET_TOKEN            – bearer token for inbound alert API (optional)
    LOG_LEVEL                   – DEBUG | INFO | WARNING | ERROR (default: INFO)
    LOG_FORMAT                  – json | console (default: json)
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── AWS ──────────────────────────────────────────────────────────────────
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    aws_profile: str | None = Field(default=None, alias="AWS_PROFILE")

    # ── VPC endpoint overrides (air-gapped) ───────────────────────────────
    use_vpc_endpoints: bool = Field(default=False, alias="USE_VPC_ENDPOINTS")
    vpc_endpoint_ec2: str | None = Field(default=None, alias="VPC_ENDPOINT_EC2")
    vpc_endpoint_ssm: str | None = Field(default=None, alias="VPC_ENDPOINT_SSM")
    vpc_endpoint_sts: str | None = Field(default=None, alias="VPC_ENDPOINT_STS")

    # ── SSM command execution settings ───────────────────────────────────
    ssm_poll_interval_sec: float = Field(default=3.0, alias="SSM_POLL_INTERVAL_SEC")
    ssm_max_wait_sec: float = Field(default=120.0, alias="SSM_MAX_WAIT_SEC")

    # ── Prometheus / Grafana Mimir (multi-tenant) ─────────────────────────
    prometheus_url: str | None = Field(default=None, alias="PROMETHEUS_URL")

    # Infra org — node_exporter, cpu/memory/disk metrics
    prometheus_infra_org_id: str | None = Field(
        default=None, alias="PROMETHEUS_INFRA_ORG_ID"
    )

    # App org mapping: archetype → X-Scope-OrgID
    # Parsed from JSON string: {"platform-mimir": "mimir-app", "_default": "app-metrics"}
    prometheus_app_org_ids: dict[str, str] = Field(
        default_factory=dict, alias="PROMETHEUS_APP_ORG_IDS"
    )

    # Legacy single org ID – used as fallback when the specific fields are absent
    prometheus_org_id: str | None = Field(default=None, alias="PROMETHEUS_ORG_ID")

    prometheus_username: str | None = Field(default=None, alias="PROMETHEUS_USERNAME")
    prometheus_password: str | None = Field(default=None, alias="PROMETHEUS_PASSWORD")
    prometheus_token: str | None = Field(default=None, alias="PROMETHEUS_TOKEN")
    prometheus_instance_label: str = Field(
        default="instance", alias="PROMETHEUS_INSTANCE_LABEL"
    )
    prometheus_lookback_minutes: int = Field(
        default=60, alias="PROMETHEUS_LOOKBACK_MINUTES"
    )
    prometheus_step_seconds: int = Field(default=60, alias="PROMETHEUS_STEP_SECONDS")
    prometheus_verify_ssl: bool = Field(default=True, alias="PROMETHEUS_VERIFY_SSL")
    prometheus_ca_cert: str | None = Field(default=None, alias="PROMETHEUS_CA_CERT")
    prometheus_timeout_sec: float = Field(default=30.0, alias="PROMETHEUS_TIMEOUT_SEC")

    # ── Alert queue ───────────────────────────────────────────────────────
    alert_queue_max_size: int = Field(default=1000, alias="ALERT_QUEUE_MAX_SIZE")
    alert_queue_workers: int = Field(default=4, alias="ALERT_QUEUE_WORKERS")
    alert_queue_retry_attempts: int = Field(default=2, alias="ALERT_QUEUE_RETRY_ATTEMPTS")

    # ── Reporter ─────────────────────────────────────────────────────────
    reporter_type: Literal["gchat", "webhook", "log"] = Field(
        default="log", alias="REPORTER_TYPE"
    )
    reporter_gchat_webhook_url: str | None = Field(
        default=None, alias="REPORTER_GCHAT_WEBHOOK_URL"
    )
    reporter_webhook_url: str | None = Field(default=None, alias="REPORTER_WEBHOOK_URL")
    reporter_webhook_headers: dict[str, str] = Field(
        default_factory=dict, alias="REPORTER_WEBHOOK_HEADERS"
    )

    # ── Alert receiver API ────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8080, alias="API_PORT")
    api_secret_token: str | None = Field(default=None, alias="API_SECRET_TOKEN")

    # ── Logging ───────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", alias="LOG_LEVEL"
    )
    log_format: Literal["json", "console"] = Field(default="json", alias="LOG_FORMAT")

    # ── Validators ────────────────────────────────────────────────────────

    @field_validator(
        "reporter_type",
        "log_level",
        "log_format",
        "aws_region",
        "aws_profile",
        "prometheus_url",
        "prometheus_infra_org_id",
        "prometheus_org_id",
        "prometheus_username",
        "prometheus_password",
        "prometheus_token",
        "prometheus_instance_label",
        "prometheus_ca_cert",
        "reporter_gchat_webhook_url",
        "reporter_webhook_url",
        "api_secret_token",
        "vpc_endpoint_ec2",
        "vpc_endpoint_ssm",
        "vpc_endpoint_sts",
        mode="before",
    )
    @classmethod
    def strip_inline_comments(cls, v: object) -> object:
        """
        Strip inline comments and surrounding whitespace from string env values.

        .env files sometimes have lines like:
            REPORTER_TYPE=log          # or gchat / webhook
            LOG_LEVEL=INFO             # DEBUG | INFO | WARNING | ERROR

        python-dotenv passes the full string including the comment to pydantic,
        which then fails validation.  This validator strips everything from the
        first ' #' onwards and trims whitespace, so both forms work:
            REPORTER_TYPE=log
            REPORTER_TYPE=log   # inline comment
        """
        if isinstance(v, str):
            # Strip inline comment: everything from first ' #' to end of line
            if " #" in v:
                v = v[: v.index(" #")]
            return v.strip()
        return v

    @field_validator("reporter_webhook_headers", "prometheus_app_org_ids", mode="before")
    @classmethod
    def parse_json_dict(cls, v: object) -> dict:
        if isinstance(v, str):
            # Strip inline comments before JSON parsing
            if " #" in v:
                v = v[: v.index(" #")].strip()
            return json.loads(v)  # type: ignore[no-any-return]
        if isinstance(v, dict):
            return v  # type: ignore[return-value]
        return {}

    @model_validator(mode="after")
    def validate_reporter(self) -> Settings:
        if self.reporter_type == "gchat" and not self.reporter_gchat_webhook_url:
            raise ValueError(
                "REPORTER_GCHAT_WEBHOOK_URL must be set when REPORTER_TYPE=gchat"
            )
        if self.reporter_type == "webhook" and not self.reporter_webhook_url:
            raise ValueError(
                "REPORTER_WEBHOOK_URL must be set when REPORTER_TYPE=webhook"
            )
        return self

    def endpoint_for(self, service: str) -> str | None:
        """Return the VPC endpoint URL override for *service* (ec2, ssm, sts)."""
        if not self.use_vpc_endpoints:
            return None
        mapping = {
            "ec2": self.vpc_endpoint_ec2,
            "ssm": self.vpc_endpoint_ssm,
            "sts": self.vpc_endpoint_sts,
        }
        return mapping.get(service)

    def infra_org_id(self) -> str | None:
        """Return the X-Scope-OrgID to use for infra/node_exporter queries."""
        return self.prometheus_infra_org_id or self.prometheus_org_id

    def app_org_id_for(self, archetype: str | None) -> str | None:
        """
        Return the X-Scope-OrgID for app metrics belonging to *archetype*.

        Lookup order:
          1. Exact archetype match in prometheus_app_org_ids
          2. Prefix match (e.g. "platform-mimir" matches "platform-mimir (use1)")
          3. "_default" key in prometheus_app_org_ids
          4. Legacy prometheus_org_id fallback
        """
        if not self.prometheus_app_org_ids:
            return self.prometheus_org_id

        if archetype:
            # Exact match
            if archetype in self.prometheus_app_org_ids:
                return self.prometheus_app_org_ids[archetype]
            # Prefix match (alert archetype may include region like "(use1)")
            for key, org in self.prometheus_app_org_ids.items():
                if key != "_default" and archetype.startswith(key):
                    return org

        return self.prometheus_app_org_ids.get("_default") or self.prometheus_org_id


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
