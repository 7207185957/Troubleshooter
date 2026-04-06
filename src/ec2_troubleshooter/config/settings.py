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
    VPC_ENDPOINT_CLOUDWATCH     – https://vpce-xxx.monitoring.us-east-1.vpce.amazonaws.com
    VPC_ENDPOINT_STS            – https://vpce-xxx.sts.us-east-1.vpce.amazonaws.com
    SSM_POLL_INTERVAL_SEC       – seconds between SSM command status polls (default: 3)
    SSM_MAX_WAIT_SEC            – maximum seconds to wait for SSM result (default: 120)
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
    vpc_endpoint_cloudwatch: str | None = Field(default=None, alias="VPC_ENDPOINT_CLOUDWATCH")
    vpc_endpoint_sts: str | None = Field(default=None, alias="VPC_ENDPOINT_STS")

    # ── SSM command execution settings ───────────────────────────────────
    ssm_poll_interval_sec: float = Field(default=3.0, alias="SSM_POLL_INTERVAL_SEC")
    ssm_max_wait_sec: float = Field(default=120.0, alias="SSM_MAX_WAIT_SEC")

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
    @field_validator("reporter_webhook_headers", mode="before")
    @classmethod
    def parse_headers(cls, v: object) -> dict[str, str]:
        if isinstance(v, str):
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
        """Return the VPC endpoint URL override for *service* (ec2, ssm, cloudwatch, sts)."""
        if not self.use_vpc_endpoints:
            return None
        mapping = {
            "ec2": self.vpc_endpoint_ec2,
            "ssm": self.vpc_endpoint_ssm,
            "cloudwatch": self.vpc_endpoint_cloudwatch,
            "monitoring": self.vpc_endpoint_cloudwatch,
            "sts": self.vpc_endpoint_sts,
        }
        return mapping.get(service)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
