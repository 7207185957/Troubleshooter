"""
AWS client factory.

In air-gapped VPC environments boto3 must use VPC interface endpoints instead
of the public AWS service endpoints.  This factory injects the correct
endpoint_url for every service client based on settings so the rest of the
code never has to worry about it.
"""

from __future__ import annotations

import boto3
from botocore.config import Config

from ec2_troubleshooter.config import Settings

# Shared botocore retry config – conservative in air-gapped envs where the
# network is reliable but the SSM agent may be slow.
_RETRY_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=10,
    read_timeout=30,
)


class AWSClientFactory:
    """Creates boto3 clients pre-configured for VPC-endpoint routing."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._session = self._build_session()

    def _build_session(self) -> boto3.Session:
        kwargs: dict[str, str] = {"region_name": self._settings.aws_region}
        if self._settings.aws_profile:
            kwargs["profile_name"] = self._settings.aws_profile
        return boto3.Session(**kwargs)

    def _client(self, service: str) -> boto3.client:  # type: ignore[name-defined]
        endpoint_url = self._settings.endpoint_for(service)
        kwargs: dict = {"config": _RETRY_CONFIG}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        return self._session.client(service, **kwargs)

    @property
    def ec2(self) -> boto3.client:  # type: ignore[name-defined]
        return self._client("ec2")

    @property
    def ssm(self) -> boto3.client:  # type: ignore[name-defined]
        return self._client("ssm")

    @property
    def sts(self) -> boto3.client:  # type: ignore[name-defined]
        return self._client("sts")
