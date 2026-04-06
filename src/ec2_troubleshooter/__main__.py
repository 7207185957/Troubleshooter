"""Entry point: python -m ec2_troubleshooter"""

from __future__ import annotations

import uvicorn

from ec2_troubleshooter.alert.receiver import create_app
from ec2_troubleshooter.config import get_settings
from ec2_troubleshooter.config.logging import configure_logging


def main() -> None:
    settings = get_settings()
    configure_logging(settings)
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,  # let structlog handle logging
    )


if __name__ == "__main__":
    main()
