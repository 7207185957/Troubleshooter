"""Base reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ec2_troubleshooter.models.findings import InvestigationReport


class BaseReporter(ABC):
    """Send an InvestigationReport to an external system."""

    @abstractmethod
    def send(self, report: InvestigationReport) -> None:
        """Dispatch *report* to the configured destination."""
