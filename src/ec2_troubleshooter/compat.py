"""
Python version compatibility shims.

StrEnum was added to the standard library in Python 3.11.
For Python 3.10 we provide a functionally identical drop-in.
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum  # noqa: F401  (re-export)
else:
    from enum import Enum

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """Backport of Python 3.11 StrEnum for Python 3.10."""

        def __str__(self) -> str:
            return self.value
