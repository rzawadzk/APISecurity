"""Base log parser interface."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from ..models import AuthMethod, TrafficRecord


class BaseLogParser(ABC):
    """Abstract base for all log parsers."""

    @abstractmethod
    def parse_line(self, line: str) -> TrafficRecord | None:
        """Parse a single log line into a TrafficRecord, or None if unparseable."""

    def parse_file(self, path: Path) -> Iterator[TrafficRecord]:
        """Parse an entire log file, yielding TrafficRecords."""
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = self.parse_line(line)
                if record:
                    yield record

    @staticmethod
    def detect_auth_method(headers_or_line: str) -> AuthMethod:
        """Detect authentication method from log line or header info."""
        lower = headers_or_line.lower()
        if "bearer " in lower:
            return AuthMethod.BEARER
        if "apikey" in lower or "x-api-key" in lower:
            return AuthMethod.API_KEY
        if "basic " in lower:
            return AuthMethod.BASIC
        if "authorization" not in lower:
            return AuthMethod.NONE
        return AuthMethod.UNKNOWN
