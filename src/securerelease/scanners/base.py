from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from securerelease.models import Finding


class RepositoryScanner(ABC):
    """Interface implemented by optional repository-scanning engines."""

    name: str
    executable: str

    def available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def scan(self, source: Path) -> list[Finding]:
        raise NotImplementedError
