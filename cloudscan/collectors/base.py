"""
Base collector class for all AWS service collectors.

Each collector follows the same pattern:
1. Read raw AWS configuration
2. Return structured data
3. Handle pagination and errors
4. NO security logic (that's for rules)
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict

from cloudscan.aws_client import AWSClient


class BaseCollector(ABC):
    """Abstract base class for AWS service collectors."""

    service_name: str = "unknown"

    def __init__(self, aws_client: AWSClient):
        """
        Initialize collector.

        Args:
            aws_client: Authenticated AWSClient instance
        """
        self.aws_client = aws_client
        self.logger = logging.getLogger(f"cloudscan.collectors.{self.service_name}")

    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """
        Collect raw AWS configuration.

        This method should:
        - Call appropriate AWS APIs
        - Handle pagination
        - Return structured data
        - NOT perform any security checks

        Returns:
            Dictionary with raw AWS configuration
        """
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"
