"""
Output formatters base class and utilities.

Handles different output formats (console, JSON, SARIF).
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from cloudscan.engine.finding import Finding


class BaseOutputFormatter(ABC):
    """Abstract base class for output formatters."""

    def __init__(self, output_file: Optional[str] = None):
        """
        Initialize formatter.

        Args:
            output_file: Optional file to write output to
        """
        self.output_file = output_file

    @abstractmethod
    def format(self, findings: List[Finding]) -> str:
        """
        Format findings for output.

        Args:
            findings: List of findings to format

        Returns:
            Formatted output string
        """
        pass

    def write(self, content: str) -> None:
        """Write content to file or print to stdout."""
        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(content)
        else:
            print(content)

    def _get_severity_count(self, findings: List[Finding]) -> dict:
        """Count findings by severity."""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for finding in findings:
            counts[finding.severity.value] += 1

        return counts
