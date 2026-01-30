"""
Base loader for configuration data sources.

Provides abstract interface for loading configurations from different sources
(AWS APIs, JSON files, CloudFormation exports, etc.).
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import logging


logger = logging.getLogger(__name__)


class BaseLoader(ABC):
    """Abstract base class for configuration loaders."""

    def __init__(self):
        """Initialize loader."""
        self.logger = logging.getLogger(f"cloudscan.loaders.{self.__class__.__name__}")

    @abstractmethod
    def load(self) -> Dict[str, Any]:
        """
        Load configuration data.

        Returns:
            Dictionary containing collected configurations with structure:
            {
                "services": ["iam", "s3", "ec2", "rds"],
                "data": {
                    "iam": {...},
                    "s3": {...},
                    "ec2": {...},
                    "rds": {...}
                }
            }
        """
        pass

    def validate_structure(self, data: Dict[str, Any]) -> bool:
        """
        Validate that loaded data has required structure.

        Args:
            data: Configuration data to validate

        Returns:
            True if valid, False otherwise
        """
        required_keys = {"services", "data"}
        if not all(key in data for key in required_keys):
            self.logger.error(f"Missing required keys. Expected {required_keys}, got {set(data.keys())}")
            return False

        if not isinstance(data.get("services"), list):
            self.logger.error("'services' must be a list")
            return False

        if not isinstance(data.get("data"), dict):
            self.logger.error("'data' must be a dictionary")
            return False

        return True
