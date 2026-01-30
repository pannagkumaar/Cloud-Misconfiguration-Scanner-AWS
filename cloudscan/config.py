"""
Core configuration management for Cloud Misconfiguration Scanner.

Handles loading config.yaml and applying environment variable overrides.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class ScannerConfig:
    """Configuration manager for the scanner."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_path: Path to config.yaml. Defaults to project root.
        """
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config.yaml"

        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, 'r') as f:
            self._config = yaml.safe_load(f) or {}

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to config."""
        # AWS overrides
        if aws_region := os.getenv("AWS_REGION"):
            self._config.setdefault("aws", {})["region"] = aws_region

        if aws_profile := os.getenv("AWS_PROFILE"):
            self._config.setdefault("aws", {})["profile"] = aws_profile

        # Scanner overrides
        if services := os.getenv("SCANNER_SERVICES"):
            self._config.setdefault("scanner", {})["services"] = services.split(",")

    def get_aws_config(self) -> Dict[str, Any]:
        """Get AWS configuration."""
        return self._config.get("aws", {})

    def get_scanner_config(self) -> Dict[str, Any]:
        """Get scanner configuration."""
        return self._config.get("scanner", {})

    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration."""
        return self._config.get("output", {})

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key path (e.g., 'aws.region')."""
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

        return value if value is not None else default

    def __repr__(self) -> str:
        return f"<ScannerConfig {self.config_path}>"
