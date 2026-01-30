"""
File Loader - Loads configuration from exported JSON/YAML files.

Enables offline analysis and pentesting without AWS credentials.
Perfect for analyzing exported configurations, CloudFormation templates, etc.
"""

import logging
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from cloudscan.loaders.base import BaseLoader


logger = logging.getLogger(__name__)


class FileLoader(BaseLoader):
    """Loads configuration from JSON or YAML files."""

    SUPPORTED_FORMATS = {".json", ".yaml", ".yml"}

    def __init__(self, file_path: str):
        """
        Initialize file loader.

        Args:
            file_path: Path to JSON or YAML configuration file
        """
        super().__init__()
        self.file_path = Path(file_path)
        
        if not self.file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        if self.file_path.suffix.lower() not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format: {self.file_path.suffix}. "
                f"Supported: {', '.join(self.SUPPORTED_FORMATS)}"
            )

    def load(self) -> Dict[str, Any]:
        """
        Load configuration from file.

        Returns:
            Dictionary with configuration data
        """
        self.logger.info(f"Loading configuration from {self.file_path}")
        
        try:
            data = self._load_file()
            
            if self.validate_structure(data):
                self.logger.info(
                    f"Successfully loaded {len(data['services'])} services "
                    f"from {self.file_path.name}"
                )
                return data
            else:
                raise ValueError("File data failed validation")
                
        except Exception as e:
            self.logger.error(f"Failed to load from file: {e}")
            raise

    def _load_file(self) -> Dict[str, Any]:
        """
        Load and parse file based on extension.

        Returns:
            Parsed configuration dictionary

        Raises:
            ValueError: If file format is invalid or parsing fails
        """
        suffix = self.file_path.suffix.lower()
        
        try:
            with open(self.file_path, "r") as f:
                if suffix == ".json":
                    return json.load(f)
                elif suffix in {".yaml", ".yml"}:
                    return yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported format: {suffix}")
                    
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {self.file_path.name}: {e}")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {self.file_path.name}: {e}")
