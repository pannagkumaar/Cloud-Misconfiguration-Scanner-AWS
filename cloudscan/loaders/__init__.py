"""
Loaders package - Configuration data source abstraction.

Provides multiple ways to load AWS configuration data:
- AWSLiveLoader: Direct AWS API access (requires credentials)
- FileLoader: From exported JSON/YAML files (offline, no credentials needed)
"""

from cloudscan.loaders.base import BaseLoader
from cloudscan.loaders.aws_live import AWSLiveLoader
from cloudscan.loaders.file_loader import FileLoader

__all__ = ["BaseLoader", "AWSLiveLoader", "FileLoader"]
