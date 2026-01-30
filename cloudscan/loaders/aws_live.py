"""
AWS Live Loader - Loads configuration directly from AWS APIs.

This is the original collector-based approach, now wrapped in the loader interface.
Requires AWS credentials.
"""

import logging
from typing import Dict, Any, Optional, List
from cloudscan.loaders.base import BaseLoader
from cloudscan.aws_client import AWSClient
from cloudscan.collectors.manager import CollectorManager


logger = logging.getLogger(__name__)


class AWSLiveLoader(BaseLoader):
    """Loads configuration directly from AWS APIs using boto3."""

    def __init__(
        self,
        aws_client: AWSClient,
        services: Optional[List[str]] = None
    ):
        """
        Initialize AWS live loader.

        Args:
            aws_client: Authenticated AWSClient instance
            services: List of services to collect (default: all)
        """
        super().__init__()
        self.aws_client = aws_client
        self.services = services or ["iam", "s3", "ec2", "rds"]
        self.manager = CollectorManager(aws_client)

    def load(self) -> Dict[str, Any]:
        """
        Load configuration directly from AWS APIs.

        Returns:
            Dictionary with collected configurations
        """
        self.logger.info("Loading configuration from AWS APIs")
        
        try:
            data = self.manager.collect_all(self.services)
            
            if self.validate_structure(data):
                self.logger.info(f"Successfully loaded {len(data['services'])} services from AWS")
                return data
            else:
                raise ValueError("Collected data failed validation")
                
        except Exception as e:
            self.logger.error(f"Failed to load from AWS: {e}")
            raise
