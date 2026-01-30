"""
Collector Manager - Coordinates collection across all AWS services.

Orchestrates the execution of multiple collectors and aggregates results.
"""

import logging
from typing import Dict, Any, List, Optional
from cloudscan.aws_client import AWSClient
from cloudscan.collectors.iam import IAMCollector
from cloudscan.collectors.s3 import S3Collector
from cloudscan.collectors.ec2 import EC2Collector
from cloudscan.collectors.rds import RDSCollector


logger = logging.getLogger(__name__)


class CollectorManager:
    """Manages all service collectors."""

    AVAILABLE_COLLECTORS = {
        "iam": IAMCollector,
        "s3": S3Collector,
        "ec2": EC2Collector,
        "rds": RDSCollector,
    }

    def __init__(self, aws_client: AWSClient):
        """
        Initialize collector manager.

        Args:
            aws_client: Authenticated AWSClient instance
        """
        self.aws_client = aws_client
        self.logger = logging.getLogger("cloudscan.collectors")

    def collect_all(self, services: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect configuration from all specified services.

        Args:
            services: List of services to collect (default: all available)

        Returns:
            Dictionary containing all collected configurations
        """
        if services is None:
            services = list(self.AVAILABLE_COLLECTORS.keys())

        self.logger.info(f"Starting collection for services: {', '.join(services)}")

        collected_data = {
            "services": services,
            "data": {},
        }

        for service in services:
            if service not in self.AVAILABLE_COLLECTORS:
                self.logger.warning(f"Unknown service: {service}")
                continue

            try:
                self.logger.info(f"Collecting {service}...")
                collector_class = self.AVAILABLE_COLLECTORS[service]
                collector = collector_class(self.aws_client)
                collected_data["data"][service] = collector.collect()

            except Exception as e:
                self.logger.error(f"Failed to collect {service}: {e}")
                collected_data["data"][service] = {
                    "error": str(e),
                    "service": service,
                }

        self.logger.info("Collection complete")
        return collected_data
