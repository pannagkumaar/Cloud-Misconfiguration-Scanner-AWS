"""
Scan context - Represents the AWS configuration being scanned.

Provides rule engines with access to collected AWS data.
"""

from typing import Dict, Any, Optional
import logging


logger = logging.getLogger(__name__)


class ScanContext:
    """Context object containing collected AWS configuration."""

    def __init__(self, account_id: str, region: str, collected_data: Dict[str, Any]):
        """
        Initialize scan context.

        Args:
            account_id: AWS account ID
            region: AWS region
            collected_data: Data from collectors
        """
        self.account_id = account_id
        self.region = region
        self._data = collected_data

    def get_service_data(self, service: str) -> Dict[str, Any]:
        """
        Get data for a specific service.

        Args:
            service: Service name (iam, s3, ec2, rds)

        Returns:
            Service data dictionary
        """
        service_data = self._data.get("data", {}).get(service, {})
        if "error" in service_data:
            logger.warning(f"No data available for {service}: {service_data['error']}")
            return {}
        return service_data

    def get_iam_users(self) -> list:
        """Get all IAM users."""
        return self.get_service_data("iam").get("users", [])

    def get_iam_roles(self) -> list:
        """Get all IAM roles."""
        return self.get_service_data("iam").get("roles", [])

    def get_iam_policies(self) -> list:
        """Get all customer-managed IAM policies."""
        return self.get_service_data("iam").get("policies", [])

    def get_credential_report(self) -> Dict[str, Any]:
        """Get IAM credential report metadata."""
        return self.get_service_data("iam").get("credential_report", {})

    def get_s3_buckets(self) -> list:
        """Get all S3 buckets."""
        return self.get_service_data("s3").get("buckets", [])

    def get_security_groups(self) -> list:
        """Get all EC2 security groups."""
        return self.get_service_data("ec2").get("security_groups", [])

    def get_ec2_instances(self) -> list:
        """Get all EC2 instances."""
        return self.get_service_data("ec2").get("instances", [])

    def get_rds_instances(self) -> list:
        """Get all RDS instances."""
        return self.get_service_data("rds").get("instances", [])

    def get_rds_clusters(self) -> list:
        """Get all RDS clusters."""
        return self.get_service_data("rds").get("clusters", [])

    def __repr__(self) -> str:
        return f"<ScanContext account={self.account_id} region={self.region}>"
