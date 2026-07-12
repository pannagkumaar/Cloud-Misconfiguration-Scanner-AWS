"""
CloudTrail Collector - Collects CloudTrail configuration.

Gathers:
- Trails and their configuration (multi-region, log validation, KMS)
- Whether each trail is actively logging

CloudTrail is account-level governance: whether *any* trail exists at
all, and how it's configured, is one of the highest-value CIS checks
since it determines whether the account has any audit trail for API
activity in the first place.
"""

from typing import Any, Dict, List

from botocore.exceptions import ClientError

from cloudscan.collectors.base import BaseCollector


class CloudTrailCollector(BaseCollector):
    """Collects CloudTrail configuration from AWS account."""

    service_name = "cloudtrail"

    def collect(self) -> Dict[str, Any]:
        """
        Collect CloudTrail configuration.

        Returns:
            Dictionary containing CloudTrail configuration
        """
        self.logger.info("Starting CloudTrail collection...")

        try:
            ct_client = self.aws_client.get_client("cloudtrail")

            result = {
                "service": "cloudtrail",
                "trails": self._collect_trails(ct_client),
            }

            self.logger.info(f"CloudTrail collection complete: {len(result['trails'])} trails")

            return result

        except ClientError as e:
            self.logger.error(f"CloudTrail collection failed: {e}")
            raise

    def _collect_trails(self, ct_client) -> List[Dict[str, Any]]:
        """
        Collect trail configurations, including logging status.

        Returns:
            List of trail configurations
        """
        trails = []
        try:
            response = ct_client.describe_trails(includeShadowTrails=False)

            for trail in response.get("trailList", []):
                trail_name = trail.get("Name")
                trail_data = {
                    "name": trail_name,
                    "arn": trail.get("TrailARN", ""),
                    "is_multi_region_trail": trail.get("IsMultiRegionTrail", False),
                    "log_file_validation_enabled": trail.get("LogFileValidationEnabled", False),
                    "kms_key_id": trail.get("KmsKeyId"),
                    "s3_bucket_name": trail.get("S3BucketName"),
                    "include_global_service_events": trail.get("IncludeGlobalServiceEvents", False),
                    "is_logging": False,
                }

                try:
                    status = ct_client.get_trail_status(Name=trail_name)
                    trail_data["is_logging"] = status.get("IsLogging", False)
                except Exception as e:
                    self.logger.debug(f"Error getting trail status for {trail_name}: {e}")

                trails.append(trail_data)

            self.logger.debug(f"Collected {len(trails)} CloudTrail trails")
            return trails

        except Exception as e:
            self.logger.error(f"Error collecting trails: {e}")
            return []
