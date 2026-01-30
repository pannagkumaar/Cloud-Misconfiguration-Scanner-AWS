"""
S3 Collector - Collects S3 bucket configuration.

Gathers:
- S3 buckets and their properties
- Bucket policies
- ACLs
- Public access blocks
- Versioning and logging
- Encryption configuration
- Server access logging
"""

from typing import Dict, Any, List
import json
import logging
from botocore.exceptions import ClientError
from cloudscan.collectors.base import BaseCollector


class S3Collector(BaseCollector):
    """Collects S3 configuration from AWS account."""

    service_name = "s3"

    def collect(self) -> Dict[str, Any]:
        """
        Collect S3 configuration.

        Returns:
            Dictionary containing S3 configuration
        """
        self.logger.info("Starting S3 collection...")

        try:
            s3_client = self.aws_client.get_client("s3")

            result = {
                "service": "s3",
                "buckets": self._collect_buckets(s3_client),
            }

            self.logger.info(f"S3 collection complete: {len(result['buckets'])} buckets")

            return result

        except ClientError as e:
            self.logger.error(f"S3 collection failed: {e}")
            raise

    def _collect_buckets(self, s3_client) -> List[Dict[str, Any]]:
        """
        Collect S3 bucket configurations.

        Returns:
            List of bucket configurations
        """
        buckets = []
        try:
            # List all buckets
            response = s3_client.list_buckets()

            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_data = {
                    "name": bucket_name,
                    "created": bucket["CreationDate"].isoformat(),
                    "region": self._get_bucket_region(s3_client, bucket_name),
                    "policy": None,
                    "acl": None,
                    "public_access_block": None,
                    "versioning": None,
                    "logging": None,
                    "encryption": None,
                    "tags": None,
                }

                # Get bucket policy
                try:
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    bucket_data["policy"] = json.loads(
                        policy_response.get("Policy", "{}")
                    )
                except s3_client.exceptions.NoSuchBucketPolicy:
                    bucket_data["policy"] = None
                except Exception as e:
                    self.logger.debug(f"Error getting policy for {bucket_name}: {e}")

                # Get bucket ACL
                try:
                    acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                    bucket_data["acl"] = {
                        "owner": acl_response.get("Owner", {}),
                        "grants": acl_response.get("Grants", []),
                    }
                except Exception as e:
                    self.logger.debug(f"Error getting ACL for {bucket_name}: {e}")

                # Get public access block
                try:
                    pub_block_response = s3_client.get_public_access_block(
                        Bucket=bucket_name
                    )
                    bucket_data["public_access_block"] = {
                        "block_public_acls": pub_block_response.get(
                            "PublicAccessBlockConfiguration", {}
                        ).get("BlockPublicAcls"),
                        "ignore_public_acls": pub_block_response.get(
                            "PublicAccessBlockConfiguration", {}
                        ).get("IgnorePublicAcls"),
                        "block_public_policy": pub_block_response.get(
                            "PublicAccessBlockConfiguration", {}
                        ).get("BlockPublicPolicy"),
                        "restrict_public_buckets": pub_block_response.get(
                            "PublicAccessBlockConfiguration", {}
                        ).get("RestrictPublicBuckets"),
                    }
                except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    bucket_data["public_access_block"] = {
                        "block_public_acls": False,
                        "ignore_public_acls": False,
                        "block_public_policy": False,
                        "restrict_public_buckets": False,
                    }
                except Exception as e:
                    self.logger.debug(f"Error getting public access block for {bucket_name}: {e}")

                # Get versioning
                try:
                    versioning_response = s3_client.get_bucket_versioning(
                        Bucket=bucket_name
                    )
                    bucket_data["versioning"] = {
                        "status": versioning_response.get("Status"),
                        "mfa_delete": versioning_response.get("MFADelete"),
                    }
                except Exception as e:
                    self.logger.debug(f"Error getting versioning for {bucket_name}: {e}")

                # Get logging
                try:
                    logging_response = s3_client.get_bucket_logging(Bucket=bucket_name)
                    bucket_data["logging"] = logging_response.get(
                        "LoggingEnabled", {}
                    )
                except Exception as e:
                    self.logger.debug(f"Error getting logging for {bucket_name}: {e}")

                # Get encryption
                try:
                    encryption_response = s3_client.get_bucket_encryption(
                        Bucket=bucket_name
                    )
                    bucket_data["encryption"] = encryption_response.get(
                        "ServerSideEncryptionConfiguration", {}
                    )
                except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    bucket_data["encryption"] = None
                except Exception as e:
                    self.logger.debug(f"Error getting encryption for {bucket_name}: {e}")

                # Get tags
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    bucket_data["tags"] = {
                        tag["Key"]: tag["Value"]
                        for tag in tags_response.get("TagSet", [])
                    }
                except s3_client.exceptions.NoSuchTagSet:
                    bucket_data["tags"] = {}
                except Exception as e:
                    self.logger.debug(f"Error getting tags for {bucket_name}: {e}")

                buckets.append(bucket_data)

            self.logger.debug(f"Collected {len(buckets)} S3 buckets")
            return buckets

        except Exception as e:
            self.logger.error(f"Error collecting buckets: {e}")
            return []

    def _get_bucket_region(self, s3_client, bucket_name: str) -> str:
        """
        Get S3 bucket region.

        Args:
            s3_client: S3 client instance
            bucket_name: Name of the bucket

        Returns:
            Bucket region name
        """
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            region = response.get("LocationConstraint")
            # us-east-1 returns None
            return region or "us-east-1"

        except Exception as e:
            self.logger.debug(f"Error getting region for {bucket_name}: {e}")
            return "unknown"
