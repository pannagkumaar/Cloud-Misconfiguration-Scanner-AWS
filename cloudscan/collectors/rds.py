"""
RDS Collector - Collects RDS database configuration.

Gathers:
- RDS instances and their properties
- Encryption configuration
- Public accessibility
- Backup configuration
- Database security groups
- Parameter groups

Only standalone DB instances -- Aurora clusters (describe_db_clusters) are
out of scope since no rule evaluates them yet. Add cluster collection back
if/when cluster-aware rules are written.
"""

from typing import Any, Dict, List

from botocore.exceptions import ClientError

from cloudscan.collectors.base import BaseCollector


class RDSCollector(BaseCollector):
    """Collects RDS configuration from AWS account."""

    service_name = "rds"

    def collect(self) -> Dict[str, Any]:
        """
        Collect RDS configuration.

        Returns:
            Dictionary containing RDS configuration
        """
        self.logger.info("Starting RDS collection...")

        try:
            rds_client = self.aws_client.get_client("rds")

            result = {
                "service": "rds",
                "instances": self._collect_instances(rds_client),
            }

            self.logger.info(f"RDS collection complete: {len(result['instances'])} instances")

            return result

        except ClientError as e:
            self.logger.error(f"RDS collection failed: {e}")
            raise

    def _collect_instances(self, rds_client) -> List[Dict[str, Any]]:
        """
        Collect RDS instance configurations.

        Returns:
            List of RDS instance configurations
        """
        instances = []
        try:
            paginator = rds_client.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for instance in page.get("DBInstances", []):
                    instance_data = {
                        "id": instance["DBInstanceIdentifier"],
                        "engine": instance.get("Engine"),
                        "engine_version": instance.get("EngineVersion"),
                        "status": instance.get("DBInstanceStatus"),
                        "allocated_storage": instance.get("AllocatedStorage"),
                        "instance_class": instance.get("DBInstanceClass"),
                        "publicly_accessible": instance.get("PubliclyAccessible", False),
                        "multi_az": instance.get("MultiAZ", False),
                        "encryption": {
                            "storage_encrypted": instance.get("StorageEncrypted", False),
                            "kms_key_id": instance.get("KmsKeyId"),
                        },
                        "backup": {
                            "backup_retention_period": instance.get("BackupRetentionPeriod"),
                            "backup_window": instance.get("PreferredBackupWindow"),
                            "copy_tags_to_snapshot": instance.get("CopyTagsToSnapshot", False),
                            "deletion_protection": instance.get("DeletionProtection", False),
                        },
                        "network": {
                            "vpc_id": instance.get("DBSubnetGroup", {}).get("VpcId"),
                            "vpc_security_groups": [
                                {
                                    "id": sg["VpcSecurityGroupId"],
                                    "status": sg["Status"]
                                }
                                for sg in instance.get("VpcSecurityGroups", [])
                            ],
                            "db_subnet_group": instance.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                        },
                        "auto_minor_version_upgrade": instance.get("AutoMinorVersionUpgrade"),
                        "tags": {
                            tag["Key"]: tag["Value"]
                            for tag in instance.get("TagList", [])
                        },
                    }

                    instances.append(instance_data)

            self.logger.debug(f"Collected {len(instances)} RDS instances")
            return instances

        except Exception as e:
            self.logger.error(f"Error collecting RDS instances: {e}")
            return []
