"""
RDS Collector - Collects RDS database configuration.

Gathers:
- RDS instances and their properties
- Encryption configuration
- Public accessibility
- Backup configuration
- Database security groups
- Parameter groups
"""

from typing import Dict, Any, List
import logging
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
                "clusters": self._collect_clusters(rds_client),
            }

            self.logger.info(
                f"RDS collection complete: {len(result['instances'])} instances, "
                f"{len(result['clusters'])} clusters"
            )

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

    def _collect_clusters(self, rds_client) -> List[Dict[str, Any]]:
        """
        Collect RDS cluster configurations.

        Returns:
            List of RDS cluster configurations
        """
        clusters = []
        try:
            paginator = rds_client.get_paginator("describe_db_clusters")

            for page in paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    cluster_data = {
                        "id": cluster["DBClusterIdentifier"],
                        "engine": cluster.get("Engine"),
                        "engine_version": cluster.get("EngineVersion"),
                        "status": cluster.get("Status"),
                        "publicly_accessible": cluster.get("PubliclyAccessible", False),
                        "encryption": {
                            "storage_encrypted": cluster.get("StorageEncrypted", False),
                            "kms_key_id": cluster.get("KmsKeyId"),
                        },
                        "backup": {
                            "backup_retention_period": cluster.get("BackupRetentionPeriod"),
                            "backup_window": cluster.get("PreferredBackupWindow"),
                            "copy_tags_to_snapshot": cluster.get("CopyTagsToSnapshot", False),
                            "deletion_protection": cluster.get("DeletionProtection", False),
                        },
                        "network": {
                            "vpc_id": cluster.get("DBSubnetGroup"),
                            "vpc_security_groups": [
                                {
                                    "id": sg["VpcSecurityGroupId"],
                                    "status": sg["Status"]
                                }
                                for sg in cluster.get("VpcSecurityGroups", [])
                            ],
                        },
                        "members": [
                            {
                                "db_instance_identifier": member["DBInstanceIdentifier"],
                                "is_cluster_writer": member.get("IsClusterWriter", False),
                            }
                            for member in cluster.get("DBClusterMembers", [])
                        ],
                        "tags": {
                            tag["Key"]: tag["Value"]
                            for tag in cluster.get("TagList", [])
                        },
                    }

                    clusters.append(cluster_data)

            self.logger.debug(f"Collected {len(clusters)} RDS clusters")
            return clusters

        except Exception as e:
            self.logger.error(f"Error collecting RDS clusters: {e}")
            return []
