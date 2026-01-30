"""
RDS-001: RDS instance is publicly accessible without encryption

Detects RDS instances that:
1. Are publicly accessible from the internet
2. Do not have encryption at rest enabled

This combination is particularly dangerous for databases.
"""

from typing import List
from cloudscan.rules.base import BaseRule
from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity


class RDSPublicUnencryptedRule(BaseRule):
    """Detects publicly accessible RDS instances without encryption."""

    id = "RDS-001"
    title = "RDS instance is publicly accessible without encryption"
    description = (
        "RDS instance allows public internet access and does not have "
        "encryption at rest enabled, allowing data exfiltration"
    )
    severity = Severity.CRITICAL
    service = "rds"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        """
        Evaluate RDS instances for dangerous configurations.

        Checks for:
        - Public accessibility + no encryption (CRITICAL)
        - Public accessibility (HIGH)
        - No encryption (HIGH)

        Returns findings for insecure instances.
        """
        findings = []

        for instance in context.get_rds_instances():
            is_public = instance.get("publicly_accessible", False)
            is_encrypted = instance.get("encryption", {}).get("storage_encrypted", False)

            if is_public and not is_encrypted:
                # CRITICAL: publicly accessible AND unencrypted
                finding = self._create_finding(
                    resource_id=instance["id"],
                    resource_type="RDS Instance",
                    risk=(
                        "Database is publicly accessible on the internet AND "
                        "data is unencrypted at rest. Attacker can access database "
                        "and read/export all data"
                    ),
                    evidence={
                        "instance_id": instance["id"],
                        "engine": instance["engine"],
                        "publicly_accessible": True,
                        "storage_encrypted": False,
                        "multi_az": instance.get("multi_az", False),
                    },
                    remediation=(
                        "IMMEDIATE ACTIONS:\n"
                        "1. Disable 'Publicly Accessible' setting\n"
                        "2. Enable encryption at rest (requires instance restart)\n\n"
                        "IMPLEMENTATION:\n"
                        "1. Create snapshot of current database\n"
                        "2. Create new encrypted database from snapshot\n"
                        "3. Update application connection strings\n"
                        "4. Delete old unencrypted database\n\n"
                        "PREVENTION:\n"
                        "5. Update RDS launch templates to require encryption\n"
                        "6. Use security groups to restrict access (not public)"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                        "Overview.Encryption.html"
                    ),
                )
                findings.append(finding)
                self.logger.warning(
                    f"Critical RDS misconfiguration: {instance['id']} "
                    "is public and unencrypted"
                )

            elif is_public:
                # HIGH: publicly accessible (but encrypted)
                finding = self._create_finding(
                    resource_id=instance["id"],
                    resource_type="RDS Instance",
                    risk=(
                        "Database is publicly accessible on the internet, "
                        "allowing anyone to attempt connections and brute-force credentials"
                    ),
                    evidence={
                        "instance_id": instance["id"],
                        "engine": instance["engine"],
                        "publicly_accessible": True,
                        "storage_encrypted": is_encrypted,
                    },
                    remediation=(
                        "1. Disable 'Publicly Accessible' setting\n"
                        "2. Use security groups to restrict database access\n"
                        "3. Place database in private subnet\n"
                        "4. Use VPN/bastion host for administrative access"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                        "USER_VPC.html"
                    ),
                )
                findings.append(finding)
                self.logger.warning(
                    f"RDS instance is public: {instance['id']}"
                )

            elif not is_encrypted:
                # HIGH: unencrypted (but not public)
                finding = self._create_finding(
                    resource_id=instance["id"],
                    resource_type="RDS Instance",
                    risk=(
                        "Database data is not encrypted at rest, allowing data "
                        "exfiltration if storage is accessed directly"
                    ),
                    evidence={
                        "instance_id": instance["id"],
                        "engine": instance["engine"],
                        "publicly_accessible": is_public,
                        "storage_encrypted": False,
                    },
                    remediation=(
                        "1. Create snapshot of current database\n"
                        "2. Create new encrypted database from snapshot\n"
                        "3. Update application connection strings\n"
                        "4. Delete old unencrypted database\n"
                        "5. Update RDS templates to require encryption by default"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                        "Overview.Encryption.html"
                    ),
                )
                findings.append(finding)
                self.logger.warning(
                    f"RDS instance is unencrypted: {instance['id']}"
                )

        return findings
