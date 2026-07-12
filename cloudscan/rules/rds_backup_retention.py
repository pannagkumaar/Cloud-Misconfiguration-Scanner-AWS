"""
RDS-004: RDS instance backup retention period is too short

A short (or zero) backup retention period limits how far back you can
recover data after accidental deletion, corruption, or a ransomware-style
incident.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class RDSBackupRetentionRule(BaseRule):
    """Detects RDS instances with backup retention under 7 days."""

    id = "RDS-004"
    title = "RDS instance backup retention period is too short"
    description = (
        "RDS instance has automated backup retention configured for "
        "fewer than 7 days (or disabled entirely), limiting how far "
        "back data can be recovered"
    )
    severity = Severity.MEDIUM
    service = "rds"

    MIN_RETENTION_DAYS = 7

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for instance in context.get_rds_instances():
            retention = instance.get("backup", {}).get("backup_retention_period")
            if retention is not None and retention >= self.MIN_RETENTION_DAYS:
                continue

            finding = self._create_finding(
                resource_id=instance["id"],
                resource_type="RDS Instance",
                risk=(
                    "A short backup retention window (or automated "
                    "backups disabled entirely, retention=0) reduces "
                    "the ability to recover from accidental or "
                    "malicious data loss"
                ),
                evidence={
                    "instance_id": instance["id"],
                    "backup_retention_period": retention,
                },
                remediation=(
                    f"1. Increase the backup retention period to at least "
                    f"{self.MIN_RETENTION_DAYS} days\n"
                    "2. Consider AWS Backup for centralized, cross-service "
                    "backup policies"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                    "USER_WorkingWithAutomatedBackups.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(
                f"Short backup retention on {instance['id']}: {retention} days"
            )

        return findings
