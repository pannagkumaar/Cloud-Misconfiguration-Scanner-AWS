"""
RDS-005: RDS instance does not have deletion protection enabled

Without deletion protection, a single mistaken or malicious API call
(or Terraform/CloudFormation apply) can permanently delete a production
database.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class RDSDeletionProtectionRule(BaseRule):
    """Detects RDS instances without deletion protection enabled."""

    id = "RDS-005"
    title = "RDS instance does not have deletion protection enabled"
    description = (
        "RDS instance can be deleted by a single API call, with no "
        "safeguard against accidental or malicious deletion"
    )
    severity = Severity.MEDIUM
    service = "rds"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for instance in context.get_rds_instances():
            if instance.get("backup", {}).get("deletion_protection"):
                continue

            finding = self._create_finding(
                resource_id=instance["id"],
                resource_type="RDS Instance",
                risk=(
                    "A single mistaken or malicious DeleteDBInstance call "
                    "(directly, via automation, or via IaC drift) would "
                    "permanently remove this database with no confirmation "
                    "step"
                ),
                evidence={
                    "instance_id": instance["id"],
                    "deletion_protection": False,
                },
                remediation=(
                    "1. Enable deletion protection on the instance\n"
                    "2. Require an explicit disable step before any "
                    "planned deletion"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                    "USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Deletion protection disabled: {instance['id']}")

        return findings
