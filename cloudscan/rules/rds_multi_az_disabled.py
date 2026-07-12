"""
RDS-006: RDS instance is not configured for Multi-AZ

Without a Multi-AZ standby replica, an availability zone outage causes
database downtime until a new instance can be provisioned, rather than
an automatic failover.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class RDSMultiAZDisabledRule(BaseRule):
    """Detects RDS instances without Multi-AZ enabled."""

    id = "RDS-006"
    title = "RDS instance is not configured for Multi-AZ"
    description = (
        "RDS instance runs in a single Availability Zone, so an AZ "
        "outage causes downtime instead of an automatic failover"
    )
    severity = Severity.LOW
    service = "rds"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for instance in context.get_rds_instances():
            if instance.get("multi_az"):
                continue

            finding = self._create_finding(
                resource_id=instance["id"],
                resource_type="RDS Instance",
                risk=(
                    "A single Availability Zone outage would take this "
                    "database offline until it can be manually recovered, "
                    "rather than failing over automatically"
                ),
                evidence={"instance_id": instance["id"], "multi_az": False},
                remediation=(
                    "1. Enable Multi-AZ deployment for production databases\n"
                    "2. Weigh the availability benefit against the "
                    "additional cost for non-critical/dev databases"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                    "Concepts.MultiAZ.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Multi-AZ disabled: {instance['id']}")

        return findings
