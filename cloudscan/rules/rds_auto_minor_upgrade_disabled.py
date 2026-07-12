"""
RDS-007: RDS instance does not auto-apply minor version upgrades

Minor version upgrades typically include security patches. Without
auto-apply enabled, an instance can silently drift further behind on
patches that fix known vulnerabilities in the database engine.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class RDSAutoMinorUpgradeDisabledRule(BaseRule):
    """Detects RDS instances without auto minor version upgrade enabled."""

    id = "RDS-007"
    title = "RDS instance does not auto-apply minor version upgrades"
    description = (
        "RDS instance has automatic minor version upgrades disabled, so "
        "engine security patches are not applied automatically during "
        "the maintenance window"
    )
    severity = Severity.LOW
    service = "rds"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for instance in context.get_rds_instances():
            # None (unknown, e.g. from a partial offline export) is not
            # treated as a finding -- only an explicit False is.
            if instance.get("auto_minor_version_upgrade") is not False:
                continue

            finding = self._create_finding(
                resource_id=instance["id"],
                resource_type="RDS Instance",
                risk=(
                    "Without automatic minor version upgrades, this "
                    "instance can silently fall behind on engine security "
                    "patches until someone manually upgrades it"
                ),
                evidence={
                    "instance_id": instance["id"],
                    "auto_minor_version_upgrade": False,
                },
                remediation=(
                    "1. Enable auto minor version upgrade on the instance\n"
                    "2. Schedule a maintenance window during low-traffic "
                    "periods so upgrades apply predictably"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
                    "USER_UpgradeDBInstance.Maintenance.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Auto minor version upgrade disabled: {instance['id']}")

        return findings
