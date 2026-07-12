"""
CT-002: No CloudTrail trail is multi-region

CIS AWS Foundations Benchmark 3.1: a single-region trail misses API
activity in every other region -- including activity an attacker might
deliberately perform in a region nobody is watching.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class NoMultiRegionTrailRule(BaseRule):
    """Detects an account where no trail is configured as multi-region."""

    id = "CT-002"
    title = "No CloudTrail trail is multi-region"
    description = (
        "None of the account's CloudTrail trails are configured as "
        "multi-region, so API activity in other regions goes unrecorded"
    )
    severity = Severity.HIGH
    service = "cloudtrail"
    cis_id = "3.1"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        trails = context.get_cloudtrail_trails()
        if not trails:
            return []  # total absence is CT-001's territory

        if any(t.get("is_multi_region_trail") for t in trails):
            return []

        finding = self._create_finding(
            resource_id="account",
            resource_type="AWS Account",
            risk=(
                "API activity in regions other than where the trail(s) "
                "are scoped is not recorded, creating blind spots an "
                "attacker could exploit deliberately"
            ),
            evidence={
                "trail_count": len(trails),
                "trail_names": [t.get("name") for t in trails],
            },
            remediation=(
                "1. Edit an existing trail (or create a new one) with "
                "'Apply trail to all regions' enabled\n"
                "2. A single multi-region trail is sufficient and is "
                "AWS's recommended approach"
            ),
            remediation_url=(
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
                "receive-cloudtrail-log-files-from-multiple-regions.html"
            ),
        )
        self.logger.warning("No multi-region CloudTrail trail configured")
        return [finding]
