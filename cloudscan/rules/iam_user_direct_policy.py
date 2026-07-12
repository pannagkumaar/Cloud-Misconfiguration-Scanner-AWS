"""
IAM-009: IAM policy attached directly to a user

CIS AWS Foundations Benchmark 1.15: manage IAM permissions through
groups (or roles), not by attaching policies directly to individual
users, so permissions stay auditable and consistent at scale.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class UserDirectPolicyAttachmentRule(BaseRule):
    """Detects managed policies attached directly to an IAM user."""

    id = "IAM-009"
    title = "IAM policy is attached directly to a user"
    description = (
        "IAM user has one or more managed policies attached directly "
        "rather than via a group, making permissions harder to audit "
        "and manage consistently at scale"
    )
    severity = Severity.LOW
    service = "iam"
    cis_id = "1.15"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for user in context.get_iam_users():
            attached = user.get("attached_policies", [])
            if not attached:
                continue

            finding = self._create_finding(
                resource_id=user["arn"],
                resource_type="IAM User",
                risk=(
                    "Directly attached policies are easy to lose track of "
                    "and don't benefit from centralized, group-based "
                    "permission management"
                ),
                evidence={
                    "user_name": user["name"],
                    "attached_policy_count": len(attached),
                    "attached_policies": [p.get("name") for p in attached],
                },
                remediation=(
                    "1. Create an IAM group with the equivalent policy\n"
                    "2. Add the user to the group\n"
                    "3. Detach the policy from the user directly"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                    "best-practices.html#use-groups-for-permissions"
                ),
            )
            findings.append(finding)
            self.logger.warning(
                f"IAM user has directly attached policies: {user['name']}"
            )

        return findings
