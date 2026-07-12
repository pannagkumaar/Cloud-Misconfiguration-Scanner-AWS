"""
IAM-008: IAM policy grants overly broad permissions

Detects customer-managed policy statements that wildcard either the
action or the resource (but not both -- that combination is the more
severe case already covered by IAM-001).
"""

from typing import Any, Dict, List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class OverlyBroadPolicyRule(BaseRule):
    """Detects IAM policy statements with a partial wildcard."""

    id = "IAM-008"
    title = "IAM policy grants overly broad permissions"
    description = (
        "IAM policy statement uses a wildcard (*) for either the action or "
        "the resource, granting broader access than typically needed"
    )
    severity = Severity.MEDIUM
    service = "iam"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for policy in context.get_iam_policies():
            document = policy.get("document", {})
            for idx, statement in enumerate(document.get("Statement", [])):
                if not self._is_partial_wildcard(statement):
                    continue

                finding = self._create_finding(
                    resource_id=policy["arn"],
                    resource_type="IAM Policy",
                    risk=(
                        "A broad action or resource wildcard increases the "
                        "blast radius if this policy's principal is compromised"
                    ),
                    evidence={
                        "policy_name": policy.get("name"),
                        "statement_index": idx,
                        "actions": statement.get("Action"),
                        "resources": statement.get("Resource"),
                    },
                    remediation=(
                        "1. Scope the wildcarded side of the statement to "
                        "specific actions or resources\n"
                        "2. Use IAM Access Analyzer policy generation to "
                        "derive least-privilege permissions from actual usage"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                        "best-practices.html#grant-least-privilege"
                    ),
                )
                findings.append(finding)
                self.logger.warning(
                    f"Overly broad policy statement in {policy.get('name')}"
                )

        return findings

    @staticmethod
    def _is_partial_wildcard(statement: Dict[str, Any]) -> bool:
        if statement.get("Effect") != "Allow":
            return False

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_action = "*" in actions
        has_wildcard_resource = "*" in resources

        # Exactly one side wildcarded -- both-wildcard is IAM-001's territory.
        return has_wildcard_action != has_wildcard_resource
