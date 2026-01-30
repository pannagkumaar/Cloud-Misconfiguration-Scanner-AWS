"""
IAM-001: IAM policy with wildcard actions (*:*)

Detects IAM policies that grant overly broad permissions with * (all actions)
on * (all resources), violating the principle of least privilege.
"""

from typing import List, Dict, Any
from cloudscan.rules.base import BaseRule
from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity


class IAMWildcardPolicyRule(BaseRule):
    """Detects overly permissive IAM policies with full access."""

    id = "IAM-001"
    title = "IAM policy grants full administrative access"
    description = (
        "IAM policy contains statement allowing all actions (*) on all resources (*), "
        "violating the principle of least privilege and increasing blast radius of compromise"
    )
    severity = Severity.CRITICAL
    service = "iam"
    cis_id = "1.18"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        """
        Evaluate IAM policies for dangerous wildcard permissions.

        Checks:
        - Inline policies on users
        - Inline policies on roles
        - Customer-managed policies

        Returns findings for overly permissive policies.
        """
        findings = []

        # Check user inline policies
        for user in context.get_iam_users():
            for policy_name in user.get("inline_policies", []):
                if self._has_wildcard_policy(
                    context, "User", user["name"], policy_name
                ):
                    finding = self._create_finding(
                        resource_id=user["arn"],
                        resource_type="IAM User",
                        risk="User has full administrative access, allowing complete "
                             "account compromise if credentials are leaked",
                        evidence={
                            "user_name": user["name"],
                            "policy_name": policy_name,
                            "policy_type": "inline",
                        },
                        remediation=self._get_remediation("user", policy_name),
                        remediation_url=(
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                            "access_policies.html"
                        ),
                    )
                    findings.append(finding)
                    self.logger.warning(
                        f"Wildcard policy detected on user: {user['name']}"
                    )

        # Check role inline policies
        for role in context.get_iam_roles():
            for policy_name in role.get("inline_policies", []):
                if self._has_wildcard_policy(
                    context, "Role", role["name"], policy_name
                ):
                    finding = self._create_finding(
                        resource_id=role["arn"],
                        resource_type="IAM Role",
                        risk="Role has full administrative access, allowing complete "
                             "account compromise if assumed by compromised service",
                        evidence={
                            "role_name": role["name"],
                            "policy_name": policy_name,
                            "policy_type": "inline",
                        },
                        remediation=self._get_remediation("role", policy_name),
                        remediation_url=(
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                            "access_policies.html"
                        ),
                    )
                    findings.append(finding)
                    self.logger.warning(
                        f"Wildcard policy detected on role: {role['name']}"
                    )

        # Check customer-managed policies for wildcard statements
        for policy in context.get_iam_policies():
            document = policy.get("document", {})
            statements = document.get("Statement", [])

            for idx, statement in enumerate(statements):
                if self._is_wildcard_statement(statement):
                    finding = self._create_finding(
                        resource_id=policy["arn"],
                        resource_type="IAM Policy",
                        risk="Policy grants full administrative access to anyone "
                             "this policy is attached to",
                        evidence={
                            "policy_name": policy["name"],
                            "policy_arn": policy["arn"],
                            "statement_index": idx,
                            "dangerous_statement": {
                                "effect": statement.get("Effect"),
                                "actions": statement.get("Action"),
                                "resources": statement.get("Resource"),
                            },
                        },
                        remediation=self._get_remediation("policy", policy["name"]),
                        remediation_url=(
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                            "access_policies.html"
                        ),
                    )
                    findings.append(finding)
                    self.logger.warning(
                        f"Wildcard policy detected: {policy['name']}"
                    )

        return findings

    def _has_wildcard_policy(
        self, context: ScanContext, principal_type: str,
        principal_name: str, policy_name: str
    ) -> bool:
        """Check if a user/role inline policy has wildcard permissions."""
        # NOTE: In a real implementation, we'd fetch the actual policy document
        # For now, return False as we don't have inline policy contents
        # This would be populated from IAM.get_user_policy() / get_role_policy()
        return False

    def _is_wildcard_statement(self, statement: Dict[str, Any]) -> bool:
        """
        Check if a statement has wildcard actions and resources.

        Wildcard statement: Effect=Allow, Action=*, Resource=*
        """
        if statement.get("Effect") != "Allow":
            return False

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        # Handle both string and list formats
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Check for wildcards
        has_wildcard_action = "*" in actions
        has_wildcard_resource = "*" in resources

        return has_wildcard_action and has_wildcard_resource

    def _get_remediation(self, principal_type: str, name: str) -> str:
        """Get remediation steps."""
        if principal_type == "user":
            return (
                "1. Remove the overly permissive inline policy from the user\n"
                "2. Create a least-privilege policy with only required permissions\n"
                "3. Use AWS managed policies as a starting point\n"
                "4. Regularly audit user permissions with IAM Access Analyzer"
            )
        elif principal_type == "role":
            return (
                "1. Remove the overly permissive inline policy from the role\n"
                "2. Create a least-privilege policy with only required permissions\n"
                "3. Document what services need this role\n"
                "4. Implement session duration limits and MFA requirements"
            )
        else:  # policy
            return (
                f"1. Remove wildcard statements from {name}\n"
                "2. Replace with specific actions and resources\n"
                "3. Use AWS managed policies as templates\n"
                "4. Test with simpler permissions first"
            )
