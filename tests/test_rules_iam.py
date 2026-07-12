"""Tests for IAM-001: wildcard IAM policy detection (managed + inline)."""

from cloudscan.rules.iam_wildcard_policy import IAMWildcardPolicyRule
from tests.conftest import (
    SCOPED_STATEMENT,
    WILDCARD_STATEMENT,
    make_context,
    make_iam_role,
    make_iam_user,
    make_managed_policy,
)


class TestIAMWildcardPolicyRule:
    def test_managed_policy_with_wildcard_flagged(self, iam_service):
        policy = make_managed_policy(name="admin", statements=[WILDCARD_STATEMENT])
        ctx = make_context(iam=iam_service(policies=[policy]))
        findings = IAMWildcardPolicyRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-001"
        assert findings[0].severity.value == "CRITICAL"

    def test_managed_policy_scoped_not_flagged(self, iam_service):
        policy = make_managed_policy(name="scoped", statements=[SCOPED_STATEMENT])
        ctx = make_context(iam=iam_service(policies=[policy]))
        findings = IAMWildcardPolicyRule().evaluate(ctx)
        assert findings == []

    def test_inline_user_policy_with_wildcard_flagged(self, iam_service):
        """Regression test: this path used to be dead code that always
        returned False (the collector only gathered inline policy names,
        not their documents)."""
        user = make_iam_user(
            name="bad-user",
            inline_policy_documents=[{
                "name": "AdminAccess",
                "document": {"Version": "2012-10-17", "Statement": [WILDCARD_STATEMENT]},
            }],
        )
        ctx = make_context(iam=iam_service(users=[user]))
        findings = IAMWildcardPolicyRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].resource_id == user["arn"]
        assert findings[0].evidence["policy_type"] == "inline"

    def test_inline_role_policy_with_wildcard_flagged(self, iam_service):
        role = make_iam_role(
            name="bad-role",
            inline_policy_documents=[{
                "name": "FullAccess",
                "document": {"Version": "2012-10-17", "Statement": [WILDCARD_STATEMENT]},
            }],
        )
        ctx = make_context(iam=iam_service(roles=[role]))
        findings = IAMWildcardPolicyRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].resource_id == role["arn"]

    def test_inline_policy_scoped_not_flagged(self, iam_service):
        user = make_iam_user(
            name="ok-user",
            inline_policy_documents=[{
                "name": "ReadOnly",
                "document": {"Version": "2012-10-17", "Statement": [SCOPED_STATEMENT]},
            }],
        )
        ctx = make_context(iam=iam_service(users=[user]))
        findings = IAMWildcardPolicyRule().evaluate(ctx)
        assert findings == []

    def test_user_with_no_inline_policies_not_flagged(self, iam_service):
        user = make_iam_user(name="clean-user")
        ctx = make_context(iam=iam_service(users=[user]))
        findings = IAMWildcardPolicyRule().evaluate(ctx)
        assert findings == []

    def test_deny_statement_with_wildcard_not_flagged(self, iam_service):
        deny_all = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        policy = make_managed_policy(name="deny-policy", statements=[deny_all])
        ctx = make_context(iam=iam_service(policies=[policy]))
        findings = IAMWildcardPolicyRule().evaluate(ctx)
        assert findings == []
