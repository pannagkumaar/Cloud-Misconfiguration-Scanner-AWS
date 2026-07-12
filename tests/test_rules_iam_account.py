"""
Tests for the account-level IAM rules added in Phase 2: root MFA/access
keys, user MFA, access key rotation/unused-credential age, password
policy strength, overly broad (partial-wildcard) policies, and
directly-attached user policies.
"""

from datetime import datetime, timedelta, timezone

from cloudscan.rules.iam_access_key_rotation import AccessKeyRotationRule
from cloudscan.rules.iam_overly_broad_policy import OverlyBroadPolicyRule
from cloudscan.rules.iam_password_policy import WeakPasswordPolicyRule
from cloudscan.rules.iam_root_access_key import RootAccessKeyRule
from cloudscan.rules.iam_root_mfa import RootMFADisabledRule
from cloudscan.rules.iam_unused_credentials import UnusedCredentialsRule
from cloudscan.rules.iam_user_direct_policy import UserDirectPolicyAttachmentRule
from cloudscan.rules.iam_user_mfa import UserMFADisabledRule
from tests.conftest import make_context, make_iam_user, make_managed_policy


def days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def credential_service(rows):
    return {
        "service": "iam", "users": [], "roles": [], "policies": [],
        "account_summary": {}, "credential_report": {"available": True, "rows": rows},
        "password_policy": {"exists": False},
    }


def root_row(**overrides):
    row = {
        "user": "<root_account>", "arn": "arn:aws:iam::123456789012:root",
        "is_root": True, "mfa_active": False, "password_enabled": True,
        "password_last_used": None,
        "access_key_1_active": False, "access_key_1_last_rotated": None,
        "access_key_1_last_used": None,
        "access_key_2_active": False, "access_key_2_last_rotated": None,
        "access_key_2_last_used": None,
    }
    row.update(overrides)
    return row


def user_row(**overrides):
    row = {
        "user": "alice", "arn": "arn:aws:iam::123456789012:user/alice",
        "is_root": False, "mfa_active": True, "password_enabled": True,
        "password_last_used": days_ago(1),
        "access_key_1_active": True, "access_key_1_last_rotated": days_ago(1),
        "access_key_1_last_used": days_ago(1),
        "access_key_2_active": False, "access_key_2_last_rotated": None,
        "access_key_2_last_used": None,
    }
    row.update(overrides)
    return row


class TestRootMFADisabledRule:
    def test_root_without_mfa_flagged(self):
        ctx = make_context(iam=credential_service([root_row(mfa_active=False)]))
        findings = RootMFADisabledRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_root_with_mfa_not_flagged(self):
        ctx = make_context(iam=credential_service([root_row(mfa_active=True)]))
        assert RootMFADisabledRule().evaluate(ctx) == []

    def test_no_credential_report_data_not_flagged(self):
        ctx = make_context(iam=credential_service([]))
        assert RootMFADisabledRule().evaluate(ctx) == []


class TestRootAccessKeyRule:
    def test_root_with_active_key_flagged(self):
        ctx = make_context(iam=credential_service([root_row(access_key_1_active=True)]))
        findings = RootAccessKeyRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_root_without_keys_not_flagged(self):
        ctx = make_context(iam=credential_service([root_row()]))
        assert RootAccessKeyRule().evaluate(ctx) == []


class TestUserMFADisabledRule:
    def test_password_enabled_no_mfa_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(password_enabled=True, mfa_active=False)
        ]))
        findings = UserMFADisabledRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_password_and_mfa_not_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(password_enabled=True, mfa_active=True)
        ]))
        assert UserMFADisabledRule().evaluate(ctx) == []

    def test_no_password_not_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(password_enabled=False, mfa_active=False)
        ]))
        assert UserMFADisabledRule().evaluate(ctx) == []

    def test_root_excluded(self):
        ctx = make_context(iam=credential_service([
            root_row(password_enabled=True, mfa_active=False)
        ]))
        assert UserMFADisabledRule().evaluate(ctx) == []


class TestAccessKeyRotationRule:
    def test_old_key_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(access_key_1_active=True, access_key_1_last_rotated=days_ago(120))
        ]))
        findings = AccessKeyRotationRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"
        assert findings[0].evidence["age_days"] >= 120

    def test_recent_key_not_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(access_key_1_active=True, access_key_1_last_rotated=days_ago(10))
        ]))
        assert AccessKeyRotationRule().evaluate(ctx) == []

    def test_inactive_key_not_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(access_key_1_active=False, access_key_1_last_rotated=days_ago(500))
        ]))
        assert AccessKeyRotationRule().evaluate(ctx) == []


class TestUnusedCredentialsRule:
    def test_unused_password_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(password_enabled=True, password_last_used=days_ago(200))
        ]))
        findings = UnusedCredentialsRule().evaluate(ctx)
        assert any(f.resource_type == "IAM User Password" for f in findings)

    def test_unused_access_key_flagged(self):
        ctx = make_context(iam=credential_service([
            user_row(access_key_1_active=True, access_key_1_last_used=days_ago(200),
                      access_key_1_last_rotated=days_ago(400))
        ]))
        findings = UnusedCredentialsRule().evaluate(ctx)
        assert any(f.resource_type == "IAM Access Key" for f in findings)

    def test_recently_used_not_flagged(self):
        ctx = make_context(iam=credential_service([user_row()]))
        assert UnusedCredentialsRule().evaluate(ctx) == []

    def test_never_used_key_falls_back_to_rotation_date(self):
        ctx = make_context(iam=credential_service([
            user_row(access_key_1_active=True, access_key_1_last_used=None,
                      access_key_1_last_rotated=days_ago(200))
        ]))
        findings = UnusedCredentialsRule().evaluate(ctx)
        assert len(findings) == 1


class TestWeakPasswordPolicyRule:
    def _service(self, policy):
        return {
            "service": "iam", "users": [], "roles": [], "policies": [],
            "account_summary": {}, "credential_report": {"available": False, "rows": []},
            "password_policy": policy,
        }

    def test_no_policy_flagged(self):
        ctx = make_context(iam=self._service({"exists": False}))
        findings = WeakPasswordPolicyRule().evaluate(ctx)
        assert len(findings) == 1

    def test_strong_policy_not_flagged(self):
        ctx = make_context(iam=self._service({
            "exists": True, "minimum_password_length": 14, "require_symbols": True,
            "require_numbers": True, "require_uppercase_characters": True,
            "require_lowercase_characters": True, "password_reuse_prevention": 24,
        }))
        assert WeakPasswordPolicyRule().evaluate(ctx) == []

    def test_short_min_length_flagged(self):
        ctx = make_context(iam=self._service({
            "exists": True, "minimum_password_length": 6, "require_symbols": True,
            "require_numbers": True, "require_uppercase_characters": True,
            "require_lowercase_characters": True, "password_reuse_prevention": 24,
        }))
        findings = WeakPasswordPolicyRule().evaluate(ctx)
        assert len(findings) == 1
        assert any("minimum length" in p for p in findings[0].evidence["problems"])


class TestOverlyBroadPolicyRule:
    def test_wildcard_action_only_flagged(self):
        policy = make_managed_policy(statements=[
            {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}
        ])
        ctx = make_context(iam={"service": "iam", "users": [], "roles": [], "policies": [policy],
                                 "account_summary": {}, "credential_report": {"available": False, "rows": []},
                                 "password_policy": {"exists": False}})
        findings = OverlyBroadPolicyRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_full_wildcard_not_double_flagged_here(self):
        """Both Action=* and Resource=* is IAM-001's territory (CRITICAL),
        not this rule's -- avoid double-counting the same statement."""
        policy = make_managed_policy(statements=[
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ])
        ctx = make_context(iam={"service": "iam", "users": [], "roles": [], "policies": [policy],
                                 "account_summary": {}, "credential_report": {"available": False, "rows": []},
                                 "password_policy": {"exists": False}})
        assert OverlyBroadPolicyRule().evaluate(ctx) == []

    def test_scoped_policy_not_flagged(self):
        policy = make_managed_policy(statements=[
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
        ])
        ctx = make_context(iam={"service": "iam", "users": [], "roles": [], "policies": [policy],
                                 "account_summary": {}, "credential_report": {"available": False, "rows": []},
                                 "password_policy": {"exists": False}})
        assert OverlyBroadPolicyRule().evaluate(ctx) == []


class TestUserDirectPolicyAttachmentRule:
    def test_direct_attachment_flagged(self):
        user = make_iam_user(
            name="bob", attached_policies=[{"name": "SomePolicy", "arn": "arn:x"}]
        )
        ctx = make_context(iam={"service": "iam", "users": [user], "roles": [], "policies": [],
                                 "account_summary": {}, "credential_report": {"available": False, "rows": []},
                                 "password_policy": {"exists": False}})
        findings = UserDirectPolicyAttachmentRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "LOW"

    def test_no_attachment_not_flagged(self):
        user = make_iam_user(name="clean-user")
        ctx = make_context(iam={"service": "iam", "users": [user], "roles": [], "policies": [],
                                 "account_summary": {}, "credential_report": {"available": False, "rows": []},
                                 "password_policy": {"exists": False}})
        assert UserDirectPolicyAttachmentRule().evaluate(ctx) == []
