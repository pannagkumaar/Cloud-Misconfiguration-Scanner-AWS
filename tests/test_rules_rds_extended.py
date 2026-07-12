"""Tests for the expanded RDS rules: backup retention, deletion protection,
Multi-AZ, and auto minor version upgrade."""

from cloudscan.rules.rds_auto_minor_upgrade_disabled import RDSAutoMinorUpgradeDisabledRule
from cloudscan.rules.rds_backup_retention import RDSBackupRetentionRule
from cloudscan.rules.rds_deletion_protection import RDSDeletionProtectionRule
from cloudscan.rules.rds_multi_az_disabled import RDSMultiAZDisabledRule
from tests.conftest import make_context, make_rds_instance


def evaluate(rule_cls, instance, rds_service):
    ctx = make_context(rds=rds_service(instances=[instance]))
    return rule_cls().evaluate(ctx)


class TestRDSBackupRetentionRule:
    def test_short_retention_flagged(self, rds_service):
        instance = make_rds_instance(backup_retention_period=3)
        findings = evaluate(RDSBackupRetentionRule, instance, rds_service)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_zero_retention_flagged(self, rds_service):
        instance = make_rds_instance(backup_retention_period=0)
        findings = evaluate(RDSBackupRetentionRule, instance, rds_service)
        assert len(findings) == 1

    def test_sufficient_retention_not_flagged(self, rds_service):
        instance = make_rds_instance(backup_retention_period=7)
        assert evaluate(RDSBackupRetentionRule, instance, rds_service) == []

    def test_generous_retention_not_flagged(self, rds_service):
        instance = make_rds_instance(backup_retention_period=30)
        assert evaluate(RDSBackupRetentionRule, instance, rds_service) == []


class TestRDSDeletionProtectionRule:
    def test_disabled_flagged(self, rds_service):
        instance = make_rds_instance(deletion_protection=False)
        findings = evaluate(RDSDeletionProtectionRule, instance, rds_service)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_enabled_not_flagged(self, rds_service):
        instance = make_rds_instance(deletion_protection=True)
        assert evaluate(RDSDeletionProtectionRule, instance, rds_service) == []


class TestRDSMultiAZDisabledRule:
    def test_disabled_flagged(self, rds_service):
        instance = make_rds_instance(multi_az=False)
        findings = evaluate(RDSMultiAZDisabledRule, instance, rds_service)
        assert len(findings) == 1
        assert findings[0].severity.value == "LOW"

    def test_enabled_not_flagged(self, rds_service):
        instance = make_rds_instance(multi_az=True)
        assert evaluate(RDSMultiAZDisabledRule, instance, rds_service) == []


class TestRDSAutoMinorUpgradeDisabledRule:
    def test_explicitly_disabled_flagged(self, rds_service):
        instance = make_rds_instance()
        instance["auto_minor_version_upgrade"] = False
        findings = evaluate(RDSAutoMinorUpgradeDisabledRule, instance, rds_service)
        assert len(findings) == 1
        assert findings[0].severity.value == "LOW"

    def test_enabled_not_flagged(self, rds_service):
        instance = make_rds_instance()
        instance["auto_minor_version_upgrade"] = True
        assert evaluate(RDSAutoMinorUpgradeDisabledRule, instance, rds_service) == []

    def test_unknown_not_flagged(self, rds_service):
        """None (e.g. from a partial offline export) isn't treated as a
        finding -- only an explicit False is."""
        instance = make_rds_instance()
        instance["auto_minor_version_upgrade"] = None
        assert evaluate(RDSAutoMinorUpgradeDisabledRule, instance, rds_service) == []
