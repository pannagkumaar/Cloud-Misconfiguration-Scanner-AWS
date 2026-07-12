"""Tests for RDS-001: publicly accessible / unencrypted RDS instances."""

import pytest

from cloudscan.rules.rds_public_unencrypted import RDSPublicUnencryptedRule
from tests.conftest import make_context, make_rds_instance


def evaluate(instance, rds_service):
    ctx = make_context(rds=rds_service(instances=[instance]))
    return RDSPublicUnencryptedRule().evaluate(ctx)


class TestRDSPublicUnencryptedRule:
    @pytest.mark.parametrize(
        "public,encrypted,expected_severity",
        [
            (True, False, "CRITICAL"),   # both bad
            (True, True, "HIGH"),        # public only
            (False, False, "HIGH"),      # unencrypted only
            (False, True, None),         # both good -> no finding
        ],
    )
    def test_severity_matches_condition(self, rds_service, public, encrypted, expected_severity):
        instance = make_rds_instance(
            instance_id="db-1", publicly_accessible=public, storage_encrypted=encrypted
        )
        findings = evaluate(instance, rds_service)
        if expected_severity is None:
            assert findings == []
        else:
            assert len(findings) == 1
            assert findings[0].severity.value == expected_severity
            assert findings[0].rule_id == "RDS-001"

    def test_only_one_finding_per_instance(self, rds_service):
        instance = make_rds_instance(instance_id="db-both-bad", publicly_accessible=True, storage_encrypted=False)
        findings = evaluate(instance, rds_service)
        assert len(findings) == 1  # not one finding per branch

    def test_multiple_instances_evaluated_independently(self, rds_service):
        good = make_rds_instance(instance_id="good-db", publicly_accessible=False, storage_encrypted=True)
        bad = make_rds_instance(instance_id="bad-db", publicly_accessible=True, storage_encrypted=False)
        ctx = make_context(rds=rds_service(instances=[good, bad]))
        findings = RDSPublicUnencryptedRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].resource_id == "bad-db"
