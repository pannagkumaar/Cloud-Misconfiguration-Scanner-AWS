"""
Tests for the SARIF 2.1.0 output formatter.

Validates against a bundled copy of the official OASIS SARIF 2.1.0 JSON
schema (tests/fixtures/sarif-2.1.0-schema.json, from
https://json.schemastore.org/sarif-2.1.0.json) rather than fetching it
over the network at test time, so this test is deterministic and works
offline/in CI.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from cloudscan.engine.finding import Finding, Severity
from cloudscan.output.sarif import SARIFOutputFormatter

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-2.1.0-schema.json"


@pytest.fixture(scope="module")
def sarif_schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def make_finding(rule_id="TEST-001", severity=Severity.HIGH, cis_id=None):
    return Finding(
        rule_id=rule_id, title="Test finding", description="A test finding description",
        severity=severity, service="s3", cis_id=cis_id,
        resource_id="my-bucket", resource_type="S3 Bucket",
        risk="Some risk description", evidence={"key": "value"},
        remediation="Do the thing", remediation_url="https://docs.aws.amazon.com/x",
    )


class TestSARIFValidatesAgainstSchema:
    def test_empty_findings_is_valid_sarif(self, sarif_schema):
        doc = json.loads(SARIFOutputFormatter().format([]))
        jsonschema.validate(instance=doc, schema=sarif_schema)

    def test_single_finding_is_valid_sarif(self, sarif_schema):
        doc = json.loads(SARIFOutputFormatter().format([make_finding()]))
        jsonschema.validate(instance=doc, schema=sarif_schema)

    def test_multiple_findings_same_rule_is_valid_sarif(self, sarif_schema):
        findings = [make_finding(), make_finding()]
        doc = json.loads(SARIFOutputFormatter().format(findings))
        jsonschema.validate(instance=doc, schema=sarif_schema)

    def test_all_severities_produce_valid_sarif(self, sarif_schema):
        findings = [make_finding(rule_id=f"TEST-{s.value}", severity=s) for s in Severity]
        doc = json.loads(SARIFOutputFormatter().format(findings))
        jsonschema.validate(instance=doc, schema=sarif_schema)

    def test_finding_with_cis_id_is_valid_sarif(self, sarif_schema):
        doc = json.loads(SARIFOutputFormatter().format([make_finding(cis_id="1.5")]))
        jsonschema.validate(instance=doc, schema=sarif_schema)


class TestSARIFStructure:
    def test_version_is_2_1_0(self):
        doc = json.loads(SARIFOutputFormatter().format([]))
        assert doc["version"] == "2.1.0"

    def test_one_rule_object_per_unique_rule_id(self):
        findings = [make_finding(rule_id="A"), make_finding(rule_id="A"), make_finding(rule_id="B")]
        doc = json.loads(SARIFOutputFormatter().format(findings))
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert sorted(rule_ids) == ["A", "B"]

    def test_result_count_matches_finding_count(self):
        findings = [make_finding(), make_finding(), make_finding()]
        doc = json.loads(SARIFOutputFormatter().format(findings))
        assert len(doc["runs"][0]["results"]) == 3

    @pytest.mark.parametrize("severity,expected_level", [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ])
    def test_severity_maps_to_correct_sarif_level(self, severity, expected_level):
        doc = json.loads(SARIFOutputFormatter().format([make_finding(severity=severity)]))
        assert doc["runs"][0]["results"][0]["level"] == expected_level

    def test_resource_id_in_logical_location(self):
        doc = json.loads(SARIFOutputFormatter().format([make_finding()]))
        result = doc["runs"][0]["results"][0]
        assert result["locations"][0]["logicalLocations"][0]["name"] == "my-bucket"

    def test_fingerprint_is_stable_for_same_rule_and_resource(self):
        doc = json.loads(SARIFOutputFormatter().format([make_finding(), make_finding()]))
        fp1 = doc["runs"][0]["results"][0]["partialFingerprints"]["cloudscanFindingId"]
        fp2 = doc["runs"][0]["results"][1]["partialFingerprints"]["cloudscanFindingId"]
        assert fp1 == fp2

    def test_fingerprint_differs_for_different_resources(self):
        f1 = make_finding()
        f2 = make_finding()
        f2.resource_id = "other-bucket"
        doc = json.loads(SARIFOutputFormatter().format([f1, f2]))
        fp1 = doc["runs"][0]["results"][0]["partialFingerprints"]["cloudscanFindingId"]
        fp2 = doc["runs"][0]["results"][1]["partialFingerprints"]["cloudscanFindingId"]
        assert fp1 != fp2
