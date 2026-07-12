"""Tests for output formatters: console, JSON, JSONL."""

import json

from cloudscan.engine.finding import Finding, Severity
from cloudscan.output.console import ConsoleOutputFormatter
from cloudscan.output.json import JSONLOutputFormatter, JSONOutputFormatter


def make_finding(severity=Severity.HIGH, rule_id="TEST-001"):
    return Finding(
        rule_id=rule_id, title="Test finding", description="desc",
        severity=severity, service="test", resource_id="res-1",
        resource_type="Test Resource", risk="some risk",
        evidence={"key": "value"}, remediation="fix it",
    )


class TestJSONOutputFormatter:
    def test_structure_and_counts(self):
        findings = [make_finding(Severity.CRITICAL), make_finding(Severity.HIGH)]
        formatter = JSONOutputFormatter()
        output = json.loads(formatter.format(findings))
        assert output["summary"]["total"] == 2
        assert output["summary"]["critical"] == 1
        assert output["summary"]["high"] == 1
        assert len(output["findings"]) == 2
        assert output["findings"][0]["id"] == "TEST-001"

    def test_empty_findings(self):
        formatter = JSONOutputFormatter()
        output = json.loads(formatter.format([]))
        assert output["summary"]["total"] == 0
        assert output["findings"] == []

    def test_metadata_can_be_excluded(self):
        formatter = JSONOutputFormatter(include_metadata=False)
        output = json.loads(formatter.format([]))
        assert "scan_metadata" not in output

    def test_timestamp_is_iso_with_z_suffix(self):
        formatter = JSONOutputFormatter()
        output = json.loads(formatter.format([]))
        assert output["scan_metadata"]["timestamp"].endswith("Z")


class TestJSONLOutputFormatter:
    def test_each_line_is_valid_json(self):
        findings = [make_finding(), make_finding(rule_id="TEST-002")]
        formatter = JSONLOutputFormatter()
        output = formatter.format(findings)
        lines = output.strip().split("\n")
        # 1 scan_start + 2 findings + 1 scan_complete
        assert len(lines) == 4
        for line in lines:
            json.loads(line)  # must not raise

    def test_line_types_in_order(self):
        formatter = JSONLOutputFormatter()
        output = formatter.format([make_finding()])
        lines = [json.loads(line) for line in output.strip().split("\n")]
        assert lines[0]["type"] == "scan_start"
        assert lines[1]["type"] == "finding"
        assert lines[2]["type"] == "scan_complete"


class TestConsoleOutputFormatter:
    def test_output_is_cp1252_encodable(self):
        """Regression test: the summary line used to contain emoji that
        crashed on Windows' default cp1252 console codepage."""
        findings = [make_finding(Severity.CRITICAL)]
        formatter = ConsoleOutputFormatter()
        output = formatter.format(findings)
        output.encode("cp1252")  # must not raise UnicodeEncodeError

    def test_empty_findings_still_encodable(self):
        formatter = ConsoleOutputFormatter()
        output = formatter.format([])
        output.encode("cp1252")

    def test_output_contains_rule_id_and_resource(self):
        findings = [make_finding()]
        formatter = ConsoleOutputFormatter()
        output = formatter.format(findings)
        assert "TEST-001" in output
        assert "res-1" in output
