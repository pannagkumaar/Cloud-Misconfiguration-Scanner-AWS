"""
SARIF output formatter - Static Analysis Results Interchange Format
(SARIF) 2.1.0, the format GitHub Code Scanning (and most other CI
security dashboards) consume.

CloudScan findings describe live AWS resources, not source code lines,
so results use `logicalLocations` (resource id/type) rather than
`physicalLocations` (file/line) -- there's no file to point at. This is
valid per the SARIF 2.1.0 spec, which does not require a physical
location on every result.
"""

import hashlib
import json
from typing import Any, Dict, List

from cloudscan.engine.finding import Finding, Severity
from cloudscan.output.base import BaseOutputFormatter

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
TOOL_NAME = "CloudScan"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/pannagkumaar/Cloud-Misconfiguration-Scanner-AWS"

# SARIF result levels: "error" | "warning" | "note" | "none"
SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub code scanning's de facto "security-severity" property (0.0-10.0,
# used to render the severity badge/filter in the UI).
SEVERITY_TO_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


class SARIFOutputFormatter(BaseOutputFormatter):
    """Formats findings as SARIF 2.1.0 for GitHub Code Scanning / CI tools."""

    def format(self, findings: List[Finding]) -> str:
        """
        Format findings as a SARIF 2.1.0 JSON document.

        Returns:
            SARIF JSON string
        """
        sarif = {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [self._build_run(findings)],
        }
        return json.dumps(sarif, indent=2, default=str)

    def _build_run(self, findings: List[Finding]) -> Dict[str, Any]:
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        results = []

        for finding in findings:
            if finding.rule_id not in rules_by_id:
                rules_by_id[finding.rule_id] = self._build_rule(finding)
            results.append(self._build_result(finding))

        return {
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": TOOL_INFO_URI,
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
        }

    def _build_rule(self, finding: Finding) -> Dict[str, Any]:
        rule: Dict[str, Any] = {
            "id": finding.rule_id,
            "name": finding.rule_id.replace("-", "_"),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "defaultConfiguration": {
                "level": SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            },
            "properties": {
                "tags": ["security", "cloud-misconfiguration", finding.service],
                "security-severity": SEVERITY_TO_SCORE.get(finding.severity, "5.0"),
                "cloudscan:severity": finding.severity.value,
            },
        }
        if finding.remediation_url:
            rule["helpUri"] = finding.remediation_url
        if finding.cis_id:
            rule["properties"]["cis_id"] = finding.cis_id
        return rule

    def _build_result(self, finding: Finding) -> Dict[str, Any]:
        message_parts = [finding.risk or finding.description or finding.title]
        if finding.remediation:
            message_parts.append(f"Remediation: {finding.remediation}")

        return {
            "ruleId": finding.rule_id,
            "level": SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {"text": "\n\n".join(message_parts)},
            "locations": [{
                "logicalLocations": [{
                    "name": finding.resource_id or "unknown",
                    "kind": "resource",
                    "fullyQualifiedName": (
                        f"{finding.resource_type}/{finding.resource_id}"
                        if finding.resource_type else finding.resource_id
                    ),
                }],
            }],
            "partialFingerprints": {
                "cloudscanFindingId": self._fingerprint(finding),
            },
            "properties": {
                "resource_type": finding.resource_type,
                "service": finding.service,
            },
        }

    @staticmethod
    def _fingerprint(finding: Finding) -> str:
        """Stable identifier for deduplicating the same finding across scans."""
        raw = f"{finding.rule_id}:{finding.resource_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
