"""
JSON output formatter - Machine-friendly JSON format.

Suitable for CI/CD integration, API endpoints, and data processing.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from cloudscan.engine.finding import Finding
from cloudscan.output.base import BaseOutputFormatter


class JSONOutputFormatter(BaseOutputFormatter):
    """Formats findings as JSON."""

    def __init__(self, output_file: str = None, pretty: bool = True, include_metadata: bool = True):
        """
        Initialize JSON formatter.

        Args:
            output_file: Optional file to write to
            pretty: Pretty-print JSON (indent)
            include_metadata: Include scan metadata
        """
        super().__init__(output_file)
        self.pretty = pretty
        self.include_metadata = include_metadata

    def format(self, findings: List[Finding]) -> str:
        """
        Format findings as JSON.

        Returns:
            JSON string
        """
        output = self._build_json_structure(findings)

        if self.pretty:
            return json.dumps(output, indent=2, default=str)
        else:
            return json.dumps(output, default=str)

    def _build_json_structure(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build JSON structure for findings."""
        counts = self._get_severity_count(findings)

        structure = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scanner": "Cloud Misconfiguration Scanner",
                "version": "0.1.0",
            } if self.include_metadata else None,
            "summary": {
                "total": len(findings),
                "critical": counts["CRITICAL"],
                "high": counts["HIGH"],
                "medium": counts["MEDIUM"],
                "low": counts["LOW"],
                "info": counts["INFO"],
            },
            "findings": [finding.to_dict() for finding in findings],
        }

        # Remove None metadata if not included
        if not self.include_metadata:
            del structure["scan_metadata"]

        return structure


class JSONLOutputFormatter(BaseOutputFormatter):
    """Formats findings as JSON Lines (one finding per line)."""

    def format(self, findings: List[Finding]) -> str:
        """
        Format findings as JSON Lines.

        One JSON object per line, suitable for streaming and log aggregation.

        Returns:
            JSONL string
        """
        lines = []

        # Metadata line
        metadata = {
            "type": "scan_start",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(findings),
        }
        lines.append(json.dumps(metadata, default=str))

        # Finding lines
        for finding in findings:
            line = {
                "type": "finding",
                **finding.to_dict()
            }
            lines.append(json.dumps(line, default=str))

        # Summary line
        counts = self._get_severity_count(findings)
        summary = {
            "type": "scan_complete",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "critical": counts["CRITICAL"],
                "high": counts["HIGH"],
                "medium": counts["MEDIUM"],
                "low": counts["LOW"],
                "info": counts["INFO"],
            }
        }
        lines.append(json.dumps(summary, default=str))

        return "\n".join(lines)
