"""
Console output formatter - Pretty terminal output for humans.

Uses colors, tables, and formatting for readability.
"""

from typing import List
from cloudscan.engine.finding import Finding
from cloudscan.output.base import BaseOutputFormatter

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLORS = True
except ImportError:
    HAS_COLORS = False


class ConsoleOutputFormatter(BaseOutputFormatter):
    """Formats findings for console output with colors and pretty printing."""

    def format(self, findings: List[Finding]) -> str:
        """
        Format findings for console output.

        Returns:
            ANSI-formatted string with findings
        """
        lines = []

        # Header
        lines.append(self._get_header(findings))

        # Findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            severity_findings = [f for f in findings if f.severity.value == severity]
            if severity_findings:
                lines.append(self._format_severity_section(severity, severity_findings))

        # Summary
        lines.append(self._get_summary(findings))

        return "\n".join(lines)

    def _get_header(self, findings: List[Finding]) -> str:
        """Get formatted header."""
        lines = []
        lines.append("")
        lines.append(self._colored("=" * 80, "blue"))
        lines.append(self._colored("Cloud Misconfiguration Scanner - Findings Report", "blue"))
        lines.append(self._colored("=" * 80, "blue"))
        lines.append("")
        return "\n".join(lines)

    def _format_severity_section(self, severity: str, findings: List[Finding]) -> str:
        """Format findings for a severity level."""
        lines = []

        # Severity header
        color_map = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "green",
            "INFO": "white",
        }
        color = color_map.get(severity, "white")

        lines.append(self._colored(f"\n[{severity}] {len(findings)} findings", color))
        lines.append(self._colored("-" * 80, color))

        # Each finding
        for finding in findings:
            lines.append(self._format_finding(finding))

        return "\n".join(lines)

    def _format_finding(self, finding: Finding) -> str:
        """Format a single finding."""
        lines = []

        # Title line
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "green",
            "INFO": "white",
        }.get(finding.severity.value, "white")

        lines.append(
            f"\n  {self._colored(finding.rule_id, severity_color)} - "
            f"{finding.title}"
        )

        # Description
        if finding.description:
            lines.append(f"    {self._indent(finding.description)}")

        # Resource
        lines.append(f"    Resource: {finding.resource_type} [{finding.resource_id}]")

        # Risk
        if finding.risk:
            lines.append(f"    Risk: {self._indent(finding.risk)}")

        # Evidence
        if finding.evidence:
            evidence_str = self._format_dict_compact(finding.evidence)
            lines.append(f"    Evidence: {evidence_str}")

        # Remediation
        if finding.remediation:
            lines.append(f"    Remediation:")
            for line in finding.remediation.split("\n"):
                lines.append(f"      {line}")

        # Documentation link
        if finding.remediation_url:
            lines.append(f"    Reference: {finding.remediation_url}")

        return "\n".join(lines)

    def _format_dict_compact(self, data: dict) -> str:
        """Format dict in compact form."""
        if not data:
            return "N/A"

        items = []
        for k, v in data.items():
            if isinstance(v, dict):
                items.append(f"{k}={{...}}")
            elif isinstance(v, list):
                items.append(f"{k}=[{len(v)} items]")
            else:
                items.append(f"{k}={v}")

        return ", ".join(items[:3])  # Show first 3 items

    def _indent(self, text: str, spaces: int = 6) -> str:
        """Indent multi-line text."""
        lines = text.split("\n")
        indent = " " * spaces
        return ("\n" + indent).join(lines)

    def _colored(self, text: str, color: str) -> str:
        """Apply color if colors are available."""
        if not HAS_COLORS:
            return text

        color_map = {
            "red": Fore.RED,
            "yellow": Fore.YELLOW,
            "cyan": Fore.CYAN,
            "green": Fore.GREEN,
            "blue": Fore.BLUE,
            "white": Fore.WHITE,
        }

        return color_map.get(color, "") + text + Style.RESET_ALL

    def _get_summary(self, findings: List[Finding]) -> str:
        """Get summary statistics."""
        lines = []

        counts = self._get_severity_count(findings)

        lines.append("")
        lines.append(self._colored("Summary", "blue"))
        lines.append(self._colored("-" * 80, "blue"))

        lines.append(
            f"  Critical: {self._colored(str(counts['CRITICAL']), 'red')}  "
            f"High: {self._colored(str(counts['HIGH']), 'yellow')}  "
            f"Medium: {self._colored(str(counts['MEDIUM']), 'cyan')}  "
            f"Low: {self._colored(str(counts['LOW']), 'green')}  "
            f"Info: {counts['INFO']}"
        )
        lines.append(f"  Total: {len(findings)}")
        lines.append("")

        if len(findings) > 0:
            lines.append(
                self._colored(
                    "⚠️  Address CRITICAL and HIGH findings immediately",
                    "red"
                )
            )
        else:
            lines.append(
                self._colored("✓ No findings. Well done!", "green")
            )

        lines.append("")

        return "\n".join(lines)
