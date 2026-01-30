"""
Website Scanner Output Formatter - Formats website scan results.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime

try:
    from colorama import Fore, Back, Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False


logger = logging.getLogger(__name__)


class WebsiteOutputFormatter:
    """Formats website scanner results for console output."""

    SEVERITY_COLORS = {
        'CRITICAL': Fore.RED if HAS_COLORAMA else '',
        'HIGH': Fore.RED if HAS_COLORAMA else '',
        'MEDIUM': Fore.YELLOW if HAS_COLORAMA else '',
        'LOW': Fore.YELLOW if HAS_COLORAMA else '',
        'INFO': Fore.CYAN if HAS_COLORAMA else '',
    }

    def __init__(self, output_file: str = None):
        """Initialize formatter."""
        self.output_file = output_file

    def format(self, url: str, indicators: List[Any], aws_services: List[str]) -> str:
        """
        Format website scan results.

        Args:
            url: Scanned URL
            indicators: List of WebsiteIndicator objects
            aws_services: List of AWS services detected

        Returns:
            Formatted output string
        """
        output = []

        # Header
        output.append("=" * 80)
        output.append("Website Security Scanner - Reconnaissance Report")
        output.append("=" * 80)
        output.append(f"URL: {url}")
        output.append(f"Timestamp: {datetime.utcnow().isoformat()}Z")
        output.append("")

        # AWS Detection Summary
        if aws_services:
            color = Fore.YELLOW if HAS_COLORAMA else ''
            reset = Style.RESET_ALL if HAS_COLORAMA else ''
            output.append(f"{color}AWS Infrastructure Detected:{reset}")
            output.append(f"  Services found: {', '.join(aws_services)}")
            output.append("")
            output.append("  RECOMMENDATION: Switch to AWS Scanner for deep analysis")
            output.append("  Command: cloudscan aws-scan --from-file <aws-config.json>")
            output.append("")
        else:
            output.append("No AWS infrastructure detected on website")
            output.append("")

        # Indicators by severity
        if not indicators:
            output.append("No security indicators found. Well done!")
        else:
            # Group by severity
            by_severity = {}
            for indicator in indicators:
                if indicator.severity not in by_severity:
                    by_severity[indicator.severity] = []
                by_severity[indicator.severity].append(indicator)

            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

            for severity in severity_order:
                if severity in by_severity:
                    color = self.SEVERITY_COLORS.get(severity, '')
                    reset = Style.RESET_ALL if HAS_COLORAMA else ''

                    output.append(f"{color}[{severity}]{reset} {severity} Severity Indicators ({len(by_severity[severity])})")
                    output.append("-" * 80)

                    for indicator in by_severity[severity]:
                        output.append(f"  {indicator.title}")
                        if indicator.aws_service:
                            output.append(f"    AWS Service: {indicator.aws_service}")
                        output.append(f"    Type: {indicator.indicator_type}")
                        output.append(f"    Description: {indicator.description}")
                        output.append(f"    Evidence: {indicator.evidence}")
                        output.append(f"    Remediation: {indicator.remediation}")
                        output.append("")

        # Summary
        output.append("=" * 80)
        output.append("Summary")
        output.append("-" * 80)
        critical = len([i for i in indicators if i.severity == 'CRITICAL'])
        high = len([i for i in indicators if i.severity == 'HIGH'])
        medium = len([i for i in indicators if i.severity == 'MEDIUM'])
        low = len([i for i in indicators if i.severity == 'LOW'])
        info = len([i for i in indicators if i.severity == 'INFO'])

        output.append(f"  CRITICAL: {critical}  HIGH: {high}  MEDIUM: {medium}  LOW: {low}  INFO: {info}")
        output.append(f"  Total: {len(indicators)}")
        output.append("")

        if aws_services:
            output.append("Next Steps:")
            output.append("  1. If you have AWS credentials, export the configuration:")
            output.append("     ./scripts/export_aws_config.sh --profile <profile> > aws-config.json")
            output.append("  2. Run AWS Scanner for deep analysis:")
            output.append("     cloudscan aws-scan --from-file aws-config.json")

        output.append("=" * 80)

        return "\n".join(output)

    def write(self, content: str):
        """Write output to file or stdout."""
        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(content)
            logger.info(f"Output written to {self.output_file}")
        else:
            print(content)
