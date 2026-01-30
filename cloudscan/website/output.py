"""
Website Scanner Output Formatter - Formats website scan results.
"""

import logging
import json
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

    INDICATOR_TYPE_NAMES = {
        'header': 'Security Header',
        'dns': 'DNS Record',
        'certificate': 'SSL Certificate',
        'error_message': 'Error Disclosure',
        'subdomain': 'Subdomain',
        'credential': 'Exposed Credential',
        's3_bucket': 'S3 Bucket',
        'aws_service': 'AWS Service',
    }

    def __init__(self, output_file: str = None, output_format: str = 'console'):
        """Initialize formatter."""
        self.output_file = output_file
        self.output_format = output_format

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
        if self.output_format == 'json':
            return self._format_json(url, indicators, aws_services)
        else:
            return self._format_console(url, indicators, aws_services)

    def _format_console(self, url: str, indicators: List[Any], aws_services: List[str]) -> str:
        """Format for console output."""
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
                    type_name = self.INDICATOR_TYPE_NAMES.get(by_severity[severity][0].indicator_type, by_severity[severity][0].indicator_type)

                    output.append(f"{color}[{severity}]{reset} {severity} Severity Indicators ({len(by_severity[severity])})")
                    output.append("-" * 80)

                    for indicator in by_severity[severity]:
                        output.append(f"  {indicator.title}")
                        if indicator.aws_service:
                            output.append(f"    AWS Service: {indicator.aws_service}")
                        output.append(f"    Type: {self.INDICATOR_TYPE_NAMES.get(indicator.indicator_type, indicator.indicator_type)}")
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

        # Statistics
        indicator_types = {}
        for indicator in indicators:
            itype = self.INDICATOR_TYPE_NAMES.get(indicator.indicator_type, indicator.indicator_type)
            indicator_types[itype] = indicator_types.get(itype, 0) + 1
        
        if indicator_types:
            output.append("Indicator Types:")
            for itype, count in sorted(indicator_types.items()):
                output.append(f"  {itype}: {count}")
            output.append("")

        if aws_services:
            output.append("Next Steps:")
            output.append("  1. If you have AWS credentials, export the configuration:")
            output.append("     ./scripts/export_aws_config.sh --profile <profile> > aws-config.json")
            output.append("  2. Run AWS Scanner for deep analysis:")
            output.append("     cloudscan aws-scan --from-file aws-config.json")

        output.append("=" * 80)

        return "\n".join(output)

    def _format_json(self, url: str, indicators: List[Any], aws_services: List[str]) -> str:
        """Format for JSON output."""
        data = {
            'scan': {
                'url': url,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'scanner': 'CloudScan-Website-Scanner',
                'version': '0.1.0'
            },
            'aws_services': aws_services,
            'indicators': [],
            'summary': {
                'total': len(indicators),
                'critical': len([i for i in indicators if i.severity == 'CRITICAL']),
                'high': len([i for i in indicators if i.severity == 'HIGH']),
                'medium': len([i for i in indicators if i.severity == 'MEDIUM']),
                'low': len([i for i in indicators if i.severity == 'LOW']),
                'info': len([i for i in indicators if i.severity == 'INFO']),
            }
        }

        for indicator in indicators:
            data['indicators'].append({
                'type': indicator.indicator_type,
                'severity': indicator.severity,
                'title': indicator.title,
                'description': indicator.description,
                'evidence': indicator.evidence,
                'remediation': indicator.remediation,
                'aws_service': indicator.aws_service,
            })

        return json.dumps(data, indent=2)

    def write(self, content: str):
        """Write output to file or stdout."""
        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(content)
            logger.info(f"Output written to {self.output_file}")
        else:
            print(content)

