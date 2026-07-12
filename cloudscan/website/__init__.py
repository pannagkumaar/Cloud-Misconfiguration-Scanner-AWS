"""
Website Security Scanner - Identifies misconfigurations exposed on websites.

Stage 1 of pentesting workflow: Passive reconnaissance to identify AWS infrastructure.
"""

from cloudscan.website.output import WebsiteOutputFormatter
from cloudscan.website.scanner import WebsiteIndicator, WebsiteScanner

__all__ = ["WebsiteScanner", "WebsiteIndicator", "WebsiteOutputFormatter"]
