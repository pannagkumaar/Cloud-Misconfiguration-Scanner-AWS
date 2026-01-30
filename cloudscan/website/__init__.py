"""
Website Security Scanner - Identifies misconfigurations exposed on websites.

Stage 1 of pentesting workflow: Passive reconnaissance to identify AWS infrastructure.
"""

from cloudscan.website.scanner import WebsiteScanner, WebsiteIndicator
from cloudscan.website.output import WebsiteOutputFormatter

__all__ = ["WebsiteScanner", "WebsiteIndicator", "WebsiteOutputFormatter"]
