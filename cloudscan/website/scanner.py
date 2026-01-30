"""
Website Security Scanner - Identifies AWS misconfigurations exposed on websites.

Stage 1 of pentesting: Passive reconnaissance to identify AWS infrastructure.
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class WebsiteIndicator:
    """Indicator of potential AWS misconfiguration found on website."""
    indicator_type: str  # 'header', 'dns', 'certificate', 'error_message', 'subdomain'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    title: str
    description: str
    evidence: str
    remediation: str
    aws_service: Optional[str] = None  # Affected AWS service if identified


class WebsiteScanner:
    """Scans website for AWS misconfigurations and exposed resources."""

    def __init__(self, url: str, timeout: int = 10):
        """
        Initialize website scanner.

        Args:
            url: Website URL to scan (e.g., https://example.com)
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CloudScan-Website-Scanner/0.1.0'
        })
        self.indicators: List[WebsiteIndicator] = []

    def scan(self) -> List[WebsiteIndicator]:
        """
        Perform full website security scan.

        Returns:
            List of security indicators found
        """
        logger.info(f"Scanning website: {self.url}")
        self.indicators = []

        try:
            # Stage 1: HTTP security headers
            self._scan_security_headers()

            # Stage 2: SSL/TLS certificate
            self._scan_ssl_certificate()

            # Stage 3: DNS records
            self._scan_dns_records()

            # Stage 4: AWS-specific indicators
            self._scan_aws_indicators()

            # Stage 5: Error pages
            self._scan_error_pages()

            logger.info(f"Website scan complete: found {len(self.indicators)} indicators")
            return self.indicators

        except Exception as e:
            logger.error(f"Website scan failed: {e}")
            raise

    def _scan_security_headers(self):
        """Check for missing security headers."""
        logger.info("Checking security headers...")

        try:
            response = self.session.get(self.url, timeout=self.timeout)

            headers = response.headers
            missing_headers = [
                ('Strict-Transport-Security', 'HSTS', 'HIGH'),
                ('X-Content-Type-Options', 'Content-Type sniffing protection', 'HIGH'),
                ('X-Frame-Options', 'Clickjacking protection', 'HIGH'),
                ('Content-Security-Policy', 'XSS protection', 'MEDIUM'),
                ('X-XSS-Protection', 'XSS filter', 'MEDIUM'),
            ]

            for header, description, severity in missing_headers:
                if header not in headers:
                    self.indicators.append(WebsiteIndicator(
                        indicator_type='header',
                        severity=severity,
                        title=f'Missing {header}',
                        description=f'Website missing {description} header',
                        evidence=f'HTTP response does not include {header}',
                        remediation=f'Add {header} to HTTP response headers'
                    ))

            # Check for AWS-specific headers
            if 'X-Amzn-RequestId' in headers or 'X-Amz-Cf-Pop' in headers:
                self.indicators.append(WebsiteIndicator(
                    indicator_type='header',
                    severity='INFO',
                    title='AWS infrastructure detected',
                    description='Website is running on AWS infrastructure',
                    evidence=f'Found AWS-specific headers: {[h for h in headers if "amz" in h.lower()]}',
                    remediation='If using AWS, ensure proper security group and IAM configurations',
                    aws_service='Multiple'
                ))

        except requests.RequestException as e:
            logger.warning(f"Failed to fetch headers: {e}")

    def _scan_ssl_certificate(self):
        """Validate SSL/TLS certificate."""
        logger.info("Checking SSL/TLS certificate...")

        try:
            import ssl
            from datetime import datetime

            parsed = urlparse(self.url)
            hostname = parsed.hostname or parsed.netloc

            context = ssl.create_default_context()
            with context.wrap_socket(context.sock_connect((hostname, 443)), server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Check expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days

                if days_until_expiry < 30:
                    severity = 'CRITICAL' if days_until_expiry < 7 else 'HIGH'
                    self.indicators.append(WebsiteIndicator(
                        indicator_type='certificate',
                        severity=severity,
                        title='SSL certificate expiring soon',
                        description=f'Certificate expires in {days_until_expiry} days',
                        evidence=f'Certificate expiry date: {not_after}',
                        remediation='Renew SSL certificate before expiration'
                    ))

                # Check for self-signed
                if cert.get('issuer') == cert.get('subject'):
                    self.indicators.append(WebsiteIndicator(
                        indicator_type='certificate',
                        severity='HIGH',
                        title='Self-signed SSL certificate',
                        description='Website uses self-signed certificate instead of trusted CA',
                        evidence='Certificate issuer matches subject (self-signed)',
                        remediation='Obtain certificate from trusted Certificate Authority'
                    ))

        except Exception as e:
            logger.warning(f"SSL check failed: {e}")

    def _scan_dns_records(self):
        """Check DNS records for misconfigurations."""
        logger.info("Checking DNS records...")

        try:
            import dns.resolver

            parsed = urlparse(self.url)
            hostname = parsed.hostname or parsed.netloc

            try:
                # Check for DNSSEC
                answers = dns.resolver.resolve(hostname, 'A')
                # If we get here, basic DNS works
                logger.debug(f"DNS resolution successful for {hostname}")
            except dns.resolver.NXDOMAIN:
                self.indicators.append(WebsiteIndicator(
                    indicator_type='dns',
                    severity='CRITICAL',
                    title='Domain does not resolve',
                    description='DNS resolution failed for this domain',
                    evidence=f'NXDOMAIN for {hostname}',
                    remediation='Verify domain is correctly configured'
                ))

        except ImportError:
            logger.debug("dnspython not installed, skipping DNS checks")
        except Exception as e:
            logger.warning(f"DNS check failed: {e}")

    def _scan_aws_indicators(self):
        """Look for AWS-specific indicators."""
        logger.info("Scanning for AWS indicators...")

        try:
            response = self.session.get(self.url, timeout=self.timeout)
            content = response.text.lower()

            # Check for AWS service mentions
            aws_indicators = {
                's3': ('S3 bucket reference', 'amazonaws.com/'),
                'cloudfront': ('CloudFront distribution', 'cloudfront.net'),
                'ec2': ('EC2 instance metadata', 'metadata.aws.internal'),
                'rds': ('RDS database endpoint', '.rds.amazonaws.com'),
                'elasticache': ('ElastiCache endpoint', 'cache.amazonaws.com'),
                'apigateway': ('API Gateway', 'execute-api.amazonaws.com'),
            }

            for service, (title, pattern) in aws_indicators.items():
                if pattern.lower() in content:
                    self.indicators.append(WebsiteIndicator(
                        indicator_type='aws_service',
                        severity='INFO',
                        title=f'AWS {service.upper()} detected',
                        description=f'Website appears to use AWS {service}',
                        evidence=f'Found reference to: {pattern}',
                        remediation=f'Ensure {service} is properly secured (see AWS {service} best practices)',
                        aws_service=service.upper()
                    ))

        except Exception as e:
            logger.warning(f"AWS indicator scan failed: {e}")

    def _scan_error_pages(self):
        """Check error pages for information disclosure."""
        logger.info("Checking error pages...")

        try:
            # Try accessing non-existent pages
            test_paths = ['/admin', '/api', '/backup', '/config', '/.aws']

            for path in test_paths:
                try:
                    response = self.session.get(f"{self.url}{path}", timeout=self.timeout)

                    # Check for information disclosure in error pages
                    if response.status_code >= 400:
                        if 'aws' in response.text.lower() or 'amazon' in response.text.lower():
                            self.indicators.append(WebsiteIndicator(
                                indicator_type='error_message',
                                severity='MEDIUM',
                                title='AWS information in error page',
                                description=f'Error page at {path} reveals AWS information',
                                evidence=f'Accessing {path} returns AWS-related error message',
                                remediation='Customize error pages to not reveal infrastructure details'
                            ))

                except requests.RequestException:
                    pass

        except Exception as e:
            logger.warning(f"Error page scan failed: {e}")

    def get_aws_services(self) -> List[str]:
        """Get list of AWS services detected on website."""
        services = []
        for indicator in self.indicators:
            if indicator.aws_service and indicator.aws_service not in services:
                services.append(indicator.aws_service)
        return services

    def has_aws_presence(self) -> bool:
        """Check if website appears to use AWS."""
        return len(self.get_aws_services()) > 0
