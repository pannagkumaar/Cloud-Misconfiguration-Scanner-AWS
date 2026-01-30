"""
Website Security Scanner - Identifies AWS misconfigurations exposed on websites.

Stage 1 of pentesting: Passive reconnaissance to identify AWS infrastructure.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class WebsiteIndicator:
    """Indicator of potential AWS misconfiguration found on website."""
    indicator_type: str  # 'header', 'dns', 'certificate', 'error_message', 'subdomain', 'credential', 's3_bucket'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    title: str
    description: str
    evidence: str
    remediation: str
    aws_service: Optional[str] = None  # Affected AWS service if identified


class WebsiteScanner:
    """Scans website for AWS misconfigurations and exposed resources."""

    # Security headers to check
    SECURITY_HEADERS = [
        ('Strict-Transport-Security', 'HSTS', 'HIGH'),
        ('X-Content-Type-Options', 'Content-Type sniffing protection', 'HIGH'),
        ('X-Frame-Options', 'Clickjacking protection', 'HIGH'),
        ('Content-Security-Policy', 'XSS protection', 'MEDIUM'),
        ('X-XSS-Protection', 'XSS filter', 'MEDIUM'),
        ('Referrer-Policy', 'Referrer information disclosure', 'LOW'),
        ('Permissions-Policy', 'Browser feature access control', 'LOW'),
        ('Cache-Control', 'Cache directives', 'MEDIUM'),
    ]

    # AWS credential patterns
    CREDENTIAL_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
        'aws_session_token': r'(?i)aws_session_token["\']?\s*[:=]',
    }

    # S3 bucket naming patterns
    S3_PATTERNS = {
        'bucket_url': r'https?://([a-z0-9.-]+)\.s3[.-]',
        'bucket_vhost': r'https?://([a-z0-9.-]+)\.s3\.amazonaws\.com',
        'bucket_path': r'https?://s3[.-]amazonaws\.com/([a-z0-9.-]+)',
    }

    # Common AWS subdomains
    COMMON_SUBDOMAINS = [
        'api', 'admin', 'cdn', 'mail', 'smtp', 'ftp', 'sftp', 'vpn',
        'staging', 'dev', 'test', 'prod', 'production',
        'aws', 'cloud', 'api-gateway', 'lambda', 'rds',
        'elasticache', 'backup', 'logs', 'metrics', 'monitoring',
    ]

    def __init__(self, url: str, timeout: int = 10, check_subdomains: bool = True):
        """
        Initialize website scanner.

        Args:
            url: Website URL to scan (e.g., https://example.com)
            timeout: Request timeout in seconds
            check_subdomains: Whether to check common subdomains
        """
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.check_subdomains = check_subdomains
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CloudScan-Website-Scanner/0.1.0'
        })
        self.indicators: List[WebsiteIndicator] = []
        self.found_subdomains: Set[str] = set()

    def scan(self) -> List[WebsiteIndicator]:
        """
        Perform full website security scan.

        Returns:
            List of security indicators found
        """
        logger.info(f"Scanning website: {self.url}")
        self.indicators = []
        self.found_subdomains = set()

        try:
            # Stage 1: HTTP security headers
            self._scan_security_headers()

            # Stage 2: SSL/TLS certificate
            self._scan_ssl_certificate()

            # Stage 3: DNS records
            self._scan_dns_records()

            # Stage 4: AWS-specific indicators
            self._scan_aws_indicators()

            # Stage 5: AWS credentials exposure
            self._scan_credential_exposure()

            # Stage 6: S3 bucket discovery
            self._scan_s3_buckets()

            # Stage 7: Subdomain enumeration
            self._scan_subdomains()

            # Stage 8: Error pages
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

            for header, description, severity in self.SECURITY_HEADERS:
                if header not in headers:
                    self.indicators.append(WebsiteIndicator(
                        indicator_type='header',
                        severity=severity,
                        title=f'Missing {header}',
                        description=f'Website missing {description} header',
                        evidence=f'HTTP response does not include {header}',
                        remediation=f'Add {header} to HTTP response headers'
                    ))
                else:
                    # Check for empty or weak values
                    value = headers.get(header, '').strip()
                    if header == 'Content-Security-Policy' and not value:
                        self.indicators.append(WebsiteIndicator(
                            indicator_type='header',
                            severity='MEDIUM',
                            title='Weak Content-Security-Policy',
                            description='CSP header exists but is empty or too permissive',
                            evidence=f'CSP value: {value if value else "empty"}',
                            remediation='Set strict CSP policy restricting script sources'
                        ))

            # Check for server disclosure
            if 'Server' in headers:
                value = headers.get('Server', '').strip()
                if value and not value.startswith('('):
                    self.indicators.append(WebsiteIndicator(
                        indicator_type='header',
                        severity='LOW',
                        title='Server version disclosure',
                        description='Server header reveals technology stack',
                        evidence=f'Server header: {value}',
                        remediation='Remove or obfuscate Server header'
                    ))

            if 'X-Powered-By' in headers:
                self.indicators.append(WebsiteIndicator(
                    indicator_type='header',
                    severity='LOW',
                    title='X-Powered-By disclosure',
                    description='Technology stack exposed via X-Powered-By header',
                    evidence=f'X-Powered-By: {headers.get("X-Powered-By")}',
                    remediation='Remove X-Powered-By header'
                ))

            # Check AWS-specific headers
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
        """Validate SSL/TLS certificate using proper methods."""
        logger.info("Checking SSL/TLS certificate...")

        try:
            import ssl
            from datetime import datetime

            parsed = urlparse(self.url)
            hostname = parsed.hostname or parsed.netloc

            try:
                context = ssl.create_default_context()
                
                # Use socket-based SSL connection
                import socket
                with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
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

                        # Check certificate subject
                        subject = dict([x[0] for x in cert.get('subject', [])])
                        if 'commonName' in subject:
                            cn = subject['commonName']
                            if '*' not in cn and cn != hostname:
                                self.indicators.append(WebsiteIndicator(
                                    indicator_type='certificate',
                                    severity='HIGH',
                                    title='Certificate CN mismatch',
                                    description=f'Certificate CN ({cn}) does not match hostname ({hostname})',
                                    evidence=f'Certificate CN: {cn}, Requested: {hostname}',
                                    remediation='Obtain certificate matching the hostname'
                                ))

            except ssl.SSLError as e:
                self.indicators.append(WebsiteIndicator(
                    indicator_type='certificate',
                    severity='HIGH',
                    title='SSL/TLS validation failed',
                    description=f'SSL certificate validation error: {str(e)}',
                    evidence=f'SSL Error: {str(e)}',
                    remediation='Fix SSL certificate configuration'
                ))

        except ImportError:
            logger.debug("Required modules not available for SSL checking")
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
                answers = dns.resolver.resolve(hostname, 'A')
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

            aws_indicators = {
                's3': ('S3 bucket reference', 'amazonaws.com/'),
                'cloudfront': ('CloudFront distribution', 'cloudfront.net'),
                'ec2': ('EC2 instance metadata', 'metadata.aws.internal'),
                'rds': ('RDS database endpoint', '.rds.amazonaws.com'),
                'elasticache': ('ElastiCache endpoint', 'cache.amazonaws.com'),
                'apigateway': ('API Gateway', 'execute-api.amazonaws.com'),
                'cognito': ('Cognito service', 'cognito-idp.amazonaws.com'),
                'dynamodb': ('DynamoDB service', 'dynamodb.amazonaws.com'),
                'lambda': ('Lambda function', 'lambda.amazonaws.com'),
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

    def _scan_credential_exposure(self):
        """Check for exposed AWS credentials."""
        logger.info("Scanning for credential exposure...")

        try:
            response = self.session.get(self.url, timeout=self.timeout)
            content = response.text

            for cred_type, pattern in self.CREDENTIAL_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    self.indicators.append(WebsiteIndicator(
                        indicator_type='credential',
                        severity='CRITICAL',
                        title=f'Exposed AWS {cred_type.replace("_", " ")}',
                        description='AWS credentials exposed in website content',
                        evidence=f'Found {len(matches)} instance(s) of {cred_type}',
                        remediation='Immediately revoke exposed credentials and rotate keys',
                        aws_service='IAM'
                    ))

        except Exception as e:
            logger.warning(f"Credential scan failed: {e}")

    def _scan_s3_buckets(self):
        """Discover S3 buckets."""
        logger.info("Scanning for S3 bucket discovery...")

        try:
            response = self.session.get(self.url, timeout=self.timeout)
            content = response.text

            found_buckets = set()

            for pattern_name, pattern in self.S3_PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    bucket_name = match.split('/')[0] if '/' in match else match
                    if bucket_name not in found_buckets:
                        found_buckets.add(bucket_name)

                        self.indicators.append(WebsiteIndicator(
                            indicator_type='s3_bucket',
                            severity='INFO',
                            title=f'S3 bucket discovered: {bucket_name}',
                            description=f'S3 bucket found in website content',
                            evidence=f'Bucket name: {bucket_name} (pattern: {pattern_name})',
                            remediation='Verify S3 bucket permissions are properly restricted',
                            aws_service='S3'
                        ))

        except Exception as e:
            logger.warning(f"S3 bucket scan failed: {e}")

    def _scan_subdomains(self):
        """Enumerate common subdomains."""
        logger.info("Enumerating common subdomains...")

        if not self.check_subdomains:
            return

        try:
            parsed = urlparse(self.url)
            hostname = parsed.hostname or parsed.netloc
            base_domain = '.'.join(hostname.split('.')[-2:])  # Get base domain

            for subdomain in self.COMMON_SUBDOMAINS:
                test_url = f"https://{subdomain}.{base_domain}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout / 2)
                    if response.status_code < 400:
                        self.found_subdomains.add(subdomain)
                        self.indicators.append(WebsiteIndicator(
                            indicator_type='subdomain',
                            severity='INFO',
                            title=f'Subdomain discovered: {subdomain}.{base_domain}',
                            description=f'Active subdomain found during enumeration',
                            evidence=f'HTTP {response.status_code} response from {test_url}',
                            remediation='Review subdomain purpose and ensure it is properly secured'
                        ))
                except requests.RequestException:
                    pass

        except Exception as e:
            logger.warning(f"Subdomain enumeration failed: {e}")

    def _scan_error_pages(self):
        """Check error pages for information disclosure."""
        logger.info("Checking error pages...")

        try:
            test_paths = ['/admin', '/api', '/backup', '/config', '/.aws', '/aws', '/cloud']

            for path in test_paths:
                try:
                    response = self.session.get(f"{self.url}{path}", timeout=self.timeout)

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

