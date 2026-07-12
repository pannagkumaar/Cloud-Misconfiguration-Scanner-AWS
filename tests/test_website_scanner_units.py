"""
Network-free unit tests for the website scanner's pure logic: the
WebsiteIndicator model, AWS-service aggregation, and the regex patterns
used to detect credentials/S3 buckets in page content. Network-dependent
scan() behavior is out of scope for unit tests (would need HTTP mocking).
"""

import re

from cloudscan.website.scanner import WebsiteIndicator, WebsiteScanner


class TestWebsiteIndicator:
    def test_optional_aws_service_defaults_to_none(self):
        indicator = WebsiteIndicator(
            indicator_type="header", severity="HIGH", title="t",
            description="d", evidence="e", remediation="r",
        )
        assert indicator.aws_service is None


class TestAWSServiceAggregation:
    def test_get_aws_services_deduplicates(self):
        scanner = WebsiteScanner("https://example.com")
        scanner.indicators = [
            WebsiteIndicator("aws_service", "INFO", "t1", "d", "e", "r", aws_service="S3"),
            WebsiteIndicator("aws_service", "INFO", "t2", "d", "e", "r", aws_service="S3"),
            WebsiteIndicator("aws_service", "INFO", "t3", "d", "e", "r", aws_service="RDS"),
        ]
        assert scanner.get_aws_services() == ["S3", "RDS"]

    def test_get_aws_services_ignores_indicators_without_service(self):
        scanner = WebsiteScanner("https://example.com")
        scanner.indicators = [
            WebsiteIndicator("header", "HIGH", "t", "d", "e", "r", aws_service=None),
        ]
        assert scanner.get_aws_services() == []

    def test_has_aws_presence_true_when_services_found(self):
        scanner = WebsiteScanner("https://example.com")
        scanner.indicators = [
            WebsiteIndicator("aws_service", "INFO", "t", "d", "e", "r", aws_service="S3"),
        ]
        assert scanner.has_aws_presence() is True

    def test_has_aws_presence_false_when_no_services(self):
        scanner = WebsiteScanner("https://example.com")
        scanner.indicators = []
        assert scanner.has_aws_presence() is False


class TestCredentialPatterns:
    def test_aws_access_key_pattern_matches(self):
        pattern = WebsiteScanner.CREDENTIAL_PATTERNS["aws_access_key"]
        assert re.search(pattern, "AKIAIOSFODNN7EXAMPLE")

    def test_aws_access_key_pattern_no_false_positive_on_short_string(self):
        pattern = WebsiteScanner.CREDENTIAL_PATTERNS["aws_access_key"]
        assert not re.search(pattern, "AKIA123")

    def test_aws_secret_key_pattern_matches(self):
        pattern = WebsiteScanner.CREDENTIAL_PATTERNS["aws_secret_key"]
        text = 'aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert re.search(pattern, text)


class TestS3BucketPatterns:
    def test_bucket_vhost_pattern_extracts_name(self):
        pattern = WebsiteScanner.S3_PATTERNS["bucket_vhost"]
        match = re.search(pattern, "https://my-bucket.s3.amazonaws.com/file.txt")
        assert match.group(1) == "my-bucket"

    def test_url_constructor_strips_trailing_slash(self):
        scanner = WebsiteScanner("https://example.com/")
        assert scanner.url == "https://example.com"
