"""Tests for cloudscan.schema: the normalized data contract helpers."""

from cloudscan.schema import empty_service_data, is_normalized, validate


class TestIsNormalized:
    def test_normalized_s3_payload(self):
        payload = {"buckets": [{"name": "b1"}]}
        assert is_normalized("s3", payload) is True

    def test_raw_s3_payload(self):
        payload = {"buckets": {"Buckets": [{"Name": "b1"}]}}
        assert is_normalized("s3", payload) is False

    def test_empty_payload_is_normalized(self):
        assert is_normalized("s3", {}) is True

    def test_unknown_service_assumed_normalized(self):
        assert is_normalized("unknown-service", {"anything": "goes"}) is True

    def test_non_dict_is_not_normalized(self):
        assert is_normalized("s3", "not-a-dict") is False


class TestEmptyServiceData:
    def test_iam_shape(self):
        data = empty_service_data("iam")
        assert data["users"] == []
        assert data["credential_report"]["rows"] == []

    def test_unknown_service(self):
        data = empty_service_data("mystery")
        assert data == {"service": "mystery"}


class TestValidate:
    def test_valid_structure(self):
        data = {"services": ["s3"], "data": {"s3": {"buckets": []}}}
        assert validate(data) == []

    def test_missing_top_level_keys(self):
        problems = validate({"services": ["s3"]})
        assert len(problems) == 1

    def test_service_with_error_is_valid(self):
        data = {"services": ["s3"], "data": {"s3": {"error": "AccessDenied"}}}
        assert validate(data) == []

    def test_non_normalized_service_flagged(self):
        data = {"services": ["s3"], "data": {"s3": {"buckets": {"Buckets": []}}}}
        problems = validate(data)
        assert len(problems) == 1
        assert "s3" in problems[0]
