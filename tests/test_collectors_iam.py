"""
Unit tests for IAMCollector's credential report parsing and password policy
collection. These use hand-crafted CSV content / a fake boto3 client rather
than moto, since they're testing pure parsing logic and ClientError-code
handling, not real AWS API interaction (that's covered by
test_integration_moto.py).
"""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cloudscan.collectors.iam import IAMCollector

CSV_HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,"
    "password_last_changed,password_next_rotation,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,"
    "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
)


def csv_row(**overrides):
    defaults = {
        "user": "alice", "arn": "arn:aws:iam::123:user/alice",
        "user_creation_time": "2024-01-01T00:00:00Z",
        "password_enabled": "true", "password_last_used": "2024-06-01T00:00:00Z",
        "password_last_changed": "N/A", "password_next_rotation": "N/A",
        "mfa_active": "false",
        "access_key_1_active": "true", "access_key_1_last_rotated": "2024-01-01T00:00:00Z",
        "access_key_1_last_used_date": "N/A", "access_key_1_last_used_region": "N/A",
        "access_key_1_last_used_service": "N/A",
        "access_key_2_active": "false", "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A", "access_key_2_last_used_region": "N/A",
        "access_key_2_last_used_service": "N/A",
        "cert_1_active": "false", "cert_1_last_rotated": "N/A",
        "cert_2_active": "false", "cert_2_last_rotated": "N/A",
    }
    defaults.update(overrides)
    return ",".join(defaults[k] for k in [
        "user", "arn", "user_creation_time", "password_enabled", "password_last_used",
        "password_last_changed", "password_next_rotation", "mfa_active",
        "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
        "access_key_1_last_used_region", "access_key_1_last_used_service",
        "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
        "access_key_2_last_used_region", "access_key_2_last_used_service",
        "cert_1_active", "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated",
    ])


class TestParseCredentialReport:
    def test_parses_regular_user_row(self):
        content = CSV_HEADER + csv_row() + "\n"
        rows = IAMCollector(MagicMock())._parse_credential_report(content.encode("utf-8"))
        assert len(rows) == 1
        row = rows[0]
        assert row["user"] == "alice"
        assert row["is_root"] is False
        assert row["mfa_active"] is False
        assert row["password_enabled"] is True
        assert row["access_key_1_active"] is True
        assert row["access_key_1_last_used"] is None  # "N/A" -> None

    def test_identifies_root_account_row(self):
        content = CSV_HEADER + csv_row(user="<root_account>", arn="arn:aws:iam::123:root") + "\n"
        rows = IAMCollector(MagicMock())._parse_credential_report(content.encode("utf-8"))
        assert rows[0]["is_root"] is True

    def test_accepts_str_as_well_as_bytes(self):
        content = CSV_HEADER + csv_row() + "\n"
        rows = IAMCollector(MagicMock())._parse_credential_report(content)
        assert len(rows) == 1

    def test_mfa_active_true(self):
        content = CSV_HEADER + csv_row(mfa_active="true") + "\n"
        rows = IAMCollector(MagicMock())._parse_credential_report(content.encode("utf-8"))
        assert rows[0]["mfa_active"] is True

    def test_multiple_rows(self):
        content = CSV_HEADER + csv_row(user="alice") + "\n" + csv_row(user="bob") + "\n"
        rows = IAMCollector(MagicMock())._parse_credential_report(content.encode("utf-8"))
        assert {r["user"] for r in rows} == {"alice", "bob"}


class TestCsvHelpers:
    def test_csv_bool_true(self):
        assert IAMCollector._csv_bool("true") is True
        assert IAMCollector._csv_bool("TRUE") is True

    def test_csv_bool_false(self):
        assert IAMCollector._csv_bool("false") is False
        assert IAMCollector._csv_bool("N/A") is False

    def test_csv_optional_na_becomes_none(self):
        assert IAMCollector._csv_optional("N/A") is None
        assert IAMCollector._csv_optional("not_supported") is None
        assert IAMCollector._csv_optional("") is None

    def test_csv_optional_passes_through_value(self):
        assert IAMCollector._csv_optional("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"


class TestPasswordPolicyCollection:
    def _client_error(self, code):
        return ClientError({"Error": {"Code": code, "Message": "x"}}, "GetAccountPasswordPolicy")

    def test_policy_exists(self):
        mock_client = MagicMock()
        mock_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14, "RequireSymbols": True,
                "RequireNumbers": True, "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True, "MaxPasswordAge": 90,
                "PasswordReusePrevention": 24,
            }
        }
        result = IAMCollector(MagicMock())._collect_password_policy(mock_client)
        assert result["exists"] is True
        assert result["minimum_password_length"] == 14

    def test_no_such_entity_means_no_custom_policy(self):
        mock_client = MagicMock()
        mock_client.get_account_password_policy.side_effect = self._client_error("NoSuchEntity")
        result = IAMCollector(MagicMock())._collect_password_policy(mock_client)
        assert result == {"exists": False}

    def test_other_client_error_does_not_crash(self):
        mock_client = MagicMock()
        mock_client.get_account_password_policy.side_effect = self._client_error("AccessDenied")
        result = IAMCollector(MagicMock())._collect_password_policy(mock_client)
        assert result == {"exists": False}
