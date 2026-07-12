"""Tests for ScannerConfig: YAML loading, dotted-key lookup, env overrides."""

import os

import pytest

from cloudscan.config import ScannerConfig


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "aws:\n  region: us-east-1\n  profile: default\n"
        "scanner:\n  services: [iam, s3]\n"
    )
    return str(path)


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        ScannerConfig("/nonexistent/config.yaml")


def test_get_dotted_key(config_file):
    cfg = ScannerConfig(config_file)
    assert cfg.get("aws.region") == "us-east-1"


def test_get_missing_key_returns_default(config_file):
    cfg = ScannerConfig(config_file)
    assert cfg.get("aws.nonexistent", "fallback") == "fallback"

def test_get_aws_config(config_file):
    cfg = ScannerConfig(config_file)
    assert cfg.get_aws_config()["region"] == "us-east-1"


def test_env_override_region(config_file, monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    cfg = ScannerConfig(config_file)
    assert cfg.get("aws.region") == "eu-west-1"


def test_env_override_services(config_file, monkeypatch):
    monkeypatch.setenv("SCANNER_SERVICES", "iam,rds")
    cfg = ScannerConfig(config_file)
    assert cfg.get("scanner.services") == ["iam", "rds"]


def test_no_env_override_when_unset(config_file, monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    cfg = ScannerConfig(config_file)
    assert cfg.get("aws.region") == "us-east-1"
