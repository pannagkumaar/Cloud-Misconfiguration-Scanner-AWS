"""Tests for FileLoader: offline config loading + normalization + error handling."""

import json

import pytest
import yaml

from cloudscan.loaders.file_loader import FileLoader


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        FileLoader(str(tmp_path / "does-not-exist.json"))


def test_unsupported_extension_raises(tmp_path):
    path = tmp_path / "config.txt"
    path.write_text("not json")
    with pytest.raises(ValueError):
        FileLoader(str(path))


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    loader = FileLoader(str(path))
    with pytest.raises(ValueError):
        loader.load()


def test_missing_required_keys_raises(tmp_path):
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps({"services": ["s3"]}))  # missing "data"
    loader = FileLoader(str(path))
    with pytest.raises(ValueError):
        loader.load()


def test_loads_and_normalizes_raw_json(tmp_path):
    raw = {
        "services": ["s3"],
        "data": {"s3": {"buckets": {"Buckets": [{"Name": "b1", "CreationDate": "x"}]}}},
    }
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(raw))
    loader = FileLoader(str(path))
    data = loader.load()
    assert data["data"]["s3"]["buckets"][0]["name"] == "b1"


def test_loads_yaml(tmp_path):
    raw = {
        "services": ["s3"],
        "data": {"s3": {"buckets": [{"name": "b1", "created": "x", "region": "us-east-1",
                                      "policy": None, "acl": None,
                                      "public_access_block": {"block_public_acls": True,
                                                               "ignore_public_acls": True,
                                                               "block_public_policy": True,
                                                               "restrict_public_buckets": True},
                                      "versioning": None, "logging": None, "encryption": None,
                                      "tags": None}]}},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(raw))
    loader = FileLoader(str(path))
    data = loader.load()
    assert data["data"]["s3"]["buckets"][0]["name"] == "b1"
