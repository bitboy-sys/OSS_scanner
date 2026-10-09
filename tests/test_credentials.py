"""临时凭证（STS）的加载、校验与脱敏。"""
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from utils.credentials import (
    ENV_ACCESS_KEY_ID,
    ENV_ACCESS_KEY_SECRET,
    ENV_SECURITY_TOKEN,
    TemporaryCredential,
    from_file,
    from_mapping,
    load_credential,
    mask_value,
    validate_for_scan,
)


class Args:
    def __init__(self, **kwargs):
        self.sts_ak = kwargs.get("sts_ak", "")
        self.sts_sk = kwargs.get("sts_sk", "")
        self.sts_token = kwargs.get("sts_token", "")
        self.sts_file = kwargs.get("sts_file", "")
        self.cloud = kwargs.get("cloud", "")


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    for name in (ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET, ENV_SECURITY_TOKEN):
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------ 脱敏

def test_mask_value_never_reveals_full_secret():
    assert mask_value("LTAI5tSecretValue") == "LTAI****"
    assert mask_value("abc") == "****"
    assert mask_value("") == ""


def test_repr_does_not_leak_secret():
    """回归防线：日志里一旦打印凭证对象，不能带出密钥与令牌。"""
    credential = TemporaryCredential(
        access_key_id="LTAI5tSecretId",
        access_key_secret="SuperSecretKeyMaterial",
        security_token="VeryLongSecurityTokenValue",
    )
    text = repr(credential) + str(credential) + credential.describe()
    assert "SuperSecretKeyMaterial" not in text
    assert "VeryLongSecurityTokenValue" not in text
    assert "LTAI****" in text


# ------------------------------------------------------------------ 字段兼容

@pytest.mark.parametrize("payload", [
    {"AccessKeyId": "ak", "AccessKeySecret": "sk", "SecurityToken": "t"},
    {"access_key_id": "ak", "access_key_secret": "sk", "security_token": "t"},
    {"SecretId": "ak", "SecretKey": "sk", "Token": "t"},                     # 腾讯云
    {"TmpSecretId": "ak", "TmpSecretKey": "sk", "Token": "t"},               # 腾讯云临时
    {"accessKeyId": "ak", "secretAccessKey": "sk", "sessionToken": "t"},     # AWS SDK
])
def test_from_mapping_accepts_vendor_field_names(payload):
    credential = from_mapping(payload, provider="aliyun")
    assert credential is not None
    assert credential.access_key_id == "ak"
    assert credential.access_key_secret == "sk"
    assert credential.security_token == "t"


def test_from_mapping_requires_both_key_parts():
    assert from_mapping({"AccessKeyId": "ak"}) is None
    assert from_mapping({"AccessKeySecret": "sk"}) is None
    assert from_mapping({}) is None
    assert from_mapping("not a dict") is None


def test_from_mapping_reads_expiration():
    credential = from_mapping({"AccessKeyId": "ak", "AccessKeySecret": "sk",
                               "Expiration": "2026-10-09T12:00:00Z"})
    assert credential.expires_at == "2026-10-09T12:00:00Z"


# ------------------------------------------------------------------ 过期判断

def test_expiry_state_detects_expired_and_expiring():
    now = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
    expired = TemporaryCredential("ak", "sk", expires_at="2026-10-09T11:00:00Z")
    soon = TemporaryCredential("ak", "sk",
                               expires_at=(now + timedelta(minutes=3)).isoformat())
    fresh = TemporaryCredential("ak", "sk",
                                expires_at=(now + timedelta(hours=4)).isoformat())
    assert expired.expiry_state(now) == "expired"
    assert soon.expiry_state(now) == "expiring"
    assert fresh.expiry_state(now) == "valid"


def test_expiry_state_none_without_expiration():
    assert TemporaryCredential("ak", "sk").expiry_state() is None


def test_expiry_state_survives_bad_format():
    assert TemporaryCredential("ak", "sk", expires_at="不是时间").expiry_state() is None


# ------------------------------------------------------------------ 加载优先级

def test_load_from_cli_args():
    credential, error = load_credential(
        Args(sts_ak="ak", sts_sk="sk", sts_token="t", cloud="aliyun"), {}, "aliyun")
    assert error is None
    assert credential.access_key_id == "ak"
    assert credential.source == "命令行参数"


def test_partial_cli_args_is_an_error():
    """只给一半会让请求静默退化成匿名，必须明确报错。"""
    credential, error = load_credential(Args(sts_ak="ak"), {}, "aliyun")
    assert credential is None
    assert error and "同时提供" in error


def test_load_from_env(monkeypatch):
    monkeypatch.setenv(ENV_ACCESS_KEY_ID, "env-ak")
    monkeypatch.setenv(ENV_ACCESS_KEY_SECRET, "env-sk")
    monkeypatch.setenv(ENV_SECURITY_TOKEN, "env-token")
    credential, error = load_credential(Args(), {}, "aws")
    assert error is None
    assert credential.access_key_id == "env-ak"
    assert credential.security_token == "env-token"
    assert "环境变量" in credential.source


def test_cli_takes_priority_over_env(monkeypatch):
    monkeypatch.setenv(ENV_ACCESS_KEY_ID, "env-ak")
    monkeypatch.setenv(ENV_ACCESS_KEY_SECRET, "env-sk")
    credential, _ = load_credential(Args(sts_ak="cli-ak", sts_sk="cli-sk"), {}, "aws")
    assert credential.access_key_id == "cli-ak"


def test_load_from_file_with_assume_role_envelope(tmp_path):
    path = tmp_path / "creds.json"
    path.write_text(json.dumps({"Credentials": {
        "AccessKeyId": "file-ak", "AccessKeySecret": "file-sk",
        "SecurityToken": "file-token", "Expiration": "2026-10-09T20:00:00Z",
    }}), encoding="utf-8")
    credential, error = load_credential(Args(sts_file=path.as_posix()), {}, "aws")
    assert error is None
    assert credential.access_key_id == "file-ak"
    assert credential.security_token == "file-token"


def test_missing_file_reports_error(tmp_path):
    _, error = load_credential(Args(sts_file=(tmp_path / "nope.json").as_posix()), {}, "aws")
    assert error and "未找到" in error


def test_unusable_file_reports_error(tmp_path):
    path = tmp_path / "creds.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    _, error = load_credential(Args(sts_file=path.as_posix()), {}, "aws")
    assert error and "未找到可用" in error


def test_load_from_config_section():
    config = {"STS": {"AccessKeyId": "cfg-ak", "AccessKeySecret": "cfg-sk"}}
    credential, error = load_credential(Args(), config, "aliyun")
    assert error is None
    assert credential.access_key_id == "cfg-ak"
    assert credential.source == "配置文件 [STS]"


def test_no_credential_configured_returns_nothing():
    credential, error = load_credential(Args(), {}, "aliyun")
    assert credential is None and error is None


def test_from_file_expands_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", tmp_path.as_posix())
    monkeypatch.setenv("USERPROFILE", tmp_path.as_posix())
    target = tmp_path / "creds.json"
    target.write_text(json.dumps({"AccessKeyId": "ak", "AccessKeySecret": "sk"}), encoding="utf-8")
    assert from_file("~/creds.json") is not None


# ------------------------------------------------------------------ 校验

def test_validate_rejects_expired_credential():
    credential = TemporaryCredential("ak", "sk", expires_at="2020-01-01T00:00:00Z")
    problem = validate_for_scan(credential, "aliyun")
    assert problem and "已过期" in problem


def test_validate_rejects_azure():
    problem = validate_for_scan(TemporaryCredential("ak", "sk"), "azure")
    assert problem and "Azure" in problem


def test_validate_requires_token_when_asked():
    problem = validate_for_scan(TemporaryCredential("ak", "sk"), "aliyun", require_token=True)
    assert problem and "SecurityToken" in problem
    assert validate_for_scan(TemporaryCredential("ak", "sk", "t"), "aliyun",
                            require_token=True) is None


def test_validate_passes_for_anonymous():
    assert validate_for_scan(None, "aliyun") is None


def test_token_header_per_provider():
    assert TemporaryCredential("ak", "sk", provider="aliyun").token_header == "x-oss-security-token"
    assert TemporaryCredential("ak", "sk", provider="aws").token_header == "x-amz-security-token"
    assert TemporaryCredential("ak", "sk", provider="tencent").token_header == "x-cos-security-token"
    assert TemporaryCredential("ak", "sk", provider="huawei").token_header == "x-obs-security-token"
