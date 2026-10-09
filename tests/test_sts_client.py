"""AssumeRole 换取临时凭证。

用本地假 STS 端点验证请求构造与响应解析；不访问任何真实云服务。
"""
import json

import pytest

from utils.credentials import TemporaryCredential
from utils.sts_client import (
    DEFAULT_DURATION,
    SUPPORTED_ASSUME_ROLE,
    _aliyun_rpc_signature,
    _parse_aws_xml,
    _percent_encode,
    _session_name,
    assume_role,
    load_base_credential,
)

BASE = TemporaryCredential(
    access_key_id="LTAI5tBaseAccessKeyId",
    access_key_secret="BaseSecretKeyMaterial",
    security_token="BaseSecurityToken",
    provider="aliyun",
)

AWS_BASE = TemporaryCredential(
    access_key_id="AKIABASEBASEBASE1234",
    access_key_secret="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    provider="aws",
)

AWS_XML = """<?xml version="1.0"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMPORARY1234567</AccessKeyId>
      <SecretAccessKey>TempSecretKeyMaterial000</SecretAccessKey>
      <SessionToken>TempSessionToken111</SessionToken>
      <Expiration>2026-10-09T20:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"""

ALIYUN_JSON = json.dumps({
    "RequestId": "req-1",
    "Credentials": {
        "AccessKeyId": "STS.TempAliyunKeyId",
        "AccessKeySecret": "TempAliyunSecret000",
        "SecurityToken": "TempAliyunToken111",
        "Expiration": "2026-10-09T20:00:00Z",
    },
})


class Args:
    def __init__(self, **kwargs):
        for key in ("role_arn", "role_ak", "role_sk", "role_session",
                    "role_duration", "sts_endpoint"):
            setattr(self, key, kwargs.get(key, ""))


@pytest.fixture(autouse=True)
def clear_role_env(monkeypatch):
    for name in ("OSS_SCANNER_ROLE_AK", "OSS_SCANNER_ROLE_SK", "OSS_SCANNER_ROLE_TOKEN",
                 "OSS_SCANNER_STS_AK", "OSS_SCANNER_STS_SK", "OSS_SCANNER_STS_TOKEN"):
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------ 编码与命名

def test_percent_encode_follows_aliyun_rules():
    """阿里云 RPC 签名要求在 URL 编码基础上替换 + * ~ 三个字符。"""
    assert _percent_encode("/") == "%2F"
    assert _percent_encode("a b") == "a%20b"
    assert _percent_encode("a*b") == "a%2Ab"
    assert _percent_encode("~") == "~"
    assert _percent_encode("a+b") == "a%2Bb"


def test_rpc_signature_deterministic_and_order_independent():
    params = {"Action": "AssumeRole", "Z": "1", "A": "2"}
    first = _aliyun_rpc_signature(params, "secret")
    second = _aliyun_rpc_signature({"A": "2", "Z": "1", "Action": "AssumeRole"}, "secret")
    assert first == second


def test_rpc_signature_changes_with_secret():
    params = {"Action": "AssumeRole"}
    assert _aliyun_rpc_signature(params, "s1") != _aliyun_rpc_signature(params, "s2")


def test_session_name_sanitised_and_bounded():
    name = _session_name("weird name/with:chars")
    assert "/" not in name and ":" not in name and " " not in name
    assert len(name) <= 64


# ------------------------------------------------------------------ XML 解析

def test_parse_aws_xml_extracts_credentials():
    parsed, error = _parse_aws_xml(AWS_XML)
    assert error is None
    assert parsed["AccessKeyId"] == "ASIATEMPORARY1234567"
    assert parsed["SessionToken"] == "TempSessionToken111"
    assert parsed["Expiration"] == "2026-10-09T20:00:00Z"


def test_parse_aws_xml_surfaces_error_message():
    parsed, error = _parse_aws_xml(
        "<ErrorResponse><Error><Message>not authorized to assume role</Message></Error></ErrorResponse>")
    assert parsed is None
    assert "not authorized to assume role" in error


def test_parse_aws_xml_rejects_incomplete_credentials():
    parsed, error = _parse_aws_xml("<Credentials><AccessKeyId>x</AccessKeyId></Credentials>")
    assert parsed is None and error


# ------------------------------------------------------------------ 阿里云流程

def test_aliyun_assume_role_success(fake_bucket):
    fake_bucket.route("POST", "/", status=200, body=ALIYUN_JSON,
                      content_type="application/json")
    credential, error = assume_role("aliyun", BASE, "acs:ram::123:role/scanner",
                                    endpoint=fake_bucket.base_url("/"),
                                    proxy=None, timeout=5)
    assert error is None
    assert credential.access_key_id == "STS.TempAliyunKeyId"
    assert credential.security_token == "TempAliyunToken111"
    assert credential.expires_at == "2026-10-09T20:00:00Z"
    assert "AssumeRole" in credential.source


def test_aliyun_request_is_signed_and_carries_base_token(fake_bucket):
    """请求必须带 Signature，且用临时凭证换时必须把当前令牌一起提交。"""
    fake_bucket.route("POST", "/", status=200, body=ALIYUN_JSON,
                      content_type="application/json")
    assume_role("aliyun", BASE, "acs:ram::123:role/scanner",
                endpoint=fake_bucket.base_url("/"), timeout=5)

    body = fake_bucket.payloads[-1]
    assert "Signature=" in body
    assert "Action=AssumeRole" in body
    assert "SecurityToken=BaseSecurityToken" in body
    assert "SignatureMethod=HMAC-SHA1" in body
    # 密钥绝不能出现在请求体里
    assert "BaseSecretKeyMaterial" not in body


def test_aliyun_error_response_is_reported(fake_bucket):
    fake_bucket.route("POST", "/", status=200,
                      body=json.dumps({"Code": "NoPermission", "Message": "not authorized"}),
                      content_type="application/json")
    credential, error = assume_role("aliyun", BASE, "acs:ram::123:role/x",
                                    endpoint=fake_bucket.base_url("/"), timeout=5)
    assert credential is None
    assert "NoPermission" in error


def test_aliyun_http_error_is_reported(fake_bucket):
    fake_bucket.route("POST", "/", status=403, body="forbidden")
    credential, error = assume_role("aliyun", BASE, "acs:ram::123:role/x",
                                    endpoint=fake_bucket.base_url("/"), timeout=5)
    assert credential is None
    assert "HTTP 403" in error


# ------------------------------------------------------------------ AWS 流程

def test_aws_assume_role_success(fake_bucket):
    fake_bucket.route("POST", "/", status=200, body=AWS_XML, content_type="text/xml")
    credential, error = assume_role("aws", AWS_BASE, "arn:aws:iam::123456789012:role/scanner",
                                    endpoint=fake_bucket.base_url("/"), timeout=5)
    assert error is None
    assert credential.access_key_id == "ASIATEMPORARY1234567"
    assert credential.access_key_secret == "TempSecretKeyMaterial000"
    assert credential.security_token == "TempSessionToken111"


def test_aws_request_is_sigv4_signed_with_sts_service(fake_bucket):
    fake_bucket.route("POST", "/", status=200, body=AWS_XML, content_type="text/xml")
    assume_role("aws", AWS_BASE, "arn:aws:iam::123456789012:role/scanner",
                endpoint=fake_bucket.base_url("/"), timeout=5)

    headers = fake_bucket.request_headers[-1]
    authorization = headers.get("authorization", "")
    assert authorization.startswith("AWS4-HMAC-SHA256")
    # service 必须是 sts，写成 s3 会被拒
    assert "/sts/aws4_request" in authorization
    assert "/us-east-1/" in authorization
    assert "BaseSecretKeyMaterial" not in json.dumps(fake_bucket.payloads)


def test_aws_error_xml_is_reported(fake_bucket):
    fake_bucket.route("POST", "/", status=200,
                      body="<ErrorResponse><Error><Message>Role not found</Message>"
                           "</Error></ErrorResponse>",
                      content_type="text/xml")
    credential, error = assume_role("aws", AWS_BASE, "arn:aws:iam::1:role/x",
                                    endpoint=fake_bucket.base_url("/"), timeout=5)
    assert credential is None
    assert "Role not found" in error


# ------------------------------------------------------------------ 参数校验与降级

@pytest.mark.parametrize("provider", ["tencent", "huawei", "gcp", "azure"])
def test_unsupported_provider_explains_workaround(provider):
    credential, error = assume_role(provider, BASE, "arn:x")
    assert credential is None
    assert "尚未实现签名方案" in error
    assert "--sts-file" in error


def test_missing_role_arn_is_rejected():
    credential, error = assume_role("aliyun", BASE, "")
    assert credential is None and "RoleArn" in error


def test_connect_failure_is_reported():
    credential, error = assume_role("aliyun", BASE, "acs:ram::1:role/x",
                                    endpoint="http://127.0.0.1:1/", timeout=2)
    assert credential is None
    assert "连接 STS 端点失败" in error


def test_supported_providers_listed():
    assert set(SUPPORTED_ASSUME_ROLE) == {"aws", "aliyun"}


# ------------------------------------------------------------------ 长期凭证来源

def test_base_credential_from_cli():
    credential, error = load_base_credential(Args(role_ak="ak", role_sk="sk"), {}, "aliyun")
    assert error is None
    assert credential.access_key_id == "ak"
    assert credential.source == "命令行角色凭证"


def test_base_credential_partial_cli_is_error():
    credential, error = load_base_credential(Args(role_ak="ak"), {}, "aliyun")
    assert credential is None
    assert error and "同时提供" in error


def test_base_credential_from_role_env(monkeypatch):
    monkeypatch.setenv("OSS_SCANNER_ROLE_AK", "role-ak")
    monkeypatch.setenv("OSS_SCANNER_ROLE_SK", "role-sk")
    credential, error = load_base_credential(Args(), {}, "aliyun")
    assert error is None
    assert credential.access_key_id == "role-ak"


def test_base_credential_falls_back_to_sts_env(monkeypatch):
    """用临时凭证再换一次临时凭证的场景。"""
    monkeypatch.setenv("OSS_SCANNER_STS_AK", "sts-ak")
    monkeypatch.setenv("OSS_SCANNER_STS_SK", "sts-sk")
    monkeypatch.setenv("OSS_SCANNER_STS_TOKEN", "sts-token")
    credential, error = load_base_credential(Args(), {}, "aliyun")
    assert error is None
    assert credential.security_token == "sts-token"


def test_base_credential_from_config_section():
    config = {"STS": {"role_ak": "cfg-ak", "role_sk": "cfg-sk"}}
    credential, error = load_base_credential(Args(), config, "aliyun")
    assert error is None
    assert credential.access_key_id == "cfg-ak"


def test_missing_base_credential_gives_actionable_error():
    credential, error = load_base_credential(Args(), {}, "aliyun")
    assert credential is None
    assert "--role-ak" in error


# ------------------------------------------------------------------ 命令行串联

def test_cli_assume_role_reaches_scanner(tmp_path, fake_bucket):
    """--role-arn 端到端：换取成功后的临时凭证要真正用于签名扫描。"""
    import os
    import tempfile
    import main as cli

    # 假 STS 端点
    fake_bucket.route("POST", "/", status=200, body=ALIYUN_JSON,
                      content_type="application/json")
    # 假存储桶
    fake_bucket.route("HEAD", "/b", status=403)
    fake_bucket.route("GET", "/b/", status=403)
    fake_bucket.route("GET", "/b/.env", status=200, body="A=1")

    cfg = os.path.join(tempfile.gettempdir(), "assume_role.ini")
    with open(cfg, "w", encoding="utf-8") as handle:
        handle.write(f"""[DEFAULT]
request_interval = 0
request_burst = 5
max_retry = 0
https_only = true

[CLOUD_TEMPLATES]
aliyun_https = {fake_bucket.base_url("/{bucket}")}

[SENSITIVE_PATHS]
key_paths = .env, id_rsa
db_paths = db.bak
config_paths = wp-config.php
log_paths = logs/app.log
src_paths = src.zip

[LOG_CONFIG]
log_file = {os.path.join(tempfile.gettempdir(), "assume_role.log")}
log_level = ERROR
""")
    out = os.path.join(tempfile.gettempdir(), "assume_role.json")
    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "b",
              "--config", cfg, "--output", "json", "--output-file", out,
              "--role-arn", "acs:ram::123:role/scanner",
              "--role-ak", "LTAI5tRoleBaseKeyId",
              "--role-sk", "RoleBaseSecretMaterial",
              "--sts-endpoint", fake_bucket.base_url("/")])

    payload = json.loads(open(out, encoding="utf-8").read())
    assert payload
    assert all(item["auth_mode"] == "authenticated" for item in payload)
    # 换来的临时令牌被用于存储桶请求
    assert any(h.get("x-oss-security-token") == "TempAliyunToken111"
               for h in fake_bucket.request_headers)
    # 长期密钥不出现在报告里
    blob = open(out, encoding="utf-8").read()
    assert "RoleBaseSecretMaterial" not in blob


def test_cli_assume_role_for_unsupported_cloud_falls_back_to_anonymous(tmp_path, fake_bucket):
    """腾讯云尚未支持自动 AssumeRole：应明确报错并以匿名继续。"""
    import os
    import tempfile
    import main as cli

    fake_bucket.route("HEAD", "/b", status=403)
    fake_bucket.route("GET", "/b/", status=403)
    fake_bucket.route("GET", "/b/.env", status=200, body="A=1")

    cfg = os.path.join(tempfile.gettempdir(), "assume_tencent.ini")
    with open(cfg, "w", encoding="utf-8") as handle:
        handle.write(f"""[DEFAULT]
request_interval = 0
request_burst = 5
max_retry = 0
https_only = true

[CLOUD_TEMPLATES]
tencent_https = {fake_bucket.base_url("/{bucket}")}

[SENSITIVE_PATHS]
key_paths = .env, id_rsa
db_paths = db.bak
config_paths = wp-config.php
log_paths = logs/app.log
src_paths = src.zip

[LOG_CONFIG]
log_file = {os.path.join(tempfile.gettempdir(), "assume_tencent.log")}
log_level = ERROR
""")
    out = os.path.join(tempfile.gettempdir(), "assume_tencent.json")
    cli.main(["--cloud", "tencent", "--region", "ap-beijing", "--bucket", "b",
              "--config", cfg, "--output", "json", "--output-file", out,
              "--role-arn", "qcs::cam::uin/1:roleName/x",
              "--role-ak", "AKIDbase", "--role-sk", "base-sk",
              "--sts-endpoint", fake_bucket.base_url("/")])

    payload = json.loads(open(out, encoding="utf-8").read())
    assert payload
    assert all(item["auth_mode"] == "anonymous" for item in payload)
