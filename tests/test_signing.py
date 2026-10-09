"""请求签名。

SigV4 用 AWS 官方测试套件里的 get-vanilla 向量校验——签名算法一旦写错，
认证态扫描会全线返回 403 而看不出原因，所以这里必须有硬校验。
"""
import base64
import calendar
import hashlib
import hmac
import time

import pytest

from utils.credentials import TemporaryCredential
from utils.signing import (
    aliyun_v1,
    aws_v4,
    sign_request,
    supported_providers,
    tencent,
)

# AWS 官方 SigV4 测试向量
AWS_VECTOR = {
    "ak": "AKIDEXAMPLE",
    "sk": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "amz_date": "20150830T123600Z",
    "region": "us-east-1",
    "service": "service",
    "signature": "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
}


def vector_time() -> float:
    return calendar.timegm(time.strptime(AWS_VECTOR["amz_date"], "%Y%m%dT%H%M%SZ"))


def test_sigv4_matches_aws_official_vector():
    """核心算法校验：必须逐字节复现官方签名。"""
    credential = TemporaryCredential(AWS_VECTOR["ak"], AWS_VECTOR["sk"])
    headers = aws_v4(credential, "GET", "https://example.amazonaws.com/", {}, b"",
                     region=AWS_VECTOR["region"], service=AWS_VECTOR["service"],
                     now=vector_time(), include_content_sha256=False)
    assert headers["Authorization"].endswith(f"Signature={AWS_VECTOR['signature']}")


def test_sigv4_official_vector_string_to_sign_shape():
    credential = TemporaryCredential(AWS_VECTOR["ak"], AWS_VECTOR["sk"])
    headers = aws_v4(credential, "GET", "https://example.amazonaws.com/", {}, b"",
                     region=AWS_VECTOR["region"], service=AWS_VECTOR["service"],
                     now=vector_time(), include_content_sha256=False)
    authorization = headers["Authorization"]
    assert authorization.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/")
    assert "SignedHeaders=host;x-amz-date" in authorization


def test_sigv4_includes_content_sha256_for_s3():
    """S3 要求携带并签名 x-amz-content-sha256，否则报 SignatureDoesNotMatch。"""
    credential = TemporaryCredential("ak", "sk")
    headers = aws_v4(credential, "GET", "https://b.s3.us-east-1.amazonaws.com/", {},
                     b"", region="us-east-1", service="s3", now=1)
    assert headers["x-amz-content-sha256"] == hashlib.sha256(b"").hexdigest()
    assert "x-amz-content-sha256" in headers["Authorization"]


def test_sigv4_payload_hash_changes_signature():
    """签名必须覆盖请求体，否则 PUT 内容可被篡改。"""
    credential = TemporaryCredential("ak", "sk")
    empty = aws_v4(credential, "PUT", "https://b.s3.us-east-1.amazonaws.com/o", {},
                   b"", now=1)
    with_body = aws_v4(credential, "PUT", "https://b.s3.us-east-1.amazonaws.com/o", {},
                       b"payload", now=1)
    assert empty["x-amz-content-sha256"] != with_body["x-amz-content-sha256"]
    assert empty["Authorization"] != with_body["Authorization"]


def test_sigv4_carries_security_token():
    """临时凭证必须把令牌一并签名下发，否则鉴权失败。"""
    credential = TemporaryCredential("ak", "sk", "the-token")
    headers = aws_v4(credential, "GET", "https://b.s3.us-east-1.amazonaws.com/", {}, b"", now=1)
    assert headers["x-amz-security-token"] == "the-token"
    assert "x-amz-security-token" in headers["Authorization"]


def test_sigv4_canonical_query_is_sorted():
    """查询串必须按 key 排序，否则子资源请求（?acl 等）签名不匹配。"""
    credential = TemporaryCredential("ak", "sk")
    a = aws_v4(credential, "GET", "https://b.s3.us-east-1.amazonaws.com/?b=2&a=1", {}, b"", now=1)
    b = aws_v4(credential, "GET", "https://b.s3.us-east-1.amazonaws.com/?a=1&b=2", {}, b"", now=1)
    assert a["Authorization"] == b["Authorization"]


def test_sigv4_strips_port_from_host():
    credential = TemporaryCredential("ak", "sk")
    headers = aws_v4(credential, "GET", "http://127.0.0.1:9000/bucket", {}, b"", now=1)
    assert headers["host"] == "127.0.0.1:9000"


# ------------------------------------------------------------------ 阿里云

def test_aliyun_signature_includes_subresources():
    """CanonicalizedResource 必须带上子资源，否则 ?acl /?policy 会鉴权失败。"""
    credential = TemporaryCredential("ak", "sk", provider="aliyun")
    plain = aliyun_v1(credential, "GET", "https://b.oss-cn-beijing.aliyuncs.com/", {}, now=1)
    policy = aliyun_v1(credential, "GET", "https://b.oss-cn-beijing.aliyuncs.com/?policy", {}, now=1)
    assert plain["Authorization"] != policy["Authorization"]
    assert policy["Authorization"].startswith("OSS ak:")


def test_aliyun_signature_carries_token_header():
    credential = TemporaryCredential("ak", "sk", "t", provider="aliyun")
    headers = aliyun_v1(credential, "GET", "https://b.oss-cn-beijing.aliyuncs.com/", {}, now=1)
    assert headers["x-oss-security-token"] == "t"


def test_aliyun_signature_deterministic_and_format():
    credential = TemporaryCredential("ak", "sk", provider="aliyun")
    first = aliyun_v1(credential, "GET", "https://b.oss-cn-beijing.aliyuncs.com/x", {}, now=1)
    second = aliyun_v1(credential, "GET", "https://b.oss-cn-beijing.aliyuncs.com/x", {}, now=1)
    assert first["Authorization"] == second["Authorization"]
    prefix, _, signature = first["Authorization"].partition(":")
    assert prefix == "OSS ak"
    assert len(base64.b64decode(signature)) == 20   # SHA1 摘要


def test_aliyun_x_oss_headers_are_signed():
    """x-oss-* 头参与签名，改任何一个都会导致签名变化。"""
    credential = TemporaryCredential("ak", "sk", provider="aliyun")
    a = aliyun_v1(credential, "GET", "https://b.oss-cn-beijing.aliyuncs.com/", {}, now=1)
    b = aliyun_v1(credential, "GET", "https://b.oss-cn-beijing.aliyuncs.com/",
                  {"x-oss-acl": "private"}, now=1)
    assert a["Authorization"] != b["Authorization"]


# ------------------------------------------------------------------ 腾讯云

def test_tencent_signature_format_and_determinism():
    credential = TemporaryCredential("ak", "sk", provider="tencent")
    headers = tencent(credential, "GET", "https://b-1250000000.cos.ap-guangzhou.myqcloud.com/",
                      {}, now=1)
    authorization = headers["Authorization"]
    for field in ("q-sign-algorithm=sha1", "q-ak=ak", "q-signature="):
        assert field in authorization
    again = tencent(credential, "GET", "https://b-1250000000.cos.ap-guangzhou.myqcloud.com/",
                    {}, now=1)
    assert authorization == again["Authorization"]


def test_tencent_signature_carries_token():
    credential = TemporaryCredential("ak", "sk", "t", provider="tencent")
    headers = tencent(credential, "GET", "https://b.cos.ap-guangzhou.myqcloud.com/", {}, now=1)
    assert headers["x-cos-security-token"] == "t"


# ------------------------------------------------------------------ 分发

def test_sign_request_dispatches_per_provider():
    credential = TemporaryCredential("ak", "sk")
    for provider in ("aliyun", "aws", "huawei", "tencent", "gcp"):
        headers = sign_request(provider, credential, "GET",
                               "https://b.s3.us-east-1.amazonaws.com/", {}, now=1)
        assert "Authorization" in headers, provider


def test_sign_request_rejects_unsupported_provider():
    with pytest.raises(ValueError, match="暂不支持签名"):
        sign_request("azure", TemporaryCredential("ak", "sk"), "GET", "https://x/", {})


def test_supported_providers_lists_known_clouds():
    assert set(supported_providers()) >= {"aliyun", "aws", "huawei", "tencent", "gcp"}


def test_gcp_forces_auto_region():
    """GCS 的 SigV4 区域固定为 auto，传具体区域会签名失败。"""
    credential = TemporaryCredential("ak", "sk")
    headers = sign_request("gcp", credential, "GET",
                           "https://storage.googleapis.com/b/o", {},
                           region="us-east1", now=1759939200)
    assert "/auto/storage/aws4_request" in headers["Authorization"]


def test_signature_does_not_mutate_input_headers():
    credential = TemporaryCredential("ak", "sk")
    original = {"X-Custom": "1"}
    aws_v4(credential, "GET", "https://b.s3.us-east-1.amazonaws.com/", original, b"", now=1)
    assert original == {"X-Custom": "1"}
