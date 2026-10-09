"""端点解析。

重点覆盖此前三套解析逻辑互相矛盾的场景：华为云是 ``obs.``（点）不是
``obs-``，AWS 既有 ``s3.{region}`` 也有 ``s3-{region}``。
"""
import pytest

from utils.endpoint_parser import detect_cloud, parse_endpoint


@pytest.mark.parametrize("value,expected", [
    ("https://mybucket.oss-cn-beijing.aliyuncs.com", ("aliyun", "mybucket", "cn-beijing")),
    ("http://mybucket.oss-ap-southeast-1.aliyuncs.com", ("aliyun", "mybucket", "ap-southeast-1")),
    ("mybucket.oss-cn-hangzhou.aliyuncs.com", ("aliyun", "mybucket", "cn-hangzhou")),
    # 内网与加速端点变体
    ("https://mybucket.oss-cn-beijing-internal.aliyuncs.com", ("aliyun", "mybucket", "cn-beijing")),
    ("https://mybucket.oss-accelerate.aliyuncs.com", ("aliyun", "mybucket", "accelerate")),
])
def test_aliyun(value, expected):
    endpoint = parse_endpoint(value, "aliyun")
    assert (endpoint.cloud, endpoint.bucket, endpoint.region) == expected


@pytest.mark.parametrize("value,expected", [
    ("https://bkt-1250000000.cos.ap-guangzhou.myqcloud.com", ("tencent", "bkt", "ap-guangzhou", "1250000000")),
    ("https://bkt.cos.ap-guangzhou.myqcloud.com", ("tencent", "bkt", "ap-guangzhou", "")),
    ("https://bkt.cos.ap-shanghai.tencentcos.cn", ("tencent", "bkt", "ap-shanghai", "")),
])
def test_tencent(value, expected):
    endpoint = parse_endpoint(value, "tencent")
    assert (endpoint.cloud, endpoint.bucket, endpoint.region, endpoint.appid) == expected


@pytest.mark.parametrize("value", [
    "https://bkt.obs.cn-north-4.myhuaweicloud.com",
    "bkt.obs.cn-north-4.myhuaweicloud.com",
])
def test_huawei_dot_form(value):
    """回归：旧实现要求 obs- 短横线形式，导致华为云端点必然解析失败。"""
    endpoint = parse_endpoint(value, "huawei")
    assert endpoint.cloud == "huawei"
    assert endpoint.bucket == "bkt"
    assert endpoint.region == "cn-north-4"


@pytest.mark.parametrize("value,expected_region", [
    ("https://bkt.s3.us-east-1.amazonaws.com", "us-east-1"),
    ("https://bkt.s3-us-east-1.amazonaws.com", "us-east-1"),
    ("https://bkt.s3.amazonaws.com", ""),
    ("https://bkt.s3.dualstack.eu-west-1.amazonaws.com", "eu-west-1"),
    ("https://bkt.s3-accelerate.amazonaws.com", ""),
])
def test_aws_variants(value, expected_region):
    """回归：旧实现只认 s3-{region}，而配置模板用的是 s3.{region}。"""
    endpoint = parse_endpoint(value, "aws")
    assert endpoint.cloud == "aws"
    assert endpoint.bucket == "bkt"
    assert endpoint.region == expected_region


def test_gcp():
    endpoint = parse_endpoint("https://bkt.storage.googleapis.com", "gcp")
    assert (endpoint.cloud, endpoint.bucket) == ("gcp", "bkt")


def test_azure_path_style():
    endpoint = parse_endpoint("https://acct.blob.core.windows.net/container", "azure")
    assert endpoint.cloud == "azure"
    assert endpoint.account == "acct"
    assert endpoint.bucket == "container"


@pytest.mark.parametrize("host,cloud", [
    ("bkt.oss-cn-beijing.aliyuncs.com", "aliyun"),
    ("bkt.cos.ap-guangzhou.myqcloud.com", "tencent"),
    ("bkt.obs.cn-north-4.myhuaweicloud.com", "huawei"),
    ("bkt.s3.us-east-1.amazonaws.com", "aws"),
    ("bkt.storage.googleapis.com", "gcp"),
    ("acct.blob.core.windows.net", "azure"),
])
def test_cloud_autodetect(host, cloud):
    assert detect_cloud(host) == cloud


def test_cloud_autodetect_when_not_specified():
    endpoint = parse_endpoint("https://bkt.obs.cn-north-4.myhuaweicloud.com")
    assert endpoint.cloud == "huawei"


def test_unknown_host_raises():
    with pytest.raises(ValueError, match="无法识别"):
        parse_endpoint("https://example.com/bucket")


def test_missing_bucket_raises():
    with pytest.raises(ValueError):
        parse_endpoint("https://aliyuncs.com", "aliyun")
