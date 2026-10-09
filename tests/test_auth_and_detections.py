"""认证态扫描（临时 STS 凭证）与扩展检测。"""
import json

import pytest

from core.risk_analyzer import Risk
from core.scanner_base import ProviderSpec, ScannerBase
from providers.aliyun_scanner import AliyunScanner
from providers.aws_scanner import AwsScanner
from utils.credentials import TemporaryCredential

CREDENTIAL = TemporaryCredential(
    access_key_id="LTAI5tFakeAccessKeyId",
    access_key_secret="FakeSecretKeyMaterial000",
    security_token="FakeSecurityTokenValue111",
    provider="aliyun",
)


def make_scanner(config, credential=None, bucket="bucket", region="cn-beijing"):
    return AliyunScanner(bucket, region, config, credential=credential)


def prepare(config, fake_bucket, extra_routes=()):
    """注册基础路由：根路径存在判定 + 一个必命中项，保证结果非空。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/.env", status=200, body="A=1")
    for method, path, kwargs in extra_routes:
        fake_bucket.route(method, path, **kwargs)
    return make_scanner(config)


# ------------------------------------------------------------------ 认证态

def test_default_scan_is_anonymous(base_config, fake_bucket):
    prepare(base_config, fake_bucket)
    scanner = make_scanner(base_config)
    assert scanner.auth_mode == "anonymous"
    results = scanner.run_scan()
    assert results
    assert all(r["auth_mode"] == "anonymous" for r in results)


def test_credential_switches_to_authenticated_mode(base_config, fake_bucket):
    prepare(base_config, fake_bucket)
    scanner = make_scanner(base_config, CREDENTIAL)
    assert scanner.auth_mode == "authenticated"
    results = scanner.run_scan()
    assert results
    assert all(r["auth_mode"] == "authenticated" for r in results)


def test_authenticated_requests_are_signed_with_token(base_config, fake_bucket):
    """认证态下每个请求都必须带签名头与安全令牌头。"""
    prepare(base_config, fake_bucket)
    make_scanner(base_config, CREDENTIAL).run_scan()

    assert fake_bucket.request_headers
    for headers in fake_bucket.request_headers:
        assert headers.get("authorization", "").startswith("OSS "), headers
        assert headers.get("x-oss-security-token") == CREDENTIAL.security_token
        assert headers.get("date")


def test_anonymous_requests_carry_no_auth_header(base_config, fake_bucket):
    prepare(base_config, fake_bucket)
    make_scanner(base_config).run_scan()
    for headers in fake_bucket.request_headers:
        assert "authorization" not in headers
        assert "x-oss-security-token" not in headers


def test_signing_failure_degrades_to_anonymous_instead_of_crashing(base_config, fake_bucket):
    """不支持的厂商签名时应降级并继续，而不是中断整次扫描。"""
    class NoSignature(ScannerBase):
        spec = ProviderSpec(name="azure", display_name="Azure", action_prefix="",
                            list_element="EnumerationResults")
        def _templates(self):
            return [fake_bucket.base_url("/{bucket}")]

    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    credential = TemporaryCredential("ak", "sk", "t", provider="azure")
    scanner = NoSignature("bucket", "", base_config, credential=credential)
    results = scanner.run_scan()   # azure 不支持签名 → 降级为匿名
    assert results
    for headers in fake_bucket.request_headers:
        assert "authorization" not in headers


def test_credential_object_never_leaks_into_results(base_config, fake_bucket):
    """回归防线：结果与证据里绝不能出现密钥或令牌。"""
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/.env", {"status": 200, "body": "A=1"}),
    ])
    results = make_scanner(base_config, CREDENTIAL).run_scan()
    blob = json.dumps(results, ensure_ascii=False)
    assert CREDENTIAL.access_key_secret not in blob
    assert CREDENTIAL.security_token not in blob


# ------------------------------------------------------------------ ACL 授权项

def test_acl_public_grant_detected(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?acl", {"status": 200, "body":
            "<AccessControlPolicy><AccessControlList><Grant><Grantee>"
            "<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>"
            "</Grantee><Permission>READ</Permission></Grant></AccessControlList>"
            "</AccessControlPolicy>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert any(r["risk_id"] == Risk.ACL_PUBLIC_GRANT.value for r in results)


def test_acl_authenticated_grant_detected(base_config, fake_bucket):
    """AWS/华为的 AuthenticatedUsers 授权意味着任意该云账号都能访问。"""
    base_config["https_only"] = True
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/?acl", status=200, body=
        "<AccessControlPolicy><AccessControlList><Grant><Grantee>"
        "<URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI>"
        "</Grantee><Permission>READ</Permission></Grant></AccessControlList>"
        "</AccessControlPolicy>")
    scanner = AwsScanner("bucket", "us-east-1", base_config)
    scanner.base_urls = [fake_bucket.base_url("/bucket")]
    results = scanner.run_scan()
    assert any(r["risk_id"] == Risk.ACL_AUTHENTICATED_GRANT.value for r in results)


def test_aliyun_public_read_acl_detected(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?acl", {"status": 200, "body":
            "<AccessControlPolicy><AccessControlList><Grant>public-read</Grant>"
            "</AccessControlList></AccessControlPolicy>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert any(r["risk_id"] == Risk.ACL_PUBLIC_GRANT.value for r in results)


def test_private_acl_is_not_reported(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?acl", {"status": 200, "body":
            "<AccessControlPolicy><AccessControlList><Grant>private</Grant>"
            "</AccessControlList></AccessControlPolicy>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert not any(r["risk_id"] in (Risk.ACL_PUBLIC_GRANT.value,
                                    Risk.ACL_AUTHENTICATED_GRANT.value) for r in results)


# ------------------------------------------------------------------ 版本控制

def test_deleted_object_recovery_detected(base_config, fake_bucket):
    """删除文件不等于数据消失：历史版本仍可取回。"""
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?versioning", {"status": 200, "body":
            "<VersioningConfiguration><Status>Enabled</Status>"
            "<MfaDelete>Disabled</MfaDelete></VersioningConfiguration>"}),
        ("GET", "/bucket/.env?versions", {"status": 200, "body":
            "<ListVersionsResult>"
            "<Version><Key>.env</Key><VersionId>v-current</VersionId>"
            "<IsLatest>true</IsLatest></Version>"
            "<Version><Key>.env</Key><VersionId>v-old-1</VersionId>"
            "<IsLatest>false</IsLatest></Version>"
            "<DeleteMarker><Key>.env</Key><VersionId>v-deleted</VersionId></DeleteMarker>"
            "</ListVersionsResult>"}),
    ])
    results = make_scanner(base_config).run_scan()
    recoverable = next(r for r in results if r["risk_id"] == Risk.DELETED_OBJECT_RECOVERABLE.value)
    assert recoverable["severity"] == "HIGH"
    assert "v-old-1" in recoverable["msg"]


def test_versioning_without_mfa_delete_reported(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?versioning", {"status": 200, "body":
            "<VersioningConfiguration><Status>Enabled</Status>"
            "<MfaDelete>Disabled</MfaDelete></VersioningConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert any(r["risk_id"] == Risk.VERSIONING_WITHOUT_MFA_DELETE.value for r in results)


def test_versioning_disabled_reports_nothing(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?versioning", {"status": 200, "body":
            "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert not any(r["risk_id"] in (Risk.DELETED_OBJECT_RECOVERABLE.value,
                                    Risk.VERSIONING_WITHOUT_MFA_DELETE.value) for r in results)


def test_version_history_check_respects_flag(base_config, fake_bucket):
    base_config["scan_version_leak"] = False
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?versioning", {"status": 200, "body":
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert not any(r["risk_id"] == Risk.DELETED_OBJECT_RECOVERABLE.value for r in results)


# ------------------------------------------------------------------ 其余扩展检查

def test_static_website_detected(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?website", {"status": 200, "body":
            "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix>"
            "</IndexDocument></WebsiteConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert any(r["risk_id"] == Risk.STATIC_WEBSITE_ENABLED.value for r in results)


def test_referer_unrestricted_detected(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?referer", {"status": 200, "body":
            "<RefererConfiguration><RefererList></RefererList>"
            "<AllowEmptyReferer>true</AllowEmptyReferer></RefererConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert any(r["risk_id"] == Risk.REFERER_UNRESTRICTED.value for r in results)


def test_referer_whitelist_is_not_reported(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?referer", {"status": 200, "body":
            "<RefererConfiguration><RefererList><Referer>https://a.example</Referer>"
            "</RefererList></RefererConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert not any(r["risk_id"] == Risk.REFERER_UNRESTRICTED.value for r in results)


def test_cross_account_replication_detected(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?replication", {"status": 200, "body":
            "<ReplicationConfiguration><Rule><Destination>"
            "<Bucket>arn:aws:s3:::other-account-bucket</Bucket>"
            "</Destination></Rule></ReplicationConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert any(r["risk_id"] == Risk.CROSS_ACCOUNT_REPLICATION.value for r in results)


def test_cors_config_read_reports_wildcard(base_config, fake_bucket):
    prepare(base_config, fake_bucket, [
        ("GET", "/bucket/?cors", {"status": 200, "body":
            "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin>"
            "<AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>"}),
    ])
    results = make_scanner(base_config).run_scan()
    assert any(r["risk_id"] == Risk.CORS_WILDCARD.value for r in results)


def test_cors_not_reported_twice(base_config, fake_bucket):
    """OPTIONS 行为探测与 ?cors 读取不应产生重复条目。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("OPTIONS", "/bucket", status=204, content_type="",
                      **{"Access-Control-Allow-Origin": "*",
                         "Access-Control-Allow-Methods": "GET,PUT"})
    fake_bucket.route("GET", "/bucket/?cors", status=200, body=
        "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin>"
        "<AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>")

    results = make_scanner(base_config).run_scan()
    cors = [r for r in results if r["risk_id"] == Risk.CORS_WILDCARD.value]
    assert len(cors) == 1


# ------------------------------------------------------------------ 区域自动发现

def test_region_discovered_from_header_retargets_scan(base_config, fake_bucket):
    """传错区域时应从响应头校正，而不是一路静默扫错地址。"""
    fake_bucket.route("HEAD", "/bucket", status=403,
                      **{"x-amz-bucket-region": "eu-west-1"})
    fake_bucket.route("GET", "/bucket/", status=403)

    scanner = AwsScanner("bucket", "us-east-1", base_config)
    scanner.base_urls = [fake_bucket.base_url("/bucket")]
    results = scanner.run_scan()
    assert any(r["risk_id"] == Risk.REGION_DISCOVERED.value for r in results)
    assert scanner.region == "eu-west-1"


def test_region_not_reported_when_correct(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403,
                      **{"x-amz-bucket-region": "us-east-1"})
    fake_bucket.route("GET", "/bucket/", status=403)
    scanner = AwsScanner("bucket", "us-east-1", base_config)
    scanner.base_urls = [fake_bucket.base_url("/bucket")]
    results = scanner.run_scan()
    assert not any(r["risk_id"] == Risk.REGION_DISCOVERED.value for r in results)
    assert scanner.region == "us-east-1"


def test_aliyun_has_no_region_header_discovery(base_config, fake_bucket):
    """阿里云不在响应头里回区域，不应凭空触发校正。"""
    assert AliyunScanner.spec.region_header == ""
