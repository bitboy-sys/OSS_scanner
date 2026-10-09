"""扫描器基类的核心行为与回归用例。"""
import json

import pytest

from core.risk_analyzer import Risk
from core.scanner_base import ProviderSpec, ScannerBase, _policy_allows_anonymous
from providers.aliyun_scanner import AliyunScanner


def make_scanner(config, bucket="bucket", region="cn-beijing"):
    return AliyunScanner(bucket, region, config)


# ------------------------------------------------------------------ 敏感路径分级

def test_sensitive_paths_ignore_surrounding_spaces(base_config):
    """回归：配置用 ", " 分隔时，旧实现只 strip 了路径却拿未 strip 的配置项
    做比较，导致每类除首条外全部降级为最低等级。"""
    base_config["SENSITIVE_PATHS"] = {
        "key_paths": ".env, credentials.json, id_rsa, private_key.pem",
        "db_paths": "db.bak, backup/database.sql",
        "config_paths": "wp-config.php, conf/app.conf",
        "log_paths": "logs/app.log",
        "src_paths": "src.zip",
    }
    mapping = dict(make_scanner(base_config).sensitive_paths)

    # 每类中除首条以外的条目此前都会落到 OTHER_FILE_EXPOSED
    assert mapping["credentials.json"] is Risk.KEY_FILE_EXPOSED
    assert mapping["id_rsa"] is Risk.KEY_FILE_EXPOSED
    assert mapping["private_key.pem"] is Risk.KEY_FILE_EXPOSED
    assert mapping["backup/database.sql"] is Risk.DB_BACKUP_EXPOSED
    assert mapping["conf/app.conf"] is Risk.CONFIG_FILE_EXPOSED
    assert mapping["logs/app.log"] is Risk.OTHER_FILE_EXPOSED


def test_sensitive_paths_deduplicated(base_config):
    base_config["SENSITIVE_PATHS"] = {"key_paths": ".env, .env", "db_paths": "", "config_paths": "",
                                     "log_paths": "", "src_paths": ""}
    paths = [path for path, _ in make_scanner(base_config).sensitive_paths]
    assert paths == [".env"]


# ------------------------------------------------------------------ URL 构造

def test_https_template_expands_to_https_first(base_config):
    base_config["https_only"] = False
    base_config["CLOUD_TEMPLATES"] = {"aliyun_https": "https://b.oss-cn-beijing.aliyuncs.com"}
    urls = make_scanner(base_config).base_urls
    assert urls == ["https://b.oss-cn-beijing.aliyuncs.com", "http://b.oss-cn-beijing.aliyuncs.com"]


def test_https_only_suppresses_http_variant(base_config):
    base_config["https_only"] = True
    base_config["CLOUD_TEMPLATES"] = {"aliyun_https": "https://b.oss-cn-beijing.aliyuncs.com"}
    assert make_scanner(base_config).base_urls == ["https://b.oss-cn-beijing.aliyuncs.com"]


def test_missing_template_yields_no_urls(base_config):
    base_config["CLOUD_TEMPLATES"] = {}
    assert make_scanner(base_config).base_urls == []


# ------------------------------------------------------------------ 存在性探测

def test_bucket_exist_continues_after_404(base_config, fake_bucket):
    """回归：旧实现遇到首个 404 直接 return False，HTTPS 正常时会被误判不存在。"""
    fake_bucket.route("HEAD", "/a", status=404)
    fake_bucket.route("HEAD", "/b", status=403)

    scanner = make_scanner(base_config)
    scanner.base_urls = [fake_bucket.base_url("/a"), fake_bucket.base_url("/b")]

    assert scanner.check_bucket_exist() is True
    assert scanner._active_base_url == fake_bucket.base_url("/b")


def test_bucket_exist_false_when_all_missing(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/a", status=404)
    fake_bucket.route("HEAD", "/b", status=404)

    scanner = make_scanner(base_config)
    scanner.base_urls = [fake_bucket.base_url("/a"), fake_bucket.base_url("/b")]
    assert scanner.check_bucket_exist() is False


def test_target_urls_collapses_to_active(base_config, fake_bucket):
    """确认可用地址后只探测它，避免每个路径都重复请求 HTTP 与 HTTPS。"""
    fake_bucket.route("HEAD", "/a", status=403)
    scanner = make_scanner(base_config)
    scanner.base_urls = [fake_bucket.base_url("/a"), fake_bucket.base_url("/b")]

    assert len(scanner.target_urls()) == 2
    scanner.check_bucket_exist()
    assert scanner._active_base_url == fake_bucket.base_url("/a")
    assert scanner.target_urls() == [scanner._active_base_url]


# ------------------------------------------------------------------ 写操作闸门

def test_write_gate_blocks_all_writes_by_default(base_config, fake_bucket):
    """默认 allow_intrusive_write=false 时，不得对目标发起任何写操作。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)

    scanner = make_scanner(base_config)
    results = scanner.run_scan()

    assert scanner.intrusive_enabled is False
    used = set(fake_bucket.methods_used())
    assert not ({"PUT", "POST", "DELETE"} & used), f"默认配置下不应发生写操作: {used}"
    assert all(r["risk_id"] not in (Risk.ANON_WRITE_PUT.value, Risk.ANON_WRITE_POST.value,
                                    Risk.ANON_DELETE.value, Risk.ACL_WRITABLE.value,
                                    Risk.ACL_READABLE.value) for r in results)


def test_write_gate_allows_put_when_enabled(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("PUT", "*", status=201)
    fake_bucket.route("DELETE", "*", status=204)

    base_config["allow_intrusive_write"] = True
    scanner = make_scanner(base_config)
    results = scanner.run_scan()

    assert "PUT" in fake_bucket.methods_used()
    risk_ids = {r["risk_id"] for r in results}
    assert Risk.ANON_WRITE_PUT.value in risk_ids
    # 测试对象应被清理
    assert "DELETE" in fake_bucket.methods_used()


def test_acl_checks_skipped_when_gate_closed(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    base_config["scan_acl_write"] = True

    scanner = make_scanner(base_config)
    scanner.run_scan()
    assert scanner.scan_object_acl_writable() is None
    assert "PUT" not in fake_bucket.methods_used()


def test_acl_read_check_when_enabled(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("PUT", "*", status=200)
    fake_bucket.route("GET", "*", status=200, body="secret")

    base_config["allow_intrusive_write"] = True
    scanner = make_scanner(base_config)
    scanner.scan_object_acl_readable()
    assert any(r["risk_id"] == Risk.ACL_READABLE.value for r in scanner.results)


# ------------------------------------------------------------------ 结果字段

def test_finding_carries_full_evidence(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/.env", status=200, body="AWS_SECRET_ACCESS_KEY=AKIAEXAMPLE")

    scanner = make_scanner(base_config)
    results = scanner.run_scan()

    finding = next(r for r in results if r["risk_id"] == Risk.KEY_FILE_EXPOSED.value)
    assert finding["severity"] == "CRITICAL"
    assert finding["title"] == "密钥文件可被访问"
    assert finding["status_code"] == 200
    assert "AWS_SECRET_ACCESS_KEY" in finding["evidence"]
    assert finding["bucket"] == "bucket"
    assert finding["cloud"] == "aliyun"
    assert finding["region"] == "cn-beijing"
    assert finding["timestamp"]

    # 结果必须可 JSON 序列化（回归：此前会抛 TypeError）
    json.dumps(results, ensure_ascii=False)


def test_probe_does_not_report_head_get_mismatch(base_config, fake_bucket):
    """回归：曾经先 HEAD 再 GET，若 HEAD 返回 200 而 GET 返回 404，会得出
    「发现可匿名访问文件」却附带 404 状态码这种自相矛盾的结论。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("HEAD", "/bucket/.env", status=200)
    fake_bucket.route("GET", "/bucket/.env", status=404)

    results = make_scanner(base_config).run_scan()
    assert not any(r["risk_id"] == Risk.KEY_FILE_EXPOSED.value for r in results)


def test_exposed_file_findings_never_show_failure_status(base_config, fake_bucket):
    """凡声明「发现可访问文件」的条目，其状态码必须真的是成功码。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/.env", status=200, body="X=1")
    fake_bucket.route("HEAD", "/bucket/id_rsa", status=200)
    fake_bucket.route("GET", "/bucket/id_rsa", status=404)

    results = make_scanner(base_config).run_scan()
    exposed = [r for r in results
               if r["risk_id"] in (Risk.KEY_FILE_EXPOSED.value, Risk.DB_BACKUP_EXPOSED.value,
                                  Risk.CONFIG_FILE_EXPOSED.value, Risk.OTHER_FILE_EXPOSED.value)]
    assert exposed
    assert all(r["status_code"] == 200 for r in exposed)
    assert all(r["status_code"] in (200, 201, 204, 302) for r in exposed)


def test_finding_has_no_python_object_values(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    scanner = make_scanner(base_config)
    for result in scanner.run_scan():
        for value in result.values():
            assert isinstance(value, (str, int, float, bool, type(None))), value


# ------------------------------------------------------------------ 策略与加密

def test_policy_anonymous_write_detected(base_config, fake_bucket):
    policy = json.dumps({
        "Version": "1",
        "Statement": [{"Effect": "Allow", "Principal": "*",
                       "Action": ["oss:PutObject", "oss:GetObject"], "Resource": ["*"]}],
    })
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/?policy", status=200, body=policy)

    scanner = make_scanner(base_config)
    results = scanner.run_scan()
    assert any(r["risk_id"] == Risk.POLICY_ANON_WRITE.value for r in results)


def test_policy_read_only_is_medium(base_config, fake_bucket):
    policy = json.dumps({
        "Version": "1",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["oss:GetObject"]}],
    })
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/?policy", status=200, body=policy)

    scanner = make_scanner(base_config)
    results = scanner.run_scan()
    finding = next(r for r in results if r["risk_id"] == Risk.POLICY_ANON_READ.value)
    assert finding["severity"] == "MEDIUM"


def test_policy_escaped_inline_form_detected():
    """策略有时以内嵌转义形式出现在 HTML 中，需回退到字符串匹配。"""
    escaped = '{"Statement": [{"Effect\\": \\"Allow", "Principal\\": \\"*"}]}'
    assert _policy_allows_anonymous(escaped) is True


def test_policy_deny_is_not_anonymous_allow():
    assert _policy_allows_anonymous(json.dumps({
        "Statement": [{"Effect": "Deny", "Principal": "*", "Action": ["oss:*"]}]})) is False


def test_encryption_aes256_detected(base_config, fake_bucket):
    body = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>" \
           "<SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>" \
           "</ServerSideEncryptionConfiguration>"
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/?encryption", status=200, body=body)

    scanner = make_scanner(base_config)
    results = scanner.run_scan()
    finding = next(r for r in results if r["risk_id"] == Risk.ENCRYPTION_AES_NOT_KMS.value)
    assert finding["severity"] == "MEDIUM"


def test_missing_encryption_reported_as_high(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/?encryption", status=200, body="<EncryptionConfiguration/>")

    scanner = make_scanner(base_config)
    results = scanner.run_scan()
    finding = next(r for r in results if r["risk_id"] == Risk.NO_SSE.value)
    assert finding["severity"] == "HIGH"


# ------------------------------------------------------------------ 其他

def test_missing_bucket_reported_as_info(base_config, fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=404)
    scanner = make_scanner(base_config)
    results = scanner.run_scan()
    assert len(results) == 1
    assert results[0]["risk_id"] == Risk.BUCKET_NOT_FOUND.value
    assert results[0]["severity"] == "INFO"


def test_public_list_detected(base_config, fake_bucket):
    listing = "<ListBucketResult><Name>bucket</Name></ListBucketResult>"
    fake_bucket.route("HEAD", "/bucket", status=200)
    fake_bucket.route("GET", "/bucket/", status=200, body=listing)

    scanner = make_scanner(base_config)
    results = scanner.run_scan()
    assert any(r["risk_id"] == Risk.PUBLIC_LIST.value for r in results)


def test_provider_spec_requires_supported_cloud():
    assert isinstance(AliyunScanner.spec, ProviderSpec)
    assert AliyunScanner.spec.action_prefix == "oss:"


def test_subclass_must_provide_templates(base_config):
    """未实现 _templates 的子类应在构造时就报错，而不是静默扫不到东西。"""
    class NoTemplate(ScannerBase):
        spec = ProviderSpec(name="x", display_name="X", action_prefix="x:", list_element="Y")

    with pytest.raises(NotImplementedError):
        NoTemplate("b", "r", base_config)
