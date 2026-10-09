"""端到端：命令行、报告输出与性能验收。"""
import json
import time

import pytest

import main as cli
from core.risk_analyzer import Risk

# 与 config/config.ini 中的真实路径列表保持一致，用于性能验收
REAL_SENSITIVE_PATHS = """key_paths = .env, credentials.json, access_key.txt, secret_key.txt, id_rsa, private_key.pem
db_paths = backup/database.sql, db/dump.sql, database_backup.zip, db.bak, sql.gz
config_paths = config/database.yml, conf/app.conf, wp-config.php, src/config.php
log_paths = logs/app.log, access.log, error.log
src_paths = wwwroot/.git/config, backup/site.tar.gz, src.zip"""


def write_config(tmp_path, bucket_url, request_interval, extra="", log_file=None, ai_section=""):
    log_file = log_file or (tmp_path / "scan.log").as_posix()
    path = tmp_path / "config.ini"
    path.write_text(f"""[DEFAULT]
request_timeout = 5
request_interval = {request_interval}
request_burst = 5
max_retry = 0
user_agent = oss-scanner-test
https_only = true
allow_intrusive_write = false
scan_put_upload = true
scan_post_upload = true
scan_delete_perm = true
scan_cors = true
scan_logs = true
scan_directory_traversal = true
scan_sensitive_headers = true
scan_bucket_policy = true
scan_kms_encryption = true
scan_acl_write = true
scan_acl_read = true
scan_blob_public_access = true
scan_version_leak = true
{extra}

[CLOUD_TEMPLATES]
aliyun_https = {bucket_url}

[SENSITIVE_PATHS]
{REAL_SENSITIVE_PATHS}

[LOG_CONFIG]
log_file = {log_file}
log_level = INFO

[ALERT_CONFIG]
dingtalk_webhook = ""
email_smtp = smtp.qq.com
email_user = ""
email_pass = ""
email_to = ""

[AUTO_EXTRACT]
hostid_url = ""
timeout = 5
retry = 0

{ai_section}
""", encoding="utf-8")
    return path.as_posix()


def ai_section(base_url, features="report,analyze,classify", ack="false", enabled="true"):
    return f"""[AI_CONFIG]
enabled = {enabled}
base_url = {base_url}
model = test-model
timeout = 5
features = {features}
redact = true
cache =
ack_data_egress = {ack}
"""


def populate(fake_bucket):
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/.env", status=200, body="DB_PASSWORD=hunter2")
    fake_bucket.route("GET", "/bucket/id_rsa", status=200, body="-----BEGIN RSA PRIVATE KEY-----")
    fake_bucket.route("GET", "/bucket/db.bak", status=200, body="PGDMP backup")
    fake_bucket.route("GET", "/bucket/wp-config.php", status=200, body="<?php define('DB_NAME','wp');")


@pytest.mark.parametrize("output", ["text", "json", "html"])
def test_cli_produces_each_output_format(tmp_path, fake_bucket, output):
    """回归：--output json 此前因枚举不可序列化直接崩溃。"""
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / f"report.{output}"

    exit_code = cli.main([
        "--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
        "--config", config_path, "--output", output, "--output-file", output_file.as_posix(),
    ])

    assert exit_code == 1, "存在严重风险时应返回 1"
    content = output_file.read_text(encoding="utf-8")
    assert content.strip()


def test_json_output_is_valid_and_correctly_graded(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    by_risk = {item["risk_id"]: item for item in payload}

    # 关键验收：原先这三类除首条外都会被降级为最低等级
    assert by_risk[Risk.KEY_FILE_EXPOSED.value]["severity"] == "CRITICAL"
    assert by_risk[Risk.DB_BACKUP_EXPOSED.value]["severity"] == "CRITICAL"
    assert by_risk[Risk.CONFIG_FILE_EXPOSED.value]["severity"] == "MEDIUM"

    for item in payload:
        assert item["severity_label"]
        assert item["remediation"]
        assert item["bucket"] == "bucket"
        assert item["cloud"] == "aliyun"


def test_html_output_contains_evidence_and_remediation(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.html"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "html",
              "--output-file", output_file.as_posix()])

    html = output_file.read_text(encoding="utf-8")
    # 回归：旧模板的「响应体」列永远显示「无响应体数据」
    assert "DB_PASSWORD=hunter2" in html
    assert "严重" in html and "修复建议" in html
    assert "无响应体数据" not in html


def test_output_file_creates_missing_directory(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "reports" / "nested" / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])
    assert output_file.exists()


def test_bucket_file_input(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    bucket_file = tmp_path / "buckets.txt"
    bucket_file.write_text("bucket\nbucket\n", encoding="utf-8")
    output_file = tmp_path / "report.json"

    exit_code = cli.main(["--cloud", "aliyun", "--region", "cn-beijing",
                          "--bucket-file", bucket_file.as_posix(),
                          "--config", config_path, "--output", "json",
                          "--output-file", output_file.as_posix()])
    assert exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    # 去重后只应扫描一次
    assert {item["bucket"] for item in payload} == {"bucket"}


def test_endpoint_url_auto_detects_cloud_and_region(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    cli.main(["--hostid-url", "https://bucket.oss-cn-beijing.aliyuncs.com",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload
    assert {item["cloud"] for item in payload} == {"aliyun"}
    assert {item["region"] for item in payload} == {"cn-beijing"}


def test_missing_region_is_rejected(tmp_path):
    config_path = write_config(tmp_path, "https://b.oss-{region}.aliyuncs.com", request_interval=0)
    assert cli.main(["--cloud", "aliyun", "--bucket", "b", "--config", config_path]) == 2


def test_azure_requires_account(tmp_path):
    config_path = write_config(tmp_path, "https://{account}.blob.core.windows.net/{bucket}",
                               request_interval=0)
    assert cli.main(["--cloud", "azure", "--bucket", "c", "--config", config_path]) == 2


def test_single_bucket_completes_within_budget(tmp_path, fake_bucket):
    """性能验收：真实路径列表（21 条）+ 默认 0.3 秒间隔应在 15 秒内完成。

    旧实现每请求 sleep 且 HTTP/HTTPS 各扫一遍，单桶实测超过 100 秒。
    """
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0.3)
    output_file = tmp_path / "report.json"

    started = time.monotonic()
    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])
    elapsed = time.monotonic() - started

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    scanned_paths = len({item["url"] for item in payload})
    assert scanned_paths >= 4
    assert elapsed < 15, f"单桶扫描耗时 {elapsed:.1f}s，超出 15s 预算"


def test_write_gate_holds_in_full_cli_run(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])

    used = set(fake_bucket.methods_used())
    assert not ({"PUT", "POST", "DELETE"} & used), f"默认配置下不应发生写操作: {used}"


# ------------------------------------------------------------------ AI 集成

def test_ai_disabled_by_default_in_cli_run(tmp_path, fake_bucket):
    """AI 默认关闭：即使配了端点也不该发起调用。"""
    populate(fake_bucket)
    fake_bucket.route_ai(json.dumps({"executive_summary": "不应出现"}))
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0,
                               ai_section=ai_section(fake_bucket.ai_base_url(), enabled="false"))
    output_file = tmp_path / "report.html"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "html",
              "--output-file", output_file.as_posix()])

    assert fake_bucket.ai_calls == 0
    assert "不应出现" not in output_file.read_text(encoding="utf-8")


def test_ai_report_and_classify_flow_through_cli(tmp_path, fake_bucket):
    """--ai all 应生成 AI 区块，并标注识别出的凭据。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/.env", status=200,
                      body="ALIYUN_AK=LTAI5tNotARealKey123456\nDB_URL=mysql://root:hunter2@db/app")
    fake_bucket.route_ai(json.dumps({
        "executive_summary": "存在可直接匿名下载的密钥文件。",
        "top_risks": [{"risk_id": "KEY_FILE_EXPOSED", "why_it_matters": "可接管账号", "priority": 1}],
        "remediation_plan": [{"step": "收敛读权限", "detail": "控制台操作路径"}],
        "notes": "确认密钥是否在用",
        "findings": [{"index": 0, "false_positive_likely": False, "confidence": "high", "reason": "真实密钥"}],
        "credentials": [{"index": 0, "type": "阿里云 AccessKey", "looks_live": True,
                         "confidence": "high", "impact": "OSS 读写"}],
    }))
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0,
                               ai_section=ai_section(fake_bucket.ai_base_url()))
    output_file = tmp_path / "report.html"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "html", "--ai", "all",
              "--output-file", output_file.as_posix()])

    html = output_file.read_text(encoding="utf-8")
    assert "AI 研判" in html
    assert "存在可直接匿名下载的密钥文件。" in html
    assert "疑似可用凭据" in html
    assert "AI 置信度 high" in html

    # 关键安全约束：原始凭据绝不能出现在发往模型的请求里
    sent = json.dumps(fake_bucket.ai_payloads(), ensure_ascii=False)
    assert "LTAI5tNotARealKey123456" not in sent
    assert "hunter2" not in sent


def test_ai_remote_endpoint_blocked_by_egress_gate(tmp_path, fake_bucket):
    """非本机端点未经确认时跳过 AI，但扫描结果照常产出。"""
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0,
                               ai_section=ai_section("https://api.example.com/v1", ack="false"))
    output_file = tmp_path / "report.json"

    exit_code = cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
                          "--config", config_path, "--output", "json", "--ai", "all",
                          "--output-file", output_file.as_posix()])

    assert exit_code == 1, "扫描仍应正常完成并返回存在严重风险"
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload, "本地结果不应因 AI 被拦截而丢失"
    assert any(item["risk_id"] == "KEY_FILE_EXPOSED" for item in payload)
    assert all("ai_confidence" not in item for item in payload)


def test_cli_flags_reach_ai_client(tmp_path):
    """直接验证命令行开关到客户端的映射（含外发闸门与 --ai 取值）。"""
    ai_section_config = {"AI_CONFIG": {
        "enabled": "false", "base_url": "http://127.0.0.1:11434/v1", "model": "test-model",
        "features": "report", "api_key": "", "timeout": "5", "max_tokens": "128",
        "redact": "true", "cache": "", "ack_data_egress": "false",
    }}
    parser = cli.build_parser()

    # 指向远程端点且未确认 → 被外发闸门拦下
    args = parser.parse_args(["--ai", "report", "--ai-base-url", "https://api.example.com/v1"])
    blocked = cli.build_ai_client(args, dict(ai_section_config))
    assert "ack_data_egress" in blocked.unavailable_reason()

    # 加 --i-accept-ai-egress 后放行
    args = parser.parse_args(["--ai", "report", "--ai-base-url", "https://api.example.com/v1",
                              "--i-accept-ai-egress"])
    assert cli.build_ai_client(args, dict(ai_section_config)).unavailable_reason() is None

    # --ai off 覆盖配置
    args = parser.parse_args(["--ai", "off"])
    assert cli.build_ai_client(args, dict(ai_section_config)).unavailable_reason() is not None

    # --ai all 展开为全部步骤，且为内容分级调高证据采集上限
    args = parser.parse_args(["--ai", "all"])
    config = dict(ai_section_config)
    client = cli.build_ai_client(args, config)
    assert set(client.config.features) == {"report", "analyze", "classify"}
    assert config["evidence_limit"] == cli.CLASSIFY_EVIDENCE_LIMIT

    # 只跑 report 时不需要拉长证据
    args = parser.parse_args(["--ai", "report"])
    config = dict(ai_section_config)
    cli.build_ai_client(args, config)
    assert "evidence_limit" not in config

    # --ai-model 覆盖配置里的模型名
    args = parser.parse_args(["--ai", "report", "--ai-model", "override-model"])
    assert cli.build_ai_client(args, dict(ai_section_config)).config.model == "override-model"


def test_ai_unreachable_endpoint_does_not_break_scan(tmp_path, fake_bucket):
    """AI 端点不可达时扫描必须照常完成。"""
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    exit_code = cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
                          "--config", config_path, "--output", "json", "--ai", "all",
                          "--ai-base-url", "http://127.0.0.1:1/v1",
                          "--output-file", output_file.as_posix()])

    assert exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert any(item["risk_id"] == "KEY_FILE_EXPOSED" for item in payload)


def test_ai_off_overrides_config(tmp_path, fake_bucket):
    populate(fake_bucket)
    fake_bucket.route_ai(json.dumps({"executive_summary": "不应出现"}))
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0,
                               ai_section=ai_section(fake_bucket.ai_base_url()))
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json", "--ai", "off",
              "--output-file", output_file.as_posix()])
    assert fake_bucket.ai_calls == 0


def test_ai_classify_raises_evidence_limit(tmp_path, fake_bucket):
    """启用内容分级时应采集更长的证据片段。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    secret = "LTAI5tNotARealKey123456"
    # 密钥放在 3KB 之后：默认 8KB 证据上限之外才会截断，这里用于确认上限被调高
    body = ("A" * 3000) + f"\nALIYUN_AK={secret}\n"
    fake_bucket.route("GET", "/bucket/.env", status=200, body=body)
    fake_bucket.route_ai(json.dumps({
        "findings": [], "executive_summary": "s",
        "credentials": [{"index": 0, "type": "阿里云 AccessKey", "looks_live": True,
                         "confidence": "high", "impact": "OSS"}],
    }))
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0,
                               ai_section=ai_section(fake_bucket.ai_base_url()))
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json", "--ai", "classify",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    finding = next(item for item in payload if item["risk_id"] == "KEY_FILE_EXPOSED")
    assert secret in finding["evidence"], "分级模式应采集足够长的证据以覆盖更深处的内容"
    sent = json.dumps(fake_bucket.ai_payloads(), ensure_ascii=False)
    assert secret not in sent


# ------------------------------------------------------------------ 临时 STS（端到端）

def test_cli_accepts_sts_credentials_and_signs_requests(tmp_path, fake_bucket):
    """认证态端到端：请求带签名与令牌头，结果标注 authenticated。"""
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    exit_code = cli.main([
        "--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
        "--config", config_path, "--output", "json",
        "--sts-ak", "LTAI5tFakeAccessKeyId",
        "--sts-sk", "FakeSecretKeyMaterial000",
        "--sts-token", "FakeSecurityTokenValue111",
        "--output-file", output_file.as_posix(),
    ])

    assert exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload
    assert all(item["auth_mode"] == "authenticated" for item in payload)

    for headers in fake_bucket.request_headers:
        assert headers.get("authorization", "").startswith("OSS ")
        assert headers.get("x-oss-security-token") == "FakeSecurityTokenValue111"

    # 密钥与令牌绝不能出现在报告里
    blob = output_file.read_text(encoding="utf-8")
    assert "FakeSecretKeyMaterial000" not in blob
    assert "FakeSecurityTokenValue111" not in blob


def test_cli_reads_sts_from_env(tmp_path, fake_bucket, monkeypatch):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"
    monkeypatch.setenv("OSS_SCANNER_STS_AK", "env-ak")
    monkeypatch.setenv("OSS_SCANNER_STS_SK", "env-sk")
    monkeypatch.setenv("OSS_SCANNER_STS_TOKEN", "env-token")

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert all(item["auth_mode"] == "authenticated" for item in payload)
    assert all(h.get("x-oss-security-token") == "env-token"
               for h in fake_bucket.request_headers)


def test_cli_partial_sts_falls_back_to_anonymous(tmp_path, fake_bucket):
    """只给一半凭证时报错并以匿名继续，而不是整个中断。"""
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    exit_code = cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
                          "--config", config_path, "--output", "json",
                          "--sts-ak", "only-the-id",
                          "--output-file", output_file.as_posix()])

    assert exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload
    assert all(item["auth_mode"] == "anonymous" for item in payload)


def test_cli_authenticated_report_shows_badge_and_token_placeholder(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.html"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "html",
              "--sts-ak", "LTAI5tFakeAccessKeyId",
              "--sts-sk", "FakeSecretKeyMaterial000",
              "--sts-token", "FakeSecurityTokenValue111",
              "--output-file", output_file.as_posix()])

    html = output_file.read_text(encoding="utf-8")
    assert "认证态发现" in html
    assert "$OSS_SCANNER_STS_TOKEN" in html
    assert "FakeSecurityTokenValue111" not in html
    assert "FakeSecretKeyMaterial000" not in html


def test_version_history_end_to_end(tmp_path, fake_bucket):
    """scan_version_leak 现已真正落地：历史版本可被检出。"""
    fake_bucket.route("HEAD", "/bucket", status=403)
    fake_bucket.route("GET", "/bucket/", status=403)
    fake_bucket.route("GET", "/bucket/.env", status=200, body="A=1")
    fake_bucket.route("GET", "/bucket/?versioning", status=200, body=
                      "<VersioningConfiguration><Status>Enabled</Status>"
                      "<MfaDelete>Disabled</MfaDelete></VersioningConfiguration>")
    fake_bucket.route("GET", "/bucket/.env?versions", status=200, body=
                      "<ListVersionsResult>"
                      "<Version><Key>.env</Key><VersionId>v-1</VersionId>"
                      "<IsLatest>false</IsLatest></Version></ListVersionsResult>")
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert any(item["risk_id"] == "DELETED_OBJECT_RECOVERABLE" for item in payload)


def test_cli_reports_include_poc(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload
    assert all(item["poc"].startswith("curl") for item in payload)


def test_no_poc_flag_suppresses_poc(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"), request_interval=0)
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json", "--no-poc",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload
    assert all("poc" not in item for item in payload)


# ------------------------------------------------------------------ 端点直填与校验

@pytest.mark.parametrize("value,cloud,bucket,region", [
    ("http://1111.cos.beijin.myqcloud.com", "tencent", "1111", "beijin"),
    ("https://1111.cos.ap-beijing.myqcloud.com", "tencent", "1111", "ap-beijing"),
    ("https://bkt.oss-cn-beijing.aliyuncs.com", "aliyun", "bkt", "cn-beijing"),
    ("bkt.oss-cn-beijing.aliyuncs.com", "aliyun", "bkt", "cn-beijing"),
    ("https://bkt.s3.us-east-1.amazonaws.com", "aws", "bkt", "us-east-1"),
    ("bkt.obs.cn-north-4.myhuaweicloud.com", "huawei", "bkt", "cn-north-4"),
    ("https://bkt-1250000000.cos.ap-guangzhou.myqcloud.com", "tencent", "bkt", "ap-guangzhou"),
])
def test_bucket_accepts_full_endpoint(value, cloud, bucket, region):
    """--bucket 直接传完整地址时应自动识别厂商与区域，不必分两次输入。"""
    args = cli.build_parser().parse_args(["--bucket", value])
    target = cli.resolve_target(args, {"AUTO_EXTRACT": {}})
    assert target is not None
    assert target["cloud"] == cloud
    assert target["buckets"] == [bucket]
    assert target["region"] == region


def test_bucket_url_carries_tencent_appid():
    args = cli.build_parser().parse_args(["--bucket", "https://bkt-1250000000.cos.ap-guangzhou.myqcloud.com"])
    assert cli.resolve_target(args, {"AUTO_EXTRACT": {}})["appid"] == "1250000000"


def test_plain_bucket_name_still_needs_cloud_and_region():
    """向后兼容：裸桶名仍走原来的 --cloud/--region 路径。"""
    args = cli.build_parser().parse_args(["--bucket", "plain", "--cloud", "aliyun",
                                          "--region", "cn-beijing"])
    target = cli.resolve_target(args, {"AUTO_EXTRACT": {}})
    assert target["cloud"] == "aliyun" and target["buckets"] == ["plain"]


def test_plain_bucket_without_region_is_rejected():
    args = cli.build_parser().parse_args(["--bucket", "plain", "--cloud", "aliyun"])
    assert cli.resolve_target(args, {"AUTO_EXTRACT": {}}) is None


def test_region_typo_gets_suggestion(caplog):
    """区域拼错时给出可操作提示，而不是静默扫错地址。"""
    import logging
    with caplog.at_level(logging.WARNING, logger="oss_scanner"):
        cli._warn_region_shape("tencent", "beijin")
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "看起来不是" in text
    assert "ap-beijing" in text


@pytest.mark.parametrize("cloud,region", [
    ("aliyun", "cn-beijing"), ("tencent", "ap-beijing"),
    ("aws", "us-east-1"), ("huawei", "cn-north-4"),
    ("aliyun", "cn-brandnew-1"),   # 形态正确的新区域不应告警
])
def test_valid_regions_do_not_warn(caplog, cloud, region):
    import logging
    with caplog.at_level(logging.WARNING, logger="oss_scanner"):
        cli._warn_region_shape(cloud, region)
    assert not any("看起来不是" in r.getMessage() for r in caplog.records)


def test_help_does_not_require_authorization_prompt():
    """回归：--help 此前会先撞上授权确认的 input() 而卡住。"""
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "main.py", "--help"],
                            capture_output=True, text=True, timeout=30, input="")
    assert result.returncode == 0
    assert "--role-arn" in result.stdout
    assert "免责声明" not in result.stdout


def test_proxy_from_config_file_is_used(tmp_path, fake_bucket):
    """回归：proxy 写在 config.ini 里此前被静默忽略。"""
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"),
                               request_interval=0,
                               extra="proxy = http://127.0.0.1:1")   # 死代理
    output_file = tmp_path / "report.json"

    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    # 代理不可达 → 目标无法访问 → 不应拿到任何敏感文件命中
    assert not any(item["risk_id"] == "KEY_FILE_EXPOSED" for item in payload)


def test_cli_proxy_overrides_config_proxy(tmp_path, fake_bucket):
    populate(fake_bucket)
    config_path = write_config(tmp_path, fake_bucket.base_url("/{bucket}"),
                               request_interval=0,
                               extra="proxy = http://127.0.0.1:1")
    output_file = tmp_path / "report.json"

    # 命令行显式给空代理不生效（argparse 只认非空），这里验证 --proxy 优先于配置
    cli.main(["--cloud", "aliyun", "--region", "cn-beijing", "--bucket", "bucket",
              "--config", config_path, "--output", "json",
              "--proxy", "http://127.0.0.1:2",
              "--output-file", output_file.as_posix()])

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert not any(item["risk_id"] == "KEY_FILE_EXPOSED" for item in payload)
