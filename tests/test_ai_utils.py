"""AI 研判层：脱敏、数据外发闸门、降级、缓存与报告集成。

全部离线运行：用 tests/conftest.py 里的假服务模拟 OpenAI 兼容端点。
"""
import json

import pytest

from utils.ai_utils import (
    AIClient,
    AIConfig,
    annotate_false_positives,
    apply_ai_passes,
    classify_exposed_content,
    find_credentials,
    generate_report_summary,
    load_prompt,
    mask_secrets,
    redact_url,
)
from utils.report_utils import generate_report, normalize_ai_summary

# 一个格式合法、但明显是占位符的 AccessKey
FAKE_AK = "LTAI5tNotARealKey123456"
PLACEHOLDER_AK = "AKIAIOSFODNN7EXAMPLE"


def make_client(fake_bucket, **overrides) -> AIClient:
    defaults = dict(
        enabled=True,
        base_url=fake_bucket.ai_base_url(),
        model="test-model",
        features=("report", "analyze", "classify"),
        redact=True,
        cache_path="",
        ack_data_egress=False,
        timeout=5,
    )
    defaults.update(overrides)
    return AIClient(AIConfig(**defaults))


def sample_results():
    return [
        {
            "risk_id": "KEY_FILE_EXPOSED", "severity": "CRITICAL", "title": "密钥文件可匿名访问",
            "msg": "发现可匿名访问文件: .env", "url": "http://bkt.oss-cn-beijing.aliyuncs.com/.env",
            "bucket": "bkt", "cloud": "aliyun", "region": "cn-beijing",
            "status_code": 200, "content_type": "text/plain", "content_length": 120,
            "evidence": f"ALIYUN_ACCESS_KEY_ID={FAKE_AK}\nDB_PASSWORD=hunter2",
            "evidence_truncated": False, "timestamp": "2026-10-09T00:00:00+00:00",
        },
        {
            "risk_id": "DIRECTORY_TRAVERSAL", "severity": "MEDIUM", "title": "存在目录遍历访问",
            "msg": "目录遍历可读取系统文件", "url": "http://bkt.oss-cn-beijing.aliyuncs.com/../../etc/passwd",
            "bucket": "bkt", "cloud": "aliyun", "region": "cn-beijing",
            "status_code": 200, "content_type": "text/html", "content_length": 900,
            "evidence": "<html><body>SPA 首页</body></html>",
            "evidence_truncated": False, "timestamp": "2026-10-09T00:00:00+00:00",
        },
    ]


# ------------------------------------------------------------------ 脱敏

def test_mask_secrets_hides_key_material():
    masked = mask_secrets(f"id={FAKE_AK} aws={PLACEHOLDER_AK} jwt=eyJhbGciOi.eyJzdWIi.SflKxwRJ")
    assert FAKE_AK not in masked
    assert PLACEHOLDER_AK not in masked
    assert "LTAI****" in masked
    # 保留前缀便于人工核对
    assert masked.startswith("id=LTAI")


def test_mask_secrets_covers_private_key_and_dsn():
    masked = mask_secrets("-----BEGIN RSA PRIVATE KEY-----\npostgres://user:s3cret@db:5432/app")
    assert "s3cret" not in masked
    # 口令整体掩码，但保留 user:****@host 结构以便判断影响面
    assert "user:****@db" in masked


def test_mask_keeps_private_key_marker_readable():
    """私钥头部是标志性字符串而非秘密本身，必须保留让模型能识别类型。"""
    masked = mask_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA")
    assert "-----BEGIN RSA PRIVATE KEY-----" in masked


def test_mask_truncates_long_identifiers_but_not_passwords():
    # 长标识符保留前 4 位，便于人工核对是哪把密钥
    assert mask_secrets("LTAI5tNotARealKey123456") == "LTAI****"
    # 口令每个字符都有价值，整段掩码
    assert mask_secrets("redis://default:abc123xyz@cache:6379") == "redis://default:****@cache:6379"


def test_find_credentials_reports_type_and_masked_fragment():
    hits = find_credentials(f"AK={FAKE_AK}")
    assert hits
    assert hits[0]["type"] == "阿里云 AccessKeyId"
    assert FAKE_AK not in hits[0]["masked"]


def test_mask_secrets_handles_empty_input():
    assert mask_secrets("") == ""
    assert find_credentials("") == []


def test_redact_url_hashes_bucket_name():
    redacted = redact_url("https://my-secret-bucket.oss-cn-beijing.aliyuncs.com/.env")
    assert "my-secret-bucket" not in redacted
    assert "oss-cn-beijing.aliyuncs.com" in redacted
    assert "/.env" in redacted


# ------------------------------------------------------------------ 外发闸门

def test_remote_endpoint_blocked_without_acknowledgement():
    client = AIClient(AIConfig(enabled=True, base_url="https://api.deepseek.com/v1",
                              model="deepseek-chat", features=("report",)))
    reason = client.unavailable_reason()
    assert reason and "ack_data_egress" in reason
    assert client.chat_json("report", "{}") is None


def test_remote_endpoint_allowed_with_acknowledgement():
    client = AIClient(AIConfig(enabled=True, base_url="https://api.deepseek.com/v1",
                               model="deepseek-chat", features=("report",)),
                      accept_egress=True)
    assert client.unavailable_reason() is None


def test_local_endpoint_needs_no_acknowledgement():
    for base in ("http://127.0.0.1:11434/v1", "http://localhost:1234/v1", "http://ollama.local/v1"):
        client = AIClient(AIConfig(enabled=True, base_url=base, model="m", features=("report",)))
        assert client.unavailable_reason() is None, base


def test_disabled_client_is_noop():
    client = AIClient(AIConfig(enabled=False))
    assert "未启用" in client.unavailable_reason()
    assert client.chat_json("report", "{}") is None


# ------------------------------------------------------------------ 调用与降级

def test_chat_json_parses_openai_envelope(fake_bucket):
    fake_bucket.route_ai(json.dumps({"executive_summary": "一切正常"}))
    client = make_client(fake_bucket)
    assert client.chat_json("report", "test")["executive_summary"] == "一切正常"


def test_chat_json_tolerates_code_fence(fake_bucket):
    fake_bucket.route_ai('```json\n{"executive_summary": "fenced"}\n```')
    client = make_client(fake_bucket)
    assert client.chat_json("report", "test")["executive_summary"] == "fenced"


def test_chat_json_tolerates_surrounding_prose(fake_bucket):
    fake_bucket.route_ai('好的，这是结果：{"executive_summary": "prose"} 以上。')
    client = make_client(fake_bucket)
    assert client.chat_json("report", "test")["executive_summary"] == "prose"


def test_unreachable_endpoint_degrades_without_raising():
    """端点不可达时扫描不能失败，只返回 None。"""
    client = AIClient(AIConfig(enabled=True, base_url="http://127.0.0.1:1/v1",
                               model="m", features=("report",), timeout=1))
    assert client.chat_json("report", "{}") is None
    assert client.unavailable_reason() is not None


def test_invalid_json_response_returns_none(fake_bucket):
    fake_bucket.route_ai("这不是 JSON")
    assert make_client(fake_bucket).chat_json("report", "{}") is None


def test_http_error_returns_none(fake_bucket):
    fake_bucket.route_ai("boom", status=500)
    assert make_client(fake_bucket).chat_json("report", "{}") is None


def test_results_are_cached(fake_bucket):
    """同一问题只调用一次模型。"""
    fake_bucket.route_ai(json.dumps({"executive_summary": "cached"}))
    client = make_client(fake_bucket)
    client.chat_json("report", "same")
    client.chat_json("report", "same")
    assert fake_bucket.ai_calls == 1


def test_cache_can_be_persisted(fake_bucket, tmp_path):
    fake_bucket.route_ai(json.dumps({"executive_summary": "persisted"}))
    cache_file = (tmp_path / "ai_cache.json").as_posix()

    first = make_client(fake_bucket, cache_path=cache_file)
    first.chat_json("report", "same")
    assert fake_bucket.ai_calls == 1

    second = make_client(fake_bucket, cache_path=cache_file)
    assert second.chat_json("report", "same")["executive_summary"] == "persisted"
    assert fake_bucket.ai_calls == 1, "命中缓存时不应再次调用端点"


# ------------------------------------------------------------------ 三个步骤

def test_analyze_annotates_confidence(fake_bucket):
    fake_bucket.route_ai(json.dumps({"findings": [
        {"index": 0, "false_positive_likely": False, "confidence": "high", "reason": "响应体含真实密钥"},
        {"index": 1, "false_positive_likely": True, "confidence": "high", "reason": "返回的是 SPA 首页"},
    ]}))
    results = sample_results()
    assert annotate_false_positives(results, make_client(fake_bucket)) == 2
    assert results[0]["ai_confidence"] == "high"
    assert results[1]["ai_false_positive_likely"] is True


def test_analyze_ignores_out_of_range_index(fake_bucket):
    fake_bucket.route_ai(json.dumps({"findings": [
        {"index": 99, "confidence": "high", "reason": "越界"},
    ]}))
    results = sample_results()
    assert annotate_false_positives(results, make_client(fake_bucket)) == 0
    assert "ai_confidence" not in results[0]


def test_analyze_skips_info_and_error(fake_bucket):
    """非风险类结果不参与误报研判。"""
    fake_bucket.route_ai(json.dumps({"findings": []}))
    results = [{"risk_id": "BUCKET_NOT_FOUND", "severity": "INFO", "msg": "", "url": ""}]
    assert annotate_false_positives(results, make_client(fake_bucket)) == 0


def test_classify_sends_only_masked_fragments(fake_bucket):
    """关键约束：原始凭据绝不能离开本机。"""
    fake_bucket.route_ai(json.dumps({"credentials": [
        {"index": 0, "type": "阿里云 AccessKey", "looks_live": True,
         "confidence": "medium", "impact": "可读写该账号下的 OSS 资源"},
    ]}))
    results = sample_results()
    assert classify_exposed_content(results, make_client(fake_bucket)) == 1

    sent = json.dumps(fake_bucket.ai_payloads(), ensure_ascii=False)
    assert FAKE_AK not in sent, "原始 AccessKey 不得发送给模型"
    assert "LTAI****" in sent
    assert "hunter2" not in sent

    credentials = results[0]["verified_credentials"]
    assert [c["type"] for c in credentials] == ["阿里云 AccessKey"]
    assert credentials[0]["looks_live"] is True


def test_classify_keeps_multiple_credentials_per_file(fake_bucket):
    """一个文件可能同时泄露多种凭据（如 .env 里的 AccessKey 与数据库口令），
    后一条不得覆盖前一条。"""
    fake_bucket.route_ai(json.dumps({"credentials": [
        {"index": 0, "type": "阿里云 AccessKey", "looks_live": True, "confidence": "high", "impact": "OSS"},
        {"index": 0, "type": "Redis 连接口令", "looks_live": True, "confidence": "medium", "impact": "缓存"},
    ]}))
    results = sample_results()
    assert classify_exposed_content(results, make_client(fake_bucket)) == 2
    assert [c["type"] for c in results[0]["verified_credentials"]] == ["阿里云 AccessKey", "Redis 连接口令"]


def test_classify_ignores_entries_without_type(fake_bucket):
    fake_bucket.route_ai(json.dumps({"credentials": [
        {"index": 0, "looks_live": True, "confidence": "high"},
    ]}))
    results = sample_results()
    assert classify_exposed_content(results, make_client(fake_bucket)) == 0
    assert "verified_credentials" not in results[0]


def test_classify_skips_files_without_credentials(fake_bucket):
    """本地正则先筛，没有命中就不调用模型。"""
    fake_bucket.route_ai(json.dumps({"credentials": []}))
    results = [{
        "risk_id": "KEY_FILE_EXPOSED", "severity": "CRITICAL", "msg": "", "url": "",
        "evidence": "SERVER_NAME=web01\nDEBUG=false",
    }]
    assert classify_exposed_content(results, make_client(fake_bucket)) == 0
    assert fake_bucket.ai_calls == 0


def test_report_summary_generated(fake_bucket):
    fake_bucket.route_ai(json.dumps({
        "executive_summary": "存在一个可直接下载的密钥文件，风险很高。",
        "top_risks": [{"risk_id": "KEY_FILE_EXPOSED", "why_it_matters": "可直接接管存储账号", "priority": 1}],
        "remediation_plan": [{"step": "收敛读权限", "detail": "OSS 控制台 → 权限管理 → 阻止公共访问"}],
        "notes": "需确认该 AccessKey 是否仍在用",
    }))
    results = sample_results()
    summary = generate_report_summary(results, make_client(fake_bucket), {"cloud": "aliyun"})
    assert summary["top_risks"][0]["risk_id"] == "KEY_FILE_EXPOSED"
    assert "阻止公共访问" in summary["remediation_plan"][0]["detail"]


def test_apply_ai_passes_runs_all_steps(fake_bucket):
    fake_bucket.route_ai(json.dumps({
        "findings": [{"index": 0, "confidence": "high", "reason": "r"}],
        "credentials": [],
        "executive_summary": "整体可控",
    }))
    results = sample_results()
    outcome = apply_ai_passes(results, make_client(fake_bucket), {"cloud": "aliyun"})
    assert outcome["summary"]["executive_summary"] == "整体可控"
    assert outcome["annotated"]["analyze"] >= 1
    # 内部字段不应泄漏到结果里
    assert all("_ai_index" not in r for r in results)


def test_apply_ai_passes_noop_when_disabled():
    results = sample_results()
    outcome = apply_ai_passes(results, AIClient(AIConfig(enabled=False)))
    assert outcome["summary"] is None
    assert "ai_confidence" not in results[0]


# ------------------------------------------------------------------ 摘要规整

def test_normalize_ai_summary_rejects_garbage():
    assert normalize_ai_summary(None) is None
    assert normalize_ai_summary("字符串") is None
    assert normalize_ai_summary({}) is None
    # 只有无关字段时视为无有效内容
    assert normalize_ai_summary({"unexpected": 1}) is None


def test_normalize_ai_summary_coerces_wrong_types():
    """模型输出不可信：字段类型不符时应降级而不是让渲染报错。"""
    normalized = normalize_ai_summary({
        "executive_summary": 123,
        "top_risks": ["不是字典", {"risk_id": "X", "priority": "一"}],
        "remediation_plan": {"step": "不是列表"},
        "notes": None,
    })
    assert normalized["executive_summary"] == ""
    assert len(normalized["top_risks"]) == 1
    assert normalized["remediation_plan"] == []
    assert normalized["disclaimer"]


# ------------------------------------------------------------------ 报告集成

def test_text_report_includes_ai_section():
    results = sample_results()
    results[0]["ai_confidence"] = "low"
    results[0]["verified_credentials"] = [{"type": "阿里云 AccessKey", "looks_live": True,
                                           "confidence": "high", "impact": "OSS"}]
    text = generate_report(results, "text", {}, {"executive_summary": "摘要内容",
                                                 "top_risks": [], "remediation_plan": []})
    assert "AI 研判" in text
    assert "摘要内容" in text
    assert "凭据 阿里云 AccessKey" in text
    assert "AI 置信度 low" in text


def test_json_report_keeps_array_shape_and_ai_fields():
    """JSON 输出保持数组结构，AI 结论作为字段附加。"""
    results = sample_results()
    results[0]["ai_confidence"] = "high"
    results[0]["verified_credentials"] = [{"type": "阿里云 AccessKey", "looks_live": True,
                                           "confidence": "high", "impact": "OSS"}]
    payload = json.loads(generate_report(results, "json", {}, None))
    assert isinstance(payload, list)
    assert payload[0]["ai_confidence"] == "high"
    assert payload[0]["verified_credentials"][0]["looks_live"] is True


def test_normalize_drops_credential_entries_without_type():
    results = [{"risk_id": "KEY_FILE_EXPOSED", "severity": "CRITICAL", "msg": "", "url": "",
                "verified_credentials": [{"looks_live": True}, "不是字典",
                                         {"type": "T", "looks_live": True}]}]
    html = generate_report(results, "html", {}, None)
    # 只有带 type 的那一条被渲染出来
    assert html.count("ai-tag cred-live") == 1
    assert "疑似占位凭据" not in html


def test_html_report_includes_ai_panel():
    html = generate_report(sample_results(), "html", {},
                           {"executive_summary": "执行摘要文本",
                            "top_risks": [{"risk_id": "KEY_FILE_EXPOSED", "why_it_matters": "要紧", "priority": 1}],
                            "remediation_plan": [{"step": "收敛权限", "detail": "控制台操作"}],
                            "notes": "需复核"})
    assert "AI 研判" in html
    assert "执行摘要文本" in html
    assert "收敛权限" in html
    assert "人工复核" in html


def test_html_escapes_target_controlled_evidence():
    """安全约束：证据来自被测目标，必须转义，否则报告会执行目标返回的脚本。"""
    results = sample_results()
    results[0]["evidence"] = '<script>alert("xss")</script>'
    results[0]["msg"] = '<img src=x onerror=alert(1)>'
    html = generate_report(results, "html", {}, None)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "onerror=alert(1)>" not in html


def test_html_escapes_ai_supplied_text():
    """AI 输出同样不可信，任何进入 HTML 的字段都要转义。"""
    html = generate_report(sample_results(), "html", {},
                           {"executive_summary": "<script>alert(1)</script>",
                            "top_risks": [], "remediation_plan": []})
    assert "<script>alert(1)</script>" not in html


# ------------------------------------------------------------------ 提示词

@pytest.mark.parametrize("feature", ["report", "analyze", "classify"])
def test_prompt_files_exist_and_are_nonempty(feature):
    prompt = load_prompt(feature)
    assert prompt.strip()
    assert "JSON" in prompt


def test_unknown_prompt_falls_back_to_empty():
    assert load_prompt("nonexistent-feature") == ""


# ------------------------------------------------------------------ 配置解析

def test_ai_config_from_ini_section():
    config = {"AI_CONFIG": {
        "enabled": "true", "base_url": "http://127.0.0.1:11434/v1/", "model": "qwen2.5:7b",
        "api_key": "", "timeout": "30", "max_tokens": "1024",
        "features": "report, classify", "redact": "true", "ack_data_egress": "false",
    }}
    ai_config = AIConfig.from_config(config)
    assert ai_config.enabled is True
    assert ai_config.base_url == "http://127.0.0.1:11434/v1"   # 去掉尾斜杠
    assert ai_config.features == ("report", "classify")
    assert ai_config.timeout == 30
    assert ai_config.redact is True
    assert ai_config.ack_data_egress is False


def test_ai_config_defaults_to_disabled():
    ai_config = AIConfig.from_config({})
    assert ai_config.enabled is False
    assert ai_config.redact is True
    assert ai_config.ack_data_egress is False
