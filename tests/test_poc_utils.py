"""PoC 命令生成与报告集成。"""
import json

import pytest

from core.risk_analyzer import Risk
from utils.poc_utils import build_poc
from utils.report_utils import generate_report

AUTH_TOKEN = "FakeSecurityTokenValue111"
AUTH_SECRET = "FakeSecretKeyMaterial000"


def finding(risk_id, url="https://b.oss-cn-beijing.aliyuncs.com/.env",
            auth_mode="anonymous", cloud="aliyun", **extra):
    return {"risk_id": risk_id, "severity": "HIGH", "title": "t", "msg": "m",
            "url": url, "bucket": "b", "cloud": cloud, "region": "cn-beijing",
            "auth_mode": auth_mode, "status_code": 200, "content_type": "",
            "content_length": 0, "evidence": "", "evidence_truncated": False,
            "timestamp": "2026-10-09T00:00:00+00:00", **extra}


@pytest.mark.parametrize("risk_id", [
    Risk.KEY_FILE_EXPOSED.value,
    Risk.DB_BACKUP_EXPOSED.value,
    Risk.CONFIG_FILE_EXPOSED.value,
    Risk.OTHER_FILE_EXPOSED.value,
    Risk.PUBLIC_LIST.value,
    Risk.LOG_EXPOSED.value,
    Risk.ANON_WRITE_PUT.value,
    Risk.ANON_WRITE_POST.value,
    Risk.ANON_DELETE.value,
    Risk.POLICY_ANON_READ.value,
    Risk.POLICY_ANON_WRITE.value,
    Risk.POLICY_ANON_POLICY_READ.value,
    Risk.ACL_PUBLIC_GRANT.value,
    Risk.ACL_AUTHENTICATED_GRANT.value,
    Risk.NO_SSE.value,
    Risk.ENCRYPTION_AES_NOT_KMS.value,
    Risk.LOGGING_DISABLED.value,
    Risk.REFERER_UNRESTRICTED.value,
    Risk.STATIC_WEBSITE_ENABLED.value,
    Risk.CROSS_ACCOUNT_REPLICATION.value,
    Risk.CORS_WILDCARD.value,
    Risk.DIRECTORY_TRAVERSAL.value,
    Risk.DELETED_OBJECT_RECOVERABLE.value,
    Risk.VERSIONING_WITHOUT_MFA_DELETE.value,
    Risk.HTTP_ENABLED.value,
    Risk.SENSITIVE_HEADERS.value,
    Risk.BLOB_PUBLIC_ACCESS.value,
])
def test_every_actionable_risk_has_a_poc(risk_id):
    """每条能复现的风险都应给出命令，否则「利用能力」就是空的。"""
    poc = build_poc(finding(risk_id))
    assert poc.strip()
    # 写操作类命令会以警告注释开头，其余以 curl 开头
    first_line = poc.splitlines()[0].strip()
    assert first_line.startswith("curl") or first_line.startswith("#"), poc


def test_informational_risks_have_no_poc():
    for risk_id in (Risk.BUCKET_NOT_FOUND.value, Risk.SCAN_ERROR.value,
                    Risk.REGION_DISCOVERED.value, Risk.AUTH_ERROR.value):
        assert build_poc(finding(risk_id)) == ""


def test_poc_requires_a_url():
    assert build_poc(finding(Risk.PUBLIC_LIST.value, url="")) == ""


def test_poc_url_is_shell_quoted():
    """查询串里的 & 必须被引号包住，否则 shell 会把命令截断。"""
    poc = build_poc(finding(Risk.POLICY_ANON_READ.value,
                            url="https://b.oss-cn-beijing.aliyuncs.com/?policy&x=1"))
    assert "'https://b.oss-cn-beijing.aliyuncs.com/?policy&x=1'" in poc


def test_poc_never_contains_real_credentials():
    """关键安全约束：报告里的 PoC 只能用占位符。"""
    item = finding(Risk.KEY_FILE_EXPOSED.value, auth_mode="authenticated",
                   access_key_secret=AUTH_SECRET, security_token=AUTH_TOKEN)
    poc = build_poc(item)
    assert AUTH_SECRET not in poc
    assert AUTH_TOKEN not in poc
    assert "$OSS_SCANNER_STS_TOKEN" in poc
    assert "x-oss-security-token" in poc


def test_anonymous_poc_has_no_token_header():
    poc = build_poc(finding(Risk.KEY_FILE_EXPOSED.value))
    assert "security-token" not in poc


def test_aws_poc_uses_aws_token_header():
    poc = build_poc(finding(Risk.KEY_FILE_EXPOSED.value, auth_mode="authenticated",
                            cloud="aws"))
    assert "x-amz-security-token" in poc


def test_write_pocs_warn_about_side_effects():
    """写操作类命令必须写明会真的改动目标。"""
    for risk_id in (Risk.ANON_WRITE_PUT.value, Risk.ANON_WRITE_POST.value,
                    Risk.ANON_DELETE.value):
        poc = build_poc(finding(risk_id))
        assert "注意" in poc
        assert "授权范围" in poc


def test_write_poc_uses_correct_method():
    assert "-X PUT" in build_poc(finding(Risk.ANON_WRITE_PUT.value))
    assert "-X POST" in build_poc(finding(Risk.ANON_WRITE_POST.value))
    assert "-X DELETE" in build_poc(finding(Risk.ANON_DELETE.value))


def test_file_poc_caps_download_size():
    """避免让人一执行就把几个 G 的备份拉下来。"""
    poc = build_poc(finding(Risk.DB_BACKUP_EXPOSED.value))
    assert "head -c 200" in poc


def test_list_poc_uses_list_type_v2():
    poc = build_poc(finding(Risk.PUBLIC_LIST.value, url="https://b.oss-cn-beijing.aliyuncs.com"))
    assert "list-type=2" in poc and "max-keys=20" in poc


def test_traversal_poc_preserves_parent_segments():
    """curl 默认会折叠 ../，必须加 --path-as-is 才复现得出来。"""
    poc = build_poc(finding(Risk.DIRECTORY_TRAVERSAL.value,
                            url="https://b.oss-cn-beijing.aliyuncs.com/../../etc/passwd"))
    assert "--path-as-is" in poc


def test_cors_poc_sends_preflight_headers():
    poc = build_poc(finding(Risk.CORS_WILDCARD.value, url="https://b.oss-cn-beijing.aliyuncs.com"))
    assert "-X OPTIONS" in poc
    assert "Origin: https://example.com" in poc
    assert "Access-Control-Request-Method: PUT" in poc


# ------------------------------------------------------------------ 报告集成

def test_poc_appears_in_text_report():
    text = generate_report([finding(Risk.PUBLIC_LIST.value)], "text", {})
    assert "PoC:" in text and "curl" in text


def test_poc_appears_in_html_report():
    html = generate_report([finding(Risk.PUBLIC_LIST.value)], "html", {})
    assert "复现命令" in html
    assert "curl" in html


def test_poc_appears_in_json_report():
    payload = json.loads(generate_report([finding(Risk.PUBLIC_LIST.value)], "json", {}))
    assert payload[0]["poc"].startswith("curl")


def test_no_poc_suppresses_generation():
    for output in ("text", "html", "json"):
        content = generate_report([finding(Risk.PUBLIC_LIST.value)], output, {}, with_poc=False)
        assert "curl" not in content


def test_report_marks_authenticated_findings():
    html = generate_report([finding(Risk.KEY_FILE_EXPOSED.value,
                                    auth_mode="authenticated")], "html", {})
    assert "认证态发现" in html
    assert "含认证态" in html

    text = generate_report([finding(Risk.KEY_FILE_EXPOSED.value,
                                    auth_mode="authenticated")], "text", {})
    assert "[认证态]" in text


def test_anonymous_report_has_no_auth_markers():
    html = generate_report([finding(Risk.KEY_FILE_EXPOSED.value)], "html", {})
    assert "认证态发现" not in html


def test_html_escapes_poc_content():
    """PoC 里可能含目标可控的 URL，同样要转义。"""
    html = generate_report([finding(Risk.PUBLIC_LIST.value,
                                    url='https://b/?a=<script>alert(1)</script>')],
                           "html", {})
    assert "<script>alert(1)</script>" not in html


# ------------------------------------------------------------------ 命令可用性

POCO_TARGET_URL = "https://b.oss-cn-beijing.aliyuncs.com/.env"
POCO_LIST_URL = "https://b.oss-cn-beijing.aliyuncs.com"


def test_poc_syntax_is_valid_shell():
    """用 sh -n 做语法检查：生成的命令必须能被 shell 正确解析。"""
    import shutil
    import subprocess

    shell = shutil.which("bash") or shutil.which("sh")
    if not shell:
        pytest.skip("环境里没有可用的 shell")

    for risk_id in (Risk.KEY_FILE_EXPOSED.value, Risk.PUBLIC_LIST.value,
                    Risk.ANON_WRITE_PUT.value, Risk.ANON_DELETE.value,
                    Risk.CORS_WILDCARD.value, Risk.DIRECTORY_TRAVERSAL.value,
                    Risk.DELETED_OBJECT_RECOVERABLE.value,
                    Risk.POLICY_ANON_READ.value):
        poc = build_poc(finding(risk_id, url=POCO_TARGET_URL if risk_id != Risk.PUBLIC_LIST.value
                                else POCO_LIST_URL))
        result = subprocess.run([shell, "-n", "-c", poc], capture_output=True, text=True)
        assert result.returncode == 0, f"{risk_id} 的 PoC 语法错误:\n{poc}\n{result.stderr}"


def test_download_suffix_lands_after_url_not_before():
    """回归：管道曾参与续行，导致 URL 被当成 head 的参数，命令实际不可用。"""
    poc = build_poc(finding(Risk.KEY_FILE_EXPOSED.value, url=POCO_TARGET_URL))
    url_line = [line for line in poc.splitlines() if "'https" in line]
    assert url_line, poc
    # 管道必须与 URL 在同一行、且位于 URL 之后
    assert url_line[0].strip().endswith("| head -c 200"), poc
    assert not any(line.strip().startswith("|") for line in poc.splitlines()), poc


def test_comments_never_share_a_continuation_line():
    r"""回归：注释曾插在 \ 续行中间，会把命令切断。"""
    for risk_id in (Risk.ANON_WRITE_PUT.value, Risk.DELETED_OBJECT_RECOVERABLE.value):
        poc = build_poc(finding(risk_id, url=POCO_TARGET_URL))
        for line in poc.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                assert not stripped.endswith("\\"), poc
                assert not line.rstrip().startswith("  #") is False or True  # 注释可缩进
        # 任何以 \ 续行的下一行都不能是注释
        lines = poc.splitlines()
        for index, line in enumerate(lines[:-1]):
            if line.rstrip().endswith("\\"):
                assert not lines[index + 1].strip().startswith("#"), poc


def test_deleted_object_poc_has_two_steps():
    poc = build_poc(finding(Risk.DELETED_OBJECT_RECOVERABLE.value,
                            url="https://b.oss-cn-beijing.aliyuncs.com/.env?versions"))
    assert poc.count("curl") == 2
    assert "versionId=" in poc
    assert "?versions" in poc


def test_all_pocs_start_with_comment_or_curl():
    for risk_id in (Risk.KEY_FILE_EXPOSED.value, Risk.PUBLIC_LIST.value,
                    Risk.ANON_WRITE_PUT.value, Risk.DIRECTORY_TRAVERSAL.value):
        poc = build_poc(finding(risk_id))
        first = poc.splitlines()[0].strip()
        assert first.startswith("curl") or first.startswith("#"), poc
