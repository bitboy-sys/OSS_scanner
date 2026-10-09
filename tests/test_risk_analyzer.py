"""风险等级与元数据的一致性。"""
import json

from core.risk_analyzer import RISK_META, Risk, Severity, severity_of, title_of


def test_every_risk_has_metadata():
    """任何 Risk 成员都必须有元数据，否则报告会丢标题与修复建议。"""
    missing = [risk.name for risk in Risk if risk not in RISK_META]
    assert missing == []


def test_no_orphan_metadata():
    for risk in RISK_META:
        assert isinstance(risk, Risk)
        assert RISK_META[risk].title.strip()
        assert RISK_META[risk].remediation.strip()


def test_risk_value_equals_name():
    """值即稳定 ID，重命名成员不应悄悄改变对外契约。"""
    for risk in Risk:
        assert risk.value == risk.name


def test_risk_ids_unique():
    values = [risk.value for risk in Risk]
    assert len(values) == len(set(values))


def test_finding_is_json_serializable():
    """回归：此前 RiskLevel 是普通枚举，--output json 会抛 TypeError。"""
    payload = [{"risk_id": Risk.KEY_FILE_EXPOSED.value, "severity": severity_of(Risk.KEY_FILE_EXPOSED).name}]
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "KEY_FILE_EXPOSED" in encoded


def test_enum_member_json_serializable():
    """str 子类枚举可直接序列化，无需自行转换。"""
    assert json.dumps({"risk": Risk.PUBLIC_LIST}) == '{"risk": "PUBLIC_LIST"}'


def test_severity_mapping_spot_checks():
    assert severity_of(Risk.KEY_FILE_EXPOSED) is Severity.CRITICAL
    assert severity_of(Risk.DB_BACKUP_EXPOSED) is Severity.CRITICAL
    assert severity_of(Risk.ANON_DELETE) is Severity.CRITICAL
    assert severity_of(Risk.PUBLIC_LIST) is Severity.HIGH
    assert severity_of(Risk.LOG_EXPOSED) is Severity.HIGH
    # 策略允许匿名读取与各厂商原始定级一致（中危）
    assert severity_of(Risk.POLICY_ANON_READ) is Severity.MEDIUM
    assert severity_of(Risk.POLICY_ANON_WRITE) is Severity.CRITICAL
    assert severity_of(Risk.SENSITIVE_HEADERS) is Severity.LOW
    assert severity_of(Risk.BUCKET_NOT_FOUND) is Severity.INFO
    assert severity_of(Risk.SCAN_ERROR) is Severity.ERROR


def test_severity_label_is_chinese():
    assert Severity.CRITICAL.label == "严重"
    assert Severity.HIGH.label == "高危"
    assert Severity.MEDIUM.label == "中危"
    assert Severity.LOW.label == "低危"
    assert Severity.INFO.label == "信息"
    assert Severity.ERROR.label == "错误"


def test_titles_are_distinct_per_meaning():
    """同一严重度下不同含义必须有不同标题（此前 LOW1/LOW2 被复用于多种含义）。"""
    titles = [title_of(risk) for risk in Risk]
    assert len(titles) == len(set(titles))
