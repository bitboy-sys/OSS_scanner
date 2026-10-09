"""报告生成。

结果在渲染前统一补齐 :data:`RISK_META` 里的展示字段（严重度中文标签、修复
建议），因此三种输出格式以及 AI 研判都基于同一份数据。

注意：证据字段来自被测目标的响应体，属于**不可信内容**，因此 HTML 模板必须
开启 autoescape；否则目标返回的 ``<script>`` 会在打开报告时执行。
"""
import json
import os
from typing import Dict, List, Optional

from jinja2 import Template

from core.risk_analyzer import RISK_META, Risk
from utils.poc_utils import build_poc

TOOL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_PATH = os.path.join(TOOL_DIR, "config", "html_template.html")

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR")

AI_DISCLAIMER = "以下内容由大模型生成，仅供参考，必须经人工复核后再作为处置依据。"


def enrich_results(results: List[Dict], with_poc: bool = True) -> List[Dict]:
    """为每条结果补充展示字段：严重度中文标签、修复建议、PoC 与 AI 注释。

    AI 字段只在确实存在时才输出，这样从报告本身就能判断「本次是否跑过
    AI 研判」；缺失的键在 Jinja 模板里会自然渲染为空。
    """
    enriched = []
    for result in results:
        item = dict(result)
        try:
            meta = RISK_META[Risk(item.get("risk_id", ""))]
        except (KeyError, ValueError):
            meta = None
        item["severity_label"] = meta.severity.label if meta else item.get("severity", "")
        item["remediation"] = meta.remediation if meta else ""
        item["auth_mode"] = str(item.get("auth_mode", "anonymous") or "anonymous")
        if with_poc:
            item["poc"] = build_poc(item)
        if any(key in item for key in ("ai_confidence", "ai_reason", "ai_false_positive_likely")):
            item["ai_confidence"] = str(item.get("ai_confidence", "") or "")
            item["ai_reason"] = str(item.get("ai_reason", "") or "")
            item["ai_false_positive_likely"] = bool(item.get("ai_false_positive_likely"))
        if "verified_credentials" in item:
            item["verified_credentials"] = _normalize_credentials(item.get("verified_credentials"))
        enriched.append(item)
    return enriched


def _normalize_credentials(value) -> List[Dict]:
    """把识别出的凭据列表规整成模板可安全渲染的形式。

    一个文件可能同时泄露多种凭据，因此这里是列表而不是单条。
    """
    if not isinstance(value, list):
        return []
    normalized = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        credential_type = str(entry.get("type", "") or "")
        if not credential_type:
            continue
        normalized.append({
            "type": credential_type,
            "looks_live": bool(entry.get("looks_live")),
            "confidence": str(entry.get("confidence", "") or ""),
            "impact": str(entry.get("impact", "") or ""),
        })
    return normalized


def normalize_ai_summary(ai_summary) -> Optional[Dict]:
    """把模型返回的摘要规整成模板可安全渲染的结构。

    模型输出属于不可信输入，字段缺失或类型不符时一律降级为空值，避免渲染报错。
    """
    if not isinstance(ai_summary, dict):
        return None

    def _text(key: str) -> str:
        value = ai_summary.get(key, "")
        return value if isinstance(value, str) else ""

    def _items(key: str, keys: tuple) -> List[Dict]:
        raw = ai_summary.get(key)
        if not isinstance(raw, list):
            return []
        items = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            normalized = {k: (entry.get(k) if isinstance(entry.get(k), (str, int)) else "") for k in keys}
            items.append(normalized)
        return items

    summary = {
        "executive_summary": _text("executive_summary"),
        "notes": _text("notes"),
        "top_risks": _items("top_risks", ("risk_id", "why_it_matters", "priority")),
        "remediation_plan": _items("remediation_plan", ("step", "detail")),
        "disclaimer": AI_DISCLAIMER,
    }
    if not (summary["executive_summary"] or summary["top_risks"] or summary["remediation_plan"]):
        return None
    return summary


def summarize(results: List[Dict]) -> Dict:
    """按严重度统计，用于终端摘要与报告的概览区。"""
    counts = {name: 0 for name in SEVERITY_ORDER}
    for result in results:
        severity = str(result.get("severity", ""))
        if severity in counts:
            counts[severity] += 1
    counts["TOTAL"] = len(results)
    return counts


def render_ai_text(ai_summary: Optional[Dict]) -> str:
    """把 AI 摘要渲染成终端可读文本。"""
    summary = normalize_ai_summary(ai_summary)
    if not summary:
        return ""

    lines = ["=" * 30 + " AI 研判 " + "=" * 30, f"（{AI_DISCLAIMER}）"]
    if summary["executive_summary"]:
        lines.append("")
        lines.append(f"执行摘要: {summary['executive_summary']}")
    if summary["top_risks"]:
        lines.append("")
        lines.append("风险优先级:")
        for entry in summary["top_risks"]:
            priority = entry.get("priority", "")
            prefix = f"{priority}. " if priority != "" else "- "
            lines.append(f"  {prefix}{entry.get('risk_id', '')} — {entry.get('why_it_matters', '')}")
    if summary["remediation_plan"]:
        lines.append("")
        lines.append("修复计划:")
        for step_index, entry in enumerate(summary["remediation_plan"], 1):
            detail = entry.get("detail", "")
            lines.append(f"  {step_index}. {entry.get('step', '')}")
            if detail:
                lines.append(f"     {detail}")
    if summary["notes"]:
        lines.append("")
        lines.append(f"备注: {summary['notes']}")
    lines.append("=" * 72)
    return "\n".join(lines)


def _finding_line(item: Dict) -> str:
    auth_tag = " [认证态]" if item.get("auth_mode") == "authenticated" else ""
    line = (f"[{item.get('severity_label', '')}] {item.get('title', '')}: "
            f"{item.get('msg', '')}{auth_tag}")
    annotations = []
    for credential in item.get("verified_credentials") or []:
        marker = "疑似可用" if credential["looks_live"] else "疑似占位"
        annotations.append(f"凭据 {credential['type']}（{marker}，置信度 {credential['confidence']}）")
    if item.get("ai_confidence"):
        annotations.append(f"AI 置信度 {item['ai_confidence']}")
    if item.get("ai_false_positive_likely"):
        annotations.append("AI 判断可能为误报")
    if annotations:
        line += "  <" + "；".join(annotations) + ">"
    if item.get("poc"):
        line += f"\n    PoC: {item['poc']}"
    return line


def generate_report(results: List[Dict], output_format: str, config: Dict,
                    ai_summary: Optional[Dict] = None,
                    with_poc: bool = True) -> str:
    """生成扫描报告。

    JSON 输出保持「结果数组」结构不变，AI 结论以每条结果上的字段形式呈现，
    以便 jq / CI 继续按数组消费；叙述性摘要只进入 HTML 与 text。
    """
    enriched = enrich_results(results, with_poc=with_poc)
    summary = summarize(enriched)

    if output_format == "json":
        return json.dumps(enriched, ensure_ascii=False, indent=2)

    if output_format == "html":
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as handle:
            # autoescape 必须开启：证据来源于被测目标，属不可信内容
            template = Template(handle.read(), autoescape=True)
        return template.render(results=enriched, summary=summary, config=config,
                               ai=normalize_ai_summary(ai_summary),
                               auth_mode=report_auth_mode(enriched))

    lines = []
    ai_text = render_ai_text(ai_summary)
    if ai_text:
        lines.append(ai_text)
        lines.append("")
    for item in enriched:
        lines.append(_finding_line(item))
    lines.append("")
    lines.append(
        "合计 {total} 项（严重 {critical} / 高危 {high} / 中危 {medium} / "
        "低危 {low} / 信息 {info} / 错误 {error}）".format(
            total=summary["TOTAL"],
            critical=summary["CRITICAL"],
            high=summary["HIGH"],
            medium=summary["MEDIUM"],
            low=summary["LOW"],
            info=summary["INFO"],
            error=summary["ERROR"],
        )
    )
    return "\n".join(lines)


def report_auth_mode(results: List[Dict]) -> str:
    """报告整体使用的扫描身份：任意一条结果来自认证请求即为认证态。"""
    if any(item.get("auth_mode") == "authenticated" for item in results):
        return "authenticated"
    return "anonymous"
