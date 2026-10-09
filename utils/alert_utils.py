"""严重漏洞的外部告警（钉钉 / 邮件）。

结果可能未经报告层富化，因此标题与严重度都在这里从 :data:`RISK_META` 兜底
解析；告警失败只记录日志，不影响扫描结果输出。
"""
import smtplib
from email.mime.text import MIMEText
from typing import Dict, List

import requests

from core.risk_analyzer import RISK_META, Risk
from utils.log_utils import logger


def _format_lines(results: List[Dict]) -> List[str]:
    lines = []
    for result in results:
        title = result.get("title", "")
        if not title:
            try:
                title = RISK_META[Risk(result.get("risk_id", ""))].title
            except (KeyError, ValueError):
                title = result.get("severity", "")
        lines.append(f"- [{title}] {result.get('msg', '')} ({result.get('url', '')})")
    return lines


def send_alert(alert_type: str, results: List[Dict], config: Dict) -> None:
    """按 alert_type 发送告警；配置缺失或发送失败时仅记录日志。"""
    if not results:
        return
    lines = _format_lines(results)
    alert_config = config.get("ALERT_CONFIG", {})

    if alert_type == "dingtalk":
        webhook = alert_config.get("dingtalk_webhook", "")
        if not webhook:
            logger.warning("未配置 dingtalk_webhook，跳过钉钉告警")
            return
        content = "发现严重 OSS 漏洞：\n" + "\n".join(lines)
        try:
            requests.post(
                webhook,
                json={"msgtype": "text", "text": {"content": content}},
                timeout=config.get("request_timeout", 10),
                proxies={"http": config["proxy"], "https": config["proxy"]} if config.get("proxy") else None,
            )
        except requests.exceptions.RequestException as exc:
            logger.error(f"钉钉告警发送失败: {exc}")

    elif alert_type == "email":
        smtp_server = alert_config.get("email_smtp", "")
        user = alert_config.get("email_user", "")
        password = alert_config.get("email_pass", "")
        to_addr = alert_config.get("email_to", "")
        if not (smtp_server and user and password and to_addr):
            logger.warning("邮件告警配置不完整（email_smtp/email_user/email_pass/email_to），跳过")
            return

        message = MIMEText("发现严重 OSS 漏洞：\n" + "\n".join(lines), "plain", "utf-8")
        message["From"] = user
        message["To"] = to_addr
        message["Subject"] = "OSS 存储桶安全告警"
        try:
            with smtplib.SMTP_SSL(smtp_server, 465, timeout=config.get("request_timeout", 10)) as server:
                server.login(user, password)
                server.sendmail(user, to_addr.split(","), message.as_string())
        except (smtplib.SMTPException, OSError) as exc:
            logger.error(f"邮件告警发送失败: {exc}")
