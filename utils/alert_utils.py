from typing import List, Dict
import requests
import smtplib
from email.mime.text import MIMEText

def send_alert(alert_type: str, results: List[Dict], config: Dict) -> None:
    """发送告警"""
    if alert_type == "dingtalk":
        webhook = config["ALERT_CONFIG"].get("dingtalk_webhook", "")
        if not webhook:
            return
        msg = "发现严重OSS漏洞：\n"
        for result in results:
            msg += f"- {result['risk']}: {result['msg']} ({result['url']})\n"
        requests.post(webhook, json={"msgtype": "text", "text": {"content": msg}})
    elif alert_type == "email":
        smtp_server = config["ALERT_CONFIG"].get("email_smtp", "")
        user = config["ALERT_CONFIG"].get("email_user", "")
        password = config["ALERT_CONFIG"].get("email_pass", "")
        to_addr = config["ALERT_CONFIG"].get("email_to", "")
        if not (smtp_server and user and password and to_addr):
            return
        msg = MIMEText("发现严重OSS漏洞：\n" + "\n".join([f"{r['risk']}: {r['msg']} ({r['url']})" for r in results]), "plain", "utf-8")
        msg["From"] = user
        msg["To"] = to_addr
        msg["Subject"] = "OSS存储桶安全告警"
        server = smtplib.SMTP_SSL(smtp_server, 465)
        server.login(user, password)
        server.sendmail(user, to_addr.split(","), msg.as_string())
        server.quit()