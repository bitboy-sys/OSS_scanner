"""通过 AssumeRole 自动获取临时凭证（STS）。

`utils/credentials.py` 负责**使用**临时凭证，这里负责**换取**：给一组长期
凭证和 RoleArn，调云厂商的 STS 接口换回一组带 SecurityToken 的临时凭证。

已实现 AWS 与阿里云（各自签名方案不同）：

* AWS：``POST https://sts.amazonaws.com/``，SigV4 签名，service 为 ``sts``
* 阿里云：``POST https://sts.aliyuncs.com/``，RPC 风格 HMAC-SHA1 签名

腾讯云（TC3）与华为云暂未实现，会明确提示改用 ``--sts-file`` 直接导入
AssumeRole 的响应，而不是静默失败。
"""
import base64
import hashlib
import hmac
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple
from urllib.parse import quote

import requests

from utils.credentials import (
    ENV_ACCESS_KEY_ID,
    ENV_ACCESS_KEY_SECRET,
    ENV_SECURITY_TOKEN,
    TemporaryCredential,
)
from utils.log_utils import logger
from utils.signing import aws_v4

DEFAULT_ENDPOINTS = {
    "aws": "https://sts.amazonaws.com/",
    "aliyun": "https://sts.aliyuncs.com/",
}

# 各厂商 AssumeRole 所需的版本号
_API_VERSIONS = {"aws": "2011-06-15", "aliyun": "2015-04-01"}

SUPPORTED_ASSUME_ROLE = ("aws", "aliyun")

DEFAULT_SESSION_NAME = "oss-scanner"
DEFAULT_DURATION = 3600


def _session_name(base: str) -> str:
    """会话名需要满足各厂商的字符与长度限制，这里附加时间戳保证可区分。"""
    raw = re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", base or DEFAULT_SESSION_NAME)
    return f"{raw[:32]}-{int(time.time())}"[:64]


# ------------------------------------------------------------------ 阿里云 RPC

def _percent_encode(value: str) -> str:
    """阿里云 RPC 签名要求的编码：在 URL 编码基础上处理 + * ~ 三个字符。"""
    encoded = quote(str(value), safe="")
    return encoded.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _aliyun_rpc_signature(params: Dict[str, str], access_key_secret: str) -> str:
    canonical = "&".join(
        f"{_percent_encode(key)}={_percent_encode(params[key])}"
        for key in sorted(params)
    )
    string_to_sign = f"POST&{_percent_encode('/')}&{_percent_encode(canonical)}"
    digest = hmac.new(f"{access_key_secret}&".encode("utf-8"),
                      string_to_sign.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def _aliyun_assume_role(base: TemporaryCredential, role_arn: str, session_name: str,
                        duration: int, endpoint: str, proxy: Optional[str],
                        timeout: int) -> Tuple[Optional[Dict], Optional[str]]:
    params = {
        "Action": "AssumeRole",
        "Version": _API_VERSIONS["aliyun"],
        "Format": "JSON",
        "AccessKeyId": base.access_key_id,
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": uuid.uuid4().hex,
        "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": str(duration),
    }
    # 用临时凭证去换临时凭证时，必须带上当前令牌
    if base.security_token:
        params["SecurityToken"] = base.security_token
    params["Signature"] = _aliyun_rpc_signature(params, base.access_key_secret)

    try:
        response = requests.post(
            endpoint, data=params, timeout=timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            proxies={"http": proxy, "https": proxy} if proxy else None,
        )
    except requests.exceptions.RequestException as exc:
        return None, f"连接 STS 端点失败: {exc}"

    if response.status_code >= 400:
        return None, f"STS 返回 HTTP {response.status_code}: {response.text[:300]}"
    try:
        payload = response.json()
    except ValueError:
        return None, f"STS 返回内容不是 JSON: {response.text[:300]}"

    credentials = payload.get("Credentials")
    if not isinstance(credentials, dict):
        code = payload.get("Code") or payload.get("Message") or response.text[:200]
        return None, f"STS 未返回凭证: {code}"
    return credentials, None


# --------------------------------------------------------------------- AWS

_AWS_XML_FIELDS = ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")


def _parse_aws_xml(body: str) -> Tuple[Optional[Dict], Optional[str]]:
    """从 AssumeRole 的 XML 响应里取出凭据。

    刻意不用 XML 解析器：只需取几个已知标签，正则更省事也避免了处理不可信
    XML 的额外风险。
    """
    credentials = {}
    for field in _AWS_XML_FIELDS:
        match = re.search(rf"<{field}>(.*?)</{field}>", body, re.DOTALL)
        if match:
            credentials[field] = match.group(1).strip()
    if not credentials.get("AccessKeyId") or not credentials.get("SecretAccessKey"):
        error = re.search(r"<Message>(.*?)</Message>", body, re.DOTALL)
        detail = error.group(1).strip() if error else body[:300]
        return None, f"STS 未返回凭证: {detail}"
    return credentials, None


def _aws_assume_role(base: TemporaryCredential, role_arn: str, session_name: str,
                     duration: int, endpoint: str, proxy: Optional[str],
                     timeout: int) -> Tuple[Optional[Dict], Optional[str]]:
    form = {
        "Action": "AssumeRole",
        "Version": _API_VERSIONS["aws"],
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": str(duration),
    }
    body = "&".join(f"{_percent_encode(k)}={_percent_encode(v)}" for k, v in form.items())

    # STS 全局端点在 us-east-1；此处签名 service 必须为 sts
    headers = aws_v4(base, "POST", endpoint,
                     {"content-type": "application/x-www-form-urlencoded"},
                     payload=body.encode("utf-8"), region="us-east-1", service="sts")
    headers.pop("host", None)  # host 由 requests 自己设置

    try:
        response = requests.post(
            endpoint, data=body, timeout=timeout, headers=headers,
            proxies={"http": proxy, "https": proxy} if proxy else None,
        )
    except requests.exceptions.RequestException as exc:
        return None, f"连接 STS 端点失败: {exc}"

    if response.status_code >= 400:
        return None, f"STS 返回 HTTP {response.status_code}: {response.text[:300]}"
    return _parse_aws_xml(response.text)


# ------------------------------------------------------------------ 对外接口

def assume_role(provider: str, base: TemporaryCredential, role_arn: str,
                session_name: str = "", duration: int = DEFAULT_DURATION,
                endpoint: str = "", proxy: Optional[str] = None,
                timeout: int = 15) -> Tuple[Optional[TemporaryCredential], Optional[str]]:
    """用长期凭证换取临时凭证。

    :return: ``(credential, error)``；成功时 error 为 None。
    """
    if provider not in SUPPORTED_ASSUME_ROLE:
        return None, (f"{provider} 的 AssumeRole 尚未实现签名方案，"
                      f"可改用 --sts-file 直接导入 AssumeRole 响应（当前支持: "
                      f"{'、'.join(SUPPORTED_ASSUME_ROLE)}）")
    if not role_arn:
        return None, "缺少 RoleArn"

    resolved_endpoint = endpoint or DEFAULT_ENDPOINTS[provider]
    name = _session_name(session_name)
    logger.info(f"正在向 {provider} STS 申请临时凭证：Role={role_arn} 会话={name} 有效期={duration}s")

    if provider == "aws":
        raw, error = _aws_assume_role(base, role_arn, name, duration,
                                     resolved_endpoint, proxy, timeout)
    else:
        raw, error = _aliyun_assume_role(base, role_arn, name, duration,
                                         resolved_endpoint, proxy, timeout)

    if error:
        return None, error

    credential = TemporaryCredential(
        access_key_id=str(raw.get("AccessKeyId", "")).strip(),
        access_key_secret=str(raw.get("AccessKeySecret") or raw.get("SecretAccessKey", "")).strip(),
        security_token=str(raw.get("SecurityToken") or raw.get("SessionToken", "")).strip(),
        provider=provider,
        expires_at=str(raw.get("Expiration", "")).strip(),
        source=f"STS AssumeRole（{role_arn}）",
    )
    if not credential.access_key_id or not credential.access_key_secret:
        return None, "STS 返回的凭证缺少 AccessKeyId 或 AccessKeySecret"
    if not credential.security_token:
        return None, "STS 返回的凭证缺少 SecurityToken，无法用于临时凭证认证"

    # 防御性兜底：部分实现不返回 Expiration，此时按申请时长估算，便于提前告警
    if not credential.expires_at:
        credential = TemporaryCredential(
            access_key_id=credential.access_key_id,
            access_key_secret=credential.access_key_secret,
            security_token=credential.security_token,
            provider=provider,
            expires_at=(datetime.now(timezone.utc) + timedelta(seconds=duration))
            .isoformat(timespec="seconds"),
            source=credential.source,
        )
    return credential, None


def load_base_credential(args=None, config: Optional[Dict] = None,
                         provider: str = "") -> Tuple[Optional[TemporaryCredential], Optional[str]]:
    """加载用于换取临时凭证的长期凭证。

    只认 AssumeRole 专用来源，避免和「直接使用临时凭证」的参数混淆。
    找不到长期凭证时会退回通用的 ``OSS_SCANNER_STS_*``，方便用临时凭证
    再换一次临时凭证的场景。
    """
    def _clean(value) -> str:
        return str(value).strip() if value else ""

    cli_ak = _clean(getattr(args, "role_ak", ""))
    cli_sk = _clean(getattr(args, "role_sk", ""))
    if cli_ak or cli_sk:
        if not (cli_ak and cli_sk):
            return None, "换取临时凭证需要同时提供 --role-ak 与 --role-sk"
        return TemporaryCredential(cli_ak, cli_sk, provider=provider,
                                   source="命令行角色凭证"), None

    for env_ak, env_sk, env_token in (
        ("OSS_SCANNER_ROLE_AK", "OSS_SCANNER_ROLE_SK", "OSS_SCANNER_ROLE_TOKEN"),
        (ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET, ENV_SECURITY_TOKEN),
    ):
        ak = _clean(os.environ.get(env_ak))
        sk = _clean(os.environ.get(env_sk))
        if ak and sk:
            return TemporaryCredential(ak, sk, _clean(os.environ.get(env_token)),
                                       provider=provider,
                                       source=f"环境变量 {env_ak}"), None

    section = (config or {}).get("STS", {}) or {}
    ak = _clean(section.get("role_ak")) or _clean(section.get("access_key_id"))
    sk = _clean(section.get("role_sk")) or _clean(section.get("access_key_secret"))
    if ak and sk:
        return TemporaryCredential(ak, sk, _clean(section.get("security_token")),
                                   provider=provider, source="配置文件 [STS]"), None

    return None, ("已指定 RoleArn 但未找到用于换取凭证的长期凭证，"
                  "请提供 --role-ak/--role-sk 或设置环境变量 OSS_SCANNER_ROLE_AK/OSS_SCANNER_ROLE_SK")
