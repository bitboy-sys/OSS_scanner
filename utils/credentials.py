"""临时凭证（STS）的加载、校验与脱敏。

支持四种来源，优先级从高到低：命令行参数 > 环境变量 > 凭证文件 > 配置文件。

安全约定：

* 任何日志、异常与报告里都不得出现 AccessKeySecret 与 SecurityToken；
  :meth:`TemporaryCredential.__repr__` 与 :func:`describe` 只输出掩码后的
  AccessKeyId。
* 加载后立即校验三元组是否齐全——只有 AccessKeyId 而没有 Secret 是无法签名
  的，此时应当明确报错，而不是发出去一堆未签名的请求被静默当成匿名扫描。
"""
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

# 各厂商在请求里携带安全令牌的头名
TOKEN_HEADERS = {
    "aliyun": "x-oss-security-token",
    "aws": "x-amz-security-token",
    "tencent": "x-cos-security-token",
    "huawei": "x-obs-security-token",
    "gcp": "x-goog-security-token",
    "azure": "",  # Azure 用 SAS token，不走 AK/SK
}

# 环境变量名
ENV_ACCESS_KEY_ID = "OSS_SCANNER_STS_AK"
ENV_ACCESS_KEY_SECRET = "OSS_SCANNER_STS_SK"
ENV_SECURITY_TOKEN = "OSS_SCANNER_STS_TOKEN"

DEFAULT_CREDENTIAL_FILE = os.path.join("~", ".oss_scanner", "credentials.json")

# 距过期多久开始提醒（分钟）
EXPIRY_WARN_MINUTES = 10


def mask_value(value: str, keep: int = 4) -> str:
    """把敏感值掩码成前几位 + ****，用于日志与报告。"""
    if not value:
        return ""
    if len(value) <= keep:
        return "****"
    return value[:keep] + "****"


@dataclass(frozen=True)
class TemporaryCredential:
    """一组临时凭证（AK/SK + 安全令牌）。"""

    access_key_id: str
    access_key_secret: str
    security_token: str = ""
    provider: str = ""
    region: str = ""
    expires_at: str = ""
    source: str = ""

    # 刻意避免 dataclass 默认 repr 泄漏密钥
    def __repr__(self) -> str:
        return f"TemporaryCredential(ak={mask_value(self.access_key_id)}, source={self.source!r})"

    __str__ = __repr__

    @property
    def masked_id(self) -> str:
        return mask_value(self.access_key_id)

    @property
    def token_header(self) -> str:
        return TOKEN_HEADERS.get(self.provider, "")

    def expiry_state(self, now: Optional[datetime] = None) -> Optional[str]:
        """返回 ``expired`` / ``expiring`` / ``valid``；未提供过期时间时返回 None。"""
        if not self.expires_at:
            return None
        try:
            expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        if current >= expires:
            return "expired"
        if current >= expires - timedelta(minutes=EXPIRY_WARN_MINUTES):
            return "expiring"
        return "valid"

    def describe(self) -> str:
        """生成可安全写入日志的一句话描述。"""
        parts = [f"AK={self.masked_id}", f"来源={self.source or '未知'}"]
        if self.security_token:
            parts.append("含安全令牌")
        state = self.expiry_state()
        if state == "expired":
            parts.append("!! 已过期")
        elif state == "expiring":
            parts.append(f"即将过期（{self.expires_at}）")
        elif state == "valid":
            parts.append(f"有效期至 {self.expires_at}")
        return "临时凭证：" + "，".join(parts)


def _clean(value) -> str:
    return str(value).strip() if value is not None else ""


def from_mapping(data: Dict, provider: str = "", source: str = "") -> Optional[TemporaryCredential]:
    """从不同厂商的字段命名里提取凭证。

    比对时把字段名统一成小写去下划线的形式，因此 ``AccessKeyId``、
    ``accessKeyId`` 与 ``access_key_id`` 都能识别，覆盖阿里云、AWS SDK
    （``secretAccessKey``/``sessionToken``）、腾讯云
    （``TmpSecretId``/``TmpSecretKey``/``Token``）等写法。
    """
    if not isinstance(data, dict):
        return None

    normalized = {
        str(key).lower().replace("_", "").replace("-", ""): value
        for key, value in data.items()
    }

    def pick(*names) -> str:
        for name in names:
            key = name.lower().replace("_", "").replace("-", "")
            value = _clean(normalized.get(key))
            if value:
                return value
        return ""

    access_key_id = pick("AccessKeyId", "SecretId", "TmpSecretId", "accessKeyId", "ak", "id")
    access_key_secret = pick("AccessKeySecret", "SecretAccessKey", "SecretKey", "TmpSecretKey",
                             "accessKeySecret", "sk", "secret")
    security_token = pick("SecurityToken", "SessionToken", "Token", "stsToken")
    resolved_provider = _clean(normalized.get("provider") or normalized.get("cloud") or provider)
    if not access_key_id or not access_key_secret:
        return None

    return TemporaryCredential(
        access_key_id=access_key_id,
        access_key_secret=access_key_secret,
        security_token=security_token,
        provider=resolved_provider,
        region=_clean(normalized.get("region")),
        expires_at=_clean(normalized.get("expiration")
                          or normalized.get("expiresat")
                          or normalized.get("expires")),
        source=source,
    )


def from_env(provider: str = "") -> Optional[TemporaryCredential]:
    """从环境变量读取，避免在配置文件里留明文。"""
    access_key_id = _clean(os.environ.get(ENV_ACCESS_KEY_ID))
    access_key_secret = _clean(os.environ.get(ENV_ACCESS_KEY_SECRET))
    if not access_key_id or not access_key_secret:
        return None
    return TemporaryCredential(
        access_key_id=access_key_id,
        access_key_secret=access_key_secret,
        security_token=_clean(os.environ.get(ENV_SECURITY_TOKEN)),
        provider=provider,
        source=f"环境变量 {ENV_ACCESS_KEY_ID}",
    )


def from_file(path: str, provider: str = "") -> Optional[TemporaryCredential]:
    """从 JSON 文件读取凭证。

    文件可以是直接的凭据对象，也可以是带 ``Credentials`` 包装的
    AssumeRole 响应原样保存。
    """
    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        return None
    with open(expanded, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    source = f"文件 {expanded}"
    if isinstance(payload, dict) and isinstance(payload.get("Credentials"), dict):
        payload = payload["Credentials"]
    if isinstance(payload, list) and payload:
        payload = payload[0]
    return from_mapping(payload, provider=provider, source=source)


def from_config_section(config: Dict, provider: str = "") -> Optional[TemporaryCredential]:
    """从配置文件的 [STS] 节读取（明文存放，仅建议配合权限受限的本地配置使用）。"""
    section = config.get("STS", {}) or {}
    if not section:
        return None
    return from_mapping(section, provider=provider, source="配置文件 [STS]")


def load_credential(args=None, config: Optional[Dict] = None,
                    provider: str = "") -> Tuple[Optional[TemporaryCredential], Optional[str]]:
    """按优先级加载临时凭证。

    :return: ``(credential, error)``。两者都为 None 表示未配置认证；
        只有 error 表示用户配置了但不完整/不可用。
    """
    config = config or {}

    # 1. 命令行（优先级最高，且允许显式覆盖 provider）
    cli_ak = _clean(getattr(args, "sts_ak", ""))
    cli_sk = _clean(getattr(args, "sts_sk", ""))
    if cli_ak or cli_sk:
        if not (cli_ak and cli_sk):
            return None, "命令行只提供了 AccessKeyId 或 AccessKeySecret 之一，两者需同时提供"
        return TemporaryCredential(
            access_key_id=cli_ak,
            access_key_secret=cli_sk,
            security_token=_clean(getattr(args, "sts_token", "")),
            provider=provider or _clean(getattr(args, "cloud", "")),
            source="命令行参数",
        ), None

    # 2. 环境变量
    credential = from_env(provider)
    if credential:
        return credential, None

    # 3. 凭证文件
    file_path = _clean(getattr(args, "sts_file", "")) or _clean(
        (config.get("STS", {}) or {}).get("credential_file", ""))
    if file_path:
        try:
            credential = from_file(file_path, provider)
        except (OSError, ValueError) as exc:
            return None, f"读取凭证文件失败: {exc}"
        if credential:
            return credential, None
        return None, f"凭证文件中未找到可用的 AccessKeyId/AccessKeySecret: {file_path}"

    # 4. 配置文件
    credential = from_config_section(config, provider)
    if credential:
        return credential, None

    return None, None


def validate_for_scan(credential: Optional[TemporaryCredential], provider: str,
                      require_token: bool = False) -> Optional[str]:
    """返回不适合继续执行的问题描述，None 表示可用。"""
    if credential is None:
        return None
    if provider == "azure":
        return "Azure 不走 AK/SK 临时凭证，请改用 SAS token 或匿名扫描"
    state = credential.expiry_state()
    if state == "expired":
        return f"临时凭证已过期（{credential.expires_at}），请重新获取"
    if require_token and not credential.security_token:
        return "该厂商要求携带安全令牌，但凭证中缺少 SecurityToken"
    return None
