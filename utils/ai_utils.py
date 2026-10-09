"""AI 研判能力（可选，默认关闭）。

三条硬约束：

* **不引入新依赖**：只用 ``requests`` 调 OpenAI 兼容的
  ``/chat/completions``，一套代码同时适配本地 Ollama、vLLM 以及
  DeepSeek / 通义 / 智谱 / Kimi 等云端端点。
* **绝不因为 AI 挂了而让扫描失败**：任何一步出错都降级为「无 AI 结论」，
  本地报告照常产出。
* **默认不外发数据**：非本机端点必须显式确认
  （``ack_data_egress = true`` 或 ``--i-accept-ai-egress``），因为这是
  授权渗透工具，把目标地址与泄露内容发给第三方可能超出授权范围。
"""
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from core.risk_analyzer import RISK_META, Risk
from utils.log_utils import logger

PROMPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "prompts")

FEATURE_REPORT = "report"
FEATURE_ANALYZE = "analyze"
FEATURE_CLASSIFY = "classify"
ALL_FEATURES = (FEATURE_REPORT, FEATURE_ANALYZE, FEATURE_CLASSIFY)

# 通用密钥环境变量，优先于各厂商约定变量
GENERIC_API_KEY_ENV = "OSS_SCANNER_AI_KEY"

# 端点预设：配置里写 provider 即可，base_url / model 可被显式配置覆盖。
# 全部走 OpenAI 兼容协议，因此换厂商不需要改代码。
PROVIDER_PRESETS = {
    "ollama": {
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "qwen2.5:7b",
        "api_key_env": "",
        "local": True,
        "label": "本地 Ollama",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "local": False,
        "label": "DeepSeek（深度求索）",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
        "local": False,
        "label": "OpenAI",
    },
    "dashscope": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-plus",
        "api_key_env": "DASHSCOPE_API_KEY",
        "local": False,
        "label": "阿里云百炼 / 通义千问",
    },
    "zhipu": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-4-flash",
        "api_key_env": "ZHIPUAI_API_KEY",
        "local": False,
        "label": "智谱 GLM",
    },
    "moonshot": {
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-8k",
        "api_key_env": "MOONSHOT_API_KEY",
        "local": False,
        "label": "月之暗面 Kimi",
    },
    "siliconflow": {
        "base_url": "https://api.siliconflow.cn/v1",
        "model": "Qwen/Qwen2.5-7B-Instruct",
        "api_key_env": "SILICONFLOW_API_KEY",
        "local": False,
        "label": "硅基流动",
    },
    "custom": {
        "base_url": "",
        "model": "",
        "api_key_env": "",
        "local": False,
        "label": "自定义 OpenAI 兼容端点",
    },
}

DEFAULT_PROVIDER = "ollama"

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


@dataclass(frozen=True)
class _CredentialPattern:
    """凭据形态的识别规则。

    ``keep`` 表示命中内容是**标志性字符串而非秘密本身**（例如私钥头部
    ``-----BEGIN RSA PRIVATE KEY-----``）——这类内容必须原样保留，否则模型
    失去判断依据。``group`` 指定只掩码某个分组，其余部分保持可读。
    """

    label: str
    regex: "re.Pattern"
    keep: bool = False
    group: Optional[str] = None


# 采集到的文件内容里可能出现的凭据形态
_CREDENTIAL_PATTERNS: Tuple[_CredentialPattern, ...] = (
    _CredentialPattern("阿里云 AccessKeyId", re.compile(r"\bLTAI[A-Za-z0-9]{8,}\b")),
    _CredentialPattern("AWS AccessKeyId", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _CredentialPattern("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), keep=True),
    _CredentialPattern("OpenAI 风格密钥", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    _CredentialPattern("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    _CredentialPattern("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    _CredentialPattern("腾讯云 SecretId", re.compile(r"\bAKID[A-Za-z0-9]{16,}\b")),
    # 连接串里的口令：只掩码口令本身，保留 user:****@host 的结构便于判断影响面
    _CredentialPattern("连接串中的口令",
                       re.compile(r"(?<=://)[^:/\s@]+:(?P<secret>[^@/\s]+)(?=@)"),
                       group="secret"),
)


def _mask_match(pattern: _CredentialPattern, match: "re.Match") -> str:
    """按规则生成命中内容的可外发形式。"""
    whole = match.group(0)
    if pattern.keep:
        return whole
    if pattern.group:
        start, end = match.span(pattern.group)
        relative_start = start - match.start()
        relative_end = end - match.start()
        # 口令本身较短，每个字符都有价值，整段掩码
        return whole[:relative_start] + "****" + whole[relative_end:]
    if len(whole) <= 6:
        return "****"
    # 长标识符保留前 4 位，便于人工核对是哪一个密钥，同时不构成可利用泄露
    return whole[:4] + "****"


def mask_secrets(text: str) -> str:
    """把文本中的凭据内容替换为掩码，保留必要的上下文供人工核对。"""
    if not text:
        return ""
    masked = text
    for pattern in _CREDENTIAL_PATTERNS:
        masked = pattern.regex.sub(lambda m, p=pattern: _mask_match(p, m), masked)
    return masked


def find_credentials(text: str) -> List[Dict]:
    """在文本中查找凭据形态的内容，返回类型与可外发的片段。"""
    if not text:
        return []
    hits = []
    seen = set()
    for pattern in _CREDENTIAL_PATTERNS:
        for match in pattern.regex.finditer(text):
            fragment = _mask_match(pattern, match)
            key = (pattern.label, fragment)
            if key in seen:
                continue
            seen.add(key)
            hits.append({"type": pattern.label, "masked": fragment})
    return hits


_BUILTIN_PROMPTS = {
    FEATURE_REPORT: (
        "你是云存储安全评估专家。根据给定的扫描结果，输出一份中文研判报告。"
        "只输出 JSON，不要输出任何解释文字。字段："
        '{"executive_summary": "3 句以内的执行摘要", '
        '"top_risks": [{"risk_id": "...", "why_it_matters": "...", "priority": 1}], '
        '"remediation_plan": [{"step": "...", "detail": "..."}], '
        '"notes": "需要人工确认的事项"}'
        "按业务影响而非仅按严重度排序；不要编造扫描结果里没有的信息。"
    ),
    FEATURE_ANALYZE: (
        "你是云存储漏洞研判专家，负责降低误报。判断每条扫描结果是真的配置缺陷还是误报。"
        "只输出 JSON："
        '{"findings": [{"index": 0, "false_positive_likely": false, '
        '"confidence": "high|medium|low", "reason": "一句话依据"}]}'
        "常见误报：对象存储对不存在的 key 也可能返回 200 的自定义错误页；"
        "单页应用列目录返回的是 HTML 首页；纯静态公开桶的 CORS 允许任意来源属于预期配置；"
        "目录遍历类请求在对象存储上通常不会生效。"
        "判断必须基于给出的状态码、Content-Type 与响应体片段，证据不足时给 low。"
    ),
    FEATURE_CLASSIFY: (
        "你是凭据泄露研判专家。给你的是从疑似泄露文件中截取的、**已掩码**的片段。"
        "判断这些内容属于哪种凭据、是否像真实可用的凭据、以及可能影响什么系统。"
        "只输出 JSON："
        '{"credentials": [{"index": 0, "type": "...", "looks_live": true, '
        '"confidence": "high|medium|low", "impact": "可能影响什么系统"}]}'
        "同一个文件里可能同时存在多种凭据，这时为每种凭据各输出一条，index 都指向该文件。"
        "注意：占位符、示例值、明显的假值（如 changeme、xxx、example）应判为 looks_live=false。"
        "不要试图还原被掩码的内容。"
    ),
}


def _is_local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in _LOCAL_HOSTS or host.endswith(".local")


@dataclass
class AIConfig:
    """[AI_CONFIG] 的归一化视图。"""

    enabled: bool = False
    provider: str = ""
    provider_label: str = ""
    base_url: str = ""
    model: str = ""
    api_key: str = ""
    timeout: int = 60
    max_tokens: int = 2048
    features: Tuple[str, ...] = ()
    redact: bool = True
    cache_path: str = ""
    ack_data_egress: bool = False
    api_key_source: str = ""

    @classmethod
    def from_config(cls, config: Dict, tool_dir: str = "") -> "AIConfig":
        section = config.get("AI_CONFIG", {}) or {}

        def _raw(key: str, default: str = "") -> str:
            value = section.get(key, default)
            return str(value).strip() if value is not None else default

        def _bool(key: str, default: bool = False) -> bool:
            return _raw(key, str(default)).lower() == "true"

        provider = _raw("provider", DEFAULT_PROVIDER).lower() or DEFAULT_PROVIDER
        preset = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["custom"])

        # 显式配置优先，缺省时落到预设
        base_url = _raw("base_url") or preset.get("base_url", "")
        model = _raw("model") or preset.get("model", "")

        api_key, key_source = _resolve_api_key(_raw("api_key"), preset.get("api_key_env", ""))

        features = tuple(
            part.strip().lower()
            for part in _raw("features", "report,analyze,classify").split(",")
            if part.strip()
        )
        cache = _raw("cache", "ai_cache.json")
        if cache and tool_dir and not os.path.isabs(cache):
            cache = os.path.join(tool_dir, cache)

        return cls(
            enabled=_bool("enabled"),
            provider=provider,
            provider_label=preset.get("label", provider),
            base_url=base_url.strip().rstrip("/"),
            model=model,
            api_key=api_key,
            timeout=int(_raw("timeout", "60") or 60),
            max_tokens=int(_raw("max_tokens", "2048") or 2048),
            features=features,
            redact=_bool("redact", True),
            cache_path=cache,
            ack_data_egress=_bool("ack_data_egress"),
            api_key_source=key_source,
        )


def _resolve_api_key(configured: str, preset_env: str) -> Tuple[str, str]:
    """按「配置值 > 通用环境变量 > 厂商约定环境变量」解析密钥。

    密钥放环境变量可以避免在 config.ini 里留明文。
    """
    if configured:
        return configured, "配置文件"
    for env_name in (GENERIC_API_KEY_ENV, preset_env):
        if not env_name:
            continue
        value = (os.environ.get(env_name) or "").strip()
        if value:
            return value, f"环境变量 {env_name}"
    return "", ""


class AIClient:
    """OpenAI 兼容的极简客户端，带缓存与失败降级。"""

    def __init__(self, ai_config: AIConfig, accept_egress: bool = False):
        self.config = ai_config
        self._cache: Dict[str, dict] = {}
        self._cache_loaded = False
        self._disabled_reason: Optional[str] = None
        self._warned = False
        if accept_egress:
            self.config.ack_data_egress = True

    # ------------------------------------------------------------------ 状态

    @property
    def local(self) -> bool:
        return _is_local(self.config.base_url)

    def unavailable_reason(self) -> Optional[str]:
        """返回不可用原因；None 表示可以尝试调用。"""
        if self._disabled_reason:
            return self._disabled_reason
        if not self.config.enabled:
            return "AI 未启用（在配置 [AI_CONFIG] 中设置 enabled = true 可开启，或用 --ai 指定步骤）"
        if not self.config.base_url:
            return "未配置 [AI_CONFIG] base_url"
        if not self.config.model:
            return "未配置 [AI_CONFIG] model"
        if not self.local and not self.config.ack_data_egress:
            return (
                "AI 端点不是本机地址，可能将目标地址与泄露内容发送给第三方。"
                "确认已获授权后，设置 [AI_CONFIG] ack_data_egress = true 或加 --i-accept-ai-egress"
            )
        return None

    def wants(self, feature: str) -> bool:
        return feature in self.config.features

    # ------------------------------------------------------------------ 缓存

    def _load_cache(self) -> None:
        if self._cache_loaded:
            return
        self._cache_loaded = True
        path = self.config.cache_path
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                self._cache = data
        except (OSError, ValueError):
            logger.debug(f"AI 缓存不可用，忽略: {path}")

    def _save_cache(self) -> None:
        path = self.config.cache_path
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self._cache, handle, ensure_ascii=False, indent=2)
        except OSError as exc:
            logger.debug(f"AI 缓存写入失败: {exc}")

    @staticmethod
    def _cache_key(feature: str, system: str, user: str) -> str:
        digest = hashlib.sha256(f"{feature}\x00{system}\x00{user}".encode("utf-8")).hexdigest()
        return digest

    # ------------------------------------------------------------------ 调用

    def chat_json(self, feature: str, user_prompt: str,
                  system_prompt: Optional[str] = None) -> Optional[dict]:
        """请求模型并解析 JSON 结果；任何失败都返回 None。"""
        reason = self.unavailable_reason()
        if reason:
            if not self._warned:
                logger.warning(f"AI 功能不可用：{reason}")
                self._warned = True
            return None

        system = system_prompt or load_prompt(feature)
        key = self._cache_key(feature, system, user_prompt)
        self._load_cache()
        if key in self._cache:
            logger.debug("AI 命中缓存，跳过调用")
            return self._cache[key]

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "max_tokens": self.config.max_tokens,
            "response_format": {"type": "json_object"},
        }
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        url = f"{self.config.base_url}/chat/completions"
        content = self._post_and_extract(url, headers, payload)
        if content is None:
            # 部分端点不认 response_format，去掉后重试一次
            payload.pop("response_format", None)
            content = self._post_and_extract(url, headers, payload)
        if content is None:
            return None

        parsed = _parse_json_object(content)
        if parsed is None:
            logger.warning("AI 返回内容不是合法 JSON，已忽略该结果")
            return None

        self._cache[key] = parsed
        self._save_cache()
        return parsed

    def _post_and_extract(self, url: str, headers: Dict, payload: Dict) -> Optional[str]:
        try:
            response = requests.post(url, headers=headers, json=payload,
                                     timeout=self.config.timeout)
        except requests.exceptions.RequestException as exc:
            self._disabled_reason = f"无法连接 AI 端点 {self.config.base_url}：{exc}"
            logger.warning(self._disabled_reason + "（本次扫描将跳过所有 AI 步骤）")
            return None

        if response.status_code >= 400:
            logger.debug(f"AI 端点返回 HTTP {response.status_code}: {response.text[:200]}")
            return None
        try:
            body = response.json()
            return body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            logger.debug(f"AI 响应结构异常: {exc}")
            return None


def _parse_json_object(content: str) -> Optional[dict]:
    """从模型输出中提取 JSON 对象，容忍 ```json 包裹与前后缀说明。"""
    if not content:
        return None
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        return None


def load_prompt(feature: str) -> str:
    """读取可编辑的提示词；文件缺失时回退到内置版本。"""
    path = os.path.join(PROMPT_DIR, f"{feature}.txt")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read().strip()
        if text:
            return text
    except OSError:
        logger.debug(f"提示词文件不存在，使用内置版本: {path}")
    return _BUILTIN_PROMPTS.get(feature, "")


# ---------------------------------------------------------------------- 脱敏

def redact_url(url: str) -> str:
    """把 URL 主机名中的 Bucket 段替换为短哈希，保留厂商与区域信息。"""
    if not url:
        return ""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return url
    parts = host.split(".")
    if len(parts) > 1:
        digest = hashlib.sha256(parts[0].encode("utf-8")).hexdigest()[:8]
        parts[0] = f"bucket-{digest}"
    netloc = ".".join(parts)
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


def _redact_urls_in(text: str) -> str:
    def _replace(match: "re.Match") -> str:
        return redact_url(match.group(0))
    return re.sub(r"https?://[^\s\"'<>]+", _replace, text)


# ---------------------------------------------------------------------- 研判流程

def _finding_payload(result: Dict, redact: bool) -> Dict:
    url = result.get("url", "")
    if redact:
        url = redact_url(url)
    evidence = mask_secrets(result.get("evidence", ""))[:1024]
    return {
        "index": result.get("_ai_index"),
        "risk_id": result.get("risk_id", ""),
        "severity": result.get("severity", ""),
        "title": result.get("title", ""),
        "msg": mask_secrets(result.get("msg", "")),
        "url": url,
        "status_code": result.get("status_code"),
        "content_type": result.get("content_type", ""),
        "evidence": evidence,
    }


def annotate_false_positives(results: List[Dict], client: AIClient) -> int:
    """误报降噪：为每条结果补充 ai_confidence 与 ai_reason。"""
    actionable = [r for r in results if r.get("severity") not in ("INFO", "ERROR")]
    if not actionable or not client.wants(FEATURE_ANALYZE):
        return 0

    for index, result in enumerate(actionable):
        result["_ai_index"] = index
    payload = {
        "cloud": actionable[0].get("cloud", ""),
        "findings": [_finding_payload(r, client.config.redact) for r in actionable],
    }
    verdict = client.chat_json(FEATURE_ANALYZE, json.dumps(payload, ensure_ascii=False))
    if not verdict:
        return 0

    entries = verdict.get("findings")
    if not isinstance(entries, list):
        return 0

    annotated = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        index = entry.get("index")
        if not isinstance(index, int) or not 0 <= index < len(actionable):
            continue
        result = actionable[index]
        result["ai_confidence"] = str(entry.get("confidence", "") or "")
        result["ai_reason"] = str(entry.get("reason", "") or "")
        result["ai_false_positive_likely"] = bool(entry.get("false_positive_likely"))
        annotated += 1
    return annotated


def classify_exposed_content(results: List[Dict], client: AIClient) -> int:
    """泄露内容分级：本地正则先筛，只把掩码后的片段交给模型判定。

    一个文件里可能同时存在多种凭据（例如 .env 里既有 AccessKey 又有数据库
    口令），因此每条结果上挂的是 ``verified_credentials`` 列表，模型对同一
    文件返回的多条结论都会被保留。
    """
    if not client.wants(FEATURE_CLASSIFY):
        return 0

    candidates = []
    for result in results:
        if result.get("risk_id") not in (
            Risk.KEY_FILE_EXPOSED.value, Risk.DB_BACKUP_EXPOSED.value,
            Risk.CONFIG_FILE_EXPOSED.value, Risk.OTHER_FILE_EXPOSED.value,
        ):
            continue
        evidence = result.get("evidence", "")
        if not evidence:
            continue
        hits = find_credentials(evidence)
        if hits:
            candidates.append((result, hits))

    if not candidates:
        return 0

    payload = {
        "files": [
            {
                "index": index,
                "path": redact_url(result.get("url", "")) if client.config.redact
                        else result.get("url", ""),
                "masked_fragments": hits,
            }
            for index, (result, hits) in enumerate(candidates)
        ]
    }
    verdict = client.chat_json(FEATURE_CLASSIFY, json.dumps(payload, ensure_ascii=False))
    if not verdict:
        return 0

    entries = verdict.get("credentials")
    if not isinstance(entries, list):
        return 0

    annotated = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        index = entry.get("index")
        if not (isinstance(index, int) and 0 <= index < len(candidates)):
            continue
        credential = {
            "type": str(entry.get("type", "") or ""),
            "looks_live": bool(entry.get("looks_live")),
            "confidence": str(entry.get("confidence", "") or ""),
            "impact": str(entry.get("impact", "") or ""),
        }
        if not credential["type"]:
            continue
        result = candidates[index][0]
        result.setdefault("verified_credentials", []).append(credential)
        annotated += 1
    return annotated


def generate_report_summary(results: List[Dict], client: AIClient,
                            context: Optional[Dict] = None) -> Optional[dict]:
    """生成执行摘要、风险排序与修复计划。"""
    if not results or not client.wants(FEATURE_REPORT):
        return None

    severity_counts: Dict[str, int] = {}
    for result in results:
        severity = str(result.get("severity", ""))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    compact = []
    for result in results:
        compact.append({
            "risk_id": result.get("risk_id", ""),
            "severity": result.get("severity", ""),
            "title": result.get("title", ""),
            "msg": mask_secrets(result.get("msg", "")),
            "bucket": result.get("bucket", ""),
            "cloud": result.get("cloud", ""),
            "region": result.get("region", ""),
            "status_code": result.get("status_code"),
            "ai_confidence": result.get("ai_confidence", ""),
        })

    payload = {
        "target": {
            "cloud": (context or {}).get("cloud", ""),
            "region": (context or {}).get("region", ""),
            "bucket_count": (context or {}).get("bucket_count", 0),
        },
        "severity_counts": severity_counts,
        "findings": compact,
    }
    text = json.dumps(payload, ensure_ascii=False)
    if client.config.redact:
        text = _redact_urls_in(text)
    return client.chat_json(FEATURE_REPORT, text)


def apply_ai_passes(results: List[Dict], client: AIClient,
                    context: Optional[Dict] = None) -> Dict:
    """按配置执行各 AI 步骤，返回报告层需要的信息。

    返回形如 ``{"summary": {...}, "annotated": {"analyze": n, "classify": n}}``；
    任何步骤失败都不会影响本地结果。
    """
    outcome: Dict = {"summary": None, "annotated": {"analyze": 0, "classify": 0}}
    reason = client.unavailable_reason()
    if reason:
        logger.warning(f"已跳过 AI 研判：{reason}")
        return outcome

    # 先降噪再分类，摘要最后生成（它可以利用前面的置信度）
    outcome["annotated"]["analyze"] = annotate_false_positives(results, client)
    outcome["annotated"]["classify"] = classify_exposed_content(results, client)
    outcome["summary"] = generate_report_summary(results, client, context)

    for result in results:
        result.pop("_ai_index", None)
    return outcome
