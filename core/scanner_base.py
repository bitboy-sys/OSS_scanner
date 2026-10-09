"""扫描器基类：共享扫描流水线 + 声明式厂商规格。

设计要点：

* :class:`ProviderSpec` 把各厂商的差异（Action 前缀、XML 标记、ACL 授权项
  标记、日志路径、附加请求头等）收敛成一份声明，通用扫描逻辑只在基类实现一次。
* 每条结果都带完整证据字段（状态码、Content-Type、响应体片段）与 ``auth_mode``
  （本次请求是匿名还是携带临时凭证发出），报告与 AI 研判都依赖这些字段。
* ``allow_intrusive_write`` 是控制所有写操作（PUT/POST/DELETE/ACL）的总闸门，
  默认关闭，避免在授权范围外修改目标桶。
* 提供临时凭证（STS）时，全部请求按厂商规则签名，认证态才能看到的配置
  （如 ACL 授权项、版本历史）才会被检测。
"""
import json
import uuid
from abc import ABC
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from core.risk_analyzer import RISK_META, Risk
from utils.credentials import TemporaryCredential
from utils.http_utils import DEFAULT_USER_AGENT, request_url
from utils.log_utils import logger
from utils.signing import sign_request

EVIDENCE_LIMIT = 8192
PROBE_WORKERS = 4

# 敏感路径分组 → 命中后的风险项
SENSITIVE_KEY_GROUPS: Tuple[Tuple[str, Risk], ...] = (
    ("key_paths", Risk.KEY_FILE_EXPOSED),
    ("db_paths", Risk.DB_BACKUP_EXPOSED),
    ("config_paths", Risk.CONFIG_FILE_EXPOSED),
    ("log_paths", Risk.OTHER_FILE_EXPOSED),
    ("src_paths", Risk.OTHER_FILE_EXPOSED),
)


@dataclass(frozen=True)
class ProviderSpec:
    """单个云厂商的差异声明。"""

    name: str
    display_name: str
    action_prefix: str
    list_element: str
    log_paths: Tuple[str, ...] = ()
    # 列目录检测尝试的查询串形式，第一个通常为空（裸根路径）
    list_queries: Tuple[str, ...] = ("", "?delimiter=/&max-keys=10")
    sse_element: str = "ServerSideEncryptionConfiguration"
    kms_key_field: str = "KMSMasterKeyID"
    custom_key_hint: str = "byok"
    meta_header_prefixes: Tuple[str, ...] = ()
    exists_status: Tuple[int, ...] = (200, 403, 302)
    extra_headers: Dict[str, str] = field(default_factory=dict)
    # 区域自动发现
    region_header: str = ""
    # ACL 授权项标记（子串匹配，响应体已被截断到安全长度）
    acl_public_markers: Tuple[str, ...] = ()
    acl_authenticated_markers: Tuple[str, ...] = ()
    # 是否支持读取防盗链配置
    supports_referer: bool = False

    @property
    def auth_mode(self) -> str:
        return "authenticated" if self.name else "anonymous"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_finding(risk: Risk, msg: str, url: str, bucket: str = "",
                  cloud: str = "", region: str = "",
                  resp: Optional[Dict] = None, evidence_limit: int = EVIDENCE_LIMIT,
                  auth_mode: str = "anonymous", **extra) -> Dict:
    """构造一条带完整证据的扫描结果。

    独立成模块级函数，便于扫描器之外的地方（例如 main 的失败兜底）产出
    结构一致的结果。
    """
    meta = RISK_META[risk]
    finding = {
        "risk_id": risk.value,
        "severity": meta.severity.name,
        "title": meta.title,
        "msg": msg,
        "url": url,
        "bucket": bucket,
        "cloud": cloud,
        "region": region,
        "auth_mode": auth_mode,
        "status_code": None,
        "content_type": "",
        "content_length": 0,
        "evidence": "",
        "evidence_truncated": False,
        "timestamp": _now_iso(),
    }
    if resp is not None:
        finding.update({
            "status_code": resp.get("status_code"),
            "content_type": resp.get("content_type", ""),
            "content_length": resp.get("content_length", 0) or 0,
            "evidence": (resp.get("content") or "").strip()[:evidence_limit],
            "evidence_truncated": bool(resp.get("body_truncated")),
        })
    finding.update(extra)
    return finding


def _policy_verbatim(doc: dict) -> List[dict]:
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [st for st in statements if isinstance(st, dict)]
    return []


def _policy_allows_anonymous(content: str) -> bool:
    """判断策略是否对匿名主体授予 Allow。

    优先按 JSON 解析；策略有时以内嵌转义形式出现在 HTML 里，此时退回
    字符串匹配。
    """
    if not content:
        return False
    try:
        doc = json.loads(content)
    except (ValueError, TypeError):
        unescaped = content.replace('\\"', '"')
        return '"Effect": "Allow' in unescaped and '"Principal": "*' in unescaped

    if not isinstance(doc, dict):
        return False
    for statement in _policy_verbatim(doc):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict) and "*" in principal.values():
            return True
    return False


# ACL 里的通用公开/已认证授权标记。无论识别成哪个厂商都检查这些信号，
# 避免因为厂商判断偏差而漏掉真实的过宽授权。
UNIVERSAL_PUBLIC_GRANT_MARKERS = (
    "AllUsers",
    "anyone:anyone",
    "<Grant>public-read</Grant>",
    "<Grant>public-read-write</Grant>",
)
UNIVERSAL_AUTHENTICATED_GRANT_MARKERS = (
    "AuthenticatedUsers",
    "AllAuthenticatedUsers",
)


def _acl_grants(content: str, spec: ProviderSpec) -> Tuple[bool, bool]:
    """从 ACL 响应里判断是否授予了公共 / 任意已认证用户权限。

    刻意用子串匹配而不是 XML 解析：响应体来自不可信目标，已截断到
    ``EVIDENCE_LIMIT``，避免引入 XML 实体展开类风险。
    """
    if not content:
        return False, False
    public_markers = set(UNIVERSAL_PUBLIC_GRANT_MARKERS) | set(spec.acl_public_markers)
    auth_markers = set(UNIVERSAL_AUTHENTICATED_GRANT_MARKERS) | set(spec.acl_authenticated_markers)
    public = any(marker in content for marker in public_markers)
    authenticated = any(marker in content for marker in auth_markers)
    return public, authenticated


def _version_history(content: str) -> Tuple[bool, List[str]]:
    """判断对象是否存在历史版本，返回 (有历史版本, 非当前版本 ID 列表)。"""
    if not content or "<Version" not in content:
        return False, []
    version_ids: List[str] = []
    for chunk in content.split("<Version>")[1:]:
        version_id = ""
        if "<VersionId>" in chunk:
            version_id = chunk.split("<VersionId>", 1)[1].split("</VersionId>", 1)[0].strip()
        # IsLatest 为 true 的条目对当前对象没有额外暴露
        is_latest = "<IsLatest>true</IsLatest>" in chunk
        if version_id and not is_latest:
            version_ids.append(version_id)
    has_delete_marker = "<DeleteMarker>" in content
    return bool(version_ids) or has_delete_marker, version_ids


class ScannerBase(ABC):
    """所有云厂商扫描器的基类。"""

    spec: ProviderSpec

    def __init__(self, bucket: str, region: str, config: Dict,
                 credential: Optional[TemporaryCredential] = None):
        self.bucket = bucket
        self.region = region
        self.config = config
        self.credential = credential
        self.results: List[Dict] = []
        self.sensitive_paths = self._parse_sensitive_paths()
        self.intrusive_enabled = bool(config.get("allow_intrusive_write", False))
        # 启用 AI 内容分级时会调高，以便在更长的片段里找凭据
        self.evidence_limit = int(config.get("evidence_limit", EVIDENCE_LIMIT))
        self.base_urls = self._build_base_urls()
        self._active_base_url: Optional[str] = None
        self._cors_reported = False

    @property
    def auth_mode(self) -> str:
        """本次扫描的请求身份。"""
        return "authenticated" if self.credential else "anonymous"

    # ------------------------------------------------------------------ 配置

    def _parse_sensitive_paths(self) -> List[Tuple[str, Risk]]:
        """把 [SENSITIVE_PATHS] 解析成「路径 → 风险项」列表。

        每个条目单独 strip，因此配置里用 ", " 分隔不会导致除首个条目外的
        路径全部落到兜底等级。
        """
        groups = self.config.get("SENSITIVE_PATHS", {})
        ordered: List[Tuple[str, Risk]] = []
        seen = set()
        for key, risk in SENSITIVE_KEY_GROUPS:
            for entry in str(groups.get(key, "")).split(","):
                path = entry.strip()
                if path and path not in seen:
                    seen.add(path)
                    ordered.append((path, risk))
        return ordered

    def _templates(self) -> List[str]:
        """返回该厂商的 https 形式 URL 模板，由子类实现。"""
        raise NotImplementedError

    def _build_base_urls(self) -> List[str]:
        """HTTPS 优先展开模板；``https_only`` 为真时不产出明文 URL。"""
        templates = [t for t in self._templates() if t]
        urls = list(templates)
        if not self.config.get("https_only", False):
            for tpl in templates:
                if tpl.startswith("https://"):
                    urls.append("http://" + tpl[len("https://"):])
        return list(dict.fromkeys(urls))

    def target_urls(self) -> List[str]:
        """扫描用的基础 URL。

        一旦确认了可用地址就只返回它，避免对每个路径重复探测 HTTP 与 HTTPS
        两份（此前单桶 42 次请求里有一半是冗余的）。
        """
        if self._active_base_url:
            return [self._active_base_url]
        return self.base_urls

    # ------------------------------------------------------------------ 请求

    def _sign(self, method: str, url: str, headers: Dict[str, str],
              data=None) -> Dict[str, str]:
        """有临时凭证时按厂商规则签名。签名失败降级为匿名并记录原因。"""
        if not self.credential:
            return headers
        payload = data.encode("utf-8") if isinstance(data, str) else (data or b"")
        try:
            return sign_request(self.spec.name, self.credential, method, url,
                                headers, payload=payload, region=self.region)
        except ValueError as exc:
            logger.warning(f"[{self.bucket}] 签名失败，该请求降级为匿名: {exc}")
            return headers

    def _request(self, url: str, method: str = "HEAD", **kwargs) -> Dict:
        """带上超时、重试、代理、UA 与签名信息的统一请求入口。"""
        kwargs.setdefault("timeout", self.config.get("request_timeout", 10))
        kwargs.setdefault("retry", self.config.get("max_retry", 2))
        kwargs.setdefault("proxy", self.config.get("proxy"))
        kwargs.setdefault("user_agent", self.config.get("user_agent") or DEFAULT_USER_AGENT)

        headers = dict(kwargs.pop("headers", None) or {})
        extra_headers = dict(self.spec.extra_headers)
        extra_headers.update(headers)
        signed = self._sign(method, url, extra_headers, kwargs.get("data"))
        return request_url(url, method=method, headers=signed or None, **kwargs)

    # ------------------------------------------------------------------ 结果

    def add_finding(self, risk: Risk, msg: str, url: str,
                    resp: Optional[Dict] = None, **extra) -> Dict:
        """构造并记录一条带完整证据的扫描结果。"""
        finding = build_finding(risk, msg, url, bucket=self.bucket,
                                cloud=self.spec.name, region=self.region,
                                resp=resp, evidence_limit=self.evidence_limit,
                                auth_mode=self.auth_mode, **extra)
        self.results.append(finding)
        return finding

    # ------------------------------------------------------------ 存在性与闸门

    def check_bucket_exist(self) -> bool:
        """逐个候选地址探测，任一地址确认存在即通过。

        遇到 404 只跳过当前地址而不是直接判定不存在——否则 HTTP 返回 404
        而 HTTPS 正常时会被误报为「Bucket 不存在」。
        """
        for base_url in self.base_urls:
            resp = self._request(base_url, method="HEAD")
            code = resp["status_code"]
            if code in self.spec.exists_status:
                self._active_base_url = base_url
                logger.info(f"[{self.bucket}] 使用基础地址: {base_url}（HTTP {code}）")
                self._discover_region(resp)
                return True
            if code == 404:
                logger.debug(f"[{self.bucket}] {base_url} 返回 404，尝试下一个地址")
                continue
            logger.debug(f"[{self.bucket}] {base_url} 返回 {code}，尝试下一个地址")
        return False

    def _discover_region(self, resp: Dict) -> None:
        """从响应头或错误体里校正区域。

        传错区域时各厂商都会在响应里留下线索，据此重写 base_urls 再探测一次，
        避免像 ``--region accelerate`` 那样拼出并不存在的域名却一路静默。
        """
        if not self.spec.region_header:
            return
        discovered = (resp.get("headers", {}) or {}).get(self.spec.region_header, "")
        discovered = str(discovered).strip()
        if not discovered or discovered == self.region:
            return

        logger.warning(f"[{self.bucket}] 响应头提示实际区域为 {discovered}（当前配置 {self.region}），已自动校正")
        self.region = discovered
        self.base_urls = self._build_base_urls()
        self._active_base_url = None
        self.add_finding(
            Risk.REGION_DISCOVERED,
            f"Bucket 实际区域为 {discovered}，已按该区域重试（原配置 {self.region}）",
            self.base_urls[0] if self.base_urls else "",
            resp=resp,
        )
        if self.check_bucket_exist():
            logger.info(f"[{self.bucket}] 区域校正后已锁定地址: {self._active_base_url}")

    def _intrusive_allowed(self, flag: str) -> bool:
        """写操作需同时满足总闸门与单项开关。"""
        if not self.intrusive_enabled:
            return False
        return bool(self.config.get(flag, False))

    def _warn_blocked(self, flag: str, label: str) -> None:
        if self.config.get(flag, False) and not self.intrusive_enabled:
            logger.warning(
                f"[{self.bucket}] 已跳过「{label}」：该项会写入目标桶，"
                f"需在配置中显式开启 allow_intrusive_write = true"
            )

    # ------------------------------------------------------------ 权限类检查

    def check_bucket_permission(self) -> None:
        """执行权限与配置类检查。"""
        logger.info(f"[{self.bucket}] 开始检测权限与配置（身份：{self.auth_mode}）")
        self._warn_blocked("scan_put_upload", "匿名 PUT 上传")
        self._warn_blocked("scan_post_upload", "匿名 POST 上传")
        self._warn_blocked("scan_delete_perm", "匿名 DELETE")

        self._check_list_permission()
        if self._intrusive_allowed("scan_put_upload"):
            self._check_anonymous_upload()
        if self._intrusive_allowed("scan_post_upload"):
            self._check_post_upload()
        if self._intrusive_allowed("scan_delete_perm"):
            self._check_delete_permission()
        if self.config.get("scan_cors", False):
            self._check_cors()
        if self.config.get("scan_directory_traversal", False):
            self._check_directory_traversal()
        if self.config.get("scan_sensitive_headers", False):
            self._check_sensitive_headers()
        logger.info(f"[{self.bucket}] 权限与配置检测完成")

    def _check_list_permission(self) -> None:
        """检测是否允许列目录。"""
        for base_url in self.target_urls():
            for query in self.spec.list_queries:
                list_url = f"{base_url}/{query}"
                resp = self._request(list_url, method="GET")
                if resp["status_code"] == 200 and self.spec.list_element in resp.get("content", ""):
                    self.add_finding(
                        Risk.PUBLIC_LIST,
                        f"Bucket 可列出对象清单: {list_url}",
                        list_url,
                        resp=resp,
                    )
                    return

    def _check_anonymous_upload(self) -> None:
        """检测是否允许匿名 PUT 上传。"""
        test_file = f"oss_scan_test_{uuid.uuid4()}.txt"
        for base_url in self.target_urls():
            upload_url = f"{base_url}/{test_file}"
            resp = self._request(upload_url, method="PUT", data="oss_scan_test_content", retry=1)
            if resp["status_code"] in (200, 201):
                self._request(upload_url, method="DELETE", timeout=5)
                self.add_finding(
                    Risk.ANON_WRITE_PUT,
                    f"Bucket 允许 PUT 上传: {upload_url}",
                    upload_url,
                    resp=resp,
                )
                return

    def _check_post_upload(self) -> None:
        """检测是否允许匿名 POST 表单上传。"""
        test_file = f"oss_scan_test_{uuid.uuid4()}.txt"
        for base_url in self.target_urls():
            upload_url = f"{base_url}/"
            files = {"file": (test_file, "oss_scan_test_content", "text/plain")}
            resp = self._request(upload_url, method="POST", files=files, retry=1)
            if resp["status_code"] in (200, 201):
                self._request(f"{base_url}/{test_file}", method="DELETE", timeout=5)
                self.add_finding(
                    Risk.ANON_WRITE_POST,
                    f"Bucket 允许 POST 表单上传: {upload_url}",
                    upload_url,
                    resp=resp,
                )
                return

    def _check_delete_permission(self) -> None:
        """检测是否允许匿名 DELETE 对象。"""
        test_file = f"oss_scan_test_{uuid.uuid4()}.txt"
        for base_url in self.target_urls():
            file_url = f"{base_url}/{test_file}"
            upload_resp = self._request(file_url, method="PUT", data="test", retry=1)
            if upload_resp["status_code"] not in (200, 201):
                continue
            delete_resp = self._request(file_url, method="DELETE")
            if delete_resp["status_code"] in (200, 204):
                self.add_finding(
                    Risk.ANON_DELETE,
                    f"Bucket 允许 DELETE 对象: {file_url}",
                    file_url,
                    resp=delete_resp,
                )
                return

    def _check_cors(self) -> None:
        """检测 CORS 是否同时放开任意来源与写方法。"""
        for base_url in self.target_urls():
            resp = self._request(base_url, method="OPTIONS",
                                 headers={"Origin": "https://example.com",
                                          "Access-Control-Request-Method": "PUT"})
            headers = resp.get("headers", {})
            allow_origin = headers.get("Access-Control-Allow-Origin", "")
            allow_methods = headers.get("Access-Control-Allow-Methods", "")
            if allow_origin == "*" and ("PUT" in allow_methods or "POST" in allow_methods):
                self.add_finding(
                    Risk.CORS_WILDCARD,
                    f"Bucket CORS 过度宽松（任意来源 + 允许上传方法）: {base_url}",
                    base_url,
                    resp=resp,
                )
                self._cors_reported = True
                return

    def _check_directory_traversal(self) -> None:
        """检测是否存在目录遍历式访问。"""
        test_paths = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "../windows/system32/drivers/etc/hosts",
            "../secret.txt",
        ]
        for path in test_paths:
            for base_url in self.target_urls():
                traversal_url = f"{base_url}/{path}"
                resp = self._request(traversal_url, method="GET", retry=1)
                if resp["status_code"] == 200 and "root:" in resp.get("content", ""):
                    self.add_finding(
                        Risk.DIRECTORY_TRAVERSAL,
                        f"目录遍历可读取系统文件: {traversal_url}",
                        traversal_url,
                        resp=resp,
                    )
                    return

    def _check_sensitive_headers(self) -> None:
        """检测响应头是否回显存储元信息。"""
        prefixes = self.spec.meta_header_prefixes
        if not prefixes:
            return
        for base_url in self.target_urls():
            resp = self._request(base_url, method="HEAD", retry=1)
            for header in resp.get("headers", {}):
                if any(header.startswith(prefix) for prefix in prefixes):
                    self.add_finding(
                        Risk.SENSITIVE_HEADERS,
                        f"响应头泄露存储元信息（{header}）: {base_url}",
                        base_url,
                        resp=resp,
                    )
                    return

    # ------------------------------------------------------------ 通用文件检查

    def scan_sensitive_files(self) -> None:
        """并发探测敏感路径，直接取回受限长度的响应体作为证据。

        这里用一次受限 GET 同时完成「存在性判定」与「证据采集」，而不是先
        HEAD 再 GET：后者在 HEAD 与 GET 结果不一致时（对象存储对不存在的 key
        也可能返回 200 的错误页）会得到自相矛盾的结论，例如状态码 404 却仍
        被记为可匿名访问。
        """
        targets = self.target_urls()
        if not targets or not self.sensitive_paths:
            return

        def probe(item: Tuple[str, Risk]) -> Optional[Dict]:
            path, risk = item
            for base_url in targets:
                file_url = f"{base_url}/{path}"
                resp = self._request(file_url, method="GET", max_body=self.evidence_limit)
                if not resp["accessible"]:
                    continue
                size_mb = resp["content_length"] / 1024 / 1024
                return self.add_finding(
                    risk,
                    f"发现可访问文件: {path} | 大小: {size_mb:.2f}MB",
                    file_url,
                    resp=resp,
                )
            return None

        workers = min(PROBE_WORKERS, len(self.sensitive_paths))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # 按原顺序消费，保证报告条目顺序稳定
            list(pool.map(probe, self.sensitive_paths))

    def scan_access_logs(self) -> None:
        """检测厂商常见的访问日志路径。"""
        for path in self.spec.log_paths:
            for base_url in self.target_urls():
                log_url = f"{base_url}{path}"
                resp = self._request(log_url, method="HEAD")
                if resp["accessible"]:
                    self.add_finding(
                        Risk.LOG_EXPOSED,
                        f"发现访问日志泄露: {log_url}",
                        log_url,
                        resp=resp,
                    )
                    break

    def scan_bucket_policy(self) -> None:
        """检测 Bucket 策略的匿名授权情况。"""
        prefix = self.spec.action_prefix
        write_actions = ("PutObject", "DeleteObject", "PutObjectAcl")
        for base_url in self.target_urls():
            policy_url = f"{base_url}/?policy"
            resp = self._request(policy_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")

            if _policy_allows_anonymous(content):
                if f"{prefix}GetBucketPolicy" in content:
                    risk = Risk.POLICY_ANON_POLICY_READ
                    detail = "允许匿名读取策略配置"
                elif any(f"{prefix}{action}" in content for action in write_actions):
                    risk = Risk.POLICY_ANON_WRITE
                    detail = "允许匿名写入或删除"
                else:
                    risk = Risk.POLICY_ANON_READ
                    detail = "允许匿名读取"
                self.add_finding(
                    risk,
                    f"{self.spec.display_name} Bucket 策略过度宽松（{detail}）: {policy_url}",
                    policy_url,
                    resp=resp,
                )
            elif "AdministratorAccess" in content and "Condition" not in content:
                self.add_finding(
                    Risk.POLICY_ADMIN_UNBOUNDED,
                    f"{self.spec.display_name} 策略存在未限制来源的管理员权限: {policy_url}",
                    policy_url,
                    resp=resp,
                )

    def scan_encryption_config(self) -> None:
        """检测服务端加密配置。"""
        for base_url in self.target_urls():
            encryption_url = f"{base_url}/?encryption"
            resp = self._request(encryption_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")

            if self.spec.sse_element not in content:
                self.add_finding(
                    Risk.NO_SSE,
                    f"{self.spec.display_name} Bucket 未启用服务端加密: {encryption_url}",
                    encryption_url,
                    resp=resp,
                )
            elif "KMS" in content and self.spec.kms_key_field in content \
                    and self.spec.custom_key_hint not in content.lower():
                self.add_finding(
                    Risk.ENCRYPTION_NO_CUSTOM_KEY,
                    f"{self.spec.display_name} Bucket 使用 KMS 但未使用自定义主密钥: {encryption_url}",
                    encryption_url,
                    resp=resp,
                )
            elif "AES256" in content and "KMS" not in content:
                self.add_finding(
                    Risk.ENCRYPTION_AES_NOT_KMS,
                    f"{self.spec.display_name} Bucket 使用 AES256 而非 KMS 加密: {encryption_url}",
                    encryption_url,
                    resp=resp,
                )

    # ------------------------------------------------------------ 扩展只读检查

    def scan_bucket_acl(self) -> None:
        """读取 Bucket ACL，识别授予公共 / 任意已认证用户的授权项。"""
        for base_url in self.target_urls():
            acl_url = f"{base_url}/?acl"
            resp = self._request(acl_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")
            public, authenticated = _acl_grants(content, self.spec)
            if public:
                self.add_finding(
                    Risk.ACL_PUBLIC_GRANT,
                    f"Bucket ACL 授予了匿名公共权限: {acl_url}",
                    acl_url,
                    resp=resp,
                )
            if authenticated:
                self.add_finding(
                    Risk.ACL_AUTHENTICATED_GRANT,
                    f"Bucket ACL 授予了任意已认证用户权限: {acl_url}",
                    acl_url,
                    resp=resp,
                )
            return

    def scan_version_history(self) -> None:
        """版本控制检查：旧版本能否被取回，以及是否缺少 MFA 删除保护。

        删除文件并不等于数据消失——开启版本控制后，历史版本仍然可读。
        """
        for base_url in self.target_urls():
            versioning_url = f"{base_url}/?versioning"
            resp = self._request(versioning_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")
            if "Enabled" not in content:
                return

            if "MfaDelete" in content and "Disabled" in content:
                self.add_finding(
                    Risk.VERSIONING_WITHOUT_MFA_DELETE,
                    f"Bucket 开启版本控制但未启用 MFA 删除保护: {versioning_url}",
                    versioning_url,
                    resp=resp,
                )

            # 检查敏感路径是否存在非当前版本（等价于「已删除但仍可取回」）
            for path, _risk in self.sensitive_paths:
                versions_url = f"{base_url}/{path}?versions"
                versions_resp = self._request(versions_url, method="GET",
                                              max_body=self.evidence_limit)
                if versions_resp["status_code"] != 200:
                    continue
                has_history, version_ids = _version_history(versions_resp.get("content", ""))
                if not has_history:
                    continue
                detail = f"，历史版本 ID 示例 {version_ids[0]}" if version_ids else "，含删除标记"
                self.add_finding(
                    Risk.DELETED_OBJECT_RECOVERABLE,
                    f"敏感对象存在历史版本，删除后仍可取回: {path}{detail}",
                    versions_url,
                    resp=versions_resp,
                )
                break
            return

    def scan_website_config(self) -> None:
        """检测是否开启静态网站托管。"""
        for base_url in self.target_urls():
            website_url = f"{base_url}/?website"
            resp = self._request(website_url, method="GET")
            if resp["status_code"] == 200 and "WebsiteConfiguration" in resp.get("content", ""):
                self.add_finding(
                    Risk.STATIC_WEBSITE_ENABLED,
                    f"Bucket 开启了静态网站托管: {website_url}",
                    website_url,
                    resp=resp,
                )
                return

    def scan_referer_config(self) -> None:
        """检测防盗链（Referer 白名单）是否配置。"""
        if not self.spec.supports_referer:
            return
        for base_url in self.target_urls():
            referer_url = f"{base_url}/?referer"
            resp = self._request(referer_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")
            if "RefererList" not in content:
                return
            if "<Referer>" not in content:
                self.add_finding(
                    Risk.REFERER_UNRESTRICTED,
                    f"Bucket 未配置 Referer 白名单，允许任意来源引用: {referer_url}",
                    referer_url,
                    resp=resp,
                )
            return

    def scan_replication_config(self) -> None:
        """检测跨账号/跨桶复制规则——数据会持续流向别处。"""
        for base_url in self.target_urls():
            replication_url = f"{base_url}/?replication"
            resp = self._request(replication_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")
            if "ReplicationConfiguration" not in content:
                return
            self.add_finding(
                Risk.CROSS_ACCOUNT_REPLICATION,
                f"Bucket 配置了复制规则，对象会同步到其他位置，请确认目标可控: {replication_url}",
                replication_url,
                resp=resp,
            )
            return

    def scan_cors_config(self) -> None:
        """读取 CORS 配置。仅当行为探测未命中时作为补充。"""
        if self._cors_reported:
            return
        for base_url in self.target_urls():
            cors_url = f"{base_url}/?cors"
            resp = self._request(cors_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")
            if "CORSConfiguration" not in content:
                return
            if "<AllowedOrigin>*</AllowedOrigin>" in content:
                self.add_finding(
                    Risk.CORS_WILDCARD,
                    f"Bucket CORS 配置允许任意来源: {cors_url}",
                    cors_url,
                    resp=resp,
                )
            return

    # ------------------------------------------------------------ 流水线

    def scan_provider_specific(self) -> None:
        """厂商特有检查的挂载点，默认无操作。"""
        return None

    def scan_extended(self) -> None:
        """只读的扩展检查，按开关逐项启用。"""
        if self.config.get("scan_acl_read", False):
            self.scan_bucket_acl()
        if self.config.get("scan_version_leak", False):
            self.scan_version_history()
        if self.config.get("scan_website", False):
            self.scan_website_config()
        if self.config.get("scan_referer", False):
            self.scan_referer_config()
        if self.config.get("scan_replication", False):
            self.scan_replication_config()
        if self.config.get("scan_cors", False):
            self.scan_cors_config()

    def run_scan(self) -> List[Dict]:
        """执行完整扫描流水线。"""
        self.results = []
        logger.info("=" * 50)
        logger.info(f"[{self.bucket}] 开始扫描（{self.spec.display_name} / 区域 {self.region} / "
                    f"身份 {self.auth_mode}）")

        if not self.check_bucket_exist():
            self.add_finding(
                Risk.BUCKET_NOT_FOUND,
                f"{self.spec.display_name} 目标不存在或无法解析: {self.bucket}",
                self.base_urls[0] if self.base_urls else "",
            )
            logger.warning(f"[{self.bucket}] 未确认目标存在，扫描终止")
            return self.results

        self.check_bucket_permission()
        self.scan_sensitive_files()

        if self.config.get("scan_logs", False):
            self.scan_access_logs()
        if self.config.get("scan_bucket_policy", False):
            self.scan_bucket_policy()
        if self.config.get("scan_kms_encryption", False):
            self.scan_encryption_config()

        self.scan_extended()
        self.scan_provider_specific()

        logger.info(f"[{self.bucket}] 扫描完成，共 {len(self.results)} 个风险项")
        return self.results
