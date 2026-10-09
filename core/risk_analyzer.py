"""风险等级与元数据。

每个 :class:`Risk` 成员代表**一个明确含义**，并继承 ``str`` 以便直接做 JSON
序列化。严重度、中文标题、修复建议、合规映射统一放在 :data:`RISK_META`，
报告、终端摘要、AI 研判、SARIF 输出都从这张表取，避免同一等级在不同代码
位置被赋予不同含义。
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict


class Severity(Enum):
    """风险严重度，用于报告配色、排序与统计。"""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0
    ERROR = -1

    @property
    def label(self) -> str:
        """中文标签，用于终端摘要与报告。"""
        return _SEVERITY_LABEL[self]

    def __str__(self) -> str:
        return self.name


_SEVERITY_LABEL = {
    Severity.CRITICAL: "严重",
    Severity.HIGH: "高危",
    Severity.MEDIUM: "中危",
    Severity.LOW: "低危",
    Severity.INFO: "信息",
    Severity.ERROR: "错误",
}


class Risk(str, Enum):
    """扫描项标识。值即稳定 ID，可直接写入 JSON/SARIF 报告。"""

    # ---- 严重：数据或权限已直接失控 ----
    KEY_FILE_EXPOSED = "KEY_FILE_EXPOSED"
    DB_BACKUP_EXPOSED = "DB_BACKUP_EXPOSED"
    ANON_WRITE_PUT = "ANON_WRITE_PUT"
    ANON_WRITE_POST = "ANON_WRITE_POST"
    ANON_DELETE = "ANON_DELETE"
    POLICY_ANON_WRITE = "POLICY_ANON_WRITE"

    # ---- 高危 ----
    PUBLIC_LIST = "PUBLIC_LIST"
    LOG_EXPOSED = "LOG_EXPOSED"
    ACL_WRITABLE = "ACL_WRITABLE"
    ACL_PUBLIC_GRANT = "ACL_PUBLIC_GRANT"
    ACL_AUTHENTICATED_GRANT = "ACL_AUTHENTICATED_GRANT"
    POLICY_ANON_READ = "POLICY_ANON_READ"
    POLICY_ANON_POLICY_READ = "POLICY_ANON_POLICY_READ"
    POLICY_ADMIN_UNBOUNDED = "POLICY_ADMIN_UNBOUNDED"
    NO_SSE = "NO_SSE"
    DELETED_OBJECT_RECOVERABLE = "DELETED_OBJECT_RECOVERABLE"
    CROSS_ACCOUNT_REPLICATION = "CROSS_ACCOUNT_REPLICATION"

    # ---- 中危 ----
    CONFIG_FILE_EXPOSED = "CONFIG_FILE_EXPOSED"
    ACL_READABLE = "ACL_READABLE"
    BLOB_PUBLIC_ACCESS = "BLOB_PUBLIC_ACCESS"
    CORS_WILDCARD = "CORS_WILDCARD"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    LOGGING_DISABLED = "LOGGING_DISABLED"
    ENCRYPTION_AES_NOT_KMS = "ENCRYPTION_AES_NOT_KMS"
    ENCRYPTION_NO_CUSTOM_KEY = "ENCRYPTION_NO_CUSTOM_KEY"
    REFERER_UNRESTRICTED = "REFERER_UNRESTRICTED"
    STATIC_WEBSITE_ENABLED = "STATIC_WEBSITE_ENABLED"

    # ---- 低危 ----
    OTHER_FILE_EXPOSED = "OTHER_FILE_EXPOSED"
    SENSITIVE_HEADERS = "SENSITIVE_HEADERS"
    HTTP_ENABLED = "HTTP_ENABLED"
    VERSIONING_WITHOUT_MFA_DELETE = "VERSIONING_WITHOUT_MFA_DELETE"

    # ---- 信息 ----
    BUCKET_NOT_FOUND = "BUCKET_NOT_FOUND"
    BUCKET_EXISTS_NO_ACCESS = "BUCKET_EXISTS_NO_ACCESS"
    REGION_DISCOVERED = "REGION_DISCOVERED"

    # ---- 错误 ----
    SCAN_ERROR = "SCAN_ERROR"
    AUTH_ERROR = "AUTH_ERROR"


@dataclass(frozen=True)
class RiskMeta:
    """单项风险的展示与处置元数据。"""

    severity: Severity
    title: str
    remediation: str
    compliance: str = ""


RISK_META: Dict[Risk, RiskMeta] = {
    Risk.KEY_FILE_EXPOSED: RiskMeta(
        Severity.CRITICAL,
        "密钥文件可被访问",
        "立即收敛 Bucket 读权限并轮换已泄露的密钥；确认对象是否必须公开，"
        "否则改为私有 ACL 或通过签名 URL 下发。",
        "等保2.0 8.1.4.2 / CIS 3.3",
    ),
    Risk.DB_BACKUP_EXPOSED: RiskMeta(
        Severity.CRITICAL,
        "数据库备份可被访问",
        "将备份移出公开 Bucket 或转为私有；轮换备份中可能包含的数据库凭据，"
        "并检查是否已被外部下载。",
        "等保2.0 8.1.4.2 / CIS 3.3",
    ),
    Risk.ANON_WRITE_PUT: RiskMeta(
        Severity.CRITICAL,
        "允许 PUT 上传",
        "在 Bucket 策略中移除匿名 PutObject 授权，关闭公共写权限；"
        "排查是否已被上传 webshell 或垃圾文件。",
        "等保2.0 8.1.4.3 / CIS 3.4",
    ),
    Risk.ANON_WRITE_POST: RiskMeta(
        Severity.CRITICAL,
        "允许 POST 表单上传",
        "关闭 Bucket 的匿名 PostObject 授权，检查 CORS 是否同时放开了上传来源。",
        "等保2.0 8.1.4.3 / CIS 3.4",
    ),
    Risk.ANON_DELETE: RiskMeta(
        Severity.CRITICAL,
        "允许删除对象",
        "移除匿名 DeleteObject 授权；开启版本控制与删除保护以降低数据损毁风险。",
        "等保2.0 8.1.4.3",
    ),
    Risk.POLICY_ANON_WRITE: RiskMeta(
        Severity.CRITICAL,
        "Bucket 策略允许匿名写入或删除",
        "策略中 Principal 为 * 且授予 PutObject/DeleteObject/PutObjectAcl，"
        "应收窄 Principal 或删除相关 Action。",
        "等保2.0 8.1.4.3 / CIS 3.4",
    ),
    Risk.PUBLIC_LIST: RiskMeta(
        Severity.HIGH,
        "可列出对象清单",
        "关闭 Bucket 的 ListObjects 匿名权限，避免对象清单被批量枚举。",
        "等保2.0 8.1.4.2 / CIS 3.3",
    ),
    Risk.LOG_EXPOSED: RiskMeta(
        Severity.HIGH,
        "访问日志可被读取",
        "访问日志常含内部域名、IP 与参数，应将日志 Bucket 设为私有并单独授权。",
        "等保2.0 8.1.4.2",
    ),
    Risk.ACL_WRITABLE: RiskMeta(
        Severity.HIGH,
        "对象或 Bucket ACL 可被写入",
        "ACL 写权限等价于权限提升，应改为私有并统一用 Bucket 策略管理。",
        "等保2.0 8.1.4.3 / CIS 3.4",
    ),
    Risk.ACL_PUBLIC_GRANT: RiskMeta(
        Severity.HIGH,
        "ACL 授予了匿名公共权限",
        "授权项里出现 AllUsers/公共组，等于对全网开放。应在 Bucket 权限管理中"
        "删除该授权项，改用 Bucket 策略并限制 Principal。",
        "等保2.0 8.1.4.3 / CIS 3.3",
    ),
    Risk.ACL_AUTHENTICATED_GRANT: RiskMeta(
        Severity.HIGH,
        "ACL 授予了任意已认证用户权限",
        "授权项里出现 AuthenticatedUsers，意味着任何拥有该云厂商账号的人都能访问。"
        "这类授权极易被横向利用，应收窄到具体账号或角色。",
        "CIS 3.3",
    ),
    Risk.DELETED_OBJECT_RECOVERABLE: RiskMeta(
        Severity.HIGH,
        "已删除的敏感对象可从历史版本恢复",
        "Bucket 开启了版本控制且历史版本仍可读取，删除文件并不等于数据消失。"
        "应清理历史版本、为敏感前缀配置生命周期过期规则，并开启 MFA 删除保护。",
        "等保2.0 8.1.4.7",
    ),
    Risk.CROSS_ACCOUNT_REPLICATION: RiskMeta(
        Severity.HIGH,
        "跨账号复制规则可能造成数据外流",
        "跨账号复制会把对象持续同步到另一个账号的 Bucket。请确认目标账号可控，"
        "否则删除该复制规则。",
        "等保2.0 8.1.4.7",
    ),
    Risk.POLICY_ANON_READ: RiskMeta(
        Severity.MEDIUM,
        "Bucket 策略允许匿名读取",
        "收窄 Principal 范围，或为公开内容改用 CDN 与签名 URL。",
        "CIS 3.3",
    ),
    Risk.POLICY_ANON_POLICY_READ: RiskMeta(
        Severity.HIGH,
        "允许匿名获取 Bucket 策略配置",
        "策略本身会暴露账号 ID 与授权结构，应移除 GetBucketPolicy 的匿名授权。",
        "CIS 3.3",
    ),
    Risk.POLICY_ADMIN_UNBOUNDED: RiskMeta(
        Severity.HIGH,
        "策略授予未限制来源的管理员权限",
        "为管理员级授权补充 Condition（如 aws:SourceIp / acs:SourceIp）限制来源。",
        "等保2.0 8.1.4.1",
    ),
    Risk.NO_SSE: RiskMeta(
        Severity.HIGH,
        "未启用服务端加密",
        "为 Bucket 开启服务端加密（KMS 或 AES256），满足数据静态加密要求。",
        "等保2.0 8.1.4.6 / CIS 3.6",
    ),
    Risk.CONFIG_FILE_EXPOSED: RiskMeta(
        Severity.MEDIUM,
        "配置文件可被访问",
        "配置文件常含数据库连接串与第三方密钥，应移出公开 Bucket 并轮换其中凭据。",
        "等保2.0 8.1.4.2",
    ),
    Risk.ACL_READABLE: RiskMeta(
        Severity.MEDIUM,
        "对象 ACL 可被读取",
        "即使对象私有，ACL 可读也会暴露授权结构，应改为私有 ACL。",
        "CIS 3.3",
    ),
    Risk.BLOB_PUBLIC_ACCESS: RiskMeta(
        Severity.MEDIUM,
        "Blob 存在匿名公开访问",
        "关闭容器级公共访问（public access level 设为 private）。",
        "CIS 3.3",
    ),
    Risk.CORS_WILDCARD: RiskMeta(
        Severity.MEDIUM,
        "CORS 配置过宽",
        "Access-Control-Allow-Origin 为 * 且允许写方法，应改为显式域名白名单并移除写方法。",
        "等保2.0 8.1.4.3",
    ),
    Risk.DIRECTORY_TRAVERSAL: RiskMeta(
        Severity.MEDIUM,
        "存在目录遍历访问",
        "对象存储通常不应返回上级路径内容，检查是否有自定义域名回源或反向代理参与。",
        "等保2.0 8.1.4.4",
    ),
    Risk.LOGGING_DISABLED: RiskMeta(
        Severity.MEDIUM,
        "未开启访问日志转存",
        "开启日志转存以便审计与事件回溯，日志 Bucket 需独立且私有。",
        "等保2.0 8.1.4.5",
    ),
    Risk.ENCRYPTION_AES_NOT_KMS: RiskMeta(
        Severity.MEDIUM,
        "使用 AES256 而非 KMS 托管密钥",
        "如需密钥轮换与访问审计，改用 KMS 托管密钥加密。",
        "CIS 3.6",
    ),
    Risk.ENCRYPTION_NO_CUSTOM_KEY: RiskMeta(
        Severity.MEDIUM,
        "使用 KMS 但未使用自定义主密钥",
        "改用客户自管主密钥（BYOK/CMK）以满足密钥自主可控要求。",
        "CIS 3.6",
    ),
    Risk.REFERER_UNRESTRICTED: RiskMeta(
        Severity.MEDIUM,
        "未配置防盗链，允许任意来源引用",
        "Bucket 未设置 Referer 白名单，任意站点都可直接引用你的对象，"
        "会造成流量盗用与内容被外链。建议配置 Referer 白名单并拒绝空 Referer。",
        "等保2.0 8.1.4.4",
    ),
    Risk.STATIC_WEBSITE_ENABLED: RiskMeta(
        Severity.MEDIUM,
        "开启了静态网站托管",
        "静态网站托管会暴露 index/error 文档路径，且常与自定义域名绑定。"
        "确认无需该功能时关闭，并检查错误页是否泄露内部路径。",
    ),
    Risk.OTHER_FILE_EXPOSED: RiskMeta(
        Severity.LOW,
        "敏感路径可被访问",
        "确认该路径内容是否必须公开，否则收紧读权限。",
    ),
    Risk.SENSITIVE_HEADERS: RiskMeta(
        Severity.LOW,
        "响应头泄露存储元信息",
        "关闭对象元数据回显，避免通过 X-*-Meta-* 头暴露内部信息。",
    ),
    Risk.HTTP_ENABLED: RiskMeta(
        Severity.LOW,
        "允许明文 HTTP 访问",
        "强制 HTTPS 访问，避免流量被中间人窃听或篡改。",
        "等保2.0 8.1.4.4",
    ),
    Risk.VERSIONING_WITHOUT_MFA_DELETE: RiskMeta(
        Severity.LOW,
        "开启版本控制但未启用 MFA 删除保护",
        "版本控制可以救回误删数据，但攻击者也能借此读取历史版本，"
        "或直接删除全部版本。建议对敏感 Bucket 开启 MFA 删除保护。",
        "等保2.0 8.1.4.7",
    ),
    Risk.BUCKET_NOT_FOUND: RiskMeta(
        Severity.INFO,
        "Bucket 不存在或不可解析",
        "无需处理。若预期存在，请核对 Bucket 名称、区域与云厂商是否正确。",
    ),
    Risk.BUCKET_EXISTS_NO_ACCESS: RiskMeta(
        Severity.INFO,
        "Bucket 存在但无匿名访问权限",
        "无需处理。这是私有 Bucket 的正常表现。",
    ),
    Risk.REGION_DISCOVERED: RiskMeta(
        Severity.INFO,
        "从响应头识别出 Bucket 区域",
        "无需处理。程序会据此校正后续请求的目标区域。",
    ),
    Risk.SCAN_ERROR: RiskMeta(
        Severity.ERROR,
        "扫描过程发生错误",
        "检查网络、代理与区域配置后重试。",
    ),
    Risk.AUTH_ERROR: RiskMeta(
        Severity.ERROR,
        "认证信息不可用",
        "检查临时凭证是否完整、是否过期，以及 SecurityToken 是否随请求下发。",
    ),
}


def severity_of(risk: Risk) -> Severity:
    """返回风险项的严重度。"""
    return RISK_META[risk].severity


def title_of(risk: Risk) -> str:
    """返回风险项的中文标题。"""
    return RISK_META[risk].title


def resolve(risk: Risk) -> RiskMeta:
    """返回风险项元数据。"""
    return RISK_META[risk]
