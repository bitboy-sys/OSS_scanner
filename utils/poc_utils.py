"""PoC 命令生成。

每条风险附一条可直接复制执行的命令，用于在授权范围内复现。

安全约定：

* 认证态结果生成的命令里**只出现占位符**（``$OSS_SCANNER_STS_TOKEN``），
  绝不写入真实的 AccessKeySecret 或 SecurityToken —— 报告会被转发、归档、
  贴进工单。
* 写操作类命令带明确注释，提醒执行者这会真的改动目标。

生成规则：注释单独成行（避免被行连接符卷进命令里），管道与重定向紧跟在
URL 之后（不能参与 ``\\`` 续行，否则 URL 会被当作下游命令的参数）。
"""
from typing import Dict, List, Optional

# 需要携带安全令牌头的厂商
_TOKEN_HEADERS = {
    "aliyun": "x-oss-security-token",
    "aws": "x-amz-security-token",
    "tencent": "x-cos-security-token",
    "huawei": "x-obs-security-token",
    "gcp": "x-goog-security-token",
}

_CURL_OPTS = "-sS -i --max-time 15"
_INDENT = "  "
# 文件类漏洞只取前若干字节，避免一执行就把几个 G 的备份拉下来
_PREVIEW_BYTES = 200


def _shell_quote(value: str) -> str:
    """安全地引用 URL，避免查询串里的 & 被 shell 解释。"""
    if not value:
        return "''"
    return "'" + value.replace("'", "'\\''") + "'"


def _auth_headers(cloud: str, auth_mode: str) -> List[str]:
    """认证态下追加令牌占位符头，提示执行者用环境变量补齐。"""
    if auth_mode != "authenticated":
        return []
    header = _TOKEN_HEADERS.get(cloud)
    if not header:
        return []
    return [f"-H '{header}: $OSS_SCANNER_STS_TOKEN'"]


def _curl(url: str, *, method: str = "GET", cloud: str = "",
          auth_mode: str = "anonymous", extra: Optional[List[str]] = None,
          body: bool = False, suffix: str = "") -> str:
    """拼一条 curl 命令。

    ``extra`` 里的元素是 curl 自己的参数；``suffix`` 追加在 URL 之后，
    用于管道或重定向——它不参与续行。
    """
    parts = [f"curl {_CURL_OPTS}"]
    if method != "GET":
        parts.append(f"-X {method}")
    if body:
        parts.append("--data 'oss_scan_test_content'")
    parts.extend(_auth_headers(cloud, auth_mode))
    parts.extend(extra or [])
    parts.append(_shell_quote(url))
    return " \\\n".join([parts[0]] + [f"{_INDENT}{p}" for p in parts[1:]]) + suffix


def _prelude(comment: str, command: str) -> str:
    """把说明放在命令之前，且不与命令共用续行。"""
    return f"# {comment}\n{command}"


def _list_poc(url: str) -> str:
    """列目录类风险统一用 list-type=2 复现，比裸根路径更明确。"""
    base = url.rstrip("/")
    separator = "&" if "?" in base else "?"
    return _curl(f"{base}{separator}list-type=2&max-keys=20")


_WRITE_WARNING = "注意：这会真的修改目标对象，仅在授权范围内执行"


def build_poc(finding: Dict) -> str:
    """按风险类型生成一条可运行命令；无法生成时返回空串。"""
    risk_id = str(finding.get("risk_id", ""))
    url = str(finding.get("url", ""))
    cloud = str(finding.get("cloud", ""))
    auth_mode = str(finding.get("auth_mode", "anonymous"))
    if not url:
        return ""

    if risk_id in ("KEY_FILE_EXPOSED", "DB_BACKUP_EXPOSED",
                   "CONFIG_FILE_EXPOSED", "OTHER_FILE_EXPOSED"):
        return _curl(url, cloud=cloud, auth_mode=auth_mode,
                     suffix=f" | head -c {_PREVIEW_BYTES}")

    if risk_id == "PUBLIC_LIST":
        return _list_poc(url)

    if risk_id == "LOG_EXPOSED":
        return _curl(url, cloud=cloud, auth_mode=auth_mode)

    if risk_id == "ANON_WRITE_PUT":
        return _prelude(_WRITE_WARNING,
                        _curl(url, method="PUT", body=True, cloud=cloud, auth_mode=auth_mode))

    if risk_id == "ANON_WRITE_POST":
        return _prelude(_WRITE_WARNING,
                        _curl(url, method="POST", body=True, cloud=cloud, auth_mode=auth_mode))

    if risk_id == "ANON_DELETE":
        return _prelude(_WRITE_WARNING,
                        _curl(url, method="DELETE", cloud=cloud, auth_mode=auth_mode))

    if risk_id in ("POLICY_ANON_READ", "POLICY_ANON_WRITE", "POLICY_ANON_POLICY_READ",
                   "POLICY_ADMIN_UNBOUNDED"):
        return _curl(url, cloud=cloud, auth_mode=auth_mode)

    if risk_id in ("ACL_PUBLIC_GRANT", "ACL_AUTHENTICATED_GRANT", "ACL_WRITABLE"):
        return _curl(url, cloud=cloud, auth_mode=auth_mode)

    if risk_id == "ACL_READABLE":
        return _curl(url, method="HEAD", cloud=cloud, auth_mode=auth_mode)

    if risk_id in ("NO_SSE", "ENCRYPTION_AES_NOT_KMS", "ENCRYPTION_NO_CUSTOM_KEY",
                   "LOGGING_DISABLED", "REFERER_UNRESTRICTED", "STATIC_WEBSITE_ENABLED",
                   "CROSS_ACCOUNT_REPLICATION", "VERSIONING_WITHOUT_MFA_DELETE"):
        return _curl(url, cloud=cloud, auth_mode=auth_mode)

    if risk_id == "CORS_WILDCARD":
        return _curl(url, method="OPTIONS", cloud=cloud, auth_mode=auth_mode, extra=[
            "-H 'Origin: https://example.com'",
            "-H 'Access-Control-Request-Method: PUT'",
        ])

    if risk_id == "DIRECTORY_TRAVERSAL":
        # --path-as-is 阻止 curl 自行折叠 ../，否则复现不出来
        return _curl(url, cloud=cloud, auth_mode=auth_mode, extra=["--path-as-is"])

    if risk_id == "DELETED_OBJECT_RECOVERABLE":
        # 先列出历史版本拿到 VersionId，再按 ID 取回内容
        list_versions = _curl(url, cloud=cloud, auth_mode=auth_mode)
        fetch_version = _curl(
            f"{url.rsplit('?', 1)[0]}?versionId=<上一步返回的 VersionId>",
            cloud=cloud, auth_mode=auth_mode)
        return _prelude(
            "先列出历史版本拿到 VersionId，再把下面命令里的 <上一步返回的 VersionId> 替换掉",
            f"{list_versions}\n\n{fetch_version}")

    if risk_id == "HTTP_ENABLED":
        return _curl(url)

    if risk_id == "SENSITIVE_HEADERS":
        return _curl(url, method="HEAD")

    if risk_id == "BLOB_PUBLIC_ACCESS":
        return _curl(url)

    return ""
