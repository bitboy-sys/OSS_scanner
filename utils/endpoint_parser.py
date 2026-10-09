"""对象存储端点解析。

此前有三套互相矛盾的解析逻辑：``main.py`` 里的 ``--hostid-url`` 正则、
``utils/hostid_extractor.py`` 的拆分逻辑，以及 ``config.ini`` 的 URL 模板。
其中华为云正则要 ``obs-``（短横线）而模板与真实端点是 ``obs.``（点号），
AWS 要 ``s3-`` 而模板是 ``s3.``，导致这两个厂商的 ``--hostid-url`` 必然失败。

这里统一处理各家真实端点形式，并支持从主机名后缀自动识别云厂商。
"""
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

# 主机名后缀 → 云厂商
_SUFFIX_TO_CLOUD = (
    ("aliyuncs.com", "aliyun"),
    ("myqcloud.com", "tencent"),
    ("tencentcos.cn", "tencent"),
    ("myhuaweicloud.com", "huawei"),
    ("amazonaws.com", "aws"),
    ("storage.googleapis.com", "gcp"),
    ("googleapis.com", "gcp"),
    ("blob.core.windows.net", "azure"),
)

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_APPID_RE = re.compile(r"-(\d{5,})$")


@dataclass(frozen=True)
class Endpoint:
    """从 URL 或主机名解析出的定位信息。"""

    cloud: str
    bucket: str = ""
    region: str = ""
    account: str = ""
    appid: str = ""
    host: str = ""


def _normalize(value: str) -> str:
    value = (value or "").strip()
    if not _SCHEME_RE.match(value):
        value = "https://" + value
    return value


def detect_cloud(host: str) -> Optional[str]:
    """按主机名后缀识别云厂商。"""
    host = (host or "").lower()
    for suffix, cloud in _SUFFIX_TO_CLOUD:
        if host == suffix or host.endswith("." + suffix):
            return cloud
    return None


def _first_segment(path: str) -> str:
    segments = [seg for seg in (path or "").split("/") if seg]
    return segments[0] if segments else ""


def _parse_aliyun(host: str, path: str) -> Endpoint:
    parts = host.split(".")
    for index, part in enumerate(parts):
        if not part.startswith("oss-"):
            continue
        region = part[4:]
        # 去掉 oss-{region}-internal / oss-accelerate 之类的变体后缀
        for suffix in ("-internal", "-accelerate", "-accelerate-internal"):
            if region.endswith(suffix):
                region = region[: -len(suffix)]
        bucket = parts[0] if index == 1 else _first_segment(path)
        return Endpoint("aliyun", bucket=bucket, region=region, host=host)
    # 没有 oss- 标记：可能是 path-style（oss-*.aliyuncs.com/{bucket}）或纯域名
    return Endpoint("aliyun", bucket=_first_segment(path), host=host)


def _parse_tencent(host: str, path: str) -> Endpoint:
    parts = host.split(".")
    for index, part in enumerate(parts):
        if part not in ("cos", "cos-internal"):
            continue
        head = parts[0] if index == 1 else _first_segment(path)
        region = parts[index + 1] if len(parts) > index + 1 else ""
        region = region.split("-internal")[0]
        appid = ""
        match = _APPID_RE.search(head)
        if match:
            appid = match.group(1)
            head = head[: match.start()]
        return Endpoint("tencent", bucket=head, region=region, appid=appid, host=host)
    return Endpoint("tencent", bucket=_first_segment(path), host=host)


def _parse_huawei(host: str, path: str) -> Endpoint:
    parts = host.split(".")
    for index, part in enumerate(parts):
        if part not in ("obs",):
            continue
        bucket = parts[0] if index == 1 else _first_segment(path)
        region = parts[index + 1] if len(parts) > index + 1 else ""
        return Endpoint("huawei", bucket=bucket, region=region, host=host)
    return Endpoint("huawei", bucket=_first_segment(path), host=host)


def _parse_aws(host: str, path: str) -> Endpoint:
    parts = host.split(".")
    if len(parts) < 2 or not parts[1].startswith("s3"):
        # path-style（s3.{region}.amazonaws.com/{bucket}）或纯域名
        return Endpoint("aws", bucket=_first_segment(path), host=host)

    bucket = parts[0]
    region = ""
    marker = parts[1]
    if marker == "s3":
        tail = parts[2:]
        if tail and tail[0] == "dualstack":
            tail = tail[1:]
        region = tail[0] if tail and tail[0] != "amazonaws" else ""
    else:
        # s3-{region} / s3-accelerate / s3-external-1 等
        region = marker[3:]
        if region in ("accelerate", "external-1"):
            region = ""
    return Endpoint("aws", bucket=bucket, region=region, host=host)


def _parse_gcp(host: str, path: str) -> Endpoint:
    parts = host.split(".")
    if parts[0] == "storage":
        # path-style: storage.googleapis.com/{bucket}
        return Endpoint("gcp", bucket=_first_segment(path), host=host)
    if host.endswith(".storage.googleapis.com"):
        return Endpoint("gcp", bucket=parts[0], host=host)
    return Endpoint("gcp", bucket=_first_segment(path), host=host)


def _parse_azure(host: str, path: str) -> Endpoint:
    parts = host.split(".")
    account = parts[0] if len(parts) > 1 else ""
    if account in ("blob", "core", "windows", "net"):
        account = ""
    return Endpoint("azure", bucket=_first_segment(path), account=account, host=host)


_PARSERS = {
    "aliyun": _parse_aliyun,
    "tencent": _parse_tencent,
    "huawei": _parse_huawei,
    "aws": _parse_aws,
    "gcp": _parse_gcp,
    "azure": _parse_azure,
}


def parse_endpoint(value: str, cloud: Optional[str] = None) -> Endpoint:
    """解析 URL、主机名或路径形式的端点。

    :param value: 例如 ``https://b.oss-cn-beijing.aliyuncs.com`` 或
        ``b.obs.cn-north-4.myhuaweicloud.com``。
    :param cloud: 指定云厂商；留空时按主机名后缀自动识别。
    :raises ValueError: 无法识别云厂商或解析结果为空。
    """
    parsed = urlparse(_normalize(value))
    host = (parsed.netloc or "").lower()
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.split(":")[0]
    if not host:
        raise ValueError(f"无法从 {value!r} 中解析出主机名")

    resolved = cloud or detect_cloud(host)
    if not resolved:
        raise ValueError(f"无法识别 {host} 属于哪个云厂商，请用 --cloud 显式指定")
    if resolved not in _PARSERS:
        raise ValueError(f"暂不支持解析 {resolved} 的端点")

    endpoint = _PARSERS[resolved](host, parsed.path)
    if not endpoint.bucket:
        raise ValueError(f"未能从 {value!r} 中提取出 Bucket/容器名")
    if resolved == "azure" and not endpoint.account:
        raise ValueError(f"未能从 {value!r} 中提取出 Azure 存储账户名")
    return endpoint


def known_clouds() -> List[str]:
    """返回支持解析的云厂商列表。"""
    return list(_PARSERS)
