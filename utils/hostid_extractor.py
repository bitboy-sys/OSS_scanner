"""从目标网页的 ``<HostId>`` 标签推断对象存储端点。

阿里云 OSS 的 XML 错误页里带有 ``<HostId>``，本模块负责抓取目标页面并把它
交给 :mod:`utils.endpoint_parser` 统一解析，避免再维护第二套 URL 规则。
"""
import re
from typing import Optional

import requests

from utils.endpoint_parser import Endpoint, parse_endpoint
from utils.http_utils import DEFAULT_USER_AGENT
from utils.log_utils import logger

_HOSTID_RE = re.compile(r"<HostId>\s*(.*?)\s*</HostId>", re.IGNORECASE)


def extract_endpoint_from_page(url: str, cloud: Optional[str] = None,
                               timeout: int = 10, proxy: Optional[str] = None) -> Endpoint:
    """抓取目标页面并解析其中的 ``<HostId>``。

    :raises ValueError: 抓取失败、页面中没有 HostId，或 HostId 无法解析。
    """
    try:
        response = requests.get(
            url,
            timeout=timeout,
            proxies={"http": proxy, "https": proxy} if proxy else None,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"抓取目标网页失败: {exc}") from exc

    match = _HOSTID_RE.search(response.text)
    if not match:
        raise ValueError("目标网页中没有 <HostId> 标签，无法自动定位存储桶")

    hostid = match.group(1).strip()
    logger.info(f"从页面提取到 HostId: {hostid}")

    try:
        endpoint = parse_endpoint(hostid, cloud)
    except ValueError as exc:
        raise ValueError(f"HostId 解析失败: {exc}") from exc
    logger.info(f"HostId 解析结果: 厂商={endpoint.cloud} Bucket={endpoint.bucket} 区域={endpoint.region}")
    return endpoint
