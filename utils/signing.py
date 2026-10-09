"""请求签名。

持有临时凭证后要真正以认证身份发请求，就必须按各厂商的规则签名。这里只实现
扫描实际用到的只读与少量写请求所需的签名方案，不引入官方 SDK：

* ``aws_v4``   —— AWS SigV4，同时覆盖 AWS S3、华为云 OBS（S3 兼容）与兼容 S3 的其他实现
* ``aliyun_v1`` —— 阿里云 OSS 签名（HMAC-SHA1）
* ``tencent``  —— 腾讯云 COS 签名

签名是纯函数：输入凭证与请求要素，输出需要附加的请求头，便于离线单元测试。
"""
import base64
import hashlib
import hmac
import time
from typing import Dict, Optional
from urllib.parse import quote, urlparse

from utils.credentials import TemporaryCredential

EMPTY_PAYLOAD_SHA256 = hashlib.sha256(b"").hexdigest()

_UNRESERVED = "-_.~"


def _uri_encode(value: str, encode_slash: bool = True) -> str:
    """按 RFC 3986 编码。SigV4 要求除了 ``-_.~`` 之外全部编码。"""
    encoded = quote(value, safe=_UNRESERVED)
    if not encode_slash:
        encoded = encoded.replace("%2F", "/")
    return encoded


def _canonical_query(query: str) -> str:
    """把查询串规范化为「按 key 排序 + 编码」的形式。"""
    if not query:
        return ""
    pairs = []
    for part in query.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        pairs.append((_uri_encode(name), _uri_encode(value)))
    pairs.sort()
    return "&".join(f"{name}={value}" for name, value in pairs)


# --------------------------------------------------------------------- AWS SigV4

def aws_v4(credential: TemporaryCredential, method: str, url: str,
           headers: Dict[str, str], payload: bytes = b"",
           region: str = "us-east-1", service: str = "s3",
           now: Optional[float] = None,
           include_content_sha256: bool = True) -> Dict[str, str]:
    """返回 AWS SigV4 需要附加的请求头。

    :param now: UNIX 时间戳，便于测试固定时间。
    :param include_content_sha256: S3 要求携带并签名 ``x-amz-content-sha256``；
        置为 False 可复现 AWS 官方测试向量（该向量不包含此头）。
    """
    parsed = urlparse(url)
    host = parsed.netloc
    if "@" in host:
        host = host.rsplit("@", 1)[1]

    timestamp = time.gmtime(now if now is not None else time.time())
    amz_date = time.strftime("%Y%m%dT%H%M%SZ", timestamp)
    date_stamp = time.strftime("%Y%m%d", timestamp)

    payload_hash = hashlib.sha256(payload or b"").hexdigest()
    signed = dict(headers or {})
    signed["host"] = host
    signed["x-amz-date"] = amz_date
    if include_content_sha256:
        signed["x-amz-content-sha256"] = payload_hash
    if credential.security_token:
        signed["x-amz-security-token"] = credential.security_token

    canonical_headers = "".join(
        f"{name.lower()}:{' '.join(str(value).split())}\n"
        for name, value in sorted(signed.items(), key=lambda kv: kv[0].lower())
    )
    signed_header_names = ";".join(sorted(name.lower() for name in signed))

    canonical_request = "\n".join([
        method.upper(),
        _uri_encode(parsed.path or "/", encode_slash=False),
        _canonical_query(parsed.query),
        canonical_headers,
        signed_header_names,
        payload_hash,
    ])

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    def _sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    key = _sign(f"AWS4{credential.access_key_secret}".encode("utf-8"), date_stamp)
    key = _sign(key, region)
    key = _sign(key, service)
    key = _sign(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    signed["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credential.access_key_id}/{scope}, "
        f"SignedHeaders={signed_header_names}, Signature={signature}"
    )
    return signed


# ------------------------------------------------------------- 阿里云 OSS 签名

def aliyun_v1(credential: TemporaryCredential, method: str, url: str,
              headers: Dict[str, str], now: Optional[float] = None) -> Dict[str, str]:
    """阿里云 OSS 签名（HMAC-SHA1）。

    ``CanonicalizedResource`` 需要带上 Bucket 与需要签名的子资源
    （``acl``/``policy``/``versioning``/``logging``/``encryption``/``versions`` 等）。
    """
    parsed = urlparse(url)
    signed = dict(headers or {})
    signed["Date"] = time.strftime(
        "%a, %d %b %Y %H:%M:%S GMT",
        time.gmtime(now if now is not None else time.time()),
    )
    if credential.security_token:
        signed["x-oss-security-token"] = credential.security_token

    canonical_headers = ""
    for name, value in sorted(signed.items(), key=lambda kv: kv[0].lower()):
        lower = name.lower()
        if lower.startswith("x-oss-"):
            canonical_headers += f"{lower}:{str(value).strip()}\n"

    resource = parsed.path or "/"
    if parsed.query:
        subresources = sorted(
            part.split("=")[0] for part in parsed.query.split("&") if part
        )
        resource += "?" + "&".join(subresources)

    content_md5 = signed.get("Content-MD5", "")
    content_type = signed.get("Content-Type", "")
    string_to_sign = "\n".join([
        method.upper(),
        content_md5,
        content_type,
        signed["Date"],
        canonical_headers + resource,
    ])

    digest = hmac.new(credential.access_key_secret.encode("utf-8"),
                      string_to_sign.encode("utf-8"), hashlib.sha1).digest()
    signed["Authorization"] = f"OSS {credential.access_key_id}:{base64.b64encode(digest).decode()}"
    return signed


# ----------------------------------------------------------------- 腾讯云 COS

def tencent(credential: TemporaryCredential, method: str, url: str,
            headers: Dict[str, str], now: Optional[float] = None) -> Dict[str, str]:
    """腾讯云 COS 签名（sha1，q-sign 系列参数放在 Authorization 头里）。"""
    parsed = urlparse(url)
    signed = dict(headers or {})
    if credential.security_token:
        signed["x-cos-security-token"] = credential.security_token

    current = int(now if now is not None else time.time())
    sign_time = f"{current};{current + 3600}"
    key_time = sign_time

    header_list = sorted(name.lower() for name in signed if name.lower().startswith("x-cos-"))
    url_param_list = sorted(
        part.split("=")[0] for part in parsed.query.split("&") if part
    )

    http_headers = "&".join(
        f"{name}={quote(str(signed_next), safe='')}"
        for name in header_list
        for signed_next in [next(v for k, v in signed.items() if k.lower() == name)]
    )
    http_params = "&".join(sorted(part for part in parsed.query.split("&") if part))

    sign_key = hmac.new(credential.access_key_secret.encode("utf-8"),
                        key_time.encode("utf-8"), hashlib.sha1).hexdigest()

    string_to_sign = "\n".join([
        method.lower(),
        parsed.path or "/",
        http_params,
        http_headers,
        "",
    ])
    signature = hmac.new(sign_key.encode("utf-8"), string_to_sign.encode("utf-8"),
                         hashlib.sha1).hexdigest()

    signed["Authorization"] = (
        "q-sign-algorithm=sha1"
        f"&q-ak={credential.access_key_id}"
        f"&q-sign-time={sign_time}"
        f"&q-key-time={key_time}"
        f"&q-header-list={';'.join(header_list)}"
        f"&q-url-param-list={';'.join(url_param_list)}"
        f"&q-signature={signature}"
    )
    return signed


# ---------------------------------------------------------------------- 分发

_SIGNERS = {
    "aliyun": aliyun_v1,
    "aws": aws_v4,
    "huawei": aws_v4,   # OBS 兼容 S3 SigV4
    "tencent": tencent,
    "gcp": aws_v4,      # GCS 的 XML API 兼容 SigV4（HMAC 密钥）
}

# 使用 SigV4 的厂商 → 该厂商在签名 scope 里的 service 名
_V4_PROVIDERS = {
    "aws": "s3",
    "huawei": "s3",
    "gcp": "storage",   # GCS 必须用 storage，写成 s3 会 SignatureDoesNotMatch
}


def supported_providers():
    """返回支持签名的云厂商列表。"""
    return sorted(_SIGNERS)


def sign_request(provider: str, credential: TemporaryCredential, method: str, url: str,
                 headers: Optional[Dict[str, str]] = None,
                 payload: bytes = b"", region: str = "",
                 now: Optional[float] = None) -> Dict[str, str]:
    """按厂商对请求签名，返回完整的请求头。

    不支持的厂商会抛出 ``ValueError``，由调用方决定降级为匿名还是直接报错。
    """
    signer = _SIGNERS.get(provider)
    if signer is None:
        raise ValueError(f"{provider} 暂不支持签名")

    clean_headers = dict(headers or {})
    service = _V4_PROVIDERS.get(provider)
    if service is None:
        return signer(credential, method, url, clean_headers, now=now)

    # GCS 的 SigV4 区域固定为 auto；其余用凭证区域或调用方给定值
    resolved_region = "auto" if provider == "gcp" else (
        region or credential.region or "us-east-1")
    return signer(credential, method, url, clean_headers,
                  payload=payload, region=resolved_region, service=service, now=now)
