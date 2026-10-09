"""统一 HTTP 请求层。

三个关键点：

* **Session 复用**：每个线程按 (retry, proxy, user_agent) 缓存一个
  ``requests.Session``，从而真正复用连接池。此前每个请求新建 Session，
  每次都重新握手，是单桶扫描耗时过百秒的主要原因之一。
* **响应体上限**：只读取前 ``max_body`` 字节，避免大对象把内存吃满。
* **全局按主机限速**：同一主机的请求在进程内统一排队，``--thread`` 调大
  不会再成倍放大实际延迟。
"""
import threading
import time
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 自动重试仅覆盖幂等方法。POST 不重试，避免重复上传或重复提交。
_RETRY_METHODS = ["HEAD", "GET", "OPTIONS"]
_RETRY_STATUS = [429, 500, 502, 503, 504]

DEFAULT_MAX_BODY = 64 * 1024
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_thread_local = threading.local()


class _HostRateLimiter:
    """按主机名的令牌桶，跨线程共享。

    桶容量决定突发上限（默认 5 个请求可立即发出），之后按 ``1/interval``
    的速率补充令牌。这样平均速率可控，又不会因为全局限速而让每个请求都
    串行等待。
    """

    def __init__(self, burst: int = 5) -> None:
        self._lock = threading.Lock()
        self._burst = max(1, burst)
        # host -> (tokens, last_refill)
        self._state: Dict[str, tuple] = {}

    def set_burst(self, burst: int) -> None:
        with self._lock:
            self._burst = max(1, int(burst))
            self._state.clear()

    def wait(self, host: str, min_interval: float) -> None:
        if min_interval <= 0 or not host:
            return
        rate = 1.0 / min_interval
        while True:
            with self._lock:
                now = time.monotonic()
                tokens, last = self._state.get(host, (float(self._burst), now))
                tokens = min(float(self._burst), tokens + (now - last) * rate)
                if tokens >= 1.0:
                    self._state[host] = (tokens - 1.0, now)
                    return
                self._state[host] = (tokens, now)
                delay = (1.0 - tokens) / rate
            # 短暂让出，避免持锁长睡导致其他线程饥饿
            time.sleep(min(delay, 0.25))


_rate_limiter = _HostRateLimiter()
_default_interval = 0.0


def set_default_interval(seconds: float) -> None:
    """设置全局默认的按主机请求间隔（0 表示不限速）。

    由 ``main.py`` 从配置的 ``request_interval`` 注入，因此所有调用点无需
    逐个传参，也不会因为漏传而失去限速。
    """
    global _default_interval
    _default_interval = max(0.0, float(seconds))


def set_burst(burst: int) -> None:
    """设置每个主机的突发请求上限。"""
    _rate_limiter.set_burst(burst)


def _build_session(retry: int, proxy: Optional[str], user_agent: str) -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=max(0, retry),
        backoff_factor=1,
        status_forcelist=_RETRY_STATUS,
        allowed_methods=_RETRY_METHODS,
        # 重试耗尽后返回响应而不是抛异常，否则会丢失真实状态码
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=8, pool_maxsize=16)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": user_agent})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.verify = True
    return session


def _session_for(retry: int, proxy: Optional[str], user_agent: str) -> requests.Session:
    """返回当前线程可复用的 Session。"""
    cache = getattr(_thread_local, "sessions", None)
    if cache is None:
        cache = {}
        _thread_local.sessions = cache
    key = (retry, proxy, user_agent)
    session = cache.get(key)
    if session is None:
        session = _build_session(retry, proxy, user_agent)
        cache[key] = session
    return session


def _read_body(response: requests.Response, max_body: int) -> tuple:
    """读取至多 max_body 字节的响应体，返回 (text, truncated)。"""
    request_method = response.request.method if response.request is not None else ""
    if max_body <= 0 or request_method in ("HEAD", "OPTIONS"):
        return "", False

    chunks = []
    size = 0
    truncated = False
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            size += len(chunk)
            if size >= max_body:
                chunks.append(chunk[: max_body - (size - len(chunk))])
                truncated = True
                break
            chunks.append(chunk)
    except requests.exceptions.RequestException:
        truncated = True

    raw = b"".join(chunks)
    encoding = response.encoding or "utf-8"
    try:
        return raw.decode(encoding, errors="replace"), truncated
    except LookupError:
        return raw.decode("utf-8", errors="replace"), truncated


def request_url(
        url: str,
        method: str = "HEAD",
        data: Optional[bytes] = None,
        files: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = 10,
        retry: int = 2,
        proxy: Optional[str] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        max_body: int = DEFAULT_MAX_BODY,
        min_interval: Optional[float] = None,
) -> Dict:
    """发起一次请求并归一化返回结果。

    返回字典始终包含 ``accessible``/``status_code``/``content_length``/
    ``content_type``/``headers``/``content``/``error``，另含
    ``body_truncated`` 与 ``elapsed_ms``。
    """
    session = _session_for(retry, proxy, user_agent)
    interval = _default_interval if min_interval is None else min_interval
    _rate_limiter.wait(urlparse(url).netloc, interval)

    started = time.monotonic()
    try:
        response = session.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=data,
            files=files,
            timeout=timeout,
            stream=True,
        )
        body, truncated = _read_body(response, max_body)
        result = {
            "accessible": response.status_code in (200, 201, 204, 302),
            "status_code": response.status_code,
            "content_length": int(response.headers.get("Content-Length", 0) or 0),
            "content_type": response.headers.get("Content-Type", ""),
            "headers": dict(response.headers),
            "content": body,
            "body_truncated": truncated,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": None,
        }
        response.close()
        return result
    except requests.exceptions.Timeout:
        return _error_result(-1, "请求超时", started)
    except requests.exceptions.ConnectionError:
        return _error_result(-2, "连接失败", started)
    except Exception as exc:  # 归一化所有异常，扫描不应因此中断
        return _error_result(-3, str(exc), started)


def _error_result(code: int, message: str, started: float) -> Dict:
    return {
        "accessible": False,
        "status_code": code,
        "content_length": 0,
        "content_type": "",
        "headers": {},
        "content": "",
        "body_truncated": False,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "error": message,
    }
