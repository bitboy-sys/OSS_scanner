import requests
from typing import Dict, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def create_session(retry: int = 2, proxy: Optional[str] = None) -> requests.Session:
    """原有逻辑保留，不修改"""
    session = requests.Session()
    retry_strategy = Retry(
        total=retry,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "PUT", "POST", "DELETE"]  # 新增POST/PUT/DELETE
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.verify = True
    return session


def request_url(
        url: str,
        method: str = "HEAD",
        data: Optional[bytes] = None,
        files: Optional[Dict] = None,  # 新增：支持表单上传的files参数
        headers: Optional[Dict] = None,
        timeout: int = 10,
        retry: int = 2,
        proxy: Optional[str] = None
) -> Dict:
    """统一HTTP请求接口（新增files参数处理）"""
    session = create_session(retry, proxy)
    headers = headers or {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"}

    try:
        # 新增：处理files参数（表单上传）
        response = session.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=data,
            files=files,  # 传递表单数据
            timeout=timeout,
            stream=True
        )

        # 先读取需要的数据再关闭连接
        result = {
            "accessible": response.status_code in [200, 201, 204, 302],  # 新增204（DELETE成功无内容）
            "status_code": response.status_code,
            "content_length": int(response.headers.get("Content-Length", 0)),
            "content_type": response.headers.get("Content-Type", ""),
            "headers": dict(response.headers),
            "content": response.text,  # 修改：始终返回响应体内容
            "error": None
        }
        response.close()
        return result
    except requests.exceptions.Timeout:
        return {"accessible": False, "status_code": -1, "error": "请求超时", "content_length": 0, "content_type": "",
                "headers": {}, "content": ""}
    except requests.exceptions.ConnectionError:
        return {"accessible": False, "status_code": -2, "error": "连接失败", "content_length": 0, "content_type": "",
                "headers": {}, "content": ""}
    except Exception as e:
        return {"accessible": False, "status_code": -3, "error": str(e), "content_length": 0, "content_type": "",
                "headers": {}, "content": ""}