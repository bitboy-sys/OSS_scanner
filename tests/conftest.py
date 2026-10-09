"""测试公共设施：一个可编程的本地「假 OSS 服务」。

不访问真实网络，也不产生对外的写入。服务会记录收到的每一个请求，便于断言
「默认配置下不应发生写操作」。
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """静默预期的连接中断。

        扫描器会带上响应体上限并提前关闭连接，服务端会看到 ConnectionAborted，
        这属于正常情况，不应刷屏。
        """


class FakeBucketServer:
    """按 (method, path) 注册响应的极简 HTTP 服务。"""

    def __init__(self):
        self.routes = {}
        self.requests = []
        self.request_headers = []   # 每个请求的头，用于断言签名/令牌是否下发
        self.payloads = []          # POST/PUT 的请求体原文，用于断言脱敏
        self.ai_calls = 0
        self._server = _QuietServer(("127.0.0.1", 0), _Handler)
        self._server.routes = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def route(self, method: str, path: str, status: int = 200,
              body: str = "", content_type: str = "application/xml", **headers):
        payload = body.encode("utf-8")
        all_headers = {"Content-Type": content_type, "Content-Length": str(len(payload))}
        all_headers.update(headers)
        self.routes[(method.upper(), path)] = (status, all_headers, payload)
        return self

    def base_url(self, path: str = "/bucket") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def ai_base_url(self) -> str:
        """OpenAI 兼容端点（含版本路径）。"""
        return f"http://127.0.0.1:{self.port}/v1"

    def route_ai(self, content: str, status: int = 200):
        """注册 /v1/chat/completions，返回给定的 content 字符串。"""
        import json as _json

        envelope = {"choices": [{"message": {"role": "assistant", "content": content}}]}
        return self.route("POST", "/v1/chat/completions", status=status,
                          body=_json.dumps(envelope), content_type="application/json")

    def methods_used(self):
        return [method for method, _ in self.requests]

    def ai_payloads(self):
        """返回所有发往 chat/completions 的请求体（已解码）。"""
        import json as _json

        decoded = []
        for payload in self.payloads:
            try:
                decoded.append(_json.loads(payload))
            except ValueError:
                decoded.append({})
        return decoded

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _dispatch(self, method: str):
        fake = self.server.routes
        fake.requests.append((method, self.path))
        fake.request_headers.append({k.lower(): v for k, v in self.headers.items()})
        if method in ("POST", "PUT"):
            self._drain(fake)
            if self.path.startswith("/v1/chat/completions"):
                fake.ai_calls += 1

        entry = fake.routes.get((method, self.path))
        if entry is None:
            entry = fake.routes.get((method, self.path.split("?")[0]))
        if entry is None:
            # 通配兜底，便于匹配带随机后缀的测试对象路径
            entry = fake.routes.get((method, "*")) or fake.routes.get(("*", self.path))
        send_body = True
        if entry is None and method == "HEAD":
            # HEAD 复用 GET 的路由，但只发头部
            entry = fake.routes.get(("GET", self.path))
            if entry is None:
                entry = fake.routes.get(("GET", self.path.split("?")[0]))
            send_body = False

        if entry is None:
            payload = b"<Error><Code>NoSuchKey</Code></Error>"
            self.send_response(404)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(payload)
            return

        status, headers, payload = entry
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if send_body and method != "HEAD" and payload:
            self.wfile.write(payload)

    def _drain(self, fake=None):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return
        raw = self.rfile.read(length)
        if fake is not None:
            fake.payloads.append(raw.decode("utf-8", errors="replace"))

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_GET(self):
        self._dispatch("GET")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_OPTIONS(self):
        self._dispatch("OPTIONS")

    def log_message(self, *args):
        """静默，避免污染测试输出。"""


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """限速器是进程级全局状态，每个用例前后都复位，避免相互影响。"""
    from utils.http_utils import set_burst, set_default_interval

    set_default_interval(0)
    set_burst(5)
    yield
    set_default_interval(0)
    set_burst(5)


@pytest.fixture
def fake_bucket():
    server = FakeBucketServer()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def base_config(fake_bucket):
    """指向假服务的最小配置。"""
    return {
        "request_timeout": 5,
        "request_interval": 0,
        "request_burst": 5,
        "max_retry": 0,
        "user_agent": "oss-scanner-test",
        # 假服务只有 HTTP。https_only=True 只用于阻止基类额外推导 http 变体，
        # 这样 base_urls 恰好就是下面模板给出的那一个地址。
        "https_only": True,
        "allow_intrusive_write": False,
        "scan_put_upload": True,
        "scan_post_upload": True,
        "scan_delete_perm": True,
        "scan_cors": True,
        "scan_logs": True,
        "scan_directory_traversal": True,
        "scan_sensitive_headers": True,
        "scan_bucket_policy": True,
        "scan_kms_encryption": True,
        "scan_acl_write": True,
        "scan_acl_read": True,
        "scan_blob_public_access": True,
        "scan_version_leak": True,
        "scan_website": True,
        "scan_referer": True,
        "scan_replication": True,
        "proxy": None,
        "CLOUD_TEMPLATES": {
            "aliyun_https": fake_bucket.base_url("/{bucket}"),
        },
        "SENSITIVE_PATHS": {
            "key_paths": ".env, credentials.json, id_rsa",
            "db_paths": "db.bak, backup/database.sql",
            "config_paths": "wp-config.php",
            "log_paths": "logs/app.log",
            "src_paths": "src.zip",
        },
        "LOG_CONFIG": {"log_file": "test.log", "log_level": "CRITICAL"},
        "ALERT_CONFIG": {},
        "AUTO_EXTRACT": {"hostid_url": "", "timeout": 5, "retry": 0},
    }
