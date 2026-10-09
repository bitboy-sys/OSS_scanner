"""阿里云 OSS 扫描器。

通用检查（敏感文件、访问日志、Bucket 策略、加密配置）由基类实现，这里只
保留阿里云特有的部分：明文 HTTP 访问、日志转存开关、以及需要写入目标桶的
对象 ACL 检查。
"""
import uuid
from typing import List

from core.risk_analyzer import Risk
from core.scanner_base import ProviderSpec, ScannerBase

SPEC = ProviderSpec(
    name="aliyun",
    display_name="阿里云 OSS",
    action_prefix="oss:",
    list_element="ListBucketResult",
    log_paths=("/oss-logs/", "/logs/", "/access-logs/", "/accesslog/"),
    meta_header_prefixes=("X-OSS-Meta-", "X-OSS-Storage-Class"),
    # 阿里云 Bucket ACL 直接以 Grant 文本回显访问级别
    acl_public_markers=("<Grant>public-read</Grant>", "<Grant>public-read-write</Grant>"),
    supports_referer=True,
)

_ACL_TEST_FILE_PREFIX = "oss_scan_acl_test_"


class AliyunScanner(ScannerBase):
    spec = SPEC

    def _templates(self) -> List[str]:
        template = self.config.get("CLOUD_TEMPLATES", {}).get("aliyun_https", "")
        if not template:
            return []
        return [template.format(bucket=self.bucket, region=self.region)]

    # ------------------------------------------------------------ 只读检查

    def scan_http_enabled(self) -> None:
        """检测是否仍允许明文 HTTP 访问。"""
        if self.config.get("https_only", False):
            return
        for base_url in self.target_urls():
            if not base_url.startswith("https://"):
                continue
            http_url = "http://" + base_url[len("https://"):]
            resp = self._request(http_url, method="HEAD", retry=1)
            if resp["status_code"] in (200, 403):
                self.add_finding(
                    Risk.HTTP_ENABLED,
                    f"Bucket 允许明文 HTTP 访问: {http_url}",
                    http_url,
                    resp=resp,
                )
                return

    def scan_logging_config(self) -> None:
        """检测访问日志转存是否开启。"""
        for base_url in self.target_urls():
            logging_url = f"{base_url}/?logging"
            resp = self._request(logging_url, method="GET")
            if resp["status_code"] == 200 and "LoggingEnabled" not in resp.get("content", ""):
                self.add_finding(
                    Risk.LOGGING_DISABLED,
                    f"Bucket 未开启访问日志转存: {logging_url}",
                    logging_url,
                    resp=resp,
                )
                return

    # ------------------------------------------------------------ 写入类检查

    def scan_object_acl_writable(self) -> None:
        """检测对象 ACL 是否可匿名改为公开可写。"""
        if not self.intrusive_enabled:
            return
        test_file = f"{_ACL_TEST_FILE_PREFIX}{uuid.uuid4()}.txt"
        for base_url in self.target_urls():
            upload_url = f"{base_url}/{test_file}"
            upload_resp = self._request(upload_url, method="PUT", data="oss_scan_acl_test", retry=1)
            if upload_resp["status_code"] not in (200, 201):
                continue

            acl_url = f"{upload_url}?acl"
            acl_resp = self._request(acl_url, method="PUT",
                                     headers={"x-oss-acl": "public-write"}, retry=1)
            self._request(upload_url, method="DELETE", timeout=5)

            if acl_resp["status_code"] in (200, 201):
                self.add_finding(
                    Risk.ACL_WRITABLE,
                    f"对象 ACL 可匿名改为公开可写: {acl_url}",
                    acl_url,
                    resp=acl_resp,
                )
                return

    def scan_object_acl_readable(self) -> None:
        """检测设为私有的对象是否仍可被匿名读取。"""
        if not self.intrusive_enabled:
            return
        test_file = f"{_ACL_TEST_FILE_PREFIX}{uuid.uuid4()}.txt"
        for base_url in self.target_urls():
            upload_url = f"{base_url}/{test_file}"
            upload_resp = self._request(upload_url, method="PUT", data="oss_scan_acl_test",
                                        headers={"x-oss-acl": "private"}, retry=1)
            if upload_resp["status_code"] not in (200, 201):
                continue

            read_resp = self._request(upload_url, method="GET", retry=1)
            self._request(upload_url, method="DELETE", timeout=5)

            if read_resp["status_code"] == 200:
                self.add_finding(
                    Risk.ACL_READABLE,
                    f"私有 ACL 对象仍可被匿名读取: {upload_url}",
                    upload_url,
                    resp=read_resp,
                )
                return

    # ------------------------------------------------------------ 流水线

    def scan_provider_specific(self) -> None:
        self.scan_http_enabled()
        self.scan_logging_config()
        self._warn_blocked("scan_acl_write", "对象 ACL 可写检测")
        self._warn_blocked("scan_acl_read", "对象 ACL 可读检测")
        if not self.intrusive_enabled:
            return
        if self.config.get("scan_acl_write", False):
            self.scan_object_acl_writable()
        if self.config.get("scan_acl_read", False):
            self.scan_object_acl_readable()
