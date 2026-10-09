"""GCP Cloud Storage 扫描器。"""
import uuid
from typing import List

from core.risk_analyzer import Risk
from core.scanner_base import ProviderSpec, ScannerBase

SPEC = ProviderSpec(
    name="gcp",
    display_name="GCP Cloud Storage",
    action_prefix="storage.",
    list_element="ListBucketResult",
    log_paths=("/logs/", "/accesslog/"),
    exists_status=(200, 403),
    acl_public_markers=("AllUsers",),
    acl_authenticated_markers=("AllAuthenticatedUsers",),
)

_ACL_TEST_PREFIX = "gcp_acl_test_"


class GcpScanner(ScannerBase):
    spec = SPEC

    def _templates(self) -> List[str]:
        template = self.config.get("CLOUD_TEMPLATES", {}).get("gcp_https", "")
        if not template:
            return []
        return [template.format(bucket=self.bucket)]

    # ------------------------------------------------------------ 写入类检查

    def scan_object_acl_writable(self) -> None:
        """检测对象 ACL 是否可匿名改为公开可读写。"""
        if not self.intrusive_enabled:
            return
        test_file = f"{_ACL_TEST_PREFIX}{uuid.uuid4()}.txt"
        for base_url in self.target_urls():
            upload_url = f"{base_url}/{test_file}"
            upload_resp = self._request(upload_url, method="PUT", data="gcp_scan_acl_test", retry=1)
            if upload_resp["status_code"] not in (200, 201):
                continue

            acl_url = f"{upload_url}?acl"
            acl_resp = self._request(acl_url, method="PUT",
                                     headers={"x-goog-acl": "public-read-write"}, retry=1)
            self._request(upload_url, method="DELETE", timeout=5)

            if acl_resp["status_code"] in (200, 201):
                self.add_finding(
                    Risk.ACL_WRITABLE,
                    f"对象 ACL 可匿名改为公开可读写: {acl_url}",
                    acl_url,
                    resp=acl_resp,
                )
                return

    def scan_bucket_acl_writable(self) -> None:
        """检测 Bucket ACL 是否可匿名改为公开可读写。"""
        if not self.intrusive_enabled:
            return
        for base_url in self.target_urls():
            acl_url = f"{base_url}/?acl"
            resp = self._request(acl_url, method="PUT",
                                 headers={"x-goog-acl": "public-read-write"}, retry=1)
            if resp["status_code"] in (200, 201):
                # 立即恢复为私有，避免把目标留在公开可写状态
                self._request(acl_url, method="PUT", headers={"x-goog-acl": "private"}, timeout=5)
                self.add_finding(
                    Risk.ACL_WRITABLE,
                    f"Bucket ACL 可匿名改为公开可读写: {acl_url}",
                    acl_url,
                    resp=resp,
                )
                return

    # ------------------------------------------------------------ 流水线

    def scan_provider_specific(self) -> None:
        self._warn_blocked("scan_acl_write", "对象/Bucket ACL 可写检测")
        if self.intrusive_enabled and self.config.get("scan_acl_write", False):
            self.scan_object_acl_writable()
            self.scan_bucket_acl_writable()
