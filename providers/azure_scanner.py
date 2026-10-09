"""Azure Blob 存储扫描器。

Azure 的寻址模型与其他厂商不同：目标是「存储账户 + 容器」，因此构造 URL
需要 ``account`` 参数，未提供时无法确定地址。
"""
import uuid
from typing import Dict, List, Optional

from core.risk_analyzer import Risk
from core.scanner_base import ProviderSpec, ScannerBase
from utils.credentials import TemporaryCredential

SPEC = ProviderSpec(
    name="azure",
    display_name="Azure Blob",
    action_prefix="",
    list_element="EnumerationResults",
    list_queries=("?restype=container&comp=list&maxresults=10",),
    exists_status=(200, 403),
)

_BLOB_TEST_PREFIX = "azure_blob_test_"


class AzureScanner(ScannerBase):
    spec = SPEC

    def __init__(self, bucket: str, region: str, config: Dict, account: str = "",
                 credential: Optional[TemporaryCredential] = None):
        self.account = account
        super().__init__(bucket, region, config, credential)

    def _templates(self) -> List[str]:
        if not self.account:
            return []
        template = self.config.get("CLOUD_TEMPLATES", {}).get("azure_blob_url", "")
        if not template:
            return []
        return [template.format(account=self.account, container=self.bucket)]

    # ------------------------------------------------------------ 检查

    def scan_container_acl(self) -> None:
        """读取容器 ACL，判断是否开放了匿名公共访问。"""
        for base_url in self.target_urls():
            acl_url = f"{base_url}?restype=container&comp=acl"
            resp = self._request(acl_url, method="GET")
            if resp["status_code"] != 200:
                continue
            content = resp.get("content", "")
            # publicAccess 为 off 或缺省表示未开放匿名访问
            if "publicAccess" not in content:
                continue
            if "container" in content or "blob" in content:
                self.add_finding(
                    Risk.BLOB_PUBLIC_ACCESS,
                    f"容器开放了匿名公共访问: {acl_url}",
                    acl_url,
                    resp=resp,
                )
                return

    def scan_blob_public_access(self) -> None:
        """上传标记为私有的 Blob 后尝试匿名读取。"""
        if not self.intrusive_enabled:
            return
        test_file = f"{_BLOB_TEST_PREFIX}{uuid.uuid4()}.txt"
        for base_url in self.target_urls():
            blob_url = f"{base_url}/{test_file}"
            upload_resp = self._request(blob_url, method="PUT", data="azure_scan_test",
                                        headers={"x-ms-blob-public-access": "off",
                                                 "x-ms-blob-type": "BlockBlob"},
                                        retry=1)
            if upload_resp["status_code"] not in (200, 201):
                continue

            access_resp = self._request(blob_url, method="GET", retry=1)
            self._request(blob_url, method="DELETE", timeout=5)

            if access_resp["status_code"] == 200:
                self.add_finding(
                    Risk.BLOB_PUBLIC_ACCESS,
                    f"标记为私有的 Blob 仍可被匿名读取: {blob_url}",
                    blob_url,
                    resp=access_resp,
                )
                return

    # ------------------------------------------------------------ 流水线

    def scan_provider_specific(self) -> None:
        self.scan_container_acl()
        self._warn_blocked("scan_blob_public_access", "Blob 匿名公开访问检测")
        if self.intrusive_enabled and self.config.get("scan_blob_public_access", False):
            self.scan_blob_public_access()
