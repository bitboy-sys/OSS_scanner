import time
import uuid
from core.scanner_base import ScannerBase
from typing import List, Dict
from utils.http_utils import request_url
from core.risk_analyzer import RiskLevel
from utils.log_utils import logger


class AzureScanner(ScannerBase):
    def __init__(self, bucket: str, region: str, config: Dict, account: str = ""):
        self.account = account  # Azure存储账户名
        super().__init__(bucket, region, config)

    def _get_base_urls(self) -> List[str]:
        """生成Azure Blob存储基础URL"""
        urls = []
        if not self.account:
            return urls

        # Azure Blob URL格式: https://{account}.blob.core.windows.net/{container}
        template = self.config["CLOUD_TEMPLATES"].get("azure_blob_url", "").format(
            account=self.account, container=self.bucket
        )

        if not self.config.get("https_only", False):
            urls.append(template.replace("https://", "http://"))
        urls.append(template)
        return urls

    def check_bucket_exist(self) -> bool:
        """检测Azure Container是否存在"""
        for base_url in self.base_urls:
            resp = request_url(
                base_url,
                method="HEAD",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            # Azure存储账户不存在会返回400，容器不存在返回404
            if resp["status_code"] == 404:
                continue
            elif resp["status_code"] in [200, 403]:
                return True
        return False

    def scan_sensitive_files(self) -> None:
        """扫描敏感文件"""
        sensitive_paths = []
        for path_key in ["key_paths", "db_paths", "config_paths", "log_paths", "src_paths"]:
            sensitive_paths.extend(self.config["SENSITIVE_PATHS"][path_key].split(","))

        for path in sensitive_paths:
            path = path.strip()
            for base_url in self.base_urls:
                file_url = f"{base_url}/{path}"
                resp = request_url(
                    file_url,
                    method="HEAD",
                    timeout=self.config["request_timeout"],
                    retry=self.config["max_retry"]
                )
                if resp["accessible"]:
                    if path in self.config["SENSITIVE_PATHS"]["key_paths"].split(","):
                        risk = RiskLevel.CRITICAL1
                    elif path in self.config["SENSITIVE_PATHS"]["db_paths"].split(","):
                        risk = RiskLevel.CRITICAL2
                    else:
                        risk = RiskLevel.MEDIUM1 if path in self.config["SENSITIVE_PATHS"]["config_paths"].split(
                            ",") else RiskLevel.LOW1

                    self.results.append({
                        "risk": risk,
                        "msg": f"发现敏感文件（{risk.name}）: {file_url} | 大小: {resp['content_length'] / 1024 / 1024:.2f}MB",
                        "url": file_url
                    })
                time.sleep(self.config["request_interval"])

    def scan_blob_public_access(self) -> None:
        """59 Azure Blob公开访问"""
        test_file = f"azure_blob_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            blob_url = f"{base_url}/{test_file}"
            # 上传时设置私有
            upload_resp = request_url(
                blob_url,
                method="PUT",
                data="test_blob_content",
                headers={"x-ms-blob-public-access": "off"},
                timeout=self.config["request_timeout"],
                retry=1
            )
            if upload_resp["status_code"] not in [200, 201]:
                continue

            # 尝试匿名访问
            access_resp = request_url(
                blob_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=1
            )
            request_url(blob_url, method="DELETE", timeout=5)

            if access_resp["status_code"] == 200:
                self.results.append({
                    "risk": RiskLevel.MEDIUM1,
                    "msg": f"Azure Blob存在公开访问漏洞: {blob_url}",
                    "url": blob_url
                })
                return

    def scan_container_traversal(self) -> None:
        """60 Azure Container Blob遍历"""
        if not self.config.get("scan_directory_traversal", False):
            return

        for base_url in self.base_urls:
            # 列出Blob
            list_url = f"{base_url}?restype=container&comp=list&maxresults=10"
            resp = request_url(
                list_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200 and "EnumerationResults" in resp.get("content", ""):
                self.results.append({
                    "risk": RiskLevel.HIGH1,
                    "msg": f"Azure Container存在Blob遍历漏洞: {list_url}",
                    "url": list_url
                })
                return

    def run_scan(self) -> List[Dict]:
        """执行完整扫描流程"""
        logger.info(f"[Azure Container: {self.bucket}] 开始扫描")
        self.results = []

        if not self.check_bucket_exist():
            self.results.append({
                "risk": RiskLevel.LOW1,
                "msg": f"Azure Container不存在: {self.bucket}",
                "url": self.base_urls[0] if self.base_urls else ""
            })
            return self.results

        self.check_bucket_permission()
        self.scan_sensitive_files()

        # 新增漏洞扫描
        self.scan_blob_public_access()
        self.scan_container_traversal()

        logger.info(f"[Azure Container: {self.bucket}] 扫描完成，发现{len(self.results)}个风险项")
        return self.results