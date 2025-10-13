import time
import uuid
from core.scanner_base import ScannerBase
from typing import List, Dict
from utils.http_utils import request_url
from core.risk_analyzer import RiskLevel
from utils.log_utils import logger


class GcpScanner(ScannerBase):
    def _get_base_urls(self) -> List[str]:
        """生成GCP基础URL"""
        urls = []
        http_url = self.config["CLOUD_TEMPLATES"].get("gcp_http", "").format(
            bucket=self.bucket
        )
        https_url = self.config["CLOUD_TEMPLATES"].get("gcp_https", "").format(
            bucket=self.bucket
        )

        if not self.config.get("https_only", False) and http_url:
            urls.append(http_url)
        if https_url:
            urls.append(https_url)
        return urls

    def check_bucket_exist(self) -> bool:
        """检测GCP Bucket是否存在"""
        for base_url in self.base_urls:
            resp = request_url(
                base_url,
                method="HEAD",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
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

    def scan_arbitrary_upload(self) -> None:
        """54 GCP对象存储任意文件上传"""
        if not self.config.get("scan_put_upload", False):
            return

        test_file = f"gcp_upload_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            upload_url = f"{base_url}/{test_file}"
            resp = request_url(
                upload_url,
                method="PUT",
                data="gcp_scan_test_content",
                timeout=self.config["request_timeout"],
                retry=1
            )
            if resp["status_code"] in [200, 201]:
                request_url(upload_url, method="DELETE", timeout=5)
                self.results.append({
                    "risk": RiskLevel.CRITICAL3,
                    "msg": f"GCP对象存储允许任意文件上传: {upload_url}",
                    "url": upload_url
                })
                return

    def scan_object_acl_writable(self) -> None:
        """55 GCP Object ACL可写"""
        test_file = f"gcp_acl_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            upload_url = f"{base_url}/{test_file}"
            # 上传测试文件
            upload_resp = request_url(
                upload_url,
                method="PUT",
                data="test_acl_content",
                timeout=self.config["request_timeout"],
                retry=1
            )
            if upload_resp["status_code"] not in [200, 201]:
                continue

            # 尝试修改ACL为公开可写
            acl_url = f"{upload_url}?acl"
            headers = {"x-goog-acl": "public-read-write"}
            acl_resp = request_url(
                acl_url,
                method="PUT",
                headers=headers,
                timeout=self.config["request_timeout"],
                retry=1
            )
            # 清理测试文件
            request_url(upload_url, method="DELETE", timeout=5)

            if acl_resp["status_code"] in [200, 201]:
                self.results.append({
                    "risk": RiskLevel.HIGH2,
                    "msg": f"GCP Object ACL可写: {acl_url}",
                    "url": acl_url
                })
                return

    def scan_bucket_acl_writable(self) -> None:
        """56 GCP Bucket ACL可写"""
        for base_url in self.base_urls:
            acl_url = f"{base_url}/?acl"
            headers = {"x-goog-acl": "public-read-write"}
            resp = request_url(
                acl_url,
                method="PUT",
                headers=headers,
                timeout=self.config["request_timeout"],
                retry=1
            )
            if resp["status_code"] in [200, 201]:
                # 恢复私有ACL
                request_url(
                    acl_url,
                    method="PUT",
                    headers={"x-goog-acl": "private"},
                    timeout=5
                )
                self.results.append({
                    "risk": RiskLevel.HIGH2,
                    "msg": f"GCP Bucket ACL可写: {acl_url}",
                    "url": acl_url
                })
                return

    def scan_object_traversal(self) -> None:
        """57 GCP Bucket对象遍历"""
        if not self.config.get("scan_directory_traversal", False):
            return

        for base_url in self.base_urls:
            list_url = f"{base_url}/?delimiter=/&max-keys=10"
            resp = request_url(
                list_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200 and "ListBucketResult" in resp.get("content", ""):
                self.results.append({
                    "risk": RiskLevel.HIGH1,
                    "msg": f"GCP Bucket存在对象遍历漏洞: {list_url}",
                    "url": list_url
                })
                return

    def run_scan(self) -> List[Dict]:
        """执行完整扫描流程"""
        logger.info(f"[GCP Bucket: {self.bucket}] 开始扫描")
        self.results = []

        if not self.check_bucket_exist():
            self.results.append({
                "risk": RiskLevel.LOW1,
                "msg": f"GCP Bucket不存在: {self.bucket}",
                "url": self.base_urls[0] if self.base_urls else ""
            })
            return self.results

        self.check_bucket_permission()
        self.scan_sensitive_files()

        # 新增漏洞扫描
        self.scan_arbitrary_upload()
        self.scan_object_acl_writable()
        self.scan_bucket_acl_writable()
        self.scan_object_traversal()

        logger.info(f"[GCP Bucket: {self.bucket}] 扫描完成，发现{len(self.results)}个风险项")
        return self.results