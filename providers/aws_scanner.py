import time
import uuid
from core.scanner_base import ScannerBase
from typing import List, Dict
from utils.http_utils import request_url
from core.risk_analyzer import RiskLevel
from utils.log_utils import logger


class AwsScanner(ScannerBase):
    def _get_base_urls(self) -> List[str]:
        """生成AWS S3基础URL"""
        urls = []
        https_url = self.config["CLOUD_TEMPLATES"].get("aws_https", "").format(
            bucket=self.bucket, region=self.region
        )

        if not self.config.get("https_only", False):
            http_url = self.config["CLOUD_TEMPLATES"].get("aws_http", "").format(
                bucket=self.bucket, region=self.region
            )
            if http_url:
                urls.append(http_url)

        if https_url:
            urls.append(https_url)
        return urls

    def check_bucket_exist(self) -> bool:
        """检测AWS S3 Bucket是否存在"""
        for base_url in self.base_urls:
            resp = request_url(
                base_url,
                method="HEAD",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 404:
                continue
            elif resp["status_code"] in [200, 403, 302]:
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

    def scan_access_logs(self) -> None:
        """扫描访问日志泄露"""
        log_paths = ["/logs/", "/s3-logs/"]
        for log_path in log_paths:
            for base_url in self.base_urls:
                log_url = f"{base_url}{log_path}"
                resp = request_url(
                    log_url,
                    method="HEAD",
                    timeout=self.config["request_timeout"],
                    retry=self.config["max_retry"]
                )
                if resp["accessible"]:
                    self.results.append({
                        "risk": RiskLevel.MEDIUM2,
                        "msg": f"发现访问日志泄露: {log_url}",
                        "url": log_url
                    })
                time.sleep(self.config["request_interval"])

    def scan_bucket_policy(self) -> None:
        """检测AWS Bucket策略配置漏洞"""
        for base_url in self.base_urls:
            policy_url = f"{base_url}/?policy"
            resp = request_url(
                policy_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200:
                policy_content = resp.get("content", "")
                # 检测是否存在过度宽松的策略
                if "Effect\": \"Allow" in policy_content and "Principal\": \"*" in policy_content:
                    # 检测是否包含危险操作权限
                    if any(action in policy_content for action in ["s3:PutObject", "s3:DeleteObject", "s3:PutObjectAcl"]):
                        self.results.append({
                            "risk": RiskLevel.CRITICAL2,
                            "msg": f"AWS Bucket存在高危宽松策略（允许匿名写入/删除）: {policy_url}",
                            "url": policy_url
                        })
                    else:
                        self.results.append({
                            "risk": RiskLevel.MEDIUM2,
                            "msg": f"AWS Bucket存在宽松策略（允许匿名读取）: {policy_url}",
                            "url": policy_url
                        })

    def scan_encryption_config(self) -> None:
        """检测AWS S3加密配置漏洞"""
        for base_url in self.base_urls:
            encryption_url = f"{base_url}/?encryption"
            resp = request_url(
                encryption_url,
                method="GET",
                headers={"x-amz-request-payer": "requester"},
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200:
                content = resp.get("content", "")
                # 检测是否未启用服务端加密
                if "ServerSideEncryptionConfiguration" not in content:
                    self.results.append({
                        "risk": RiskLevel.HIGH2,
                        "msg": f"AWS S3 Bucket未启用服务端加密: {encryption_url}",
                        "url": encryption_url
                    })
                # 检测是否使用KMS但未使用自定义密钥
                elif "KMS" in content and "KMSMasterKeyID" in content and "customer" not in content.lower():
                    self.results.append({
                        "risk": RiskLevel.MEDIUM3,
                        "msg": f"AWS S3 Bucket使用KMS加密但未使用CMK（客户主密钥）: {encryption_url}",
                        "url": encryption_url
                    })