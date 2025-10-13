from abc import ABC, abstractmethod
from typing import List, Dict
import uuid
import time
from utils.log_utils import logger
from utils.http_utils import request_url
from core.risk_analyzer import RiskLevel


class ScannerBase(ABC):
    def __init__(self, bucket: str, region: str, config: Dict):
        self.bucket = bucket
        self.region = region
        self.config = config  # 从config.ini加载的配置
        self.base_urls = self._get_base_urls()  # 生成HTTP/HTTPS基础URL
        self.results = []  # 扫描结果存储

    @abstractmethod
    def _get_base_urls(self) -> List[str]:
        """生成当前厂商的基础URL列表（支持HTTP/HTTPS、带/不带APPID等）"""
        pass

    @abstractmethod
    def check_bucket_exist(self) -> bool:
        """检测Bucket是否存在"""
        pass

    def check_bucket_permission(self) -> None:
        """检测Bucket权限（列目录、匿名上传、CORS等）"""
        logger.info(f"[Bucket: {self.bucket}] 开始检测权限配置...")
        logger.info(f"[Bucket: {self.bucket}] 开关状态：")
        logger.info(f"  - 检测PUT上传: {self.config.get('scan_put_upload', False)}")
        logger.info(f"  - 检测POST上传: {self.config.get('scan_post_upload', False)}")
        logger.info(f"  - 检测DELETE权限: {self.config.get('scan_delete_perm', False)}")
        logger.info(f"  - 检测CORS: {self.config.get('scan_cors', False)}")
        logger.info(f"  - 检测日志泄露: {self.config.get('scan_logs', False)}")
        logger.info(f"  - 检测目录遍历: {self.config.get('scan_directory_traversal', False)}")
        logger.info(f"  - 检测敏感HTTP头: {self.config.get('scan_sensitive_headers', False)}")
        logger.info(f"  - 检测Bucket策略: {self.config.get('scan_bucket_policy', False)}")
        logger.info(f"  - 检测KMS加密: {self.config.get('scan_kms_encryption', False)}")

        # 1. 检测列目录权限
        logger.info(f"[Bucket: {self.bucket}] → 正在检测是否允许列目录")
        self._check_list_permission()

        # 2. 检测匿名PUT上传
        if self.config.get("scan_put_upload", False):
            logger.info(f"[Bucket: {self.bucket}] → 正在检测匿名PUT上传漏洞")
            self._check_anonymous_upload()

        # 3. 检测匿名POST上传
        if self.config.get("scan_post_upload", False):
            logger.info(f"[Bucket: {self.bucket}] → 正在检测匿名POST上传漏洞")
            self._check_post_upload()

        # 4. 检测DELETE权限
        if self.config.get("scan_delete_perm", False):
            logger.info(f"[Bucket: {self.bucket}] → 正在检测匿名DELETE权限")
            self._check_delete_permission()

        # 5. 检测CORS配置
        if self.config.get("scan_cors", False):
            logger.info(f"[Bucket: {self.bucket}] → 正在检测CORS配置是否过宽")
            self._check_cors()

        # 6. 检测访问日志泄露
        if self.config.get("scan_logs", False):
            logger.info(f"[Bucket: {self.bucket}] → 正在检测访问日志泄露")
            self._check_log_leak()

        # 7. 检测目录遍历
        if self.config.get("scan_directory_traversal", False):
            logger.info(f"[Bucket: {self.bucket}] → 正在检测目录遍历漏洞")
            self._check_directory_traversal()

        # 8. 检测敏感HTTP头
        if self.config.get("scan_sensitive_headers", False):
            logger.info(f"[Bucket: {self.bucket}] → 正在检测敏感HTTP头泄露")
            self._check_sensitive_headers()

        logger.info(f"[Bucket: {self.bucket}] 权限配置检测完成")

    def _check_list_permission(self) -> None:
        """检测是否允许列目录"""
        for base_url in self.base_urls:
            root_url = f"{base_url}/"
            resp = request_url(
                root_url,
                method="HEAD",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["accessible"] and "xml" in resp.get("content_type", ""):
                self.results.append({
                    "risk": RiskLevel.HIGH1,
                    "msg": f"Bucket公开可列目录: {root_url}",
                    "url": root_url
                })
                return

    def _check_anonymous_upload(self) -> None:
        """检测是否允许匿名PUT上传"""
        test_file = f"oss_scan_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            upload_url = f"{base_url}/{test_file}"
            resp = request_url(
                upload_url,
                method="PUT",
                data="oss_scan_test_content",
                timeout=self.config["request_timeout"],
                retry=1
            )
            if resp["status_code"] in [200, 201]:
                request_url(upload_url, method="DELETE", timeout=5)
                self.results.append({
                    "risk": RiskLevel.CRITICAL3,
                    "msg": f"Bucket允许匿名PUT上传: {upload_url}",
                    "url": upload_url
                })
                return

    def _check_post_upload(self) -> None:
        """检测是否允许匿名POST表单上传"""
        test_file = f"oss_scan_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            upload_url = f"{base_url}/"
            files = {"file": (test_file, "oss_scan_test_content", "text/plain")}
            resp = request_url(
                upload_url,
                method="POST",
                files=files,
                timeout=self.config["request_timeout"],
                retry=1
            )
            if resp["status_code"] in [200, 201]:
                request_url(f"{base_url}/{test_file}", method="DELETE", timeout=5)
                self.results.append({
                    "risk": RiskLevel.CRITICAL3,
                    "msg": f"Bucket允许匿名POST上传: {upload_url}",
                    "url": upload_url
                })
                return

    def _check_delete_permission(self) -> None:
        """检测是否允许匿名DELETE文件"""
        test_file = f"oss_scan_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            file_url = f"{base_url}/{test_file}"
            upload_resp = request_url(
                file_url,
                method="PUT",
                data="test",
                timeout=self.config["request_timeout"]
            )
            if upload_resp["status_code"] not in [200, 201]:
                continue
            delete_resp = request_url(
                file_url,
                method="DELETE",
                timeout=self.config["request_timeout"]
            )
            if delete_resp["status_code"] in [200, 204]:
                self.results.append({
                    "risk": RiskLevel.CRITICAL4,
                    "msg": f"Bucket允许匿名DELETE: {file_url}",
                    "url": file_url
                })
                return

    def _check_cors(self) -> None:
        """检测CORS配置是否过度宽松"""
        for base_url in self.base_urls:
            resp = request_url(
                base_url,
                method="OPTIONS",
                headers={"Origin": "https://malicious.com"},
                timeout=self.config["request_timeout"]
            )
            allow_origin = resp.get("headers", {}).get("Access-Control-Allow-Origin", "")
            allow_methods = resp.get("headers", {}).get("Access-Control-Allow-Methods", "")
            if allow_origin == "*" and (("PUT" in allow_methods) or ("POST" in allow_methods)):
                self.results.append({
                    "risk": RiskLevel.MEDIUM2,
                    "msg": f"Bucket CORS过度宽松（允许所有域名+上传方法）: {base_url}",
                    "url": base_url
                })
                return

    def _check_log_leak(self) -> None:
        """检测访问日志泄露"""
        log_paths = [
            "/logs/", "/accesslog/", "/oss-logs/",
            "/cos-logs/", "/tencent-logs/",
            "/s3-logs/", "/aws-logs/"
        ]
        for path in log_paths:
            for base_url in self.base_urls:
                log_url = f"{base_url}{path}"
                resp = request_url(
                    log_url,
                    method="HEAD",
                    timeout=self.config["request_timeout"],
                    retry=1
                )
                if resp["accessible"]:
                    self.results.append({
                        "risk": RiskLevel.HIGH2,
                        "msg": f"访问日志泄露: {log_url}",
                        "url": log_url
                    })
                    return

    def _check_directory_traversal(self) -> None:
        """检测目录遍历漏洞"""
        test_paths = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "../windows/system32/drivers/etc/hosts",
            "../secret.txt"
        ]
        for path in test_paths:
            for base_url in self.base_urls:
                traversal_url = f"{base_url}/{path}"
                resp = request_url(
                    traversal_url,
                    method="GET",
                    timeout=self.config["request_timeout"],
                    retry=1
                )
                if resp["status_code"] == 200 and "root:" in resp.get("content", ""):
                    self.results.append({
                        "risk": RiskLevel.MEDIUM3,
                        "msg": f"目录遍历漏洞（可访问系统文件）: {traversal_url}",
                        "url": traversal_url
                    })
                    return

    def _check_sensitive_headers(self) -> None:
        """检测敏感HTTP头泄露"""
        sensitive_prefixes = [
            "X-OSS-Meta-", "X-Amz-Meta-", "X-Cos-Meta-", "X-Obs-Meta-",
            "X-OSS-Storage-Class", "X-Amz-Storage-Class"
        ]
        for base_url in self.base_urls:
            resp = request_url(
                base_url,
                method="HEAD",
                timeout=self.config["request_timeout"],
                retry=1
            )
            for header in resp.get("headers", {}):
                if any(header.startswith(prefix) for prefix in sensitive_prefixes):
                    self.results.append({
                        "risk": RiskLevel.LOW3,
                        "msg": f"敏感HTTP头泄露（{header}）: {base_url}",
                        "url": base_url
                    })
                    return

    @abstractmethod
    def scan_sensitive_files(self) -> None:
        """扫描敏感文件"""
        pass

    @abstractmethod
    def scan_access_logs(self) -> None:
        """扫描访问日志泄露"""
        pass

    @abstractmethod
    def scan_bucket_policy(self) -> None:
        """扫描Bucket策略配置漏洞"""
        pass

    @abstractmethod
    def scan_encryption_config(self) -> None:
        """扫描加密配置漏洞"""
        pass

    def run_scan(self) -> List[Dict]:
        """执行完整扫描流程"""
        logger.info(f"="*50)
        logger.info(f"[Bucket: {self.bucket}] 开始完整扫描")
        logger.info(f"[Bucket: {self.bucket}] 目标区域: {self.region}")
        logger.info(f"[Bucket: {self.bucket}] 基础URL: {self.base_urls}")
        logger.info(f"="*50)

        # 1. 检测Bucket是否存在
        logger.info(f"[Bucket: {self.bucket}] 第一步：检测Bucket是否存在")
        if not self.check_bucket_exist():
            self.results.append({
                "risk": RiskLevel.LOW1,
                "msg": f"Bucket不存在: {self.bucket}",
                "url": self.base_urls[0] if self.base_urls else ""
            })
            logger.warning(f"[Bucket: {self.bucket}] Bucket不存在，扫描终止")
            return self.results
        logger.info(f"[Bucket: {self.bucket}] Bucket存在，继续扫描")

        # 2. 检测权限配置
        logger.info(f"[Bucket: {self.bucket}] 第二步：检测Bucket权限配置")
        self.check_bucket_permission()

        # 3. 扫描敏感文件
        logger.info(f"[Bucket: {self.bucket}] 第三步：扫描敏感文件")
        self.scan_sensitive_files()

        # 4. 扫描访问日志（厂商特有）
        if self.config.get("scan_logs", False):
            logger.info(f"[Bucket: {self.bucket}] 第四步：扫描访问日志泄露（厂商特有）")
            self.scan_access_logs()

        # 5. 扫描Bucket策略（新增）
        if self.config.get("scan_bucket_policy", False):
            logger.info(f"[Bucket: {self.bucket}] 第五步：扫描Bucket策略配置（厂商特有）")
            self.scan_bucket_policy()

        # 6. 扫描加密配置（新增）
        if self.config.get("scan_kms_encryption", False):
            logger.info(f"[Bucket: {self.bucket}] 第六步：扫描加密配置（厂商特有）")
            self.scan_encryption_config()

        # 扫描结束
        logger.info(f"="*50)
        logger.info(f"[Bucket: {self.bucket}] 完整扫描结束")
        logger.info(f"[Bucket: {self.bucket}] 共发现 {len(self.results)} 个风险项")
        logger.info(f"="*50)

        return self.results