import time
from core.scanner_base import ScannerBase
from typing import List, Dict
from utils.http_utils import request_url
from core.risk_analyzer import RiskLevel
from utils.log_utils import logger
import uuid


class AliyunScanner(ScannerBase):
    def _get_base_urls(self) -> List[str]:
        """生成阿里云基础URL（支持HTTP/HTTPS）"""
        urls = []
        # 按配置决定是否添加HTTP/HTTPS
        if not self.config.get("https_only", False):
            urls.append(self.config["CLOUD_TEMPLATES"]["aliyun_http"].format(
                bucket=self.bucket, region=self.region
            ))
        urls.append(self.config["CLOUD_TEMPLATES"]["aliyun_https"].format(
            bucket=self.bucket, region=self.region
        ))
        return urls

    def check_bucket_exist(self) -> bool:
        """检测阿里云Bucket是否存在（404=不存在，403=存在但无权限）"""
        for base_url in self.base_urls:
            resp = request_url(
                base_url,
                method="HEAD",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 404:
                return False
            elif resp["status_code"] in [200, 403, 302]:
                return True
        return False

    def scan_sensitive_files(self) -> None:
        """扫描敏感文件（从配置加载路径）"""
        sensitive_paths = []
        # 从config.ini加载所有敏感路径
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
                    # 根据路径类型判定风险等级
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
                time.sleep(self.config["request_interval"])  # 遵守请求间隔

    def scan_access_logs(self) -> None:
        """扫描阿里云OSS访问日志泄露（厂商特有路径：/oss-logs/、/logs/）"""
        aliyun_log_paths = ["/oss-logs/", "/logs/", "/access-logs/"]  # 阿里云常见日志路径
        for log_path in aliyun_log_paths:
            for base_url in self.base_urls:
                log_url = f"{base_url}{log_path}"
                time.sleep(self.config["request_interval"])  # 遵守请求间隔
                resp = request_url(
                    log_url,
                    method="HEAD",
                    timeout=self.config["request_timeout"],
                    retry=self.config["max_retry"]
                )
                if resp["accessible"]:
                    self.results.append({
                        "risk": RiskLevel.HIGH2,
                        "msg": f"阿里云OSS访问日志泄露: {log_url}",
                        "url": log_url
                    })
                    return  # 找到一个即可，避免重复

    def scan_arbitrary_upload(self) -> None:
        """检测阿里云对象存储任意文件上传漏洞"""
        if not self.config.get("scan_put_upload", False):
            return

        test_file = f"aliyun_scan_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            upload_url = f"{base_url}/{test_file}"
            resp = request_url(
                upload_url,
                method="PUT",
                data="aliyun_scan_test_content",
                timeout=self.config["request_timeout"],
                retry=1
            )
            if resp["status_code"] in [200, 201]:
                # 清理测试文件
                request_url(upload_url, method="DELETE", timeout=5)
                self.results.append({
                    "risk": RiskLevel.CRITICAL3,
                    "msg": f"阿里云对象存储允许任意文件上传: {upload_url}",
                    "url": upload_url
                })
                return

    def scan_object_traversal(self) -> None:
        """检测阿里云对象存储Bucket对象遍历漏洞"""
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
                    "msg": f"阿里云Bucket存在对象遍历漏洞: {list_url}",
                    "url": list_url
                })
                return

    def scan_object_acl_writable(self) -> None:
        """检测阿里云Object ACL可写漏洞"""
        test_file = f"aliyun_acl_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            # 先上传测试文件
            upload_url = f"{base_url}/{test_file}"
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
            headers = {"x-oss-acl": "public-write"}
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
                    "msg": f"阿里云Object ACL可写: {acl_url}",
                    "url": acl_url
                })
                return

    def scan_object_acl_readable(self) -> None:
        """检测阿里云Object ACL可读漏洞"""
        test_file = f"aliyun_acl_test_{uuid.uuid4()}.txt"
        for base_url in self.base_urls:
            upload_url = f"{base_url}/{test_file}"
            # 上传文件时设置私有ACL
            headers = {"x-oss-acl": "private"}
            upload_resp = request_url(
                upload_url,
                method="PUT",
                data="test_acl_content",
                headers=headers,
                timeout=self.config["request_timeout"],
                retry=1
            )
            if upload_resp["status_code"] not in [200, 201]:
                continue

            # 尝试匿名读取
            read_resp = request_url(
                upload_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=1
            )
            # 清理测试文件
            request_url(upload_url, method="DELETE", timeout=5)

            if read_resp["status_code"] == 200:
                self.results.append({
                    "risk": RiskLevel.MEDIUM1,
                    "msg": f"阿里云Object ACL可读: {upload_url}",
                    "url": upload_url
                })
                return

    def scan_bucket_public_access(self) -> None:
        """检测阿里云Bucket公开访问漏洞"""
        for base_url in self.base_urls:
            resp = request_url(
                base_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200 and "ListBucketResult" in resp.get("content", ""):
                self.results.append({
                    "risk": RiskLevel.HIGH1,
                    "msg": f"阿里云Bucket存在公开访问漏洞: {base_url}",
                    "url": base_url
                })
                return

    def scan_bucket_policy_readable(self) -> None:
        """检测阿里云Bucket策略可读漏洞"""
        for base_url in self.base_urls:
            policy_url = f"{base_url}/?policy"
            resp = request_url(
                policy_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200 and "Statement" in resp.get("content", ""):
                self.results.append({
                    "risk": RiskLevel.MEDIUM2,
                    "msg": f"阿里云Bucket策略可读: {policy_url}",
                    "url": policy_url
                })
                return

    def scan_http_enabled(self) -> None:
        """检测阿里云Bucket HTTP访问开启漏洞"""
        if self.config.get("https_only", False):
            return

        for base_url in self.base_urls:
            if base_url.startswith("http://"):
                resp = request_url(
                    base_url,
                    method="HEAD",
                    timeout=self.config["request_timeout"],
                    retry=1
                )
                if resp["status_code"] in [200, 403]:
                    self.results.append({
                        "risk": RiskLevel.LOW2,
                        "msg": f"阿里云Bucket允许HTTP访问: {base_url}",
                        "url": base_url
                    })
                    return

    def scan_special_policy(self) -> None:
        """检测阿里云特殊Bucket策略漏洞"""
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
                if "Effect\": \"Allow" in policy_content and "Principal\": \"*" in policy_content:
                    self.results.append({
                        "risk": RiskLevel.HIGH2,
                        "msg": f"阿里云Bucket存在过度宽松策略: {policy_url}",
                        "url": policy_url
                    })
                    return

    def scan_logging_not_enabled(self) -> None:
        """检测阿里云Bucket日志转存未开启漏洞"""
        for base_url in self.base_urls:
            logging_url = f"{base_url}/?logging"
            resp = request_url(
                logging_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200 and "LoggingEnabled" not in resp.get("content", ""):
                self.results.append({
                    "risk": RiskLevel.MEDIUM3,
                    "msg": f"阿里云Bucket日志转存未开启: {logging_url}",
                    "url": logging_url
                })
                return

    def scan_encryption_not_kms(self) -> None:
        """检测阿里云Bucket服务端加密未使用KMS漏洞"""
        for base_url in self.base_urls:
            encryption_url = f"{base_url}/?encryption"
            resp = request_url(
                encryption_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200:
                content = resp.get("content", "")
                if "ServerSideEncryptionConfiguration" in content and "KMS" not in content:
                    self.results.append({
                        "risk": RiskLevel.MEDIUM3,
                        "msg": f"阿里云Bucket服务端加密未使用KMS: {encryption_url}",
                        "url": encryption_url
                    })
                    return

    def scan_encryption_not_byok(self) -> None:
        """检测阿里云Bucket服务端加密未使用BYOK漏洞"""
        for base_url in self.base_urls:
            encryption_url = f"{base_url}/?encryption"
            resp = request_url(
                encryption_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200:
                content = resp.get("content", "")
                if "KMSMasterKeyID" in content and "byok" not in content.lower():
                    self.results.append({
                        "risk": RiskLevel.LOW3,
                        "msg": f"阿里云Bucket服务端加密未使用BYOK: {encryption_url}",
                        "url": encryption_url
                    })
                    return

    def scan_bucket_policy(self) -> None:
        """检测阿里云Bucket策略配置漏洞"""
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
                    # 1. 检测是否允许获取Policy（新增逻辑）
                    if "oss:GetBucketPolicy" in policy_content:
                        self.results.append({
                            "risk": RiskLevel.HIGH2,  # 提升风险等级
                            "msg": f"阿里云Bucket允许匿名获取Policy配置: {policy_url}",
                            "url": policy_url
                        })
                    # 2. 检测是否包含危险操作权限（原有逻辑）
                    elif any(action in policy_content for action in
                             ["oss:PutObject", "oss:DeleteObject", "oss:PutObjectAcl"]):
                        self.results.append({
                            "risk": RiskLevel.CRITICAL2,
                            "msg": f"阿里云Bucket存在高危宽松策略（允许匿名写入/删除）: {policy_url}",
                            "url": policy_url
                        })
                    # 3. 其他允许匿名访问的情况（原有逻辑）
                    else:
                        self.results.append({
                            "risk": RiskLevel.MEDIUM2,
                            "msg": f"阿里云Bucket存在宽松策略（允许匿名读取）: {policy_url}",
                            "url": policy_url
                        })
                # 检测是否存在未限制IP的管理员权限
                elif "Effect\": \"Allow" in policy_content and "AdministratorAccess" in policy_content and "Condition" not in policy_content:
                    self.results.append({
                        "risk": RiskLevel.HIGH1,
                        "msg": f"阿里云Bucket策略存在未限制IP的管理员权限: {policy_url}",
                        "url": policy_url
                    })

    def scan_encryption_config(self) -> None:
        """检测阿里云Bucket加密配置漏洞"""
        for base_url in self.base_urls:
            encryption_url = f"{base_url}/?encryption"
            resp = request_url(
                encryption_url,
                method="GET",
                timeout=self.config["request_timeout"],
                retry=self.config["max_retry"]
            )
            if resp["status_code"] == 200:
                content = resp.get("content", "")
                # 检测是否未启用服务端加密
                if "ServerSideEncryptionConfiguration" not in content:
                    self.results.append({
                        "risk": RiskLevel.HIGH2,
                        "msg": f"阿里云Bucket未启用服务端加密: {encryption_url}",
                        "url": encryption_url
                    })
                # 检测是否使用KMS但未使用BYOK
                elif "KMS" in content and "KMSMasterKeyID" in content and "byok" not in content.lower():
                    self.results.append({
                        "risk": RiskLevel.MEDIUM3,
                        "msg": f"阿里云Bucket使用KMS加密但未使用BYOK（自定义密钥）: {encryption_url}",
                        "url": encryption_url
                    })
                # 检测是否使用AES-256而非KMS
                elif "AES256" in content and "KMS" not in content:
                    self.results.append({
                        "risk": RiskLevel.MEDIUM2,
                        "msg": f"阿里云Bucket使用AES-256加密而非更安全的KMS: {encryption_url}",
                        "url": encryption_url
                    })

    def run_scan(self) -> List[Dict]:
        """执行完整扫描流程"""
        logger.info(f"[阿里云Bucket: {self.bucket}] 开始扫描")
        self.results = []

        if not self.check_bucket_exist():
            self.results.append({
                "risk": RiskLevel.LOW1,
                "msg": f"阿里云Bucket不存在: {self.bucket}",
                "url": self.base_urls[0] if self.base_urls else ""
            })
            return self.results

        # 基础权限扫描
        self.check_bucket_permission()

        # 敏感文件扫描
        self.scan_sensitive_files()

        # 访问日志扫描
        if self.config.get("scan_logs", False):
            self.scan_access_logs()

        # 新增漏洞扫描
        self.scan_arbitrary_upload()
        self.scan_object_traversal()
        self.scan_object_acl_writable()
        self.scan_object_acl_readable()
        self.scan_bucket_public_access()
        self.scan_bucket_policy_readable()
        self.scan_http_enabled()
        self.scan_special_policy()
        self.scan_logging_not_enabled()
        self.scan_encryption_not_kms()
        self.scan_encryption_not_byok()
        # 新增抽象方法实现的调用
        if self.config.get("scan_bucket_policy", False):
            self.scan_bucket_policy()
        if self.config.get("scan_kms_encryption", False):
            self.scan_encryption_config()

        logger.info(f"[阿里云Bucket: {self.bucket}] 扫描完成，发现{len(self.results)}个风险项")
        return self.results