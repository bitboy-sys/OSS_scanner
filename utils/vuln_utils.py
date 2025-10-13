import requests
import uuid

def check_put_upload(bucket_url, timeout=10):
    """检测PUT匿名上传漏洞"""
    test_filename = f"oss_scan_test_{uuid.uuid4()}.txt"
    url = f"{bucket_url}/{test_filename}"
    data = b"oss_scan_test_content"
    try:
        resp = requests.put(url, data=data, timeout=timeout)
        if resp.status_code in [200, 201]:
            requests.delete(url, timeout=5)  # 清理
            return True, url
        return False, None
    except Exception:
        return False, None


def check_post_upload(bucket_url, timeout=10):
    """检测POST表单上传漏洞"""
    test_filename = f"oss_scan_test_{uuid.uuid4()}.txt"
    url = f"{bucket_url}/"
    files = {"file": (test_filename, b"oss_scan_test_content")}
    try:
        resp = requests.post(url, files=files, timeout=timeout)
        if resp.status_code in [200, 201]:
            requests.delete(f"{bucket_url}/{test_filename}", timeout=5)
            return True, url
        return False, None
    except Exception:
        return False, None


def check_delete_permission(bucket_url, timeout=10):
    """检测DELETE权限"""
    test_filename = f"oss_scan_test_{uuid.uuid4()}.txt"
    url = f"{bucket_url}/{test_filename}"
    requests.put(url, data=b"test", timeout=timeout)
    try:
        resp = requests.delete(url, timeout=timeout)
        if resp.status_code in [200, 204]:
            return True, url
        return False, None
    except Exception:
        return False, None


def check_cors(bucket_url, timeout=10):
    """检测CORS配置是否过宽"""
    headers = {"Origin": "https://evil.com"}
    try:
        resp = requests.options(bucket_url, headers=headers, timeout=timeout)
        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        allow_methods = resp.headers.get("Access-Control-Allow-Methods", "")
        if allow_origin == "*" and ("PUT" in allow_methods or "POST" in allow_methods):
            return True
        return False
    except Exception:
        return False


def check_log_leak(bucket_url, timeout=10):
    """检测访问日志泄露"""
    log_paths = ["/logs/", "/accesslog/", "/oss-logs/", "/cos-logs/", "/s3-logs/"]
    for path in log_paths:
        try:
            resp = requests.head(f"{bucket_url}{path}", timeout=timeout)
            if resp.status_code == 200:
                return True, f"{bucket_url}{path}"
        except Exception:
            continue
    return False, None


def check_directory_traversal(bucket_url, timeout=10):
    """检测目录遍历漏洞"""
    test_paths = ["../../etc/passwd", "../../../etc/passwd", "../secret.txt"]
    for path in test_paths:
        try:
            resp = requests.get(f"{bucket_url}/{path}", timeout=timeout)
            if resp.status_code == 200 and "root:" in resp.text:
                return True, f"{bucket_url}/{path}"
        except Exception:
            continue
    return False, None


def check_sensitive_headers(bucket_url, timeout=10):
    """检测敏感HTTP头"""
    try:
        resp = requests.head(bucket_url, timeout=timeout)
        sensitive_prefixes = ["X-OSS-Meta-", "X-Amz-Meta-", "X-OSS-Storage-Class", "X-Amz-Storage-Class"]
        for h in resp.headers:
            if any(h.startswith(p) for p in sensitive_prefixes):
                return True, h
        return False, None
    except Exception:
        return False, None