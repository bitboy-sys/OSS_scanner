from typing import List, Dict, Optional
import json

def load_bucket_list(bucket: Optional[str], bucket_list: Optional[str], bucket_file: Optional[str]) -> List[str]:
    """加载Bucket列表"""
    buckets = []
    if bucket:
        buckets.append(bucket.strip())
    if bucket_list:
        buckets.extend([b.strip() for b in bucket_list.split(",") if b.strip()])
    if bucket_file:
        with open(bucket_file, "r", encoding="utf-8") as f:
            buckets.extend([line.strip() for line in f if line.strip()])
    return list(dict.fromkeys(buckets))  # 去重

def load_ignore_list(file_path: str) -> List[str]:
    """加载忽略列表"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def save_results(results: List[Dict], file_path: str, output_format: str) -> None:
    """保存扫描结果到文件"""
    if output_format == "json":
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    elif output_format == "html":
        from utils.report_utils import generate_report
        html_content = generate_report(results, "html", {})
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    else:  # text
        with open(file_path, "w", encoding="utf-8") as f:
            for result in results:
                f.write(f"{result['risk']}: {result['msg']} ({result['url']})\n")