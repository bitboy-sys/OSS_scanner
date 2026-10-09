"""Bucket 列表、忽略列表与结果落盘。"""
import os
from typing import Dict, List, Optional


def load_bucket_list(bucket: Optional[str], bucket_list: Optional[str], bucket_file: Optional[str]) -> List[str]:
    """加载 Bucket 列表（去重，保持首次出现顺序）。"""
    buckets = []
    if bucket:
        buckets.append(bucket.strip())
    if bucket_list:
        buckets.extend([b.strip() for b in bucket_list.split(",") if b.strip()])
    if bucket_file:
        with open(bucket_file, "r", encoding="utf-8") as handle:
            buckets.extend([line.strip() for line in handle if line.strip()])
    return list(dict.fromkeys(buckets))


def load_ignore_list(file_path: str) -> List[str]:
    """加载忽略列表，文件不存在时返回空列表。"""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def save_results(results: List[Dict], file_path: str, output_format: str,
                 config: Optional[Dict] = None, ai_summary: Optional[Dict] = None,
                 with_poc: bool = True) -> None:
    """保存扫描结果。

    统一走 :func:`utils.report_utils.generate_report`，避免落盘内容与终端
    输出各自实现一套而逐渐不一致。
    """
    from utils.report_utils import generate_report

    content = generate_report(results, output_format, config or {}, ai_summary, with_poc)
    parent = os.path.dirname(os.path.abspath(file_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(content)
