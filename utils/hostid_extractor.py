# utils/hostid_extractor.py
import re
import requests
from typing import Tuple, Optional
from utils.log_utils import logger

def extract_bucket_region_from_hostid(url: str, cloud: str) -> Tuple[Optional[str], Optional[str]]:
    """
    从目标网址的 <HostId> 标签中提取 Bucket 和 Region
    :param url: 包含 HostID 的目标 URL
    :param cloud: 云厂商（aliyun/tencent/huawei/aws）
    :return: (bucket, region) 或 (None, None)
    """
    try:
        # 爬取目标网页内容
        resp = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
        )
        resp.raise_for_status()
        html_content = resp.text

        # 正则匹配 <HostId> 标签内容（兼容大小写和空格）
        hostid_match = re.search(r'<HostId>\s*(.*?)\s*</HostId>', html_content, re.IGNORECASE)
        if not hostid_match:
            raise ValueError("未在目标网页中找到 <HostId> 标签")

        hostid = hostid_match.group(1).strip()
        logger.info(f"提取到 HostID：{hostid}")

        # 根据云厂商解析 Bucket 和 Region
        if cloud == "aliyun":
            # 阿里云格式：<bucket>.oss-<region>.aliyuncs.com
            parts = hostid.split('.')
            if len(parts) >= 3 and parts[1].startswith("oss-"):
                bucket = parts[0]
                region = parts[1][4:]  # 去掉 "oss-" 前缀
                return bucket, region
            raise ValueError(f"阿里云 HostID 格式不正确：{hostid}")

        elif cloud == "tencent":
            # 腾讯云格式：<bucket>-<appid>.cos.<region>.myqcloud.com
            parts = hostid.split('.')
            if len(parts) >= 4 and parts[2] == "cos":
                bucket_with_appid = parts[0]
                bucket = bucket_with_appid.rsplit('-', 1)[0]  # 去掉 appid 部分
                region = parts[3]
                return bucket, region
            raise ValueError(f"腾讯云 HostID 格式不正确：{hostid}")

        elif cloud == "huawei":
            # 华为云格式：<bucket>.obs.<region>.myhuaweicloud.com
            parts = hostid.split('.')
            if len(parts) >= 3 and parts[1] == "obs":
                bucket = parts[0]
                region = parts[2]
                return bucket, region
            raise ValueError(f"华为云 HostID 格式不正确：{hostid}")

        elif cloud == "aws":
            # AWS 格式：<bucket>.s3.<region>.amazonaws.com
            parts = hostid.split('.')
            if len(parts) >= 4 and parts[1] == "s3":
                bucket = parts[0]
                region = parts[2]
                return bucket, region
            raise ValueError(f"AWS HostID 格式不正确：{hostid}")

        else:
            raise NotImplementedError(f"暂不支持 {cloud} 的 HostID 自动提取")

    except requests.exceptions.RequestException as e:
        raise ValueError(f"爬取目标网址失败：{str(e)}")
    except Exception as e:
        raise ValueError(f"解析 HostID 失败：{str(e)}")