import argparse
import os
import time
import re
import requests
from typing import List, Dict, Tuple, Optional
from configparser import ConfigParser
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# 导入核心类和工具（新增HostID提取相关依赖）
from core.risk_analyzer import RiskLevel
from core.scanner_base import ScannerBase
from providers.aliyun_scanner import AliyunScanner
from providers.tencent_scanner import TencentScanner
from providers.huawei_scanner import HuaweiScanner
from providers.aws_scanner import AwsScanner
from utils.file_utils import load_bucket_list, load_ignore_list, save_results
from utils.hostid_extractor import extract_bucket_region_from_hostid
from utils.report_utils import generate_report
from utils.log_utils import init_logger, logger
from utils.alert_utils import send_alert
from colorama import Fore, Style, init  # 新增colorama导入（确保彩色输出）


def load_config(config_path: str = "config/config.ini") -> Dict:
    # 获取工具所在目录的绝对路径（关键修改1：使用工具目录而非当前工作目录）
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    config_abs_path = os.path.join(tool_dir, config_path)
    print(f"[DEBUG] 工具目录: {tool_dir}")
    print(f"[DEBUG] 配置文件绝对路径: {config_abs_path}")

    if not os.path.exists(config_abs_path):
        print(f"[ERROR] 配置文件不存在！路径: {config_abs_path}")
        raise FileNotFoundError(f"配置文件不存在: {config_abs_path}")
    print(f"[DEBUG] 配置文件存在，开始读取")

    config = ConfigParser()
    with open(config_abs_path, "r", encoding="utf-8") as f:
        config.read_file(f)

    config_dict = {}

    # 基础配置
    config_dict["request_timeout"] = int(config.get("DEFAULT", "request_timeout", fallback="10"))
    config_dict["request_interval"] = float(config.get("DEFAULT", "request_interval", fallback="1"))
    config_dict["max_retry"] = int(config.get("DEFAULT", "max_retry", fallback="2"))
    config_dict["user_agent"] = config.get("DEFAULT", "user_agent",
                                           fallback="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36")

    # 功能开关
    config_dict["https_only"] = config.get("DEFAULT", "https_only", fallback="false").lower() == "true"
    config_dict["scan_put_upload"] = config.get("DEFAULT", "scan_put_upload", fallback="false").lower() == "true"
    config_dict["scan_post_upload"] = config.get("DEFAULT", "scan_post_upload", fallback="false").lower() == "true"
    config_dict["scan_delete_perm"] = config.get("DEFAULT", "scan_delete_perm", fallback="false").lower() == "true"
    config_dict["scan_cors"] = config.get("DEFAULT", "scan_cors", fallback="false").lower() == "true"
    config_dict["scan_logs"] = config.get("DEFAULT", "scan_logs", fallback="false").lower() == "true"
    config_dict["scan_directory_traversal"] = config.get("DEFAULT", "scan_directory_traversal",
                                                         fallback="false").lower() == "true"
    config_dict["scan_sensitive_headers"] = config.get("DEFAULT", "scan_sensitive_headers",
                                                       fallback="false").lower() == "true"
    config_dict["scan_version_leak"] = config.get("DEFAULT", "scan_version_leak", fallback="false").lower() == "true"
    # 新增扫描Bucket策略和KMS加密的开关配置
    config_dict["scan_bucket_policy"] = config.get("DEFAULT", "scan_bucket_policy", fallback="false").lower() == "true"
    config_dict["scan_kms_encryption"] = config.get("DEFAULT", "scan_kms_encryption",
                                                    fallback="false").lower() == "true"

    # 新增：自动提取HostID的配置
    config_dict["AUTO_EXTRACT"] = {
        "hostid_url": config.get("AUTO_EXTRACT", "hostid_url", fallback=""),
        "timeout": int(config.get("AUTO_EXTRACT", "timeout", fallback="10")),
        "retry": int(config.get("AUTO_EXTRACT", "retry", fallback="2"))
    }

    # 其他section
    for section in config.sections():
        if section not in config_dict:  # 避免覆盖AUTO_EXTRACT
            config_dict[section] = dict(config[section])

    print("\n[DEBUG] 最终开关状态（强制读取后）:")
    print(f"  - scan_put_upload: {config_dict['scan_put_upload']}")
    print(f"  - scan_post_upload: {config_dict['scan_post_upload']}")
    print(f"  - scan_delete_perm: {config_dict['scan_delete_perm']}")
    print(f"  - scan_cors: {config_dict['scan_cors']}")
    print(f"  - scan_logs: {config_dict['scan_logs']}")
    print(f"  - scan_bucket_policy: {config_dict['scan_bucket_policy']}")  # 新增
    print(f"  - scan_kms_encryption: {config_dict['scan_kms_encryption']}")  # 新增
    print(f"  - 自动提取HostID默认网址: {config_dict['AUTO_EXTRACT']['hostid_url']}")  # 新增

    return config_dict


# -------------------------- 原有逻辑保留（无需修改） --------------------------
def init_scanner(cloud: str, bucket: str, region: str, config: Dict, appid: str = "") -> ScannerBase:
    scanner_map = {
        "aliyun": AliyunScanner,
        "tencent": lambda b, r, c: TencentScanner(b, r, c, appid=appid),
        "huawei": HuaweiScanner,
        "aws": AwsScanner
    }
    if cloud not in scanner_map:
        raise ValueError(f"不支持的云厂商: {cloud}")
    return scanner_map[cloud](bucket, region, config)


def scan_single_bucket(bucket: str, cloud: str, region: str, config: Dict, ignore_list: List[str], appid: str = "") -> \
        List[Dict]:
    if bucket in ignore_list:
        logger.info(f"Bucket {bucket} 在忽略列表中，跳过扫描")
        return []
    try:
        scanner = init_scanner(cloud, bucket, region, config, appid)
        results = scanner.run_scan()
        logger.info(f"Bucket {bucket} 扫描完成，发现 {len(results)} 个风险项")
        return results
    except Exception as e:
        logger.error(f"Bucket {bucket} 扫描失败: {str(e)}")
        return [{"risk": RiskLevel.ERROR, "msg": f"Bucket {bucket} 扫描失败: {str(e)}", "url": ""}]


# -------------------------- 主函数（关键修改3：参数解析与自动提取逻辑） --------------------------
def main():
    # 解析命令行参数（修改--region和--bucket为非必填，新增--hostid-url）
    parser = argparse.ArgumentParser(description="OSS存储桶漏洞扫描工具（支持多厂商/自动提取Bucket）")
    parser.add_argument("--cloud", required=True, choices=["aliyun", "tencent", "huawei", "aws"], help="目标云厂商")
    parser.add_argument("--region", help="存储桶区域（如阿里云：ap-southeast-1，未指定则自动提取）")  # 改为非必填
    parser.add_argument("--bucket", help="单个Bucket名称（未指定则自动提取）")  # 改为非必填
    parser.add_argument("--bucket-list", help="多个Bucket（逗号分隔，与--bucket/--bucket-file互斥）")
    parser.add_argument("--bucket-file", help="Bucket列表文件（与--bucket/--bucket-list互斥）")
    parser.add_argument("--tencent-appid", help="腾讯云APPID（可选）")
    parser.add_argument("--config", default="config/config.ini", help="配置文件路径（默认：config/config.ini）")
    parser.add_argument("--ignore-file", default="config/ignore_list.txt",
                        help="忽略列表文件（默认：config/ignore_list.txt）")
    parser.add_argument("--output", choices=["text", "json", "html"], default="text", help="输出格式（默认：text）")
    parser.add_argument("--output-file", help="结果保存路径（如：results.json）")
    parser.add_argument("--thread", type=int, default=5, help="扫描线程数（默认：5）")
    parser.add_argument("--progress", action="store_true", help="显示扫描进度条")
    parser.add_argument("--proxy", help="代理地址（如：http://127.0.0.1:8080）")
    parser.add_argument("--alert", choices=["dingtalk", "email"], help="严重漏洞告警方式（钉钉/邮件）")
    parser.add_argument("--hostid-url", help="用于提取HostID的目标网址（默认从配置读取）")  # 新增参数

    args = parser.parse_args()

    if args.hostid_url:
        import re
        # 根据云厂商匹配URL格式
        if args.cloud == "aliyun":
            # 阿里云URL格式：https://{bucket}.oss-{region}.aliyuncs.com
            pattern = r"^https?://([^.]+)\.oss-([^.]+)\.aliyuncs\.com"
            match = re.match(pattern, args.hostid_url)
            if match:
                args.bucket = match.group(1)  # 提取Bucket
                args.region = match.group(2)  # 提取Region（如cn-beijing）
            else:
                logger.error(f"阿里云URL格式错误！示例：https://bucket.oss-cn-beijing.aliyuncs.com")
                return
        elif args.cloud == "tencent":
            # 腾讯云URL格式：https://{bucket}.cos.{region}.myqcloud.com
            pattern = r"^https?://([^.]+)\.cos\.([^.]+)\.myqcloud\.com"
            match = re.match(pattern, args.hostid_url)
            if match:
                args.bucket = match.group(1)
                args.region = match.group(2)  # 如ap-guangzhou
            else:
                logger.error(f"腾讯云URL格式错误！示例：https://bucket.cos.ap-guangzhou.myqcloud.com")
                return
        elif args.cloud == "aws":
            # AWS S3 URL格式：https://{bucket}.s3-{region}.amazonaws.com
            pattern = r"^https?://([^.]+)\.s3-([^.]+)\.amazonaws\.com"
            match = re.match(pattern, args.hostid_url)
            if match:
                args.bucket = match.group(1)
                args.region = match.group(2)  # 如us-east-1
            else:
                logger.error(f"AWS URL格式错误！示例：https://bucket.s3-us-east-1.amazonaws.com")
                return
        elif args.cloud == "huawei":
            # 华为云URL格式：https://{bucket}.obs-{region}.myhuaweicloud.com
            pattern = r"^https?://([^.]+)\.obs-([^.]+)\.myhuaweicloud\.com"
            match = re.match(pattern, args.hostid_url)
            if match:
                args.bucket = match.group(1)
                args.region = match.group(2)  # 如cn-north-4
            else:
                logger.error(f"华为云URL格式错误！示例：https://bucket.obs-cn-north-4.myhuaweicloud.com")
                return
        else:
            logger.error(f"暂不支持{args.cloud}的URL解析，请手动指定--bucket和--region")
            return

        # 验证提取结果
        if not (args.bucket and args.region):
            logger.error("从URL中提取Bucket或Region失败，请检查URL格式")
            return
        logger.info(f"从URL提取成功：Bucket={args.bucket}，Region={args.region}")

    # 加载配置和忽略列表
    config = load_config(args.config)
    config["proxy"] = args.proxy

    # 关键修改2：配置自检逻辑
    if not config.get("scan_bucket_policy", False):
        logger.warning(f"{Fore.YELLOW}[警告] scan_bucket_policy未启用，可能无法检测Policy漏洞{Style.RESET_ALL}")

    ignore_list = load_ignore_list(args.ignore_file)

    # 处理Bucket和Region的来源（用户输入优先，否则自动提取）
    buckets = []
    region = args.region
    # 确定HostID提取的目标网址（命令行参数 > 配置文件）
    target_hostid_url = args.hostid_url or config["AUTO_EXTRACT"]["hostid_url"]

    if args.bucket or args.bucket_list or args.bucket_file:
        # 从用户输入加载Bucket
        buckets = load_bucket_list(args.bucket, args.bucket_list, args.bucket_file)
        if not region:
            logger.error("未指定--region，且未启用自动提取（需不提供任何Bucket参数）")
            return
    else:
        # 自动从HostID提取Bucket和Region
        if not target_hostid_url:
            logger.error("未指定--hostid-url且配置文件中未设置AUTO_EXTRACT.hostid_url")
            return
        try:
            extracted_bucket, extracted_region = extract_bucket_region_from_hostid(target_hostid_url, args.cloud)
            if not extracted_bucket or not extracted_region:
                raise ValueError("提取结果为空")
            buckets = [extracted_bucket]
            region = extracted_region
            logger.info(f"自动提取成功：Bucket={extracted_bucket}，Region={extracted_region}")
        except Exception as e:
            logger.error(f"自动提取失败：{str(e)}")
            logger.error("请手动通过--bucket和--region指定参数")
            return

    # 校验Bucket和Region有效性
    if not buckets:
        logger.error("未获取到有效Bucket列表")
        return
    if not region:
        logger.error("未获取到有效Region")
        return

    # 初始化日志
    init_logger(config["LOG_CONFIG"]["log_file"], config["LOG_CONFIG"]["log_level"])
    logger.info(f"开始扫描：云厂商={args.cloud}，区域={region}，Bucket数量={len(buckets)}，线程数={args.thread}")

    # 多线程扫描
    all_results = []
    with ThreadPoolExecutor(max_workers=args.thread) as executor:
        tasks = {
            executor.submit(scan_single_bucket, bucket, args.cloud, region, config, ignore_list, args.tencent_appid):
                bucket for bucket in buckets
        }
        progress_bar = tqdm(total=len(tasks), desc="扫描进度") if args.progress else None
        for future in as_completed(tasks):
            bucket = tasks[future]
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                logger.error(f"Bucket {bucket} 任务执行失败: {str(e)}")
            if progress_bar:
                progress_bar.update(1)
        if progress_bar:
            progress_bar.close()

    # 生成并保存报告
    report = generate_report(all_results, args.output, config)
    print(report)
    if args.output_file:
        save_results(all_results, args.output_file, args.output)
        logger.info(f"结果已保存到: {args.output_file}")

    # 严重漏洞告警
    if args.alert:
        critical_results = [r for r in all_results if r["risk"].name.startswith("CRITICAL")]
        if critical_results:
            send_alert(args.alert, critical_results, config)
            logger.info(f"已发送 {len(critical_results)} 个严重漏洞告警")

    # 扫描摘要
    logger.info("\n" + "=" * 40 + " 扫描摘要 " + "=" * 40)
    risk_count = {level: 0 for level in RiskLevel}
    for result in all_results:
        risk_count[result["risk"]] += 1

    risk_desc = {
        RiskLevel.CRITICAL1: "敏感密钥文件泄露",
        RiskLevel.CRITICAL2: "数据库备份泄露",
        RiskLevel.CRITICAL3: "匿名上传漏洞（PUT/POST）",
        RiskLevel.CRITICAL4: "匿名删除漏洞",
        RiskLevel.HIGH1: "公开可列目录",
        RiskLevel.HIGH2: "访问日志泄露",
        RiskLevel.MEDIUM1: "配置文件泄露",
        RiskLevel.MEDIUM2: "CORS配置过度宽松",
        RiskLevel.MEDIUM3: "目录遍历漏洞",
        RiskLevel.LOW1: "低风险文件泄露",
        RiskLevel.LOW2: "Bucket存在但不可访问",
        RiskLevel.LOW3: "敏感HTTP头泄露",
        RiskLevel.ERROR: "扫描错误"
    }

    high_risk_levels = [
        RiskLevel.CRITICAL1, RiskLevel.CRITICAL2, RiskLevel.CRITICAL3, RiskLevel.CRITICAL4,
        RiskLevel.HIGH1, RiskLevel.HIGH2,
        RiskLevel.MEDIUM1, RiskLevel.MEDIUM2, RiskLevel.MEDIUM3,
        RiskLevel.LOW1, RiskLevel.LOW2, RiskLevel.LOW3,
        RiskLevel.ERROR
    ]
    for level in high_risk_levels:
        count = risk_count[level]
        if count > 0:
            if level.name.startswith("CRITICAL"):
                logger.info(f"  {Fore.RED}[!] 严重: {risk_desc[level]}: {count} 项{Style.RESET_ALL}")
            elif level.name.startswith("HIGH"):
                logger.info(f"  {Fore.RED}[!] 高危: {risk_desc[level]}: {count} 项{Style.RESET_ALL}")
            elif level.name.startswith("MEDIUM"):
                logger.info(f"  {Fore.YELLOW}[!] 中危: {risk_desc[level]}: {count} 项{Style.RESET_ALL}")
            elif level.name.startswith("LOW"):
                logger.info(f"  {Fore.CYAN}[!] 低危: {risk_desc[level]}: {count} 项{Style.RESET_ALL}")
            elif level == RiskLevel.ERROR:
                logger.info(f"  {Fore.MAGENTA}[!] 错误: {risk_desc[level]}: {count} 项{Style.RESET_ALL}")

    logger.info(f"  {Fore.GREEN}[*] 信息: 总计扫描项: {len(all_results)} 项{Style.RESET_ALL}")
    logger.info("=" * 80)


if __name__ == "__main__":
    try:
        init(autoreset=True)

        tool_name = "OSS_Scanner"
        author = "sjdalu"
        version = "v1.0.3"  # 版本号更新
        description = "多厂商OSS存储桶漏洞扫描工具（支持自动提取Bucket/Region）"

        logo = f"""
{Fore.CYAN}   ____   ____   ____   ____  
  / ___| |  _ \ |  _ \ |  _ \ 
 | |  _  | |_) || | | || |_) |
 | |_| | |  __/ | |_| ||  _ < 
  \____| |_|    |____/ |_| \_\\
{Fore.YELLOW}==========================================  {tool_name} {version}  ==========================================
{Fore.GREEN}作者: {author: <60} 最后更新: 2025-10
{Fore.BLUE}功能: {description}
{Fore.YELLOW}=====================================================================================================
        """

        print(logo)

        print(f"\n{Fore.RED}{'⚠️  免责声明 ⚠️':^80}")
        print(f"{Fore.RED}{'=' * 80}")
        print(f"{Fore.RED}  1. 本工具仅用于合法授权的网络安全测试，严禁用于未授权的攻击行为！")
        print(f"{Fore.RED}  2. 使用本工具前，必须获得目标存储桶的书面授权，否则将承担法律责任。")
        print(f"{Fore.RED}  3. 作者不对使用本工具产生的任何后果负责，使用者需自行承担全部风险。")
        print(f"{Fore.RED}{'=' * 80}")

        input(f"\n{Fore.CYAN}[+] 请确认已满足上述条件，按回车键开始扫描（关闭窗口可终止）...{Style.RESET_ALL}")

        main()

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] 用户手动中断扫描")
        logger.info("用户中断扫描")
    except ImportError as e:
        print("=" * 80)
        print(f"{Fore.CYAN}   ____   ____   ____   ____  ")
        print(f"  / ___| |  _ \ |  _ \ |  _ \ ")
        print(f" | |  _  | |_) || | | || |_) |{Fore.RESET} OSS_Scanner {version}")
        print(f"{Fore.CYAN} | |_| | |  __/ | |_| ||  _ < ")
        print(f"  \____| |_|    |____/ |_| \_\\{Fore.RESET} 作者: {author}")
        print("=" * 80)
        print(f"\n⚠️  依赖缺失: {str(e)}，建议执行 'pip install -r requirements.txt'")
        print("\n⚠️  免责声明：本工具仅用于合法授权测试，滥用将承担法律责任！")
        input("\n请确认已获得授权，按回车键继续...")
        main()
    except Exception as e:
        print(f"\n{Fore.RED}[!] 程序异常退出: {str(e)}")
        logger.error(f"程序异常退出: {str(e)}")