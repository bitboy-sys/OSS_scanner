"""OSS 存储桶漏洞扫描工具 —— 命令行入口。"""
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from configparser import ConfigParser
from configparser import Error as ConfigError
from typing import Dict, List, Optional

from colorama import Fore, Style
from colorama import init as colorama_init
from tqdm import tqdm

from core.risk_analyzer import RISK_META, Risk, Severity
from core.scanner_base import ScannerBase, build_finding
from providers.aliyun_scanner import AliyunScanner
from providers.aws_scanner import AwsScanner
from providers.azure_scanner import AzureScanner
from providers.gcp_scanner import GcpScanner
from providers.huawei_scanner import HuaweiScanner
from providers.tencent_scanner import TencentScanner
from utils.ai_utils import (
    ALL_FEATURES,
    FEATURE_CLASSIFY,
    AIClient,
    AIConfig,
    apply_ai_passes,
)
from utils.alert_utils import send_alert
from utils.credentials import (
    ENV_ACCESS_KEY_ID,
    ENV_ACCESS_KEY_SECRET,
    ENV_SECURITY_TOKEN,
    TemporaryCredential,
    load_credential,
    validate_for_scan,
)
from utils.endpoint_parser import parse_endpoint
from utils.file_utils import load_bucket_list, load_ignore_list, save_results
from utils.hostid_extractor import extract_endpoint_from_page
from utils.http_utils import set_burst, set_default_interval
from utils.log_utils import init_logger, logger
from utils.report_utils import generate_report, summarize
from utils.signing import supported_providers
from version import __version__

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))

# 启用内容分级时提高证据采集长度，以便在更长的片段里发现凭据
CLASSIFY_EVIDENCE_LIMIT = 64 * 1024

SCANNERS = {
    "aliyun": AliyunScanner,
    "tencent": TencentScanner,
    "huawei": HuaweiScanner,
    "aws": AwsScanner,
    "gcp": GcpScanner,
    "azure": AzureScanner,
}

# 这些厂商的端点必须带区域；GCP / Azure 的寻址方式不同
REGION_REQUIRED = {"aliyun", "tencent", "huawei", "aws"}

_WRITE_CHECKS = (
    ("scan_put_upload", "匿名 PUT 上传"),
    ("scan_post_upload", "匿名 POST 上传"),
    ("scan_delete_perm", "匿名 DELETE"),
    ("scan_acl_write", "ACL 可写"),
    ("scan_acl_read", "ACL 可读"),
    ("scan_blob_public_access", "Blob 匿名公开访问"),
)

_BOOL_KEYS = (
    "https_only", "allow_intrusive_write",
    "scan_put_upload", "scan_post_upload", "scan_delete_perm",
    "scan_cors", "scan_logs", "scan_directory_traversal", "scan_sensitive_headers",
    "scan_version_leak", "scan_bucket_policy", "scan_kms_encryption",
    "scan_acl_write", "scan_acl_read", "scan_blob_public_access",
    "scan_website", "scan_referer", "scan_replication",
)

_INT_KEYS = {"request_timeout": 10, "max_retry": 2, "request_burst": 5}
_FLOAT_KEYS = {"request_interval": 0.3}

DEFAULT_CONFIG_PATH = os.path.join("config", "config.ini")


def _clean(value: str) -> str:
    """去掉首尾空白与包裹的引号。

    ConfigParser 不会剥离 ``key = ""`` 里的引号，直接用会把字面量 ``""``
    当成配置值（例如把 webhook 发到名为 ``""`` 的地址）。
    """
    text = (value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1].strip()
    return text


def load_config(config_path: str = DEFAULT_CONFIG_PATH, debug: bool = False) -> Dict:
    """读取配置文件并做类型归一化。

    路径按工具所在目录解析，因此从任意工作目录调用都可以。
    """
    config_abs_path = config_path if os.path.isabs(config_path) else os.path.join(TOOL_DIR, config_path)
    if not os.path.exists(config_abs_path):
        raise FileNotFoundError(f"配置文件不存在: {config_abs_path}")

    parser = ConfigParser(inline_comment_prefixes=("#", ";"))
    try:
        with open(config_abs_path, "r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except ConfigError as exc:
        # 同一节里重复填写同一个键时会走到这里；给出可读提示而不是 configparser 的原始堆栈
        raise ValueError(
            f"配置文件解析失败：{exc}。"
            f"通常是因为同一个节里重复填写了同一个配置项，请检查 {config_abs_path}"
        ) from exc

    default_keys = set(parser.defaults())
    config: Dict = {}

    for key in _BOOL_KEYS:
        config[key] = _clean(parser.get("DEFAULT", key, fallback="false")).lower() == "true"
    for key, fallback in _INT_KEYS.items():
        # fallback 必须传正确类型：ConfigParser 在选项缺失时原样返回 fallback，不做转换
        config[key] = parser.getint("DEFAULT", key, fallback=fallback)
    for key, fallback in _FLOAT_KEYS.items():
        config[key] = parser.getfloat("DEFAULT", key, fallback=fallback)
    config["user_agent"] = _clean(parser.get("DEFAULT", "user_agent", fallback=""))

    # 其余 section 只保留自己的键，避免 ConfigParser 把 DEFAULT 注入到每个 section
    for section in parser.sections():
        config[section] = {
            key: _clean(value)
            for key, value in parser.items(section)
            if key not in default_keys
        }

    auto_extract = config.setdefault("AUTO_EXTRACT", {})
    for key, fallback in (("timeout", 10), ("retry", 2)):
        try:
            auto_extract[key] = int(auto_extract.get(key) or fallback)
        except (TypeError, ValueError):
            auto_extract[key] = fallback

    unknown = sorted(set(parser.defaults()) - set(_BOOL_KEYS) - set(_INT_KEYS)
                     - set(_FLOAT_KEYS) - {"user_agent"})
    if unknown:
        logger.warning(f"配置文件 [DEFAULT] 中存在未被识别的键，已被忽略: {', '.join(unknown)}")

    if debug:
        logger.debug(f"配置路径: {config_abs_path}")
        logger.debug(f"请求间隔: {config['request_interval']}s 突发: {config['request_burst']}")
        logger.debug(f"写操作闸门 allow_intrusive_write: {config['allow_intrusive_write']}")

    return config


def init_scanner(cloud: str, bucket: str, region: str, config: Dict,
                 appid: str = "", account: str = "",
                 credential: Optional[TemporaryCredential] = None) -> ScannerBase:
    """按云厂商构造扫描器。"""
    if cloud not in SCANNERS:
        raise ValueError(f"不支持的云厂商: {cloud}")
    if cloud == "tencent":
        return TencentScanner(bucket, region, config, appid=appid, credential=credential)
    if cloud == "azure":
        return AzureScanner(bucket, region, config, account=account, credential=credential)
    return SCANNERS[cloud](bucket, region, config, credential=credential)


def scan_single_bucket(bucket: str, cloud: str, region: str, config: Dict,
                       ignore_list: List[str], appid: str = "", account: str = "",
                       credential: Optional[TemporaryCredential] = None) -> List[Dict]:
    """扫描单个 Bucket，异常时产出结构一致的错误结果。"""
    if bucket in ignore_list:
        logger.info(f"Bucket {bucket} 在忽略列表中，跳过扫描")
        return []
    try:
        scanner = init_scanner(cloud, bucket, region, config, appid, account, credential)
        results = scanner.run_scan()
        logger.info(f"Bucket {bucket} 扫描完成，发现 {len(results)} 个风险项")
        return results
    except Exception as exc:  # 单个 Bucket 失败不应中断整批扫描
        logger.error(f"Bucket {bucket} 扫描失败: {exc}")
        return [build_finding(Risk.SCAN_ERROR, f"Bucket {bucket} 扫描失败: {exc}",
                              "", bucket=bucket, cloud=cloud, region=region)]


def resolve_target(args, config: Dict) -> Optional[Dict]:
    """确定扫描目标（厂商 / Bucket / 区域 / 账户）。

    输入优先级：命令行 Bucket 参数 > 命令行端点 URL > 配置文件默认端点 URL。
    端点 URL 若本身就是存储地址则直接解析，否则当作网页抓取其中的 HostId。
    """
    cloud = args.cloud
    bucket = args.bucket
    region = args.region or ""
    account = args.account or ""
    appid = args.tencent_appid or ""

    if bucket or args.bucket_list or args.bucket_file:
        if not cloud:
            logger.error("使用 --bucket/--bucket-list/--bucket-file 时必须指定 --cloud")
            return None
        if cloud in REGION_REQUIRED and not region:
            logger.error(f"{cloud} 需要指定 --region（如 aliyun 的 ap-southeast-1、aws 的 us-east-1）")
            return None
        if cloud == "azure" and not account:
            logger.error("azure 需要同时指定 --account（存储账户名）与 --bucket（容器名）")
            return None
        return {"cloud": cloud, "buckets": load_bucket_list(bucket, args.bucket_list, args.bucket_file),
                "region": region, "account": account, "appid": appid}

    endpoint_url = args.endpoint_url or config.get("AUTO_EXTRACT", {}).get("hostid_url", "")
    if not endpoint_url:
        logger.error("未指定扫描目标：请提供 --bucket（配合 --cloud/--region）"
                     "或 --hostid-url / --endpoint-url 指定端点")
        return None

    timeout = int(config.get("AUTO_EXTRACT", {}).get("timeout", 10) or 10)
    try:
        endpoint = parse_endpoint(endpoint_url, cloud)
    except ValueError as direct_error:
        logger.info(f"未能直接解析为存储端点（{direct_error}），尝试抓取页面中的 HostId")
        try:
            endpoint = extract_endpoint_from_page(endpoint_url, cloud, timeout=timeout)
        except ValueError as page_error:
            logger.error(f"端点解析失败: {page_error}")
            return None

    logger.info(f"目标解析成功：厂商={endpoint.cloud} Bucket={endpoint.bucket} "
                f"区域={endpoint.region or '-'}")
    return {
        "cloud": endpoint.cloud,
        "buckets": [endpoint.bucket],
        "region": endpoint.region,
        "account": endpoint.account or account,
        "appid": endpoint.appid or appid,
    }


def print_startup_notices(config: Dict) -> None:
    """把会影响结果完整性的配置风险显式喊出来，避免结果被误读。"""
    if not config.get("allow_intrusive_write", False):
        enabled = [label for key, label in _WRITE_CHECKS if config.get(key, False)]
        if enabled:
            logger.warning(
                f"{Fore.YELLOW}[!] 写操作闸门已关闭（allow_intrusive_write = false），"
                f"以下检查会被跳过：{'、'.join(enabled)}{Style.RESET_ALL}"
            )
            logger.warning(
                f"{Fore.YELLOW}    这些检查需要向目标桶写入测试对象。确认已获授权后，"
                f"在配置中设置 allow_intrusive_write = true{Style.RESET_ALL}"
            )


def print_summary(results: List[Dict]) -> None:
    """按严重度分组打印风险项统计，标题取自 RISK_META。"""
    counts = summarize(results)
    by_risk: Dict[str, int] = {}
    for result in results:
        risk_id = result.get("risk_id", "")
        by_risk[risk_id] = by_risk.get(risk_id, 0) + 1

    grouped: Dict[Severity, List] = {}
    for risk_id, count in by_risk.items():
        try:
            meta = RISK_META[Risk(risk_id)]
        except (KeyError, ValueError):
            continue
        grouped.setdefault(meta.severity, []).append((meta.title, count))

    colors = {
        Severity.CRITICAL: Fore.RED,
        Severity.HIGH: Fore.RED,
        Severity.MEDIUM: Fore.YELLOW,
        Severity.LOW: Fore.CYAN,
        Severity.INFO: Fore.GREEN,
        Severity.ERROR: Fore.MAGENTA,
    }

    logger.info("=" * 40 + " 扫描摘要 " + "=" * 40)
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                     Severity.LOW, Severity.INFO, Severity.ERROR):
        entries = sorted(grouped.get(severity, []))
        for title, count in entries:
            logger.info(f"  {colors[severity]}[{severity.label}] {title}: {count} 项{Style.RESET_ALL}")
    logger.info(f"  {Fore.GREEN}[*] 合计: {counts['TOTAL']} 项"
                f"（严重 {counts['CRITICAL']} / 高危 {counts['HIGH']} / 中危 {counts['MEDIUM']} / "
                f"低危 {counts['LOW']} / 信息 {counts['INFO']} / 错误 {counts['ERROR']}）{Style.RESET_ALL}")
    logger.info("=" * 80)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OSS 存储桶漏洞扫描工具（多厂商）")
    parser.add_argument("--cloud", choices=sorted(SCANNERS), help="目标云厂商")
    parser.add_argument("--region", help="存储桶区域（如阿里云 ap-southeast-1、AWS us-east-1）")
    parser.add_argument("--bucket", help="单个 Bucket / 容器名称")
    parser.add_argument("--bucket-list", help="多个 Bucket（逗号分隔）")
    parser.add_argument("--bucket-file", help="Bucket 列表文件（每行一个）")
    parser.add_argument("--tencent-appid", help="腾讯云 APPID（可选）")
    parser.add_argument("--account", help="Azure 存储账户名（azure 厂商必填）")
    parser.add_argument("--sts-ak", help="临时凭证 AccessKeyId（也可用环境变量 "
                                        f"{ENV_ACCESS_KEY_ID}）")
    parser.add_argument("--sts-sk", help="临时凭证 AccessKeySecret（也可用环境变量 "
                                        f"{ENV_ACCESS_KEY_SECRET}）")
    parser.add_argument("--sts-token", help="临时凭证 SecurityToken（也可用环境变量 "
                                           f"{ENV_SECURITY_TOKEN}）")
    parser.add_argument("--sts-file", help="保存 STS 凭证的 JSON 文件（AssumeRole 响应原样即可）")
    parser.add_argument("--hostid-url", "--endpoint-url", dest="endpoint_url",
                        help="端点地址或含 <HostId> 的页面地址；缺省时读取配置 AUTO_EXTRACT.hostid_url")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="配置文件路径")
    parser.add_argument("--ignore-file", default=os.path.join("config", "ignore_list.txt"),
                        help="忽略列表文件")
    parser.add_argument("--output", choices=["text", "json", "html"], default="text", help="输出格式")
    parser.add_argument("--output-file", help="结果保存路径，例如 ./reports/scan.html")
    parser.add_argument("--thread", type=int, default=5, help="并发扫描的 Bucket 数（默认 5）")
    parser.add_argument("--progress", action="store_true", help="显示进度条")
    parser.add_argument("--proxy", help="代理地址，如 http://127.0.0.1:8080")
    parser.add_argument("--alert", choices=["dingtalk", "email"], help="严重漏洞告警方式")
    parser.add_argument("--no-poc", action="store_true",
                        help="报告中不生成可运行的 PoC 命令")
    parser.add_argument("--ai", choices=["off", *ALL_FEATURES, "all"],
                        help="AI 研判步骤；缺省时使用配置 [AI_CONFIG] features。"
                             "off 强制关闭，all 启用全部")
    parser.add_argument("--ai-provider", help="覆盖 AI 厂商预设，如 deepseek / ollama / dashscope")
    parser.add_argument("--ai-model", help="覆盖配置的 AI 模型名")
    parser.add_argument("--ai-base-url", help="覆盖配置的 AI 端点（需含版本路径，如 http://127.0.0.1:11434/v1）")
    parser.add_argument("--i-accept-ai-egress", action="store_true",
                        help="确认允许把目标信息发送到非本机 AI 端点")
    parser.add_argument("--debug", action="store_true", help="输出调试日志")
    return parser


def build_ai_client(args, config: Dict) -> AIClient:
    """按配置与命令行参数构造 AI 客户端。"""
    ai_config = AIConfig.from_config(config, tool_dir=TOOL_DIR)
    if args.ai_provider:
        from utils.ai_utils import PROVIDER_PRESETS
        preset = PROVIDER_PRESETS.get(args.ai_provider.strip().lower())
        if preset is None:
            logger.warning(f"未知的 AI 厂商预设: {args.ai_provider}，可选 "
                           f"{'、'.join(sorted(PROVIDER_PRESETS))}")
        else:
            ai_config.provider = args.ai_provider.strip().lower()
            ai_config.provider_label = preset.get("label", ai_config.provider)
            ai_config.base_url = preset.get("base_url", "") or ai_config.base_url
            ai_config.model = preset.get("model", "") or ai_config.model
    if args.ai_base_url:
        ai_config.base_url = args.ai_base_url.strip().rstrip("/")
    if args.ai_model:
        ai_config.model = args.ai_model.strip()

    if args.ai == "off":
        ai_config.enabled = False
    elif args.ai == "all":
        ai_config.enabled = True
        ai_config.features = tuple(ALL_FEATURES)
    elif args.ai:
        ai_config.enabled = True
        ai_config.features = (args.ai,)

    client = AIClient(ai_config, accept_egress=args.i_accept_ai_egress)
    if ai_config.enabled:
        if FEATURE_CLASSIFY in ai_config.features:
            config["evidence_limit"] = CLASSIFY_EVIDENCE_LIMIT
        key_hint = f"，密钥来自{ai_config.api_key_source}" if ai_config.api_key_source else ""
        logger.info(f"AI 研判已启用：厂商={ai_config.provider_label} 模型={ai_config.model} "
                    f"端点={'本机' if client.local else '远程'}{key_hint} "
                    f"步骤={'、'.join(ai_config.features)}")
    return client


def resolve_credential(args, config: Dict, cloud: str) -> Optional[TemporaryCredential]:
    """加载并校验临时凭证；返回 None 表示以匿名身份扫描。"""
    credential, error = load_credential(args, config, cloud)
    if error:
        logger.error(f"临时凭证不可用：{error}")
        return None
    if credential is None:
        return None

    if cloud and cloud not in supported_providers():
        logger.warning(f"{cloud} 暂不支持请求签名，临时凭证将被忽略，本次以匿名身份扫描")
        return None

    problem = validate_for_scan(credential, cloud, require_token=True)
    if problem:
        logger.error(f"临时凭证不可用：{problem}")
        return None

    if not credential.security_token:
        logger.warning("临时凭证未包含 SecurityToken，若目标强制校验临时凭证将返回鉴权失败")
    logger.info(credential.describe())
    return credential


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.config, debug=args.debug)
    except (FileNotFoundError, ValueError) as exc:
        print(f"{Fore.RED}[ERROR] {exc}{Style.RESET_ALL}")
        return 2

    config["proxy"] = args.proxy

    ignore_path = args.ignore_file
    if not os.path.isabs(ignore_path):
        ignore_path = os.path.join(TOOL_DIR, ignore_path)
    ignore_list = load_ignore_list(ignore_path)

    target = resolve_target(args, config)
    if target is None:
        return 2

    log_config = config.get("LOG_CONFIG", {})
    log_file = log_config.get("log_file", "oss_scan.log")
    if not os.path.isabs(log_file):
        log_file = os.path.join(TOOL_DIR, log_file)
    log_level = "DEBUG" if args.debug else log_config.get("log_level", "INFO")
    init_logger(log_file, log_level)

    # 全局按主机限速与突发容量
    set_default_interval(config["request_interval"])
    set_burst(config["request_burst"])

    buckets = target["buckets"]
    credential = resolve_credential(args, config, target["cloud"])
    auth_mode = "认证态" if credential else "匿名"

    logger.info(f"开始扫描：云厂商={target['cloud']} 区域={target['region'] or '-'} "
                f"Bucket 数量={len(buckets)} 并发={args.thread} 身份={auth_mode}")
    print_startup_notices(config)

    ai_client = build_ai_client(args, config)

    all_results: List[Dict] = []
    if buckets:
        with ThreadPoolExecutor(max_workers=max(1, args.thread)) as executor:
            futures = {
                executor.submit(scan_single_bucket, bucket, target["cloud"], target["region"],
                                config, ignore_list, target["appid"], target["account"],
                                credential): bucket
                for bucket in buckets
            }
            progress_bar = tqdm(total=len(futures), desc="扫描进度") if args.progress else None
            for future in as_completed(futures):
                bucket = futures[future]
                try:
                    all_results.extend(future.result())
                except Exception as exc:  # 兜底：任务本身失败
                    logger.error(f"Bucket {bucket} 任务执行失败: {exc}")
                if progress_bar:
                    progress_bar.update(1)
            if progress_bar:
                progress_bar.close()

    # AI 研判：只产出建议，失败不影响本地结果
    ai_outcome = apply_ai_passes(all_results, ai_client, context={
        "cloud": target["cloud"],
        "region": target["region"],
        "bucket_count": len(buckets),
    })
    ai_summary = ai_outcome.get("summary")
    annotated = ai_outcome.get("annotated", {})
    if annotated.get("analyze"):
        logger.info(f"AI 已研判 {annotated['analyze']} 条结果的误报可能性")
    if annotated.get("classify"):
        logger.info(f"AI 已识别 {annotated['classify']} 处泄露凭据")

    report = generate_report(all_results, args.output, config, ai_summary,
                             with_poc=not args.no_poc)
    print(report)
    if args.output_file:
        save_results(all_results, args.output_file, args.output, config, ai_summary,
                     with_poc=not args.no_poc)
        logger.info(f"结果已保存到: {args.output_file}")

    if args.alert:
        critical_results = [r for r in all_results if r.get("severity") == "CRITICAL"]
        if critical_results:
            send_alert(args.alert, critical_results, config)
            logger.info(f"已发送 {len(critical_results)} 项严重漏洞告警")

    print_summary(all_results)
    return 1 if any(r.get("severity") == "CRITICAL" for r in all_results) else 0


def _print_banner() -> None:
    tool_name = "OSS_Scanner"
    author = "sjdalu"
    description = "多厂商 OSS 存储桶漏洞扫描工具"
    print(f"""
{Fore.CYAN}   ____   ____   ____   ____
  / ___| |  _ \\ |  _ \\ |  _ \\
 | |  _  | |_) || | | || |_) |
 | |_| | |  __/ | |_| ||  _ <
  \\____| |_|    |____/ |_| \\_\\
{Fore.YELLOW}==========================================  {tool_name} {__version__}  ==========================================
{Fore.GREEN}作者: {author: <60} 最后更新: 2026-10
{Fore.BLUE}功能: {description}
{Fore.YELLOW}=====================================================================================================
        """)
    print(f"\n{Fore.RED}{'⚠️  免责声明 ⚠️':^80}")
    print(f"{Fore.RED}{'=' * 80}")
    print(f"{Fore.RED}  1. 本工具仅用于合法授权的网络安全测试，严禁用于未授权的攻击行为！")
    print(f"{Fore.RED}  2. 使用本工具前，必须获得目标存储桶的书面授权，否则将承担法律责任。")
    print(f"{Fore.RED}  3. 作者不对使用本工具产生的任何后果负责，使用者需自行承担全部风险。")
    print(f"{Fore.RED}{'=' * 80}")


if __name__ == "__main__":
    colorama_init(autoreset=True)
    _print_banner()
    input(f"\n{Fore.CYAN}[+] 请确认已满足上述条件，按回车键开始扫描（关闭窗口可终止）...{Style.RESET_ALL}")
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] 用户手动中断扫描")
        logger.info("用户中断扫描")
