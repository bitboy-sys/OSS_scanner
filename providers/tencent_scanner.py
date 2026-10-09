"""腾讯云 COS 扫描器。"""
from typing import Dict, List, Optional

from core.scanner_base import ProviderSpec, ScannerBase
from utils.credentials import TemporaryCredential

SPEC = ProviderSpec(
    name="tencent",
    display_name="腾讯云 COS",
    action_prefix="cos:",
    list_element="ListBucketResult",
    log_paths=("/cos-logs/", "/tencent-logs/", "/accesslog/", "/logs/"),
    meta_header_prefixes=("X-Cos-Meta-", "X-Cos-Storage-Class"),
    # COS 的公共授权项固定为 qcs::cam::anyone:anyone
    acl_public_markers=("anyone:anyone",),
    supports_referer=True,
)


class TencentScanner(ScannerBase):
    spec = SPEC

    def __init__(self, bucket: str, region: str, config: Dict, appid: str = "",
                 credential: Optional[TemporaryCredential] = None):
        self.appid = appid
        super().__init__(bucket, region, config, credential)

    def _templates(self) -> List[str]:
        templates = self.config.get("CLOUD_TEMPLATES", {})
        forms = []
        if self.appid and templates.get("tencent_http"):
            forms.append(templates["tencent_http"].format(
                bucket=self.bucket, appid=self.appid, region=self.region))
        if templates.get("tencent_http_no_appid"):
            forms.append(templates["tencent_http_no_appid"].format(
                bucket=self.bucket, region=self.region))
        # 配置模板以 http:// 书写，统一转成 https 形式交由基类展开
        return [form.replace("http://", "https://") for form in forms if form]
