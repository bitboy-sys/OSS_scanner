"""华为云 OBS 扫描器。"""
from typing import List

from core.scanner_base import ProviderSpec, ScannerBase

SPEC = ProviderSpec(
    name="huawei",
    display_name="华为云 OBS",
    action_prefix="obs:",
    list_element="ListBucketResult",
    log_paths=("/obs-logs/", "/logs/", "/accesslog/"),
    meta_header_prefixes=("X-Obs-Meta-", "X-Obs-Storage-Class"),
    acl_public_markers=("AllUsers",),
    acl_authenticated_markers=("AuthenticatedUsers",),
    supports_referer=True,
)


class HuaweiScanner(ScannerBase):
    spec = SPEC

    def _templates(self) -> List[str]:
        template = self.config.get("CLOUD_TEMPLATES", {}).get("huawei_https", "")
        if not template:
            return []
        return [template.format(bucket=self.bucket, region=self.region)]
