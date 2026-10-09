"""AWS S3 扫描器。"""
from typing import List

from core.scanner_base import ProviderSpec, ScannerBase

SPEC = ProviderSpec(
    name="aws",
    display_name="AWS S3",
    action_prefix="s3:",
    list_element="ListBucketResult",
    log_paths=("/s3-logs/", "/aws-logs/", "/logs/", "/accesslog/"),
    meta_header_prefixes=("X-Amz-Meta-", "X-Amz-Storage-Class"),
    custom_key_hint="customer",
    region_header="x-amz-bucket-region",
    acl_public_markers=("AllUsers",),
    acl_authenticated_markers=("AuthenticatedUsers",),
    # S3 对未开启加密返回 404，对未授权返回 403，都说明对象存在
    extra_headers={"x-amz-request-payer": "requester"},
)


class AwsScanner(ScannerBase):
    spec = SPEC

    def _templates(self) -> List[str]:
        template = self.config.get("CLOUD_TEMPLATES", {}).get("aws_https", "")
        if not template:
            return []
        return [template.format(bucket=self.bucket, region=self.region)]
