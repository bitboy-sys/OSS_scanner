"""配置文件读取。"""
import pytest

import main as cli


def write(tmp_path, body):
    path = tmp_path / "config.ini"
    path.write_text(body, encoding="utf-8")
    return path.as_posix()


def test_quotes_are_stripped(tmp_path):
    """回归：ConfigParser 不剥离引号，`key = ""` 会变成字面量两个引号。"""
    path = write(tmp_path, '[DEFAULT]\nallow_intrusive_write = false\nuser_agent = "UA"\n\n'
                           '[ALERT_CONFIG]\ndingtalk_webhook = ""\nemail_to = \'a@b.c\'\n\n'
                           '[AUTO_EXTRACT]\nhostid_url = ""\ntimeout = 10\nretry = 2\n')
    config = cli.load_config(path)
    assert config["ALERT_CONFIG"]["dingtalk_webhook"] == ""
    assert config["ALERT_CONFIG"]["email_to"] == "a@b.c"
    assert config["AUTO_EXTRACT"]["hostid_url"] == ""
    assert config["user_agent"] == "UA"


def test_inline_comments_are_ignored(tmp_path):
    """README 文档里的写法带行尾注释，必须能正确解析。"""
    path = write(tmp_path, "[DEFAULT]\nrequest_timeout = 10   # 请求超时时间（秒）\n"
                           "request_interval = 0.5  # 请求间隔\nallow_intrusive_write = true  # 已获授权\n")
    config = cli.load_config(path)
    assert config["request_timeout"] == 10
    assert config["request_interval"] == 0.5
    assert config["allow_intrusive_write"] is True


def test_defaults_applied_when_keys_absent(tmp_path):
    config = cli.load_config(write(tmp_path, "[DEFAULT]\n"))
    assert config["request_timeout"] == 10
    assert config["request_interval"] == 0.3
    assert config["request_burst"] == 5
    assert config["max_retry"] == 2
    # 安全默认：写操作闸门必须是关闭的
    assert config["allow_intrusive_write"] is False


def test_sections_do_not_inherit_default_keys(tmp_path):
    """ConfigParser 会把 DEFAULT 注入每个 section，读取时需要剔除。"""
    path = write(tmp_path, "[DEFAULT]\nrequest_timeout = 10\nscan_logs = true\n\n"
                           "[SENSITIVE_PATHS]\nkey_paths = .env\n")
    config = cli.load_config(path)
    assert set(config["SENSITIVE_PATHS"]) == {"key_paths"}


def test_auto_extract_ints_coerced(tmp_path):
    path = write(tmp_path, "[DEFAULT]\n\n[AUTO_EXTRACT]\ntimeout = 7\nretry = 3\n")
    config = cli.load_config(path)
    assert config["AUTO_EXTRACT"]["timeout"] == 7
    assert config["AUTO_EXTRACT"]["retry"] == 3


def test_auto_extract_bad_int_falls_back(tmp_path):
    path = write(tmp_path, "[DEFAULT]\n\n[AUTO_EXTRACT]\ntimeout = abc\n")
    assert cli.load_config(path)["AUTO_EXTRACT"]["timeout"] == 10


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        cli.load_config((tmp_path / "nope.ini").as_posix())


def test_real_config_file_loads():
    """仓库自带配置必须能被正确解析。"""
    config = cli.load_config("config/config.ini")
    assert config["allow_intrusive_write"] is False
    assert config["request_interval"] > 0
    assert config["SENSITIVE_PATHS"]["key_paths"].startswith(".env")
    assert config["CLOUD_TEMPLATES"]["aliyun_https"].startswith("https://")
    assert config["AUTO_EXTRACT"]["hostid_url"] == ""
    assert config["LOG_CONFIG"]["log_file"] == "oss_scan.log"


def test_duplicate_key_gives_readable_error(tmp_path):
    """回归：同一节重复填写同一个键时，此前会抛出 configparser 的原始堆栈。"""
    path = write(tmp_path, "[DEFAULT]\nscan_logs = true\nscan_logs = false\n")
    with pytest.raises(ValueError, match="重复填写"):
        cli.load_config(path)


def test_duplicate_key_is_reported_not_crashed_via_cli(tmp_path):
    path = write(tmp_path, "[DEFAULT]\nscan_logs = true\nscan_logs = false\n")
    assert cli.main(["--cloud", "aliyun", "--bucket", "b", "--region", "r",
                     "--config", path]) == 2


def test_new_extended_scan_flags_load(tmp_path):
    path = write(tmp_path, """[DEFAULT]
scan_acl_read = true
scan_version_leak = true
scan_website = false
scan_referer = true
scan_replication = false
""")
    config = cli.load_config(path)
    assert config["scan_acl_read"] is True
    assert config["scan_version_leak"] is True
    assert config["scan_website"] is False
    assert config["scan_referer"] is True
    assert config["scan_replication"] is False


def test_sts_section_loads_credential_file(tmp_path):
    path = write(tmp_path, "[DEFAULT]\n\n[STS]\ncredential_file = /tmp/creds.json\n")
    assert cli.load_config(path)["STS"]["credential_file"] == "/tmp/creds.json"


def test_ai_provider_key_loads(tmp_path):
    path = write(tmp_path, "[DEFAULT]\n\n[AI_CONFIG]\nprovider = deepseek\nenabled = true\n")
    assert cli.load_config(path)["AI_CONFIG"]["provider"] == "deepseek"
