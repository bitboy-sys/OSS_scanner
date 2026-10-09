"""日志初始化与全局 logger。"""
import logging
import os

_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}

logger = logging.getLogger("oss_scanner")


def init_logger(log_file: str, log_level: str = "INFO") -> None:
    """初始化日志：同时写入文件与终端。"""
    level = _LEVEL_MAP.get(str(log_level).upper(), logging.INFO)

    parent = os.path.dirname(os.path.abspath(log_file))
    if parent:
        os.makedirs(parent, exist_ok=True)

    handlers = [logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler()]
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
        force=True,
    )
    logger.setLevel(level)
