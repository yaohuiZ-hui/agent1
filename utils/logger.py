"""
工具函数 - 日志记录器

统一的日志记录模块，同时输出到文件和终端。
"""
import os
import sys
import logging
from typing import Optional
from logging.handlers import RotatingFileHandler

from config.settings import get_config, Config


# 日志格式定义
CONSOLE_FORMAT = "[%(levelname)s] %(message)s"
FILE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

_loggers = {}


def get_logger(name: str = "agent1", log_file: Optional[str] = None) -> logging.Logger:
    """
    获取或创建日志记录器

    Args:
        name: 记录器名称
        log_file: 日志文件路径，None则使用默认路径

    Returns:
        配置好的 logging.Logger 实例
    """
    if name in _loggers:
        return _loggers[name]

    config = get_config()

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
    logger.propagate = False

    # 清除已有处理器
    logger.handlers.clear()

    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(CONSOLE_FORMAT))
    logger.addHandler(console_handler)

    # 文件处理器
    log_path = log_file or config.LOG_FILE
    try:
        log_dir = os.path.dirname(log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter(FILE_FORMAT))
        logger.addHandler(file_handler)
    except (OSError, PermissionError):
        # 文件不可写时，仅使用控制台输出
        pass

    _loggers[name] = logger
    return logger


class LoggerMixin:
    """日志混合类，为类提供便捷的日志方法"""

    @property
    def logger(self) -> logging.Logger:
        """获取类名对应的日志记录器"""
        if not hasattr(self, "_logger"):
            self._logger = get_logger(self.__class__.__name__)
        return self._logger

    def log_info(self, message: str):
        self.logger.info(message)

    def log_warning(self, message: str):
        self.logger.warning(message)

    def log_error(self, message: str):
        self.logger.error(message)

    def log_debug(self, message: str):
        self.logger.debug(message)