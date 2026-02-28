# -*- coding: utf-8 -*-
"""
luodllhack/core/logging.py - 日志管理

提供统一的日志配置和管理功能
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


# 日志格式
DEFAULT_FORMAT = "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s"
DETAILED_FORMAT = "[%(asctime)s] %(levelname)-8s %(name)s (%(filename)s:%(lineno)d): %(message)s"
SIMPLE_FORMAT = "%(levelname)s: %(message)s"


class ColoredFormatter(logging.Formatter):
    """
    带颜色的日志格式化器 (仅终端)
    """

    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'

    def __init__(self, fmt=None, datefmt=None, use_colors=True) -> None:
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record) -> str:
        if self.use_colors:
            color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class LuoDllHackLogger:
    """
    LuoDllHack 日志管理器

    提供统一的日志配置接口
    """

    _configured = False
    _root_logger = None

    @classmethod
    def setup(
        cls,
        level: str = "INFO",
        log_file: Optional[Path] = None,
        detailed: bool = False,
        use_colors: bool = True
    ):
        """
        配置日志系统

        Args:
            level: 日志级别 (DEBUG/INFO/WARNING/ERROR/CRITICAL)
            log_file: 日志文件路径 (可选)
            detailed: 是否使用详细格式
            use_colors: 是否使用彩色输出
        """
        if cls._configured:
            return

        # 获取根 logger
        root = logging.getLogger("luodllhack")
        root.setLevel(getattr(logging, level.upper(), logging.INFO))

        # 选择格式
        fmt = DETAILED_FORMAT if detailed else DEFAULT_FORMAT

        # 控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColoredFormatter(fmt, use_colors=use_colors))
        root.addHandler(console_handler)

        # 文件处理器 (如果指定)
        if log_file:
            log_file = Path(log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(logging.Formatter(DETAILED_FORMAT))
            root.addHandler(file_handler)

        cls._root_logger = root
        cls._configured = True

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        获取命名 logger

        Args:
            name: logger 名称 (会自动添加 luodllhack. 前缀)

        Returns:
            Logger 实例
        """
        if not cls._configured:
            cls.setup()

        if not name.startswith("luodllhack."):
            name = f"luodllhack.{name}"

        return logging.getLogger(name)

    @classmethod
    def set_level(cls, level: str) -> None:
        """动态调整日志级别"""
        if cls._root_logger:
            cls._root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))


# 便捷函数
def get_logger(name: str) -> logging.Logger:
    """获取 logger 的便捷函数"""
    return LuoDllHackLogger.get_logger(name)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    detailed: bool = False
):
    """设置日志的便捷函数"""
    LuoDllHackLogger.setup(
        level=level,
        log_file=Path(log_file) if log_file else None,
        detailed=detailed
    )


def setup_logging_from_config(config=None):
    """
    从 LuoDllHackConfig 配置对象设置日志

    Args:
        config: LuoDllHackConfig 实例 (None 时使用 default_config)
    """
    # 延迟导入避免循环引用
    if config is None:
        try:
            from .config import default_config
            config = default_config
        except ImportError:
            # 回退到默认值
            setup_logging()
            return

    if config is None:
        setup_logging()
        return

    setup_logging(
        level=config.log_level,
        log_file=str(config.log_file) if config.log_file else None,
        detailed=(config.log_level.upper() == "DEBUG")
    )


# 模块级别的 logger
logger = get_logger("core")
