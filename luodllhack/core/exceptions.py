# -*- coding: utf-8 -*-
"""
luodllhack/core/exceptions.py - 统一异常处理

LuoDllHack 项目的自定义异常类层次结构
"""

from typing import Optional, Dict, Any


class LuoDllHackError(Exception):
    """
    LuoDllHack 基础异常类

    所有 LuoDllHack 自定义异常的基类
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


# =============================================================================
# 分析模块异常
# =============================================================================

class AnalysisError(LuoDllHackError):
    """分析模块基础异常"""
    pass


class TaintAnalysisError(AnalysisError):
    """污点分析异常"""

    def __init__(self, message: str, address: int = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.address = address


class SymbolicExecutionError(AnalysisError):
    """符号执行异常"""

    def __init__(self, message: str, state_count: int = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.state_count = state_count


class DisassemblyError(AnalysisError):
    """反汇编异常"""

    def __init__(self, message: str, offset: int = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.offset = offset


# =============================================================================
# PE/DLL 模块异常
# =============================================================================

class PEError(LuoDllHackError):
    """PE 文件处理基础异常"""
    pass


class PEParseError(PEError):
    """PE 解析异常"""

    def __init__(self, message: str, file_path: str = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.file_path = file_path


class ExportExtractionError(PEError):
    """导出函数提取异常"""

    def __init__(self, message: str, dll_name: str = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.dll_name = dll_name


class DLLCompilationError(PEError):
    """DLL 编译异常"""

    def __init__(self, message: str, compiler: str = None, arch: str = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.compiler = compiler
        self.arch = arch


# =============================================================================
# AI/Agent 模块异常
# =============================================================================

class AIError(LuoDllHackError):
    """AI 模块基础异常"""
    pass


class APIKeyError(AIError):
    """API 密钥异常"""
    pass


class RateLimitError(AIError):
    """速率限制异常"""

    def __init__(self, message: str, retry_after: float = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.retry_after = retry_after


class TokenLimitError(AIError):
    """Token 限制异常"""

    def __init__(self, message: str, token_count: int = None, max_tokens: int = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.token_count = token_count
        self.max_tokens = max_tokens


class ToolExecutionError(AIError):
    """工具执行异常"""

    def __init__(self, message: str, tool_name: str = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.tool_name = tool_name


# =============================================================================
# 验证模块异常
# =============================================================================

class ValidationError(LuoDllHackError):
    """验证模块基础异常"""
    pass


class EmulationError(ValidationError):
    """模拟执行异常"""

    def __init__(self, message: str, emulator: str = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.emulator = emulator


class PoCGenerationError(ValidationError):
    """PoC 生成异常"""

    def __init__(self, message: str, vuln_type: str = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.vuln_type = vuln_type


# =============================================================================
# 配置异常
# =============================================================================

class ConfigError(LuoDllHackError):
    """配置异常"""
    pass


class ConfigValidationError(ConfigError):
    """配置验证异常"""

    def __init__(self, message: str, field: str = None, value: Any = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.field = field
        self.value = value


class ConfigLoadError(ConfigError):
    """配置加载异常"""

    def __init__(self, message: str, config_path: str = None, **kwargs) -> None:
        super().__init__(message, kwargs)
        self.config_path = config_path


# =============================================================================
# 辅助函数
# =============================================================================

def format_exception(exc: Exception, include_traceback: bool = False) -> str:
    """
    格式化异常信息

    Args:
        exc: 异常对象
        include_traceback: 是否包含完整堆栈

    Returns:
        格式化的异常字符串
    """
    if isinstance(exc, LuoDllHackError):
        result = f"[{exc.__class__.__name__}] {exc.message}"
        if exc.details:
            result += f"\n  Details: {exc.details}"
    else:
        result = f"[{exc.__class__.__name__}] {str(exc)}"

    if include_traceback:
        import traceback
        result += f"\n  Traceback:\n{traceback.format_exc()}"

    return result
