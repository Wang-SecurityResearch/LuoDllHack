# -*- coding: utf-8 -*-
"""
luodllhack/core/utils.py - 通用工具函数

提供项目中共享的工具函数，避免重复实现。
"""

from typing import Union, Dict, Any, Callable, List, Tuple, Optional
from functools import wraps
import os
import re
import subprocess
from pathlib import Path
import sys
import logging
import ctypes

# PE Machine Type 常量
MACHINE_I386 = 0x014c   # x86 32-bit
MACHINE_AMD64 = 0x8664  # x64 64-bit
MACHINE_ARM64 = 0xaa64  # ARM64

logger = logging.getLogger(__name__)


def require_dependencies(*deps: str):
    """
    装饰器：检查依赖是否可用

    用于统一工具方法的可用性检查，减少重复代码。

    Args:
        deps: 依赖名称列表，如 "taint_engine", "HAVE_CAPSTONE"

    Usage:
        @require_dependencies("taint_engine")
        def _analyze_taint_flow(self, ...):
            ...

        @require_dependencies("taint_engine", "exports")
        def _find_path_to_sink(self, ...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            missing = []
            for dep in deps:
                # 检查实例属性
                if hasattr(self, dep):
                    attr = getattr(self, dep)
                    if attr is None or (isinstance(attr, dict) and not attr):
                        missing.append(dep)
                # 检查全局变量 (如 HAVE_CAPSTONE)
                elif dep.startswith("HAVE_"):
                    # 从调用者的全局命名空间获取
                    import inspect
                    frame = inspect.currentframe()
                    try:
                        caller_globals = frame.f_back.f_globals
                        if not caller_globals.get(dep, False):
                            missing.append(dep)
                    finally:
                        del frame
                else:
                    missing.append(dep)

            if missing:
                return {"error": f"Dependencies not available: {', '.join(missing)}"}

            return func(self, *args, **kwargs)
        return wrapper
    return decorator


def parse_address(addr_input: Union[str, int]) -> int:
    """
    统一的地址解析函数

    支持格式:
    - 十六进制字符串: "0x1234", "0X1234"
    - 十进制字符串: "1234"
    - 整数: 1234

    Args:
        addr_input: 地址输入 (字符串或整数)

    Returns:
        解析后的整数地址

    Raises:
        ValueError: 地址格式无效

    Examples:
        >>> parse_address("0x1000")
        4096
        >>> parse_address("4096")
        4096
        >>> parse_address(4096)
        4096
    """
    if isinstance(addr_input, int):
        return addr_input

    if isinstance(addr_input, str):
        addr_input = addr_input.strip()
        if not addr_input:
            raise ValueError("Empty address string")

        if addr_input.lower().startswith("0x"):
            return int(addr_input, 16)
        else:
            return int(addr_input)

    # 尝试转换其他类型
    return int(addr_input)


def parse_exports_dict(exports: Dict[str, Any]) -> Dict[str, int]:
    """
    解析导出函数字典中的地址

    将 {name: address} 字典中的地址统一转换为整数

    Args:
        exports: 导出函数字典 {name: address}

    Returns:
        解析后的字典 {name: int_address}
    """
    result = {}
    for name, addr in exports.items():
        try:
            result[name] = parse_address(addr)
        except (ValueError, TypeError):
            continue  # 跳过无效地址
    return result


# ============================================================================
# 架构检测与兼容性工具
# ============================================================================

def get_python_arch() -> str:
    """
    获取当前 Python 解释器的架构

    Returns:
        "x64" 或 "x86"
    """
    return "x64" if sys.maxsize > 2**32 else "x86"


def detect_pe_arch(binary_path: Union[str, Path]) -> str:
    """
    从 PE 文件检测架构

    Args:
        binary_path: PE 文件路径

    Returns:
        "x64" 或 "x86"

    Raises:
        ValueError: 无效的 PE 文件
    """
    try:
        import pefile
        pe = pefile.PE(str(binary_path), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        if machine == MACHINE_AMD64:
            return "x64"
        elif machine == MACHINE_I386:
            return "x86"
        elif machine == MACHINE_ARM64:
            return "arm64"
        else:
            raise ValueError(f"Unknown PE machine type: 0x{machine:x}")
    except ImportError:
        # Fallback: read raw PE header
        return detect_pe_arch_raw(binary_path)


def detect_pe_arch_raw(binary_path: Union[str, Path]) -> str:
    """
    从原始 PE 文件检测架构 (不依赖 pefile)

    Args:
        binary_path: PE 文件路径

    Returns:
        "x64" 或 "x86"

    Raises:
        ValueError: 无效的 PE 文件
    """
    import struct
    with open(binary_path, 'rb') as f:
        # Check MZ signature
        if f.read(2) != b'MZ':
            raise ValueError("Not a valid PE file (no MZ signature)")

        # Get PE header offset
        f.seek(0x3C)
        pe_offset = struct.unpack('<I', f.read(4))[0]

        # Check PE signature
        f.seek(pe_offset)
        if f.read(4) != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")

        # Read machine type
        machine = struct.unpack('<H', f.read(2))[0]

        if machine == MACHINE_AMD64:
            return "x64"
        elif machine == MACHINE_I386:
            return "x86"
        elif machine == MACHINE_ARM64:
            return "arm64"
        else:
            raise ValueError(f"Unknown PE machine type: 0x{machine:x}")


def check_arch_compatibility(binary_path: Union[str, Path]) -> Tuple[str, str, bool]:
    """
    检查 PE 文件与当前 Python 的架构兼容性

    Args:
        binary_path: PE 文件路径

    Returns:
        (dll_arch, python_arch, is_compatible)
    """
    py_arch = get_python_arch()
    try:
        dll_arch = detect_pe_arch(binary_path)
        return dll_arch, py_arch, dll_arch == py_arch
    except Exception as e:
        logger.warning(f"Cannot detect PE architecture: {e}")
        return "unknown", py_arch, False


# ============================================================================
# C++ Symbol Demangling
# ============================================================================

def demangle_cpp_symbol(mangled_name: str) -> str:
    """
    Demangle a C++ symbol name (MSVC decoraded names).
    
    Uses UnDecorateSymbolName from dbghelp.dll on Windows.
    
    Args:
        mangled_name: The mangled symbol string (e.g., starts with ?)
        
    Returns:
        Demangled name or the original name if demangling fails.
    """
    if not mangled_name or not mangled_name.startswith("?"):
        return mangled_name

    # Try Windows UnDecorateSymbolName via dbghelp.dll
    if sys.platform == 'win32':
        try:
            # UNDNAME FLAGS
            # 0x0000: Complete symbol (return type, parameters, etc.)
            # 0x1000: No leading underscore
            # 0x0080: No return type
            # 0x0002: No parameters
            dbghelp = ctypes.windll.dbghelp
            buffer = ctypes.create_string_buffer(4096)
            result = dbghelp.UnDecorateSymbolName(
                mangled_name.encode('utf-8'),
                buffer,
                4096,
                0x0000  # UNDNAME_COMPLETE
            )
            if result:
                return buffer.value.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"dbghelp demangle failed: {e}")

    # Fallback 1: basic naming pattern (?FuncName@@...)
    # This is very rough but helps when dbghelp is not available
    match = re.match(r"\?([^@]+)@", mangled_name)
    if match:
        return match.group(1)

    return mangled_name


def sanitize_filename(filename: str, replacement: str = "_") -> str:
    """
    清理文件名中的非法字符，使其在 Windows/Linux/macOS 上均可安全使用。
    
    Args:
        filename: 原始文件名 (如 mangled symbol)
        replacement: 替换字符，默认为下划线
        
    Returns:
        清理后的文件名
    """
    if not filename:
        return "unknown"
        
    # Windows 非法字符: < > : " / \ | ? *
    # 额外清理: 空格, @ (虽然合法但也建议替换以避免 shell 引用问题)
    # 额外清理: C++ 作用域符 ::, 括号 ()
    invalid_chars = r'[<>:"/\\|?*\x00-\x1f\s@]'
    
    # 先处理 :: 以保持语义
    sanitized = filename.replace("::", "_")
    
    # 替换其他非法字符
    sanitized = re.sub(invalid_chars, replacement, sanitized)
    
    # 替换连续的下划线
    sanitized = re.sub(r'_{2,}', '_', sanitized)
    
    # 去除首尾下划线
    sanitized = sanitized.strip('_')
    
    # 截断过长文件名
    return sanitized[:128]


def warn_arch_mismatch(binary_path: Union[str, Path], context: str = "") -> Optional[str]:
    """
    检查并警告架构不匹配

    Args:
        binary_path: PE 文件路径
        context: 额外的上下文描述

    Returns:
        如果不匹配，返回警告信息；否则返回 None
    """
    dll_arch, py_arch, compatible = check_arch_compatibility(binary_path)

    if not compatible and dll_arch != "unknown":
        msg = (
            f"Architecture mismatch: DLL is {dll_arch}, Python is {py_arch}. "
            f"Some features (ctypes loading, dynamic analysis) will not work. "
            f"Use {dll_arch} Python for full functionality."
        )
        if context:
            msg = f"[{context}] {msg}"
        logger.warning(msg)
        return msg
    return None


class ArchMismatchWarning:
    """
    架构不匹配警告上下文管理器

    Usage:
        with ArchMismatchWarning(dll_path, "PoC Generator") as arch_info:
            if not arch_info.compatible:
                print(f"Warning: {arch_info.message}")
                # Generate static analysis only
            else:
                # Can use dynamic analysis
    """
    def __init__(self, binary_path: Union[str, Path], context: str = ""):
        self.binary_path = binary_path
        self.context = context
        self.dll_arch: str = "unknown"
        self.py_arch: str = get_python_arch()
        self.compatible: bool = False
        self.message: Optional[str] = None

    def __enter__(self) -> 'ArchMismatchWarning':
        self.dll_arch, self.py_arch, self.compatible = check_arch_compatibility(
            self.binary_path
        )
        if not self.compatible and self.dll_arch != "unknown":
            self.message = (
                f"DLL ({self.dll_arch}) / Python ({self.py_arch}) architecture mismatch"
            )
            if self.context:
                self.message = f"[{self.context}] {self.message}"
        return self

    def __exit__(self, *args):
        pass
