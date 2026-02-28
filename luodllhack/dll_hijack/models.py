# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack/models.py
Data models for DLL proxy generation.

签名相关类型从 luodllhack.core.signatures 导入。
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import List, Dict, Optional, Any

# 从统一签名模块导入
from luodllhack.core.signatures.models import (
    CallingConvention,
    ArgInfo,
    FunctionSignature,
)

# ExportSymbol 是 FunctionSignature 的别名
ExportSymbol = FunctionSignature


class Architecture(Enum):
    """Target architectures."""
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"


class CompilerType(Enum):
    """Supported compiler types for code generation."""
    MSVC = "msvc"
    MINGW = "mingw"
    CLANG = "clang"


@dataclass
class TLSCallback:
    """TLS callback information."""
    rva: int
    index: int


@dataclass
class VersionInfo:
    """Version resource information."""
    file_version: str = ""
    product_version: str = ""
    company_name: str = ""
    file_description: str = ""
    internal_name: str = ""
    original_filename: str = ""
    product_name: str = ""
    legal_copyright: str = ""


@dataclass
class PEInfo:
    """Parsed PE file information."""
    path: Path
    machine: int
    image_base: int
    entry_point: int
    is_64bit: bool
    exports: List[ExportSymbol] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    is_arm64: bool = False
    tls_callbacks: List[TLSCallback] = field(default_factory=list)
    has_tls: bool = False
    version_info: Optional[VersionInfo] = None
    delay_imports: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def arch_name(self) -> str:
        if self.is_arm64:
            return "arm64"
        return "x64" if self.is_64bit else "x86"

    @property
    def arch(self) -> Architecture:
        if self.is_arm64:
            return Architecture.ARM64
        return Architecture.X64 if self.is_64bit else Architecture.X86


__all__ = [
    'CallingConvention',
    'ArgInfo',
    'FunctionSignature',
    'ExportSymbol',
    'Architecture',
    'CompilerType',
    'TLSCallback',
    'VersionInfo',
    'PEInfo',
]
