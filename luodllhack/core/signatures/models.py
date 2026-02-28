# -*- coding: utf-8 -*-
"""
luodllhack/core/signatures/models.py - 统一签名数据模型

整合了 DLL 劫持和漏洞挖掘两个系统的签名数据结构，
提供统一的函数签名表示。
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Any, Optional
import ctypes


class CallingConvention(Enum):
    """调用约定枚举"""
    CDECL = auto()      # C 调用约定 (调用者清理栈)
    STDCALL = auto()    # 标准调用约定 (被调用者清理栈)
    FASTCALL = auto()   # 快速调用约定 (使用寄存器)
    THISCALL = auto()   # C++ this 调用约定
    WIN64 = auto()      # Windows x64 调用约定
    ARM64 = auto()      # ARM64 调用约定
    UNKNOWN = auto()    # 未知

    @classmethod
    def from_string(cls, s: str) -> 'CallingConvention':
        """从字符串转换"""
        mapping = {
            'cdecl': cls.CDECL,
            'stdcall': cls.STDCALL,
            'fastcall': cls.FASTCALL,
            'thiscall': cls.THISCALL,
            'win64': cls.WIN64,
            'ms': cls.WIN64,  # Microsoft x64
            'arm64': cls.ARM64,
            'aarch64': cls.ARM64,
        }
        return mapping.get(s.lower(), cls.UNKNOWN)

    def to_string(self) -> str:
        """转换为字符串"""
        mapping = {
            self.CDECL: 'cdecl',
            self.STDCALL: 'stdcall',
            self.FASTCALL: 'fastcall',
            self.THISCALL: 'thiscall',
            self.WIN64: 'win64',
            self.ARM64: 'arm64',
            self.UNKNOWN: 'unknown',
        }
        return mapping.get(self, 'unknown')


@dataclass
class ArgInfo:
    """
    参数信息 - 统一的参数表示

    整合了 dll_hijack.models.ArgInfo 和 analysis.signature_extractor.ArgumentInfo
    """
    index: int                          # 参数索引 (0-based)
    location: str = ""                  # 位置: "rcx", "rdx", "r8", "r9", "stack+0x28", etc.
    size: int = 8                       # 大小 (字节)
    type_hint: str = "unknown"          # 类型提示: "int", "ptr", "struct", "string", "unknown"

    # 指针相关
    is_pointer: bool = False            # 是否为指针
    is_output: bool = False             # 是否为输出参数 (指针被写入)
    dereferenced: bool = False          # 是否被解引用

    # 类型信息
    ctype: str = "c_int64"              # ctypes 类型名
    name_hint: str = ""                 # 参数名提示 (从符号或模式推断)

    def get_ctypes_type(self) -> type:
        """获取 ctypes 类型"""
        type_map = {
            'c_void_p': ctypes.c_void_p,
            'c_char_p': ctypes.c_char_p,
            'c_wchar_p': ctypes.c_wchar_p,
            'c_int': ctypes.c_int,
            'c_int32': ctypes.c_int32,
            'c_int64': ctypes.c_int64,
            'c_uint': ctypes.c_uint,
            'c_uint32': ctypes.c_uint32,
            'c_uint64': ctypes.c_uint64,
            'c_size_t': ctypes.c_size_t,
            'c_bool': ctypes.c_bool,
            'c_float': ctypes.c_float,
            'c_double': ctypes.c_double,
        }
        return type_map.get(self.ctype, ctypes.c_int64)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'index': self.index,
            'location': self.location,
            'size': self.size,
            'type_hint': self.type_hint,
            'is_pointer': self.is_pointer,
            'is_output': self.is_output,
            'dereferenced': self.dereferenced,
            'ctype': self.ctype,
            'name_hint': self.name_hint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ArgInfo':
        """从字典创建"""
        return cls(
            index=data.get('index', 0),
            location=data.get('location', ''),
            size=data.get('size', 8),
            type_hint=data.get('type_hint', 'unknown'),
            is_pointer=data.get('is_pointer', False),
            is_output=data.get('is_output', False),
            dereferenced=data.get('dereferenced', False),
            ctype=data.get('ctype', 'c_int64'),
            name_hint=data.get('name_hint', ''),
        )


@dataclass
class FunctionSignature:
    """
    统一的函数签名 - 整合 ExportSymbol 和 FunctionSignature

    用于:
    - DLL 劫持代码生成
    - 漏洞 PoC 生成
    - 函数调用分析
    """
    # 基本信息
    name: str                                   # 函数名
    ordinal: int = 0                            # 序号
    rva: int = 0                                # 相对虚拟地址

    # 调用约定和参数
    calling_convention: CallingConvention = CallingConvention.UNKNOWN
    arg_count: int = 0                          # 参数数量
    args: List[ArgInfo] = field(default_factory=list)  # 参数列表

    # 返回类型
    return_type: str = "unknown"                # "void", "int", "ptr", "bool", "hresult", "unknown"

    # 转发和 thunk
    forwarder: Optional[str] = None             # 转发目标 (如 "KERNEL32.HeapAlloc")
    is_thunk: bool = False                      # 是否为 thunk 函数
    thunk_target: Optional[str] = None          # thunk 目标函数名

    # 函数属性
    is_data: bool = False                       # 是否为数据导出 (非函数)
    is_noreturn: bool = False                   # 是否不返回 (如 ExitProcess)
    stack_frame_size: int = 0                   # 栈帧大小

    # COM 接口相关
    is_com_method: bool = False                 # 是否为 COM 方法
    has_this_pointer: bool = False              # 是否有隐式 this 指针

    # 分析元数据
    confidence: float = 0.5                     # 置信度 (0.0 - 1.0)
    analysis_source: str = "unknown"            # 分析来源: "pefile", "angr", "disasm", "external", etc.
    signature_source: str = ""                  # 签名来源文件

    # 原始签名字符串 (用于调试)
    raw_signature: str = ""

    @property
    def is_named(self) -> bool:
        """是否为命名导出 (有名称)"""
        return bool(self.name and self.name.strip())

    @property
    def is_forwarded(self) -> bool:
        """是否为转发导出"""
        return bool(self.forwarder)

    @property
    def is_cpp_mangled(self) -> bool:
        """是否为 C++ 修饰名"""
        if not self.name:
            return False
        # C++ 修饰名通常以 ? 开头 (MSVC) 或 _Z 开头 (GCC/Clang)
        return self.name.startswith('?') or self.name.startswith('_Z')

    def get_safe_c_name(self) -> str:
        """获取安全的 C 标识符名称
        
        将函数名转换为合法的 C 标识符:
        - 移除非字母数字字符
        - 如果没有名称,使用 ordinal_N 格式
        """
        if self.name:
            # 替换非字母数字字符为下划线
            safe = ''.join(c if c.isalnum() or c == '_' else '_' for c in self.name)
            # 确保不以数字开头
            if safe and safe[0].isdigit():
                safe = f'func_{safe}'
            return safe if safe else f'ordinal_{self.ordinal}'
        return f'ordinal_{self.ordinal}'

    def get_export_name(self) -> str:
        """获取导出名称 (用于显示和验证)
        
        Returns:
            函数名或 @ordinal 格式
        """
        if self.name:
            return self.name
        return f'@{self.ordinal}'

    def get_calling_convention_str(self) -> str:
        """获取调用约定字符串"""
        if isinstance(self.calling_convention, CallingConvention):
            return self.calling_convention.to_string()
        return str(self.calling_convention)

    def get_ctypes_argtypes(self) -> List[type]:
        """生成 ctypes argtypes 列表"""
        types = []

        # COM 方法需要添加 this 指针
        if self.is_com_method and self.has_this_pointer:
            types.append(ctypes.c_void_p)

        # 如果有详细的参数信息，使用它
        if self.args:
            for arg in self.args:
                if isinstance(arg, ArgInfo):
                    types.append(arg.get_ctypes_type())
                elif isinstance(arg, dict):
                    # 兼容字典格式
                    if arg.get('is_pointer', False) or arg.get('type_hint') == 'ptr':
                        types.append(ctypes.c_void_p)
                    else:
                        types.append(ctypes.c_int64)
                else:
                    types.append(ctypes.c_int64)
        elif self.arg_count > 0:
            # 没有详细信息，根据 arg_count 生成默认类型
            types.extend([ctypes.c_int64] * self.arg_count)

        return types

    def get_ctypes_argtypes_str(self) -> str:
        """生成 ctypes argtypes 字符串表示"""
        types = []

        if self.is_com_method and self.has_this_pointer:
            types.append("ctypes.c_void_p")

        if self.args:
            for arg in self.args:
                if isinstance(arg, ArgInfo):
                    types.append(f"ctypes.{arg.ctype}")
                elif isinstance(arg, dict):
                    if arg.get('is_pointer', False) or arg.get('type_hint') == 'ptr':
                        types.append("ctypes.c_void_p")
                    else:
                        types.append("ctypes.c_int64")
                else:
                    types.append("ctypes.c_int64")
        elif self.arg_count > 0:
            types.extend(["ctypes.c_int64"] * self.arg_count)

        return f"[{', '.join(types)}]"

    def get_ctypes_restype(self) -> type:
        """获取 ctypes 返回类型"""
        type_map = {
            'void': None,
            'int': ctypes.c_int,
            'int32': ctypes.c_int32,
            'int64': ctypes.c_int64,
            'uint': ctypes.c_uint,
            'uint32': ctypes.c_uint32,
            'uint64': ctypes.c_uint64,
            'ptr': ctypes.c_void_p,
            'bool': ctypes.c_bool,
            'hresult': ctypes.c_long,
            'unknown': ctypes.c_int64,
        }
        return type_map.get(self.return_type.lower(), ctypes.c_int64)

    def get_ctypes_restype_str(self) -> str:
        """获取 ctypes 返回类型字符串"""
        type_map = {
            'void': 'None',
            'int': 'ctypes.c_int',
            'int32': 'ctypes.c_int32',
            'int64': 'ctypes.c_int64',
            'uint': 'ctypes.c_uint',
            'uint32': 'ctypes.c_uint32',
            'uint64': 'ctypes.c_uint64',
            'ptr': 'ctypes.c_void_p',
            'bool': 'ctypes.c_bool',
            'hresult': 'ctypes.c_long',
            'unknown': 'ctypes.c_int64',
        }
        return type_map.get(self.return_type.lower(), 'ctypes.c_int64')

    def get_default_call_args(self, arch: str = 'x64') -> str:
        """生成默认调用参数"""
        if self.arg_count == 0:
            return ""

        args = []
        for i, arg in enumerate(self.args):
            if isinstance(arg, ArgInfo):
                if arg.is_pointer:
                    args.append(f"ctypes.c_void_p(0)")
                else:
                    args.append(f"ctypes.c_int64(0)")
            elif isinstance(arg, dict):
                if arg.get('is_pointer', False):
                    args.append(f"ctypes.c_void_p(0)")
                else:
                    args.append(f"ctypes.c_int64(0)")
            else:
                args.append(f"ctypes.c_int64(0)")

        # 如果 args 列表不够，补充默认值
        while len(args) < self.arg_count:
            args.append(f"ctypes.c_int64(0)")

        return ", ".join(args)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'name': self.name,
            'ordinal': self.ordinal,
            'rva': self.rva,
            'calling_convention': self.get_calling_convention_str(),
            'arg_count': self.arg_count,
            'args': [a.to_dict() if isinstance(a, ArgInfo) else a for a in self.args],
            'return_type': self.return_type,
            'forwarder': self.forwarder,
            'is_thunk': self.is_thunk,
            'thunk_target': self.thunk_target,
            'is_data': self.is_data,
            'is_noreturn': self.is_noreturn,
            'stack_frame_size': self.stack_frame_size,
            'is_com_method': self.is_com_method,
            'has_this_pointer': self.has_this_pointer,
            'confidence': self.confidence,
            'analysis_source': self.analysis_source,
            'raw_signature': self.raw_signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FunctionSignature':
        """从字典创建"""
        # 解析调用约定
        cc = data.get('calling_convention', 'unknown')
        if isinstance(cc, str):
            cc = CallingConvention.from_string(cc)

        # 解析参数
        args = []
        for arg_data in data.get('args', []):
            if isinstance(arg_data, dict):
                args.append(ArgInfo.from_dict(arg_data))
            elif isinstance(arg_data, ArgInfo):
                args.append(arg_data)

        return cls(
            name=data.get('name', ''),
            ordinal=data.get('ordinal', 0),
            rva=data.get('rva', 0),
            calling_convention=cc,
            arg_count=data.get('arg_count', len(args)),
            args=args,
            return_type=data.get('return_type', 'unknown'),
            forwarder=data.get('forwarder'),
            is_thunk=data.get('is_thunk', False),
            thunk_target=data.get('thunk_target'),
            is_data=data.get('is_data', False),
            is_noreturn=data.get('is_noreturn', False),
            stack_frame_size=data.get('stack_frame_size', 0),
            is_com_method=data.get('is_com_method', False),
            has_this_pointer=data.get('has_this_pointer', False),
            confidence=data.get('confidence', 0.5),
            analysis_source=data.get('analysis_source', 'unknown'),
            raw_signature=data.get('raw_signature', ''),
        )


# =============================================================================
# 类型别名 (向后兼容)
# =============================================================================

# 保持与 dll_hijack.models 的兼容
ExportSymbol = FunctionSignature

# 保持与 analysis.signature_extractor 的兼容
ArgumentInfo = ArgInfo
