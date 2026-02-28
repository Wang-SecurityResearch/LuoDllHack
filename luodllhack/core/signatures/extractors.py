# -*- coding: utf-8 -*-
"""
luodllhack/core/signatures/extractors.py - 统一签名提取器

整合了 DLL 劫持和漏洞挖掘的签名提取功能：
- PefileExtractor: 基础 PE 导出表分析
- DisasmAnalyzer: 反汇编增强分析
- AngrExtractor: 深度符号执行分析 (可选)
- SignatureExtractor: 统一入口

使用方法:
    extractor = SignatureExtractor(dll_path)
    sig = extractor.get_signature("FunctionName")
    all_sigs = extractor.get_all_signatures()
"""

import struct
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
import logging

from .models import FunctionSignature, ArgInfo, CallingConvention

logger = logging.getLogger(__name__)

# =============================================================================
# 可选依赖检测
# =============================================================================

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False
    pefile = None

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False
    Cs = None

try:
    import angr
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False
    angr = None


# =============================================================================
# COM 接口检测
# =============================================================================

COM_METHOD_PATTERNS = {
    'QueryInterface', 'AddRef', 'Release',
    'CreateInstance', 'LockServer',
    'GetHandlerProperty', 'GetHandlerProperty2', 'CreateObject',
}

COM_METHOD_REGEX = re.compile(
    r'^(QueryInterface|AddRef|Release|'
    r'Get[A-Z]\w*|Set[A-Z]\w*|'
    r'Create\w*|Open\w*|Close\w*|'
    r'Read\w*|Write\w*)$'
)


def _is_com_method(func_name: str) -> bool:
    """检查是否为 COM 方法"""
    if func_name in COM_METHOD_PATTERNS:
        return True
    return bool(COM_METHOD_REGEX.match(func_name))


# =============================================================================
# PefileExtractor - 基础 PE 导出表分析
# =============================================================================

class PefileExtractor:
    """使用 pefile 提取 DLL 导出函数"""

    def __init__(self, dll_path: Path):
        self.dll_path = Path(dll_path)
        self.pe = None
        self.arch = 'x64'
        self._load_pe()

    def _load_pe(self) -> None:
        """加载 PE 文件"""
        if not HAVE_PEFILE:
            raise ImportError("pefile is required")

        self.pe = pefile.PE(str(self.dll_path))
        self.arch = 'x64' if self.pe.FILE_HEADER.Machine == 0x8664 else 'x86'

    def get_all_exports(self) -> List[FunctionSignature]:
        """获取所有导出函数"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []

        signatures = []
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"ordinal_{exp.ordinal}"

            # 检查是否为转发
            forwarder = None
            if exp.forwarder:
                forwarder = exp.forwarder.decode('utf-8', errors='ignore')

            sig = FunctionSignature(
                name=name,
                ordinal=exp.ordinal,
                rva=exp.address,
                forwarder=forwarder,
                calling_convention=CallingConvention.WIN64 if self.arch == 'x64' else CallingConvention.STDCALL,
                analysis_source='pefile',
                confidence=0.3,
            )

            signatures.append(sig)

        return signatures

    def get_export(self, func_name: str) -> Optional[FunctionSignature]:
        """获取指定函数的导出信息"""
        for sig in self.get_all_exports():
            if sig.name == func_name:
                return sig
        return None

    @staticmethod
    def is_available() -> bool:
        return HAVE_PEFILE


# =============================================================================
# DisasmAnalyzer - 反汇编增强分析
# =============================================================================

class DisasmAnalyzer:
    """使用 Capstone 反汇编进行增强签名分析"""

    # x64 参数寄存器映射
    X64_ARG_REGS = {
        'rcx': 0, 'ecx': 0, 'cx': 0, 'cl': 0,
        'rdx': 1, 'edx': 1, 'dx': 1, 'dl': 1,
        'r8': 2, 'r8d': 2, 'r8w': 2, 'r8b': 2,
        'r9': 3, 'r9d': 3, 'r9w': 3, 'r9b': 3,
    }

    # 用于保存指针的寄存器
    PTR_SAVE_REGS = {'rdi', 'rsi', 'rbx', 'r12', 'r13', 'r14', 'r15'}

    def __init__(self, dll_path: Path):
        self.dll_path = Path(dll_path)
        self.pe = None
        self.binary_data = None
        self.image_base = 0
        self.arch = 'x64'
        self._load()

    def _load(self) -> None:
        """加载 PE 文件和二进制数据"""
        if not HAVE_PEFILE:
            raise ImportError("pefile is required")
        if not HAVE_CAPSTONE:
            raise ImportError("capstone is required")

        self.pe = pefile.PE(str(self.dll_path))
        self.binary_data = self.pe.get_memory_mapped_image()
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.arch = 'x64' if self.pe.FILE_HEADER.Machine == 0x8664 else 'x86'

    def analyze_function(self, func_name: str, rva: int) -> Optional[FunctionSignature]:
        """分析函数签名"""
        if not self.binary_data or rva <= 0 or rva >= len(self.binary_data):
            return None

        # 读取函数代码
        code_size = min(512, len(self.binary_data) - rva)
        code = self.binary_data[rva:rva + code_size]

        if self.arch == 'x64':
            return self._analyze_x64_function(code, rva, func_name)
        else:
            return self._analyze_x86_function(code, rva, func_name)

    def _analyze_x64_function(self, code: bytes, rva: int, func_name: str) -> Optional[FunctionSignature]:
        """分析 x64 函数"""
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # 追踪参数使用
        args_used: Set[int] = set()
        pointer_args: Set[int] = set()
        output_args: Set[int] = set()

        # 追踪寄存器保存到的目标
        saved_arg_regs: Dict[str, int] = {}  # 目标寄存器 -> 参数索引
        is_com_method = _is_com_method(func_name)

        instructions = list(md.disasm(code, rva))[:100]

        for i, insn in enumerate(instructions):
            mnemonic = insn.mnemonic
            op_str = insn.op_str

            # 检测函数结束
            if mnemonic == 'ret':
                break
            if mnemonic in ('jmp', 'call') and i < 3:
                # 可能是 thunk
                pass

            # 检测参数寄存器使用
            for reg, arg_idx in self.X64_ARG_REGS.items():
                if reg in op_str:
                    args_used.add(arg_idx)

                    # 检测指针保存: mov rdi, rcx
                    if mnemonic == 'mov' and ',' in op_str:
                        parts = op_str.split(',')
                        if len(parts) == 2:
                            dest = parts[0].strip()
                            src = parts[1].strip()
                            if src == reg and dest in self.PTR_SAVE_REGS:
                                saved_arg_regs[dest] = arg_idx

            # 检测解引用: mov rax, [rdi] 或 mov [rdi], rax
            if mnemonic in ('mov', 'lea', 'cmp', 'test'):
                for saved_reg, arg_idx in saved_arg_regs.items():
                    # 读取解引用
                    if f'[{saved_reg}]' in op_str or f'[{saved_reg}+' in op_str:
                        pointer_args.add(arg_idx)
                    # 写入解引用 (输出参数)
                    if op_str.startswith(f'[{saved_reg}]') or op_str.startswith(f'[{saved_reg}+'):
                        pointer_args.add(arg_idx)
                        output_args.add(arg_idx)

                # 检测直接解引用参数寄存器
                for reg, arg_idx in self.X64_ARG_REGS.items():
                    if f'[{reg}]' in op_str or f'[{reg}+' in op_str:
                        pointer_args.add(arg_idx)
                        args_used.add(arg_idx)

        # 确定参数数量
        arg_count = max(args_used) + 1 if args_used else 0

        # 构建参数列表
        args = []
        locations = ['rcx', 'rdx', 'r8', 'r9']
        for i in range(arg_count):
            is_ptr = i in pointer_args
            is_out = i in output_args

            args.append(ArgInfo(
                index=i,
                location=locations[i] if i < 4 else f'stack+{0x28 + (i-4)*8:x}',
                size=8,
                type_hint='ptr' if is_ptr else 'int',
                is_pointer=is_ptr,
                is_output=is_out,
                dereferenced=is_ptr,
                ctype='c_void_p' if is_ptr else 'c_int64',
                name_hint=f'arg{i+1}',
            ))

        # 推断返回类型
        return_type = self._infer_return_type(instructions, func_name)

        sig = FunctionSignature(
            name=func_name,
            rva=rva,
            calling_convention=CallingConvention.WIN64,
            arg_count=arg_count,
            args=args,
            return_type=return_type,
            is_com_method=is_com_method,
            has_this_pointer=is_com_method and arg_count > 0,
            confidence=0.7,
            analysis_source='disasm',
        )

        return sig

    def _analyze_x86_function(self, code: bytes, rva: int, func_name: str) -> Optional[FunctionSignature]:
        """分析 x86 函数"""
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        # 简化的 x86 分析：检测 ret N 来推断参数数量
        stack_cleanup = 0
        instructions = list(md.disasm(code, rva))[:100]

        for insn in instructions:
            if insn.mnemonic == 'ret':
                # ret N 表示清理 N 字节的栈参数
                if insn.op_str:
                    try:
                        stack_cleanup = int(insn.op_str, 0)
                    except ValueError:
                        pass
                break

        arg_count = stack_cleanup // 4 if stack_cleanup else 0

        # 推断调用约定
        cc = CallingConvention.STDCALL if stack_cleanup > 0 else CallingConvention.CDECL

        args = []
        for i in range(arg_count):
            args.append(ArgInfo(
                index=i,
                location=f'stack+{(i+1)*4:x}',
                size=4,
                type_hint='int',
                ctype='c_int32',
                name_hint=f'arg{i+1}',
            ))

        return FunctionSignature(
            name=func_name,
            rva=rva,
            calling_convention=cc,
            arg_count=arg_count,
            args=args,
            return_type='int32',
            is_com_method=_is_com_method(func_name),
            confidence=0.6,
            analysis_source='disasm',
        )

    def _infer_return_type(self, instructions: list, func_name: str) -> str:
        """推断返回类型"""
        # COM 方法通常返回 HRESULT
        if _is_com_method(func_name):
            return 'hresult'

        # 检查返回前 eax/rax 的使用
        for insn in reversed(instructions[:50]):
            if insn.mnemonic == 'ret':
                break
            if insn.mnemonic in ('xor', 'mov') and 'eax' in insn.op_str:
                if 'xor eax, eax' in f'{insn.mnemonic} {insn.op_str}':
                    return 'int32'
                return 'int32'

        return 'int64'

    @staticmethod
    def is_available() -> bool:
        return HAVE_PEFILE and HAVE_CAPSTONE


# =============================================================================
# CompositeExtractor - 组合多种提取方法
# =============================================================================

class CompositeExtractor:
    """组合多种提取器，按优先级使用"""

    def __init__(self, dll_path: Path):
        self.dll_path = Path(dll_path)
        self.pefile_extractor = None
        self.disasm_analyzer = None

        if PefileExtractor.is_available():
            self.pefile_extractor = PefileExtractor(dll_path)

        if DisasmAnalyzer.is_available():
            self.disasm_analyzer = DisasmAnalyzer(dll_path)

    def get_signature(self, func_name: str) -> Optional[FunctionSignature]:
        """获取函数签名"""
        # 1. 先获取基础导出信息
        base_sig = None
        if self.pefile_extractor:
            base_sig = self.pefile_extractor.get_export(func_name)

        if not base_sig:
            return None

        # 2. 使用反汇编增强
        if self.disasm_analyzer and base_sig.rva > 0:
            enhanced_sig = self.disasm_analyzer.analyze_function(func_name, base_sig.rva)
            if enhanced_sig:
                # 合并信息
                enhanced_sig.ordinal = base_sig.ordinal
                enhanced_sig.forwarder = base_sig.forwarder
                return enhanced_sig

        return base_sig

    def get_all_signatures(self) -> List[FunctionSignature]:
        """获取所有函数签名"""
        if not self.pefile_extractor:
            return []

        signatures = []
        for base_sig in self.pefile_extractor.get_all_exports():
            if self.disasm_analyzer and base_sig.rva > 0 and not base_sig.forwarder:
                enhanced = self.disasm_analyzer.analyze_function(base_sig.name, base_sig.rva)
                if enhanced:
                    enhanced.ordinal = base_sig.ordinal
                    enhanced.forwarder = base_sig.forwarder
                    signatures.append(enhanced)
                    continue
            signatures.append(base_sig)

        return signatures


# =============================================================================
# SignatureExtractor - 统一入口
# =============================================================================

class SignatureExtractor:
    """
    统一签名提取器

    使用方法:
        extractor = SignatureExtractor(dll_path)
        sig = extractor.get_signature("FunctionName")
        all_sigs = extractor.get_all_signatures()
    """

    def __init__(self, dll_path: Path, signature_file: Path = None):
        """
        初始化提取器

        Args:
            dll_path: DLL 文件路径
            signature_file: 外部签名文件路径 (可选，优先使用)
        """
        self.dll_path = Path(dll_path)
        self.signature_file = Path(signature_file) if signature_file else None
        self._composite = None
        self._signature_loader = None
        self._cache: Dict[str, FunctionSignature] = {}

        # 初始化提取器
        if CompositeExtractor is not None:
            try:
                self._composite = CompositeExtractor(dll_path)
            except Exception as e:
                logger.warning(f"Failed to initialize CompositeExtractor: {e}")

        # 初始化外部签名加载器 (仅当显式提供时)
        if signature_file:
            try:
                from .loader import load_signatures_for_dll
                self._signature_loader = load_signatures_for_dll(
                    self.dll_path,
                    self.signature_file,
                    auto_detect=False
                )
            except Exception as e:
                logger.debug(f"Signature loader not available: {e}")

    def get_signature(self, func_name: str) -> Optional[FunctionSignature]:
        """
        获取函数签名

        优先级:
        1. 缓存
        2. 外部签名文件
        3. 反汇编分析
        4. PE 导出表
        """
        # 检查缓存
        if func_name in self._cache:
            return self._cache[func_name]

        # 尝试外部签名
        if self._signature_loader and self._signature_loader.is_loaded:
            sig = self._signature_loader.get_function_signature(func_name)
            if sig:
                self._cache[func_name] = sig
                logger.info(f"[SignatureExtractor] Using external signature: {func_name}")
                return sig

        # 使用组合提取器
        if self._composite:
            sig = self._composite.get_signature(func_name)
            if sig:
                self._cache[func_name] = sig
                return sig

        return None

    def get_all_signatures(self) -> List[FunctionSignature]:
        """获取所有函数签名"""
        signatures = {}

        # 从组合提取器获取
        if self._composite:
            for sig in self._composite.get_all_signatures():
                signatures[sig.name] = sig

        # 用外部签名覆盖/增强
        if self._signature_loader and self._signature_loader.is_loaded:
            for name in self._signature_loader.get_all_signatures():
                sig = self._signature_loader.get_function_signature(name)
                if sig:
                    signatures[name] = sig

        return list(signatures.values())

    @staticmethod
    def is_available() -> bool:
        """检查是否可用"""
        return HAVE_PEFILE


# =============================================================================
# 便捷函数
# =============================================================================

def get_signature(dll_path: Path, func_name: str,
                  signature_file: Path = None) -> Optional[FunctionSignature]:
    """获取函数签名"""
    extractor = SignatureExtractor(dll_path, signature_file)
    return extractor.get_signature(func_name)


def get_all_signatures(dll_path: Path,
                       signature_file: Path = None) -> List[FunctionSignature]:
    """获取所有函数签名"""
    extractor = SignatureExtractor(dll_path, signature_file)
    return extractor.get_all_signatures()
