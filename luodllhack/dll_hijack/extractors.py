# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack/extractors.py
Export extractor implementations for DLL analysis.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from .constants import MACHINE_AMD64, SECTION_MEM_EXECUTE
from .interfaces import ExportExtractor

# 使用统一签名模块
from luodllhack.core.signatures.models import (
    FunctionSignature as ExportSymbol,
    CallingConvention,
    ArgInfo,
)

# Optional dependencies
try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    import angr
    import claripy
    from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCStdcall, SimCCCdecl
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False

import logging
import time

logger = logging.getLogger(__name__)


class PefileExtractor(ExportExtractor):
    """Extract exports using pefile library.

    Provides comprehensive export extraction with:
    - Named and ordinal-only export detection
    - Forwarder resolution
    - Data export detection (section-based + heuristics)
    - Optional calling convention inference (requires Capstone)
    """

    def __init__(self, analyze_calling_convention: bool = False):
        """Initialize extractor.

        Args:
            analyze_calling_convention: If True and Capstone is available,
                attempt to infer calling conventions by analyzing function prologues.
        """
        self._analyze_cc = analyze_calling_convention and HAVE_CAPSTONE

    def is_available(self) -> bool:
        return HAVE_PEFILE

    def extract(self, dll_path: Path) -> List[ExportSymbol]:
        if not self.is_available():
            raise RuntimeError("pefile library not available")

        pe = pefile.PE(str(dll_path))
        is_64bit = pe.FILE_HEADER.Machine == MACHINE_AMD64
        exports = []

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports

        # Build section lookup table for efficient RVA-to-section mapping
        sections = self._build_section_table(pe)

        # Read file data for optional disassembly
        file_data = None
        if self._analyze_cc:
            with open(dll_path, 'rb') as f:
                file_data = f.read()

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode('utf-8', errors='ignore') if exp.name else None
            ordinal = int(getattr(exp, 'ordinal', 0))
            rva = exp.address

            # Extract forwarder string
            forwarder = self._get_forwarder(exp)

            # Detect data exports
            is_data = self._is_data_export(rva, sections)

            # Determine calling convention
            calling_conv = CallingConvention.WIN64 if is_64bit else CallingConvention.UNKNOWN
            arg_count = 0

            # Optionally analyze function prologue for x86 calling convention
            if self._analyze_cc and not is_data and not forwarder and rva:
                cc_info = self._analyze_prologue(pe, file_data, rva, is_64bit)
                if cc_info:
                    calling_conv, arg_count = cc_info

            exports.append(ExportSymbol(
                name=name,
                ordinal=ordinal,
                rva=rva,
                forwarder=forwarder,
                is_data=is_data,
                calling_convention=calling_conv,
                arg_count=arg_count
            ))

        return exports

    def _build_section_table(self, pe) -> List[Dict]:
        """Build efficient section lookup table."""
        sections = []
        for section in pe.sections:
            sections.append({
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'start': section.VirtualAddress,
                'end': section.VirtualAddress + section.Misc_VirtualSize,
                'characteristics': section.Characteristics
            })
        return sections

    def _get_forwarder(self, exp) -> Optional[str]:
        """Extract forwarder string from export entry."""
        if not getattr(exp, 'forwarder', None):
            return None
        fwd = exp.forwarder
        if isinstance(fwd, bytes):
            return fwd.decode('utf-8', errors='ignore')
        return str(fwd)

    def _is_data_export(self, rva: int, sections: List[Dict]) -> bool:
        """Determine if export is data based on section characteristics and heuristics."""
        if not rva:
            return False

        for section in sections:
            if section['start'] <= rva < section['end']:
                # Check section characteristics
                is_exec = bool(section['characteristics'] & SECTION_MEM_EXECUTE)
                if not is_exec:
                    return True

                # Even in executable section, check if it's in a data-like area
                sec_name = section['name'].lower()
                if sec_name in ('.rdata', '.data', '.bss', '.idata'):
                    return True

                return False

        # RVA not in any section - likely invalid or special
        return False

    def _analyze_prologue(self, pe, file_data: bytes, rva: int, is_64bit: bool) -> Optional[Tuple[CallingConvention, int]]:
        """Analyze function prologue to infer calling convention and argument count."""
        if not HAVE_CAPSTONE:
            logger.debug(f"[prologue] RVA={rva:#x} Capstone not available")
            if is_64bit:
                return (CallingConvention.WIN64, 0)
            return None

        try:
            offset = pe.get_offset_from_rva(rva)
            if offset < 0 or offset >= len(file_data):
                logger.warning(f"[prologue] RVA={rva:#x} invalid offset={offset:#x}, file_size={len(file_data):#x}")
                if is_64bit:
                    return (CallingConvention.WIN64, 0)
                return None

            code = file_data[offset:offset + 512]  # 读取更多字节用于分析

            if len(code) == 0:
                logger.warning(f"[prologue] RVA={rva:#x} empty code at offset={offset:#x}")
                if is_64bit:
                    return (CallingConvention.WIN64, 0)
                return None

            logger.debug(f"[prologue] RVA={rva:#x} offset={offset:#x} code_len={len(code)} first_bytes={code[:16].hex()}")

            if is_64bit:
                # x64 参数分析
                return self._analyze_x64_args(code, rva)
            else:
                # x86 参数分析
                return self._analyze_x86_args(code, rva)

        except Exception as e:
            logger.warning(f"[prologue] RVA={rva:#x} exception: {e}")

        if is_64bit:
            return (CallingConvention.WIN64, 0)
        return None

    def _analyze_x64_args(self, code: bytes, rva: int) -> Tuple[CallingConvention, int]:
        """Analyze x64 function to detect argument count.

        x64 调用约定:
        - 前4个参数: rcx, rdx, r8, r9
        - 第5个及以后: 栈 [rsp+0x28], [rsp+0x30], ...
        - shadow space: [rsp+0x8] ~ [rsp+0x20]

        检测策略 (综合多种模式):
        1. 参数寄存器保存到 shadow space
        2. 参数寄存器保存到局部变量 [rbp-XX]
        3. 参数寄存器直接使用 (mov, cmp, test, push 等)
        4. 栈参数访问 [rsp+0x28] 及以后
        5. 启发式：非平凡函数默认至少有参数
        """
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
        except Exception as e:
            logger.warning(f"Failed to create Capstone disassembler: {e}")
            return (CallingConvention.WIN64, 0)

        # 跟踪检测到的参数
        detected_args = set()

        # 调试：记录前几条指令
        debug_insns = []
        debug_enabled = logger.isEnabledFor(logging.DEBUG)

        # 参数寄存器 (包括子寄存器)
        arg_regs = {
            # 参数1: rcx/ecx/cx/cl
            'rcx': 1, 'ecx': 1, 'cx': 1, 'cl': 1,
            # 参数2: rdx/edx/dx/dl
            'rdx': 2, 'edx': 2, 'dx': 2, 'dl': 2,
            # 参数3: r8/r8d/r8w/r8b
            'r8': 3, 'r8d': 3, 'r8w': 3, 'r8b': 3,
            # 参数4: r9/r9d/r9w/r9b
            'r9': 4, 'r9d': 4, 'r9w': 4, 'r9b': 4,
        }

        # shadow space 偏移到参数索引
        shadow_to_arg = {0x8: 1, 0x10: 2, 0x18: 3, 0x20: 4}

        # 栈参数偏移到参数索引 (5th+ parameters)
        # [rsp+0x28]=5, [rsp+0x30]=6, ...
        stack_param_base = 0x28

        insn_count = 0
        has_sub_rsp = False
        is_thunk = False
        func_size = 0

        for insn in md.disasm(code, rva):
            insn_count += 1
            func_size = insn.address - rva + insn.size

            # 分析前 30 条指令
            if insn_count > 30:
                break

            mnemonic = insn.mnemonic.lower()
            op_str = insn.op_str.lower()

            # 记录调试信息
            if insn_count <= 15:
                debug_insns.append(f"{insn.address:x}: {mnemonic} {op_str}")

            # 检测 thunk 函数 (开头直接 jmp)
            if mnemonic == 'jmp' and insn_count <= 2:
                is_thunk = True
                break

            # 检测 ret
            if mnemonic == 'ret':
                break

            # 检测 sub rsp (栈帧建立)
            if mnemonic == 'sub' and 'rsp' in op_str:
                has_sub_rsp = True

            # === 模式1: 保存到 shadow space ===
            # mov [rsp+0x8], rcx
            if mnemonic == 'mov' and '[rsp' in op_str and '+' in op_str:
                parts = op_str.split(',')
                if len(parts) == 2:
                    dest, src = parts[0].strip(), parts[1].strip()
                    if src in arg_regs:
                        match = re.search(r'\[rsp\s*\+\s*(?:0x)?([0-9a-fA-F]+)', dest)
                        if match:
                            try:
                                offset = int(match.group(1), 16)
                                if offset in shadow_to_arg:
                                    detected_args.add(shadow_to_arg[offset])
                            except ValueError:
                                pass

            # === 模式2: 保存到局部变量 [rbp-XX] ===
            if mnemonic == 'mov' and '[rbp' in op_str and '-' in op_str:
                parts = op_str.split(',')
                if len(parts) == 2:
                    src = parts[1].strip()
                    if src in arg_regs:
                        detected_args.add(arg_regs[src])

            # === 模式3: 参数寄存器直接使用 ===
            # 包括: mov, cmp, test, push, lea, add, sub, and, or, xor 等
            usage_insns = {'mov', 'cmp', 'test', 'push', 'lea', 'add', 'sub',
                           'and', 'or', 'xor', 'shl', 'shr', 'imul', 'call'}
            if mnemonic in usage_insns:
                for reg, arg_idx in arg_regs.items():
                    # 检查寄存器是否出现在操作数中
                    # 需要精确匹配，避免 r8 匹配 r8d 的子串问题
                    # 使用单词边界检查
                    if re.search(rf'\b{reg}\b', op_str):
                        detected_args.add(arg_idx)

            # === 模式4: 栈参数访问 [rsp+0x28] 及以后 ===
            if '[rsp' in op_str and '+' in op_str:
                match = re.search(r'\[rsp\s*\+\s*(?:0x)?([0-9a-fA-F]+)', op_str)
                if match:
                    try:
                        offset = int(match.group(1), 16)
                        if offset >= stack_param_base:
                            # 计算栈参数索引: (offset - 0x28) / 8 + 5
                            stack_arg_idx = (offset - stack_param_base) // 8 + 5
                            if stack_arg_idx <= 10:  # 合理上限
                                detected_args.add(stack_arg_idx)
                    except ValueError:
                        pass

        # Thunk 函数无法确定参数
        if is_thunk:
            logger.debug(f"[x64_args] RVA={rva:#x} is THUNK, returning 0 args")
            logger.debug(f"[x64_args] First insns: {debug_insns[:5]}")
            return (CallingConvention.WIN64, 0)

        # 计算参数数量
        arg_count = max(detected_args) if detected_args else 0

        # === 启发式补充 ===
        # 如果函数有一定大小但检测到 0 参数，可能是优化后的代码
        # 对于漏洞分析，宁可多给参数也不要漏掉
        if arg_count == 0 and func_size > 20 and has_sub_rsp:
            # 有栈帧的非平凡函数，至少假设有 1-2 个参数
            arg_count = 1
            logger.debug(f"[x64_args] RVA={rva:#x} heuristic fallback: arg_count=1")

        # 没有反汇编到任何指令
        if insn_count == 0:
            logger.warning(f"[x64_args] RVA={rva:#x} NO INSTRUCTIONS disassembled! code_len={len(code)}, first_bytes={code[:16].hex() if code else 'empty'}")
            return (CallingConvention.WIN64, 0)

        # 输出调试信息
        logger.debug(f"[x64_args] RVA={rva:#x} result: {arg_count} args, detected_args={detected_args}")
        logger.debug(f"[x64_args] insn_count={insn_count}, func_size={func_size}, has_sub_rsp={has_sub_rsp}")
        if debug_insns:
            logger.debug(f"[x64_args] First 10 insns:\n  " + "\n  ".join(debug_insns[:10]))

        return (CallingConvention.WIN64, arg_count)

    def _analyze_x86_args(self, code: bytes, rva: int) -> Optional[Tuple[CallingConvention, int]]:
        """Analyze x86 function to detect calling convention and argument count."""
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True

        for insn in md.disasm(code, rva):
            if insn.mnemonic == 'ret':
                if insn.operands:
                    stack_cleanup = insn.operands[0].imm
                    arg_count = stack_cleanup // 4
                    return (CallingConvention.STDCALL, arg_count)
                else:
                    return (CallingConvention.CDECL, 0)

            if insn.address - rva > 128:
                break

        return None


class DumpbinExtractor(ExportExtractor):
    """Extract exports using Visual Studio's dumpbin.exe.

    Handles all dumpbin /EXPORTS output formats:
    - Standard: "   ordinal hint RVA      name"
    - Forwarded: "   ordinal hint          name (forwarded to TARGET)"
    - Ordinal-only: "   ordinal hint RVA      [NONAME]"
    - With = syntax: "   ordinal hint RVA      name = internalname"
    """

    # Regex patterns for different dumpbin output formats
    _PATTERN_STANDARD = re.compile(
        r'^\s*(\d+)\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]{8})\s+(\S+)(?:\s+=\s+(\S+))?\s*$'
    )
    _PATTERN_FORWARDED = re.compile(
        r'^\s*(\d+)\s+[0-9A-Fa-f]+\s+(\S+)\s+\(forwarded to\s+(\S+)\)\s*$'
    )
    _PATTERN_NONAME = re.compile(
        r'^\s*(\d+)\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]{8})\s+\[NONAME\]\s*$'
    )

    def __init__(self):
        self._dumpbin_path = self._find_dumpbin()

    def _find_dumpbin(self) -> Optional[str]:
        """Locate dumpbin.exe from PATH or Visual Studio installations."""
        # Check PATH first
        for p in os.environ.get("PATH", "").split(os.pathsep):
            dumpbin = Path(p) / "dumpbin.exe"
            if dumpbin.exists():
                return str(dumpbin)

        # Check VS installations (newest first)
        vs_paths = [
            r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC",
            r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
            r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC",
        ]

        for base in vs_paths:
            if not os.path.exists(base):
                continue
            for root, _, files in os.walk(base):
                if "dumpbin.exe" in files:
                    if "hostx64" in root or "Hostx64" in root:
                        return os.path.join(root, "dumpbin.exe")

        return None

    def is_available(self) -> bool:
        return self._dumpbin_path is not None

    def extract(self, dll_path: Path) -> List[ExportSymbol]:
        """Extract exports by parsing dumpbin /EXPORTS output."""
        if not self.is_available():
            raise RuntimeError("dumpbin.exe not found")

        cmd = [self._dumpbin_path, "/EXPORTS", str(dll_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        exports = []
        for line in result.stdout.splitlines():
            exp = self._parse_export_line(line)
            if exp:
                exports.append(exp)

        return exports

    def _parse_export_line(self, line: str) -> Optional[ExportSymbol]:
        """Parse a single line from dumpbin /EXPORTS output."""
        # Try standard pattern first
        m = self._PATTERN_STANDARD.match(line)
        if m:
            ordinal = int(m.group(1))
            rva = int(m.group(2), 16)
            name = m.group(3)

            if name == '[NONAME]':
                return ExportSymbol(name=None, ordinal=ordinal, rva=rva)

            return ExportSymbol(name=name, ordinal=ordinal, rva=rva, forwarder=None)

        # Try forwarded pattern
        m = self._PATTERN_FORWARDED.match(line)
        if m:
            ordinal = int(m.group(1))
            name = m.group(2)
            forwarder = m.group(3)

            if name == '[NONAME]':
                name = None

            return ExportSymbol(name=name, ordinal=ordinal, rva=0, forwarder=forwarder)

        # Try ordinal-only pattern
        m = self._PATTERN_NONAME.match(line)
        if m:
            ordinal = int(m.group(1))
            rva = int(m.group(2), 16)
            return ExportSymbol(name=None, ordinal=ordinal, rva=rva)

        return None


class AngrExtractor(ExportExtractor):
    """Extract exports using angr binary analysis framework.

    Provides deep analysis capabilities:
    - Precise calling convention detection via SimCC
    - Argument count and location inference via VariableRecovery
    - Function/data classification via CFG analysis
    - Thunk/trampoline detection
    - Return type inference
    - Stack frame size calculation
    """

    # Known noreturn functions
    NORETURN_FUNCS = {
        'ExitProcess', 'TerminateProcess', 'ExitThread', 'TerminateThread',
        'FatalExit', 'abort', 'exit', '_exit', 'quick_exit', '_Exit',
        'RaiseException', 'longjmp', '_longjmp', '__fastfail'
    }

    def __init__(
        self,
        analyze_cc: bool = True,
        analyze_args: bool = True,
        analyze_returns: bool = True,
        detect_thunks: bool = True,
        timeout_per_func: float = 3.0,
        max_functions: int = 500,
        auto_load_libs: bool = False,
        verbose: bool = False
    ):
        """Initialize angr extractor.

        Args:
            analyze_cc: Analyze calling conventions
            analyze_args: Analyze argument count and locations
            analyze_returns: Analyze return types
            detect_thunks: Detect jump thunks/trampolines
            timeout_per_func: Timeout per function analysis (seconds)
            max_functions: Maximum functions to analyze (0 = unlimited)
            auto_load_libs: Load dependent libraries in angr
            verbose: Print progress messages
        """
        self._analyze_cc = analyze_cc
        self._analyze_args = analyze_args
        self._analyze_returns = analyze_returns
        self._detect_thunks = detect_thunks
        self._timeout = timeout_per_func
        self._max_funcs = max_functions
        self._auto_load = auto_load_libs
        self._verbose = verbose

    def is_available(self) -> bool:
        return HAVE_ANGR

    def extract(self, dll_path: Path) -> List[ExportSymbol]:
        """Extract exports with deep angr analysis."""
        if not self.is_available():
            raise RuntimeError("angr library not available")

        # Suppress angr logging
        logging.getLogger('angr').setLevel(logging.ERROR)
        logging.getLogger('cle').setLevel(logging.ERROR)
        logging.getLogger('pyvex').setLevel(logging.ERROR)

        if self._verbose:
            print(f"[angr] Loading {dll_path.name}...")

        start_time = time.perf_counter()

        # Load project
        proj = angr.Project(
            str(dll_path),
            auto_load_libs=self._auto_load,
            load_options={'main_opts': {'base_addr': 0x10000000}}  # Consistent base for analysis
        )

        is_64bit = proj.arch.bits == 64
        exports = []

        # Build CFG for analysis
        if self._verbose:
            print(f"[angr] Building CFG...")

        cfg = proj.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            force_complete_scan=False
        )

        # Get export symbols from CLE loader
        main_obj = proj.loader.main_object
        export_symbols = {}

        # Collect exports from symbol table
        for sym in main_obj.symbols:
            if sym.is_export and sym.rebased_addr:
                name = sym.name
                # Handle ordinal-only exports
                if name and name.startswith('ordinal_'):
                    export_symbols[sym.rebased_addr] = (None, int(name.split('_')[1]))
                else:
                    export_symbols[sym.rebased_addr] = (name, getattr(sym, 'ordinal', 0))

        if self._verbose:
            print(f"[angr] Found {len(export_symbols)} exports, analyzing...")

        processed = 0
        for addr, (name, ordinal) in export_symbols.items():
            if self._max_funcs > 0 and processed >= self._max_funcs:
                if self._verbose:
                    print(f"[angr] Reached max function limit ({self._max_funcs})")
                break

            elapsed = time.perf_counter() - start_time
            if elapsed > self._timeout * len(export_symbols):
                if self._verbose:
                    print(f"[angr] Global timeout reached")
                break

            export = self._analyze_export(
                proj, cfg, addr, name, ordinal, is_64bit
            )
            exports.append(export)
            processed += 1

        if self._verbose:
            elapsed = time.perf_counter() - start_time
            print(f"[angr] Analysis complete: {len(exports)} exports in {elapsed:.2f}s")

        return exports

    def _analyze_export(
        self,
        proj: 'angr.Project',
        cfg: 'angr.analyses.CFGFast',
        addr: int,
        name: Optional[str],
        ordinal: int,
        is_64bit: bool
    ) -> ExportSymbol:
        """Analyze a single export function."""
        # Base RVA calculation
        base_addr = proj.loader.main_object.mapped_base
        rva = addr - base_addr

        # Default values
        calling_conv = CallingConvention.WIN64 if is_64bit else CallingConvention.UNKNOWN
        arg_count = 0
        args = []
        return_type = "unknown"
        is_data = False
        is_thunk = False
        thunk_target = None
        is_noreturn = False
        stack_frame_size = 0
        confidence = 0.5

        # Check if this is a known function in CFG
        func = cfg.kb.functions.get(addr)

        if func is None:
            # Not recognized as function - might be data
            is_data = self._check_is_data(proj, addr)
            if is_data:
                return ExportSymbol(
                    name=name,
                    ordinal=ordinal,
                    rva=rva,
                    is_data=True,
                    analysis_source="angr",
                    confidence=0.8
                )
            # Try to create function anyway
            try:
                proj.analyses.CFGFast(
                    start_at_entry=False,
                    function_starts=[addr],
                    force_complete_scan=False
                )
                func = cfg.kb.functions.get(addr)
            except Exception:
                pass

        if func:
            confidence = 0.9

            # Check for noreturn
            if name and name in self.NORETURN_FUNCS:
                is_noreturn = True

            # Detect thunks
            if self._detect_thunks:
                thunk_info = self._detect_thunk(proj, func, addr)
                if thunk_info:
                    is_thunk = True
                    thunk_target = thunk_info

            # Analyze calling convention
            if self._analyze_cc:
                cc_result = self._analyze_calling_convention(proj, func, is_64bit)
                if cc_result:
                    calling_conv = cc_result

            # Analyze arguments
            if self._analyze_args and not is_thunk:
                args_result = self._analyze_arguments(proj, func, is_64bit)
                if args_result:
                    args = args_result
                    arg_count = len(args)
                    confidence = min(confidence + 0.05, 1.0)

            # Analyze return type
            if self._analyze_returns and not is_thunk:
                ret_result = self._analyze_return_type(proj, func)
                if ret_result:
                    return_type = ret_result

            # Get stack frame size
            try:
                if hasattr(func, 'sp_delta'):
                    stack_frame_size = abs(func.sp_delta) if func.sp_delta else 0
            except Exception:
                pass

        return ExportSymbol(
            name=name,
            ordinal=ordinal,
            rva=rva,
            is_data=is_data,
            calling_convention=calling_conv,
            arg_count=arg_count,
            args=args,
            return_type=return_type,
            is_thunk=is_thunk,
            thunk_target=thunk_target,
            is_noreturn=is_noreturn,
            stack_frame_size=stack_frame_size,
            analysis_source="angr",
            confidence=confidence
        )

    def _check_is_data(self, proj: 'angr.Project', addr: int) -> bool:
        """Check if address points to data rather than code."""
        try:
            # Check section characteristics
            section = proj.loader.find_section_containing(addr)
            if section:
                # Non-executable section = data
                if not section.is_executable:
                    return True
                # .rdata, .data sections
                if section.name in ('.rdata', '.data', '.bss', '.idata'):
                    return True

            # Try to disassemble first instruction
            block = proj.factory.block(addr, num_inst=1)
            if block.instructions == 0:
                return True

            # Check for common data patterns (all zeros, repeated bytes)
            mem = proj.loader.memory.load(addr, 16)
            if mem == b'\x00' * 16:
                return True

        except Exception:
            pass

        return False

    def _detect_thunk(
        self,
        proj: 'angr.Project',
        func: 'angr.knowledge_plugins.functions.Function',
        addr: int
    ) -> Optional[str]:
        """Detect if function is a thunk/trampoline."""
        try:
            # Get first block
            block = proj.factory.block(addr)

            # Check for JMP as first instruction
            if block.instructions >= 1:
                insns = block.capstone.insns
                if insns and insns[0].mnemonic == 'jmp':
                    # Direct jump
                    op = insns[0].op_str

                    # Try to resolve target
                    if op.startswith('0x'):
                        target_addr = int(op, 16)
                        # Check if target is an import
                        sym = proj.loader.find_symbol(target_addr)
                        if sym:
                            return sym.name

                    # Indirect jump (IAT)
                    if 'qword ptr' in op or 'dword ptr' in op:
                        # This is likely an IAT thunk
                        return f"[IAT:{op}]"

            # Check function size - thunks are typically very small
            if func.size <= 16 and func.size > 0:
                # Likely a thunk
                return "[small_func]"

        except Exception:
            pass

        return None

    def _analyze_calling_convention(
        self,
        proj: 'angr.Project',
        func: 'angr.knowledge_plugins.functions.Function',
        is_64bit: bool
    ) -> Optional[CallingConvention]:
        """Analyze calling convention using angr."""
        try:
            if is_64bit:
                # x64 always uses Microsoft x64 calling convention on Windows
                return CallingConvention.WIN64

            # For x86, try to determine CC
            # Run calling convention analysis
            cc_analysis = proj.analyses.CallingConvention(func)

            if cc_analysis.cc:
                cc = cc_analysis.cc

                # Map angr CC to our enum
                cc_name = cc.__class__.__name__

                if 'Cdecl' in cc_name:
                    return CallingConvention.CDECL
                elif 'Stdcall' in cc_name:
                    return CallingConvention.STDCALL
                elif 'Fastcall' in cc_name:
                    return CallingConvention.FASTCALL
                elif 'Thiscall' in cc_name:
                    return CallingConvention.THISCALL

            # Fallback: analyze ret instruction
            for block_addr in func.block_addrs:
                try:
                    block = proj.factory.block(block_addr)
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'ret':
                            # ret imm16 = stdcall
                            if insn.operands:
                                return CallingConvention.STDCALL
                            else:
                                return CallingConvention.CDECL
                except Exception:
                    continue

        except Exception:
            pass

        return None

    def _analyze_arguments(
        self,
        proj: 'angr.Project',
        func: 'angr.knowledge_plugins.functions.Function',
        is_64bit: bool
    ) -> List[ArgInfo]:
        """Analyze function arguments using VariableRecovery."""
        args = []

        try:
            # Run variable recovery
            vr = proj.analyses.VariableRecoveryFast(func)

            # Get input variables (arguments)
            if hasattr(vr, 'input_variables'):
                for i, var in enumerate(vr.input_variables()):
                    location = self._var_to_location(var, is_64bit)
                    is_ptr = self._is_pointer_type(var)

                    args.append(ArgInfo(
                        index=i,
                        location=location,
                        size=var.size if hasattr(var, 'size') else 0,
                        type_hint="ptr" if is_ptr else "int",
                        is_pointer=is_ptr
                    ))

            # Fallback: use calling convention to infer arg locations
            if not args:
                args = self._infer_args_from_cc(proj, func, is_64bit)

        except Exception:
            # Fallback to basic analysis
            args = self._infer_args_from_cc(proj, func, is_64bit)

        return args

    def _var_to_location(self, var, is_64bit: bool) -> str:
        """Convert angr variable to location string."""
        try:
            if hasattr(var, 'reg'):
                return var.reg
            elif hasattr(var, 'offset'):
                # Stack variable
                offset = var.offset
                if offset >= 0:
                    return f"stack+0x{offset:x}"
                else:
                    return f"stack-0x{abs(offset):x}"
            elif hasattr(var, 'addr'):
                return f"mem:0x{var.addr:x}"
        except Exception:
            pass
        return "unknown"

    def _is_pointer_type(self, var) -> bool:
        """Check if variable is likely a pointer."""
        try:
            if hasattr(var, 'size'):
                # Pointer size matches architecture
                return var.size in (4, 8)
            if hasattr(var, 'type') and var.type:
                type_str = str(var.type).lower()
                return 'ptr' in type_str or '*' in type_str
        except Exception:
            pass
        return False

    def _infer_args_from_cc(
        self,
        proj: 'angr.Project',
        func: 'angr.knowledge_plugins.functions.Function',
        is_64bit: bool
    ) -> List[ArgInfo]:
        """Infer arguments from calling convention and register usage."""
        args = []

        try:
            # Analyze register usage in function prologue
            block = proj.factory.block(func.addr)

            # x64 argument registers
            if is_64bit:
                arg_regs = ['rcx', 'rdx', 'r8', 'r9']
            else:
                # x86 - depends on CC, use generic approach
                arg_regs = ['ecx', 'edx']  # fastcall

            used_regs = set()

            for insn in block.capstone.insns:
                # Check operands for register usage
                for op in insn.operands:
                    if op.type == 1:  # REG
                        reg_name = insn.reg_name(op.reg)
                        if reg_name in arg_regs:
                            used_regs.add(reg_name)

                # Also check for stack accesses (additional args)
                if 'rbp' in insn.op_str or 'rsp' in insn.op_str or 'ebp' in insn.op_str or 'esp' in insn.op_str:
                    # Check for positive offsets (args)
                    if '+' in insn.op_str:
                        # Likely accessing argument
                        pass

            # Create ArgInfo for used registers
            for i, reg in enumerate(arg_regs):
                if reg in used_regs or i < len(used_regs):
                    args.append(ArgInfo(
                        index=i,
                        location=reg,
                        size=8 if is_64bit else 4,
                        type_hint="int",
                        is_pointer=False
                    ))

        except Exception:
            pass

        return args

    def _analyze_return_type(
        self,
        proj: 'angr.Project',
        func: 'angr.knowledge_plugins.functions.Function'
    ) -> Optional[str]:
        """Analyze function return type."""
        try:
            # Check all return sites
            for block_addr in func.block_addrs:
                try:
                    block = proj.factory.block(block_addr)

                    for insn in block.capstone.insns:
                        # Look for patterns before ret
                        if insn.mnemonic == 'xor':
                            # xor eax, eax = return 0 (likely bool or int)
                            if 'eax' in insn.op_str and insn.op_str.count('eax') == 2:
                                return "int"

                        if insn.mnemonic == 'mov':
                            if 'eax' in insn.op_str or 'rax' in insn.op_str:
                                op_str = insn.op_str

                                # mov eax, 1 or mov eax, 0 -> bool
                                if ', 0' in op_str or ', 1' in op_str:
                                    return "bool"

                                # mov rax, [mem] -> likely ptr
                                if '[' in op_str:
                                    return "ptr"

                        if insn.mnemonic == 'lea':
                            # lea rax, [...] = returning pointer
                            if 'rax' in insn.op_str or 'eax' in insn.op_str:
                                return "ptr"

                        # Check for setcc instructions (sete, setne, etc.)
                        if insn.mnemonic.startswith('set'):
                            return "bool"

                except Exception:
                    continue

        except Exception:
            pass

        return "unknown"


class CompositeExtractor(ExportExtractor):
    """Tries multiple extractors in order until one succeeds."""

    def __init__(self, extractors: List[ExportExtractor] = None, use_angr: bool = False):
        """Initialize composite extractor.

        Args:
            extractors: Custom list of extractors. If None, uses defaults.
            use_angr: Include AngrExtractor in default extractors (slower but more accurate)
        """
        if extractors is not None:
            self._extractors = [e for e in extractors if e.is_available()]
        else:
            # Default order: pefile (fast) first, then dumpbin, optionally angr
            self._extractors = []

            pefile_ext = PefileExtractor(analyze_calling_convention=True)
            dumpbin_ext = DumpbinExtractor()

            if pefile_ext.is_available():
                self._extractors.append(pefile_ext)
            if dumpbin_ext.is_available():
                self._extractors.append(dumpbin_ext)

            # Add angr if requested and available
            if use_angr:
                angr_ext = AngrExtractor(verbose=True)
                if angr_ext.is_available():
                    self._extractors.append(angr_ext)

    def is_available(self) -> bool:
        return len(self._extractors) > 0

    def extract(self, dll_path: Path) -> List[ExportSymbol]:
        last_error = None
        for extractor in self._extractors:
            try:
                return extractor.extract(dll_path)
            except Exception as e:
                last_error = e
                continue

        if last_error:
            raise last_error
        raise RuntimeError("No export extractor available")


class EnhancedExtractor(ExportExtractor):
    """Combines fast pefile extraction with selective angr enhancement.

    Uses pefile for basic extraction, then enhances selected exports
    with deep angr analysis. This provides a good balance between
    speed and accuracy.
    """

    def __init__(
        self,
        angr_threshold: int = 50,
        enhance_unnamed: bool = True,
        enhance_complex: bool = True,
        verbose: bool = False
    ):
        """Initialize enhanced extractor.

        Args:
            angr_threshold: Max exports to analyze with angr (0 = all)
            enhance_unnamed: Use angr for ordinal-only exports
            enhance_complex: Use angr for C++ mangled names
            verbose: Print progress
        """
        self._threshold = angr_threshold
        self._enhance_unnamed = enhance_unnamed
        self._enhance_complex = enhance_complex
        self._verbose = verbose

        self._pefile_ext = PefileExtractor(analyze_calling_convention=True)
        self._angr_ext = AngrExtractor(verbose=verbose) if HAVE_ANGR else None

    def is_available(self) -> bool:
        return self._pefile_ext.is_available()

    def extract(self, dll_path: Path) -> List[ExportSymbol]:
        """Extract with selective enhancement."""
        # Fast extraction first
        exports = self._pefile_ext.extract(dll_path)

        if not self._angr_ext or not self._angr_ext.is_available():
            return exports

        # Identify exports needing enhancement
        needs_enhancement = []
        for i, exp in enumerate(exports):
            if self._should_enhance(exp):
                needs_enhancement.append((i, exp))

        if not needs_enhancement:
            return exports

        # Limit to threshold
        if self._threshold > 0 and len(needs_enhancement) > self._threshold:
            needs_enhancement = needs_enhancement[:self._threshold]

        if self._verbose:
            print(f"[enhanced] Enhancing {len(needs_enhancement)} exports with angr...")

        # Run angr analysis
        try:
            angr_exports = self._angr_ext.extract(dll_path)
            angr_map = {(e.name, e.ordinal): e for e in angr_exports}

            # Merge results
            for i, exp in needs_enhancement:
                key = (exp.name, exp.ordinal)
                if key in angr_map:
                    enhanced = angr_map[key]
                    exports[i] = self._merge_exports(exp, enhanced)

        except Exception as e:
            if self._verbose:
                print(f"[enhanced] Angr analysis failed: {e}")

        return exports

    def _should_enhance(self, exp: ExportSymbol) -> bool:
        """Determine if export needs angr enhancement."""
        # Ordinal-only exports
        if self._enhance_unnamed and not exp.is_named:
            return True

        # C++ mangled names (complex calling conventions)
        if self._enhance_complex and exp.is_cpp_mangled:
            return True

        # Unknown calling convention
        if exp.calling_convention == CallingConvention.UNKNOWN:
            return True

        return False

    def _merge_exports(self, base: ExportSymbol, enhanced: ExportSymbol) -> ExportSymbol:
        """Merge base export with angr-enhanced data."""
        return ExportSymbol(
            name=base.name,
            ordinal=base.ordinal,
            rva=base.rva,
            forwarder=base.forwarder,
            is_data=enhanced.is_data if enhanced.confidence > 0.7 else base.is_data,
            calling_convention=enhanced.calling_convention if enhanced.confidence > 0.7 else base.calling_convention,
            arg_count=enhanced.arg_count if enhanced.args else base.arg_count,
            demangled_name=base.demangled_name,
            is_cpp_decorated=base.is_cpp_decorated,
            hint=base.hint,
            args=enhanced.args,
            return_type=enhanced.return_type,
            is_thunk=enhanced.is_thunk,
            thunk_target=enhanced.thunk_target,
            is_noreturn=enhanced.is_noreturn,
            stack_frame_size=enhanced.stack_frame_size,
            analysis_source="enhanced",
            confidence=enhanced.confidence
        )
