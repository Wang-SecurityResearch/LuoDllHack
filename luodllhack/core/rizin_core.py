# -*- coding: utf-8 -*-
"""
luodllhack/core/rizin_core.py - Rizin 核心分析引擎

LuoDllHack v6.0 的核心分析引擎，完全基于 Rizin 实现。
提供统一的二进制分析接口，替代原有的 Capstone + pefile 方案。

核心能力:
    1. 二进制加载和解析 (替代 pefile)
    2. 反汇编 (替代 Capstone)
    3. 控制流图构建 (替代自实现 CFG)
    4. 反编译 (新增能力)
    5. 类型恢复 (新增能力)
    6. 虚表分析 (新增能力)
    7. 调试支持 (新增能力)
    8. ROP Gadget 搜索 (新增能力)

依赖:
    - rzpipe: Rizin 的 Python 接口

作者: LuoDllHack Team
版本: 6.0.0
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Rizin Python 接口
try:
    import rzpipe
    HAVE_RIZIN = True
except ImportError:
    HAVE_RIZIN = False
    rzpipe = None

from .rizin_types import (
    # 架构和基本类型
    Architecture, Endianness, BinaryType, BinaryInfo,
    # 指令相关
    Instruction, InstructionType, Operand,
    # CFG 相关
    BasicBlock, EdgeType, Function, Variable,
    # 符号相关
    Import, Export, Symbol, Section, StringRef,
    # 高级分析
    VTable, VTableEntry, XRef, XRefType,
    # 调试和 ROP
    RegisterState, Breakpoint, RopGadget,
)

logger = logging.getLogger(__name__)


# =============================================================================
# 常量定义
# =============================================================================

# Rizin 指令类型映射
RIZIN_TYPE_MAP = {
    "mov": InstructionType.MOV,
    "lea": InstructionType.LEA,
    "push": InstructionType.PUSH,
    "pop": InstructionType.POP,
    "call": InstructionType.CALL,
    "jmp": InstructionType.JUMP,
    "ret": InstructionType.RET,
    "retn": InstructionType.RET,
    "nop": InstructionType.NOP,
    "syscall": InstructionType.SYSCALL,
    "int": InstructionType.SYSCALL,
    # 条件跳转
    "je": InstructionType.CJUMP,
    "jne": InstructionType.CJUMP,
    "jz": InstructionType.CJUMP,
    "jnz": InstructionType.CJUMP,
    "ja": InstructionType.CJUMP,
    "jae": InstructionType.CJUMP,
    "jb": InstructionType.CJUMP,
    "jbe": InstructionType.CJUMP,
    "jg": InstructionType.CJUMP,
    "jge": InstructionType.CJUMP,
    "jl": InstructionType.CJUMP,
    "jle": InstructionType.CJUMP,
    "jo": InstructionType.CJUMP,
    "jno": InstructionType.CJUMP,
    "js": InstructionType.CJUMP,
    "jns": InstructionType.CJUMP,
    "jp": InstructionType.CJUMP,
    "jnp": InstructionType.CJUMP,
    # 算术运算
    "add": InstructionType.ARITHMETIC,
    "sub": InstructionType.ARITHMETIC,
    "mul": InstructionType.ARITHMETIC,
    "imul": InstructionType.ARITHMETIC,
    "div": InstructionType.ARITHMETIC,
    "idiv": InstructionType.ARITHMETIC,
    "inc": InstructionType.ARITHMETIC,
    "dec": InstructionType.ARITHMETIC,
    "neg": InstructionType.ARITHMETIC,
    # 逻辑运算
    "and": InstructionType.LOGIC,
    "or": InstructionType.LOGIC,
    "xor": InstructionType.LOGIC,
    "not": InstructionType.LOGIC,
    "shl": InstructionType.LOGIC,
    "shr": InstructionType.LOGIC,
    "sar": InstructionType.LOGIC,
    "rol": InstructionType.LOGIC,
    "ror": InstructionType.LOGIC,
    # 比较
    "cmp": InstructionType.COMPARE,
    "test": InstructionType.COMPARE,
}

# x64 调用约定参数寄存器
X64_ARG_REGS = ["rcx", "rdx", "r8", "r9"]
X86_ARG_REGS = []  # x86 使用栈传参


# =============================================================================
# 异常定义
# =============================================================================

class RizinError(Exception):
    """Rizin 相关错误"""
    pass


class RizinNotFoundError(RizinError):
    """Rizin 未安装"""
    pass


class BinaryLoadError(RizinError):
    """二进制加载失败"""
    pass


class AnalysisError(RizinError):
    """分析错误"""
    pass


# =============================================================================
# RizinCore 核心引擎
# =============================================================================

class RizinCore:
    """
    Rizin 核心分析引擎

    LuoDllHack v6.0 的统一分析入口，提供:
    - 二进制加载和解析
    - 反汇编和 CFG 构建
    - 反编译 (Ghidra 插件)
    - 类型恢复
    - 虚表分析
    - 调试功能
    - ROP Gadget 搜索

    使用示例:
        with RizinCore("target.dll") as rz:
            # 获取导出函数
            exports = rz.get_exports()

            # 分析函数
            func = rz.analyze_function(exports[0].address)
            print(func.decompiled)

            # 搜索漏洞模式
            for block in func.blocks:
                for insn in block.instructions:
                    if insn.is_call:
                        print(f"发现调用: {insn}")
    """

    def __init__(
        self,
        binary_path: Union[str, Path],
        auto_analyze: bool = True,
        analyze_level: int = 2
    ):
        """
        初始化 Rizin 分析引擎

        参数:
            binary_path: 二进制文件路径
            auto_analyze: 是否自动执行分析
            analyze_level: 分析级别 (0-3, 越高越深入但越慢)
                0: 不分析
                1: 基本分析 (aa)
                2: 深度分析 (aaa) - 默认
                3: 完整分析 (aaaa) + 虚表分析
        """
        if not HAVE_RIZIN:
            raise RizinNotFoundError(
                "Rizin 未安装。请运行: pip install rzpipe\n"
                "并确保系统已安装 Rizin: https://rizin.re/"
            )

        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise BinaryLoadError(f"文件不存在: {binary_path}")

        # 初始化 Rizin
        try:
            self._rz = rzpipe.open(str(self.binary_path))
        except Exception as e:
            raise BinaryLoadError(f"无法加载二进制文件: {e}")

        # 缓存
        self._info_cache: Optional[BinaryInfo] = None
        self._imports_cache: Optional[Dict[int, Import]] = None
        self._exports_cache: Optional[Dict[int, Export]] = None
        self._functions_cache: Optional[Dict[int, Function]] = None
        self._sections_cache: Optional[List[Section]] = None
        self._strings_cache: Optional[List[StringRef]] = None
        self._vtables_cache: Optional[List[VTable]] = None

        # 执行自动分析
        if auto_analyze:
            self._auto_analyze(analyze_level)

        logger.info(f"已加载: {self.binary_path.name} ({self.info.arch.name}, {self.info.bits}位)")

    def _auto_analyze(self, level: int):
        """执行自动分析"""
        if level >= 1:
            self._rz.cmd("aa")       # 基本分析
        if level >= 2:
            self._rz.cmd("aaa")      # 深度分析
        if level >= 3:
            self._rz.cmd("aaaa")     # 完整分析
            self._rz.cmd("aav")      # 虚表分析

    # =========================================================================
    # 基本信息获取
    # =========================================================================

    @property
    def info(self) -> BinaryInfo:
        """获取二进制基本信息"""
        if self._info_cache is None:
            self._info_cache = self._load_binary_info()
        return self._info_cache

    def _load_binary_info(self) -> BinaryInfo:
        """加载二进制基本信息"""
        # 获取基本信息
        info = self._rz.cmdj("iIj") or {}
        entries = self._rz.cmdj("iej") or []

        # 解析架构
        bits = info.get("bits", 64)
        arch_str = info.get("arch", "x86")
        if arch_str == "x86":
            arch = Architecture.X64 if bits == 64 else Architecture.X86
        elif arch_str == "arm":
            arch = Architecture.ARM64 if bits == 64 else Architecture.ARM32
        elif arch_str == "mips":
            arch = Architecture.MIPS64 if bits == 64 else Architecture.MIPS32
        else:
            arch = Architecture.UNKNOWN

        # 解析文件类型
        bin_type_str = info.get("bintype", "").lower()
        if "pe" in bin_type_str:
            bin_type = BinaryType.PE
        elif "elf" in bin_type_str:
            bin_type = BinaryType.ELF
        elif "mach" in bin_type_str:
            bin_type = BinaryType.MACHO
        else:
            bin_type = BinaryType.UNKNOWN

        # 解析安全特性
        checksec = self._rz.cmdj("iCj") or {}

        return BinaryInfo(
            path=str(self.binary_path),
            size=self.binary_path.stat().st_size,
            arch=arch,
            bits=bits,
            endian=Endianness.BIG if info.get("endian") == "big" else Endianness.LITTLE,
            binary_type=bin_type,
            format=info.get("bintype", ""),
            image_base=info.get("baddr", 0),
            entry_point=entries[0].get("vaddr", 0) if entries else 0,
            compiler=info.get("compiler", ""),
            language=info.get("lang", ""),
            has_nx=checksec.get("nx", False),
            has_canary=checksec.get("canary", False),
            has_pie=checksec.get("pic", False),
            has_relro=checksec.get("relro", "") != "no",
            has_cfg=checksec.get("cfg", False),
        )

    @property
    def arch(self) -> Architecture:
        """获取架构"""
        return self.info.arch

    @property
    def bits(self) -> int:
        """获取位数"""
        return self.info.bits

    @property
    def image_base(self) -> int:
        """获取映像基址"""
        return self.info.image_base

    @property
    def entry_point(self) -> int:
        """获取入口点"""
        return self.info.entry_point

    # =========================================================================
    # 导入导出
    # =========================================================================

    def get_imports(self) -> Dict[int, Import]:
        """
        获取导入表

        返回:
            Dict[地址, Import]: 导入函数字典
        """
        if self._imports_cache is None:
            self._imports_cache = {}
            imports_data = self._rz.cmdj("iij") or []

            for imp in imports_data:
                addr = imp.get("plt", imp.get("vaddr", 0))
                if addr:
                    self._imports_cache[addr] = Import(
                        address=addr,
                        name=imp.get("name", ""),
                        library=imp.get("libname", ""),
                        ordinal=imp.get("ordinal", 0),
                    )

        return self._imports_cache

    def get_exports(self) -> Dict[int, Export]:
        """
        获取导出表

        返回:
            Dict[地址, Export]: 导出函数字典
        """
        if self._exports_cache is None:
            self._exports_cache = {}
            exports_data = self._rz.cmdj("iEj") or []

            for exp in exports_data:
                addr = exp.get("vaddr", 0)
                if addr:
                    self._exports_cache[addr] = Export(
                        address=addr,
                        name=exp.get("name", ""),
                        ordinal=exp.get("ordinal", 0),
                        is_forwarded=exp.get("forwarded", False),
                        forward_name=exp.get("forward", ""),
                    )

        return self._exports_cache

    def get_import_by_name(self, name: str) -> Optional[Import]:
        """根据名称查找导入函数"""
        for imp in self.get_imports().values():
            if imp.name == name or imp.full_name == name:
                return imp
        return None

    def get_export_by_name(self, name: str) -> Optional[Export]:
        """根据名称查找导出函数"""
        for exp in self.get_exports().values():
            if exp.name == name:
                return exp
        return None

    # =========================================================================
    # 节区和字符串
    # =========================================================================

    def get_sections(self) -> List[Section]:
        """获取节区列表"""
        if self._sections_cache is None:
            self._sections_cache = []
            sections_data = self._rz.cmdj("iSj") or []

            for sec in sections_data:
                perm = sec.get("perm", "")
                self._sections_cache.append(Section(
                    name=sec.get("name", ""),
                    virtual_address=sec.get("vaddr", 0),
                    virtual_size=sec.get("vsize", 0),
                    raw_offset=sec.get("paddr", 0),
                    raw_size=sec.get("size", 0),
                    is_executable="x" in perm,
                    is_writable="w" in perm,
                    is_readable="r" in perm,
                    contains_code="x" in perm,
                    contains_data="w" in perm and "x" not in perm,
                ))

        return self._sections_cache

    def get_strings(self, min_length: int = 4) -> List[StringRef]:
        """获取字符串列表"""
        if self._strings_cache is None:
            self._strings_cache = []
            strings_data = self._rz.cmdj("izj") or []

            for s in strings_data:
                if s.get("length", 0) >= min_length:
                    self._strings_cache.append(StringRef(
                        address=s.get("vaddr", 0),
                        value=s.get("string", ""),
                        length=s.get("length", 0),
                        encoding=s.get("type", "ascii"),
                        section=s.get("section", ""),
                    ))

        return self._strings_cache

    # =========================================================================
    # 反汇编
    # =========================================================================

    def disasm_at(self, address: int, count: int = 50) -> List[Instruction]:
        """
        从指定地址反汇编

        参数:
            address: 起始地址
            count: 指令数量

        返回:
            指令列表
        """
        data = self._rz.cmdj(f"pdj {count} @ {address}") or []
        return [self._parse_instruction(d) for d in data if d.get("offset")]

    def disasm_bytes(self, data: bytes, address: int = 0) -> List[Instruction]:
        """
        反汇编字节序列

        参数:
            data: 字节序列
            address: 起始地址

        返回:
            指令列表
        """
        # 写入临时文件或使用内存
        hex_str = data.hex()
        result = self._rz.cmdj(f"pad {hex_str} @ {address}") or []
        return [self._parse_instruction(d) for d in result if d.get("offset")]

    def _parse_instruction(self, data: Dict) -> Instruction:
        """解析 Rizin 指令数据"""
        mnemonic = data.get("mnemonic", "")
        type_str = data.get("type", "")

        # 确定指令类型
        inst_type = RIZIN_TYPE_MAP.get(
            mnemonic.lower(),
            InstructionType.OTHER
        )

        # 如果 Rizin 提供了类型信息，使用它
        if type_str:
            if "call" in type_str:
                inst_type = InstructionType.CALL
            elif "cjmp" in type_str:
                inst_type = InstructionType.CJUMP
            elif "jmp" in type_str:
                inst_type = InstructionType.JUMP
            elif "ret" in type_str:
                inst_type = InstructionType.RET

        # 提取操作数
        disasm = data.get("disasm", "")
        opcode = data.get("opcode", "")
        operands_str = opcode.replace(mnemonic, "").strip() if opcode else ""

        insn = Instruction(
            address=data.get("offset", 0),
            size=data.get("size", 0),
            mnemonic=mnemonic,
            operands_str=operands_str,
            bytes_hex=data.get("bytes", ""),
            disasm=disasm,
            type=inst_type,
            type_str=type_str,
            esil=data.get("esil", ""),
            jump_target=data.get("jump", 0),
            comment=data.get("comment", ""),
        )

        # 解析引用
        if data.get("refs"):
            insn.xrefs_from = [r.get("addr", 0) for r in data["refs"]]

        # 设置调用目标
        if inst_type == InstructionType.CALL:
            insn.call_target = data.get("jump", 0)

        return insn

    # =========================================================================
    # 函数分析
    # =========================================================================

    def get_all_functions(self) -> Dict[int, Function]:
        """获取所有函数"""
        if self._functions_cache is None:
            self._functions_cache = {}
            funcs_data = self._rz.cmdj("aflj") or []

            for f in funcs_data:
                addr = f.get("offset", 0)
                self._functions_cache[addr] = Function(
                    address=addr,
                    name=f.get("name", f"fcn_{addr:x}"),
                    size=f.get("size", 0),
                    arg_count=f.get("nargs", 0),
                    var_count=f.get("nlocals", 0),
                    stack_size=f.get("stackframe", 0),
                    is_thunk="thunk" in f.get("name", "").lower(),
                )

        return self._functions_cache

    def analyze_function(self, address: int) -> Function:
        """
        深度分析函数

        参数:
            address: 函数地址

        返回:
            完整的函数信息，包括 CFG、反编译等
        """
        # 跳转到函数
        self._rz.cmd(f"s {address}")

        # 获取函数基本信息
        func_info = self._rz.cmdj("afij") or [{}]
        func_info = func_info[0] if func_info else {}

        func = Function(
            address=address,
            name=func_info.get("name", f"fcn_{address:x}"),
            size=func_info.get("size", 0),
            calling_convention=func_info.get("calltype", ""),
            signature=func_info.get("signature", ""),
            return_type=func_info.get("type", ""),
            arg_count=func_info.get("nargs", 0),
            var_count=func_info.get("nlocals", 0),
            stack_size=func_info.get("stackframe", 0),
            cyclomatic_complexity=func_info.get("cc", 0),
        )

        # 获取参数和变量
        func.arguments = self._get_function_args(address)
        func.local_vars = self._get_function_vars(address)

        # 获取基本块
        func.blocks = self._get_function_blocks(address)
        func.block_count = len(func.blocks)

        # 检测是否有循环
        func.has_loop = self._detect_loops(func.blocks)

        # 获取调用关系
        func.calls_to = self._get_calls_from(address)
        func.called_from = self._get_calls_to(address)
        func.is_leaf = len(func.calls_to) == 0

        # 获取反编译结果
        func.decompiled = self.decompile(address)

        # 检查是否是导出函数
        func.is_export = address in self.get_exports()

        return func

    def _get_function_args(self, address: int) -> List[Variable]:
        """获取函数参数"""
        args = []
        try:
            data = self._rz.cmdj(f"afvlj @ {address}") or {}

            # 解析寄存器参数
            for v in data.get("reg", []):
                if v.get("arg", False):
                    var_type = v.get("type", "")
                    storage = v.get("storage", {})
                    args.append(Variable(
                        name=v.get("name", ""),
                        type=var_type,
                        kind="arg",
                        storage=storage.get("reg", ""),
                        size=8,  # 默认 64 位
                        stack_offset=0,
                        is_pointer="*" in var_type,
                        is_array="[" in var_type,
                    ))

            # 解析栈参数
            for v in data.get("stack", []):
                if v.get("arg", False):
                    var_type = v.get("type", "")
                    storage = v.get("storage", {})
                    args.append(Variable(
                        name=v.get("name", ""),
                        type=var_type,
                        kind="arg",
                        storage="stack",
                        size=8,
                        stack_offset=storage.get("stack", 0),
                        is_pointer="*" in var_type,
                        is_array="[" in var_type,
                    ))
        except Exception:
            pass

        return args

    def _get_function_vars(self, address: int) -> List[Variable]:
        """获取函数局部变量"""
        vars_list = []
        try:
            data = self._rz.cmdj(f"afvlj @ {address}") or {}

            # 解析栈变量 (非参数)
            for v in data.get("stack", []):
                if not v.get("arg", False):
                    var_type = v.get("type", "")
                    storage = v.get("storage", {})
                    vars_list.append(Variable(
                        name=v.get("name", ""),
                        type=var_type,
                        kind="var",
                        storage="stack",
                        size=8,
                        stack_offset=storage.get("stack", 0),
                        is_pointer="*" in var_type,
                        is_array="[" in var_type,
                    ))

            # 解析寄存器变量 (非参数)
            for v in data.get("reg", []):
                if not v.get("arg", False):
                    var_type = v.get("type", "")
                    storage = v.get("storage", {})
                    vars_list.append(Variable(
                        name=v.get("name", ""),
                        type=var_type,
                        kind="reg",
                        storage=storage.get("reg", ""),
                        size=8,
                        stack_offset=0,
                        is_pointer="*" in var_type,
                        is_array="[" in var_type,
                    ))
        except Exception:
            pass

        return vars_list

    def _get_function_blocks(self, address: int) -> List[BasicBlock]:
        """获取函数的所有基本块"""
        blocks = []
        blocks_data = self._rz.cmdj(f"afbj @ {address}") or []

        for b in blocks_data:
            block = BasicBlock(
                address=b.get("addr", 0),
                size=b.get("size", 0),
                instruction_count=b.get("ninstr", 0),
                jump_target=b.get("jump", 0),
                fail_target=b.get("fail", 0),
                is_traced=b.get("traced", False),
            )

            # 计算结束地址
            block.end_address = block.address + block.size

            # 获取块内指令
            if block.instruction_count > 0:
                block.instructions = self.disasm_at(
                    block.address,
                    block.instruction_count
                )

            # 设置后继
            if block.jump_target:
                if block.fail_target:
                    # 条件跳转: 两个后继
                    block.successors.append((block.jump_target, EdgeType.CONDITIONAL_TRUE))
                    block.successors.append((block.fail_target, EdgeType.CONDITIONAL_FALSE))
                else:
                    # 无条件跳转
                    block.successors.append((block.jump_target, EdgeType.UNCONDITIONAL))
            elif block.fail_target:
                # Fall-through
                block.successors.append((block.fail_target, EdgeType.CONDITIONAL_FALSE))

            blocks.append(block)

        # 构建前驱关系
        block_map = {b.address: b for b in blocks}
        for block in blocks:
            for succ_addr, _ in block.successors:
                if succ_addr in block_map:
                    block_map[succ_addr].predecessors.append(block.address)

        return blocks

    def _detect_loops(self, blocks: List[BasicBlock]) -> bool:
        """检测是否存在循环 (简单的后向边检测)"""
        visited = set()
        rec_stack = set()

        def has_back_edge(addr: int) -> bool:
            visited.add(addr)
            rec_stack.add(addr)

            block = next((b for b in blocks if b.address == addr), None)
            if block:
                for succ_addr, _ in block.successors:
                    if succ_addr not in visited:
                        if has_back_edge(succ_addr):
                            return True
                    elif succ_addr in rec_stack:
                        return True

            rec_stack.discard(addr)
            return False

        if blocks:
            return has_back_edge(blocks[0].address)
        return False

    def _get_calls_from(self, address: int) -> List[int]:
        """获取函数调用的其他函数"""
        xrefs = self._rz.cmdj(f"afxj @ {address}") or []
        return [x.get("to", 0) for x in xrefs if x.get("type") == "CALL"]

    def _get_calls_to(self, address: int) -> List[int]:
        """获取调用该函数的位置"""
        xrefs = self._rz.cmdj(f"axtj @ {address}") or []
        return [x.get("from", 0) for x in xrefs if x.get("type") == "CALL"]

    # =========================================================================
    # 反编译 (核心新增能力)
    # =========================================================================

    def decompile(self, address: int) -> str:
        """
        反编译函数

        使用 Rizin 的 Ghidra 反编译插件 (r2ghidra) 或内置反编译器。

        参数:
            address: 函数地址

        返回:
            反编译的伪代码字符串
        """
        self._rz.cmd(f"s {address}")

        # 尝试使用 Ghidra 反编译器
        result = self._rz.cmd("pdg")
        if result and "Cannot" not in result:
            return result.strip()

        # 回退到 pdf (反汇编函数)
        result = self._rz.cmd("pdf")
        if result and "Cannot" not in result:
            return result.strip()

        return ""

    def decompile_json(self, address: int) -> Dict:
        """获取结构化的反编译结果"""
        self._rz.cmd(f"s {address}")
        return self._rz.cmdj("pdgj") or {}

    # =========================================================================
    # 交叉引用
    # =========================================================================

    def get_xrefs_to(self, address: int) -> List[XRef]:
        """获取指向该地址的引用"""
        xrefs = []
        data = self._rz.cmdj(f"axtj @ {address}") or []

        for x in data:
            xref_type_str = x.get("type", "")
            if "CALL" in xref_type_str:
                xref_type = XRefType.CALL
            elif "JMP" in xref_type_str:
                xref_type = XRefType.JUMP
            elif "DATA" in xref_type_str:
                xref_type = XRefType.DATA
            elif "STRING" in xref_type_str:
                xref_type = XRefType.STRING
            else:
                xref_type = XRefType.UNKNOWN

            xrefs.append(XRef(
                from_addr=x.get("from", 0),
                to_addr=address,
                type=xref_type,
                from_function=x.get("fcn_name", ""),
            ))

        return xrefs

    def get_xrefs_from(self, address: int) -> List[XRef]:
        """获取从该地址发出的引用"""
        xrefs = []
        data = self._rz.cmdj(f"axfj @ {address}") or []

        for x in data:
            xref_type_str = x.get("type", "")
            if "CALL" in xref_type_str:
                xref_type = XRefType.CALL
            elif "JMP" in xref_type_str:
                xref_type = XRefType.JUMP
            else:
                xref_type = XRefType.DATA

            xrefs.append(XRef(
                from_addr=address,
                to_addr=x.get("to", 0),
                type=xref_type,
            ))

        return xrefs

    # =========================================================================
    # 虚表分析 (新增能力)
    # =========================================================================

    def get_vtables(self) -> List[VTable]:
        """
        获取虚表信息

        用于解析 C++ 虚函数调用，提升间接调用覆盖率。
        """
        if self._vtables_cache is None:
            self._vtables_cache = []

            # 确保执行过虚表分析
            self._rz.cmd("aav")
            vtables_data = self._rz.cmdj("avj") or []

            for vt in vtables_data:
                entries = []
                methods = vt.get("methods", [])

                for i, method in enumerate(methods):
                    entries.append(VTableEntry(
                        offset=i * (self.bits // 8),
                        target_address=method if isinstance(method, int) else method.get("addr", 0),
                        target_name="",
                    ))

                self._vtables_cache.append(VTable(
                    address=vt.get("offset", 0),
                    entries=entries,
                ))

        return self._vtables_cache

    def resolve_indirect_call(self, address: int) -> List[int]:
        """
        解析间接调用的可能目标

        参数:
            address: call 指令地址

        返回:
            可能的目标地址列表
        """
        targets = []

        # 从交叉引用获取
        xrefs = self.get_xrefs_from(address)
        for xref in xrefs:
            if xref.type == XRefType.CALL:
                targets.append(xref.to_addr)

        # 从虚表获取
        for vt in self.get_vtables():
            targets.extend(vt.method_addresses)

        return list(set(targets))

    # =========================================================================
    # ROP Gadget 搜索 (新增能力)
    # =========================================================================

    def find_rop_gadgets(self, pattern: str = "") -> List[RopGadget]:
        """
        搜索 ROP gadgets

        参数:
            pattern: 搜索模式 (如 "pop r??; ret")

        返回:
            ROP gadget 列表
        """
        if pattern:
            data = self._rz.cmdj(f"/Rj {pattern}") or []
        else:
            data = self._rz.cmdj("/Rj") or []

        gadgets = []
        for g in data:
            gadgets.append(RopGadget(
                address=g.get("offset", 0),
                instructions=g.get("opcode", ""),
                size=g.get("size", 0),
            ))

        return gadgets

    def find_gadget_by_regs(self, regs: List[str]) -> List[RopGadget]:
        """
        根据寄存器查找 gadget

        参数:
            regs: 需要控制的寄存器列表 (如 ["rdi", "rsi"])

        返回:
            可以控制这些寄存器的 gadget
        """
        gadgets = []
        for reg in regs:
            pattern = f"pop {reg}"
            gadgets.extend(self.find_rop_gadgets(pattern))
        return gadgets

    # =========================================================================
    # 调试支持 (新增能力)
    # =========================================================================

    def debug_start(self, args: List[str] = None):
        """启动调试"""
        if args:
            self._rz.cmd(f"doo {' '.join(args)}")
        else:
            self._rz.cmd("doo")

    def debug_continue(self):
        """继续执行"""
        self._rz.cmd("dc")

    def debug_step(self):
        """单步执行"""
        self._rz.cmd("ds")

    def debug_step_over(self):
        """单步跳过"""
        self._rz.cmd("dso")

    def debug_set_breakpoint(self, address: int) -> Breakpoint:
        """设置断点"""
        self._rz.cmd(f"db {address}")
        return Breakpoint(address=address)

    def debug_remove_breakpoint(self, address: int):
        """移除断点"""
        self._rz.cmd(f"db- {address}")

    def debug_get_registers(self) -> RegisterState:
        """获取寄存器状态"""
        data = self._rz.cmdj("drj") or {}
        return RegisterState(values=data)

    def debug_read_memory(self, address: int, size: int) -> bytes:
        """读取内存"""
        hex_str = self._rz.cmd(f"p8 {size} @ {address}")
        return bytes.fromhex(hex_str.strip()) if hex_str else b""

    def debug_write_memory(self, address: int, data: bytes):
        """写入内存"""
        hex_str = data.hex()
        self._rz.cmd(f"wx {hex_str} @ {address}")

    # =========================================================================
    # 内存读写
    # =========================================================================

    def read_bytes(self, address: int, size: int) -> bytes:
        """读取字节"""
        hex_str = self._rz.cmd(f"p8 {size} @ {address}")
        return bytes.fromhex(hex_str.strip()) if hex_str else b""

    def read_string(self, address: int, max_length: int = 256) -> str:
        """读取字符串"""
        result = self._rz.cmd(f"ps @ {address}")
        return result.strip() if result else ""

    def read_pointer(self, address: int) -> int:
        """读取指针"""
        size = self.bits // 8
        data = self.read_bytes(address, size)
        if len(data) == size:
            return int.from_bytes(data, byteorder='little')
        return 0

    # =========================================================================
    # 辅助方法
    # =========================================================================

    def seek(self, address: int):
        """跳转到地址"""
        self._rz.cmd(f"s {address}")

    def cmd(self, command: str) -> str:
        """执行原始 Rizin 命令"""
        return self._rz.cmd(command)

    def cmdj(self, command: str) -> Any:
        """执行命令并返回 JSON"""
        return self._rz.cmdj(command)

    def clear_cache(self):
        """清除所有缓存"""
        self._info_cache = None
        self._imports_cache = None
        self._exports_cache = None
        self._functions_cache = None
        self._sections_cache = None
        self._strings_cache = None
        self._vtables_cache = None

    def close(self):
        """关闭引擎"""
        if self._rz:
            self._rz.quit()
            self._rz = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()


# =============================================================================
# 便捷函数
# =============================================================================

def load_binary(path: str, auto_analyze: bool = True) -> RizinCore:
    """
    加载二进制文件

    便捷函数，创建 RizinCore 实例。

    参数:
        path: 文件路径
        auto_analyze: 是否自动分析

    返回:
        RizinCore 实例
    """
    return RizinCore(path, auto_analyze=auto_analyze)


def check_rizin_available() -> bool:
    """检查 Rizin 是否可用"""
    return HAVE_RIZIN
