# -*- coding: utf-8 -*-
"""
luodllhack/core/rizin_types.py - Rizin 数据结构定义

LuoDllHack v6.0 核心数据结构，完全基于 Rizin 分析引擎。
所有分析模块使用统一的数据结构，确保数据一致性。

作者: LuoDllHack Team
版本: 6.0.0
"""

from typing import Dict, List, Set, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto


# =============================================================================
# 架构枚举
# =============================================================================

class Architecture(Enum):
    """CPU 架构类型"""
    X86 = auto()        # 32位 x86
    X64 = auto()        # 64位 x86-64
    ARM32 = auto()      # 32位 ARM
    ARM64 = auto()      # 64位 ARM (AArch64)
    MIPS32 = auto()     # 32位 MIPS
    MIPS64 = auto()     # 64位 MIPS
    UNKNOWN = auto()    # 未知架构


class Endianness(Enum):
    """字节序"""
    LITTLE = auto()     # 小端
    BIG = auto()        # 大端


class BinaryType(Enum):
    """二进制文件类型"""
    PE = auto()         # Windows PE (DLL/EXE)
    ELF = auto()        # Linux ELF
    MACHO = auto()      # macOS Mach-O
    RAW = auto()        # 原始二进制
    UNKNOWN = auto()


# =============================================================================
# 指令相关
# =============================================================================

class InstructionType(Enum):
    """指令类型分类"""
    MOV = auto()        # 数据移动
    ARITHMETIC = auto() # 算术运算
    LOGIC = auto()      # 逻辑运算
    COMPARE = auto()    # 比较
    JUMP = auto()       # 无条件跳转
    CJUMP = auto()      # 条件跳转
    CALL = auto()       # 函数调用
    RET = auto()        # 返回
    PUSH = auto()       # 压栈
    POP = auto()        # 出栈
    LEA = auto()        # 地址计算
    NOP = auto()        # 空操作
    SYSCALL = auto()    # 系统调用
    PRIVILEGED = auto() # 特权指令
    CRYPTO = auto()     # 加密指令
    SIMD = auto()       # SIMD 向量指令
    OTHER = auto()      # 其他


@dataclass
class Operand:
    """指令操作数"""
    type: str               # reg, imm, mem
    value: Union[str, int]  # 寄存器名 或 立即数值
    size: int = 0           # 操作数大小 (字节)

    # 内存操作数详情
    base_reg: str = ""      # 基址寄存器
    index_reg: str = ""     # 索引寄存器
    scale: int = 1          # 比例因子
    displacement: int = 0   # 偏移量

    @property
    def is_register(self) -> bool:
        return self.type == "reg"

    @property
    def is_immediate(self) -> bool:
        return self.type == "imm"

    @property
    def is_memory(self) -> bool:
        return self.type == "mem"


@dataclass
class Instruction:
    """
    反汇编指令

    包含 Rizin 提供的完整指令信息，包括 ESIL 中间表示。
    """
    address: int                # 指令地址
    size: int                   # 指令大小 (字节)
    mnemonic: str               # 助记符 (mov, call, jmp 等)
    operands_str: str           # 操作数字符串
    bytes_hex: str              # 指令字节 (十六进制)
    disasm: str                 # 完整反汇编文本

    # 指令分类
    type: InstructionType = InstructionType.OTHER
    type_str: str = ""          # Rizin 原始类型字符串

    # ESIL 中间表示 (用于精确语义分析)
    esil: str = ""

    # 操作数解析
    operands: List[Operand] = field(default_factory=list)

    # 寄存器读写
    regs_read: List[str] = field(default_factory=list)
    regs_write: List[str] = field(default_factory=list)

    # 引用信息
    jump_target: int = 0        # 跳转目标地址
    call_target: int = 0        # 调用目标地址
    xrefs_from: List[int] = field(default_factory=list)

    # 注释和标注
    comment: str = ""

    @property
    def bytes(self) -> bytes:
        """获取指令字节"""
        return bytes.fromhex(self.bytes_hex) if self.bytes_hex else b""

    @property
    def is_call(self) -> bool:
        return self.type == InstructionType.CALL

    @property
    def is_jump(self) -> bool:
        return self.type in (InstructionType.JUMP, InstructionType.CJUMP)

    @property
    def is_conditional_jump(self) -> bool:
        return self.type == InstructionType.CJUMP

    @property
    def is_ret(self) -> bool:
        return self.type == InstructionType.RET

    @property
    def is_terminator(self) -> bool:
        """是否是基本块终结指令"""
        return self.type in (
            InstructionType.JUMP,
            InstructionType.CJUMP,
            InstructionType.RET,
            InstructionType.CALL
        )

    def __str__(self) -> str:
        return f"0x{self.address:08x}: {self.disasm}"


# =============================================================================
# 基本块和控制流图
# =============================================================================

class EdgeType(Enum):
    """控制流边类型"""
    UNCONDITIONAL = auto()  # 无条件跳转
    CONDITIONAL_TRUE = auto()   # 条件为真
    CONDITIONAL_FALSE = auto()  # 条件为假 (fall-through)
    CALL = auto()           # 函数调用
    RETURN = auto()         # 返回


@dataclass
class BasicBlock:
    """
    基本块

    控制流图的基本单元，包含线性执行的指令序列。
    """
    address: int                # 起始地址
    size: int = 0               # 块大小 (字节)
    end_address: int = 0        # 结束地址

    # 指令列表
    instructions: List[Instruction] = field(default_factory=list)
    instruction_count: int = 0

    # 控制流
    jump_target: int = 0        # 跳转目标 (jmp/jcc 的目标)
    fail_target: int = 0        # fall-through 目标

    # 前驱和后继
    predecessors: List[int] = field(default_factory=list)
    successors: List[tuple] = field(default_factory=list)  # [(addr, EdgeType), ...]

    # 数据流分析用
    defs: Set[str] = field(default_factory=set)     # 定义的变量
    uses: Set[str] = field(default_factory=set)     # 使用的变量
    live_in: Set[str] = field(default_factory=set)  # 入口活跃变量
    live_out: Set[str] = field(default_factory=set) # 出口活跃变量

    # 元数据
    is_traced: bool = False     # 是否被追踪过

    @property
    def terminator(self) -> Optional[Instruction]:
        """获取终结指令"""
        return self.instructions[-1] if self.instructions else None

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other) -> bool:
        if isinstance(other, BasicBlock):
            return self.address == other.address
        return False


# =============================================================================
# 函数相关
# =============================================================================

@dataclass
class Variable:
    """函数变量 (参数或局部变量)"""
    name: str               # 变量名
    type: str               # 类型字符串
    kind: str               # arg, var, reg
    storage: str            # 存储位置 (寄存器名 或 栈偏移)
    size: int = 0           # 大小

    # 栈变量详情
    stack_offset: int = 0   # 栈偏移 (相对于 rbp/rsp)

    # 类型详情
    is_pointer: bool = False
    is_array: bool = False
    array_size: int = 0
    base_type: str = ""     # 基础类型 (去掉指针/数组后)


@dataclass
class Function:
    """
    函数信息

    包含 Rizin 分析得到的完整函数信息，包括反编译结果。
    """
    address: int                # 函数起始地址
    name: str                   # 函数名
    size: int = 0               # 函数大小

    # 基本块和 CFG
    blocks: List[BasicBlock] = field(default_factory=list)
    block_count: int = 0

    # 调用约定和签名
    calling_convention: str = ""    # cdecl, stdcall, fastcall, ms_fastcall
    signature: str = ""             # 完整函数签名
    return_type: str = ""           # 返回类型

    # 参数和变量
    arguments: List[Variable] = field(default_factory=list)
    local_vars: List[Variable] = field(default_factory=list)
    arg_count: int = 0
    var_count: int = 0
    stack_size: int = 0             # 栈帧大小

    # 调用关系
    calls_to: List[int] = field(default_factory=list)       # 调用的函数地址
    called_from: List[int] = field(default_factory=list)    # 被调用位置

    # 反编译结果 (核心增强)
    decompiled: str = ""            # 反编译伪代码

    # 属性标记
    is_export: bool = False         # 是否是导出函数
    is_import: bool = False         # 是否是导入函数
    is_thunk: bool = False          # 是否是跳转桩
    is_leaf: bool = False           # 是否是叶子函数 (不调用其他函数)
    has_loop: bool = False          # 是否包含循环

    # 复杂度指标
    cyclomatic_complexity: int = 0  # 圈复杂度

    def get_block(self, addr: int) -> Optional[BasicBlock]:
        """根据地址获取基本块"""
        for block in self.blocks:
            if block.address <= addr < block.address + block.size:
                return block
        return None


# =============================================================================
# 导入导出和符号
# =============================================================================

@dataclass
class Import:
    """导入函数"""
    address: int            # PLT/IAT 地址
    name: str               # 函数名
    library: str            # 所属库 (DLL/SO)
    ordinal: int = 0        # 序号 (如果按序号导入)

    @property
    def full_name(self) -> str:
        return f"{self.library}!{self.name}" if self.library else self.name


@dataclass
class Export:
    """导出函数"""
    address: int            # 函数地址
    name: str               # 函数名
    ordinal: int = 0        # 序号
    is_forwarded: bool = False  # 是否是转发
    forward_name: str = ""      # 转发目标


@dataclass
class Symbol:
    """符号信息"""
    address: int
    name: str
    type: str               # func, object, section, ...
    size: int = 0
    is_global: bool = False


# =============================================================================
# 节区和内存
# =============================================================================

@dataclass
class Section:
    """节区/段信息"""
    name: str               # 节区名 (.text, .data, ...)
    virtual_address: int    # 虚拟地址
    virtual_size: int       # 虚拟大小
    raw_offset: int         # 文件偏移
    raw_size: int           # 文件大小

    # 权限
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True

    # 特殊标记
    contains_code: bool = False
    contains_data: bool = False
    is_bss: bool = False


@dataclass
class StringRef:
    """字符串引用"""
    address: int            # 字符串地址
    value: str              # 字符串内容
    length: int             # 长度
    encoding: str = "ascii" # 编码 (ascii, utf-8, utf-16le, ...)
    section: str = ""       # 所在节区
    xrefs: List[int] = field(default_factory=list)  # 引用该字符串的地址


# =============================================================================
# 虚表和类 (C++ 分析)
# =============================================================================

@dataclass
class VTableEntry:
    """虚表条目"""
    offset: int             # 在虚表中的偏移
    target_address: int     # 目标函数地址
    target_name: str = ""   # 目标函数名


@dataclass
class VTable:
    """虚表信息 (C++ 类分析)"""
    address: int                        # 虚表地址
    entries: List[VTableEntry] = field(default_factory=list)
    class_name: str = ""                # 类名 (如果能识别)

    @property
    def method_addresses(self) -> List[int]:
        return [e.target_address for e in self.entries]


# =============================================================================
# 交叉引用
# =============================================================================

class XRefType(Enum):
    """交叉引用类型"""
    CALL = auto()       # 函数调用
    JUMP = auto()       # 跳转
    DATA = auto()       # 数据引用
    STRING = auto()     # 字符串引用
    UNKNOWN = auto()


@dataclass
class XRef:
    """交叉引用"""
    from_addr: int          # 来源地址
    to_addr: int            # 目标地址
    type: XRefType          # 引用类型

    # 可选详情
    from_function: str = "" # 来源函数名
    to_function: str = ""   # 目标函数名


# =============================================================================
# 二进制文件信息
# =============================================================================

@dataclass
class BinaryInfo:
    """二进制文件基本信息"""
    path: str                   # 文件路径
    size: int                   # 文件大小

    # 架构信息
    arch: Architecture = Architecture.UNKNOWN
    bits: int = 64              # 位数
    endian: Endianness = Endianness.LITTLE

    # 文件类型
    binary_type: BinaryType = BinaryType.UNKNOWN
    format: str = ""            # pe, elf, mach0, ...

    # 地址信息
    image_base: int = 0         # 映像基址
    entry_point: int = 0        # 入口点

    # 编译器信息
    compiler: str = ""          # 编译器 (gcc, msvc, clang, ...)
    language: str = ""          # 语言 (c, c++, rust, go, ...)

    # 安全特性
    has_nx: bool = False        # DEP/NX
    has_canary: bool = False    # 栈保护
    has_pie: bool = False       # ASLR/PIE
    has_relro: bool = False     # RELRO (Linux)
    has_cfg: bool = False       # Control Flow Guard (Windows)


# =============================================================================
# 调试相关
# =============================================================================

@dataclass
class RegisterState:
    """寄存器状态"""
    values: Dict[str, int] = field(default_factory=dict)

    def get(self, reg: str, default: int = 0) -> int:
        return self.values.get(reg.lower(), default)

    def set(self, reg: str, value: int):
        self.values[reg.lower()] = value


@dataclass
class Breakpoint:
    """断点"""
    address: int
    enabled: bool = True
    hit_count: int = 0
    condition: str = ""     # 条件表达式
    commands: List[str] = field(default_factory=list)  # 触发时执行的命令


# =============================================================================
# ROP Gadget
# =============================================================================

@dataclass
class RopGadget:
    """ROP Gadget"""
    address: int            # gadget 地址
    instructions: str       # 指令序列
    size: int = 0           # 大小

    # 分类
    gadget_type: str = ""   # pop, mov, xchg, syscall, ...

    # 语义
    regs_modified: List[str] = field(default_factory=list)
    regs_controlled: List[str] = field(default_factory=list)
