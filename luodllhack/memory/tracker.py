# -*- coding: utf-8 -*-
"""
luodllhack/memory/tracker.py - 增强的内存位置追踪器

追踪指针在内存位置之间的传播:
- 支持 [base + offset] 形式的内存位置
- 追踪 mov [mem], reg 和 mov reg, [mem] 操作
- 维护指针状态在寄存器和内存中的传播
"""

from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import re
import logging

logger = logging.getLogger(__name__)


class PointerState(Enum):
    """指针状态"""
    UNKNOWN = auto()        # 未知
    ALLOCATED = auto()      # 已分配
    FREED = auto()          # 已释放
    REALLOCATED = auto()    # 重新分配
    ESCAPED = auto()        # 逃逸 (存入全局/返回)
    INVALID = auto()        # 无效


@dataclass(frozen=True)
class MemoryLocation:
    """
    内存位置

    表示形如 [base + offset] 的内存位置:
    - [rax + 0x10]: 寄存器基址
    - [rbp - 0x20]: 栈位置
    - [0x140001000]: 绝对地址
    - heap:0x1234: 堆位置 (符号)
    """
    base: str           # 基址: 寄存器名、'heap'、'stack'、或绝对地址
    offset: int         # 偏移
    size: int = 8       # 访问大小 (字节)

    def __str__(self) -> str:
        if self.base.startswith('0x'):
            # 绝对地址
            addr = int(self.base, 16) + self.offset
            return f"[0x{addr:x}]"
        elif self.base == 'heap':
            return f"[heap+0x{self.offset:x}]"
        elif self.base == 'stack':
            return f"[stack+0x{self.offset:x}]"
        elif self.offset >= 0:
            return f"[{self.base}+0x{self.offset:x}]"
        else:
            return f"[{self.base}-0x{-self.offset:x}]"

    @classmethod
    def from_operand(cls, operand: str, size: int = 8) -> Optional['MemoryLocation']:
        """
        从操作数字符串解析内存位置

        Args:
            operand: 如 "[rax+0x10]", "[rbp-0x20]", "qword ptr [rcx]"
            size: 访问大小

        Returns:
            MemoryLocation 或 None
        """
        # 移除 ptr 修饰符
        operand = re.sub(r'\b(byte|word|dword|qword)\s+ptr\s+', '', operand, flags=re.I)
        operand = operand.strip()

        # 匹配 [...]
        match = re.match(r'\[(.+)\]', operand)
        if not match:
            return None

        inner = match.group(1).strip()

        # 解析 base + offset 或 base - offset
        # 支持: rax, rax+0x10, rax-0x10, 0x140001000
        if '+' in inner:
            parts = inner.split('+')
            base = parts[0].strip()
            try:
                offset = int(parts[1].strip(), 0)
            except ValueError:
                offset = 0
        elif '-' in inner and not inner.startswith('0x'):
            parts = inner.split('-')
            base = parts[0].strip()
            try:
                offset = -int(parts[1].strip(), 0)
            except ValueError:
                offset = 0
        else:
            # 纯寄存器或绝对地址
            base = inner
            offset = 0

        return cls(base=base, offset=offset, size=size)

    def with_offset(self, additional_offset: int) -> 'MemoryLocation':
        """返回新偏移的位置"""
        return MemoryLocation(self.base, self.offset + additional_offset, self.size)


@dataclass
class PointerInfo:
    """指针信息"""
    state: PointerState
    alloc_addr: int             # 分配地址
    alloc_api: str              # 分配 API
    alloc_id: int               # 分配 ID (用于追踪同一分配)
    size: Optional[int] = None  # 分配大小
    free_addr: Optional[int] = None
    free_api: Optional[str] = None
    source_reg: Optional[str] = None  # 来源寄存器
    tainted: bool = False       # 是否被污点数据影响

    def copy(self) -> 'PointerInfo':
        """创建副本"""
        return PointerInfo(
            state=self.state,
            alloc_addr=self.alloc_addr,
            alloc_api=self.alloc_api,
            alloc_id=self.alloc_id,
            size=self.size,
            free_addr=self.free_addr,
            free_api=self.free_api,
            source_reg=self.source_reg,
            tainted=self.tainted
        )


@dataclass
class MemoryAccess:
    """内存访问记录"""
    address: int                # 指令地址
    location: MemoryLocation    # 内存位置
    is_write: bool              # 是否是写操作
    value_source: str           # 值来源 (寄存器名或常量)
    pointer_info: Optional[PointerInfo] = None


class EnhancedMemoryTracker:
    """
    增强的内存追踪器

    追踪指针在寄存器和内存位置之间的传播:
    1. 寄存器 -> 寄存器: mov rax, rbx
    2. 寄存器 -> 内存: mov [rcx+0x10], rax
    3. 内存 -> 寄存器: mov rax, [rcx+0x10]

    用法:
        tracker = EnhancedMemoryTracker()

        # 追踪分配
        tracker.track_alloc('rax', 0x1000, 'malloc', size=256)

        # 追踪存储
        tracker.track_store(0x1010, MemoryLocation('rcx', 0x10), 'rax')

        # 追踪加载
        tracker.track_load(0x1020, 'rbx', MemoryLocation('rcx', 0x10))

        # 追踪释放
        result = tracker.track_free('rbx', 0x1030, 'free')
    """

    # Windows x64 通用寄存器
    X64_REGS = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}

    # 寄存器别名
    REG_ALIASES = {
        'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
        'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
        'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
        'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
        'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
        'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
        'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
        'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
        'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
        'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
        'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
        'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
        'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
        'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
    }

    def __init__(self):
        # 寄存器状态: reg -> PointerInfo
        self.reg_states: Dict[str, PointerInfo] = {}

        # 内存状态: MemoryLocation -> PointerInfo
        self.mem_states: Dict[MemoryLocation, PointerInfo] = {}

        # 分配 ID 计数器
        self._alloc_counter = 0

        # 访问历史
        self.access_history: List[MemoryAccess] = []

        # 检测到的问题
        self.findings: List[Dict] = []

    def _normalize_reg(self, reg: str) -> str:
        """规范化寄存器名"""
        reg = reg.lower()
        return self.REG_ALIASES.get(reg, reg)

    def _next_alloc_id(self) -> int:
        """获取下一个分配 ID"""
        self._alloc_counter += 1
        return self._alloc_counter

    def track_alloc(self, reg: str, addr: int, api: str,
                    size: Optional[int] = None) -> PointerInfo:
        """
        追踪内存分配

        Args:
            reg: 返回值寄存器
            addr: 分配指令地址
            api: 分配 API 名称
            size: 分配大小

        Returns:
            PointerInfo
        """
        reg = self._normalize_reg(reg)

        info = PointerInfo(
            state=PointerState.ALLOCATED,
            alloc_addr=addr,
            alloc_api=api,
            alloc_id=self._next_alloc_id(),
            size=size,
            source_reg=reg
        )

        self.reg_states[reg] = info
        return info

    def track_free(self, reg: str, addr: int, api: str) -> Optional[Dict]:
        """
        追踪内存释放

        Args:
            reg: 指针寄存器
            addr: 释放指令地址
            api: 释放 API 名称

        Returns:
            如果检测到 Double-Free，返回 finding 信息
        """
        reg = self._normalize_reg(reg)
        info = self.reg_states.get(reg)

        if info is None:
            # 释放未知指针
            return None

        if info.state == PointerState.FREED:
            # Double-Free!
            finding = {
                'type': 'DOUBLE_FREE',
                'address': addr,
                'api': api,
                'alloc_addr': info.alloc_addr,
                'alloc_api': info.alloc_api,
                'first_free_addr': info.free_addr,
                'first_free_api': info.free_api,
                'alloc_id': info.alloc_id
            }
            self.findings.append(finding)
            return finding

        # 更新状态
        info.state = PointerState.FREED
        info.free_addr = addr
        info.free_api = api

        # 更新所有指向同一分配的位置
        self._propagate_free(info.alloc_id, addr, api)

        return None

    def _propagate_free(self, alloc_id: int, free_addr: int, free_api: str):
        """传播释放状态到所有别名"""
        # 更新寄存器
        for reg, info in self.reg_states.items():
            if info.alloc_id == alloc_id and info.state != PointerState.FREED:
                info.state = PointerState.FREED
                info.free_addr = free_addr
                info.free_api = free_api

        # 更新内存位置
        for loc, info in self.mem_states.items():
            if info.alloc_id == alloc_id and info.state != PointerState.FREED:
                info.state = PointerState.FREED
                info.free_addr = free_addr
                info.free_api = free_api

    def track_store(self, addr: int, location: MemoryLocation,
                    src_reg: str) -> Optional[Dict]:
        """
        追踪存储操作: mov [mem], reg

        Args:
            addr: 指令地址
            location: 目标内存位置
            src_reg: 源寄存器

        Returns:
            如果检测到问题，返回 finding 信息
        """
        src_reg = self._normalize_reg(src_reg)
        info = self.reg_states.get(src_reg)

        # 记录访问
        access = MemoryAccess(
            address=addr,
            location=location,
            is_write=True,
            value_source=src_reg,
            pointer_info=info.copy() if info else None
        )
        self.access_history.append(access)

        if info is not None:
            # 将指针信息传播到内存位置
            self.mem_states[location] = info.copy()

        return None

    def track_load(self, addr: int, dst_reg: str,
                   location: MemoryLocation) -> Optional[Dict]:
        """
        追踪加载操作: mov reg, [mem]

        Args:
            addr: 指令地址
            dst_reg: 目标寄存器
            location: 源内存位置

        Returns:
            如果检测到 UAF，返回 finding 信息
        """
        dst_reg = self._normalize_reg(dst_reg)
        info = self.mem_states.get(location)

        # 记录访问
        access = MemoryAccess(
            address=addr,
            location=location,
            is_write=False,
            value_source=dst_reg,
            pointer_info=info.copy() if info else None
        )
        self.access_history.append(access)

        if info is not None:
            # 检查 UAF
            if info.state == PointerState.FREED:
                finding = {
                    'type': 'USE_AFTER_FREE',
                    'address': addr,
                    'location': str(location),
                    'alloc_addr': info.alloc_addr,
                    'alloc_api': info.alloc_api,
                    'free_addr': info.free_addr,
                    'free_api': info.free_api,
                    'alloc_id': info.alloc_id
                }
                self.findings.append(finding)
                return finding

            # 传播指针信息到目标寄存器
            self.reg_states[dst_reg] = info.copy()

        return None

    def track_reg_move(self, addr: int, dst_reg: str, src_reg: str):
        """
        追踪寄存器间移动: mov dst, src

        Args:
            addr: 指令地址
            dst_reg: 目标寄存器
            src_reg: 源寄存器
        """
        dst_reg = self._normalize_reg(dst_reg)
        src_reg = self._normalize_reg(src_reg)

        info = self.reg_states.get(src_reg)
        if info is not None:
            self.reg_states[dst_reg] = info.copy()

    def track_use(self, addr: int, reg: str, use_type: str = 'read') -> Optional[Dict]:
        """
        追踪指针使用 (解引用)

        Args:
            addr: 指令地址
            reg: 指针寄存器
            use_type: 使用类型 ('read', 'write', 'call')

        Returns:
            如果检测到 UAF，返回 finding 信息
        """
        reg = self._normalize_reg(reg)
        info = self.reg_states.get(reg)

        if info is not None and info.state == PointerState.FREED:
            finding = {
                'type': 'USE_AFTER_FREE',
                'address': addr,
                'register': reg,
                'use_type': use_type,
                'alloc_addr': info.alloc_addr,
                'alloc_api': info.alloc_api,
                'free_addr': info.free_addr,
                'free_api': info.free_api,
                'alloc_id': info.alloc_id
            }
            self.findings.append(finding)
            return finding

        return None

    def get_pointer_state(self, reg: str) -> Optional[PointerInfo]:
        """获取寄存器的指针状态"""
        return self.reg_states.get(self._normalize_reg(reg))

    def get_memory_state(self, location: MemoryLocation) -> Optional[PointerInfo]:
        """获取内存位置的指针状态"""
        return self.mem_states.get(location)

    def get_all_locations_for_alloc(self, alloc_id: int) -> List[Union[str, MemoryLocation]]:
        """获取指向特定分配的所有位置"""
        locations = []

        for reg, info in self.reg_states.items():
            if info.alloc_id == alloc_id:
                locations.append(reg)

        for loc, info in self.mem_states.items():
            if info.alloc_id == alloc_id:
                locations.append(loc)

        return locations

    def clear(self):
        """清空追踪状态"""
        self.reg_states.clear()
        self.mem_states.clear()
        self.access_history.clear()
        self.findings.clear()
        self._alloc_counter = 0

    def get_summary(self) -> Dict:
        """获取追踪摘要"""
        return {
            'tracked_registers': len(self.reg_states),
            'tracked_memory_locations': len(self.mem_states),
            'total_accesses': len(self.access_history),
            'findings': len(self.findings),
            'allocations': self._alloc_counter
        }
