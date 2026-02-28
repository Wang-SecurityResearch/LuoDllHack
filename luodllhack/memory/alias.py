# -*- coding: utf-8 -*-
"""
luodllhack/memory/alias.py - 别名分析

分析哪些位置可能指向同一内存对象:
- 寄存器别名: rax 和 rbx 指向同一对象
- 内存别名: [rsp+0x10] 和 [rbp-0x20] 指向同一对象
- 用于精确检测 UAF/Double-Free
"""

from typing import Dict, List, Set, Optional, Tuple, Any, Union, FrozenSet
from dataclasses import dataclass, field
from collections import defaultdict
import logging

from .tracker import MemoryLocation, PointerState, PointerInfo, EnhancedMemoryTracker

logger = logging.getLogger(__name__)


@dataclass
class AliasSet:
    """
    别名集合

    表示指向同一内存对象的所有位置
    """
    alloc_id: int                           # 对应的分配 ID
    registers: Set[str] = field(default_factory=set)
    memory_locations: Set[MemoryLocation] = field(default_factory=set)
    state: PointerState = PointerState.ALLOCATED

    def add_register(self, reg: str):
        """添加寄存器"""
        self.registers.add(reg.lower())

    def add_memory(self, loc: MemoryLocation):
        """添加内存位置"""
        self.memory_locations.add(loc)

    def remove_register(self, reg: str):
        """移除寄存器"""
        self.registers.discard(reg.lower())

    def remove_memory(self, loc: MemoryLocation):
        """移除内存位置"""
        self.memory_locations.discard(loc)

    def contains(self, location: Union[str, MemoryLocation]) -> bool:
        """检查位置是否在集合中"""
        if isinstance(location, str):
            return location.lower() in self.registers
        return location in self.memory_locations

    def all_locations(self) -> List[Union[str, MemoryLocation]]:
        """获取所有位置"""
        return list(self.registers) + list(self.memory_locations)

    def size(self) -> int:
        """获取别名集合大小"""
        return len(self.registers) + len(self.memory_locations)

    def is_empty(self) -> bool:
        """检查是否为空"""
        return not self.registers and not self.memory_locations

    def __repr__(self) -> str:
        parts = list(self.registers) + [str(m) for m in self.memory_locations]
        return f"AliasSet({self.alloc_id}: {', '.join(parts)})"


class AliasAnalyzer:
    """
    别名分析器

    维护和查询指针别名关系:
    1. 追踪从同一分配点派生的所有指针
    2. 在释放时更新所有别名的状态
    3. 检测通过别名导致的 UAF

    用法:
        analyzer = AliasAnalyzer()

        # 追踪分配
        analyzer.track_alloc('rax', alloc_id=1)

        # 追踪传播
        analyzer.track_copy('rbx', 'rax')
        analyzer.track_store(MemoryLocation('rsp', 0x10), 'rax')

        # 查询别名
        aliases = analyzer.get_aliases_for('rax')

        # 追踪释放
        findings = analyzer.track_free('rax')
    """

    def __init__(self):
        # alloc_id -> AliasSet
        self.alias_sets: Dict[int, AliasSet] = {}

        # 位置 -> alloc_id (反向索引)
        self.location_to_alloc: Dict[Union[str, FrozenSet], int] = {}

        # 分析发现
        self.findings: List[Dict] = []

    def _normalize_reg(self, reg: str) -> str:
        """规范化寄存器名"""
        return reg.lower()

    def _loc_key(self, loc: MemoryLocation) -> FrozenSet:
        """为 MemoryLocation 创建哈希键"""
        return frozenset([('base', loc.base), ('offset', loc.offset), ('size', loc.size)])

    def track_alloc(self, reg: str, alloc_id: int):
        """
        追踪内存分配

        Args:
            reg: 返回值寄存器
            alloc_id: 分配 ID
        """
        reg = self._normalize_reg(reg)

        # 创建新的别名集合
        alias_set = AliasSet(alloc_id=alloc_id, state=PointerState.ALLOCATED)
        alias_set.add_register(reg)

        self.alias_sets[alloc_id] = alias_set
        self.location_to_alloc[reg] = alloc_id

    def track_copy(self, dst: str, src: str):
        """
        追踪寄存器复制: mov dst, src

        Args:
            dst: 目标寄存器
            src: 源寄存器
        """
        dst = self._normalize_reg(dst)
        src = self._normalize_reg(src)

        alloc_id = self.location_to_alloc.get(src)
        if alloc_id is None:
            return

        alias_set = self.alias_sets.get(alloc_id)
        if alias_set is None:
            return

        # 添加目标到别名集合
        alias_set.add_register(dst)
        self.location_to_alloc[dst] = alloc_id

    def track_store(self, location: MemoryLocation, src_reg: str):
        """
        追踪存储: mov [mem], reg

        Args:
            location: 目标内存位置
            src_reg: 源寄存器
        """
        src_reg = self._normalize_reg(src_reg)
        loc_key = self._loc_key(location)

        alloc_id = self.location_to_alloc.get(src_reg)
        if alloc_id is None:
            return

        alias_set = self.alias_sets.get(alloc_id)
        if alias_set is None:
            return

        # 添加内存位置到别名集合
        alias_set.add_memory(location)
        self.location_to_alloc[loc_key] = alloc_id

    def track_load(self, dst_reg: str, location: MemoryLocation) -> Optional[Dict]:
        """
        追踪加载: mov reg, [mem]

        Args:
            dst_reg: 目标寄存器
            location: 源内存位置

        Returns:
            如果检测到 UAF，返回 finding
        """
        dst_reg = self._normalize_reg(dst_reg)
        loc_key = self._loc_key(location)

        alloc_id = self.location_to_alloc.get(loc_key)
        if alloc_id is None:
            return None

        alias_set = self.alias_sets.get(alloc_id)
        if alias_set is None:
            return None

        # 检查 UAF
        if alias_set.state == PointerState.FREED:
            finding = {
                'type': 'USE_AFTER_FREE_VIA_ALIAS',
                'alloc_id': alloc_id,
                'location': str(location),
                'dst_reg': dst_reg,
                'alias_count': alias_set.size()
            }
            self.findings.append(finding)
            return finding

        # 添加目标到别名集合
        alias_set.add_register(dst_reg)
        self.location_to_alloc[dst_reg] = alloc_id

        return None

    def track_free(self, reg: str) -> List[Dict]:
        """
        追踪释放

        Args:
            reg: 指针寄存器

        Returns:
            检测到的问题列表
        """
        reg = self._normalize_reg(reg)
        alloc_id = self.location_to_alloc.get(reg)

        if alloc_id is None:
            return []

        alias_set = self.alias_sets.get(alloc_id)
        if alias_set is None:
            return []

        findings = []

        # 检查 Double-Free
        if alias_set.state == PointerState.FREED:
            finding = {
                'type': 'DOUBLE_FREE_VIA_ALIAS',
                'alloc_id': alloc_id,
                'freed_via': reg,
                'all_aliases': alias_set.all_locations()
            }
            findings.append(finding)
            self.findings.append(finding)
        else:
            # 标记为已释放
            alias_set.state = PointerState.FREED

            # 如果有多个别名，报告潜在的 UAF 风险
            if alias_set.size() > 1:
                finding = {
                    'type': 'POTENTIAL_UAF',
                    'alloc_id': alloc_id,
                    'freed_via': reg,
                    'remaining_aliases': [
                        loc for loc in alias_set.all_locations()
                        if loc != reg
                    ]
                }
                findings.append(finding)
                self.findings.append(finding)

        return findings

    def track_use(self, location: Union[str, MemoryLocation],
                  use_addr: int = 0) -> Optional[Dict]:
        """
        追踪指针使用

        Args:
            location: 使用的位置
            use_addr: 使用的指令地址

        Returns:
            如果检测到 UAF，返回 finding
        """
        if isinstance(location, str):
            key = self._normalize_reg(location)
        else:
            key = self._loc_key(location)

        alloc_id = self.location_to_alloc.get(key)
        if alloc_id is None:
            return None

        alias_set = self.alias_sets.get(alloc_id)
        if alias_set is None:
            return None

        if alias_set.state == PointerState.FREED:
            finding = {
                'type': 'USE_AFTER_FREE',
                'alloc_id': alloc_id,
                'use_location': str(location),
                'use_addr': use_addr,
                'all_aliases': alias_set.all_locations()
            }
            self.findings.append(finding)
            return finding

        return None

    def get_aliases_for(self, location: Union[str, MemoryLocation]) -> Optional[AliasSet]:
        """
        获取位置的别名集合

        Args:
            location: 寄存器或内存位置

        Returns:
            AliasSet 或 None
        """
        if isinstance(location, str):
            key = self._normalize_reg(location)
        else:
            key = self._loc_key(location)

        alloc_id = self.location_to_alloc.get(key)
        if alloc_id is None:
            return None

        return self.alias_sets.get(alloc_id)

    def may_alias(self, loc1: Union[str, MemoryLocation],
                  loc2: Union[str, MemoryLocation]) -> bool:
        """
        检查两个位置是否可能别名

        Args:
            loc1: 位置 1
            loc2: 位置 2

        Returns:
            是否可能别名
        """
        alias_set1 = self.get_aliases_for(loc1)
        alias_set2 = self.get_aliases_for(loc2)

        if alias_set1 is None or alias_set2 is None:
            return False

        return alias_set1.alloc_id == alias_set2.alloc_id

    def kill_location(self, location: Union[str, MemoryLocation]):
        """
        杀死位置 (被重新赋值)

        Args:
            location: 被重新赋值的位置
        """
        if isinstance(location, str):
            key = self._normalize_reg(location)
        else:
            key = self._loc_key(location)

        alloc_id = self.location_to_alloc.get(key)
        if alloc_id is None:
            return

        alias_set = self.alias_sets.get(alloc_id)
        if alias_set is not None:
            if isinstance(location, str):
                alias_set.remove_register(location)
            else:
                alias_set.remove_memory(location)

        # 从反向索引中移除
        if key in self.location_to_alloc:
            del self.location_to_alloc[key]

    def clear(self):
        """清空分析状态"""
        self.alias_sets.clear()
        self.location_to_alloc.clear()
        self.findings.clear()

    def get_summary(self) -> Dict:
        """获取分析摘要"""
        total_aliases = sum(s.size() for s in self.alias_sets.values())
        freed_sets = sum(1 for s in self.alias_sets.values()
                        if s.state == PointerState.FREED)

        return {
            'alias_sets': len(self.alias_sets),
            'total_aliases': total_aliases,
            'freed_sets': freed_sets,
            'findings': len(self.findings)
        }

    def from_tracker(self, tracker: EnhancedMemoryTracker):
        """
        从 EnhancedMemoryTracker 导入状态

        Args:
            tracker: 内存追踪器
        """
        self.clear()

        # 按 alloc_id 分组
        alloc_groups: Dict[int, AliasSet] = {}

        # 处理寄存器
        for reg, info in tracker.reg_states.items():
            if info.alloc_id not in alloc_groups:
                alloc_groups[info.alloc_id] = AliasSet(
                    alloc_id=info.alloc_id,
                    state=info.state
                )
            alloc_groups[info.alloc_id].add_register(reg)
            self.location_to_alloc[reg] = info.alloc_id

        # 处理内存位置
        for loc, info in tracker.mem_states.items():
            if info.alloc_id not in alloc_groups:
                alloc_groups[info.alloc_id] = AliasSet(
                    alloc_id=info.alloc_id,
                    state=info.state
                )
            alloc_groups[info.alloc_id].add_memory(loc)
            self.location_to_alloc[self._loc_key(loc)] = info.alloc_id

        self.alias_sets = alloc_groups
