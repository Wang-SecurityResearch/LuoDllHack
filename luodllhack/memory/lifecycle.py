# -*- coding: utf-8 -*-
"""
luodllhack/memory/lifecycle.py - 指针生命周期分析

分析指针从分配到释放的完整生命周期:
- 状态转换追踪
- 生命周期异常检测
- 跨函数生命周期分析
"""

from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

from .tracker import MemoryLocation, PointerState, PointerInfo
from .alias import AliasAnalyzer, AliasSet

logger = logging.getLogger(__name__)


class LifecycleEvent(Enum):
    """生命周期事件"""
    ALLOC = auto()          # 分配
    COPY = auto()           # 复制
    STORE = auto()          # 存储到内存
    LOAD = auto()           # 从内存加载
    USE = auto()            # 使用 (解引用)
    FREE = auto()           # 释放
    REALLOC = auto()        # 重新分配
    ESCAPE = auto()         # 逃逸 (返回/存全局)
    KILL = auto()           # 杀死 (被覆盖)


@dataclass
class LifecycleEventRecord:
    """生命周期事件记录"""
    event: LifecycleEvent
    address: int            # 指令地址
    location: str           # 发生的位置 (寄存器/内存)
    detail: str = ""        # 额外信息

    def __str__(self) -> str:
        return f"0x{self.address:x}: {self.event.name} @ {self.location}"


@dataclass
class PointerLifecycle:
    """
    指针生命周期

    追踪单个分配从创建到销毁的完整过程
    """
    alloc_id: int
    alloc_addr: int
    alloc_api: str
    alloc_size: Optional[int] = None

    events: List[LifecycleEventRecord] = field(default_factory=list)

    free_addr: Optional[int] = None
    free_api: Optional[str] = None

    is_freed: bool = False
    is_escaped: bool = False
    has_uaf: bool = False
    has_double_free: bool = False

    def add_event(self, event: LifecycleEvent, address: int,
                  location: str, detail: str = ""):
        """添加事件"""
        record = LifecycleEventRecord(
            event=event,
            address=address,
            location=location,
            detail=detail
        )
        self.events.append(record)

        # 更新状态
        if event == LifecycleEvent.FREE:
            if self.is_freed:
                self.has_double_free = True
            self.is_freed = True
            self.free_addr = address

        elif event == LifecycleEvent.USE:
            if self.is_freed:
                self.has_uaf = True

        elif event == LifecycleEvent.ESCAPE:
            self.is_escaped = True

    def get_duration(self) -> Optional[int]:
        """获取生命周期持续时间 (地址范围)"""
        if not self.events:
            return None

        first_addr = self.alloc_addr
        last_addr = self.events[-1].address

        return last_addr - first_addr

    def get_event_count(self) -> Dict[LifecycleEvent, int]:
        """获取各事件计数"""
        counts: Dict[LifecycleEvent, int] = {}
        for record in self.events:
            counts[record.event] = counts.get(record.event, 0) + 1
        return counts

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'alloc_id': self.alloc_id,
            'alloc_addr': f'0x{self.alloc_addr:x}',
            'alloc_api': self.alloc_api,
            'alloc_size': self.alloc_size,
            'free_addr': f'0x{self.free_addr:x}' if self.free_addr else None,
            'free_api': self.free_api,
            'is_freed': self.is_freed,
            'is_escaped': self.is_escaped,
            'has_uaf': self.has_uaf,
            'has_double_free': self.has_double_free,
            'event_count': len(self.events)
        }


@dataclass
class LifecycleAnomaly:
    """生命周期异常"""
    anomaly_type: str       # 'DOUBLE_FREE', 'USE_AFTER_FREE', 'LEAK', etc.
    severity: str           # 'Critical', 'High', 'Medium', 'Low'
    alloc_id: int
    address: int            # 发现异常的地址
    description: str
    lifecycle: PointerLifecycle

    def to_dict(self) -> Dict:
        return {
            'type': self.anomaly_type,
            'severity': self.severity,
            'alloc_id': self.alloc_id,
            'address': f'0x{self.address:x}',
            'description': self.description
        }


class LifecycleAnalyzer:
    """
    生命周期分析器

    分析指针的完整生命周期，检测:
    - Double-Free
    - Use-After-Free
    - Memory Leak (未释放)
    - 生命周期异常

    用法:
        analyzer = LifecycleAnalyzer()

        # 追踪分配
        lifecycle = analyzer.track_alloc(alloc_id=1, addr=0x1000,
                                          api='malloc', size=256)

        # 追踪事件
        analyzer.track_event(1, LifecycleEvent.COPY, 0x1010, 'rbx')
        analyzer.track_event(1, LifecycleEvent.STORE, 0x1020, '[rsp+0x10]')
        analyzer.track_event(1, LifecycleEvent.FREE, 0x1100, 'rax')

        # 分析异常
        anomalies = analyzer.detect_anomalies()
    """

    # 异常严重性
    SEVERITY_MAP = {
        'DOUBLE_FREE': 'Critical',
        'USE_AFTER_FREE': 'Critical',
        'MEMORY_LEAK': 'Medium',
        'ESCAPED_FREED': 'High',
        'SHORT_LIFETIME': 'Low',
    }

    def __init__(self):
        # alloc_id -> PointerLifecycle
        self.lifecycles: Dict[int, PointerLifecycle] = {}

        # 检测到的异常
        self.anomalies: List[LifecycleAnomaly] = []

        # 函数边界追踪
        self.current_function: Optional[str] = None
        self.function_allocations: Dict[str, Set[int]] = {}

    def track_alloc(self, alloc_id: int, addr: int, api: str,
                    size: Optional[int] = None) -> PointerLifecycle:
        """
        追踪内存分配

        Args:
            alloc_id: 分配 ID
            addr: 分配指令地址
            api: 分配 API
            size: 分配大小

        Returns:
            PointerLifecycle
        """
        lifecycle = PointerLifecycle(
            alloc_id=alloc_id,
            alloc_addr=addr,
            alloc_api=api,
            alloc_size=size
        )

        lifecycle.add_event(LifecycleEvent.ALLOC, addr, api,
                           f"size={size}" if size else "")

        self.lifecycles[alloc_id] = lifecycle

        # 记录函数分配
        if self.current_function:
            if self.current_function not in self.function_allocations:
                self.function_allocations[self.current_function] = set()
            self.function_allocations[self.current_function].add(alloc_id)

        return lifecycle

    def track_event(self, alloc_id: int, event: LifecycleEvent,
                    addr: int, location: str, detail: str = "") -> Optional[LifecycleAnomaly]:
        """
        追踪生命周期事件

        Args:
            alloc_id: 分配 ID
            event: 事件类型
            addr: 指令地址
            location: 位置
            detail: 额外信息

        Returns:
            如果检测到异常，返回 LifecycleAnomaly
        """
        lifecycle = self.lifecycles.get(alloc_id)
        if lifecycle is None:
            return None

        # 检查异常
        anomaly = None

        if event == LifecycleEvent.FREE:
            if lifecycle.is_freed:
                # Double-Free
                anomaly = LifecycleAnomaly(
                    anomaly_type='DOUBLE_FREE',
                    severity='Critical',
                    alloc_id=alloc_id,
                    address=addr,
                    description=f"Double free detected. First free at 0x{lifecycle.free_addr:x}",
                    lifecycle=lifecycle
                )
                self.anomalies.append(anomaly)

        elif event == LifecycleEvent.USE:
            if lifecycle.is_freed:
                # Use-After-Free
                anomaly = LifecycleAnomaly(
                    anomaly_type='USE_AFTER_FREE',
                    severity='Critical',
                    alloc_id=alloc_id,
                    address=addr,
                    description=f"Use after free. Freed at 0x{lifecycle.free_addr:x}",
                    lifecycle=lifecycle
                )
                self.anomalies.append(anomaly)

        # 记录事件
        lifecycle.add_event(event, addr, location, detail)

        return anomaly

    def track_free(self, alloc_id: int, addr: int,
                   api: str = 'free') -> Optional[LifecycleAnomaly]:
        """
        追踪释放

        Args:
            alloc_id: 分配 ID
            addr: 释放指令地址
            api: 释放 API

        Returns:
            如果检测到异常，返回 LifecycleAnomaly
        """
        lifecycle = self.lifecycles.get(alloc_id)
        if lifecycle is None:
            return None

        lifecycle.free_api = api

        return self.track_event(alloc_id, LifecycleEvent.FREE, addr, api)

    def enter_function(self, func_name: str):
        """进入函数"""
        self.current_function = func_name
        if func_name not in self.function_allocations:
            self.function_allocations[func_name] = set()

    def exit_function(self, func_name: str) -> List[LifecycleAnomaly]:
        """
        退出函数，检测泄漏

        Args:
            func_name: 函数名

        Returns:
            检测到的异常列表
        """
        anomalies = []

        allocations = self.function_allocations.get(func_name, set())

        for alloc_id in allocations:
            lifecycle = self.lifecycles.get(alloc_id)
            if lifecycle is None:
                continue

            # 检查未释放且未逃逸的分配
            if not lifecycle.is_freed and not lifecycle.is_escaped:
                anomaly = LifecycleAnomaly(
                    anomaly_type='MEMORY_LEAK',
                    severity='Medium',
                    alloc_id=alloc_id,
                    address=lifecycle.alloc_addr,
                    description=f"Memory allocated by {lifecycle.alloc_api} not freed before function exit",
                    lifecycle=lifecycle
                )
                self.anomalies.append(anomaly)
                anomalies.append(anomaly)

        self.current_function = None
        return anomalies

    def detect_anomalies(self) -> List[LifecycleAnomaly]:
        """
        检测所有异常

        Returns:
            异常列表
        """
        anomalies = []

        for alloc_id, lifecycle in self.lifecycles.items():
            # 检查已存在的异常
            if lifecycle.has_double_free:
                # 已在 track_event 中记录
                pass

            if lifecycle.has_uaf:
                # 已在 track_event 中记录
                pass

            # 检查逃逸后释放
            if lifecycle.is_escaped and lifecycle.is_freed:
                anomaly = LifecycleAnomaly(
                    anomaly_type='ESCAPED_FREED',
                    severity='High',
                    alloc_id=alloc_id,
                    address=lifecycle.free_addr or lifecycle.alloc_addr,
                    description="Pointer was escaped before being freed - may cause UAF in caller",
                    lifecycle=lifecycle
                )
                if anomaly not in self.anomalies:
                    self.anomalies.append(anomaly)
                    anomalies.append(anomaly)

            # 检查过短的生命周期 (可能是错误)
            duration = lifecycle.get_duration()
            if duration is not None and duration < 0x10 and lifecycle.is_freed:
                event_count = len(lifecycle.events)
                if event_count <= 2:  # 只有分配和释放
                    anomaly = LifecycleAnomaly(
                        anomaly_type='SHORT_LIFETIME',
                        severity='Low',
                        alloc_id=alloc_id,
                        address=lifecycle.alloc_addr,
                        description="Very short lifetime - may indicate error or unnecessary allocation",
                        lifecycle=lifecycle
                    )
                    if anomaly not in self.anomalies:
                        self.anomalies.append(anomaly)
                        anomalies.append(anomaly)

        return anomalies

    def get_lifecycle(self, alloc_id: int) -> Optional[PointerLifecycle]:
        """获取特定分配的生命周期"""
        return self.lifecycles.get(alloc_id)

    def get_active_allocations(self) -> List[PointerLifecycle]:
        """获取所有活跃的分配 (未释放)"""
        return [lc for lc in self.lifecycles.values()
                if not lc.is_freed]

    def get_freed_allocations(self) -> List[PointerLifecycle]:
        """获取所有已释放的分配"""
        return [lc for lc in self.lifecycles.values()
                if lc.is_freed]

    def clear(self):
        """清空分析状态"""
        self.lifecycles.clear()
        self.anomalies.clear()
        self.function_allocations.clear()
        self.current_function = None

    def get_summary(self) -> Dict:
        """获取分析摘要"""
        return {
            'total_allocations': len(self.lifecycles),
            'active_allocations': len(self.get_active_allocations()),
            'freed_allocations': len(self.get_freed_allocations()),
            'anomalies': len(self.anomalies),
            'double_free': sum(1 for a in self.anomalies if a.anomaly_type == 'DOUBLE_FREE'),
            'use_after_free': sum(1 for a in self.anomalies if a.anomaly_type == 'USE_AFTER_FREE'),
            'memory_leak': sum(1 for a in self.anomalies if a.anomaly_type == 'MEMORY_LEAK')
        }

    def generate_report(self) -> str:
        """生成分析报告"""
        lines = [
            "=" * 60,
            "POINTER LIFECYCLE ANALYSIS REPORT",
            "=" * 60,
            ""
        ]

        summary = self.get_summary()
        lines.append(f"Total allocations: {summary['total_allocations']}")
        lines.append(f"Active (not freed): {summary['active_allocations']}")
        lines.append(f"Freed: {summary['freed_allocations']}")
        lines.append("")

        if self.anomalies:
            lines.append(f"[!] Anomalies detected: {len(self.anomalies)}")
            lines.append("")

            # 按严重性分组
            by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
            for a in self.anomalies:
                by_severity[a.severity].append(a)

            for severity in ['Critical', 'High', 'Medium', 'Low']:
                anomalies = by_severity[severity]
                if anomalies:
                    lines.append(f"  [{severity}]")
                    for a in anomalies:
                        lines.append(f"    - {a.anomaly_type} @ 0x{a.address:x}")
                        lines.append(f"      {a.description}")
                    lines.append("")
        else:
            lines.append("[*] No anomalies detected")

        return "\n".join(lines)
