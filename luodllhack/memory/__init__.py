# -*- coding: utf-8 -*-
"""
luodllhack.memory - 内存状态追踪模块

提供完整的内存位置追踪与别名分析:
- MemoryLocation: 表示内存位置 (base + offset)
- EnhancedMemoryTracker: 追踪指针在内存中的传播
- AliasAnalyzer: 别名分析，检测指向同一对象的多个位置
- LifecycleAnalyzer: 指针生命周期分析
"""

from .tracker import MemoryLocation, EnhancedMemoryTracker
from .alias import AliasAnalyzer, AliasSet
from .lifecycle import LifecycleAnalyzer, PointerLifecycle

__all__ = [
    'MemoryLocation',
    'EnhancedMemoryTracker',
    'AliasAnalyzer',
    'AliasSet',
    'LifecycleAnalyzer',
    'PointerLifecycle'
]
