# -*- coding: utf-8 -*-
"""
disasm - LuoDllHack v6.0 反汇编模块

基于 Rizin 的反汇编和分析入口。
所有反汇编、CFG 构建、反编译功能均通过 RizinCore 提供。

使用示例:
    from disasm import RizinCore, IntegratedAnalyzer

    # 方式1: 直接使用 RizinCore
    with RizinCore("target.dll") as rz:
        func = rz.analyze_function(0x10001000)
        print(func.decompiled)

    # 方式2: 使用整合分析器
    analyzer = IntegratedAnalyzer("target.dll")
    findings = analyzer.hunt_vulnerabilities()

作者: LuoDllHack Team
版本: 6.0.0
"""

# =============================================================================
# 从 luodllhack.core 导入 Rizin 核心
# =============================================================================

from luodllhack.core import (
    # 核心引擎
    RizinCore,
    load_binary,
    check_rizin_available,
    HAVE_RIZIN,
    # 异常
    RizinError,
    RizinNotFoundError,
    BinaryLoadError,
    AnalysisError,
    # 数据结构
    Architecture,
    BinaryInfo,
    Instruction,
    InstructionType,
    BasicBlock,
    EdgeType,
    Function,
    Variable,
    Import,
    Export,
    Section,
    StringRef,
    VTable,
    XRef,
    RopGadget,
)

# =============================================================================
# 整合分析器
# =============================================================================

from .integrated_analyzer import IntegratedAnalyzer

# =============================================================================
# 导出
# =============================================================================

__all__ = [
    # 核心引擎
    'RizinCore',
    'load_binary',
    'check_rizin_available',
    'HAVE_RIZIN',
    # 异常
    'RizinError',
    'RizinNotFoundError',
    'BinaryLoadError',
    'AnalysisError',
    # 数据结构
    'Architecture',
    'BinaryInfo',
    'Instruction',
    'InstructionType',
    'BasicBlock',
    'EdgeType',
    'Function',
    'Variable',
    'Import',
    'Export',
    'Section',
    'StringRef',
    'VTable',
    'XRef',
    'RopGadget',
    # 整合分析器
    'IntegratedAnalyzer',
]
