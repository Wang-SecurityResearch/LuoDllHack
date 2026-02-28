# -*- coding: utf-8 -*-
"""
luodllhack.symbolic - 符号执行模块

提供真正的约束收集与求解能力:
- ConstraintCollector: 收集路径约束
- ExploitSolver: 求解触发漏洞的具体输入
- TaintSymbolicBridge: 污点分析到符号执行的桥接
- SymbolicExecutor: 基于 angr 的符号执行
"""

from .executor import ConstraintCollector, EnhancedSymbolicExecutor
from .solver import ExploitSolver, SolverResult
from .bridge import TaintSymbolicBridge

# 基于 angr 的符号执行器 (从 disasm/symbolic_executor.py 迁移)
try:
    from .angr_executor import (
        SymbolicExecutor, SymbolicInput, PathConstraint, ExploitInput, HAVE_ANGR
    )
except ImportError:
    SymbolicExecutor = None
    SymbolicInput = None
    PathConstraint = None
    ExploitInput = None
    HAVE_ANGR = False

__all__ = [
    'ConstraintCollector',
    'EnhancedSymbolicExecutor',
    'ExploitSolver',
    'SolverResult',
    'TaintSymbolicBridge',
    # angr 符号执行
    'SymbolicExecutor', 'SymbolicInput', 'PathConstraint', 'ExploitInput', 'HAVE_ANGR',
]
