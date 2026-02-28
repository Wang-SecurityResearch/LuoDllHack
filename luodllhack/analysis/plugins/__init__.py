# -*- coding: utf-8 -*-
"""
luodllhack/analysis/plugins - Code Pattern Analysis Plugin System

Provides extensible code pattern analysis capabilities based on disassembly results.

Usage:
    from luodllhack.analysis.plugins import PluginManager, AnalysisPlugin

    # Load plugins
    manager = PluginManager()
    manager.load_plugins()  # Automatically load plugins from the plugins/ directory

    # Use in analysis
    for insn in instructions:
        findings = manager.on_instruction(insn, context)
"""

from .base import (
    AnalysisPlugin,
    PluginManager,
    PluginContext,
    Finding,
    FindingType,
    TaintDefinitionPlugin,
    MemoryLifecyclePlugin,
)

__all__ = [
    'AnalysisPlugin',
    'PluginManager',
    'PluginContext',
    'Finding',
    'FindingType',
    'TaintDefinitionPlugin',
    'MemoryLifecyclePlugin',
]
