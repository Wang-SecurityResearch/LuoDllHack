# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/__init__.py
Tool System Module - Provides analysis tools callable by LLM

Module Structure:
- types.py: Type definitions (ToolResult, AgentState, VulnReport, etc.)
- definitions.py: Tool schema definitions
- executors/: Tool executor package
  - base.py: Base classes and shared state
  - analysis.py: Analysis tools
  - poc.py: PoC generation and verification
  - enhanced.py: Enhanced analysis tools
- registry.py: Tool Registry

Exports:
- ToolRegistry: Tool Registry
- ToolExecutors: Tool Executors
- ToolResult, ToolResultType: Tool call results
- ToolDefinition: Tool definition
- AlgorithmFindings: Algorithm analysis result storage
- AgentState, VulnReport: Agent state and report
- TOOL_DEFINITIONS: List of tool definitions
"""

from .types import (
    ToolResult,
    ToolResultType,
    ToolDefinition,
    AlgorithmFindings,
    AgentState,
    VulnReport,
)

from .definitions import (
    TOOL_DEFINITIONS,
    get_tool_definition,
    get_all_tool_names,
)

from .executors import ToolExecutors

from .registry import ToolRegistry

__all__ = [
    # Core Classes
    'ToolRegistry',
    'ToolExecutors',
    # Type Definitions
    'ToolResult',
    'ToolResultType',
    'ToolDefinition',
    'AlgorithmFindings',
    'AgentState',
    'VulnReport',
    # Tool Definitions
    'TOOL_DEFINITIONS',
    'get_tool_definition',
    'get_all_tool_names',
]
