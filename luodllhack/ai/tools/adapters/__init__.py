# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/adapters - MCP Style Tool Adapters

Wraps LuoDllHack core capabilities into standardized tool interfaces.

Adapters:
    - RizinTools: Binary analysis
    - TaintTools: Taint analysis
    - VerificationTools: Symbolic execution + Deep verification
"""

from .base import (
    MCPTool,
    MCPToolSchema,
    MCPToolResult,
    MCPToolRegistry,
    MCPToolAdapter,
)

from .rizin import RizinTools
from .taint import TaintTools
from .verification import VerificationTools

__all__ = [
    # Base classes
    'MCPTool',
    'MCPToolSchema',
    'MCPToolResult',
    'MCPToolRegistry',
    'MCPToolAdapter',
    # Adapters
    'RizinTools',
    'TaintTools',
    'VerificationTools',
]
