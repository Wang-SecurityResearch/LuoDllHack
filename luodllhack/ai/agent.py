# -*- coding: utf-8 -*-
"""
luodllhack/ai/agent.py
AI-driven vulnerability mining Agent - Entry Module

This module is a streamlined entry point, with actual implementations distributed across:
- hunting.py: VulnHuntingAgent core logic
- tools/: Tool registration and execution
- react/: ReAct loop and token management
- report/: Report generation

Example usage:
    from luodllhack.ai.agent import VulnHuntingAgent, run_ai_hunt

    agent = VulnHuntingAgent(binary_path)
    report = agent.hunt(metadata, exports)
"""

# =============================================================================
# Core Exports
# =============================================================================

# Import main classes from hunting.py
from .hunting import VulnHuntingAgent, run_ai_hunt

# Import types from tools/
from .tools import (
    ToolRegistry,
    ToolResult,
    ToolResultType,
    AgentState,
    VulnReport,
    AlgorithmFindings,
)

# Import from react/
from .react import TokenManager, ReActLoop

# Import from report/
from .report import ReportGenerator

# Import dependency checks from compat.py
from .compat import (
    DEPS,
    HAVE_GENAI,
    HAVE_VULN_ANALYSIS,
    HAVE_CAPSTONE,
    HAVE_CONFIG,
    safe_parse_address,
)

# =============================================================================
# Compatibility Flags (re-exported from compat)
# =============================================================================

HAVE_AI_AGENT = HAVE_GENAI and HAVE_VULN_ANALYSIS

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Main Classes
    'VulnHuntingAgent',
    # Convenience Functions
    'run_ai_hunt',
    # Tools
    'ToolRegistry',
    'ToolResult',
    'ToolResultType',
    # State and Report
    'AgentState',
    'VulnReport',
    'AlgorithmFindings',
    # Token Management
    'TokenManager',
    # ReAct Loop
    'ReActLoop',
    # Report Generation
    'ReportGenerator',
    # Dependency Detection
    'DEPS',
    'HAVE_GENAI',
    'HAVE_VULN_ANALYSIS',
    'HAVE_AI_AGENT',
    # Utility Functions
    'safe_parse_address',
]
