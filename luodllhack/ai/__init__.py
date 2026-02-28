# -*- coding: utf-8 -*-
"""
luodllhack/ai - AI Assistance Capabilities

AI-driven analysis:
- VulnHuntingAgent: Autonomous vulnerability mining Agent
- SecurityAnalyzer: Security analyzer
- AIAnalyzer: AI code analysis assistant
"""

# AI-driven vulnerability mining (migrated from sys_dll/ai_agent.py)
try:
    from .agent import (
        VulnHuntingAgent,
        ToolRegistry,
        VulnReport,
        run_ai_hunt,
    )
    HAVE_AI_AGENT = True
except BaseException:
    HAVE_AI_AGENT = False
    VulnHuntingAgent = None
    ToolRegistry = None
    VulnReport = None
    run_ai_hunt = None

# Security analysis (migrated from sys_dll/security.py)
try:
    from .security import (
        SecurityAnalyzer,
        AIAgent as SecurityAIAgent,
    )
    HAVE_SECURITY_ANALYZER = True
except BaseException:
    HAVE_SECURITY_ANALYZER = False
    SecurityAnalyzer = None
    SecurityAIAgent = None

# AI analyzer (migrated from disasm/ai_analyzer.py)
try:
    from .analyzer import AIAnalyzer
    HAVE_AI_ANALYZER = True
except BaseException:
    HAVE_AI_ANALYZER = False
    AIAnalyzer = None

__all__ = [
    # AI Vulnerability Mining
    'VulnHuntingAgent', 'ToolRegistry', 'VulnReport', 'run_ai_hunt',
    'HAVE_AI_AGENT',
    # Security Analysis
    'SecurityAnalyzer', 'SecurityAIAgent', 'HAVE_SECURITY_ANALYZER',
    # AI Analyzer
    'AIAnalyzer', 'HAVE_AI_ANALYZER',
]
