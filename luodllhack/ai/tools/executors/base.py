# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/executors/base.py
Tool Executor Base Class - Initialization and shared state
"""

from pathlib import Path
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from luodllhack.core.config import LuoDllHackConfig
    from luodllhack.analysis.taint import TaintEngine

# =============================================================================
# Conditional Imports
# =============================================================================

from ...compat import (
    HAVE_CAPSTONE, HAVE_VULN_ANALYSIS,
    HAVE_BOUNDS_CHECKER, HAVE_LIFECYCLE, HAVE_SYMBOLIC, HAVE_SIGNATURE,
    HAVE_CORE_UTILS
)

Cs = None
CS_ARCH_X86 = None
CS_MODE_64 = None
CS_MODE_32 = None
if HAVE_CAPSTONE:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    except ImportError:
        pass

DANGEROUS_SINKS = {}
TAINT_SOURCES = {}
TaintEngineClass = None
if HAVE_VULN_ANALYSIS:
    try:
        from luodllhack.analysis.taint import (
            TaintEngine as TaintEngineClass, DANGEROUS_SINKS, TAINT_SOURCES
        )
    except ImportError:
        pass

BoundsChecker = None
if HAVE_BOUNDS_CHECKER:
    try:
        from luodllhack.analysis.enhanced.bounds_checker import BoundsChecker
    except ImportError:
        pass

LifecycleAnalyzer = None
LifecycleEvent = None
if HAVE_LIFECYCLE:
    try:
        from luodllhack.memory.lifecycle import LifecycleAnalyzer, LifecycleEvent
    except ImportError:
        pass

EnhancedSymbolicExecutor = None
if HAVE_SYMBOLIC:
    try:
        from luodllhack.symbolic.executor import EnhancedSymbolicExecutor
    except ImportError:
        pass

SignatureExtractor = None
get_function_signature = None
get_enhanced_signature = None
if HAVE_SIGNATURE:
    try:
        from luodllhack.core.signatures import (
            SignatureExtractor, get_function_signature, get_enhanced_signature
        )
    except ImportError:
        pass

parse_exports_dict = None
if HAVE_CORE_UTILS:
    try:
        from luodllhack.core.utils import parse_exports_dict
    except ImportError:
        pass


# =============================================================================
# ToolExecutorsBase - Base Class
# =============================================================================

class ToolExecutorsBase:
    """
    Tool Executor Base Class

    Provides:
    - Initialization and configuration
    - Shared state
    - Algorithm findings management
    """

    def __init__(self, binary_path: Path, taint_engine: 'TaintEngine' = None,
                 llm_backend: Any = None, config: 'LuoDllHackConfig' = None,
                 signature_file: Path = None):
        self.binary_path = binary_path
        self.taint_engine = taint_engine
        self.llm_backend = llm_backend
        self.config = config
        self.signature_file = Path(signature_file) if signature_file else None

        # Initialize exports
        self.exports: Dict[str, int] = {}
        self.last_poc_code: Optional[str] = None

        # Algorithm analysis findings storage
        self.algorithm_findings: Dict[str, Any] = {
            "taint_paths": [],
            "memory_vulns": [],
            "integer_overflows": [],
            "cross_function_uaf": [],
            "summary": {}
        }

    # =========================================================================
    # Algorithm Findings
    # =========================================================================

    def get_algorithm_findings(self, category: str = "all") -> Dict:
        """Retrieve algorithm analysis results"""
        if category == "all":
            return self.algorithm_findings
        elif category in self.algorithm_findings:
            return {category: self.algorithm_findings[category]}
        else:
            return {"error": f"Unknown category: {category}"}

    def validate_algorithm_finding(self, finding_index: int, category: str) -> Dict:
        """Validate algorithm finding - returns detailed information for AI analysis"""
        if category not in self.algorithm_findings:
            return {"error": f"Unknown category: {category}"}

        findings = self.algorithm_findings[category]
        if finding_index < 0 or finding_index >= len(findings):
            return {"error": f"Invalid index: {finding_index}"}

        finding = findings[finding_index]
        result = {
            "finding": finding,
            "context": {}
        }

        if self.taint_engine:
            if category == "taint_paths" and finding_index < len(self.taint_engine.taint_paths):
                path = self.taint_engine.taint_paths[finding_index]
                result["context"]["steps"] = [
                    {"addr": f"0x{s.addr:x}", "instruction": s.instruction, "effect": s.effect}
                    for s in path.steps[:10]
                ]

        return result

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _find_function_containing(self, addr: int) -> Optional[int]:
        """Find the function containing the specified address"""
        if not self.taint_engine:
            return None

        for func_addr, node in self.taint_engine.callgraph.items():
            if func_addr <= addr < func_addr + 0x10000:
                return func_addr

        return None

    def _has_llm_backend(self) -> bool:
        """Check if an LLM backend is available"""
        if self.llm_backend is not None:
            return self.llm_backend.is_available()
        return False
