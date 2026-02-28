# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/registry.py
Tool Registry - Manages all analysis tools callable by LLM

Refactored streamlined version:
- Tool Definitions: definitions.py
- Tool Execution: executors.py
- This module: Registration logic + Algorithm Findings management
"""

import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, TYPE_CHECKING

# Import type definitions
from .types import ToolResult, ToolResultType

# Import tool definitions
from .definitions import TOOL_DEFINITIONS

# Import tool executors
from .executors import ToolExecutors

# Use unified dependency detection
from ..compat import HAVE_VULN_ANALYSIS

if TYPE_CHECKING:
    from luodllhack.core.config import LuoDllHackConfig
    from luodllhack.analysis.taint import TaintEngine


# =============================================================================
# ToolRegistry - Tool Registry Center
# =============================================================================

class ToolRegistry:
    """
    Tool Registry

    Manages all analysis tools callable by LLM.
    Actual tool implementations are delegated to ToolExecutors.
    """

    def __init__(self, binary_path: Path, taint_engine: 'TaintEngine' = None,
                 llm_backend: Any = None, config: 'LuoDllHackConfig' = None,
                 signature_file: Path = None):
        self.binary_path = binary_path
        self.taint_engine = taint_engine
        # Store directly to internal attribute to avoid triggering property setter (at this time _executors hasn't been created yet)
        self._signature_file = Path(signature_file) if signature_file else None
        self.tools: Dict[str, Callable] = {}
        self.tool_schemas: List[Dict] = []

        # Initialize executors
        self._executors = ToolExecutors(
            binary_path=binary_path,
            taint_engine=taint_engine,
            llm_backend=llm_backend,
            config=config,
            signature_file=self._signature_file
        )

        # Algorithm analysis findings storage (delegated to executors)
        self.algorithm_findings = self._executors.algorithm_findings

        # Register built-in tools
        self._register_builtin_tools()

    # =========================================================================
    # Property Proxy
    # =========================================================================

    @property
    def exports(self) -> Dict[str, int]:
        """Dictionary of export functions"""
        return self._executors.exports

    @exports.setter
    def exports(self, value: Dict[str, int]):
        self._executors.exports = value

    @property
    def last_poc_code(self) -> Optional[str]:
        """Recently generated PoC code"""
        return self._executors.last_poc_code

    @last_poc_code.setter
    def last_poc_code(self, value: Optional[str]):
        self._executors.last_poc_code = value

    @property
    def llm_backend(self):
        """LLM Backend"""
        return self._executors.llm_backend

    @llm_backend.setter
    def llm_backend(self, value):
        self._executors.llm_backend = value

    @property
    def config(self):
        """Configuration"""
        return self._executors.config

    @config.setter
    def config(self, value):
        self._executors.config = value

    @property
    def signature_file(self):
        """External signature file"""
        # Prioritize getting from _executors (keep in sync), if not present return internal property
        if hasattr(self, '_executors'):
            return self._executors.signature_file
        return getattr(self, '_signature_file', None)

    @signature_file.setter
    def signature_file(self, value):
        """Set signature file (sync to executors)"""
        self._signature_file = value
        # If _executors is already created, sync update
        if hasattr(self, '_executors'):
            self._executors.signature_file = value

    # =========================================================================
    # Tool Registration
    # =========================================================================

    def _register_builtin_tools(self):
        """Register built-in analysis tools"""
        # Mapping of tool names to executor methods
        tool_method_map = {
            "disassemble_function": self._executors.disassemble_function,
            "analyze_taint_flow": self._executors.analyze_taint_flow,
            "analyze_cross_function": self._executors.analyze_cross_function,
            "check_dangerous_imports": self._executors.check_dangerous_imports,
            "find_path_to_sink": self._executors.find_path_to_sink,
            "generate_poc": self._executors.generate_poc,
            "verify_poc": self._executors.verify_poc,
            "verify_last_poc": self._executors.verify_last_poc,
            "solve_input": self._executors.solve_input,
            "get_algorithm_findings": self._executors.get_algorithm_findings,
            "validate_algorithm_finding": self._executors.validate_algorithm_finding,
            "check_bounds_before_sink": self._executors.check_bounds_before_sink,
            "analyze_pointer_lifecycle": self._executors.analyze_pointer_lifecycle,
            "symbolic_explore": self._executors.symbolic_explore,
            "deep_verify_vulnerability": self._executors.deep_verify_vulnerability,
            "verify_all_dangerous_imports": self._executors.verify_all_dangerous_imports,
        }

        # Register all tools from definitions
        for tool_def in TOOL_DEFINITIONS:
            name = tool_def["name"]
            if name in tool_method_map:
                self.register_tool(
                    name=name,
                    func=tool_method_map[name],
                    description=tool_def["description"],
                    parameters=tool_def["parameters"]
                )

    def register_tool(self, name: str, func: Callable,
                      description: str, parameters: Dict):
        """Register a new tool"""
        self.tools[name] = func
        self.tool_schemas.append({
            "name": name,
            "description": description,
            "parameters": parameters
        })

    def get_tool_declarations(self) -> List[Dict]:
        """Get tool declarations in Gemini Function Calling format"""
        return [
            {
                "function_declarations": self.tool_schemas
            }
        ]

    def call_tool(self, name: str, arguments: Dict) -> ToolResult:
        """Call a tool"""
        if name not in self.tools:
            return ToolResult(
                tool_name=name,
                status=ToolResultType.ERROR,
                error=f"Unknown tool: {name}"
            )

        start_time = time.time()
        try:
            result = self.tools[name](**arguments)
            return ToolResult(
                tool_name=name,
                status=ToolResultType.SUCCESS,
                data=result,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name=name,
                status=ToolResultType.ERROR,
                error=str(e),
                execution_time=time.time() - start_time
            )

    # =========================================================================
    # Algorithm Findings Management
    # =========================================================================

    def set_algorithm_findings(self, taint_engine: 'TaintEngine',
                               cross_function_findings: List = None):
        """
        Set algorithm analysis results (for AI cross-validation)

        Args:
            taint_engine: Taint engine (containing analysis results)
            cross_function_findings: Cross-function analysis results
        """
        # Format taint paths
        for i, path in enumerate(taint_engine.taint_paths):
            self.algorithm_findings["taint_paths"].append({
                "index": i,
                "vuln_type": path.sink.vuln_type.name if path.sink else "UNKNOWN",
                "severity": path.sink.severity if path.sink else "Medium",
                "source_api": path.source.api_name if path.source else "unknown",
                "source_type": path.source.type.name if path.source else "UNKNOWN",
                "sink_api": path.sink.api_name if path.sink else "unknown",
                "sink_addr": f"0x{path.sink.addr:x}" if path.sink else "0x0",
                "path_length": len(path.steps),
                "confidence": path.confidence
            })

        # Format memory vulnerabilities
        for i, finding in enumerate(taint_engine.memory_findings):
            self.algorithm_findings["memory_vulns"].append({
                "index": i,
                "vuln_type": finding.vuln_type.name,
                "severity": finding.severity,
                "alloc_addr": f"0x{finding.alloc_addr:x}",
                "alloc_api": finding.alloc_api,
                "free_addr": f"0x{finding.free_addr:x}",
                "free_api": finding.free_api,
                "vuln_addr": f"0x{finding.vuln_addr:x}",
                "action": finding.vuln_action
            })

        # Format integer overflows
        for i, finding in enumerate(taint_engine.integer_overflow_findings):
            self.algorithm_findings["integer_overflows"].append({
                "index": i,
                "vuln_type": finding.vuln_type.name,
                "severity": finding.severity,
                "overflow_addr": f"0x{finding.overflow_addr:x}",
                "overflow_instruction": finding.overflow_instruction,
                "alloc_addr": f"0x{finding.alloc_addr:x}",
                "alloc_api": finding.alloc_api,
                "func_name": finding.func_name,
                "risk_level": finding.risk_level
            })

        # Generate summary
        self.algorithm_findings["summary"] = {
            "total_taint_paths": len(taint_engine.taint_paths),
            "total_memory_vulns": len(taint_engine.memory_findings),
            "total_integer_overflows": len(taint_engine.integer_overflow_findings),
            "by_severity": self._count_by_severity(),
            "by_vuln_type": self._count_by_type()
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Statistics by severity"""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for path in self.algorithm_findings["taint_paths"]:
            sev = path.get("severity", "Medium")
            if sev in counts:
                counts[sev] += 1
        for finding in self.algorithm_findings["memory_vulns"]:
            sev = finding.get("severity", "Medium")
            if sev in counts:
                counts[sev] += 1
        for finding in self.algorithm_findings["integer_overflows"]:
            sev = finding.get("severity", "Medium")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _count_by_type(self) -> Dict[str, int]:
        """Statistics by vulnerability type"""
        counts = {}
        for path in self.algorithm_findings["taint_paths"]:
            vtype = path.get("vuln_type", "UNKNOWN")
            counts[vtype] = counts.get(vtype, 0) + 1
        for finding in self.algorithm_findings["memory_vulns"]:
            vtype = finding.get("vuln_type", "UNKNOWN")
            counts[vtype] = counts.get(vtype, 0) + 1
        for finding in self.algorithm_findings["integer_overflows"]:
            vtype = finding.get("vuln_type", "UNKNOWN")
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts
