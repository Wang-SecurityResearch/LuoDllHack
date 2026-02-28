# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/adapters/taint.py
Taint Analysis Tool Adapter

Wraps TaintEngine capabilities as MCP tools:
    - Taint flow analysis
    - Cross-function analysis
    - Dangerous API detection
    - Path tracing
"""

import logging
from typing import Dict, List, Any, Optional, TYPE_CHECKING

from .base import MCPTool, MCPToolAdapter

if TYPE_CHECKING:
    from luodllhack.analysis.taint import TaintEngine

logger = logging.getLogger(__name__)


# =============================================================================
# Taint Analysis Tool Definitions
# =============================================================================

class AnalyzeTaintFlowTool(MCPTool):
    """Taint flow analysis tool"""

    def __init__(self, engine: "TaintEngine"):
        self.engine = engine

    @property
    def name(self) -> str:
        return "analyze_taint_flow"

    @property
    def description(self) -> str:
        return "Analyze taint flow from a function to identify potential vulnerabilities. Tracks data flow from sources to sinks."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "func_address": {
                "type": "integer",
                "description": "Function address to analyze"
            },
            "func_name": {
                "type": "string",
                "description": "Function name (optional, for logging)"
            },
            "max_instructions": {
                "type": "integer",
                "description": "Maximum instructions to analyze (default: 0 = use config default)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["func_address"]

    def execute(
        self,
        func_address: int,
        func_name: str = None,
        max_instructions: int = 0
    ) -> Dict[str, Any]:
        """Execute taint flow analysis"""
        paths = self.engine.analyze_function(
            func_address,
            func_name or f"func_0x{func_address:x}",
            max_instructions=max_instructions
        )

        result_paths = []
        for path in paths[:10]:  # Limit returned quantity
            result_paths.append({
                "source": {
                    "type": path.source.type.name if path.source else "UNKNOWN",
                    "api": path.source.api_name if path.source else "",
                    "address": path.source.addr if path.source else 0,
                },
                "sink": {
                    "api": path.sink.api_name if path.sink else "",
                    "address": path.sink.addr if path.sink else 0,
                    "vuln_type": path.sink.vuln_type.name if path.sink else "UNKNOWN",
                    "severity": path.sink.severity if path.sink else "Medium",
                },
                "path_length": len(path.steps),
                "confidence": path.confidence,
            })

        return {
            "function": func_name or f"0x{func_address:x}",
            "taint_paths_found": len(paths),
            "paths": result_paths,
        }


class CheckDangerousImportsTool(MCPTool):
    """Check dangerous imports tool"""

    def __init__(self, engine: "TaintEngine"):
        self.engine = engine

    @property
    def name(self) -> str:
        return "check_dangerous_imports"

    @property
    def description(self) -> str:
        return "Check imported functions for known dangerous APIs that could lead to vulnerabilities."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {}

    def execute(self) -> Dict[str, Any]:
        """Check dangerous imports"""
        # Get imports
        imports = self.engine.rz.get_imports()

        # Dangerous API list
        from luodllhack.core.types import DANGEROUS_SINKS

        dangerous = []
        for addr, imp in imports.items():
            # Ensure name is a string
            name = imp.name
            if isinstance(name, bytes):
                name = name.decode('utf-8', errors='ignore')
            name_lower = name.lower()

            for sink_name, info in DANGEROUS_SINKS.items():
                # sink_name could be bytes
                if isinstance(sink_name, bytes):
                    sink_str = sink_name.decode('utf-8', errors='ignore')
                else:
                    sink_str = str(sink_name)
                sink_lower = sink_str.lower()

                if sink_lower in name_lower:
                    # Get vulnerability type
                    vuln = info.get("vuln")
                    vuln_type = vuln.name if hasattr(vuln, 'name') else str(vuln) if vuln else "UNKNOWN"

                    dangerous.append({
                        "name": name,
                        "address": addr,
                        "vuln_type": vuln_type,
                        "severity": info.get("severity", "Medium"),
                        "cwe": info.get("cwe", ""),
                    })

        return {
            "total_imports": len(imports),
            "dangerous_count": len(dangerous),
            "dangerous_imports": dangerous,
        }


class AnalyzeCrossFunctionTool(MCPTool):
    """Cross-function analysis tool"""

    def __init__(self, engine: "TaintEngine"):
        self.engine = engine

    @property
    def name(self) -> str:
        return "analyze_cross_function"

    @property
    def description(self) -> str:
        return "Perform cross-function taint analysis to find vulnerabilities that span multiple functions."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "entry_address": {
                "type": "integer",
                "description": "Entry function address"
            },
            "max_call_depth": {
                "type": "integer",
                "description": "Maximum call depth to follow (default: 5)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["entry_address"]

    def execute(
        self,
        entry_address: int,
        max_call_depth: int = 5
    ) -> Dict[str, Any]:
        """Execute cross-function analysis"""
        findings = self.engine.analyze_cross_function(
            entry_address,
            max_depth=max_call_depth
        )

        vulns = []
        for finding in findings[:10]:
            vulns.append({
                "entry_function": finding.get("entry", ""),
                "call_chain": finding.get("call_chain", []),
                "sink": finding.get("sink", {}),
                "vuln_type": finding.get("vuln_type", "UNKNOWN"),
                "confidence": finding.get("confidence", 0.5),
            })

        return {
            "entry_address": f"0x{entry_address:x}",
            "cross_function_vulns": len(findings),
            "vulnerabilities": vulns,
        }


class FindPathToSinkTool(MCPTool):
    """Find path to sink tool"""

    def __init__(self, engine: "TaintEngine"):
        self.engine = engine

    @property
    def name(self) -> str:
        return "find_path_to_sink"

    @property
    def description(self) -> str:
        return "Find all taint paths from a source to a specific sink address."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "source_address": {
                "type": "integer",
                "description": "Source address (e.g., input function)"
            },
            "sink_address": {
                "type": "integer",
                "description": "Target sink address"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["source_address", "sink_address"]

    def execute(
        self,
        source_address: int,
        sink_address: int
    ) -> Dict[str, Any]:
        """Find path to sink"""
        paths = self.engine.find_path_to_sink(source_address, sink_address)

        result_paths = []
        for path in paths[:5]:
            result_paths.append({
                "steps": [
                    {
                        "address": s.address,
                        "instruction": s.instruction,
                        "registers": list(s.tainted_regs),
                    }
                    for s in path.steps[:20]
                ],
                "total_steps": len(path.steps),
                "confidence": path.confidence,
            })

        return {
            "source": f"0x{source_address:x}",
            "sink": f"0x{sink_address:x}",
            "paths_found": len(paths),
            "paths": result_paths,
        }


class AnalyzePointerLifecycleTool(MCPTool):
    """Pointer lifecycle analysis tool"""

    def __init__(self, engine: "TaintEngine"):
        self.engine = engine

    @property
    def name(self) -> str:
        return "analyze_pointer_lifecycle"

    @property
    def description(self) -> str:
        return "Analyze pointer lifecycle to detect use-after-free, double-free, and memory leak vulnerabilities."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "func_address": {
                "type": "integer",
                "description": "Function address to analyze"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["func_address"]

    def execute(self, func_address: int) -> Dict[str, Any]:
        """Analyze pointer lifecycle"""
        findings = self.engine.analyze_memory_lifecycle(func_address)

        anomalies = []
        for finding in findings:
            anomalies.append({
                "type": finding.vuln_type.name,
                "alloc_address": f"0x{finding.alloc_addr:x}",
                "alloc_api": finding.alloc_api,
                "free_address": f"0x{finding.free_addr:x}",
                "free_api": finding.free_api,
                "vuln_address": f"0x{finding.vuln_addr:x}",
                "severity": finding.severity,
            })

        return {
            "function": f"0x{func_address:x}",
            "anomalies_found": len(anomalies),
            "anomalies": anomalies,
        }


class DeepVerifyVulnerabilityTool(MCPTool):
    """Deep verify vulnerability tool"""

    def __init__(self, engine: "TaintEngine"):
        self.engine = engine

    @property
    def name(self) -> str:
        return "taint_deep_verify"  # Distinguish from deep_verify_vulnerability in verification.py

    @property
    def description(self) -> str:
        return "Perform taint-based deep verification with bounds checking and sanitizer detection."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "sink_address": {
                "type": "integer",
                "description": "Address of the potential sink"
            },
            "vuln_type": {
                "type": "string",
                "description": "Type of vulnerability to verify (e.g., BUFFER_OVERFLOW)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["sink_address", "vuln_type"]

    def execute(
        self,
        sink_address: int,
        vuln_type: str,
        **kwargs  # Ignore extra parameters (e.g., tainted_arg_index)
    ) -> Dict[str, Any]:
        """Deep verify vulnerability"""
        _ = kwargs
        result = self.engine.deep_verify(sink_address, vuln_type)

        return {
            "sink_address": f"0x{sink_address:x}",
            "vuln_type": vuln_type,
            "is_likely_exploitable": result.get("exploitable", False),
            "confidence_score": result.get("confidence", 0.0),
            "confidence_level": result.get("level", "Low"),
            "bounds_checked": result.get("bounds_checked", False),
            "sanitizer_detected": result.get("sanitizer", False),
            "evidence": result.get("evidence", []),
        }


class GetTaintSummaryTool(MCPTool):
    """Get taint analysis summary tool"""

    def __init__(self, engine: "TaintEngine"):
        self.engine = engine

    @property
    def name(self) -> str:
        return "get_taint_summary"

    @property
    def description(self) -> str:
        return "Get a summary of all taint analysis findings."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {}

    def execute(self) -> Dict[str, Any]:
        """Get taint analysis summary"""
        # Summarize various findings
        taint_paths = self.engine.taint_paths
        memory_findings = self.engine.memory_findings
        overflow_findings = self.engine.integer_overflow_findings

        # Count by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        vuln_type_counts = {}

        for path in taint_paths:
            if path.sink:
                severity = path.sink.severity
                if severity in severity_counts:
                    severity_counts[severity] += 1
                vuln_type = path.sink.vuln_type.name
                vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

        for finding in memory_findings:
            severity = finding.severity
            if severity in severity_counts:
                severity_counts[severity] += 1
            vuln_type = finding.vuln_type.name
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

        return {
            "total_taint_paths": len(taint_paths),
            "total_memory_vulns": len(memory_findings),
            "total_integer_overflows": len(overflow_findings),
            "by_severity": severity_counts,
            "by_vuln_type": vuln_type_counts,
            "high_confidence_count": sum(
                1 for p in taint_paths if p.confidence >= 0.7
            ),
        }


# =============================================================================
# Taint Analysis Tool Adapter
# =============================================================================

class TaintTools(MCPToolAdapter):
    """
    Taint Analysis Tool Adapter

    Wraps TaintEngine capabilities as a set of MCP tools.
    """

    def __init__(self, engine: "TaintEngine"):
        """
        Initialize adapter

        Args:
            engine: TaintEngine instance
        """
        self.engine = engine
        self._tools: List[MCPTool] = []
        self._init_tools()

    def _init_tools(self) -> None:
        """Initialize all tools"""
        self._tools = [
            AnalyzeTaintFlowTool(self.engine),
            CheckDangerousImportsTool(self.engine),
            AnalyzeCrossFunctionTool(self.engine),
            FindPathToSinkTool(self.engine),
            AnalyzePointerLifecycleTool(self.engine),
            DeepVerifyVulnerabilityTool(self.engine),
            GetTaintSummaryTool(self.engine),
        ]

    def get_tools(self) -> List[MCPTool]:
        """Get all tools"""
        return self._tools
