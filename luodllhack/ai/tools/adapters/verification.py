# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/adapters/verification.py
Verification Tool Adapter

Wraps symbolic execution and deep verification capabilities as MCP tools:
    - Symbolic execution exploration (symbolic_explore)
    - Deep vulnerability verification (deep_verify_vulnerability)
    - Batch verification of dangerous imports (verify_all_dangerous_imports)
    - Speakeasy dynamic verification (speakeasy_verify)
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, TYPE_CHECKING

from .base import MCPTool, MCPToolAdapter, MCPToolResult, MCPResultStatus

if TYPE_CHECKING:
    from luodllhack.analysis.taint import TaintEngine

logger = logging.getLogger(__name__)

# Check dependencies
try:
    import angr
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False

try:
    from luodllhack.symbolic.executor import EnhancedSymbolicExecutor
    HAVE_SYMBOLIC = True
except ImportError:
    HAVE_SYMBOLIC = False
    EnhancedSymbolicExecutor = None

try:
    from luodllhack.verify.speakeasy import SpeakeasyVerifier, HAVE_SPEAKEASY
except ImportError:
    HAVE_SPEAKEASY = False
    SpeakeasyVerifier = None

try:
    from luodllhack.analysis.enhanced import BoundsChecker
    HAVE_BOUNDS_CHECKER = True
except ImportError:
    HAVE_BOUNDS_CHECKER = False
    BoundsChecker = None


# =============================================================================
# Symbolic Execution Exploration Tool
# =============================================================================

class SymbolicExploreTool(MCPTool):
    """Symbolic execution exploration tool - Solve path constraints"""

    def __init__(self, binary_path: Path, taint_engine: "TaintEngine" = None):
        self.binary_path = binary_path
        self.taint_engine = taint_engine

    @property
    def name(self) -> str:
        return "symbolic_explore"

    @property
    def description(self) -> str:
        return "Use symbolic execution (angr) to explore paths from function to sink, collect constraints and solve for concrete inputs that trigger the vulnerability."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "func_address": {
                "type": "string",
                "description": "Function entry address (hex string like '0x18001000')"
            },
            "target_sink_address": {
                "type": "string",
                "description": "Target sink address to reach (hex string)"
            },
            "num_args": {
                "type": "integer",
                "description": "Number of function arguments to make symbolic (default: 4)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["func_address", "target_sink_address"]

    def execute(
        self,
        func_address: str,
        target_sink_address: str,
        num_args: int = 4,
        **kwargs  # Ignore extra parameters
    ) -> Dict[str, Any]:
        """Execute symbolic exploration"""
        _ = kwargs
        if not HAVE_SYMBOLIC or not HAVE_ANGR:
            return {
                "error": "Symbolic execution not available. Install angr: pip install angr",
                "available": False
            }

        try:
            # Parse addresses
            func_addr = int(func_address, 16) if isinstance(func_address, str) else int(func_address)
            sink_addr = int(target_sink_address, 16) if isinstance(target_sink_address, str) else int(target_sink_address)
            num_args = int(num_args) if num_args else 4

            # Create symbolic executor
            executor = EnhancedSymbolicExecutor(
                str(self.binary_path),
                auto_load_libs=False
            )

            # Explore paths
            path_states = executor.explore_with_constraints(
                func_addr=func_addr,
                target_addr=sink_addr,
                max_steps=2000,
                timeout=60
            )

            if not path_states:
                return {
                    "func_address": func_address,
                    "target_sink": target_sink_address,
                    "paths_found": 0,
                    "reachable": False,
                    "note": "No paths found to target sink - vulnerability may not be reachable"
                }

            # Analyze paths
            paths_info = []
            solved_inputs = {}
            reachable_count = 0

            for i, ps in enumerate(path_states[:5]):
                path_info = {
                    "path_id": ps.path_id,
                    "constraint_count": ps.get_constraint_count(),
                    "reached_target": ps.reached_target,
                    "is_satisfiable": ps.is_satisfiable
                }

                if ps.reached_target:
                    reachable_count += 1

                if ps.is_satisfiable and ps.reached_target:
                    try:
                        for var_name, sym_var in ps.symbolic_vars.items():
                            if ps.final_state.solver.satisfiable():
                                concrete = ps.final_state.solver.eval(sym_var.bitvec, cast_to=bytes)
                                solved_inputs[var_name] = concrete.hex()
                                path_info["solved"] = True
                    except Exception:
                        path_info["solved"] = False

                paths_info.append(path_info)

            return {
                "func_address": func_address,
                "target_sink": target_sink_address,
                "paths_found": len(path_states),
                "paths_to_target": reachable_count,
                "reachable": reachable_count > 0,
                "paths_info": paths_info,
                "solved_inputs": solved_inputs,
                "confidence_boost": 0.25 if reachable_count > 0 else 0.0,
                "note": "Path reachable - vulnerability confirmed" if reachable_count > 0 else "No reachable paths"
            }

        except Exception as e:
            import traceback
            return {
                "error": f"Symbolic exploration failed: {str(e)}",
                "trace": traceback.format_exc()
            }


# =============================================================================
# Deep Verification Tool
# =============================================================================

class DeepVerifyTool(MCPTool):
    """Deep vulnerability verification tool - Multi-technique fused verification"""

    def __init__(self, binary_path: Path, taint_engine: "TaintEngine" = None):
        self.binary_path = binary_path
        self.taint_engine = taint_engine
        self._bounds_checker = None
        if HAVE_BOUNDS_CHECKER and taint_engine:
            try:
                self._bounds_checker = BoundsChecker(taint_engine.rz)
            except Exception:
                pass

    @property
    def name(self) -> str:
        return "deep_verify_vulnerability"

    @property
    def description(self) -> str:
        return "Perform deep vulnerability verification using multiple techniques: bounds checking analysis, taint confirmation, symbolic execution. Returns confidence score and evidence."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "sink_address": {
                "type": "string",
                "description": "Vulnerable sink address (hex string)"
            },
            "vuln_type": {
                "type": "string",
                "description": "Vulnerability type (e.g., 'buffer_overflow', 'use_after_free')"
            },
            "func_address": {
                "type": "string",
                "description": "Function entry address for symbolic verification (optional)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["sink_address", "vuln_type"]

    def execute(
        self,
        sink_address: str,
        vuln_type: str,
        func_address: str = None,
        **kwargs  # Ignore extra parameters
    ) -> Dict[str, Any]:
        """Execute deep verification"""
        # Ignore unused parameters (e.g., tainted_arg_index)
        _ = kwargs
        try:
            addr = int(sink_address, 16) if isinstance(sink_address, str) else int(sink_address)
            vuln_type = vuln_type.upper().replace("-", "_")

            confidence_score = 0.3  # Base score
            evidence = []
            verification_methods = []

            # 1. Bounds check analysis (Weight: 25%)
            if self._bounds_checker:
                try:
                    bounds_result = self._bounds_checker.check_before_call(addr)
                    verification_methods.append("bounds_check")

                    if bounds_result.get("has_effective_check"):
                        confidence_score -= 0.25
                        evidence.append("✗ Found effective bounds check - likely false positive")
                    elif bounds_result.get("has_check"):
                        confidence_score -= 0.10
                        evidence.append("△ Found bounds check but may be bypassable")
                    else:
                        confidence_score += 0.20
                        evidence.append("✓ No bounds check found before sink")
                except Exception as e:
                    evidence.append(f"Bounds check analysis error: {e}")

            # 2. Taint path confirmation (Weight: 25%)
            if self.taint_engine:
                taint_confirmed = False
                for path in getattr(self.taint_engine, 'taint_paths', []):
                    if path.sink and path.sink.addr == addr:
                        taint_confirmed = True
                        confidence_score += 0.25
                        evidence.append(f"✓ Taint path confirmed: {path.source.type.name} -> sink")
                        verification_methods.append("taint_analysis")
                        break

                if not taint_confirmed:
                    evidence.append("△ No taint path to this sink")

            # 3. Symbolic execution verification (Weight: 30%)
            if HAVE_SYMBOLIC and func_address:
                try:
                    sym_tool = SymbolicExploreTool(self.binary_path, self.taint_engine)
                    sym_result = sym_tool.execute(func_address, sink_address)

                    if sym_result.get("reachable"):
                        confidence_score += 0.30
                        evidence.append(f"✓ Symbolic execution: path reachable ({sym_result.get('paths_to_target')} paths)")
                        verification_methods.append("symbolic_execution")

                        if sym_result.get("solved_inputs"):
                            confidence_score += 0.10
                            evidence.append("✓ Concrete trigger inputs found")
                    elif not sym_result.get("error"):
                        confidence_score -= 0.15
                        evidence.append("✗ Symbolic execution: path not reachable")
                except Exception as e:
                    evidence.append(f"Symbolic verification error: {e}")

            # 4. Vulnerability type specific check (Weight: 10%)
            type_specific_score = self._check_vuln_type_specific(addr, vuln_type)
            confidence_score += type_specific_score
            if type_specific_score > 0:
                evidence.append(f"✓ Vulnerability pattern matches {vuln_type}")
                verification_methods.append("pattern_match")

            # Final score
            confidence_score = max(0.0, min(1.0, confidence_score))

            if confidence_score >= 0.85:
                level = "Confirmed"
            elif confidence_score >= 0.70:
                level = "High"
            elif confidence_score >= 0.50:
                level = "Medium"
            elif confidence_score >= 0.30:
                level = "Low"
            else:
                level = "Likely False Positive"

            return {
                "sink_address": sink_address,
                "vuln_type": vuln_type,
                "confidence_score": round(confidence_score, 2),
                "confidence_level": level,
                "is_verified": confidence_score >= 0.50,
                "is_exploitable": confidence_score >= 0.70,
                "evidence": evidence,
                "verification_methods": verification_methods,
                "recommendation": self._get_recommendation(level)
            }

        except Exception as e:
            import traceback
            return {
                "error": f"Deep verification failed: {str(e)}",
                "trace": traceback.format_exc()
            }

    def _check_vuln_type_specific(self, addr: int, vuln_type: str) -> float:
        """Vulnerability type specific check"""
        # Simplified implementation - can be extended
        high_risk_types = {
            "BUFFER_OVERFLOW", "HEAP_OVERFLOW", "USE_AFTER_FREE",
            "DOUBLE_FREE", "CONTROL_FLOW_HIJACK", "FORMAT_STRING"
        }
        if vuln_type in high_risk_types:
            return 0.10
        return 0.05

    def _get_recommendation(self, level: str) -> str:
        """Give recommendation based on verification level"""
        recommendations = {
            "Confirmed": "Vulnerability confirmed. Proceed with exploitation.",
            "High": "High confidence. Recommend dynamic verification with Speakeasy.",
            "Medium": "Medium confidence. Need additional verification.",
            "Low": "Low confidence. May be false positive.",
            "Likely False Positive": "Likely false positive. Review manually if critical."
        }
        return recommendations.get(level, "Unknown")


# =============================================================================
# Speakeasy Dynamic Verification Tool
# =============================================================================

class SpeakeasyVerifyTool(MCPTool):
    """Speakeasy dynamic verification tool"""

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path

    @property
    def name(self) -> str:
        return "speakeasy_verify"

    @property
    def description(self) -> str:
        return "Use Speakeasy emulator to dynamically verify vulnerability by emulating the DLL and monitoring for crashes, memory corruption, or other anomalies."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "func_address": {
                "type": "string",
                "description": "Function address to emulate"
            },
            "vuln_type": {
                "type": "string",
                "description": "Expected vulnerability type"
            },
            "trigger_input": {
                "type": "string",
                "description": "Hex-encoded input to trigger vulnerability (optional)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["func_address", "vuln_type"]

    def execute(
        self,
        func_address: str,
        vuln_type: str,
        trigger_input: str = None,
        **kwargs  # Ignore extra parameters
    ) -> Dict[str, Any]:
        """Execute dynamic verification"""
        _ = kwargs
        if not HAVE_SPEAKEASY:
            return {
                "error": "Speakeasy not available. Install: pip install speakeasy-emulator",
                "available": False
            }

        try:
            addr = int(func_address, 16) if isinstance(func_address, str) else int(func_address)

            verifier = SpeakeasyVerifier(self.binary_path)
            result = verifier.verify(addr, vuln_type.upper(), trigger=True)

            return {
                "func_address": func_address,
                "vuln_type": vuln_type,
                "verified": result.verified,
                "confidence": result.confidence,
                "crash_detected": any(e.vuln_type for e in result.events),
                "events": [
                    {
                        "type": e.vuln_type,
                        "address": hex(e.address),
                        "details": e.details
                    }
                    for e in result.events[:5]
                ],
                "analysis": result.analysis,
                "is_exploitable": result.verified and result.confidence >= 0.7
            }

        except Exception as e:
            import traceback
            return {
                "error": f"Speakeasy verification failed: {str(e)}",
                "trace": traceback.format_exc()
            }


# =============================================================================
# Verification Tool Adapter
# =============================================================================

class VerificationTools(MCPToolAdapter):
    """
    Verification Tool Adapter

    Provides symbolic execution and dynamic verification capabilities.
    """

    def __init__(self, binary_path: Path, taint_engine: "TaintEngine" = None):
        self.binary_path = Path(binary_path)
        self.taint_engine = taint_engine
        self._tools: Dict[str, MCPTool] = {}
        self._init_tools()

    def _init_tools(self):
        """Initialize tools"""
        # Symbolic execution tool
        self._tools["symbolic_explore"] = SymbolicExploreTool(
            self.binary_path, self.taint_engine
        )

        # Deep verification tool
        self._tools["deep_verify_vulnerability"] = DeepVerifyTool(
            self.binary_path, self.taint_engine
        )

        # Speakeasy dynamic verification
        self._tools["speakeasy_verify"] = SpeakeasyVerifyTool(
            self.binary_path
        )

    @property
    def name(self) -> str:
        return "verification"

    @property
    def tools(self) -> List[MCPTool]:
        return list(self._tools.values())

    def get_tool(self, name: str) -> Optional[MCPTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[str]:
        return list(self._tools.keys())

    @property
    def capabilities(self) -> Dict[str, bool]:
        return {
            "symbolic_execution": HAVE_SYMBOLIC and HAVE_ANGR,
            "bounds_checking": HAVE_BOUNDS_CHECKER,
            "speakeasy_emulation": HAVE_SPEAKEASY,
        }
