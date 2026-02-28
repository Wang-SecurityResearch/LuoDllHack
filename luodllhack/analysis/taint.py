# -*- coding: utf-8 -*-
"""
luodllhack/analysis/taint.py - LuoDllHack v6.0 Taint Analysis Module

Type-aware taint analysis engine based on Rizin, removing all Capstone/pefile dependencies.

Core Capabilities:
    1. Deep Taint Analysis - Track complete Source → Sink paths
    2. Type-Aware Analysis - Utilize Rizin's type recovery capabilities
    3. Cross-Function Analysis - Trace internal function call chains
    4. Memory Lifecycle Tracking - UAF/Double-Free detection
    5. Integer Overflow Detection - Overflow → Heap Overflow vulnerability chain

Author: LuoDllHack Team
Version: 6.0.0
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict

# =============================================================================
# Rizin Core Imports
# =============================================================================

from luodllhack.core import (
    RizinCore,
    Function,
    BasicBlock,
    Instruction,
    InstructionType,
    Import,
    Export,
    Architecture,
)

# =============================================================================
# Configuration Management
# =============================================================================

try:
    from luodllhack.core.config import default_config, ConfidenceWeightsConfig
    HAVE_CONFIG = True
except ImportError:
    HAVE_CONFIG = False
    default_config = None

# =============================================================================
# Unified Type Definitions (Imported from core.types)
# =============================================================================

from luodllhack.core.types import (
    VulnType,
    SourceType,
    PointerState,
    ArithmeticOp,
    ConfidenceFactor,
    TaintSource,
    TaintSink,
    TaintStep,
    TaintPath,
    VulnFinding,
    InternalCall,
    FunctionSummary,
    CallGraphNode,
    CrossFunctionPath,
    PointerInfo,
    MemoryVulnFinding,
    CrossFunctionUAF,
    PointerParamState,
    IntegerOverflowInfo,
    IntegerOverflowFinding,
    ConfidenceScore,
    ScoredFinding,
    DANGEROUS_SINKS,
    TAINT_SOURCES,
    ALLOC_APIS,
    FREE_APIS,
    POINTER_USE_APIS,
    OVERFLOW_RISK_INSTRUCTIONS,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Optional Dependencies
# =============================================================================

try:
    from triton import (
        TritonContext, ARCH, MODE, Instruction as TritonInstruction,
        MemoryAccess, CALLBACK, OPCODE, OPERAND
    )
    HAVE_TRITON = True
except ImportError:
    HAVE_TRITON = False

try:
    import angr
    import claripy
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False

# Plugin system
try:
    from .plugins import PluginManager, PluginContext, Finding
    HAVE_PLUGINS = True
except ImportError:
    HAVE_PLUGINS = False
    PluginManager = None
    PluginContext = None


# =============================================================================
# Confidence Scoring System
# =============================================================================

def _build_confidence_weights() -> Dict[ConfidenceFactor, float]:
    """Build confidence weights dictionary, prioritizing configuration file"""
    if HAVE_CONFIG and default_config is not None:
        weights = default_config.confidence_weights
        return {
            ConfidenceFactor.TAINT_PATH_EXISTS: weights.taint_path_exists,
            ConfidenceFactor.AI_CONFIRMED: weights.ai_confirmed,
            ConfidenceFactor.DANGEROUS_API_CALL: weights.dangerous_api_call,
            ConfidenceFactor.USER_INPUT_DIRECT: weights.user_input_direct,
            ConfidenceFactor.NO_BOUNDS_CHECK: weights.no_bounds_check,
            ConfidenceFactor.ARITHMETIC_OVERFLOW: weights.arithmetic_overflow,
            ConfidenceFactor.INDIRECT_CALL_TAINTED: weights.indirect_call_tainted,
            ConfidenceFactor.NO_NULL_CHECK: weights.no_null_check,
            ConfidenceFactor.CROSS_FUNCTION: weights.cross_function,
            ConfidenceFactor.MULTIPLE_PATHS: weights.multiple_paths,
        }
    # Fallback: Use hardcoded defaults
    return {
        ConfidenceFactor.TAINT_PATH_EXISTS: 0.25,
        ConfidenceFactor.AI_CONFIRMED: 0.20,
        ConfidenceFactor.DANGEROUS_API_CALL: 0.15,
        ConfidenceFactor.USER_INPUT_DIRECT: 0.10,
        ConfidenceFactor.NO_BOUNDS_CHECK: 0.10,
        ConfidenceFactor.ARITHMETIC_OVERFLOW: 0.05,
        ConfidenceFactor.INDIRECT_CALL_TAINTED: 0.10,
        ConfidenceFactor.NO_NULL_CHECK: 0.03,
        ConfidenceFactor.CROSS_FUNCTION: 0.05,
        ConfidenceFactor.MULTIPLE_PATHS: 0.03,
    }


CONFIDENCE_WEIGHTS: Dict[ConfidenceFactor, float] = _build_confidence_weights()

# Confidence level thresholds
CONFIDENCE_LEVELS = {
    "Confirmed": 0.85,
    "High": 0.70,
    "Medium": 0.50,
    "Low": 0.30,
    "Suspicious": 0.0,
}

# Arithmetic risk levels
OVERFLOW_RISK_LEVELS = {
    ArithmeticOp.MUL: "Critical",
    ArithmeticOp.IMUL: "Critical",
    ArithmeticOp.SHL: "High",
    ArithmeticOp.ADD: "Medium",
    ArithmeticOp.SUB: "Medium",
}


def get_weights_for_vuln_type(vuln_type: VulnType) -> Dict[ConfidenceFactor, float]:
    """Dynamically adjust weights based on vulnerability type"""
    base_weights = CONFIDENCE_WEIGHTS.copy()

    if vuln_type in (VulnType.BUFFER_OVERFLOW, VulnType.HEAP_OVERFLOW, VulnType.STACK_BUFFER_OVERFLOW):
        base_weights[ConfidenceFactor.NO_BOUNDS_CHECK] *= 1.5
        base_weights[ConfidenceFactor.USER_INPUT_DIRECT] *= 1.2
    elif vuln_type in (VulnType.USE_AFTER_FREE, VulnType.DOUBLE_FREE):
        base_weights[ConfidenceFactor.NO_NULL_CHECK] *= 2.0
        base_weights[ConfidenceFactor.CROSS_FUNCTION] *= 1.5
    elif vuln_type == VulnType.CONTROL_FLOW_HIJACK:
        base_weights[ConfidenceFactor.INDIRECT_CALL_TAINTED] *= 2.0
        base_weights[ConfidenceFactor.TAINT_PATH_EXISTS] *= 1.3
    elif vuln_type == VulnType.INTEGER_OVERFLOW:
        base_weights[ConfidenceFactor.ARITHMETIC_OVERFLOW] *= 2.0
    elif vuln_type == VulnType.FORMAT_STRING:
        base_weights[ConfidenceFactor.USER_INPUT_DIRECT] *= 1.5
        base_weights[ConfidenceFactor.DANGEROUS_API_CALL] *= 1.3

    return base_weights


# =============================================================================
# ConfidenceScorer - Confidence Scorer
# =============================================================================

class ConfidenceScorer:
    """
    Vulnerability Confidence Scorer

    Calculates reliability score for each finding based on multi-factor analysis:
    - Taint path completeness
    - Dangerous API call confirmation
    - Missing bounds check
    - AI cross-validation
    """

    def __init__(self, config=None):
        """Initialize the scorer"""
        self.config = config or (default_config if HAVE_CONFIG else None)
        self.weights = CONFIDENCE_WEIGHTS.copy()

    def score_finding(self, finding: Any, factors: Dict[ConfidenceFactor, bool]) -> ConfidenceScore:
        """
        Calculate confidence score for a vulnerability finding

        Args:
            finding: Raw finding (TaintPath, MemoryVulnFinding, etc.)
            factors: Dictionary of whether each factor is satisfied

        Returns:
            ConfidenceScore instance
        """
        vuln_type = self._extract_vuln_type(finding)
        adjusted_weights = get_weights_for_vuln_type(vuln_type)

        total_score = 0.0
        factor_contributions = {}

        for factor, present in factors.items():
            if present and factor in adjusted_weights:
                contribution = adjusted_weights[factor]
                factor_contributions[factor] = contribution
                total_score += contribution

        # Limit to [0, 1] range
        total_score = min(1.0, max(0.0, total_score))

        # Determine level
        level = "Suspicious"
        # Since CONFIDENCE_LEVELS is sorted by value, we need to iterate in reverse to find the highest matching level
        sorted_levels = sorted(CONFIDENCE_LEVELS.items(), key=lambda x: x[1], reverse=True)
        for lvl_name, threshold in sorted_levels:
            if total_score >= threshold:
                level = lvl_name
                break

        explanation = self._generate_explanation(factors, factor_contributions)

        return ConfidenceScore(
            total_score=total_score,
            level=level,
            factors=factors,
            factor_contributions=factor_contributions,
            explanation=explanation
        )

    def _extract_vuln_type(self, finding: Any) -> VulnType:
        """Extract vulnerability type from finding"""
        if hasattr(finding, 'vuln_type'):
            return finding.vuln_type
        if hasattr(finding, 'sink') and hasattr(finding.sink, 'vuln_type'):
            return finding.sink.vuln_type
        return VulnType.BUFFER_OVERFLOW

    def _generate_explanation(self, factors: Dict[ConfidenceFactor, bool],
                               contributions: Dict[ConfidenceFactor, float]) -> str:
        """Generate scoring explanation"""
        parts = []
        for factor, present in factors.items():
            if present:
                contrib = contributions.get(factor, 0)
                parts.append(f"{factor.value}: +{contrib:.2f}")
        return "; ".join(parts) if parts else "No confidence factors"


# =============================================================================
# TaintEngine - Core Taint Analysis Engine (Rizin-based)
# =============================================================================

class TaintEngine:
    """
    Core Taint Analysis Engine - Based on Rizin

    Uses Rizin's disassembly and type recovery capabilities to provide:
    1. Function argument taint marking (assuming arguments come from user input)
    2. Type-aware taint propagation analysis
    3. Dangerous Sink detection
    4. Complete propagation path recording
    5. Cross-function taint analysis
    6. Memory lifecycle tracking (UAF/Double-Free)
    7. Integer overflow detection
    """

    def __init__(self, rz: RizinCore, config=None):
        """
        Initialize the taint analysis engine

        Args:
            rz: RizinCore instance (loaded binary)
            config: LuoDllHackConfig instance (default if None)
        """
        self.rz = rz
        self.config = config or (default_config if HAVE_CONFIG else None)

        # Read analysis parameters from config
        if self.config:
            self.max_depth = self.config.taint_max_depth
            self.cross_function_enabled = self.config.taint_cross_function
            self.track_memory = self.config.taint_track_memory
            self.detect_uaf = self.config.memory_detect_uaf
            self.detect_double_free = self.config.memory_detect_double_free
        else:
            self.max_depth = 1000
            self.cross_function_enabled = True
            self.track_memory = True
            self.detect_uaf = True
            self.detect_double_free = True

        # Architecture info
        self.arch = self._detect_arch()
        self.image_base = rz.info.image_base

        # Build import/export maps
        self.import_map = self._build_import_map()
        self.export_map = self._build_export_map()

        # Set calling conventions based on architecture
        if self.arch == "x64":
            self.arg_regs = ['rcx', 'rdx', 'r8', 'r9']
            self.ret_reg = 'rax'
        elif self.arch == "arm64":
            self.arg_regs = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
            self.ret_reg = 'x0'
        else:  # x86
            self.arg_regs = []  # x86 stdcall/cdecl uses stack parameters
            self.ret_reg = 'eax'

        # Taint state
        self.tainted_regs: Dict[str, TaintSource] = {}
        self.tainted_mem: Dict[int, TaintSource] = {}
        self.taint_paths: List[TaintPath] = []
        self.current_path_steps: List[TaintStep] = []

        # Cross-function analysis state
        self.callgraph: Dict[int, CallGraphNode] = {}
        self.function_summaries: Dict[int, FunctionSummary] = {}
        self.discovered_functions: Set[int] = set()
        self.current_call_chain: List[str] = []
        self.cross_function_paths: List[CrossFunctionPath] = []

        # Memory lifecycle tracking state
        self.pointer_states: Dict[str, PointerInfo] = {}
        self.memory_findings: List[MemoryVulnFinding] = []
        self.freed_pointers: Set[str] = set()

        # Integer overflow tracking state
        self.overflow_risk_regs: Dict[str, IntegerOverflowInfo] = {}
        self.integer_overflow_findings: List[IntegerOverflowFinding] = []

        # Triton context (if available)
        self.ctx = None
        if HAVE_TRITON:
            self._init_triton()

        # Plugin system
        self.plugin_manager = None
        self.plugin_findings: List[Any] = []
        self.extended_sources: Dict[str, Dict] = {}
        self.extended_sinks: Dict[str, Dict] = {}
        if HAVE_PLUGINS:
            self._init_plugins()

    def _detect_arch(self) -> str:
        """Detect binary architecture"""
        arch = self.rz.info.arch
        if arch == Architecture.X64:
            return "x64"
        elif arch == Architecture.X86:
            return "x86"
        elif arch == Architecture.ARM64:
            return "arm64"
        elif arch == Architecture.ARM32:
            return "arm32"
        else:
            logger.warning(f"Unknown architecture {arch}, defaulting to x64")
            return "x64"

    def _build_import_map(self) -> Dict[int, bytes]:
        """Build address → API name map"""
        import_map = {}
        for addr, imp in self.rz.get_imports().items():
            if imp.name:
                import_map[addr] = imp.name.encode('utf-8')
        return import_map

    def _build_export_map(self) -> Dict[int, str]:
        """Build address → export name map"""
        export_map = {}
        for addr, exp in self.rz.get_exports().items():
            if exp.name:
                export_map[addr] = exp.name
        return export_map

    def _init_triton(self):
        """Initialize Triton symbolic execution context"""
        self.ctx = TritonContext()
        if self.arch == "x64":
            self.ctx.setArchitecture(ARCH.X86_64)
        elif self.arch == "arm64":
            self.ctx.setArchitecture(ARCH.AARCH64)
        else:
            self.ctx.setArchitecture(ARCH.X86)
        logger.info("Triton symbolic execution engine initialized")

    def _init_plugins(self):
        """Initialize plugin system"""
        self.plugin_manager = PluginManager()
        loaded = self.plugin_manager.load_plugins()
        if loaded:
            logger.info(f"Loaded {len(loaded)} analysis plugins: {', '.join(loaded)}")

        self.extended_sources = self.plugin_manager.get_taint_sources()
        self.extended_sinks = self.plugin_manager.get_taint_sinks()

    # =========================================================================
    # API Check Methods
    # =========================================================================

    def _is_taint_source(self, api_name: str) -> bool:
        """Check if API is a taint source (built-in + plugin extended)"""
        if isinstance(api_name, bytes):
            api_name_str = api_name.decode('utf-8', errors='ignore')
            api_name_bytes = api_name
        else:
            api_name_str = api_name
            api_name_bytes = api_name.encode('utf-8')

        if api_name_bytes in TAINT_SOURCES:
            return True

        func_name = api_name_str.split("!")[-1] if "!" in api_name_str else api_name_str
        return func_name in self.extended_sources

    def _is_dangerous_sink(self, api_name: str) -> bool:
        """Check if API is a dangerous sink"""
        if isinstance(api_name, bytes):
            api_name_str = api_name.decode('utf-8', errors='ignore')
            api_name_bytes = api_name
        else:
            api_name_str = api_name
            api_name_bytes = api_name.encode('utf-8')

        if api_name_bytes in DANGEROUS_SINKS:
            return True

        func_name = api_name_str.split("!")[-1] if "!" in api_name_str else api_name_str
        return func_name in self.extended_sinks

    def _get_source_info(self, api_name: str) -> Optional[Dict]:
        """Get taint source information"""
        if isinstance(api_name, bytes):
            api_name_str = api_name.decode('utf-8', errors='ignore')
            api_name_bytes = api_name
        else:
            api_name_str = api_name
            api_name_bytes = api_name.encode('utf-8')

        if api_name_bytes in TAINT_SOURCES:
            return TAINT_SOURCES[api_name_bytes]

        func_name = api_name_str.split("!")[-1] if "!" in api_name_str else api_name_str
        return self.extended_sources.get(func_name)

    def _get_sink_info(self, api_name: str) -> Optional[Dict]:
        """Get taint sink information"""
        if isinstance(api_name, bytes):
            api_name_str = api_name.decode('utf-8', errors='ignore')
            api_name_bytes = api_name
        else:
            api_name_str = api_name
            api_name_bytes = api_name.encode('utf-8')

        if api_name_bytes in DANGEROUS_SINKS:
            return DANGEROUS_SINKS[api_name_bytes]

        func_name = api_name_str.split("!")[-1] if "!" in api_name_str else api_name_str
        return self.extended_sinks.get(func_name)

    # =========================================================================
    # Core Analysis Methods
    # =========================================================================

    def analyze_function(self, func_addr: int, func_name: str,
                        max_instructions: int = 0) -> List[TaintPath]:
        """
        Analyze taint propagation in a single function

        Args:
            func_addr: Function start address
            func_name: Function name
            max_instructions: Maximum instructions to analyze (0 uses config default)

        Returns:
            List of discovered taint paths
        """
        if max_instructions <= 0:
            max_instructions = self.max_depth

        # Reset analysis state
        self.tainted_regs.clear()
        self.tainted_mem.clear()
        self.taint_paths = []
        self.current_path_steps = []
        self.pointer_states.clear()
        self.overflow_risk_regs.clear()
        self.current_call_chain = [func_name]

        # Mark all argument registers as tainted
        for idx, reg in enumerate(self.arg_regs):
            source = TaintSource(
                type=SourceType.ARGUMENT,
                addr=func_addr,
                api_name=func_name,
                tainted_location=f'reg:{reg}'
            )
            self.tainted_regs[reg] = source

            self.current_path_steps.append(TaintStep(
                addr=func_addr,
                instruction=f"entry: {func_name}",
                effect='init',
                from_loc='user_input',
                to_loc=f'reg:{reg}'
            ))

            if self.ctx and HAVE_TRITON:
                triton_reg = getattr(self.ctx.registers, reg, None)
                if triton_reg:
                    self.ctx.taintRegister(triton_reg)

        # Analyze function with Rizin
        func = self.rz.analyze_function(func_addr)
        if not func:
            logger.warning(f"Could not analyze function {func_name} @ 0x{func_addr:x}")
            return self.taint_paths

        # Iterate through all basic blocks
        analyzed_count = 0
        for bb in func.blocks:
            if analyzed_count >= max_instructions:
                break

            for insn in bb.instructions:
                if analyzed_count >= max_instructions:
                    break

                # Track taint propagation
                self._track_taint(insn)

                # Check if call instruction
                if insn.type == InstructionType.CALL:
                    self._handle_call(insn, func_name)

                # Check if ret instruction
                if insn.type == InstructionType.RET:
                    break

                analyzed_count += 1

        return self.taint_paths

    def _track_taint(self, insn: Instruction):
        """
        Track taint propagation for an instruction

        Supported propagation patterns:
        1. reg -> reg: mov rax, rbx
        2. reg -> mem: mov [rcx], rax
        3. mem -> reg: mov rax, [rcx]
        4. lea instruction: lea rax, [rbx+8]
        """
        mnemonic = insn.mnemonic.lower()

        # Handle MOV instructions
        if mnemonic == 'mov' and len(insn.operands) >= 2:
            self._track_mov_taint(insn)

        # Handle LEA instructions
        elif mnemonic == 'lea' and len(insn.operands) >= 2:
            self._track_lea_taint(insn)

        # Handle PUSH/POP
        elif mnemonic == 'push':
            self._track_push_taint(insn)
        elif mnemonic == 'pop':
            self._track_pop_taint(insn)

        # Track arithmetic overflow risk
        self._track_arithmetic_overflow(insn)

    def _track_mov_taint(self, insn: Instruction):
        """Track taint propagation for MOV instruction"""
        if len(insn.operands) < 2:
            return

        dst = insn.operands[0]
        src = insn.operands[1]

        # reg -> reg propagation
        if src.type == 'reg' and dst.type == 'reg':
            src_name = src.reg.lower() if src.reg else None
            dst_name = dst.reg.lower() if dst.reg else None

            if src_name and dst_name and src_name in self.tainted_regs:
                self.tainted_regs[dst_name] = self.tainted_regs[src_name]

                self.current_path_steps.append(TaintStep(
                    addr=insn.address,
                    instruction=insn.disasm,
                    effect='copy',
                    from_loc=f'reg:{src_name}',
                    to_loc=f'reg:{dst_name}'
                ))

                # Propagate overflow risk
                if src_name in self.overflow_risk_regs:
                    self.overflow_risk_regs[dst_name] = self.overflow_risk_regs[src_name]

        # reg -> mem propagation (out-argument taint)
        elif src.type == 'reg' and dst.type == 'mem':
            src_name = src.reg.lower() if src.reg else None
            if src_name and src_name in self.tainted_regs:
                mem_addr = self._calculate_mem_address(dst)
                if mem_addr is not None:
                    self.tainted_mem[mem_addr] = self.tainted_regs[src_name]

                    self.current_path_steps.append(TaintStep(
                        addr=insn.address,
                        instruction=insn.disasm,
                        effect='store',
                        from_loc=f'reg:{src_name}',
                        to_loc=f'mem:0x{mem_addr:x}'
                    ))

        # mem -> reg propagation
        elif src.type == 'mem' and dst.type == 'reg':
            mem_addr = self._calculate_mem_address(src)
            dst_name = dst.reg.lower() if dst.reg else None
            if mem_addr is not None and mem_addr in self.tainted_mem and dst_name:
                self.tainted_regs[dst_name] = self.tainted_mem[mem_addr]

                self.current_path_steps.append(TaintStep(
                    addr=insn.address,
                    instruction=insn.disasm,
                    effect='load',
                    from_loc=f'mem:0x{mem_addr:x}',
                    to_loc=f'reg:{dst_name}'
                ))

    def _track_lea_taint(self, insn: Instruction):
        """Track taint propagation for LEA instruction"""
        if len(insn.operands) < 2:
            return

        dst = insn.operands[0]
        src = insn.operands[1]

        if dst.type != 'reg' or src.type != 'mem':
            return

        dst_name = dst.reg.lower() if dst.reg else None
        if not dst_name:
            return

        # Check if registers in source operand are tainted
        is_tainted = False
        source = None

        # Parse registers in memory operand
        mem_str = insn.operands_str
        for reg in self.tainted_regs.keys():
            if reg in mem_str.lower():
                is_tainted = True
                source = self.tainted_regs[reg]
                break

        if is_tainted and source:
            self.tainted_regs[dst_name] = source
            self.current_path_steps.append(TaintStep(
                addr=insn.address,
                instruction=insn.disasm,
                effect='addr_calc',
                from_loc='tainted_base',
                to_loc=f'reg:{dst_name}'
            ))

    def _track_push_taint(self, insn: Instruction):
        """Track taint propagation for PUSH instruction"""
        if not insn.operands:
            return

        op = insn.operands[0]
        if op.type == 'reg' and op.reg:
            reg_name = op.reg.lower()
            if reg_name in self.tainted_regs:
                # Use instruction address as symbolic stack location identifier
                stack_loc = hash(f"stack_{insn.address}") & 0x7FFFFFFFFFFFFFFF
                self.tainted_mem[stack_loc] = self.tainted_regs[reg_name]

    def _track_pop_taint(self, insn: Instruction):
        """Track taint propagation for POP instruction"""
        # Accurate POP tracking requires stack pointer tracking; simplified here
        pass

    def _track_arithmetic_overflow(self, insn: Instruction):
        """Track integer overflow risk for arithmetic operations"""
        mnemonic = insn.mnemonic.lower()

        # Check if high-risk arithmetic instruction
        if mnemonic not in OVERFLOW_RISK_INSTRUCTIONS:
            return

        op_type = OVERFLOW_RISK_INSTRUCTIONS[mnemonic]

        # Check if operands are tainted
        is_tainted = False
        source = None

        for op in insn.operands:
            if op.type == 'reg' and op.reg:
                reg_name = op.reg.lower()
                if reg_name in self.tainted_regs:
                    is_tainted = True
                    source = self.tainted_regs[reg_name]
                    break

        if is_tainted and source:
            # Determine result register
            result_reg = None
            if insn.operands and insn.operands[0].type == 'reg':
                result_reg = insn.operands[0].reg.lower() if insn.operands[0].reg else None

            if result_reg:
                overflow_info = IntegerOverflowInfo(
                    operation=op_type,
                    addr=insn.address,
                    instruction=insn.disasm,
                    operand1_tainted=True,
                    result_reg=result_reg,
                    risk_level=OVERFLOW_RISK_LEVELS.get(op_type, "Medium"),
                    source=source
                )
                self.overflow_risk_regs[result_reg] = overflow_info

    def _calculate_mem_address(self, operand) -> Optional[int]:
        """Calculate address for memory operand"""
        if operand.type != 'mem':
            return None

        # Use operand value as symbolic address
        if hasattr(operand, 'value') and operand.value:
            return operand.value

        # Use hash as symbolic address
        if hasattr(operand, 'reg') and operand.reg:
            return hash(operand.reg) & 0x7FFFFFFFFFFFFFFF

        return None

    def _handle_call(self, insn: Instruction, current_func: str):
        """Handle CALL instruction"""
        # Get call target
        target = self._get_call_target(insn)
        if not target:
            # Check for indirect call taint
            self._check_indirect_call_taint(insn)
            return

        # Check if import function
        if target in self.import_map:
            api_name = self.import_map[target]
            self._handle_import_call(insn, api_name)
        elif target in self.discovered_functions or self._is_valid_code_addr(target):
            # Internal function call
            self._handle_internal_call(insn, target, current_func)

    def _get_call_target(self, insn: Instruction) -> Optional[int]:
        """Get target address for CALL instruction"""
        if not insn.operands:
            return None

        op = insn.operands[0]

        # Direct call: call 0x12345678
        if op.type == 'imm' and hasattr(op, 'value'):
            return op.value

        # Indirect call (RIP-relative etc.)
        if op.type == 'mem' and hasattr(op, 'value'):
            # For x64 RIP-relative calls
            return op.value

        return None

    def _handle_import_call(self, insn: Instruction, api_name: bytes):
        """Handle import function call"""
        api_str = api_name.decode('utf-8', errors='ignore')

        # Check if taint source
        if self._is_taint_source(api_name):
            source_info = self._get_source_info(api_name)
            if source_info:
                self._apply_taint_source(insn, api_str, source_info)

        # Check if dangerous sink
        if self._is_dangerous_sink(api_name):
            sink_info = self._get_sink_info(api_name)
            if sink_info:
                self._check_sink(insn, api_str, sink_info)

        # Check if allocation/deallocation API
        if api_name in ALLOC_APIS:
            self._handle_alloc(insn, api_str, ALLOC_APIS[api_name])
        elif api_name in FREE_APIS:
            self._handle_free(insn, api_str, FREE_APIS[api_name])

    def _apply_taint_source(self, insn: Instruction, api_name: str, source_info: Dict):
        """Apply taint source"""
        source = TaintSource(
            type=source_info.get('type', SourceType.UNKNOWN),
            addr=insn.address,
            api_name=api_name,
            tainted_location=f'ret:{self.ret_reg}'
        )

        # Taint return value
        if source_info.get('tainted_ret'):
            self.tainted_regs[self.ret_reg] = source

        # Taint specified arguments
        for arg_idx in source_info.get('tainted_args', []):
            if arg_idx < len(self.arg_regs):
                reg = self.arg_regs[arg_idx]
                self.tainted_regs[reg] = source

        self.current_path_steps.append(TaintStep(
            addr=insn.address,
            instruction=insn.disasm,
            effect='source',
            from_loc=api_name,
            to_loc=f'reg:{self.ret_reg}'
        ))

    def _check_sink(self, insn: Instruction, api_name: str, sink_info: Dict):
        """Check dangerous sink"""
        for check_idx in sink_info.get('check_args', []):
            if check_idx < len(self.arg_regs):
                reg = self.arg_regs[check_idx]
                if reg in self.tainted_regs:
                    # Taint reached sink
                    source = self.tainted_regs[reg]
                    sink = TaintSink(
                        vuln_type=sink_info['vuln'],
                        severity=sink_info['severity'],
                        addr=insn.address,
                        api_name=api_name,
                        tainted_arg_idx=check_idx
                    )

                    path = TaintPath(
                        source=source,
                        sink=sink,
                        steps=self.current_path_steps.copy(),
                        confidence=0.8
                    )
                    self.taint_paths.append(path)

                    logger.info(f"Discovered taint path: {source.api_name} -> {api_name} @ 0x{insn.address:x}")

    def _handle_alloc(self, insn: Instruction, api_name: str, alloc_info: Dict):
        """Handle memory allocation"""
        # Mark returned pointer
        if alloc_info.get('ret_ptr'):
            # Check if allocation size comes from overflow operation
            size_arg = alloc_info.get('size_arg')
            size_tainted = False

            if isinstance(size_arg, int) and size_arg < len(self.arg_regs):
                reg = self.arg_regs[size_arg]
                if reg in self.overflow_risk_regs:
                    size_tainted = True
                    overflow_info = self.overflow_risk_regs[reg]

                    # Record integer overflow → heap overflow vulnerability
                    finding = IntegerOverflowFinding(
                        overflow_addr=overflow_info.addr,
                        overflow_op=overflow_info.operation.name,
                        overflow_instruction=overflow_info.instruction,
                        alloc_addr=insn.address,
                        alloc_api=api_name,
                        size_reg=reg,
                        func_name=self.current_call_chain[-1] if self.current_call_chain else "",
                        call_chain=self.current_call_chain.copy(),
                        risk_level=overflow_info.risk_level
                    )
                    self.integer_overflow_findings.append(finding)

            ptr_info = PointerInfo(
                state=PointerState.ALLOCATED,
                alloc_addr=insn.address,
                alloc_api=api_name,
                size_tainted=size_tainted,
                source_reg=self.ret_reg
            )
            self.pointer_states[self.ret_reg] = ptr_info

    def _handle_free(self, insn: Instruction, api_name: str, free_info: Dict):
        """Handle memory deallocation"""
        ptr_arg = free_info.get('ptr_arg', 0)
        if ptr_arg < len(self.arg_regs):
            reg = self.arg_regs[ptr_arg]

            # Check for Double-Free
            if reg in self.pointer_states:
                ptr_info = self.pointer_states[reg]
                if ptr_info.state == PointerState.FREED:
                    # Double-Free vulnerability
                    finding = MemoryVulnFinding(
                        vuln_type=VulnType.DOUBLE_FREE,
                        severity="Critical",
                        alloc_addr=ptr_info.alloc_addr,
                        alloc_api=ptr_info.alloc_api,
                        free_addr=ptr_info.free_addr or 0,
                        free_api=ptr_info.free_api or "",
                        vuln_addr=insn.address,
                        vuln_action=f"second free at {api_name}",
                        pointer_reg=reg,
                        call_chain=self.current_call_chain.copy(),
                        cwe_id="CWE-415"
                    )
                    self.memory_findings.append(finding)
                else:
                    # Mark as freed
                    ptr_info.state = PointerState.FREED
                    ptr_info.free_addr = insn.address
                    ptr_info.free_api = api_name
                    self.freed_pointers.add(reg)

    def _handle_internal_call(self, insn: Instruction, target: int, current_func: str):
        """Handle internal function call"""
        if not self.cross_function_enabled:
            return

        # Record tainted arguments at call time
        tainted_args = set()
        for idx, reg in enumerate(self.arg_regs):
            if reg in self.tainted_regs:
                tainted_args.add(idx)

        if tainted_args:
            call = InternalCall(
                call_addr=insn.address,
                target_addr=target,
                tainted_args=tainted_args
            )

            # Update function summary
            if target in self.function_summaries:
                summary = self.function_summaries[target]
                summary.internal_calls.append(call)

    def _check_indirect_call_taint(self, insn: Instruction):
        """Detect tainted data in indirect calls"""
        if not insn.operands:
            return

        op = insn.operands[0]

        # Register call: call rax
        if op.type == 'reg' and op.reg:
            reg_name = op.reg.lower()
            if reg_name in self.tainted_regs:
                # Control flow hijack vulnerability
                source = self.tainted_regs[reg_name]
                sink = TaintSink(
                    vuln_type=VulnType.CONTROL_FLOW_HIJACK,
                    severity="Critical",
                    addr=insn.address,
                    api_name=f"indirect_call_{reg_name}",
                    tainted_arg_idx=-1
                )

                path = TaintPath(
                    source=source,
                    sink=sink,
                    steps=self.current_path_steps.copy(),
                    confidence=0.95
                )
                self.taint_paths.append(path)

                logger.warning(f"Control flow hijack discovered: {reg_name} tainted @ 0x{insn.address:x}")

    def _is_valid_code_addr(self, addr: int) -> bool:
        """Check if address is within a code section"""
        # Check using Rizin
        for section in self.rz.get_sections():
            if section.paddr <= addr < section.paddr + section.size:
                if 'x' in section.perm:  # Executable
                    return True
        return False

    # =========================================================================
    # Register Alias Handling
    # =========================================================================

    def _get_register_aliases(self, reg_name: str) -> Set[str]:
        """Get all aliases for a register"""
        reg_name = reg_name.lower()

        # x64 register alias mapping
        x64_aliases = {
            'rax': {'rax', 'eax', 'ax', 'al', 'ah'},
            'rbx': {'rbx', 'ebx', 'bx', 'bl', 'bh'},
            'rcx': {'rcx', 'ecx', 'cx', 'cl', 'ch'},
            'rdx': {'rdx', 'edx', 'dx', 'dl', 'dh'},
            'rsi': {'rsi', 'esi', 'si', 'sil'},
            'rdi': {'rdi', 'edi', 'di', 'dil'},
            'rsp': {'rsp', 'esp', 'sp', 'spl'},
            'rbp': {'rbp', 'ebp', 'bp', 'bpl'},
            'r8': {'r8', 'r8d', 'r8w', 'r8b'},
            'r9': {'r9', 'r9d', 'r9w', 'r9b'},
            'r10': {'r10', 'r10d', 'r10w', 'r10b'},
            'r11': {'r11', 'r11d', 'r11w', 'r11b'},
            'r12': {'r12', 'r12d', 'r12w', 'r12b'},
            'r13': {'r13', 'r13d', 'r13w', 'r13b'},
            'r14': {'r14', 'r14d', 'r14w', 'r14b'},
            'r15': {'r15', 'r15d', 'r15w', 'r15b'},
        }

        for full_reg, aliases in x64_aliases.items():
            if reg_name in aliases:
                return aliases

        return {reg_name}

    # =========================================================================
    # Call Graph Construction
    # =========================================================================

    def build_callgraph(self, entry_points: Dict[str, int],
                       max_depth: int = 20) -> Dict[int, CallGraphNode]:
        """
        Build call graph

        Args:
            entry_points: Export functions {name: addr}
            max_depth: Maximum recursion depth

        Returns:
            Call graph {addr: CallGraphNode}
        """
        logger.info("Building call graph...")
        self.callgraph.clear()
        self.discovered_functions.clear()

        # Initialize export function nodes
        for name, addr in entry_points.items():
            node = CallGraphNode(addr=addr, name=name, is_export=True)
            self.callgraph[addr] = node
            self.discovered_functions.add(addr)

        # Initialize import function nodes
        for addr, name in self.import_map.items():
            node = CallGraphNode(
                addr=addr,
                name=name.decode() if isinstance(name, bytes) else name,
                is_import=True
            )
            self.callgraph[addr] = node

        # BFS traversal to discover internal functions
        to_analyze = list(entry_points.values())
        analyzed = set()
        depth = 0

        while to_analyze and depth < max_depth:
            next_batch = []
            for func_addr in to_analyze:
                if func_addr in analyzed:
                    continue
                analyzed.add(func_addr)

                # Scan function for call instructions
                callees = self._scan_function_calls(func_addr)

                if func_addr in self.callgraph:
                    self.callgraph[func_addr].callees = callees

                for callee in callees:
                    if callee in self.callgraph:
                        self.callgraph[callee].callers.add(func_addr)
                    else:
                        if callee not in self.import_map and self._is_valid_code_addr(callee):
                            node = CallGraphNode(
                                addr=callee,
                                name=f"sub_{callee:x}"
                            )
                            node.callers.add(func_addr)
                            self.callgraph[callee] = node
                            self.discovered_functions.add(callee)
                            next_batch.append(callee)

            to_analyze = next_batch
            depth += 1

        internal_count = len([n for n in self.callgraph.values()
                             if not n.is_export and not n.is_import])
        logger.info(f"Discovered {internal_count} internal functions, total call graph nodes: {len(self.callgraph)}")

        return self.callgraph

    def _scan_function_calls(self, func_addr: int,
                            max_instructions: int = 2000) -> Set[int]:
        """Scan function for all call instructions"""
        callees = set()

        func = self.rz.analyze_function(func_addr)
        if not func:
            return callees

        count = 0
        for bb in func.blocks:
            if count >= max_instructions:
                break
            for insn in bb.instructions:
                if count >= max_instructions:
                    break
                if insn.type == InstructionType.CALL:
                    target = self._get_call_target(insn)
                    if target:
                        callees.add(target)
                if insn.type == InstructionType.RET:
                    break
                count += 1

        return callees

    # =========================================================================
    # Cross-Function Analysis
    # =========================================================================

    def analyze_cross_function(self, exports: Dict[str, int],
                               max_depth: int = 5) -> List[CrossFunctionPath]:
        """
        Cross-function taint analysis

        Starting from export functions, tracks taint propagation through function call chains.

        Args:
            exports: Export functions {name: addr}
            max_depth: Maximum call depth

        Returns:
            List of cross-function taint paths
        """
        if not self.cross_function_enabled:
            logger.info("Cross-function analysis disabled")
            return []

        logger.info("Starting cross-function taint analysis...")
        self.cross_function_paths.clear()

        # Build call graph
        self.build_callgraph(exports, max_depth=max_depth + 5)

        # Generate summaries for each export function
        for name, addr in exports.items():
            logger.debug(f"Analyzing function summary: {name}")
            self.analyze_function_summary(addr, name)

        # Trace cross-function paths
        for name, addr in exports.items():
            self._trace_cross_function_paths(addr, name, [], max_depth)

        logger.info(f"Discovered {len(self.cross_function_paths)} cross-function taint paths")
        return self.cross_function_paths

    def analyze_function_summary(self, func_addr: int,
                                func_name: str) -> FunctionSummary:
        """Generate taint summary for a function"""
        summary = FunctionSummary(func_addr=func_addr, func_name=func_name)

        # Analyze taint propagation for each argument
        for arg_idx in range(len(self.arg_regs)):
            self.tainted_regs.clear()
            self.tainted_mem.clear()
            self.current_path_steps = []

            # Mark single argument as tainted
            source = TaintSource(
                type=SourceType.ARGUMENT,
                addr=func_addr,
                api_name=func_name,
                tainted_location=f'reg:{self.arg_regs[arg_idx]}'
            )
            self.tainted_regs[self.arg_regs[arg_idx]] = source

            # Analyze and collect results
            sinks_reached, affects_return, calls = self._analyze_single_arg_flow(
                func_addr, func_name, arg_idx
            )

            if sinks_reached:
                summary.tainted_args_to_sink[arg_idx] = sinks_reached
                summary.internal_sinks.extend(sinks_reached)

            if affects_return:
                summary.args_affect_return.add(arg_idx)

            for call in calls:
                summary.called_functions.add(call.target_addr)
                existing = [c for c in summary.internal_calls
                           if c.call_addr == call.call_addr]
                if existing:
                    existing[0].tainted_args.update(call.tainted_args)
                else:
                    summary.internal_calls.append(call)

        summary.analyzed = True
        self.function_summaries[func_addr] = summary

        return summary

    def _analyze_single_arg_flow(self, func_addr: int, func_name: str,
                                arg_idx: int) -> Tuple[List[TaintSink], bool, List[InternalCall]]:
        """Analyze flow for a single argument"""
        sinks_reached = []
        affects_return = False
        internal_calls = []

        func = self.rz.analyze_function(func_addr)
        if not func:
            return sinks_reached, affects_return, internal_calls

        for bb in func.blocks:
            for insn in bb.instructions:
                # Taint propagation
                self._track_taint(insn)

                # Check call
                if insn.type == InstructionType.CALL:
                    target = self._get_call_target(insn)
                    if target and target in self.import_map:
                        api_name = self.import_map[target]
                        if api_name in DANGEROUS_SINKS:
                            sink_info = DANGEROUS_SINKS[api_name]
                            for check_idx in sink_info['check_args']:
                                if check_idx < len(self.arg_regs):
                                    reg = self.arg_regs[check_idx]
                                    if reg in self.tainted_regs:
                                        sink = TaintSink(
                                            vuln_type=sink_info['vuln'],
                                            severity=sink_info['severity'],
                                            addr=insn.address,
                                            api_name=api_name.decode(),
                                            tainted_arg_idx=check_idx
                                        )
                                        sinks_reached.append(sink)
                    elif target and self._is_valid_code_addr(target):
                        tainted_args = set()
                        for idx, reg in enumerate(self.arg_regs):
                            if reg in self.tainted_regs:
                                tainted_args.add(idx)
                        if tainted_args:
                            internal_calls.append(InternalCall(
                                call_addr=insn.address,
                                target_addr=target,
                                tainted_args=tainted_args
                            ))

                # Check return
                if insn.type == InstructionType.RET:
                    if self.ret_reg in self.tainted_regs:
                        affects_return = True
                    break

        return sinks_reached, affects_return, internal_calls

    def _trace_cross_function_paths(self, entry_addr: int, entry_name: str,
                                   call_chain: List[str], max_depth: int):
        """Recursively trace cross-function paths"""
        if len(call_chain) >= max_depth:
            return

        call_chain = call_chain + [entry_name]

        if entry_addr not in self.function_summaries:
            return

        summary = self.function_summaries[entry_addr]

        # Check for sinks
        for arg_idx, sinks in summary.tainted_args_to_sink.items():
            for sink in sinks:
                source = TaintSource(
                    type=SourceType.ARGUMENT,
                    addr=entry_addr,
                    api_name=entry_name,
                    tainted_location=f'arg{arg_idx}'
                )
                path = CrossFunctionPath(
                    entry_func=call_chain[0],
                    call_chain=call_chain,
                    source=source,
                    sink=sink,
                    confidence=0.7
                )
                self.cross_function_paths.append(path)

        # Recursively analyze called functions
        for call in summary.internal_calls:
            if call.target_addr in self.callgraph:
                callee = self.callgraph[call.target_addr]
                if not callee.is_import:
                    self._trace_cross_function_paths(
                        call.target_addr, callee.name, call_chain, max_depth
                    )

    # =========================================================================
    # Results Retrieval
    # =========================================================================

    def get_findings(self) -> Dict[str, Any]:
        """Retrieve all analysis results"""
        return {
            'taint_paths': self.taint_paths,
            'memory_findings': self.memory_findings,
            'integer_overflow_findings': self.integer_overflow_findings,
            'cross_function_paths': self.cross_function_paths,
            'plugin_findings': self.plugin_findings,
            'statistics': {
                'total_taint_paths': len(self.taint_paths),
                'total_memory_vulns': len(self.memory_findings),
                'total_overflow_vulns': len(self.integer_overflow_findings),
                'total_cross_function': len(self.cross_function_paths),
                'high_confidence_findings': sum(
                    1 for p in self.taint_paths
                    if p.confidence >= 0.7
                ) + sum(
                    1 for f in self.memory_findings
                    if f.severity in ["Critical", "High"]
                )
            }
        }

    def reset(self):
        """Reset analysis state"""
        self.tainted_regs.clear()
        self.tainted_mem.clear()
        self.taint_paths.clear()
        self.current_path_steps.clear()
        self.pointer_states.clear()
        self.memory_findings.clear()
        self.freed_pointers.clear()
        self.overflow_risk_regs.clear()
        self.integer_overflow_findings.clear()
        self.current_call_chain.clear()
        self.cross_function_paths.clear()
        self.plugin_findings.clear()


# =============================================================================
# Symbolic Execution Engine (Imported from symbolic module)
# =============================================================================

try:
    from luodllhack.symbolic.executor import EnhancedSymbolicExecutor as SymbolicEngine
except ImportError:
    # Placeholder if symbolic module unavailable
    class SymbolicEngine:
        """Symbolic execution engine placeholder (requires angr)"""
        def __init__(self, binary_path: Path):
            self.binary_path = binary_path
            logger.debug("Symbolic execution not available (angr not installed)")

        def solve_trigger_input(self, taint_path: TaintPath) -> Optional[bytes]:
            return None


# =============================================================================
# Fuzzing Module (Uses enhanced.harness)
# =============================================================================

try:
    from luodllhack.analysis.enhanced.harness import HarnessGenerator as _HarnessGen
    _HAVE_HARNESS = True
except ImportError:
    _HAVE_HARNESS = False


class FuzzingModule:
    """
    Fuzzing Module - Wraps HarnessGenerator to provide simplified interface
    """

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.dll_name = binary_path.stem
        self._harness_gen = _HarnessGen() if _HAVE_HARNESS else None

    def generate_harness(self, taint_path: TaintPath, func_name: str) -> str:
        """Generate Harness code"""
        if self._harness_gen:
            try:
                from luodllhack.analysis.enhanced.harness import (
                    HarnessConfig, FunctionSignature, HarnessType
                )
                sig = FunctionSignature(
                    name=func_name,
                    address=taint_path.sink.addr,
                    params=[{'name': 'input', 'type': 'char*', 'tainted': True}]
                )
                config = HarnessConfig(
                    dll_path=str(self.binary_path),
                    function=sig,
                    harness_type=HarnessType.FUZZING
                )
                result = self._harness_gen.generate(config)
                return result.code
            except Exception as e:
                logger.debug(f"HarnessGenerator failed: {e}")

        # Fallback to simple template
        vuln_type = taint_path.sink.vuln_type
        return self._simple_harness(func_name, vuln_type)

    def _simple_harness(self, func_name: str, vuln_type: VulnType) -> str:
        """Simple Harness template"""
        return f'''// LuoDllHack Harness - {func_name}
// Vuln: {vuln_type.name}
#include <windows.h>
#include <stdio.h>
int main(int argc, char** argv) {{
    HMODULE dll = LoadLibraryA("{self.dll_name}.dll");
    void* func = GetProcAddress(dll, "{func_name}");
    if (argc > 1) ((void(*)(char*))func)(argv[1]);
    return 0;
}}
'''

    def generate_seed(self, taint_path: TaintPath, func_name: str) -> bytes:
        """Generate Fuzzing seed"""
        vuln_type = taint_path.sink.vuln_type
        seeds = {
            VulnType.BUFFER_OVERFLOW: b'A' * 1024,
            VulnType.FORMAT_STRING: b'%x' * 20 + b'%n',
            VulnType.COMMAND_INJECTION: b'test & calc.exe',
            VulnType.PATH_TRAVERSAL: b'..\\..\\..\\windows\\system32\\config\\sam',
            VulnType.INTEGER_OVERFLOW: b'\xff' * 8,
        }
        return seeds.get(vuln_type, b'AAAA' * 64) + b'\x00'
