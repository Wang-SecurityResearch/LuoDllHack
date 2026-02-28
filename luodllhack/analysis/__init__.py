# -*- coding: utf-8 -*-
"""
luodllhack/analysis - LuoDllHack v6.0 Vulnerability Analysis Module

Vulnerability analysis capabilities based on Rizin:
    - RizinTaintEngine: Type-aware taint analysis
    - Neuro-symbolic Reasoning: 0day discovery
    - Pattern Learning: Vulnerability pattern recognition
    - Enhanced Analysis: False positive elimination

Author: LuoDllHack Team
Version: 6.0.0
"""

# =============================================================================
# Import basic types from core
# =============================================================================

from luodllhack.core import (
    # Rizin Core
    RizinCore,
    # Data Structures
    Function,
    BasicBlock,
    Instruction,
    # Vulnerability Types
    VulnType,
    SourceType,
    PointerState,
    TaintSource,
    TaintSink,
    TaintStep,
    TaintPath,
    VulnFinding,
    # Cross-function Analysis
    InternalCall,
    FunctionSummary,
    CallGraphNode,
    CrossFunctionPath,
    # Memory Analysis
    PointerInfo,
    MemoryVulnFinding,
    CrossFunctionUAF,
    PointerParamState,
    # Integer Overflow
    ArithmeticOp,
    IntegerOverflowInfo,
    IntegerOverflowFinding,
    # Confidence
    ConfidenceFactor,
    ConfidenceScore,
    ScoredFinding,
    # API Constants
    DANGEROUS_SINKS,
    TAINT_SOURCES,
    ALLOC_APIS,
    FREE_APIS,
    POINTER_USE_APIS,
    OVERFLOW_RISK_INSTRUCTIONS,
)

# =============================================================================
# Taint Analysis Engine
# =============================================================================

from .taint import (
    TaintEngine,
    ConfidenceScorer,
    CONFIDENCE_WEIGHTS,
    CONFIDENCE_LEVELS,
    OVERFLOW_RISK_LEVELS,
)

# =============================================================================
# Vulnerability Analyzer
# =============================================================================

from .vuln_analyzer import VulnAnalyzer

# =============================================================================
# Memory Lifecycle Analysis
# =============================================================================

try:
    from ..memory.lifecycle import LifecycleAnalyzer, PointerLifecycle
    from ..memory.tracker import EnhancedMemoryTracker, MemoryLocation
    from ..memory.alias import AliasAnalyzer
    HAVE_MEMORY_ANALYSIS = True
except ImportError:
    HAVE_MEMORY_ANALYSIS = False
    LifecycleAnalyzer = None
    EnhancedMemoryTracker = None
    AliasAnalyzer = None

# =============================================================================
# Symbolic Execution
# =============================================================================

try:
    from ..symbolic.executor import EnhancedSymbolicExecutor
    from ..symbolic.solver import ExploitSolver
    HAVE_SYMBOLIC = True
except ImportError:
    HAVE_SYMBOLIC = False
    EnhancedSymbolicExecutor = None
    ExploitSolver = None

# =============================================================================
# Enhanced Analysis Modules
# =============================================================================

try:
    from .enhanced import (
        EnhancedAnalyzer,
        SinkAnalysisResult,
        FunctionAnalysisResult,
        BoundsChecker,
        SanitizerDetector,
        EnhancedConfidenceScorer,
        ConfidenceFactors,
        IndirectCallTracker,
        CallbackAnalyzer,
        StructFieldTracker,
        ConstraintCollector,
        HarnessGenerator,
        HarnessConfig,
    )
    HAVE_ENHANCED = True
except ImportError:
    HAVE_ENHANCED = False
    EnhancedAnalyzer = None

# =============================================================================
# Neuro-symbolic Reasoning (0day Discovery)
# =============================================================================

try:
    from .neuro_symbolic import (
        ZeroDayDiscoveryEngine,
        VulnerabilityPattern,
        PatternLearningEngine,
        InstructionEmbedding,
    )
    HAVE_NEURO_SYMBOLIC = True
except ImportError:
    HAVE_NEURO_SYMBOLIC = False
    ZeroDayDiscoveryEngine = None
    PatternLearningEngine = None

# =============================================================================
# Pattern Learning
# =============================================================================

try:
    from .pattern_learning import (
        AdvancedVulnerabilityMiner,
        ZeroShotVulnerabilityDetector,
        CodePattern,
        AssemblyEmbedder,
        PatternExtractor,
    )
    HAVE_PATTERN_LEARNING = True
except ImportError:
    HAVE_PATTERN_LEARNING = False
    AdvancedVulnerabilityMiner = None
    ZeroShotVulnerabilityDetector = None

# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Rizin Core
    'RizinCore',
    # Data Structures
    'Function',
    'BasicBlock',
    'Instruction',
    # Vulnerability Types
    'VulnType',
    'SourceType',
    'PointerState',
    'TaintSource',
    'TaintSink',
    'TaintStep',
    'TaintPath',
    'VulnFinding',
    # Cross-function Analysis
    'InternalCall',
    'FunctionSummary',
    'CallGraphNode',
    'CrossFunctionPath',
    # Memory Analysis
    'PointerInfo',
    'MemoryVulnFinding',
    'CrossFunctionUAF',
    'PointerParamState',
    # Integer Overflow
    'ArithmeticOp',
    'IntegerOverflowInfo',
    'IntegerOverflowFinding',
    # Confidence
    'ConfidenceFactor',
    'ConfidenceScore',
    'ScoredFinding',
    'ConfidenceScorer',
    # Constants
    'DANGEROUS_SINKS',
    'TAINT_SOURCES',
    'ALLOC_APIS',
    'FREE_APIS',
    'POINTER_USE_APIS',
    'OVERFLOW_RISK_INSTRUCTIONS',
    'CONFIDENCE_WEIGHTS',
    'CONFIDENCE_LEVELS',
    'OVERFLOW_RISK_LEVELS',
    # Taint Engine
    'TaintEngine',
    # Vulnerability Analyzer
    'VulnAnalyzer',
    # Availability Flags
    'HAVE_MEMORY_ANALYSIS',
    'HAVE_SYMBOLIC',
    'HAVE_ENHANCED',
    'HAVE_NEURO_SYMBOLIC',
    'HAVE_PATTERN_LEARNING',
]
