# -*- coding: utf-8 -*-
"""
luodllhack/core - LuoDllHack v6.0 核心模块

基于 Rizin 的统一分析引擎，提供:
    - 二进制加载与解析
    - 反汇编与 CFG 构建
    - 反编译 (Ghidra)
    - 类型恢复
    - 虚表分析
    - 调试支持
    - ROP Gadget 搜索

作者: LuoDllHack Team
版本: 6.0.0
"""

# =============================================================================
# Rizin 核心引擎
# =============================================================================

from .rizin_core import (
    # 核心类
    RizinCore,
    # 便捷函数
    load_binary,
    check_rizin_available,
    # 可用性标志
    HAVE_RIZIN,
    # 异常
    RizinError,
    RizinNotFoundError,
    BinaryLoadError,
    AnalysisError,
)

# =============================================================================
# Rizin 数据结构
# =============================================================================

from .rizin_types import (
    # 架构
    Architecture,
    Endianness,
    BinaryType,
    BinaryInfo,
    # 指令
    Instruction,
    InstructionType,
    Operand,
    # CFG
    BasicBlock,
    EdgeType,
    Function,
    Variable,
    # 符号
    Import,
    Export,
    Symbol,
    Section,
    StringRef,
    # 高级分析
    VTable,
    VTableEntry,
    XRef,
    XRefType,
    # 调试
    RegisterState,
    Breakpoint,
    RopGadget,
)

# =============================================================================
# 漏洞分析类型
# =============================================================================

from .types import (
    # 漏洞类型枚举
    VulnType,
    SourceType,
    PointerState,
    ArithmeticOp,
    ConfidenceFactor,
    # 污点分析结构
    TaintSource,
    TaintSink,
    TaintStep,
    TaintPath,
    VulnFinding,
    # 跨函数分析
    InternalCall,
    FunctionSummary,
    CallGraphNode,
    CrossFunctionPath,
    # 内存分析
    PointerInfo,
    MemoryVulnFinding,
    CrossFunctionUAF,
    PointerParamState,
    # 整数溢出
    IntegerOverflowInfo,
    IntegerOverflowFinding,
    # 置信度
    ConfidenceScore,
    ScoredFinding,
    # API 常量
    DANGEROUS_SINKS,
    TAINT_SOURCES,
    ALLOC_APIS,
    FREE_APIS,
    POINTER_USE_APIS,
    OVERFLOW_RISK_INSTRUCTIONS,
)

# =============================================================================
# 配置管理
# =============================================================================

from .config import (
    LuoDllHackConfig,
    ConfidenceWeightsConfig,
    VerifyConfidenceConfig,
    default_config,
    load_config,
)

# =============================================================================
# 异常
# =============================================================================

from .exceptions import (
    LuoDllHackError,
    TaintAnalysisError,
    SymbolicExecutionError,
    DisassemblyError,
    PEError,
    PEParseError,
    ExportExtractionError,
    DLLCompilationError,
    AIError,
    APIKeyError,
    RateLimitError,
    TokenLimitError,
    ToolExecutionError,
    ValidationError,
    EmulationError,
    PoCGenerationError,
    ConfigError,
    ConfigValidationError,
    ConfigLoadError,
    format_exception,
)

# =============================================================================
# 日志
# =============================================================================

from .logging import (
    LuoDllHackLogger,
    get_logger,
    setup_logging,
    setup_logging_from_config,
)

# =============================================================================
# 导出列表
# =============================================================================

__all__ = [
    # Rizin 核心
    'RizinCore',
    'load_binary',
    'check_rizin_available',
    'HAVE_RIZIN',
    'RizinError',
    'RizinNotFoundError',
    'BinaryLoadError',
    'AnalysisError',
    # Rizin 数据结构
    'Architecture',
    'Endianness',
    'BinaryType',
    'BinaryInfo',
    'Instruction',
    'InstructionType',
    'Operand',
    'BasicBlock',
    'EdgeType',
    'Function',
    'Variable',
    'Import',
    'Export',
    'Symbol',
    'Section',
    'StringRef',
    'VTable',
    'VTableEntry',
    'XRef',
    'XRefType',
    'RegisterState',
    'Breakpoint',
    'RopGadget',
    # 漏洞类型
    'VulnType',
    'SourceType',
    'PointerState',
    'ArithmeticOp',
    'ConfidenceFactor',
    'TaintSource',
    'TaintSink',
    'TaintStep',
    'TaintPath',
    'VulnFinding',
    'InternalCall',
    'FunctionSummary',
    'CallGraphNode',
    'CrossFunctionPath',
    'PointerInfo',
    'MemoryVulnFinding',
    'CrossFunctionUAF',
    'PointerParamState',
    'IntegerOverflowInfo',
    'IntegerOverflowFinding',
    'ConfidenceScore',
    'ScoredFinding',
    'DANGEROUS_SINKS',
    'TAINT_SOURCES',
    'ALLOC_APIS',
    'FREE_APIS',
    'POINTER_USE_APIS',
    'OVERFLOW_RISK_INSTRUCTIONS',
    # 配置
    'LuoDllHackConfig',
    'ConfidenceWeightsConfig',
    'VerifyConfidenceConfig',
    'default_config',
    'load_config',
    # 异常
    'LuoDllHackError',
    'TaintAnalysisError',
    'SymbolicExecutionError',
    'DisassemblyError',
    'PEError',
    'PEParseError',
    'ExportExtractionError',
    'DLLCompilationError',
    'AIError',
    'APIKeyError',
    'RateLimitError',
    'TokenLimitError',
    'ToolExecutionError',
    'ValidationError',
    'EmulationError',
    'PoCGenerationError',
    'ConfigError',
    'ConfigValidationError',
    'ConfigLoadError',
    'format_exception',
    # 日志
    'LuoDllHackLogger',
    'get_logger',
    'setup_logging',
    'setup_logging_from_config',
]
