# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack - DLL 劫持能力

核心功能 (从 sys_dll 迁移):
- ProxyGenerator: 代理 DLL 生成
- PEParser: PE 文件解析
- Compiler: DLL 编译
- ExportValidator: 导出验证
"""

# 常量
from .constants import (
    MACHINE_I386, MACHINE_AMD64, MACHINE_ARM64,
    DLL_CHAR_DYNAMIC_BASE, DLL_CHAR_NX_COMPAT, DLL_CHAR_GUARD_CF,
    SECTION_MEM_EXECUTE, SECTION_MEM_READ, SECTION_MEM_WRITE,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
)

# 数据模型
from .models import (
    CallingConvention,
    Architecture,
    CompilerType,
    ArgInfo,
    ExportSymbol,
    TLSCallback,
    VersionInfo,
    PEInfo,
)

# 接口
from .interfaces import (
    ExportExtractor,
    CodeEmitter,
)

# 工具函数
from .utils import (
    resolve_forwarder_module,
    WinTrustVerifier,
    SecurityUtils,
)

# 提取器
from .extractors import (
    PefileExtractor,
    DumpbinExtractor,
    CompositeExtractor,
    AngrExtractor,
    EnhancedExtractor,
)

# 解析器
from .parser import PEParser

# 代码生成器
from .emitters import (
    DefFileEmitter,
    CCodeEmitter,
    DynamicProxyEmitter,
    BuildScriptEmitter,
    CppExportEmitter,
    ResourceEmitter,
    TLSCallbackEmitter,
)

# 核心生成器
from .generator import ProxyGenerator

# 验证器
from .validator import (
    ExportValidator,
    ValidationResult,
    validate_proxy,
)

# 编译器
from .compiler import (
    Compiler,
    MSVCCompiler,
    MinGWCompiler,
    AutoCompiler,
    CompileResult,
    detect_compilers,
    compile_proxy,
)

# DLL劫持扫描器
from .scanner import (
    HijackScanner,
    RiskLevel,
    TriggerType,
    DllDependency,
    PEScanResult,
    scan_for_hijack,
    quick_check,
    analyze_exploitation_trigger,
    TriggerAnalyzerAI,
)

# DLL劫持PoC生成器
from .hijack_gen import (
    HijackGenerator,
    HijackTarget,
    GenerationResult,
    generate_hijack_poc,
)

__all__ = [
    # 常量
    'MACHINE_I386', 'MACHINE_AMD64', 'MACHINE_ARM64',
    'DLL_CHAR_DYNAMIC_BASE', 'DLL_CHAR_NX_COMPAT', 'DLL_CHAR_GUARD_CF',
    'SECTION_MEM_EXECUTE', 'SECTION_MEM_READ', 'SECTION_MEM_WRITE',
    'LOAD_LIBRARY_SEARCH_SYSTEM32',
    # 模型
    'CallingConvention', 'Architecture', 'CompilerType',
    'ArgInfo', 'ExportSymbol', 'TLSCallback', 'VersionInfo', 'PEInfo',
    # 接口
    'ExportExtractor', 'CodeEmitter',
    # 工具
    'resolve_forwarder_module', 'WinTrustVerifier', 'SecurityUtils',
    # 提取器
    'PefileExtractor', 'DumpbinExtractor', 'CompositeExtractor',
    'AngrExtractor', 'EnhancedExtractor',
    # 解析器
    'PEParser',
    # 生成器
    'DefFileEmitter', 'CCodeEmitter', 'DynamicProxyEmitter',
    'BuildScriptEmitter', 'CppExportEmitter', 'ResourceEmitter', 'TLSCallbackEmitter',
    'ProxyGenerator',
    # 验证器
    'ExportValidator', 'ValidationResult', 'validate_proxy',
    # 编译器
    'Compiler', 'MSVCCompiler', 'MinGWCompiler', 'AutoCompiler',
    'CompileResult', 'detect_compilers', 'compile_proxy',
    # 扫描器
    'HijackScanner', 'RiskLevel', 'TriggerType', 'DllDependency', 'PEScanResult',
    'scan_for_hijack', 'quick_check', 'analyze_exploitation_trigger', 'TriggerAnalyzerAI',
    # PoC生成器
    'HijackGenerator', 'HijackTarget', 'GenerationResult', 'generate_hijack_poc',
]
