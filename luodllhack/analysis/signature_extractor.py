# -*- coding: utf-8 -*-
"""
luodllhack/analysis/signature_extractor.py - Function Signature Extractor

This module has been consolidated into luodllhack.core.signatures.
For new code, use:
    from luodllhack.core.signatures import (
        FunctionSignature, ArgInfo, CallingConvention,
        SignatureExtractor, SignatureLoader,
        get_signature, get_all_signatures,
    )

This file is preserved for backward compatibility; all functionality is imported from core.signatures.
"""

# Re-export all contents from the unified signature module
from luodllhack.core.signatures import (
    # Data models
    CallingConvention,
    ArgInfo,
    FunctionSignature,
    ExportSymbol,
    ArgumentInfo,

    # Convenience functions
    get_signature,
    get_all_signatures,
    get_function_signature,
    get_enhanced_signature,

    # Classes
    SignatureExtractor,
    SignatureLoader,
    DisasmAnalyzer,
)

# For full compatibility, add aliases
DisasmSignatureAnalyzer = DisasmAnalyzer

__all__ = [
    'CallingConvention',
    'ArgInfo',
    'ArgumentInfo',
    'FunctionSignature',
    'ExportSymbol',
    'SignatureExtractor',
    'SignatureLoader',
    'DisasmAnalyzer',
    'DisasmSignatureAnalyzer',
    'get_signature',
    'get_all_signatures',
    'get_function_signature',
    'get_enhanced_signature',
]
