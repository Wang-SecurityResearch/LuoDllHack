# -*- coding: utf-8 -*-
"""
luodllhack/analysis/signature_loader.py - External Signature File Loader

This module has been consolidated into luodllhack.core.signatures.loader.
For new code, use:
    from luodllhack.core.signatures import (
        SignatureLoader,
        LoadedSignature,
        load_signatures_for_dll,
    )

This file is preserved for backward compatibility; all functionality is imported from core.signatures.
"""

# Re-export all contents from the unified signature module
from luodllhack.core.signatures import (
    SignatureLoader,
    LoadedSignature,
    load_signatures_for_dll,
)

__all__ = [
    'SignatureLoader',
    'LoadedSignature',
    'load_signatures_for_dll',
]
