# -*- coding: utf-8 -*-
"""
luodllhack/verify - 漏洞验证能力

验证引擎:
- SpeakeasyVerifier: Speakeasy 模拟器验证 (推荐)
- ConfidenceScorer: 置信度评分
- PoCValidator: PoC 验证
"""

# Speakeasy 验证器 (主要验证引擎)
try:
    from .speakeasy import SpeakeasyVerifier, HAVE_SPEAKEASY
except ImportError:
    HAVE_SPEAKEASY = False
    SpeakeasyVerifier = None

# 置信度评分 (从 taint 模块导入)
from ..analysis.taint import (
    ConfidenceScorer,
    ConfidenceScore,
    ScoredFinding,
    ConfidenceFactor,
    CONFIDENCE_WEIGHTS,
    CONFIDENCE_LEVELS,
)

# PoC 验证 (luodllhack 原有)
from ..exploit.validator import (
    PoCValidator,
    ValidationResult as PoCValidationResult,
    ValidationStatus,
    CrashType,
)

__all__ = [
    # Speakeasy 验证
    'SpeakeasyVerifier', 'HAVE_SPEAKEASY',
    # 置信度评分
    'ConfidenceScorer', 'ConfidenceScore', 'ScoredFinding',
    'ConfidenceFactor', 'CONFIDENCE_WEIGHTS', 'CONFIDENCE_LEVELS',
    # PoC 验证
    'PoCValidator', 'PoCValidationResult', 'ValidationStatus', 'CrashType',
]
