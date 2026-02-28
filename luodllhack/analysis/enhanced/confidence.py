# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/confidence.py

Enhanced Confidence Computation - Phase 1.3

Core Capabilities:
    1. Calculate real confidence based on multiple factors
    2. Dynamically adjust weights
    3. Generate detailed scoring explanations

Scoring Factors:
    Increase Confidence:
        - Taint path is complete
        - Direct call to dangerous API
        - No bounds check
        - Cross-function propagation confirmed
        - User input is directly controllable

    Decrease Confidence:
        - Bounds check detected
        - Passed through sanitization function
        - Null pointer check exists
        - Complex path constraints
        - Static hardcoded parameters

Confidence Levels:
    - Critical (>=0.90): Almost certain to be a vulnerability
    - High     (>=0.75): Highly likely
    - Medium   (>=0.50): Requires manual confirmation
    - Low      (>=0.30): Possible false positive
    - Info     (<0.30):  For reference only
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum, auto


class ConfidenceLevel(Enum):
    """Confidence Level"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class ConfidenceFactors:
    """Confidence Scoring Factors"""
    # === Factors that increase confidence ===
    has_taint_path: bool = True          # Taint path exists
    is_dangerous_api: bool = True         # Call to dangerous API
    has_user_input: bool = True           # User input is controllable
    cross_function_confirmed: bool = False # Cross-function analysis confirmed
    no_null_check: bool = True            # No null pointer check
    arithmetic_risk: bool = False          # Arithmetic operation risk exists
    direct_parameter: bool = True          # Parameters passed directly

    # === Factors that decrease confidence ===
    has_bounds_check: bool = False         # Bounds check exists
    was_sanitized: bool = False            # Data was sanitized
    has_length_limit: bool = False         # Length limit exists
    has_path_constraints: bool = False     # Path constraints exist
    is_hardcoded: bool = False             # Hardcoded parameters
    safe_api_used: bool = False            # Safe API version used

    # === Detailed Information ===
    bounds_check_details: Any = None
    sanitize_details: Any = None

    # === Other Flags ===
    has_null_check: bool = False


@dataclass
class ConfidenceResult:
    """Confidence Computation Result"""
    score: float
    level: ConfidenceLevel
    factors: ConfidenceFactors
    # Component scores
    positive_score: float = 0.0
    negative_score: float = 0.0
    # Explanations
    explanation: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'score': round(self.score, 3),
            'level': self.level.value,
            'positive_score': round(self.positive_score, 3),
            'negative_score': round(self.negative_score, 3),
            'explanation': self.explanation,
            'recommendations': self.recommendations
        }


class EnhancedConfidenceScorer:
    """
    Enhanced Confidence Scorer

    Usage:
        scorer = EnhancedConfidenceScorer()

        factors = ConfidenceFactors(
            has_taint_path=True,
            has_bounds_check=True,
            was_sanitized=False
        )

        result = scorer.calculate_detailed(0.9, factors)
        print(f"Real confidence: {result.score} ({result.level.value})")
        print(f"Explanation: {result.explanation}")
    """

    # ==========================================================================
    # Scoring Weight Configuration
    # ==========================================================================

    # Positive factor weights (increase confidence)
    POSITIVE_WEIGHTS = {
        'has_taint_path': 0.25,           # Taint path exists - core evidence
        'is_dangerous_api': 0.15,          # Dangerous API - important
        'has_user_input': 0.15,            # User controllable - important
        'cross_function_confirmed': 0.10,  # Cross-function confirmation - bolstering
        'no_null_check': 0.05,             # No null check - auxiliary
        'arithmetic_risk': 0.08,           # Arithmetic risk - vulnerability specific
        'direct_parameter': 0.07,          # Direct parameter - auxiliary
    }

    # Negative factor weights (decrease confidence)
    NEGATIVE_WEIGHTS = {
        'has_bounds_check': 0.30,          # Bounds check - strong reduction
        'was_sanitized': 0.35,             # Sanitized - strong reduction
        'has_length_limit': 0.25,          # Length limit - moderate reduction
        'has_path_constraints': 0.10,      # Path constraints - slight reduction
        'is_hardcoded': 0.40,              # Hardcoded - strong reduction
        'safe_api_used': 0.45,             # Safe API - strong reduction
    }

    # Confidence level thresholds
    LEVEL_THRESHOLDS = {
        ConfidenceLevel.CRITICAL: 0.90,
        ConfidenceLevel.HIGH: 0.75,
        ConfidenceLevel.MEDIUM: 0.50,
        ConfidenceLevel.LOW: 0.30,
        ConfidenceLevel.INFO: 0.0,
    }

    def __init__(self, custom_weights: Dict[str, float] = None):
        """
        Initialize the scorer

        Args:
            custom_weights: Custom weights (optional)
        """
        if custom_weights:
            self.POSITIVE_WEIGHTS.update(custom_weights.get('positive', {}))
            self.NEGATIVE_WEIGHTS.update(custom_weights.get('negative', {}))

    def calculate(self, base_confidence: float,
                  factors: ConfidenceFactors) -> float:
        """
        Calculate real confidence (simplified version)

        Args:
            base_confidence: Base confidence (0.0-1.0)
            factors: Scoring factors

        Returns:
            Adjusted confidence
        """
        result = self.calculate_detailed(base_confidence, factors)
        return result.score

    def calculate_detailed(self, base_confidence: float,
                            factors: ConfidenceFactors) -> ConfidenceResult:
        """
        Calculate real confidence (detailed version)

        Args:
            base_confidence: Base confidence (0.0-1.0)
            factors: Scoring factors

        Returns:
            ConfidenceResult containing detailed scoring info
        """
        explanation = []
        recommendations = []

        # Calculate positive score
        positive_score = 0.0
        for factor, weight in self.POSITIVE_WEIGHTS.items():
            if getattr(factors, factor, False):
                positive_score += weight
                explanation.append(f"[+{weight:.0%}] {self._factor_description(factor)}")

        # Calculate negative score (penalty)
        negative_score = 0.0
        for factor, weight in self.NEGATIVE_WEIGHTS.items():
            if getattr(factors, factor, False):
                negative_score += weight
                explanation.append(f"[-{weight:.0%}] {self._factor_description(factor)}")

                # Add recommendation
                rec = self._get_recommendation(factor)
                if rec:
                    recommendations.append(rec)

        # Calculate final score
        # Base adjustment
        adjusted = base_confidence

        # Apply negative penalties
        if factors.was_sanitized:
            if factors.sanitize_details and getattr(factors.sanitize_details, 'is_complete_sanitization', False):
                adjusted *= 0.2  # Fully sanitized, major reduction
                explanation.append("[!] Data fully sanitized, vulnerability may have been mitigated")
            else:
                adjusted *= 0.5  # Partially sanitized

        if factors.has_bounds_check:
            if factors.bounds_check_details and getattr(factors.bounds_check_details, 'is_effective', False):
                adjusted *= 0.3  # Effective bounds check
                explanation.append("[!] Effective bounds check detected")
            else:
                adjusted *= 0.6  # Bounds checked but effectiveness uncertain

        if factors.is_hardcoded:
            adjusted *= 0.1  # Hardcoded parameters, almost certainly not a vulnerability
            explanation.append("[!] Parameters are hardcoded, not user-controllable")

        if factors.safe_api_used:
            adjusted *= 0.2  # Safe API used
            explanation.append("[!] Safe version of the API was used")

        # Apply positive bonus
        positive_bonus = min(0.1, positive_score * 0.15)
        adjusted += positive_bonus

        # Ensure within valid range
        final_score = max(0.0, min(1.0, adjusted))

        # Determine level
        level = self._determine_level(final_score)

        return ConfidenceResult(
            score=final_score,
            level=level,
            factors=factors,
            positive_score=positive_score,
            negative_score=negative_score,
            explanation=explanation,
            recommendations=recommendations
        )

    def _determine_level(self, score: float) -> ConfidenceLevel:
        """Determine confidence level"""
        for level, threshold in self.LEVEL_THRESHOLDS.items():
            if score >= threshold:
                return level
        return ConfidenceLevel.INFO

    def _factor_description(self, factor: str) -> str:
        """Get factor description"""
        descriptions = {
            # Positive
            'has_taint_path': 'Taint path exists',
            'is_dangerous_api': 'Calls dangerous API',
            'has_user_input': 'User input controllable',
            'cross_function_confirmed': 'Cross-function analysis confirmed',
            'no_null_check': 'No null check detected',
            'arithmetic_risk': 'Arithmetic risk exists',
            'direct_parameter': 'Parameters passed directly',
            # Negative
            'has_bounds_check': 'Bounds check detected',
            'was_sanitized': 'Data passed through sanitization',
            'has_length_limit': 'Length limit exists',
            'has_path_constraints': 'Complex path constraints exist',
            'is_hardcoded': 'Parameters are hardcoded',
            'safe_api_used': 'Safe version of API used',
        }
        return descriptions.get(factor, factor)

    def _get_recommendation(self, factor: str) -> Optional[str]:
        """Get recommendation"""
        recommendations = {
            'has_bounds_check': 'Verify if bounds check effectively prevents vulnerability',
            'was_sanitized': 'Confirm if sanitizer fully covers the attack vector',
            'has_length_limit': 'Check if length limit is sufficiently strict',
            'is_hardcoded': 'Hardcoded parameters rarely lead to vulnerabilities; skip',
            'safe_api_used': 'Safe API used; focus research on other paths',
        }
        return recommendations.get(factor)

    @staticmethod
    def quick_score(has_bounds_check: bool = False,
                    was_sanitized: bool = False,
                    is_hardcoded: bool = False,
                    base: float = 0.9) -> float:
        """
        Quick confidence score (for simple scenarios)

        Args:
            has_bounds_check: Whether bounds check exists
            was_sanitized: Whether sanitized
            is_hardcoded: Whether hardcoded
            base: Base confidence

        Returns:
            Adjusted confidence
        """
        score = base

        if is_hardcoded:
            score *= 0.1
        if was_sanitized:
            score *= 0.4
        if has_bounds_check:
            score *= 0.5

        return max(0.05, score)


# Convenience function
def calculate_confidence(base: float, **kwargs) -> float:
    """
    Convenience function to calculate confidence

    Args:
        base: Base confidence
        **kwargs: Factors (has_bounds_check, was_sanitized, etc.)

    Returns:
        Adjusted confidence

    Example:
        conf = calculate_confidence(0.9, has_bounds_check=True)
    """
    factors = ConfidenceFactors(**kwargs)
    scorer = EnhancedConfidenceScorer()
    return scorer.calculate(base, factors)
