# -*- coding: utf-8 -*-
"""
luodllhack/analysis/confidence.py - Confidence Scorer

Split from taint.py to provide independent confidence scoring functionality.
"""

from typing import Dict, List, Set, Optional, TYPE_CHECKING, Any

# Import type definitions from core.types
from luodllhack.core.types import (
    VulnType,
    SourceType,
    TaintSource,
    TaintSink,
    TaintStep,
    TaintPath,
    MemoryVulnFinding,
    CrossFunctionUAF,
    IntegerOverflowFinding,
    ConfidenceFactor,
    ConfidenceScore,
    ScoredFinding,
)

# Avoid circular imports
if TYPE_CHECKING:
    from .taint import TaintEngine

# =============================================================================
# Confidence Weight Configuration - Agent Focused (Static 40%, Agent 60%)
# =============================================================================

# Default weight configuration
CONFIDENCE_WEIGHTS = {
    # =========================================================================
    # Static Analysis Factors (Total weight 40%)
    # =========================================================================
    ConfidenceFactor.TAINT_PATH_EXISTS: 0.15,       # Taint path exists
    ConfidenceFactor.DANGEROUS_API_CALL: 0.10,     # Dangerous API call
    ConfidenceFactor.USER_INPUT_DIRECT: 0.05,      # User input controllable
    ConfidenceFactor.NO_BOUNDS_CHECK: 0.05,        # No bounds check
    ConfidenceFactor.ARITHMETIC_OVERFLOW: 0.02,    # Arithmetic overflow risk
    ConfidenceFactor.INDIRECT_CALL_TAINTED: 0.02,  # Indirect call tainted
    ConfidenceFactor.NO_NULL_CHECK: 0.01,          # No NULL pointer check
    ConfidenceFactor.CROSS_FUNCTION: 0.02,         # Cross-function propagation
    ConfidenceFactor.MULTIPLE_PATHS: 0.01,         # Reachable via multiple paths

    # =========================================================================
    # Agent Verification Factors (Total weight 60% - Agent focused)
    # =========================================================================
    # PoC Execution Verification (Weight 30%)
    ConfidenceFactor.POC_CRASH_CONTROLLED: 0.25,       # Crash at controlled address
    ConfidenceFactor.POC_CRASH_UNCONTROLLED: 0.10,     # Crash but address uncontrolled
    ConfidenceFactor.POC_FUNCTION_ERROR: -0.20,        # Function returns error code (negative weight)
    ConfidenceFactor.POC_EXECUTION_OK: 0.05,           # Executed successfully without crash
    ConfidenceFactor.POC_TIMEOUT: -0.05,               # Execution timeout (negative weight)

    # Agent Intelligent Adjudication (Weight 30%)
    ConfidenceFactor.AI_CONFIRMED: 0.10,               # Initial AI confirmation
    ConfidenceFactor.AGENT_TRUE_POSITIVE: 0.25,        # Agent determines true positive
    ConfidenceFactor.AGENT_FALSE_POSITIVE: -0.40,      # Agent determines false positive (negative weight)
    ConfidenceFactor.AGENT_NEEDS_REVIEW: 0.0,          # Needs further verification
    ConfidenceFactor.LLM_DEEP_VERIFIED: 0.15,          # Deep LLM verification passed
    ConfidenceFactor.LLM_DEEP_REJECTED: -0.25,         # Deep LLM verification rejected (negative weight)
}

# Attempt to load weights from configuration (overrides defaults)
try:
    from luodllhack.core.config import default_config
    if default_config and hasattr(default_config, 'confidence_weights'):
        _weights = default_config.confidence_weights
        # Override only weights defined in the configuration
        if hasattr(_weights, 'taint_path_exists'):
            CONFIDENCE_WEIGHTS[ConfidenceFactor.TAINT_PATH_EXISTS] = _weights.taint_path_exists
        if hasattr(_weights, 'ai_confirmed'):
            CONFIDENCE_WEIGHTS[ConfidenceFactor.AI_CONFIRMED] = _weights.ai_confirmed
        if hasattr(_weights, 'dangerous_api_call'):
            CONFIDENCE_WEIGHTS[ConfidenceFactor.DANGEROUS_API_CALL] = _weights.dangerous_api_call
except (ImportError, AttributeError):
    pass  # Use default weights

# Confidence level thresholds
CONFIDENCE_LEVELS = {
    0.85: "Confirmed",
    0.70: "High",
    0.50: "Medium",
    0.30: "Low",
    0.0: "Suspicious"
}


class ConfidenceScorer:
    """
    Confidence Scorer

    Integrates vulnerability findings from multiple sources, calculates confidence scores,
    and outputs results sorted by reliability.
    """

    def __init__(self, min_threshold: float = None) -> None:
        """
        Initialize the Confidence Scorer

        Args:
            min_threshold: Minimum confidence threshold (read from config if None)
        """
        # AI report cache (used for cross-validation)
        self.ai_findings: Dict[int, Dict] = {}  # addr -> AI finding info
        self.ai_findings_by_func: Dict[str, Dict] = {} # func_name -> AI finding info
        # Scored findings
        self.scored_findings: List[ScoredFinding] = []
        self.false_positives: List[ScoredFinding] = []
        self.filtered_count: int = 0

        # Get minimum confidence threshold from configuration
        if min_threshold is not None:
            self.min_threshold = min_threshold
        else:
            try:
                from luodllhack.core.config import default_config
                if default_config:
                    self.min_threshold = default_config.confidence_min_threshold
                else:
                    self.min_threshold = 0.30
            except ImportError:
                self.min_threshold = 0.30

    def add_ai_findings(self, ai_report: Dict) -> None:
        """
        Add AI analysis results for cross-validation

        Args:
            ai_report: AI agent analysis report (VulnReport format or dict)
        """
        if not ai_report:
            return

        vulns = ai_report.get('vulnerabilities', [])
        for vuln in vulns:
            addr = vuln.get('address', 0)
            func_name = vuln.get('function', '')

            # Store by address (for address matching)
            if addr:
                self.ai_findings[addr] = vuln

            # Also store by function name (for function name matching)
            if func_name:
                self.ai_findings_by_func[func_name] = vuln

    def score_taint_path(self, path: TaintPath, func_name: str = "",
                         ai_analysis: Optional[str] = None) -> ScoredFinding:
        """
        Score a taint path discovery

        Args:
            path: TaintPath object
            func_name: Function name (uses path.func_name if empty)
            ai_analysis: AI analysis result

        Returns:
            ScoredFinding
        """
        # Prioritize passed func_name, otherwise use the one in path
        actual_func_name = func_name or getattr(path, 'func_name', '') or ''

        factors: Dict[ConfidenceFactor, bool] = {}
        contributions: Dict[ConfidenceFactor, float] = {}

        # 1. Taint path exists - Base score
        factors[ConfidenceFactor.TAINT_PATH_EXISTS] = True
        contributions[ConfidenceFactor.TAINT_PATH_EXISTS] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.TAINT_PATH_EXISTS
        ]

        # 2. Dangerous API call
        if path.sink and path.sink.api_name:
            factors[ConfidenceFactor.DANGEROUS_API_CALL] = True
            contributions[ConfidenceFactor.DANGEROUS_API_CALL] = CONFIDENCE_WEIGHTS[
                ConfidenceFactor.DANGEROUS_API_CALL
            ]
        else:
            factors[ConfidenceFactor.DANGEROUS_API_CALL] = False
            contributions[ConfidenceFactor.DANGEROUS_API_CALL] = 0.0

        # 3. Direct user input control
        direct_sources = {SourceType.NETWORK, SourceType.FILE, SourceType.USER_INPUT}
        if path.source and path.source.type in direct_sources:
            factors[ConfidenceFactor.USER_INPUT_DIRECT] = True
            contributions[ConfidenceFactor.USER_INPUT_DIRECT] = CONFIDENCE_WEIGHTS[
                ConfidenceFactor.USER_INPUT_DIRECT
            ]
        else:
            factors[ConfidenceFactor.USER_INPUT_DIRECT] = False
            contributions[ConfidenceFactor.USER_INPUT_DIRECT] = 0.0

        # 4. AI Confirmation (Cross-validation)
        sink_addr = path.sink.addr if path.sink else 0
        if sink_addr in self.ai_findings:
            factors[ConfidenceFactor.AI_CONFIRMED] = True
            contributions[ConfidenceFactor.AI_CONFIRMED] = CONFIDENCE_WEIGHTS[
                ConfidenceFactor.AI_CONFIRMED
            ]
        else:
            factors[ConfidenceFactor.AI_CONFIRMED] = False
            contributions[ConfidenceFactor.AI_CONFIRMED] = 0.0

        # 5. Detect bounds check (via step analysis)
        has_bounds_check = self._detect_bounds_check(path.steps)
        factors[ConfidenceFactor.NO_BOUNDS_CHECK] = not has_bounds_check
        contributions[ConfidenceFactor.NO_BOUNDS_CHECK] = (
            CONFIDENCE_WEIGHTS[ConfidenceFactor.NO_BOUNDS_CHECK] if not has_bounds_check else 0.0
        )

        # Initialize other factors as False
        for factor in ConfidenceFactor:
            if factor not in factors:
                factors[factor] = False
                contributions[factor] = 0.0

        # Calculate total score
        total = sum(contributions.values())

        # Generate explanation
        explanation = self._generate_explanation(factors, contributions)

        confidence = ConfidenceScore(
            total_score=min(total, 1.0),
            level="",  # Calculated by __post_init__
            factors=factors,
            factor_contributions=contributions,
            explanation=explanation
        )

        # Generate original finding ID to associate with shared state Finding
        original_finding_id = f"taint_{sink_addr:x}_{actual_func_name}"

        return ScoredFinding(
            finding_type="TaintPath",
            vuln_type=path.sink.vuln_type if path.sink else VulnType.BUFFER_OVERFLOW,
            severity=path.sink.severity if path.sink else "Medium",
            location=sink_addr,
            func_name=actual_func_name,
            confidence=confidence,
            raw_finding=path,
            sources=["taint_engine"],
            ai_analysis=ai_analysis,
            original_finding_id=original_finding_id,
            poc_path=getattr(path, 'poc_path', None),
            harness_path=getattr(path, 'harness_path', None)
        )

    def score_memory_finding(self, finding: MemoryVulnFinding,
                              func_name: str = "",
                              ai_analysis: Optional[str] = None) -> ScoredFinding:
        """Score a memory vulnerability discovery (UAF/Double-Free)"""
        actual_func_name = func_name or getattr(finding, 'func_name', '') or ''

        factors: Dict[ConfidenceFactor, bool] = {}
        contributions: Dict[ConfidenceFactor, float] = {}

        # 1. Taint path exists (Memory lifecycle tracking)
        factors[ConfidenceFactor.TAINT_PATH_EXISTS] = True
        contributions[ConfidenceFactor.TAINT_PATH_EXISTS] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.TAINT_PATH_EXISTS
        ]

        # 2. Dangerous API call (free/HeapFree etc.)
        factors[ConfidenceFactor.DANGEROUS_API_CALL] = True
        contributions[ConfidenceFactor.DANGEROUS_API_CALL] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.DANGEROUS_API_CALL
        ]

        # 3. AI Confirmation
        if finding.vuln_addr in self.ai_findings:
            factors[ConfidenceFactor.AI_CONFIRMED] = True
            contributions[ConfidenceFactor.AI_CONFIRMED] = CONFIDENCE_WEIGHTS[
                ConfidenceFactor.AI_CONFIRMED
            ]
        else:
            factors[ConfidenceFactor.AI_CONFIRMED] = False
            contributions[ConfidenceFactor.AI_CONFIRMED] = 0.0

        # 4. No NULL pointer check (usually missing in UAF)
        factors[ConfidenceFactor.NO_NULL_CHECK] = True
        contributions[ConfidenceFactor.NO_NULL_CHECK] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.NO_NULL_CHECK
        ]

        # Initialize other factors
        for factor in ConfidenceFactor:
            if factor not in factors:
                factors[factor] = False
                contributions[factor] = 0.0

        total = sum(contributions.values())
        explanation = self._generate_explanation(factors, contributions)

        confidence = ConfidenceScore(
            total_score=min(total, 1.0),
            level="",
            factors=factors,
            factor_contributions=contributions,
            explanation=explanation
        )

        # Generate original finding ID to associate with shared state Finding
        original_finding_id = f"memory_{finding.vuln_addr:x}_{actual_func_name}"

        return ScoredFinding(
            finding_type="MemoryVuln",
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            location=finding.vuln_addr,
            func_name=actual_func_name,
            confidence=confidence,
            raw_finding=finding,
            sources=["taint_engine"],
            ai_analysis=ai_analysis,
            original_finding_id=original_finding_id,
            poc_path=getattr(finding, 'poc_path', None),
            harness_path=getattr(finding, 'harness_path', None)
        )

    def score_integer_overflow(self, finding: IntegerOverflowFinding,
                                ai_analysis: Optional[str] = None) -> ScoredFinding:
        """Score integer overflow discoveries"""
        factors: Dict[ConfidenceFactor, bool] = {}
        contributions: Dict[ConfidenceFactor, float] = {}

        # 1. Taint path exists
        factors[ConfidenceFactor.TAINT_PATH_EXISTS] = True
        contributions[ConfidenceFactor.TAINT_PATH_EXISTS] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.TAINT_PATH_EXISTS
        ]

        # 2. Arithmetic overflow risk
        factors[ConfidenceFactor.ARITHMETIC_OVERFLOW] = True
        contributions[ConfidenceFactor.ARITHMETIC_OVERFLOW] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.ARITHMETIC_OVERFLOW
        ]

        # 3. Dangerous API call (malloc etc.)
        factors[ConfidenceFactor.DANGEROUS_API_CALL] = True
        contributions[ConfidenceFactor.DANGEROUS_API_CALL] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.DANGEROUS_API_CALL
        ]

        # 4. AI Confirmation
        if finding.alloc_addr in self.ai_findings:
            factors[ConfidenceFactor.AI_CONFIRMED] = True
            contributions[ConfidenceFactor.AI_CONFIRMED] = CONFIDENCE_WEIGHTS[
                ConfidenceFactor.AI_CONFIRMED
            ]
        else:
            factors[ConfidenceFactor.AI_CONFIRMED] = False
            contributions[ConfidenceFactor.AI_CONFIRMED] = 0.0

        # 5. No bounds check
        factors[ConfidenceFactor.NO_BOUNDS_CHECK] = True
        contributions[ConfidenceFactor.NO_BOUNDS_CHECK] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.NO_BOUNDS_CHECK
        ]

        # Initialize other factors
        for factor in ConfidenceFactor:
            if factor not in factors:
                factors[factor] = False
                contributions[factor] = 0.0

        total = sum(contributions.values())
        explanation = self._generate_explanation(factors, contributions)

        confidence = ConfidenceScore(
            total_score=min(total, 1.0),
            level="",
            factors=factors,
            factor_contributions=contributions,
            explanation=explanation
        )

        # Generate original finding ID to associate with shared state Finding
        original_finding_id = f"overflow_{finding.alloc_addr:x}_{finding.func_name}"

        return ScoredFinding(
            finding_type="IntegerOverflow",
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            location=finding.alloc_addr,
            func_name=finding.func_name,
            confidence=confidence,
            raw_finding=finding,
            sources=["taint_engine"],
            ai_analysis=ai_analysis,
            original_finding_id=original_finding_id,
            poc_path=getattr(finding, 'poc_path', None),
            harness_path=getattr(finding, 'harness_path', None)
        )

    def score_cross_function_uaf(self, finding: CrossFunctionUAF,
                                 ai_analysis: Optional[str] = None) -> ScoredFinding:
        """Score cross-function UAF discoveries"""
        factors: Dict[ConfidenceFactor, bool] = {}
        contributions: Dict[ConfidenceFactor, float] = {}

        # 1. Taint path exists
        factors[ConfidenceFactor.TAINT_PATH_EXISTS] = True
        contributions[ConfidenceFactor.TAINT_PATH_EXISTS] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.TAINT_PATH_EXISTS
        ]

        # 2. Cross-function confirmation - Important evidence
        factors[ConfidenceFactor.CROSS_FUNCTION] = True
        contributions[ConfidenceFactor.CROSS_FUNCTION] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.CROSS_FUNCTION
        ]

        # 3. Dangerous API call
        factors[ConfidenceFactor.DANGEROUS_API_CALL] = True
        contributions[ConfidenceFactor.DANGEROUS_API_CALL] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.DANGEROUS_API_CALL
        ]

        # 4. AI Confirmation
        if finding.use_addr in self.ai_findings:
            factors[ConfidenceFactor.AI_CONFIRMED] = True
            contributions[ConfidenceFactor.AI_CONFIRMED] = CONFIDENCE_WEIGHTS[
                ConfidenceFactor.AI_CONFIRMED
            ]
        else:
            factors[ConfidenceFactor.AI_CONFIRMED] = False
            contributions[ConfidenceFactor.AI_CONFIRMED] = 0.0

        # Initialize other factors
        for factor in ConfidenceFactor:
            if factor not in factors:
                factors[factor] = False
                contributions[factor] = 0.0

        total = sum(contributions.values())
        explanation = self._generate_explanation(factors, contributions)

        confidence = ConfidenceScore(
            total_score=min(total, 1.0),
            level="",
            factors=factors,
            factor_contributions=contributions,
            explanation=explanation
        )

        return ScoredFinding(
            finding_type="CrossFunctionUAF",
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            location=finding.use_addr,
            func_name=finding.use_func,
            confidence=confidence,
            raw_finding=finding,
            sources=["taint_engine"],
            ai_analysis=ai_analysis,
            poc_path=getattr(finding, 'poc_path', None),
            harness_path=getattr(finding, 'harness_path', None)
        )

    def score_ai_only_finding(self, ai_finding: Dict) -> ScoredFinding:
        """
        Score AI-only findings (no algorithmic verification)

        Base AI find confidence calculated dynamically based on report quality:
        - Function name present: +10%
        - Specific description present: +10%
        - Root cause analysis present: +10%
        - Trigger conditions present: +5%
        """
        factors: Dict[ConfidenceFactor, bool] = {}
        contributions: Dict[ConfidenceFactor, float] = {}

        # AI-only confirmation - Base score
        factors[ConfidenceFactor.AI_CONFIRMED] = True
        contributions[ConfidenceFactor.AI_CONFIRMED] = CONFIDENCE_WEIGHTS[
            ConfidenceFactor.AI_CONFIRMED
        ]

        # AI report quality bonus
        ai_quality_bonus = 0.0

        # Specific function name
        if ai_finding.get('function'):
            ai_quality_bonus += 0.10

        # Detailed description
        description = ai_finding.get('description', '')
        if description and len(description) > 50:
            ai_quality_bonus += 0.10

        # Root cause analysis
        if ai_finding.get('root_cause') or 'root cause' in description.lower():
            ai_quality_bonus += 0.10

        # Trigger conditions
        if ai_finding.get('trigger') or 'trigger' in description.lower():
            ai_quality_bonus += 0.05

        # Mitigation suggestions
        if ai_finding.get('mitigation') or 'mitigation' in description.lower():
            ai_quality_bonus += 0.05

        # Initialize other factors as False
        for factor in ConfidenceFactor:
            if factor not in factors:
                factors[factor] = False
                contributions[factor] = 0.0

        total = sum(contributions.values()) + ai_quality_bonus

        # Generate explanation
        explanation_parts = ["AI Report"]
        if ai_quality_bonus > 0:
            explanation_parts.append(f"Quality Bonus({ai_quality_bonus:.0%})")
        explanation = " ".join(explanation_parts)

        confidence = ConfidenceScore(
            total_score=min(total, 1.0),
            level="",
            factors=factors,
            factor_contributions=contributions,
            explanation=explanation
        )

        # Parse vulnerability type
        vuln_type_str = ai_finding.get('type', 'BUFFER_OVERFLOW')
        # Handle format variations
        vuln_type_str = vuln_type_str.upper().replace(' ', '_').replace('-', '_')
        try:
            vuln_type = VulnType[vuln_type_str]
        except KeyError:
            # Fuzzy match backup
            vuln_type = VulnType.BUFFER_OVERFLOW
            for vt in VulnType:
                if vt.name in vuln_type_str or vuln_type_str in vt.name:
                    vuln_type = vt
                    break

        return ScoredFinding(
            finding_type="AI",
            vuln_type=vuln_type,
            severity=ai_finding.get('severity', 'Medium'),
            location=ai_finding.get('address', 0),
            func_name=ai_finding.get('function', ''),
            confidence=confidence,
            raw_finding=ai_finding,
            sources=["ai_agent"],
            ai_analysis=ai_finding.get('description', ''),
            poc_path=ai_finding.get('poc_path'),
            harness_path=ai_finding.get('harness_path')
        )

    def _detect_bounds_check(self, steps: List[TaintStep]) -> bool:
        """Detect presence of bounds checking in taint path"""
        bounds_check_patterns = ['cmp', 'test', 'jae', 'jbe', 'ja', 'jb', 'jle', 'jge']
        for step in steps:
            insn = step.instruction.lower() if step.instruction else ""
            for pattern in bounds_check_patterns:
                if pattern in insn:
                    return True
        return False

    def _generate_explanation(self, factors: Dict[ConfidenceFactor, bool],
                               contributions: Dict[ConfidenceFactor, float]) -> str:
        """Generate scoring explanation"""
        parts = []
        for factor, present in factors.items():
            if present:
                weight = contributions.get(factor, 0)
                parts.append(f"+{factor.value}({weight:.0%})")
        return " ".join(parts) if parts else "No confidence factors"

    def aggregate_and_rank(self, taint_engine: 'TaintEngine',
                           ai_report: Optional[Dict] = None,
                           extra_findings: Optional[List] = None) -> List[ScoredFinding]:
        """
        Aggregate all findings and sort by confidence

        Args:
            taint_engine: Taint engine (contains all algorithmic findings)
            ai_report: AI analysis report (optional)
            extra_findings: List of extra findings (e.g., cross-function analysis)

        Returns:
            List of findings in descending order of confidence
        """
        self.scored_findings.clear()

        # Load AI findings for cross-validation
        if ai_report:
            self.add_ai_findings(ai_report)

        # Track processed addresses and function names to avoid duplicates
        processed_addrs: Set[int] = set()
        processed_funcs: Set[str] = set()

        # Helper: Get AI analysis text by address or function name
        def get_ai_text(addr: int, func_name: str = "") -> Optional[str]:
            if addr in self.ai_findings:
                return self.ai_findings[addr].get('description', '')
            if func_name and func_name in self.ai_findings_by_func:
                return self.ai_findings_by_func[func_name].get('description', '')
            return None

        # 0. Process extra findings (Prioritize already generated VulnFinding)
        if extra_findings:
            for f in extra_findings:
                addr = f.sink.addr if getattr(f, 'sink', None) else 0
                func_name = getattr(f.taint_path, 'func_name', '') if getattr(f, 'taint_path', None) else ''
                if addr and addr not in processed_addrs:
                    if f.taint_path:
                        ai_text = get_ai_text(addr, func_name)
                        scored = self.score_taint_path(f.taint_path, ai_analysis=ai_text)
                        # Propagate paths
                        scored.poc_path = getattr(f, 'poc_path', None)
                        scored.harness_path = getattr(f, 'harness_path', None)
                        self.scored_findings.append(scored)
                        processed_addrs.add(addr)
                        if func_name:
                            processed_funcs.add(func_name)

        # 1. Score taint path findings
        for path in taint_engine.taint_paths:
            addr = path.sink.addr if path.sink else 0
            func_name = getattr(path, 'func_name', '') or ''
            if addr and addr not in processed_addrs:
                ai_text = get_ai_text(addr, func_name)
                scored = self.score_taint_path(path, ai_analysis=ai_text)
                self.scored_findings.append(scored)
                processed_addrs.add(addr)
                if func_name:
                    processed_funcs.add(func_name)

        # 2. Score memory vulnerability findings
        for finding in taint_engine.memory_findings:
            func_name = getattr(finding, 'func_name', '') or ''
            if finding.vuln_addr not in processed_addrs:
                ai_text = get_ai_text(finding.vuln_addr, func_name)
                scored = self.score_memory_finding(finding, ai_analysis=ai_text)
                self.scored_findings.append(scored)
                processed_addrs.add(finding.vuln_addr)
                if func_name:
                    processed_funcs.add(func_name)

        # 3. Score integer overflow findings
        for finding in taint_engine.integer_overflow_findings:
            if finding.alloc_addr not in processed_addrs:
                ai_text = get_ai_text(finding.alloc_addr, finding.func_name)
                scored = self.score_integer_overflow(finding, ai_analysis=ai_text)
                self.scored_findings.append(scored)
                processed_addrs.add(finding.alloc_addr)
                if finding.func_name:
                    processed_funcs.add(finding.func_name)

        # 4. Add AI-only findings (By address)
        for addr, ai_finding in self.ai_findings.items():
            if addr not in processed_addrs:
                func_name = ai_finding.get('function', '')
                if func_name and func_name in processed_funcs:
                    continue
                scored = self.score_ai_only_finding(ai_finding)
                self.scored_findings.append(scored)
                processed_addrs.add(addr)
                if func_name:
                    processed_funcs.add(func_name)

        # 5. Add AI-only findings (By function name)
        for func_name, ai_finding in self.ai_findings_by_func.items():
            if func_name not in processed_funcs:
                addr = ai_finding.get('address', 0)
                if addr and addr in processed_addrs:
                    continue
                scored = self.score_ai_only_finding(ai_finding)
                self.scored_findings.append(scored)
                processed_funcs.add(func_name)
                if addr:
                    processed_addrs.add(addr)

        # Sort by confidence (descending)
        self.scored_findings.sort(key=lambda x: x.confidence.total_score, reverse=True)

        # Segregate false positives (exclude from subsequent filters)
        self.false_positives = [f for f in self.scored_findings if getattr(f, 'is_false_positive', False)]
        active_findings = [f for f in self.scored_findings if not getattr(f, 'is_false_positive', False)]

        pre_filter_count = len(active_findings)

        # Filter low confidence findings
        if self.min_threshold > 0:
            algo_only = [f for f in active_findings if 'taint_engine' in f.sources and 'ai_agent' not in f.sources]
            ai_only = [f for f in active_findings if 'ai_agent' in f.sources and 'taint_engine' not in f.sources]
            cross_validated = [f for f in active_findings if 'taint_engine' in f.sources and 'ai_agent' in f.sources]
            other_sources = [f for f in active_findings if 'taint_engine' not in f.sources and 'ai_agent' not in f.sources]

            filtered_algo = [f for f in algo_only if f.confidence.total_score >= self.min_threshold]
            # Lower threshold for AI-only findings (0.15)
            ai_min_threshold = min(self.min_threshold * 0.5, 0.15)
            filtered_ai = [f for f in ai_only if f.confidence.total_score >= ai_min_threshold]
            # cross-validated findings are always kept
            filtered_cross = cross_validated
            filtered_other = [f for f in other_sources if f.confidence.total_score >= self.min_threshold]

            self.scored_findings = sorted(filtered_algo + filtered_ai + filtered_cross + filtered_other, key=lambda x: x.confidence.total_score, reverse=True)
        else:
            self.scored_findings = sorted(active_findings, key=lambda x: x.confidence.total_score, reverse=True)

        self.filtered_count = pre_filter_count - len(self.scored_findings)
        return self.scored_findings

    def print_ranked_report(self, top_n: int = 20) -> None:
        """Print confidence-ranked vulnerability report"""
        print("\n" + "=" * 70)
        print(" CONFIDENCE-RANKED VULNERABILITY REPORT")
        print("=" * 70)

        # Display filter statistics
        filtered_count = getattr(self, 'filtered_count', 0)
        false_positive_count = len(getattr(self, 'false_positives', []))
        total_active = len(self.scored_findings)
        original_count = total_active + filtered_count + false_positive_count

        if original_count > 0:
            print(f"\n  Filter Summary:")
            print(f"    Original findings: {original_count}")
            if false_positive_count > 0:
                print(f"    Marked as false positive: {false_positive_count}")
            if filtered_count > 0:
                print(f"    Filtered (low confidence): {filtered_count}")
            print(f"    Remaining findings: {total_active}")

        if not self.scored_findings:
            if false_positive_count > 0:
                print("\n  All findings were marked as false positives by AI review.")
            elif filtered_count > 0:
                print("\n  All findings were filtered due to low confidence scores.")
            else:
                print("\n  No findings to report.")
            return

        # Classification statistics
        algo_count = sum(1 for f in self.scored_findings if 'taint_engine' in f.sources)
        ai_only_count = sum(1 for f in self.scored_findings if 'ai_agent' in f.sources and 'taint_engine' not in f.sources)
        cross_validated = sum(1 for f in self.scored_findings if f.confidence.factors.get(ConfidenceFactor.AI_CONFIRMED, False))

        displayed_findings = self.scored_findings[:top_n]

        for i, finding in enumerate(displayed_findings, 1):
            conf = finding.confidence
            is_false_positive = getattr(finding, 'is_false_positive', False)
            review_reasons = getattr(finding, 'review_reasons', None)

            # Adjust icons and labels based on AI review
            if is_false_positive:
                level_icon = "[FP]"
                conf_level = "FALSE POSITIVE"
                conf_percent = "0%"
            else:
                level_icon = {
                    "Confirmed": "[!!!]",
                    "High": "[!! ]",
                    "Medium": "[!  ]",
                    "Low": "[?  ]",
                    "Suspicious": "[.  ]"
                }.get(conf.level, "[   ]")
                conf_level = conf.level
                conf_percent = f"{conf.total_score:.0%}"

            source_tag = " [AI-ONLY]" if 'ai_agent' in finding.sources and 'taint_engine' not in finding.sources else ""
            fp_tag = " [FALSE POSITIVE]" if is_false_positive else ""

            print(f"\n{level_icon} #{i} [{conf_level} {conf_percent}] "
                  f"{finding.vuln_type.name}{source_tag}{fp_tag}")

            if finding.location:
                print(f"    Location: 0x{finding.location:x} in {finding.func_name}")
            elif finding.func_name:
                print(f"    Function: {finding.func_name}")

            if finding.poc_path:
                print(f"    PoC: {finding.poc_path}")
            if finding.harness_path:
                print(f"    Harness: {finding.harness_path}")

            print(f"    Type: {finding.finding_type} | Severity: {finding.severity}")
            print(f"    Sources: {', '.join(finding.sources)}")
            print(f"    Factors: {conf.explanation}")

            # Display false positive reason if present
            if is_false_positive and review_reasons:
                if isinstance(review_reasons, str):
                    reason_text = review_reasons[:100] + "..." if len(review_reasons) > 100 else review_reasons
                    print(f"    FP Reason: {reason_text}")
                elif isinstance(review_reasons, list):
                    print(f"    FP Reasons: {', '.join(str(r) for r in review_reasons[:3])}")

            if finding.ai_analysis:
                ai_text = finding.ai_analysis
                if len(ai_text) > 200:
                    ai_text = ai_text[:200] + "..."
                print(f"    [AI] {ai_text}")

        if len(self.scored_findings) > top_n:
            print(f"\n  ... and {len(self.scored_findings) - top_n} more findings")

        # Result statistics
        print("\n" + "=" * 70)
        print(f"\n[Summary]")
        print(f"    Total: {len(self.scored_findings)} findings")
        print(f"    Algorithm: {algo_count} | AI-Only: {ai_only_count} | Cross-validated: {cross_validated}")
        if ai_only_count > 0:
            print(f"\n[Note] AI-Only findings require manual verification")
        print("=" * 70)
