# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/__init__.py

Enhanced Vulnerability Mining Module - Improves detection accuracy and coverage

Design Principles:
    1. Do not break existing code - All enhancement functions are integrated through the combination pattern
    2. Optionally enabled - Each enhancement module can be independently toggled
    3. Incremental improvement - Gradually enhance detection capabilities

Modules:
    Phase 1 - Reduce False Positives:
        - BoundsChecker: Bounds check detection
        - SanitizerDetector: Sanitization function identification
        - EnhancedConfidence: Enhanced confidence computation

    Phase 2 - Expand Detection Surface:
        - IndirectCallTracker: Indirect call tracking
        - CallbackAnalyzer: Callback function analysis
        - StructFieldTracker: Structure field tracking

    Phase 3 - Deep Verification:
        - ConstraintCollector: Constraint collection and propagation
        - HarnessGenerator: Automatic harness generation
"""

from .bounds_checker import BoundsChecker, BoundsCheckResult
from .sanitizer import SanitizerDetector, SanitizeEvent
from .confidence import EnhancedConfidenceScorer, ConfidenceFactors

# Phase 2 - Expand Detection Surface
from .indirect_call import IndirectCallTracker, IndirectCallInfo
from .callback import CallbackAnalyzer, CallbackRegistration
from .struct_tracker import StructFieldTracker, FieldAccess, FieldVulnerability

# Phase 3 - Deep Verification
from .constraints import ConstraintCollector, ConstraintSet, PathConstraint, ValueConstraint
from .harness import HarnessGenerator, HarnessConfig, GeneratedHarness

__all__ = [
    # Phase 1 - Reduce False Positives
    'BoundsChecker',
    'BoundsCheckResult',
    'SanitizerDetector',
    'SanitizeEvent',
    'EnhancedConfidenceScorer',
    'ConfidenceFactors',
    # Phase 2 - Expand Detection Surface
    'IndirectCallTracker',
    'IndirectCallInfo',
    'CallbackAnalyzer',
    'CallbackRegistration',
    'StructFieldTracker',
    'FieldAccess',
    'FieldVulnerability',
    # Phase 3 - Deep Verification
    'ConstraintCollector',
    'ConstraintSet',
    'PathConstraint',
    'ValueConstraint',
    'HarnessGenerator',
    'HarnessConfig',
    'GeneratedHarness',
    # Unified Entry Point
    'EnhancedAnalyzer',
    'SinkAnalysisResult',
]


class EnhancedAnalyzer:
    """
    Enhanced Analyzer - Unified Entry Point

    Integrates all enhancement modules to provide a unified analysis interface

    Usage:
        from luodllhack.analysis.enhanced import EnhancedAnalyzer

        # Create enhanced analyzer
        analyzer = EnhancedAnalyzer(binary_data, image_base)

        # Analyze sink point
        result = analyzer.analyze_sink(
            sink_addr=0x1000,
            tainted_reg='rcx',
            taint_path=path
        )

        print(f"Real confidence: {result.confidence}")
        print(f"Has bounds check: {result.has_bounds_check}")
        print(f"Was sanitized: {result.was_sanitized}")
    """

    def __init__(self, binary_data: bytes, image_base: int,
                 arch: str = "x64", pe=None, import_map: dict = None):
        """
        Initialize the enhanced analyzer

        Args:
            binary_data: Binary data
            image_base: Image base address
            arch: Architecture (x64/x86)
            pe: pefile object (optional)
            import_map: Import table map {addr: api_name} (optional)
        """
        self.binary_data = binary_data
        self.image_base = image_base
        self.arch = arch
        self.pe = pe
        self.import_map = import_map or {}

        # Phase 1 - Reduce False Positives
        self.bounds_checker = BoundsChecker(binary_data, image_base, arch, pe)
        self.sanitizer_detector = SanitizerDetector()
        self.confidence_scorer = EnhancedConfidenceScorer()

        # Phase 2 - Expand Detection Surface
        self.indirect_call_tracker = IndirectCallTracker(binary_data, image_base, arch, pe)
        self.callback_analyzer = CallbackAnalyzer(binary_data, image_base, import_map, arch)
        self.struct_tracker = StructFieldTracker(binary_data, image_base, arch, pe)

        # Phase 3 - Deep Verification
        self.constraint_collector = ConstraintCollector()
        self.harness_generator = HarnessGenerator()

        # Analysis state
        self.sanitize_events: list = []
        self.indirect_calls: list = []
        self.callback_registrations: list = []
        self.field_vulnerabilities: list = []

    def analyze_sink(self, sink_addr: int, tainted_reg: str,
                      taint_path=None, call_trace: list = None) -> 'SinkAnalysisResult':
        """
        Analyze the real risk of a sink point

        Args:
            sink_addr: Sink call address
            tainted_reg: Tainted register
            taint_path: Taint path (TaintPath object)
            call_trace: Call trace (used to detect sanitization)

        Returns:
            SinkAnalysisResult containing real confidence and analysis details
        """
        factors = ConfidenceFactors()

        # 1. Bounds check detection
        bounds_result = self.bounds_checker.check_before_sink(
            sink_addr, tainted_reg
        )
        factors.has_bounds_check = bounds_result.has_check
        factors.bounds_check_details = bounds_result

        # 2. Sanitization function detection
        if call_trace:
            sanitize_result = self.sanitizer_detector.check_sanitized(
                tainted_reg, call_trace
            )
            factors.was_sanitized = sanitize_result.is_sanitized
            factors.sanitize_details = sanitize_result

        # 3. Calculate real confidence
        base_confidence = 0.9 if taint_path else 0.7
        real_confidence = self.confidence_scorer.calculate(
            base_confidence, factors
        )

        return SinkAnalysisResult(
            sink_addr=sink_addr,
            tainted_reg=tainted_reg,
            confidence=real_confidence,
            factors=factors,
            has_bounds_check=factors.has_bounds_check,
            was_sanitized=factors.was_sanitized,
            analysis_notes=self._generate_notes(factors)
        )

    def _generate_notes(self, factors: 'ConfidenceFactors') -> list:
        """Generate analysis notes"""
        notes = []

        if factors.has_bounds_check:
            notes.append(f"Detected bounds check @ 0x{factors.bounds_check_details.check_addr:x}")

        if factors.was_sanitized:
            notes.append(f"Data passed through sanitization function: {factors.sanitize_details.sanitizer_name}")

        if factors.has_null_check:
            notes.append("Detected null pointer check")

        return notes

    def record_api_call(self, api_name: bytes, addr: int,
                        tainted_args: list = None):
        """
        Record API call (used for sanitization function tracking)

        Called during TaintEngine analysis to record API calls
        """
        event = self.sanitizer_detector.check_api_call(
            api_name, addr, tainted_args or []
        )
        if event:
            self.sanitize_events.append(event)
            return event
        return None

    def analyze_function(self, func_addr: int, tainted_regs: set = None,
                          call_trace: list = None) -> 'FunctionAnalysisResult':
        """
        Deep analyze function - Integrates all detection modules

        Args:
            func_addr: Function address
            tainted_regs: Set of tainted registers
            call_trace: API call trace

        Returns:
            FunctionAnalysisResult
        """
        tainted_regs = tainted_regs or set()
        results = {
            'func_addr': func_addr,
            'indirect_calls': [],
            'callbacks': [],
            'field_vulns': [],
            'constraints': None,
            'findings': []
        }

        # Phase 2.1: Indirect call analysis
        indirect_calls = self.indirect_call_tracker.analyze_function(
            func_addr, max_instructions=500, tainted_regs=tainted_regs
        )
        results['indirect_calls'] = indirect_calls
        self.indirect_calls.extend(indirect_calls)

        # Detect dangerous indirect calls
        for ic in indirect_calls:
            if ic.is_tainted:
                results['findings'].append({
                    'type': 'TAINTED_INDIRECT_CALL',
                    'addr': ic.addr,
                    'risk': 'Critical',
                    'detail': f"Control flow can be hijacked by user data: {ic.target}"
                })

        # Phase 2.2: Callback function analysis
        callback_result = self.callback_analyzer.analyze_function(
            func_addr, tainted_regs, call_trace
        )
        results['callbacks'] = callback_result.registrations
        self.callback_registrations.extend(callback_result.registrations)

        for cb in callback_result.registrations:
            if cb.is_callback_tainted:
                results['findings'].append({
                    'type': 'TAINTED_CALLBACK',
                    'addr': cb.addr,
                    'risk': cb.risk_level,
                    'detail': f"Callback function pointer is controllable: {cb.api_name}"
                })

        # Phase 2.3: Structure field tracking
        field_accesses, field_vulns = self.struct_tracker.analyze_function(
            func_addr, tainted_regs
        )
        results['field_vulns'] = field_vulns
        self.field_vulnerabilities.extend(field_vulns)

        for fv in field_vulns:
            results['findings'].append({
                'type': fv.vuln_type,
                'addr': fv.addr,
                'risk': fv.risk_level,
                'detail': fv.description
            })

        # Phase 3.1: Collect constraints (for subsequent harness generation)
        results['constraints'] = self.constraint_collector.get_constraints()

        return FunctionAnalysisResult(**results)

    def generate_harness(self, vuln_addr: int, dll_path: str,
                        func_name: str = "", vuln_type: str = "buffer_overflow",
                        harness_type: str = "BASIC",
                        language: str = "c",
                        params: list = None) -> 'GeneratedHarness':
        """
        Generate test harness for a vulnerability

        Args:
            vuln_addr: Vulnerability address
            dll_path: DLL path
            func_name: Vulnerability function name
            vuln_type: Vulnerability type
            harness_type: Harness type (BASIC/FUZZING/REPRO)
            language: Language (c/python)
            params: Parameter list [{name, type, tainted}, ...]

        Returns:
            GeneratedHarness
        """
        from .harness import HarnessType, HarnessLanguage, FunctionSignature

        # Create function signature
        func_sig = FunctionSignature(
            name=func_name or f"vuln_{vuln_addr:x}",
            address=vuln_addr,
            return_type="int",
            params=params or [
                {'name': 'buffer', 'type': 'char*', 'tainted': True},
                {'name': 'size', 'type': 'int', 'tainted': False}
            ]
        )

        # Language mapping
        lang_map = {
            'c': HarnessLanguage.C,
            'python': HarnessLanguage.PYTHON,
            'ps1': HarnessLanguage.POWERSHELL
        }

        config = HarnessConfig(
            dll_path=dll_path,
            function=func_sig,
            harness_type=HarnessType[harness_type],
            language=lang_map.get(language, HarnessLanguage.C),
            constraints=self.constraint_collector.get_constraints().to_dict()
                        if self.constraint_collector.get_constraints() else {}
        )

        return self.harness_generator.generate(config)

    def get_summary(self) -> dict:
        """Get analysis summary"""
        dangerous_indirect = sum(1 for ic in self.indirect_calls if ic.is_tainted)
        dangerous_callbacks = sum(1 for cb in self.callback_registrations
                                   if cb.is_callback_tainted)

        return {
            'total_indirect_calls': len(self.indirect_calls),
            'dangerous_indirect_calls': dangerous_indirect,
            'total_callbacks': len(self.callback_registrations),
            'dangerous_callbacks': dangerous_callbacks,
            'field_vulnerabilities': len(self.field_vulnerabilities),
            'sanitize_events': len(self.sanitize_events),
            'constraints_collected': len(self.constraint_collector.constraints.all_constraints)
        }

    def reset(self):
        """Reset analysis state"""
        self.sanitize_events.clear()
        self.indirect_calls.clear()
        self.callback_registrations.clear()
        self.field_vulnerabilities.clear()
        self.constraint_collector.clear()


from dataclasses import dataclass, field
from typing import Optional, List, Any


@dataclass
class SinkAnalysisResult:
    """Sink Analysis Result"""
    sink_addr: int
    tainted_reg: str
    confidence: float
    factors: 'ConfidenceFactors'
    has_bounds_check: bool
    was_sanitized: bool
    analysis_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'sink_addr': f'0x{self.sink_addr:x}',
            'tainted_reg': self.tainted_reg,
            'confidence': round(self.confidence, 3),
            'has_bounds_check': self.has_bounds_check,
            'was_sanitized': self.was_sanitized,
            'notes': self.analysis_notes
        }


@dataclass
class FunctionAnalysisResult:
    """Function Deep Analysis Result"""
    func_addr: int
    indirect_calls: List[Any] = field(default_factory=list)
    callbacks: List[Any] = field(default_factory=list)
    field_vulns: List[Any] = field(default_factory=list)
    constraints: Any = None
    findings: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'func_addr': f'0x{self.func_addr:x}',
            'indirect_calls': len(self.indirect_calls),
            'callbacks': len(self.callbacks),
            'field_vulnerabilities': len(self.field_vulns),
            'findings': self.findings,
            'total_findings': len(self.findings)
        }

    def get_critical_findings(self) -> List[dict]:
        """Get critical findings"""
        return [f for f in self.findings if f.get('risk') == 'Critical']

    def get_high_risk_findings(self) -> List[dict]:
        """Get high risk findings"""
        return [f for f in self.findings if f.get('risk') in ('Critical', 'High')]
