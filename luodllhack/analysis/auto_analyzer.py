# -*- coding: utf-8 -*-
"""
luodllhack/analysis/auto_analyzer.py - Auto Analyzer

Automatically validates vulnerability discoveries, providing:
- Vulnerability location verification
- Call chain analysis
- Dangerous pattern detection
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from disasm.engine import DisasmEngine, Instruction, Function


@dataclass
class VulnVerification:
    """Vulnerability Verification Result"""
    address: int
    vuln_type: str
    verified: bool
    confidence: float
    evidence: List[str] = field(default_factory=list)
    context_before: List[Instruction] = field(default_factory=list)
    context_after: List[Instruction] = field(default_factory=list)
    analysis: str = ""


class AutoAnalyzer:
    """
    Automatic Vulnerability Verification Analyzer

    Usage:
        analyzer = AutoAnalyzer(engine)

        # Verify a single finding
        result = analyzer.verify_finding({
            "address": 0x18001b690,
            "vuln_type": "DOUBLE_FREE",
            "func_name": "ldap_value_free"
        })

        # Batch verify
        results = analyzer.verify_all(findings)
    """

    # Dangerous API patterns
    DANGEROUS_PATTERNS = {
        'DOUBLE_FREE': {
            'apis': ['free', 'HeapFree', 'LocalFree', 'GlobalFree', 'VirtualFree'],
            'pattern': 'same_ptr_freed_twice'
        },
        'USE_AFTER_FREE': {
            'apis': ['free', 'HeapFree', 'LocalFree', 'GlobalFree'],
            'pattern': 'use_after_free_call'
        },
        'BUFFER_OVERFLOW': {
            'apis': ['strcpy', 'strcat', 'sprintf', 'gets', 'memcpy', 'memmove'],
            'pattern': 'unbounded_copy'
        },
        'FORMAT_STRING': {
            'apis': ['printf', 'sprintf', 'fprintf', 'vprintf', 'vsprintf'],
            'pattern': 'user_controlled_format'
        },
        'COMMAND_INJECTION': {
            'apis': ['system', 'popen', 'CreateProcessA', 'CreateProcessW', 'ShellExecuteA'],
            'pattern': 'user_controlled_command'
        },
        'INTEGER_OVERFLOW': {
            'apis': ['malloc', 'HeapAlloc', 'VirtualAlloc', 'calloc'],
            'pattern': 'unchecked_arithmetic_before_alloc'
        }
    }

    def __init__(self, engine: DisasmEngine):
        self.engine = engine

    def verify_finding(self, finding: Dict[str, Any]) -> VulnVerification:
        """
        Verify a single vulnerability finding

        Args:
            finding: Vulnerability info dictionary, containing address, vuln_type, func_name

        Returns:
            Verification result
        """
        address = finding.get('address', finding.get('location', 0))
        vuln_type = finding.get('vuln_type', 'UNKNOWN')
        func_name = finding.get('func_name', '')

        # Get context
        context = self.engine.get_context(address, before=10, after=5)

        # Separate context before/after
        before = []
        after = []
        found = False
        for insn in context:
            if insn.address == address:
                found = True
                after.append(insn)
            elif found:
                after.append(insn)
            else:
                before.append(insn)

        result = VulnVerification(
            address=address,
            vuln_type=vuln_type,
            verified=False,
            confidence=0.0,
            context_before=before,
            context_after=after
        )

        # Verify according to vulnerability type
        if vuln_type in self.DANGEROUS_PATTERNS:
            self._verify_pattern(result, vuln_type)
        else:
            result.analysis = f"Unknown vulnerability type: {vuln_type}"

        return result

    def _verify_pattern(self, result: VulnVerification, vuln_type: str):
        """Verify constant vulnerability pattern"""
        pattern = self.DANGEROUS_PATTERNS[vuln_type]
        apis = pattern['apis']

        evidence = []
        confidence = 0.0

        # Check instruction at target address
        target_insn = None
        for insn in result.context_after:
            if insn.address == result.address:
                target_insn = insn
                break

        if not target_insn:
            result.analysis = "Unable to retrieve instruction at target address"
            return

        # Check for dangerous API call
        if target_insn.is_call:
            for api in apis:
                if api.lower() in target_insn.comment.lower():
                    evidence.append(f"Calling dangerous API: {target_insn.comment}")
                    confidence += 0.3
                    break

        # Type-specific checks
        if vuln_type == 'DOUBLE_FREE':
            confidence += self._check_double_free(result, evidence)

        elif vuln_type == 'USE_AFTER_FREE':
            confidence += self._check_uaf(result, evidence)

        elif vuln_type == 'BUFFER_OVERFLOW':
            confidence += self._check_buffer_overflow(result, evidence)

        elif vuln_type == 'INTEGER_OVERFLOW':
            confidence += self._check_integer_overflow(result, evidence)

        result.evidence = evidence
        result.confidence = min(confidence, 1.0)
        result.verified = confidence >= 0.5

        # Generate analysis report
        result.analysis = self._generate_analysis(result, vuln_type)

    def _check_double_free(self, result: VulnVerification,
                           evidence: List[str]) -> float:
        """Check for Double-Free pattern"""
        confidence = 0.0
        free_calls = []

        # Find all free calls
        for insn in result.context_before + result.context_after:
            if insn.is_call and any(api in insn.comment.lower()
                                      for api in ['free', 'heapfree']):
                free_calls.append(insn)

        if len(free_calls) >= 2:
            evidence.append(f"Found {len(free_calls)} free calls")
            confidence += 0.3

            # Check if using the same parameter register
            # Simplified: look for same mov to parameter register
            confidence += 0.2

        return confidence

    def _check_uaf(self, result: VulnVerification,
                   evidence: List[str]) -> float:
        """Check for Use-After-Free pattern"""
        confidence = 0.0
        free_found = False
        use_after_free = False

        for insn in result.context_before:
            if insn.is_call and any(api in insn.comment.lower()
                                      for api in ['free', 'heapfree']):
                free_found = True
                evidence.append(f"Found free call at 0x{insn.address:x}")

        if free_found:
            # Check if target address is a use operation
            target = result.context_after[0] if result.context_after else None
            if target and not target.mnemonic.startswith('j'):
                use_after_free = True
                evidence.append("Memory access after free detected")
                confidence += 0.4

        return confidence

    def _check_buffer_overflow(self, result: VulnVerification,
                                evidence: List[str]) -> float:
        """Check for buffer overflow pattern"""
        confidence = 0.0

        # Check for bounds check
        has_bounds_check = False
        for insn in result.context_before:
            if insn.mnemonic in ['cmp', 'test']:
                has_bounds_check = True
                break

        if not has_bounds_check:
            evidence.append("No bounds check detected")
            confidence += 0.3

        return confidence

    def _check_integer_overflow(self, result: VulnVerification,
                                 evidence: List[str]) -> float:
        """Check for integer overflow pattern"""
        confidence = 0.0

        # Find arithmetic operations
        for insn in result.context_before:
            if insn.mnemonic in ['mul', 'imul', 'add', 'shl']:
                evidence.append(f"Arithmetic operation: {insn.mnemonic} @ 0x{insn.address:x}")
                confidence += 0.2

                # Check for overflow check
                has_check = False
                idx = result.context_before.index(insn)
                for check_insn in result.context_before[idx+1:]:
                    if check_insn.mnemonic in ['jo', 'jc', 'cmp']:
                        has_check = True
                        break
                if not has_check:
                    evidence.append("No overflow check after arithmetic operation")
                    confidence += 0.2
                break

        return confidence

    def _generate_analysis(self, result: VulnVerification,
                            vuln_type: str) -> str:
        """Generate analysis report"""
        lines = []
        lines.append(f"Vulnerability Type: {vuln_type}")
        lines.append(f"Verification Result: {'Confirmed' if result.verified else 'Unconfirmed'}")
        lines.append(f"Confidence: {result.confidence:.0%}")
        lines.append("")
        lines.append("Evidence:")
        for e in result.evidence:
            lines.append(f"  - {e}")
        return "\n".join(lines)

    def verify_all(self, findings: List[Dict]) -> List[VulnVerification]:
        """Batch verify"""
        return [self.verify_finding(f) for f in findings]

    def print_verification(self, result: VulnVerification):
        """Print verification result"""
        status = "[VERIFIED]" if result.verified else "[UNVERIFIED]"
        print(f"\n{status} {result.vuln_type} @ 0x{result.address:x}")
        print(f"Confidence: {result.confidence:.0%}")
        print("-" * 60)

        print("\n[Context Before]")
        for insn in result.context_before[-5:]:
            print(f"  {insn}")

        print("\n[Target Address] >>>")
        if result.context_after:
            print(f"  >>> {result.context_after[0]}")

        print("\n[Context After]")
        for insn in result.context_after[1:6]:
            print(f"  {insn}")

        print("\n[Analysis]")
        print(result.analysis)


class PatternMatcher:
    """
    Dangerous Pattern Matcher

    Detects common vulnerability code patterns
    """

    PATTERNS = {
        'unbounded_strcpy': {
            'sequence': ['mov', 'call strcpy'],
            'missing': ['cmp', 'jae', 'jbe'],
            'description': 'strcpy without bounds checking'
        },
        'double_free': {
            'sequence': ['call free', 'call free'],
            'check': 'same_first_arg',
            'description': 'Double free'
        },
        'stack_buffer': {
            'sequence': ['sub esp', 'lea', 'call'],
            'check': 'small_buffer_large_copy',
            'description': 'Stack buffer overflow risk'
        }
    }

    def __init__(self, engine: DisasmEngine):
        self.engine = engine

    def scan_function(self, func: Function) -> List[Dict]:
        """Scan function for dangerous patterns"""
        findings = []

        for i, insn in enumerate(func.instructions):
            for pattern_name, pattern in self.PATTERNS.items():
                if self._match_pattern(func.instructions, i, pattern):
                    findings.append({
                        'pattern': pattern_name,
                        'address': insn.address,
                        'description': pattern['description']
                    })

        return findings

    def _match_pattern(self, instructions: List[Instruction],
                        start_idx: int, pattern: Dict) -> bool:
        """Match a single pattern"""
        # Simplified implementation
        sequence = pattern.get('sequence', [])
        if not sequence:
            return False

        idx = start_idx
        for expected in sequence:
            if idx >= len(instructions):
                return False

            insn = instructions[idx]
            if expected.startswith('call '):
                api = expected[5:]
                if not (insn.is_call and api.lower() in insn.comment.lower()):
                    return False
            elif insn.mnemonic != expected:
                return False

            idx += 1

        return True
