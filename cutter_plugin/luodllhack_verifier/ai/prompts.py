# -*- coding: utf-8 -*-
"""AI prompt templates for vulnerability verification."""

from typing import Dict, List
from ..analysis.report_parser import Finding
from ..analysis.context_extractor import VerificationContext
from ..analysis.vuln_checkers import AnalysisResult


class PromptBuilder:
    """Build prompts for AI vulnerability verification"""

    SYSTEM_PROMPT = """You are an expert binary security analyst specializing in vulnerability assessment.
Your task is to analyze code and determine if a reported vulnerability is a TRUE POSITIVE (real, exploitable) or FALSE POSITIVE (not exploitable).

Be rigorous and conservative:
- Only mark as TRUE POSITIVE if you see clear evidence of exploitability
- Consider mitigations, bounds checks, and error handling
- Provide detailed reasoning for your verdict"""

    VERIFICATION_TEMPLATE = """Analyze this vulnerability finding and determine if it's real.

<vulnerability>
Type: {vuln_type}
Address: 0x{address:x}
Function: {function}
Sink API: {sink_api}
CWE: {cwe_id}
Original Confidence: {confidence:.0%}
</vulnerability>

<decompiled_code>
{decompiled}
</decompiled_code>

<disassembly_snippet>
{disassembly}
</disassembly_snippet>

<static_analysis>
Bounds Check Detected: {has_bounds_check}
Null Check Detected: {has_null_check}
Safe Function Used: {safe_function_used}
Error Handling Present: {has_error_handling}
Stack Cookie: {has_stack_cookie}
Dangerous APIs Found: {dangerous_apis}
Protections: {protections}
Notes: {notes}
</static_analysis>

<cross_references>
Callers (who calls this function): {callers}
Callees (what this function calls): {callees}
</cross_references>

Based on the above analysis, determine:
1. Is this a TRUE POSITIVE (exploitable vulnerability) or FALSE POSITIVE?
2. Your confidence level (0.0 to 1.0)
3. Detailed reasoning
4. Exploitability assessment if TRUE POSITIVE

Respond with ONLY valid JSON in this exact format:
{{
    "verdict": "true_positive" or "false_positive" or "inconclusive",
    "confidence": 0.0 to 1.0,
    "reasoning": "detailed explanation of your verdict",
    "exploitability": "high" or "medium" or "low" or "none",
    "key_evidence": ["list", "of", "key", "observations"],
    "mitigations_found": ["list", "of", "mitigations", "if", "any"]
}}"""

    # Type-specific analysis hints
    TYPE_HINTS = {
        "BUFFER_OVERFLOW": """
For BUFFER_OVERFLOW, specifically check:
- Is the destination buffer size known and checked?
- Is there length validation before copy operations?
- Are safe alternatives used (strcpy_s, strncpy with proper size)?
- Can attacker control the source data length?""",

        "USE_AFTER_FREE": """
For USE_AFTER_FREE, specifically check:
- Is the pointer set to NULL after free()?
- Is there definite use of the pointer after free()?
- Could the pointer be reassigned between free and use?
- Is there reference counting that prevents UAF?""",

        "DOUBLE_FREE": """
For DOUBLE_FREE, specifically check:
- Is there conditional freeing that could execute twice?
- Is the pointer nullified after first free?
- Are there multiple code paths that both free the same pointer?""",

        "FORMAT_STRING": """
For FORMAT_STRING, specifically check:
- Is the format string a constant/literal? (If so, likely FALSE POSITIVE)
- Can user input reach the format string parameter?
- Are there any format specifiers (%s, %n, %x) that could be exploited?""",

        "INTEGER_OVERFLOW": """
For INTEGER_OVERFLOW, specifically check:
- Is the result used for memory allocation or array indexing?
- Are there overflow checks before the arithmetic?
- Could attacker control the operands?
- Is SafeInt or similar library used?""",

        "COMMAND_INJECTION": """
For COMMAND_INJECTION, specifically check:
- Is user input directly concatenated into command string?
- Is there any input sanitization or escaping?
- Are shell metacharacters filtered?""",
    }

    @classmethod
    def build_prompt(cls, finding: Finding, context: VerificationContext,
                     analysis: AnalysisResult) -> str:
        """Build complete verification prompt"""

        # Format callers and callees
        callers = cls._format_xrefs(context.xrefs_to, max_count=5)
        callees = cls._format_xrefs(context.xrefs_from, max_count=5)

        # Truncate code if too long
        decompiled = cls._truncate(context.decompiled, 3000)
        disassembly = cls._truncate(context.disassembly, 1500)

        # Build main prompt
        prompt = cls.VERIFICATION_TEMPLATE.format(
            vuln_type=finding.vuln_type,
            address=finding.address,
            function=finding.function or context.function_name,
            sink_api=finding.sink_api or "unknown",
            cwe_id=finding.cwe_id or "N/A",
            confidence=finding.confidence,
            decompiled=decompiled or "(decompilation not available)",
            disassembly=disassembly or "(disassembly not available)",
            has_bounds_check="Yes" if analysis.has_bounds_check else "No",
            has_null_check="Yes" if analysis.has_null_check else "No",
            safe_function_used="Yes" if analysis.safe_function_used else "No",
            has_error_handling="Yes" if analysis.has_error_handling else "No",
            has_stack_cookie="Yes" if analysis.has_stack_cookie else "No",
            dangerous_apis=", ".join(analysis.dangerous_apis_found) or "none detected",
            protections=", ".join(analysis.protections) or "none detected",
            notes="; ".join(analysis.notes) or "none",
            callers=callers or "none found",
            callees=callees or "none found",
        )

        # Add type-specific hints
        type_hint = cls.TYPE_HINTS.get(finding.vuln_type, "")
        if type_hint:
            prompt = prompt + "\n" + type_hint

        return prompt

    @classmethod
    def get_system_prompt(cls) -> str:
        """Get system prompt for AI"""
        return cls.SYSTEM_PROMPT

    @staticmethod
    def _format_xrefs(xrefs: List[Dict], max_count: int = 5) -> str:
        """Format cross-references for prompt"""
        if not xrefs:
            return ""
        items = []
        for xref in xrefs[:max_count]:
            addr = xref.get("from", xref.get("addr", 0))
            name = xref.get("fcn_name", xref.get("name", ""))
            if name:
                items.append(f"0x{addr:x} ({name})")
            else:
                items.append(f"0x{addr:x}")
        result = ", ".join(items)
        if len(xrefs) > max_count:
            result += f" (+{len(xrefs) - max_count} more)"
        return result

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        """Truncate text to max length"""
        if not text:
            return ""
        if len(text) <= max_len:
            return text
        return text[:max_len] + "\n... (truncated)"
