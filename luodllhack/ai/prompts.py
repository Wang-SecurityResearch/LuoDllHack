# -*- coding: utf-8 -*-
"""
luodllhack/ai/prompts.py - AI Prompt Optimization System

Provides:
- VulnPatternDB: Vulnerability pattern knowledge base
- LayeredPromptBuilder: Layered analysis prompt builder
- StructuredOutputParser: Structured output parser
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import json
import re


class AnalysisStage(Enum):
    """Analysis Stage"""
    QUICK_SCAN = auto()       # Quick Scan
    DEEP_ANALYSIS = auto()    # Deep Analysis
    VULN_CONFIRM = auto()     # Vulnerability Confirmation
    POC_GENERATION = auto()   # PoC Generation


@dataclass
class VulnPattern:
    """Vulnerability Pattern"""
    cwe_id: str
    name: str
    description: str
    asm_patterns: List[str]           # Assembly code patterns
    api_indicators: List[str]         # Dangerous API indicators
    anti_patterns: List[str]          # Anti-patterns (security checks)
    verification_steps: List[str]     # Verification steps
    exploit_hints: List[str]          # Exploit hints
    false_positive_hints: List[str]   # False positive hints


class VulnPatternDB:
    """
    Vulnerability Pattern Knowledge Base

    Defines for each CWE:
    - Assembly/pseudocode patterns
    - API call characteristics
    - False positive indicators
    - Verification steps
    """

    def __init__(self):
        self.patterns: Dict[str, VulnPattern] = {}
        self._load_builtin_patterns()

    def _load_builtin_patterns(self):
        """Load built-in vulnerability patterns"""

        # CWE-120: Buffer Copy without Checking Size of Input
        self.patterns["CWE-120"] = VulnPattern(
            cwe_id="CWE-120",
            name="Buffer Copy without Size Check",
            description="Classic Buffer Overflow - copying data to buffer without validating size",
            asm_patterns=[
                "call strcpy/memcpy without prior cmp",
                "rep movs without size validation",
                "loop with unchecked counter writing to buffer",
                "mov [reg+offset], ... in loop without bounds check"
            ],
            api_indicators=[
                "strcpy", "strcat", "sprintf", "vsprintf",
                "gets", "scanf", "memcpy", "memmove",
                "lstrcpy", "lstrcpyA", "lstrcpyW",
                "wcscpy", "wcscat", "_mbscpy"
            ],
            anti_patterns=[
                "cmp reg, imm before copy (size check)",
                "jae/jbe conditional before write",
                "call to strlen before strcpy with comparison",
                "strncpy/strncat usage (bounded copy)"
            ],
            verification_steps=[
                "1. Trace buffer allocation size (look for malloc/alloca/sub rsp)",
                "2. Find the copy operation and its source",
                "3. Check if source size is validated before copy",
                "4. Verify no bounds check between source and destination",
                "5. Confirm attacker can control source data"
            ],
            exploit_hints=[
                "Calculate exact offset to overwrite return address",
                "Check for stack canaries (__security_cookie)",
                "Look for controllable data after overflow target",
                "Consider heap metadata corruption if heap buffer"
            ],
            false_positive_hints=[
                "Fixed-size source with smaller destination",
                "Input sanitization before copy",
                "Size check exists but in different basic block",
                "Bounded copy function used (strncpy, memcpy_s)"
            ]
        )

        # CWE-134: Use of Externally-Controlled Format String
        self.patterns["CWE-134"] = VulnPattern(
            cwe_id="CWE-134",
            name="Format String Vulnerability",
            description="User input used directly as format string parameter",
            asm_patterns=[
                "push user_buffer; call printf (no format string)",
                "mov rcx, user_input; call sprintf",
                "lea rax, [user_data]; push rax; call fprintf"
            ],
            api_indicators=[
                "printf", "fprintf", "sprintf", "snprintf",
                "vprintf", "vfprintf", "vsprintf", "vsnprintf",
                "syslog", "err", "warn", "wprintf"
            ],
            anti_patterns=[
                "push format_string_literal before user_input",
                "lea rcx, [static_format]; ... call printf",
                "format specifier in .rdata/.data section"
            ],
            verification_steps=[
                "1. Identify format function call",
                "2. Trace first argument (format string parameter)",
                "3. Check if format string comes from user input",
                "4. Verify no hardcoded format string prepended",
                "5. Test with %x%x%x%x to leak stack values"
            ],
            exploit_hints=[
                "Use %n to write to arbitrary memory",
                "Use %s to read from arbitrary memory",
                "Calculate stack offset to target address",
                "Consider Direct Parameter Access (%7$n)"
            ],
            false_positive_hints=[
                "Format string is a constant in data section",
                "Input is sanitized to remove % characters",
                "Only safe format specifiers used (%s, %d)"
            ]
        )

        # CWE-416: Use After Free
        self.patterns["CWE-416"] = VulnPattern(
            cwe_id="CWE-416",
            name="Use After Free",
            description="Memory accessed after being freed",
            asm_patterns=[
                "call free; ... mov/use same pointer",
                "call HeapFree; ... deref original reg",
                "store ptr in global; free; load global; use",
                "free in one path; use in another (conditional)"
            ],
            api_indicators=[
                "free", "HeapFree", "LocalFree", "GlobalFree",
                "VirtualFree", "CoTaskMemFree", "SysFreeString",
                "delete", "delete[]"
            ],
            anti_patterns=[
                "ptr = NULL immediately after free",
                "if (ptr) check before use after potential free path",
                "unique_ptr/shared_ptr usage (RAII)",
                "reference counting check before free"
            ],
            verification_steps=[
                "1. Identify memory allocation point",
                "2. Trace all free/release operations on that pointer",
                "3. Find any dereference after free",
                "4. Check for NULL assignment after free",
                "5. Verify use and free can occur in same execution path"
            ],
            exploit_hints=[
                "Allocate object of same size to reclaim freed memory",
                "Control freed chunk content via heap spray",
                "Look for virtual function calls on freed object",
                "Use type confusion if different object types"
            ],
            false_positive_hints=[
                "Pointer nullified after free",
                "Use is in error handling path (unreachable)",
                "Different pointer variable (aliasing confusion)"
            ]
        )

        # CWE-415: Double Free
        self.patterns["CWE-415"] = VulnPattern(
            cwe_id="CWE-415",
            name="Double Free",
            description="Memory freed more than once",
            asm_patterns=[
                "call free; ... call free (same ptr)",
                "free in error path; free in normal path",
                "free in loop without NULL check",
                "conditional free followed by unconditional free"
            ],
            api_indicators=[
                "free", "HeapFree", "LocalFree", "GlobalFree",
                "VirtualFree", "delete", "delete[]"
            ],
            anti_patterns=[
                "ptr = NULL after first free",
                "if (ptr != NULL) before second free",
                "freed flag variable tracking",
                "reference count > 0 check before free"
            ],
            verification_steps=[
                "1. Find all free() calls on same pointer/alias",
                "2. Check if same pointer can be freed twice",
                "3. Trace pointer aliases (copies)",
                "4. Verify no NULL assignment between frees",
                "5. Check conditional paths for double free"
            ],
            exploit_hints=[
                "Corrupt heap metadata via double free",
                "Use fastbin dup (glibc) or similar technique",
                "Allocate controlled data in freed slot",
                "Achieve arbitrary write via corrupted freelist"
            ],
            false_positive_hints=[
                "Different pointers (not aliases)",
                "Conditional prevents both frees executing",
                "Pointer reset between frees"
            ]
        )

        # CWE-190: Integer Overflow
        self.patterns["CWE-190"] = VulnPattern(
            cwe_id="CWE-190",
            name="Integer Overflow or Wraparound",
            description="Integer operation wraps around, causing unexpected small value",
            asm_patterns=[
                "add/mul without overflow check before malloc",
                "imul without jo/jc check",
                "add reg, user_input; ... call malloc(reg)",
                "shl without checking high bits"
            ],
            api_indicators=[
                "malloc", "calloc", "realloc", "HeapAlloc",
                "VirtualAlloc", "LocalAlloc", "GlobalAlloc",
                "new", "new[]"
            ],
            anti_patterns=[
                "jo/jc check after arithmetic",
                "cmp with max before operation",
                "SafeInt/checked arithmetic library",
                "explicit size_t bounds check"
            ],
            verification_steps=[
                "1. Find arithmetic operation on size/count",
                "2. Check if result used in memory allocation",
                "3. Verify no overflow check after operation",
                "4. Calculate if overflow can occur with user input",
                "5. Trace data flow from input to arithmetic"
            ],
            exploit_hints=[
                "Cause small allocation via overflow",
                "Write beyond allocated buffer",
                "Chain with heap overflow",
                "Exploit size confusion in copy operations"
            ],
            false_positive_hints=[
                "Arithmetic on trusted/bounded values",
                "Overflow check exists but not adjacent",
                "Result not used in security-sensitive context"
            ]
        )

        # CWE-78: OS Command Injection
        self.patterns["CWE-78"] = VulnPattern(
            cwe_id="CWE-78",
            name="OS Command Injection",
            description="User input incorporated into OS command without sanitization",
            asm_patterns=[
                "strcat user_input to command; call system",
                "sprintf command with %s user_input; call CreateProcess",
                "ShellExecute with user-controlled parameter"
            ],
            api_indicators=[
                "system", "popen", "_popen", "WinExec",
                "CreateProcess", "CreateProcessA", "CreateProcessW",
                "ShellExecute", "ShellExecuteA", "ShellExecuteW",
                "execl", "execv", "execve", "execlp"
            ],
            anti_patterns=[
                "input sanitization (filter ; | & ` $)",
                "whitelist validation on input",
                "parameterized command (no string concat)",
                "escapeShellArg equivalent usage"
            ],
            verification_steps=[
                "1. Find command execution API call",
                "2. Trace command string parameter source",
                "3. Check for user input concatenation",
                "4. Verify no sanitization of shell metacharacters",
                "5. Test with ; id or | whoami injection"
            ],
            exploit_hints=[
                "Use ; to chain commands",
                "Use | for pipe injection",
                "Use ` or $() for command substitution",
                "Consider NULL byte injection to truncate"
            ],
            false_positive_hints=[
                "Command is fully hardcoded",
                "User input only affects non-command parts",
                "Strong input validation in place"
            ]
        )

        # CWE-22: Path Traversal
        self.patterns["CWE-22"] = VulnPattern(
            cwe_id="CWE-22",
            name="Path Traversal",
            description="User input used in file path without proper validation",
            asm_patterns=[
                "strcat base_path with user_input; call CreateFile",
                "sprintf path with %s user_filename; call fopen",
                "user input directly to file open API"
            ],
            api_indicators=[
                "CreateFile", "CreateFileA", "CreateFileW",
                "fopen", "_wfopen", "open", "_open",
                "DeleteFile", "RemoveDirectory", "CopyFile",
                "MoveFile", "SetCurrentDirectory"
            ],
            anti_patterns=[
                "path canonicalization before use",
                "check for .. in path",
                "realpath/GetFullPathName validation",
                "whitelist of allowed directories"
            ],
            verification_steps=[
                "1. Find file operation API call",
                "2. Trace file path parameter source",
                "3. Check for user input in path construction",
                "4. Verify no ../ filtering or path canonicalization",
                "5. Test with ../../../etc/passwd or ..\\..\\..\\windows\\system.ini"
            ],
            exploit_hints=[
                "Use ../ or ..\\ to traverse directories",
                "Try URL encoding (%2e%2e%2f)",
                "Consider NULL byte to truncate extension",
                "Test both forward and backslashes"
            ],
            false_positive_hints=[
                "Path is fully hardcoded",
                "Proper canonicalization applied",
                "Strong path validation regex"
            ]
        )

    def get_pattern(self, cwe_id: str) -> Optional[VulnPattern]:
        """Get pattern for specific CWE"""
        return self.patterns.get(cwe_id)

    def get_pattern_for_vuln_type(self, vuln_type: str) -> Optional[VulnPattern]:
        """Get pattern by vulnerability type name"""
        vuln_to_cwe = {
            "BUFFER_OVERFLOW": "CWE-120",
            "HEAP_OVERFLOW": "CWE-120",
            "FORMAT_STRING": "CWE-134",
            "USE_AFTER_FREE": "CWE-416",
            "DOUBLE_FREE": "CWE-415",
            "INTEGER_OVERFLOW": "CWE-190",
            "COMMAND_INJECTION": "CWE-78",
            "PATH_TRAVERSAL": "CWE-22",
        }
        cwe = vuln_to_cwe.get(vuln_type.upper())
        return self.patterns.get(cwe) if cwe else None

    def get_all_patterns(self) -> List[VulnPattern]:
        """Get all patterns"""
        return list(self.patterns.values())

    def format_pattern_for_prompt(self, pattern: VulnPattern) -> str:
        """Format pattern into prompt text"""
        return f"""
## {pattern.cwe_id}: {pattern.name}
**Description**: {pattern.description}

**Assembly Patterns** (Search for these features):
{chr(10).join(f'  - {p}' for p in pattern.asm_patterns)}

**Dangerous APIs**:
  {', '.join(pattern.api_indicators[:10])}

**Security Checks (Anti-patterns - if present, may not be a vulnerability)**:
{chr(10).join(f'  - {p}' for p in pattern.anti_patterns)}

**Verification Steps**:
{chr(10).join(pattern.verification_steps)}

**Exploit Hints**:
{chr(10).join(f'  - {h}' for h in pattern.exploit_hints[:3])}

**Common False Positives**:
{chr(10).join(f'  - {h}' for h in pattern.false_positive_hints)}
"""


class LayeredPromptBuilder:
    """
    Layered Analysis Prompt Builder

    Three-stage analysis:
    - Stage 1: Quick Identification - Identify dangerous APIs and suspicious patterns
    - Stage 2: Deep Analysis - Control flow graph analysis, data flow tracing
    - Stage 3: Vulnerability Confirmation - Root cause analysis, reachability verification, PoC construction
    """

    def __init__(self):
        self.pattern_db = VulnPatternDB()

    def build_stage1_prompt(self, binary_name: str, exports: Dict[str, int],
                            dangerous_imports: List[Dict]) -> str:
        """
        Build Stage 1: Quick Scan Prompt

        Goal: Quickly identify high-priority analysis targets
        """
        exports_str = "\n".join(f"  - {name}: 0x{addr:x}" for name, addr in list(exports.items())[:30])

        dangerous_str = ""
        if dangerous_imports:
            dangerous_str = "\nIdentified Dangerous Imports:\n"
            for imp in dangerous_imports[:15]:
                dangerous_str += f"  - {imp.get('api', 'unknown')} @ {imp.get('address', 'N/A')} [{imp.get('vuln_type', 'N/A')}]\n"

        return f"""# Stage 1: Quick Scan Analysis

## Goal
Quickly identify high-risk analysis targets in {binary_name}. Do not perform deep analysis yet, just surface scan.

## Exported Functions (Partial)
{exports_str}
{dangerous_str}

## Tasks
1. **Scan Dangerous APIs**: Call check_dangerous_imports to view all dangerous imports
2. **Prioritization**: Sort findings by severity
3. **Mark Targets**: List functions requiring deep analysis

## Output Format
Please output the scan results in JSON format:
```json
{{
  "high_priority_targets": [
    {{"function": "...", "reason": "...", "vuln_type": "..."}},
    ...
  ],
  "dangerous_api_summary": {{
    "total": N,
    "critical": N,
    "high": N
  }},
  "recommended_next_step": "..."
}}
```

When you complete the scan, output "[STAGE1_COMPLETE]" along with the results.
"""

    def build_stage2_prompt(self, target_function: str, target_addr: int,
                            vuln_type: str, context: Dict = None) -> str:
        """
        Build Stage 2: Deep Analysis Prompt

        Goal: Perform deep code audit of a specific function
        """
        pattern = self.pattern_db.get_pattern_for_vuln_type(vuln_type)
        pattern_guidance = self.pattern_db.format_pattern_for_prompt(pattern) if pattern else ""

        context_str = ""
        if context:
            context_str = f"\n## Context Information\n```json\n{json.dumps(context, indent=2, ensure_ascii=False)}\n```\n"

        return f"""# Stage 2: Deep Analysis - {target_function}

## Target Function
- **Name**: {target_function}
- **Address**: 0x{target_addr:x}
- **Suspected Vulnerability Type**: {vuln_type}
{context_str}

## Vulnerability Pattern Reference
{pattern_guidance}

## Analysis Tasks

### Step 1: Understand Function Logic
Call `disassemble_function` to get assembly code, then:
1. Identify the main functionality and data flow of the function
2. Mark all external entry points (parameters, global variables, API return values)
3. Sketch simplified control flow (which branches lead to dangerous operations)

### Step 2: Data Flow Tracing
Call `analyze_taint_flow` to trace taint propagation:
1. Confirm which inputs can reach the dangerous Sink
2. Identify data transformations and constraints
3. Check for security checks (anti-patterns)

### Step 3: Bounds Check Verification
Call `check_bounds_before_sink` to verify:
1. Detect if effective bounds/length checks exist before the Sink
2. Evaluate if checks can be bypassed
3. Record discovered security mechanisms

## Output Format (Chain of Thought)
```
[Observation] Assembly code shows...
[Hypothesis] According to pattern X, there might be...
[Verification] Call tool Y to check...
[Conclusion] This vulnerability is/is not real because...
```

Output "[STAGE2_COMPLETE]" when finished, along with structured analysis results.
"""

    def build_stage3_prompt(self, vuln_info: Dict, taint_result: Dict = None,
                            bounds_check_result: Dict = None) -> str:
        """
        Build Stage 3: Vulnerability Confirmation Prompt

        Goal: Finally confirm and generate PoC
        """
        vuln_type = vuln_info.get('vuln_type', 'UNKNOWN')
        target_func = vuln_info.get('function', 'unknown')
        sink_addr = vuln_info.get('sink_address', '0x0')

        taint_str = ""
        if taint_result:
            taint_str = f"\n## Taint Analysis Result\n```json\n{json.dumps(taint_result, indent=2, ensure_ascii=False)[:2000]}\n```\n"

        bounds_str = ""
        if bounds_check_result:
            bounds_str = f"\n## Bounds Check Result\n```json\n{json.dumps(bounds_check_result, indent=2, ensure_ascii=False)}\n```\n"

        return f"""# Stage 3: Vulnerability Confirmation and PoC Generation

## Vulnerability to Confirm
- **Type**: {vuln_type}
- **Function**: {target_func}
- **Sink Address**: {sink_addr}
{taint_str}
{bounds_str}

## Final Verification Tasks

### 1. Comprehensive Verification
Call `deep_verify_vulnerability` for comprehensive assessment:
- Combine bounds check, taint analysis, and symbolic execution results
- Get final confidence score

### 2. Root Cause Analysis
Please answer:
- **Root Cause**: What is the root cause of the vulnerability?
- **Trigger Condition**: How to trigger this vulnerability?
- **Impact**: Scope of the vulnerability's impact?

### 3. PoC Generation (if confidence >= 0.5)
Call `generate_poc` to generate verification code:
- Set correct vulnerability type and target function
- Use `symbolic_explore` to get precise input if possible

### 4. PoC Verification
Call `verify_poc` to test in sandbox

## Final Report Format
```json
{{
  "confirmed": true/false,
  "confidence": 0.XX,
  "vuln_type": "...",
  "root_cause": "...",
  "trigger_condition": "...",
  "impact": "...",
  "poc_generated": true/false,
  "poc_verified": true/false,
  "mitigation": "..."
}}
```

Output "[ANALYSIS_COMPLETE]" when finished along with the final report.
"""

    def build_focused_prompt(self, algorithm_findings: List[Dict]) -> str:
        """
        Build Focused Prompt - Based on algorithm pre-analysis results

        Guidance for AI to verify specific suspicious points found by algorithms
        """
        if not algorithm_findings:
            return ""

        findings_str = ""
        for i, f in enumerate(algorithm_findings[:5], 1):
            vtype = f.get('vuln_type', 'UNKNOWN')
            addr = f.get('sink_addr', f.get('address', 'N/A'))
            api = f.get('sink_api', f.get('api', 'unknown'))
            conf = f.get('confidence', 0)

            findings_str += f"""
### Finding #{i}
- **Type**: {vtype}
- **Location**: {addr}
- **API**: {api}
- **Algorithm Confidence**: {conf:.2f}
"""

        return f"""# Algorithm Pre-analysis Verification

Static analysis algorithms have identified the following suspicious points, please verify them in order:
{findings_str}

## Verification Flow
For each finding:
1. Call `disassemble_function` to view code context
2. Call `check_bounds_before_sink` to check security mechanisms
3. Call `deep_verify_vulnerability` to get comprehensive score
4. Decide whether to generate PoC

**Important**: Do not blindly trust algorithm results; your task is to verify or negate these findings.
"""


@dataclass
class StructuredVulnReport:
    """Structured Vulnerability Report"""
    confirmed: bool = False
    confidence: float = 0.0
    vuln_type: str = ""
    cwe_id: str = ""
    function: str = ""
    address: str = ""
    root_cause: str = ""
    trigger_condition: str = ""
    impact: str = ""
    evidence: List[str] = field(default_factory=list)
    counter_evidence: List[str] = field(default_factory=list)
    poc_generated: bool = False
    poc_verified: bool = False
    poc_code: str = ""
    mitigation: str = ""

    def to_dict(self) -> Dict:
        return {
            'confirmed': self.confirmed,
            'confidence': self.confidence,
            'vuln_type': self.vuln_type,
            'cwe_id': self.cwe_id,
            'function': self.function,
            'address': self.address,
            'root_cause': self.root_cause,
            'trigger_condition': self.trigger_condition,
            'impact': self.impact,
            'evidence': self.evidence,
            'counter_evidence': self.counter_evidence,
            'poc_generated': self.poc_generated,
            'poc_verified': self.poc_verified,
            'mitigation': self.mitigation
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


class StructuredOutputParser:
    """
    Structured Output Parser

    Extracts structured data from AI responses
    """

    @staticmethod
    def extract_json_blocks(text: str) -> List[Dict]:
        """Extract JSON blocks from text"""
        results = []

        # Match ```json ... ``` blocks
        json_pattern = r'```json\s*([\s\S]*?)\s*```'
        matches = re.findall(json_pattern, text)

        for match in matches:
            try:
                data = json.loads(match)
                results.append(data)
            except json.JSONDecodeError:
                continue

        # Also attempt to match bare JSON objects
        bare_json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        bare_matches = re.findall(bare_json_pattern, text)

        for match in bare_matches:
            try:
                data = json.loads(match)
                if data not in results:  # De-duplicate
                    results.append(data)
            except json.JSONDecodeError:
                continue

        return results

    @staticmethod
    def parse_vuln_report(text: str) -> Optional[StructuredVulnReport]:
        """Parse vulnerability report"""
        json_blocks = StructuredOutputParser.extract_json_blocks(text)

        for block in json_blocks:
            if 'confirmed' in block or 'vuln_type' in block:
                report = StructuredVulnReport(
                    confirmed=block.get('confirmed', False),
                    confidence=block.get('confidence', 0.0),
                    vuln_type=block.get('vuln_type', ''),
                    cwe_id=block.get('cwe_id', ''),
                    function=block.get('function', ''),
                    address=block.get('address', ''),
                    root_cause=block.get('root_cause', ''),
                    trigger_condition=block.get('trigger_condition', ''),
                    impact=block.get('impact', ''),
                    evidence=block.get('evidence', []),
                    counter_evidence=block.get('counter_evidence', []),
                    poc_generated=block.get('poc_generated', False),
                    poc_verified=block.get('poc_verified', False),
                    poc_code=block.get('poc_code', ''),
                    mitigation=block.get('mitigation', '')
                )
                return report

        return None

    @staticmethod
    def extract_analysis_stages(text: str) -> Dict[str, bool]:
        """Detect analysis stage completion status"""
        return {
            'stage1_complete': '[STAGE1_COMPLETE]' in text,
            'stage2_complete': '[STAGE2_COMPLETE]' in text,
            'analysis_complete': '[ANALYSIS_COMPLETE]' in text
        }


# Convenience functions
def get_vuln_pattern(vuln_type: str) -> Optional[VulnPattern]:
    """Get vulnerability pattern"""
    db = VulnPatternDB()
    return db.get_pattern_for_vuln_type(vuln_type)


def build_analysis_prompt(stage: AnalysisStage, **kwargs) -> str:
    """Build analysis prompt"""
    builder = LayeredPromptBuilder()

    if stage == AnalysisStage.QUICK_SCAN:
        return builder.build_stage1_prompt(
            kwargs.get('binary_name', 'unknown'),
            kwargs.get('exports', {}),
            kwargs.get('dangerous_imports', [])
        )
    elif stage == AnalysisStage.DEEP_ANALYSIS:
        return builder.build_stage2_prompt(
            kwargs.get('target_function', 'unknown'),
            kwargs.get('target_addr', 0),
            kwargs.get('vuln_type', 'BUFFER_OVERFLOW'),
            kwargs.get('context')
        )
    elif stage == AnalysisStage.VULN_CONFIRM:
        return builder.build_stage3_prompt(
            kwargs.get('vuln_info', {}),
            kwargs.get('taint_result'),
            kwargs.get('bounds_check_result')
        )

    return ""
