# -*- coding: utf-8 -*-
"""Static vulnerability analysis checkers."""

import re
from dataclasses import dataclass, field
from typing import List, Set
from .context_extractor import VerificationContext


@dataclass
class AnalysisResult:
    """Results from static vulnerability analysis"""
    has_bounds_check: bool = False
    has_null_check: bool = False
    has_error_handling: bool = False
    sink_api_confirmed: bool = False
    safe_function_used: bool = False
    has_stack_cookie: bool = False
    has_free_call: bool = False
    has_null_after_free: bool = False
    notes: List[str] = field(default_factory=list)
    dangerous_apis_found: List[str] = field(default_factory=list)
    protections: List[str] = field(default_factory=list)


class VulnChecker:
    """Static analysis for vulnerability verification"""

    # Dangerous APIs by vulnerability type
    DANGEROUS_APIS = {
        "BUFFER_OVERFLOW": ["strcpy", "strcat", "sprintf", "vsprintf", "gets",
                           "memcpy", "memmove", "strncpy", "strncat", "scanf"],
        "HEAP_OVERFLOW": ["memcpy", "memmove", "strcpy", "strcat", "realloc"],
        "FORMAT_STRING": ["printf", "fprintf", "sprintf", "snprintf", "syslog"],
        "COMMAND_INJECTION": ["system", "popen", "exec", "WinExec", "ShellExecute",
                              "CreateProcess"],
        "USE_AFTER_FREE": ["free", "HeapFree", "delete", "VirtualFree"],
        "DOUBLE_FREE": ["free", "HeapFree", "delete", "VirtualFree"],
        "INTEGER_OVERFLOW": ["malloc", "calloc", "realloc", "HeapAlloc"],
    }

    # Safe alternatives
    SAFE_FUNCTIONS = {"strcpy_s", "strcat_s", "sprintf_s", "snprintf",
                      "memcpy_s", "strncpy_s", "strncat_s"}

    # Bounds check patterns in decompiled code
    BOUNDS_PATTERNS = [
        r'if\s*\([^)]*<[^)]*\)',       # if (x < size)
        r'if\s*\([^)]*>[^)]*\)',       # if (x > limit)
        r'if\s*\([^)]*<=\s*\d+\)',     # if (x <= 100)
        r'if\s*\([^)]*>=\s*\d+\)',     # if (x >= 0)
        r'\bmin\s*\(',                  # min() function
        r'\bmax\s*\(',                  # max() function
        r'sizeof\s*\(',                 # sizeof usage
    ]

    # Null check patterns
    NULL_CHECK_PATTERNS = [
        r'if\s*\([^)]*==\s*NULL',
        r'if\s*\([^)]*!=\s*NULL',
        r'if\s*\([^)]*==\s*0\s*\)',
        r'if\s*\([^)]*!=\s*0\s*\)',
        r'if\s*\(\s*!\s*\w+\s*\)',     # if (!ptr)
    ]

    def analyze(self, ctx: VerificationContext, vuln_type: str, sink_api: str = "") -> AnalysisResult:
        """Perform static analysis based on vulnerability type"""
        result = AnalysisResult()
        code = ctx.decompiled or ctx.disassembly

        if not code:
            result.notes.append("No decompiled code available")
            return result

        # Check for dangerous APIs
        dangerous_list = self.DANGEROUS_APIS.get(vuln_type, [])
        for api in dangerous_list:
            if api.lower() in code.lower():
                result.dangerous_apis_found.append(api)
                if sink_api and api.lower() == sink_api.lower():
                    result.sink_api_confirmed = True

        # Check for safe function variants
        for safe_func in self.SAFE_FUNCTIONS:
            if safe_func.lower() in code.lower():
                result.safe_function_used = True
                result.notes.append(f"Safe function {safe_func} detected")
                break

        # Check for bounds checking
        for pattern in self.BOUNDS_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                result.has_bounds_check = True
                result.notes.append("Bounds checking pattern detected")
                break

        # Check for null checks
        for pattern in self.NULL_CHECK_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                result.has_null_check = True
                break

        # Check for error handling (return -1, return NULL, goto error)
        if re.search(r'return\s+(-1|NULL|0|false)', code, re.IGNORECASE):
            result.has_error_handling = True
        if re.search(r'goto\s+(error|fail|cleanup)', code, re.IGNORECASE):
            result.has_error_handling = True

        # Check for stack cookie
        if "__security_cookie" in code or "__stack_chk" in code:
            result.has_stack_cookie = True
            result.protections.append("Stack Cookie")

        # Type-specific checks
        if vuln_type in ("USE_AFTER_FREE", "DOUBLE_FREE"):
            result.has_free_call = any(f in code.lower() for f in ["free(", "heapfree(", "delete "])
            # Check for null assignment after free
            if re.search(r'free\s*\([^)]+\)\s*;[^}]*=\s*NULL', code, re.IGNORECASE | re.DOTALL):
                result.has_null_after_free = True
                result.notes.append("Pointer nullified after free")

        # Additional protection checks
        if "SafeSEH" in code or "_except_handler" in code:
            result.protections.append("SafeSEH")
        if "CFG" in code or "__guard_dispatch" in code:
            result.protections.append("CFG")

        return result
