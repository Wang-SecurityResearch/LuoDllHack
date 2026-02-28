# -*- coding: utf-8 -*-
"""
luodllhack/analysis/plugins/builtin.py - Built-in Analysis Plugins

Core detection plugins extracted from existing TaintEngine logic.
"""

from typing import List, Any, Optional, Dict, Set
from .base import AnalysisPlugin, PluginContext, Finding, FindingType


# ============================================================================
# Dangerous API Call Detection Plugin
# ============================================================================

class DangerousAPIPlugin(AnalysisPlugin):
    """
    Dangerous API Call Detection

    Detects calls to known dangerous functions like strcpy, sprintf, gets, etc.
    """

    name = "dangerous_api"
    description = "Detects dangerous API calls"
    version = "1.0"
    priority = 80  # High priority

    # Dangerous API classifications
    DANGEROUS_APIS: Dict[str, Dict[str, Any]] = {
        # Buffer overflow risks
        "strcpy": {"risk": "buffer_overflow", "confidence": 0.7},
        "strcat": {"risk": "buffer_overflow", "confidence": 0.7},
        "sprintf": {"risk": "buffer_overflow", "confidence": 0.7},
        "vsprintf": {"risk": "buffer_overflow", "confidence": 0.7},
        "gets": {"risk": "buffer_overflow", "confidence": 0.9},
        "scanf": {"risk": "buffer_overflow", "confidence": 0.6},
        "sscanf": {"risk": "buffer_overflow", "confidence": 0.6},
        "memcpy": {"risk": "buffer_overflow", "confidence": 0.5},
        "memmove": {"risk": "buffer_overflow", "confidence": 0.5},
        "lstrcpyA": {"risk": "buffer_overflow", "confidence": 0.7},
        "lstrcpyW": {"risk": "buffer_overflow", "confidence": 0.7},
        "lstrcatA": {"risk": "buffer_overflow", "confidence": 0.7},
        "lstrcatW": {"risk": "buffer_overflow", "confidence": 0.7},
        "wcscpy": {"risk": "buffer_overflow", "confidence": 0.7},
        "wcscat": {"risk": "buffer_overflow", "confidence": 0.7},

        # Format string risks
        "printf": {"risk": "format_string", "confidence": 0.4},
        "fprintf": {"risk": "format_string", "confidence": 0.4},
        "wprintf": {"risk": "format_string", "confidence": 0.4},
        "syslog": {"risk": "format_string", "confidence": 0.5},

        # Command injection risks
        "system": {"risk": "command_injection", "confidence": 0.7},
        "popen": {"risk": "command_injection", "confidence": 0.7},
        "WinExec": {"risk": "command_injection", "confidence": 0.7},
        "ShellExecuteA": {"risk": "command_injection", "confidence": 0.6},
        "ShellExecuteW": {"risk": "command_injection", "confidence": 0.6},
        "CreateProcessA": {"risk": "command_injection", "confidence": 0.5},
        "CreateProcessW": {"risk": "command_injection", "confidence": 0.5},

        # Memory management risks
        "free": {"risk": "double_free", "confidence": 0.3},
        "HeapFree": {"risk": "double_free", "confidence": 0.3},
        "LocalFree": {"risk": "double_free", "confidence": 0.3},
        "GlobalFree": {"risk": "double_free", "confidence": 0.3},
        "realloc": {"risk": "use_after_free", "confidence": 0.4},
        "HeapReAlloc": {"risk": "use_after_free", "confidence": 0.4},
    }

    def on_call(self, insn: Any, target: Optional[int],
                api_name: Optional[str], ctx: PluginContext) -> List[Finding]:
        if not api_name:
            return []

        # Extract function name (remove DLL prefix)
        func_name = api_name.split("!")[-1] if "!" in api_name else api_name

        # Check if it is a dangerous API
        api_info = None
        for dangerous_api, info in self.DANGEROUS_APIS.items():
            if dangerous_api.lower() in func_name.lower():
                api_info = info
                break

        if api_info:
            return [Finding(
                type=FindingType.DANGEROUS_CALL,
                address=insn.address,
                description=f"Calling dangerous API: {func_name}",
                confidence=api_info["confidence"],
                details={
                    "api_name": func_name,
                    "risk_type": api_info["risk"],
                    "full_name": api_name
                }
            )]

        return []


# ============================================================================
# Missing Bounds Check Detection Plugin
# ============================================================================

class NoBoundsCheckPlugin(AnalysisPlugin):
    """
    Missing Bounds Check Detection

    Detects cases where dangerous functions are called without a preceding bounds check.
    """

    name = "no_bounds_check"
    description = "Detects dangerous calls without bounds checks"
    version = "1.0"
    priority = 70

    # APIs requiring bounds checks
    NEEDS_CHECK = {"strcpy", "memcpy", "strcat", "sprintf", "memmove",
                   "lstrcpy", "lstrcat", "wcscpy", "wcscat", "memset"}

    def __init__(self):
        super().__init__()
        self._recent_instructions: List[Any] = []
        self._has_bounds_check = False

    def on_instruction(self, insn: Any, ctx: PluginContext) -> List[Finding]:
        # Record recent instructions
        self._recent_instructions.append(insn)
        if len(self._recent_instructions) > 10:
            self._recent_instructions.pop(0)

        # Detect bounds check instructions
        if insn.mnemonic in ("cmp", "test"):
            self._has_bounds_check = True

        return []

    def on_call(self, insn: Any, target: Optional[int],
                api_name: Optional[str], ctx: PluginContext) -> List[Finding]:
        if not api_name:
            self._has_bounds_check = False  # Reset
            return []

        func_name = api_name.split("!")[-1] if "!" in api_name else api_name

        # Check if it is an API that requires bounds checks
        needs_check = any(api.lower() in func_name.lower() for api in self.NEEDS_CHECK)

        if needs_check and not self._has_bounds_check:
            finding = Finding(
                type=FindingType.NO_BOUNDS_CHECK,
                address=insn.address,
                description=f"No bounds check before calling {func_name}",
                confidence=0.6,
                details={
                    "api_name": func_name,
                    "recent_instructions": len(self._recent_instructions)
                }
            )
            self._has_bounds_check = False  # Reset
            return [finding]

        self._has_bounds_check = False  # Reset
        return []

    def on_function_start(self, func_addr: int, func_name: str,
                          ctx: PluginContext) -> None:
        self._recent_instructions.clear()
        self._has_bounds_check = False


# ============================================================================
# Indirect Call Detection Plugin
# ============================================================================

class IndirectCallPlugin(AnalysisPlugin):
    """
    Indirect Call Detection

    Detects indirect calls through registers or memory (call rax, call [rbx+8], etc.)
    """

    name = "indirect_call"
    description = "Detects indirect calls"
    version = "1.0"
    priority = 60

    def on_call(self, insn: Any, target: Optional[int],
                api_name: Optional[str], ctx: PluginContext) -> List[Finding]:
        # If target is None, it indicates an indirect call
        if target is None:
            # Check operand type
            is_reg_call = False
            is_mem_call = False
            operand_str = insn.op_str

            if operand_str and not operand_str.startswith("0x"):
                if "[" in operand_str:
                    is_mem_call = True
                else:
                    is_reg_call = True

            # Check if the called register/memory is tainted
            is_tainted = False
            if is_reg_call:
                reg = operand_str.lower()
                if reg in ctx.tainted_regs:
                    is_tainted = True

            confidence = 0.7 if is_tainted else 0.4

            return [Finding(
                type=FindingType.INDIRECT_CALL,
                address=insn.address,
                description=f"Indirect call: call {operand_str}",
                confidence=confidence,
                details={
                    "operand": operand_str,
                    "is_register": is_reg_call,
                    "is_memory": is_mem_call,
                    "is_tainted": is_tainted
                }
            )]

        return []


# ============================================================================
# Integer Overflow Detection Plugin
# ============================================================================

class IntegerOverflowPlugin(AnalysisPlugin):
    """
    Integer Overflow Detection

    Detects arithmetic operations that may lead to integer overflows.
    """

    name = "integer_overflow"
    description = "Detects integer overflow risks"
    version = "1.0"
    priority = 50

    # Instructions with overflow risk
    OVERFLOW_INSTRUCTIONS = {"add", "sub", "mul", "imul", "inc", "dec", "shl", "sal"}

    def __init__(self):
        super().__init__()
        self._arithmetic_result_regs: Set[str] = set()

    def on_instruction(self, insn: Any, ctx: PluginContext) -> List[Finding]:
        mnemonic = insn.mnemonic.lower()

        if mnemonic in self.OVERFLOW_INSTRUCTIONS:
            # Record arithmetic result registers
            if hasattr(insn, 'operands') and insn.operands:
                try:
                    dst = insn.operands[0]
                    if dst.type == 1:  # REG
                        reg_name = insn.reg_name(dst.reg).lower()
                        self._arithmetic_result_regs.add(reg_name)
                except:
                    pass

            # Check if operands originate from user input (tainted)
            is_tainted = False
            if hasattr(insn, 'operands'):
                for op in insn.operands:
                    try:
                        if op.type == 1:  # REG
                            reg = insn.reg_name(op.reg).lower()
                            if reg in ctx.tainted_regs:
                                is_tainted = True
                                break
                    except:
                        pass

            if is_tainted:
                return [Finding(
                    type=FindingType.SUSPICIOUS_PATTERN,
                    address=insn.address,
                    description=f"Tainted data involved in arithmetic: {mnemonic} {insn.op_str}",
                    confidence=0.5,
                    details={
                        "instruction": mnemonic,
                        "operands": insn.op_str
                    }
                )]

        return []

    def on_function_start(self, func_addr: int, func_name: str,
                          ctx: PluginContext) -> None:
        self._arithmetic_result_regs.clear()


# ============================================================================
# Return Value Check Plugin
# ============================================================================

class ReturnValueCheckPlugin(AnalysisPlugin):
    """
    Return Value Check Plugin

    Detects whether the return values of critical APIs are checked.
    """

    name = "return_value_check"
    description = "Detects if return values are checked"
    version = "1.0"
    priority = 40

    # APIs requiring return value checks
    NEEDS_CHECK = {
        "malloc", "calloc", "realloc",
        "HeapAlloc", "LocalAlloc", "GlobalAlloc", "VirtualAlloc",
        "CreateFile", "OpenFile", "fopen", "_wfopen",
        "RegOpenKey", "RegCreateKey",
    }

    def __init__(self):
        super().__init__()
        self._last_call_addr: Optional[int] = None
        self._last_call_api: Optional[str] = None
        self._instructions_since_call = 0

    def on_call(self, insn: Any, target: Optional[int],
                api_name: Optional[str], ctx: PluginContext) -> List[Finding]:
        if api_name:
            func_name = api_name.split("!")[-1]
            if any(api.lower() in func_name.lower() for api in self.NEEDS_CHECK):
                self._last_call_addr = insn.address
                self._last_call_api = func_name
                self._instructions_since_call = 0

        return []

    def on_instruction(self, insn: Any, ctx: PluginContext) -> List[Finding]:
        if self._last_call_addr is None:
            return []

        self._instructions_since_call += 1

        # Check for return value check (test/cmp rax or eax)
        if insn.mnemonic in ("test", "cmp"):
            if "eax" in insn.op_str.lower() or "rax" in insn.op_str.lower():
                self._last_call_addr = None
                return []

        # If more than 5 instructions without a check, report the issue
        if self._instructions_since_call > 5:
            finding = Finding(
                type=FindingType.SUSPICIOUS_PATTERN,
                address=self._last_call_addr,
                description=f"Return value of {self._last_call_api} not checked after call",
                confidence=0.5,
                details={
                    "api_name": self._last_call_api,
                    "instructions_before_check": self._instructions_since_call
                }
            )
            self._last_call_addr = None
            return [finding]

        return []

    def on_function_start(self, func_addr: int, func_name: str,
                          ctx: PluginContext) -> None:
        self._last_call_addr = None
        self._last_call_api = None
        self._instructions_since_call = 0


# ============================================================================
# Export Built-in Plugins
# ============================================================================

def get_builtin_plugins() -> List[AnalysisPlugin]:
    """Get all built-in plugin instances"""
    return [
        DangerousAPIPlugin(),
        NoBoundsCheckPlugin(),
        IndirectCallPlugin(),
        IntegerOverflowPlugin(),
        ReturnValueCheckPlugin(),
    ]
