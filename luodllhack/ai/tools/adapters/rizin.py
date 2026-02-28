# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/adapters/rizin.py
Rizin Tool Adapter - Binary Analysis Tools

Wraps RizinCore capabilities as MCP tools:
    - Disassembly
    - Function analysis
    - String extraction
    - Import/Export analysis
    - CFG construction
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, TYPE_CHECKING

from .base import MCPTool, MCPToolAdapter, MCPToolResult

if TYPE_CHECKING:
    from luodllhack.core import RizinCore

logger = logging.getLogger(__name__)


# =============================================================================
# Rizin Tool Definitions
# =============================================================================

class DisassembleFunctionTool(MCPTool):
    """Disassemble function tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "disassemble_function"

    @property
    def description(self) -> str:
        return "Disassemble a function at the given address and return its instructions."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "address": {
                "type": "integer",
                "description": "Function address to disassemble"
            },
            "max_instructions": {
                "type": "integer",
                "description": "Maximum number of instructions to return (default: 100)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["address"]

    def execute(self, address: int, max_instructions: int = 100) -> Dict[str, Any]:
        """Disassemble function"""
        func = self.rz.get_function_at(address)
        if not func:
            return {"error": f"No function found at 0x{address:x}"}

        instructions = []
        for bb in func.blocks:
            for insn in bb.instructions[:max_instructions - len(instructions)]:
                instructions.append({
                    "address": insn.address,
                    "mnemonic": insn.mnemonic,
                    "operands": insn.operands,
                    "size": insn.size,
                })
                if len(instructions) >= max_instructions:
                    break

        return {
            "function_name": func.name,
            "address": func.address,
            "size": func.size,
            "num_blocks": len(func.blocks),
            "instructions": instructions,
            "instruction_count": len(instructions),
        }


class GetFunctionInfoTool(MCPTool):
    """Get function information tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "get_function_info"

    @property
    def description(self) -> str:
        return "Get detailed information about a function including signature, local variables, and references."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "address": {
                "type": "integer",
                "description": "Function address"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["address"]

    def execute(self, address: int) -> Dict[str, Any]:
        """Get function information"""
        func = self.rz.get_function_at(address)
        if not func:
            return {"error": f"No function found at 0x{address:x}"}

        # Get local variables
        locals_info = self.rz.get_function_locals(address)

        # Get call graph
        callees = []
        callers = []
        try:
            callees = self.rz.get_function_callees(address)
            callers = self.rz.get_function_callers(address)
        except Exception:
            pass

        return {
            "name": func.name,
            "address": func.address,
            "size": func.size,
            "num_blocks": len(func.blocks),
            "num_instructions": sum(len(bb.instructions) for bb in func.blocks),
            "locals": locals_info,
            "callees": [{"name": c.get("name", ""), "address": c.get("addr", 0)} for c in callees[:20]],
            "callers": [{"name": c.get("name", ""), "address": c.get("addr", 0)} for c in callers[:20]],
        }


class ListFunctionsTool(MCPTool):
    """List functions tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "list_functions"

    @property
    def description(self) -> str:
        return "List all functions in the binary with optional filtering."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "filter_pattern": {
                "type": "string",
                "description": "Filter functions by name pattern (optional)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of functions to return (default: 50)"
            }
        }

    def execute(self, filter_pattern: str = None, limit: int = 50) -> Dict[str, Any]:
        """List functions"""
        functions = list(self.rz.get_functions().values())

        if filter_pattern:
            functions = [f for f in functions if filter_pattern.lower() in f.name.lower()]

        result = []
        for func in functions[:limit]:
            result.append({
                "name": func.name,
                "address": func.address,
                "size": func.size,
            })

        return {
            "total": len(functions),
            "returned": len(result),
            "functions": result,
        }


class GetExportsTool(MCPTool):
    """Get exported functions tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "get_exports"

    @property
    def description(self) -> str:
        return "Get all exported functions from the binary."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "limit": {
                "type": "integer",
                "description": "Maximum number of exports to return (default: 100)"
            }
        }

    def execute(self, limit: int = 100) -> Dict[str, Any]:
        """Get exported functions"""
        exports = self.rz.get_exports()

        result = []
        for addr, exp in list(exports.items())[:limit]:
            result.append({
                "name": exp.name,
                "address": exp.address,
                "type": exp.type,
            })

        return {
            "total": len(exports),
            "returned": len(result),
            "exports": result,
        }


class GetImportsTool(MCPTool):
    """Get imported functions tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "get_imports"

    @property
    def description(self) -> str:
        return "Get all imported functions from the binary."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "limit": {
                "type": "integer",
                "description": "Maximum number of imports to return (default: 100)"
            }
        }

    def execute(self, limit: int = 100) -> Dict[str, Any]:
        """Get imported functions"""
        imports = self.rz.get_imports()

        result = []
        for addr, imp in list(imports.items())[:limit]:
            result.append({
                "name": imp.name,
                "address": imp.address,
                "library": getattr(imp, 'library', ''),
            })

        return {
            "total": len(imports),
            "returned": len(result),
            "imports": result,
        }


class GetStringsTool(MCPTool):
    """Get strings tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "get_strings"

    @property
    def description(self) -> str:
        return "Extract strings from the binary."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "min_length": {
                "type": "integer",
                "description": "Minimum string length (default: 4)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of strings to return (default: 100)"
            }
        }

    def execute(self, min_length: int = 4, limit: int = 100) -> Dict[str, Any]:
        """Get strings"""
        strings = self.rz.get_strings()

        result = []
        for s in strings:
            if len(s.get("string", "")) >= min_length:
                result.append({
                    "address": s.get("vaddr", 0),
                    "string": s.get("string", "")[:200],  # Truncate long strings
                    "length": s.get("length", 0),
                    "type": s.get("type", ""),
                })
                if len(result) >= limit:
                    break

        return {
            "total": len(strings),
            "returned": len(result),
            "strings": result,
        }


class GetXrefsTool(MCPTool):
    """Get cross-references tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "get_xrefs"

    @property
    def description(self) -> str:
        return "Get cross-references to/from an address."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "address": {
                "type": "integer",
                "description": "Target address"
            },
            "direction": {
                "type": "string",
                "description": "Direction: 'to' or 'from' (default: 'to')"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["address"]

    def execute(self, address: int, direction: str = "to") -> Dict[str, Any]:
        """Get cross-references"""
        if direction == "to":
            xrefs = self.rz.get_xrefs_to(address)
        else:
            xrefs = self.rz.get_xrefs_from(address)

        result = []
        for xref in xrefs[:50]:
            result.append({
                "from": xref.get("from", 0),
                "to": xref.get("to", 0),
                "type": xref.get("type", ""),
            })

        return {
            "address": address,
            "direction": direction,
            "count": len(result),
            "xrefs": result,
        }


class GetBinaryInfoTool(MCPTool):
    """Get binary info tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "get_binary_info"

    @property
    def description(self) -> str:
        return "Get general information about the binary file."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {}

    def execute(self) -> Dict[str, Any]:
        """Get binary information"""
        info = self.rz.info

        return {
            "path": str(info.path),
            "arch": str(info.arch),
            "bits": info.bits,
            "format": getattr(info, 'format', 'unknown'),
            "binary_type": str(getattr(info, 'binary_type', 'unknown')),
            "image_base": getattr(info, 'image_base', 0),
            "entry_point": getattr(info, 'entry_point', 0),
            "endian": str(getattr(info, 'endian', 'unknown')),
            "compiler": getattr(info, 'compiler', ''),
        }


class CheckSecurityTool(MCPTool):
    """Security features check tool"""

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "check_security"

    @property
    def description(self) -> str:
        return "Check security features of the binary (ASLR, DEP, CFG, etc.)."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {}

    def execute(self) -> Dict[str, Any]:
        """Check security features"""
        security = self.rz.check_security()
        return security


class AnalyzeBoundsCheckTool(MCPTool):
    """
    Analyze bounds check tool

    Checks if bounds checking patterns exist in a function, used to verify vulnerability exploitability.
    """

    # Bounds check related instructions
    BOUNDS_CHECK_MNEMONICS = {
        'cmp', 'test', 'cmpxchg',
    }

    # Conditional jumps (usually follow a bounds check)
    CONDITIONAL_JUMPS = {
        'ja', 'jae', 'jb', 'jbe',  # Unsigned comparisons
        'jg', 'jge', 'jl', 'jle',  # Signed comparisons
        'je', 'jz', 'jne', 'jnz',  # Equality/Zero checks
        'jo', 'jno', 'js', 'jns',  # Overflow/Sign
    }

    def __init__(self, rz: "RizinCore"):
        self.rz = rz

    @property
    def name(self) -> str:
        return "analyze_bounds_check"

    @property
    def description(self) -> str:
        return "Analyze code before a sink call to check for bounds checking patterns. Returns whether effective bounds checks exist."

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "sink_address": {
                "type": "string",
                "description": "Address of the dangerous sink call (hex string like '0x18001000')"
            },
            "lookback_instructions": {
                "type": "integer",
                "description": "Number of instructions to analyze before sink (default: 30)"
            }
        }

    @property
    def required_params(self) -> List[str]:
        return ["sink_address"]

    def execute(self, sink_address: str, lookback_instructions: int = 30, **kwargs) -> Dict[str, Any]:
        """Analyze bounds check"""
        _ = kwargs  # Ignore extra parameters
        try:
            addr = int(sink_address, 16) if isinstance(sink_address, str) else int(sink_address)
        except (ValueError, TypeError):
            return {"error": f"Invalid address: {sink_address}"}

        # Get function containing this address
        func = self.rz.get_function_containing(addr)
        if not func:
            return {
                "sink_address": sink_address,
                "has_bounds_check": False,
                "confidence": 0.3,
                "note": "Could not find containing function"
            }

        # Collect instructions before sink
        instructions_before_sink = []
        found_sink = False

        for bb in func.blocks:
            for insn in bb.instructions:
                if insn.address == addr:
                    found_sink = True
                    break
                instructions_before_sink.append(insn)
            if found_sink:
                break

        # Only analyze the most recent N instructions
        recent_instructions = instructions_before_sink[-lookback_instructions:]

        # Analyze bounds check patterns
        bounds_checks = []
        for i, insn in enumerate(recent_instructions):
            mnemonic = insn.mnemonic.lower()

            # Check if it's a comparison instruction
            if mnemonic in self.BOUNDS_CHECK_MNEMONICS:
                # Check if followed by a conditional jump
                for j in range(i + 1, min(i + 5, len(recent_instructions))):
                    next_mnemonic = recent_instructions[j].mnemonic.lower()
                    if next_mnemonic in self.CONDITIONAL_JUMPS:
                        bounds_checks.append({
                            "type": "cmp_jump",
                            "cmp_address": hex(insn.address),
                            "cmp_instruction": f"{insn.mnemonic} {insn.operands}",
                            "jump_address": hex(recent_instructions[j].address),
                            "jump_instruction": f"{recent_instructions[j].mnemonic} {recent_instructions[j].operands}",
                        })
                        break

        # Evaluate bounds check effectiveness
        has_check = len(bounds_checks) > 0
        # Check if it's an effective bounds check (length/size related)
        effective_check = False
        size_related_regs = {'ecx', 'rcx', 'edx', 'rdx', 'r8', 'r9'}  # Common size parameter registers

        for check in bounds_checks:
            cmp_instr = check.get("cmp_instruction", "").lower()
            # Check if comparing potentially size-related registers
            if any(reg in cmp_instr for reg in size_related_regs):
                effective_check = True
                break

        # Calculate confidence adjustment
        if effective_check:
            confidence = 0.2  # Effective bounds check, lower vulnerability confidence
            note = "Effective bounds check found - likely false positive"
        elif has_check:
            confidence = 0.5  # Check exists but might be bypassable
            note = "Bounds check found but may be bypassable"
        else:
            confidence = 0.8  # No bounds check
            note = "No bounds check found - vulnerability likely exploitable"

        return {
            "sink_address": sink_address,
            "function_name": func.name,
            "function_address": hex(func.address),
            "instructions_analyzed": len(recent_instructions),
            "has_bounds_check": has_check,
            "effective_bounds_check": effective_check,
            "bounds_checks": bounds_checks,
            "confidence": confidence,
            "note": note,
            "disassembly_snippet": [
                f"0x{insn.address:x}: {insn.mnemonic} {insn.operands}"
                for insn in recent_instructions[-10:]
            ]
        }


# =============================================================================
# Rizin Tool Adapter
# =============================================================================

class RizinTools(MCPToolAdapter):
    """
    Rizin Tool Adapter

    Wraps RizinCore capabilities as a set of MCP tools.
    """

    def __init__(self, rz: "RizinCore" = None, binary_path: str = None):
        """
        Initialize adapter

        Args:
            rz: RizinCore instance (optional)
            binary_path: Binary file path (if rz is None)
        """
        if rz:
            self.rz = rz
        elif binary_path:
            from luodllhack.core import RizinCore
            self.rz = RizinCore(binary_path)
        else:
            raise ValueError("Either rz or binary_path must be provided")

        self._tools: List[MCPTool] = []
        self._init_tools()

    def _init_tools(self) -> None:
        """Initialize all tools"""
        self._tools = [
            DisassembleFunctionTool(self.rz),
            GetFunctionInfoTool(self.rz),
            ListFunctionsTool(self.rz),
            GetExportsTool(self.rz),
            GetImportsTool(self.rz),
            GetStringsTool(self.rz),
            GetXrefsTool(self.rz),
            GetBinaryInfoTool(self.rz),
            CheckSecurityTool(self.rz),
            AnalyzeBoundsCheckTool(self.rz),  # Bounds check analysis
        ]

    def get_tools(self) -> List[MCPTool]:
        """Get all tools"""
        return self._tools
