# -*- coding: utf-8 -*-
"""Extract analysis context from Cutter/Rizin."""

import cutter
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class VerificationContext:
    """Context extracted from Cutter for AI verification"""
    address: int = 0
    function_name: str = ""
    function_address: int = 0
    decompiled: str = ""           # Ghidra decompiler output
    disassembly: str = ""          # Function disassembly
    basic_blocks: List[Dict] = field(default_factory=list)
    xrefs_to: List[Dict] = field(default_factory=list)    # Callers
    xrefs_from: List[Dict] = field(default_factory=list)  # Callees
    variables: List[Dict] = field(default_factory=list)
    function_info: Dict = field(default_factory=dict)


class ContextExtractor:
    """Extract rich context from Cutter/Rizin for vulnerability verification"""

    def extract(self, address: int) -> VerificationContext:
        """Extract full context for a vulnerability address"""
        ctx = VerificationContext(address=address)

        # Get function containing this address
        ctx.function_info = self._get_function_at(address)
        if ctx.function_info:
            ctx.function_name = ctx.function_info.get("name", f"fcn_{address:x}")
            ctx.function_address = ctx.function_info.get("offset", address)
        else:
            ctx.function_name = f"fcn_{address:x}"
            ctx.function_address = address

        # Seek to function start for analysis
        func_addr = ctx.function_address
        cutter.cmd(f"s {func_addr}")

        # Get decompiled code (Ghidra)
        ctx.decompiled = self._get_decompiled(func_addr)

        # Get disassembly
        ctx.disassembly = self._get_disassembly(func_addr)

        # Get CFG (basic blocks)
        ctx.basic_blocks = self._get_basic_blocks(func_addr)

        # Get cross-references
        ctx.xrefs_to = self._get_xrefs_to(address)
        ctx.xrefs_from = self._get_xrefs_from(func_addr)

        # Get variables
        ctx.variables = self._get_variables(func_addr)

        return ctx

    def _get_function_at(self, address: int) -> Dict:
        """Get function info containing address"""
        try:
            cutter.cmd(f"s {address}")
            info = cutter.cmdj("afij")
            if info and len(info) > 0:
                return info[0]
        except Exception:
            pass
        return {}

    def _get_decompiled(self, address: int) -> str:
        """Get Ghidra decompiler output"""
        try:
            cutter.cmd(f"s {address}")
            result = cutter.cmd("pdg")
            if result and "Cannot" not in result and "error" not in result.lower():
                return result.strip()
        except Exception:
            pass
        return ""

    def _get_disassembly(self, address: int) -> str:
        """Get function disassembly"""
        try:
            result = cutter.cmd(f"pdf @ {address}")
            if result and "Cannot" not in result:
                return result.strip()
        except Exception:
            pass
        return ""

    def _get_basic_blocks(self, address: int) -> List[Dict]:
        """Get basic blocks as JSON"""
        try:
            blocks = cutter.cmdj(f"afbj @ {address}")
            return blocks if blocks else []
        except Exception:
            return []

    def _get_xrefs_to(self, address: int) -> List[Dict]:
        """Get cross-references TO this address (callers)"""
        try:
            xrefs = cutter.cmdj(f"axtj @ {address}")
            return xrefs if xrefs else []
        except Exception:
            return []

    def _get_xrefs_from(self, address: int) -> List[Dict]:
        """Get cross-references FROM this address (callees)"""
        try:
            xrefs = cutter.cmdj(f"axfj @ {address}")
            return xrefs if xrefs else []
        except Exception:
            return []

    def _get_variables(self, address: int) -> List[Dict]:
        """Get function variables"""
        try:
            cutter.cmd(f"s {address}")
            variables = cutter.cmdj("afvj")
            return variables if variables else []
        except Exception:
            return []

    def get_disasm_at(self, address: int, count: int = 20) -> str:
        """Get disassembly around specific address"""
        try:
            return cutter.cmd(f"pd {count} @ {address}")
        except Exception:
            return ""
