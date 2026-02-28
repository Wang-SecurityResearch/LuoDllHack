# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/bounds_checker.py

Bounds Check Detector - Phase 1.1

Core Capabilities:
    1. Detect length/bounds checks before a sink
    2. Identify common bounds check patterns
    3. Analyze the effectiveness of the checks

Detection Patterns:
    - cmp reg, imm + ja/jae (Unsigned comparison)
    - cmp reg, imm + jg/jge (Signed comparison)
    - test reg, reg + jz/jnz (Null/Zero check)
    - Comparison after calling strlen
    - Secure function calls (strncpy vs strcpy)

Principle:
    If there is a check on the input length before calling a dangerous API,
    and the check leads to skipping the dangerous call, the path might be safe.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple, Dict
from enum import Enum, auto

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


class CheckType(Enum):
    """Type of bounds check"""
    LENGTH_CMP = auto()       # Length comparison (cmp len, max)
    NULL_CHECK = auto()        # Null pointer check (test ptr, ptr)
    SIZE_VALIDATION = auto()   # Size validation (comparison after calling strlen)
    SAFE_API_CALL = auto()     # Safe API call (strncpy vs strcpy)
    LOOP_BOUND = auto()        # Loop bounds check
    BUFFER_SIZE_CHECK = auto() # Buffer size check


@dataclass
class BoundsCheckResult:
    """Result of bounds check detection"""
    has_check: bool
    check_type: Optional[CheckType] = None
    check_addr: int = 0
    check_instruction: str = ""
    jump_addr: int = 0
    jump_instruction: str = ""
    # Specific check info
    compared_reg: str = ""
    compared_value: Optional[int] = None
    # Whether the check is effective (actually prevents a vulnerability)
    is_effective: bool = False
    effectiveness_reason: str = ""
    # Detailed info
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'has_check': self.has_check,
            'check_type': self.check_type.name if self.check_type else None,
            'check_addr': f'0x{self.check_addr:x}' if self.check_addr else None,
            'is_effective': self.is_effective,
            'details': self.details
        }


class BoundsChecker:
    """
    Bounds Check Detector

    Usage:
        checker = BoundsChecker(binary_data, image_base)

        # Detect bounds check before sink
        result = checker.check_before_sink(
            sink_addr=0x1000,
            tainted_reg='rcx'
        )

        if result.has_check:
            print(f"Detected bounds check: {result.check_type}")
            if result.is_effective:
                print("Check is effective, might not be a vulnerability")
    """

    # Conditional jump instructions
    COND_JUMPS = {
        # Unsigned comparisons
        'ja', 'jae', 'jb', 'jbe', 'jnb', 'jnbe', 'jna', 'jnae',
        # Signed comparisons
        'jg', 'jge', 'jl', 'jle', 'jng', 'jnge', 'jnl', 'jnle',
        # Equality/Zero checks
        'je', 'jne', 'jz', 'jnz',
        # Others
        'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
    }

    # Comparison instructions
    CMP_INSTRUCTIONS = {'cmp', 'test'}

    # Length-related registers (typically used to store lengths)
    LENGTH_REGS_X64 = {'rax', 'eax', 'rcx', 'ecx', 'rdx', 'edx', 'r8', 'r8d', 'r9', 'r9d'}
    LENGTH_REGS_X86 = {'eax', 'ecx', 'edx', 'ebx'}

    # Functions to get length
    LENGTH_FUNCTIONS = {
        b'strlen', b'wcslen', b'lstrlenA', b'lstrlenW',
        b'_mbstrlen', b'strnlen', b'wcsnlen',
    }

    # Safe function alternatives
    SAFE_ALTERNATIVES = {
        b'strcpy': b'strncpy',
        b'strcat': b'strncat',
        b'sprintf': b'snprintf',
        b'vsprintf': b'vsnprintf',
        b'gets': b'fgets',
        b'lstrcpyA': b'StringCchCopyA',
        b'lstrcpyW': b'StringCchCopyW',
    }

    def __init__(self, binary_data: bytes, image_base: int,
                 arch: str = "x64", pe=None):
        """
        Initialize the bounds check detector

        Args:
            binary_data: Binary data
            image_base: Image base address
            arch: Architecture
            pe: pefile object
        """
        if not HAVE_CAPSTONE:
            raise ImportError("Capstone is required: pip install capstone")

        self.binary_data = binary_data
        self.image_base = image_base
        self.arch = arch
        self.pe = pe

        # Initialize disassembler
        mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
        self.md = Cs(CS_ARCH_X86, mode)
        self.md.detail = True

        self.length_regs = self.LENGTH_REGS_X64 if arch == "x64" else self.LENGTH_REGS_X86

        # Cache analyzed functions
        self._analysis_cache: Dict[int, List] = {}

    def check_before_sink(self, sink_addr: int, tainted_reg: str,
                          window: int = 50) -> BoundsCheckResult:
        """
        Detect if there is a bounds check before a sink

        Args:
            sink_addr: Sink call address
            tainted_reg: Tainted register
            window: Number of instructions to scan backwards

        Returns:
            BoundsCheckResult
        """
        result = BoundsCheckResult(has_check=False)
        details = []

        # Get instruction sequence before sink
        instructions = self._get_instructions_before(sink_addr, window)
        if not instructions:
            result.details.append("Could not retrieve instructions before sink")
            return result

        # Analyze instruction sequence for bounds check patterns
        cmp_insn = None
        cmp_idx = -1

        for idx, insn in enumerate(instructions):
            # Detect comparison instructions
            if insn.mnemonic in self.CMP_INSTRUCTIONS:
                cmp_insn = insn
                cmp_idx = idx
                details.append(f"Found comparison instruction @ 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

                # Check if the compared register is related to taint
                if self._involves_register(insn, tainted_reg):
                    details.append(f"  → Involves tainted register {tainted_reg}")

                    # Check for subsequent conditional jump
                    for j in range(idx + 1, min(idx + 5, len(instructions))):
                        next_insn = instructions[j]
                        if next_insn.mnemonic in self.COND_JUMPS:
                            result.has_check = True
                            result.check_type = CheckType.LENGTH_CMP
                            result.check_addr = insn.address
                            result.check_instruction = f"{insn.mnemonic} {insn.op_str}"
                            result.jump_addr = next_insn.address
                            result.jump_instruction = f"{next_insn.mnemonic} {next_insn.op_str}"
                            result.compared_reg = tainted_reg

                            # Extract comparison value
                            result.compared_value = self._extract_compare_value(insn)

                            # Evaluate check effectiveness
                            self._evaluate_effectiveness(result, insn, next_insn, sink_addr)

                            details.append(f"  → Followed by conditional jump @ 0x{next_insn.address:x}: {next_insn.mnemonic}")
                            result.details = details
                            return result

            # Detect test instruction (null pointer check)
            if insn.mnemonic == 'test':
                if self._is_null_check(insn, tainted_reg):
                    for j in range(idx + 1, min(idx + 5, len(instructions))):
                        next_insn = instructions[j]
                        if next_insn.mnemonic in ('jz', 'je', 'jnz', 'jne'):
                            result.has_check = True
                            result.check_type = CheckType.NULL_CHECK
                            result.check_addr = insn.address
                            result.check_instruction = f"{insn.mnemonic} {insn.op_str}"
                            result.jump_addr = next_insn.address
                            result.is_effective = True
                            result.effectiveness_reason = "Null pointer check prevents null pointer dereference"
                            details.append(f"Detected null pointer check @ 0x{insn.address:x}")
                            result.details = details
                            return result

        # Check for strlen followed by comparison pattern
        strlen_result = self._check_strlen_pattern(instructions, tainted_reg)
        if strlen_result:
            result.has_check = True
            result.check_type = CheckType.SIZE_VALIDATION
            result.details = strlen_result.details
            result.is_effective = strlen_result.is_effective
            return result

        result.details = details if details else ["No bounds check detected"]
        return result

    def _get_instructions_before(self, addr: int, count: int) -> List:
        """Retrieve N instructions before a specified address"""
        # Calculate start RVA
        try:
            rva = addr - self.image_base
            # Scan backwards (estimating 5 bytes average per instruction)
            scan_size = count * 15
            start_rva = max(0, rva - scan_size)

            if self.pe:
                offset = self.pe.get_offset_from_rva(start_rva)
                if offset is None or offset < 0:
                    return []
            else:
                offset = start_rva

            code = self.binary_data[offset:offset + scan_size + 100]
            if not code:
                return []

            # Disassemble
            instructions = list(self.md.disasm(code, self.image_base + start_rva))

            # Find instructions before target address
            result = []
            for insn in instructions:
                if insn.address >= addr:
                    break
                result.append(insn)

            # Return the last N instructions
            return result[-count:] if len(result) > count else result

        except Exception as e:
            return []

    def _involves_register(self, insn, reg: str) -> bool:
        """Check if an instruction involves a specified register"""
        reg_lower = reg.lower()
        op_str_lower = insn.op_str.lower()

        # Direct match
        if reg_lower in op_str_lower:
            return True

        # Check register aliases (rax/eax/ax/al)
        reg_aliases = self._get_register_aliases(reg_lower)
        for alias in reg_aliases:
            if alias in op_str_lower:
                return True

        return False

    def _get_register_aliases(self, reg: str) -> Set[str]:
        """Get all aliases for a register"""
        aliases = {reg}

        # x64 register mapping
        reg_families = {
            'rax': {'rax', 'eax', 'ax', 'al', 'ah'},
            'rbx': {'rbx', 'ebx', 'bx', 'bl', 'bh'},
            'rcx': {'rcx', 'ecx', 'cx', 'cl', 'ch'},
            'rdx': {'rdx', 'edx', 'dx', 'dl', 'dh'},
            'rsi': {'rsi', 'esi', 'si', 'sil'},
            'rdi': {'rdi', 'edi', 'di', 'dil'},
            'rbp': {'rbp', 'ebp', 'bp', 'bpl'},
            'rsp': {'rsp', 'esp', 'sp', 'spl'},
            'r8': {'r8', 'r8d', 'r8w', 'r8b'},
            'r9': {'r9', 'r9d', 'r9w', 'r9b'},
            'r10': {'r10', 'r10d', 'r10w', 'r10b'},
            'r11': {'r11', 'r11d', 'r11w', 'r11b'},
            'r12': {'r12', 'r12d', 'r12w', 'r12b'},
            'r13': {'r13', 'r13d', 'r13w', 'r13b'},
            'r14': {'r14', 'r14d', 'r14w', 'r14b'},
            'r15': {'r15', 'r15d', 'r15w', 'r15b'},
        }

        for family_base, family_regs in reg_families.items():
            if reg in family_regs:
                return family_regs

        return aliases

    def _is_null_check(self, insn, reg: str) -> bool:
        """Check if instruction is a null point check (test reg, reg)"""
        if insn.mnemonic != 'test':
            return False

        op_str = insn.op_str.lower()
        parts = [p.strip() for p in op_str.split(',')]

        if len(parts) == 2:
            # test reg, reg form
            if parts[0] == parts[1]:
                return self._involves_register(insn, reg)

        return False

    def _extract_compare_value(self, insn) -> Optional[int]:
        """Extract immediate value from comparison instruction"""
        if not insn.operands:
            return None

        for op in insn.operands:
            if op.type == X86_OP_IMM:
                return op.imm

        return None

    def _evaluate_effectiveness(self, result: BoundsCheckResult,
                                 cmp_insn, jmp_insn, sink_addr: int):
        """Evaluate effectiveness of a bounds check"""
        # Get jump target
        jmp_target = self._get_jump_target(jmp_insn)

        if jmp_target is None:
            result.is_effective = False
            result.effectiveness_reason = "Could not determine jump target"
            return

        # Check if the jump skips the sink
        if jmp_target > sink_addr:
            result.is_effective = True
            result.effectiveness_reason = "Skips dangerous call on check failure"
        elif jmp_target < cmp_insn.address:
            result.is_effective = False
            result.effectiveness_reason = "Jump target is before the check (likely a loop)"
        else:
            # Requires more complex control flow analysis
            result.is_effective = False
            result.effectiveness_reason = "Requires further control flow analysis"

        # Check if comparison value is reasonable
        if result.compared_value is not None:
            if result.compared_value == 0:
                result.effectiveness_reason += "; comparison value is 0 (likely null check)"
            elif result.compared_value > 0x10000:
                result.is_effective = False
                result.effectiveness_reason += "; comparison value too large, likely not a length check"

    def _get_jump_target(self, jmp_insn) -> Optional[int]:
        """Get target address for a jump instruction"""
        if not jmp_insn.operands:
            return None

        op = jmp_insn.operands[0]
        if op.type == X86_OP_IMM:
            return op.imm

        return None

    def _check_strlen_pattern(self, instructions: List,
                               tainted_reg: str) -> Optional[BoundsCheckResult]:
        """Detect strlen + comparison pattern"""
        # Look for comparison of rax after calling strlen
        for idx, insn in enumerate(instructions):
            # Detect call instruction
            if insn.mnemonic == 'call':
                # Simplified handling; assume comparison of rax follows
                if idx + 1 < len(instructions):
                    next_insn = instructions[idx + 1]
                    # Check for cmp rax (strlen return value)
                    if next_insn.mnemonic == 'cmp' and 'rax' in next_insn.op_str.lower():
                        result = BoundsCheckResult(has_check=True)
                        result.check_type = CheckType.SIZE_VALIDATION
                        result.check_addr = next_insn.address
                        result.is_effective = True
                        result.details.append(f"Detected strlen + comparison pattern @ 0x{next_insn.address:x}")
                        return result

        return None

    def check_safe_api_alternative(self, api_name: bytes) -> Optional[bytes]:
        """Check if a safe alternative for the API exists"""
        return self.SAFE_ALTERNATIVES.get(api_name)
