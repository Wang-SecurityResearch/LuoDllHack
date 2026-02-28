# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/indirect_call.py

Indirect Call Tracking - Phase 2.1

Core Capabilities:
    1. Identify indirect calls (call reg, call [mem])
    2. Track function pointer sources
    3. Analyze vtable calls
    4. Resolve callback function registrations

Indirect Call Types:
    - Function pointer call: call rax
    - VTable call: call [rcx+offset]
    - Import table call: call [IAT]
    - Jump table: jmp [table+reg*8]

Attack Surface:
    - Tainted data influencing function pointers → Control flow hijacking
    - VTable pointer overwritten → Type confusion exploitation
    - Callback function parameters controllable → Arbitrary code execution
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple, Any
from enum import Enum, auto
import logging

from .cpp_semantics import RTTIParser, VTableMapper
from luodllhack.core.utils import demangle_cpp_symbol

logger = logging.getLogger(__name__)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


class IndirectCallType(Enum):
    """Indirect Call Type"""
    REG_CALL = auto()          # call reg
    MEM_CALL = auto()          # call [mem]
    VTABLE_CALL = auto()       # call [this+offset]
    IAT_CALL = auto()          # call [IAT entry]
    JUMP_TABLE = auto()        # jmp [table+idx*scale]
    CALLBACK = auto()          # Callback function


@dataclass
class IndirectCallInfo:
    """Indirect Call Information"""
    addr: int
    call_type: IndirectCallType
    instruction: str
    # Call target analysis
    target_reg: Optional[str] = None
    target_mem_base: Optional[str] = None
    target_mem_offset: int = 0
    target_mem_scale: int = 1
    # Taint analysis
    is_tainted: bool = False
    taint_source: Optional[str] = None
    # Possible targets
    possible_targets: List[int] = field(default_factory=list)
    # Risk assessment
    risk_level: str = "Medium"
    risk_reason: str = ""

    def to_dict(self) -> dict:
        return {
            'addr': f'0x{self.addr:x}',
            'type': self.call_type.name,
            'instruction': self.instruction,
            'is_tainted': self.is_tainted,
            'risk_level': self.risk_level,
            'risk_reason': self.risk_reason,
            'possible_targets': [f'0x{t:x}' for t in self.possible_targets]
        }


@dataclass
class VTableInfo:
    """VTable Information"""
    vtable_ptr_reg: str          # Register storing vtable pointer (usually this)
    vtable_offset: int           # Offset of vtable within object
    method_offset: int           # Offset of method within vtable
    method_index: int            # Method index
    is_tainted: bool = False     # Whether vtable pointer is tainted

    def to_dict(self) -> dict:
        return {
            'vtable_reg': self.vtable_ptr_reg,
            'vtable_offset': self.vtable_offset,
            'method_offset': self.method_offset,
            'method_index': self.method_index,
            'is_tainted': self.is_tainted
        }


@dataclass
class FunctionPointerSource:
    """Function Pointer Source"""
    addr: int
    source_type: str             # 'import', 'internal', 'callback', 'vtable'
    source_name: Optional[str]   # API name or function name
    assigned_reg: str            # Register the pointer is assigned to
    is_tainted: bool = False

    def to_dict(self) -> dict:
        return {
            'addr': f'0x{self.addr:x}',
            'type': self.source_type,
            'name': self.source_name,
            'reg': self.assigned_reg,
            'tainted': self.is_tainted
        }


class IndirectCallTracker:
    """
    Indirect Call Tracker

    Usage:
        tracker = IndirectCallTracker(binary_data, image_base)

        # Analyze indirect calls in function
        calls = tracker.analyze_function(func_addr)

        for call in calls:
            if call.is_tainted:
                print(f"Danger! Tainted data controls function pointer @ 0x{call.addr:x}")

        # Check for vtable calls
        vtable_calls = tracker.find_vtable_calls(func_addr)
    """

    # Common vtable offset patterns
    VTABLE_PATTERNS = {
        # C++ vtable is usually at the start of the object
        0: "Possible vtable pointer (object+0)",
        8: "Possible secondary vtable (multiple inheritance)",
    }

    # Common callback registration APIs
    CALLBACK_APIS = {
        b'SetWindowsHookExA': {'callback_arg': 2, 'type': 'hook'},
        b'SetWindowsHookExW': {'callback_arg': 2, 'type': 'hook'},
        b'CreateThread': {'callback_arg': 2, 'type': 'thread'},
        b'QueueUserWorkItem': {'callback_arg': 0, 'type': 'work'},
        b'RegisterWaitForSingleObject': {'callback_arg': 2, 'type': 'wait'},
        b'SetTimer': {'callback_arg': 3, 'type': 'timer'},
        b'EnumWindows': {'callback_arg': 0, 'type': 'enum'},
        b'EnumChildWindows': {'callback_arg': 1, 'type': 'enum'},
        b'RegNotifyChangeKeyValue': {'callback_arg': 4, 'type': 'registry'},
        b'ReadFileEx': {'callback_arg': 4, 'type': 'io'},
        b'WriteFileEx': {'callback_arg': 4, 'type': 'io'},
    }

    def __init__(self, binary_data: bytes, image_base: int,
                 arch: str = "x64", pe=None):
        """
        Initialize the indirect call tracker

        Args:
            binary_data: Binary data
            image_base: Image base address
            arch: Architecture
            pe: pefile object
        """
        if not HAVE_CAPSTONE:
            raise ImportError("Capstone is required")

        self.binary_data = binary_data
        self.image_base = image_base
        self.arch = arch
        self.pe = pe
        self.ptr_size = 8 if arch == "x64" else 4

        mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
        self.md = Cs(CS_ARCH_X86, mode)
        self.md.detail = True

        # Import Address Table range
        self.iat_range = self._get_iat_range()

        # Tracking state
        self.function_pointers: Dict[str, FunctionPointerSource] = {}
        self.indirect_calls: List[IndirectCallInfo] = []
        
        # C++ Semantic support
        self.rtti_parser = RTTIParser(binary_data, image_base, pe)
        self.vtable_mapper = VTableMapper(self.rtti_parser)
        self.vtable_mapper.populate()

    def _get_iat_range(self) -> Tuple[int, int]:
        """Get the IAT address range"""
        if not self.pe:
            return (0, 0)

        try:
            iat_rva = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
            iat_size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
            iat_start = self.image_base + iat_rva
            return (iat_start, iat_start + iat_size)
        except (IndexError, AttributeError):
            # PE data directory access failed
            return (0, 0)

    def analyze_function(self, func_addr: int,
                          max_instructions: int = 1000,
                          tainted_regs: Set[str] = None) -> List[IndirectCallInfo]:
        """
        Analyze indirect calls within a function

        Args:
            func_addr: Function address
            max_instructions: Maximum number of instructions to analyze
            tainted_regs: Currently tainted registers

        Returns:
            List of indirect calls
        """
        tainted_regs = tainted_regs or set()
        self.indirect_calls = []

        try:
            rva = func_addr - self.image_base
            if self.pe:
                offset = self.pe.get_offset_from_rva(rva)
            else:
                offset = rva

            if offset is None or offset < 0:
                return []

            code = self.binary_data[offset:offset + max_instructions * 15]
            if not code:
                return []

            for i, insn in enumerate(self.md.disasm(code, func_addr)):
                if i >= max_instructions:
                    break

                # Detect indirect call
                if insn.mnemonic in ('call', 'jmp'):
                    call_info = self._analyze_call(insn, tainted_regs)
                    if call_info:
                        self.indirect_calls.append(call_info)

                # Track function pointer assignment
                self._track_function_pointer(insn, tainted_regs)

                # Stop at ret
                if insn.mnemonic in ('ret', 'retn'):
                    break

        except Exception as e:
            pass

        return self.indirect_calls

    def _analyze_call(self, insn, tainted_regs: Set[str]) -> Optional[IndirectCallInfo]:
        """Analyze a single call instruction"""
        if not insn.operands:
            return None

        op = insn.operands[0]

        # Direct call (call imm) - skip
        if op.type == X86_OP_IMM:
            return None

        # Register call (call reg)
        if op.type == X86_OP_REG:
            reg_name = insn.reg_name(op.reg).lower()
            is_tainted = reg_name in tainted_regs or self._is_reg_alias_tainted(reg_name, tainted_regs)

            call_info = IndirectCallInfo(
                addr=insn.address,
                call_type=IndirectCallType.REG_CALL,
                instruction=f"{insn.mnemonic} {insn.op_str}",
                target_reg=reg_name,
                is_tainted=is_tainted,
            )

            # Check for known source
            if reg_name in self.function_pointers:
                source = self.function_pointers[reg_name]
                call_info.possible_targets.append(source.addr)
                call_info.risk_reason = f"Function pointer source: {source.source_type}"

            if is_tainted:
                call_info.risk_level = "Critical"
                call_info.risk_reason = "Tainted data controls call target - potential control flow hijacking"
                call_info.taint_source = f"reg:{reg_name}"

            return call_info

        # Memory call (call [mem])
        if op.type == X86_OP_MEM:
            base_reg = insn.reg_name(op.mem.base).lower() if op.mem.base else None
            index_reg = insn.reg_name(op.mem.index).lower() if op.mem.index else None
            offset = op.mem.disp
            scale = op.mem.scale

            # Check if it's an IAT call
            if self._is_iat_address(insn.address, op):
                return None  # IAT call is normal, don't report

            # Check for vtable call pattern
            vtable_info = self._check_vtable_pattern(base_reg, offset)
            if vtable_info:
                is_tainted = base_reg in tainted_regs if base_reg else False
                call_info = IndirectCallInfo(
                    addr=insn.address,
                    call_type=IndirectCallType.VTABLE_CALL,
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    target_mem_base=base_reg,
                    target_mem_offset=offset,
                    is_tainted=is_tainted,
                )

                if is_tainted:
                    call_info.risk_level = "Critical"
                    call_info.risk_reason = "VTable pointer tainted - potential type confusion exploitation"
                else:
                    class_name = self.vtable_mapper.get_class_for_vtable(offset)
                    if class_name:
                        class_name = demangle_cpp_symbol(class_name)
                    class_suffix = f" (class: {class_name})" if class_name else ""
                    call_info.risk_level = "Low"
                    call_info.risk_reason = f"VTable call (method index: {offset // self.ptr_size}){class_suffix}"

                return call_info

            # Check for jump table
            if index_reg and scale in (4, 8):
                is_tainted = index_reg in tainted_regs
                call_info = IndirectCallInfo(
                    addr=insn.address,
                    call_type=IndirectCallType.JUMP_TABLE,
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    target_mem_base=base_reg,
                    target_mem_offset=offset,
                    target_mem_scale=scale,
                    is_tainted=is_tainted,
                )

                if is_tainted:
                    call_info.risk_level = "High"
                    call_info.risk_reason = "Jump table index affected by taint"
                else:
                    call_info.risk_level = "Info"
                    call_info.risk_reason = "Jump table call"

                return call_info

            # General memory indirect call
            is_tainted = (base_reg in tainted_regs if base_reg else False) or \
                         (index_reg in tainted_regs if index_reg else False)

            call_info = IndirectCallInfo(
                addr=insn.address,
                call_type=IndirectCallType.MEM_CALL,
                instruction=f"{insn.mnemonic} {insn.op_str}",
                target_mem_base=base_reg,
                target_mem_offset=offset,
                is_tainted=is_tainted,
            )

            if is_tainted:
                call_info.risk_level = "High"
                call_info.risk_reason = "Memory indirect call address may be controlled"

            return call_info

        return None

    def _is_iat_address(self, insn_addr: int, op) -> bool:
        """Check if it's an IAT call"""
        if not self.iat_range[0]:
            return False

        # Calculate actual address
        if op.mem.base == 0 and op.mem.index == 0:
            # Absolute address
            addr = op.mem.disp
        elif self.arch == "x64" and op.mem.base:
            # RIP-relative addressing
            # For call [rip+disp], the actual address = next_insn_addr + disp
            # Calculated by capstone
            addr = insn_addr + op.mem.disp + 6  # assuming instruction length 6
        else:
            return False

        return self.iat_range[0] <= addr < self.iat_range[1]

    def _check_vtable_pattern(self, base_reg: str, offset: int) -> Optional[Dict]:
        """Check for vtable call pattern"""
        if not base_reg:
            return None

        # Typical vtable call: call [rcx] or call [rcx+offset]
        # rcx is often the this pointer
        if base_reg in ('rcx', 'ecx', 'rdi', 'edi'):  # Common this pointer registers
            if offset % self.ptr_size == 0:  # Offset is a multiple of pointer size
                return {
                    'base': base_reg,
                    'offset': offset,
                    'method_index': offset // self.ptr_size
                }

        return None

    def _track_function_pointer(self, insn, tainted_regs: Set[str]):
        """Track function pointer assignment"""
        # lea reg, [rip+offset] - may load function address
        if insn.mnemonic == 'lea' and len(insn.operands) >= 2:
            dst = insn.operands[0]
            src = insn.operands[1]

            if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                reg_name = insn.reg_name(dst.reg).lower()

                source = FunctionPointerSource(
                    addr=insn.address,
                    source_type='internal',
                    source_name=None,
                    assigned_reg=reg_name,
                    is_tainted=False
                )
                self.function_pointers[reg_name] = source

        # mov reg, [IAT] - loading from import table
        if insn.mnemonic == 'mov' and len(insn.operands) >= 2:
            dst = insn.operands[0]
            src = insn.operands[1]

            if dst.type == X86_OP_REG:
                reg_name = insn.reg_name(dst.reg).lower()
                is_tainted = False

                if src.type == X86_OP_REG:
                    src_reg = insn.reg_name(src.reg).lower()
                    is_tainted = src_reg in tainted_regs

                source = FunctionPointerSource(
                    addr=insn.address,
                    source_type='mov',
                    source_name=None,
                    assigned_reg=reg_name,
                    is_tainted=is_tainted
                )
                self.function_pointers[reg_name] = source

    def _is_reg_alias_tainted(self, reg: str, tainted_regs: Set[str]) -> bool:
        """Check if register alias is tainted"""
        aliases = {
            'rax': {'eax', 'ax', 'al'},
            'rbx': {'ebx', 'bx', 'bl'},
            'rcx': {'ecx', 'cx', 'cl'},
            'rdx': {'edx', 'dx', 'dl'},
        }

        for base, alias_set in aliases.items():
            if reg == base or reg in alias_set:
                full_set = {base} | alias_set
                if full_set & tainted_regs:
                    return True

        return False

    def find_callback_registrations(self, func_addr: int,
                                     max_instructions: int = 500) -> List[Dict]:
        """
        Find callback function registrations

        Args:
            func_addr: Function address
            max_instructions: Maximum instructions to analyze

        Returns:
            List of callback registrations
        """
        registrations = []

        try:
            rva = func_addr - self.image_base
            if self.pe:
                offset = self.pe.get_offset_from_rva(rva)
            else:
                offset = rva

            code = self.binary_data[offset:offset + max_instructions * 15]

            for insn in self.md.disasm(code, func_addr):
                if insn.mnemonic == 'call':
                    # Logic needed to resolve call target and check for callback reg API
                    # Simplified placeholder
                    pass

        except Exception:
            pass

        return registrations

    def get_tainted_calls(self) -> List[IndirectCallInfo]:
        """Get all taint-related indirect calls"""
        return [c for c in self.indirect_calls if c.is_tainted]

    def get_high_risk_calls(self) -> List[IndirectCallInfo]:
        """Get high risk indirect calls"""
        return [c for c in self.indirect_calls
                if c.risk_level in ('Critical', 'High')]
