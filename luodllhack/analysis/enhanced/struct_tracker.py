# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/struct_tracker.py

Structure Field Tracking - Phase 2.3

Core Capabilities:
    1. Identify structure/object access patterns
    2. Track field-level taint propagation
    3. Analyze structure layout
    4. Detect field-related vulnerabilities

Detection Patterns:
    - mov reg, [base+offset] : Field read
    - mov [base+offset], reg : Field write
    - lea reg, [base+offset] : Field address acquisition

Attack Surface:
    - Taint written to sensitive fields (function pointers, length fields)
    - Integer overflow affecting length fields
    - Type confusion leading to field misalignment

Common Sensitive Fields:
    - Offset 0: VTable pointer
    - Function pointer fields
    - Size/Length fields
    - Reference count fields
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple, Any
from enum import Enum, auto


class FieldType(Enum):
    """Field Type"""
    UNKNOWN = auto()
    VTABLE_PTR = auto()      # VTable pointer
    FUNC_PTR = auto()        # Function pointer
    SIZE_FIELD = auto()      # Size field
    LENGTH_FIELD = auto()    # Length field
    REF_COUNT = auto()       # Reference count
    DATA_PTR = auto()        # Data pointer
    BUFFER = auto()          # Inlined buffer
    FLAGS = auto()           # Flags


class AccessType(Enum):
    """Access Type"""
    READ = auto()
    WRITE = auto()
    LEA = auto()            # Load Effective Address


@dataclass
class FieldAccess:
    """Field Access Record"""
    addr: int               # Address of the access instruction
    access_type: AccessType
    base_reg: str           # Base register
    offset: int             # Field offset
    size: int               # Access size (bytes)
    value_reg: str          # Value register
    instruction: str
    # Taint status
    is_base_tainted: bool = False
    is_value_tainted: bool = False
    # Field analysis
    field_type: FieldType = FieldType.UNKNOWN
    is_sensitive: bool = False

    def to_dict(self) -> dict:
        return {
            'addr': f'0x{self.addr:x}',
            'type': self.access_type.name,
            'base': self.base_reg,
            'offset': self.offset,
            'size': self.size,
            'value_reg': self.value_reg,
            'base_tainted': self.is_base_tainted,
            'value_tainted': self.is_value_tainted,
            'field_type': self.field_type.name,
            'sensitive': self.is_sensitive
        }


@dataclass
class StructInfo:
    """Structure Information"""
    base_reg: str
    base_source: str        # Structure source (parameter/allocation/global)
    known_fields: Dict[int, FieldType]  # offset -> type
    field_accesses: List[FieldAccess]
    # Estimated size
    estimated_size: int = 0
    # Whether it is a known type
    known_type: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'base': self.base_reg,
            'source': self.base_source,
            'estimated_size': self.estimated_size,
            'known_type': self.known_type,
            'fields': {f'0x{k:x}': v.name for k, v in self.known_fields.items()},
            'accesses': len(self.field_accesses)
        }


@dataclass
class FieldVulnerability:
    """Field-related Vulnerability"""
    addr: int
    vuln_type: str
    field_offset: int
    field_type: FieldType
    description: str
    risk_level: str
    taint_source: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'addr': f'0x{self.addr:x}',
            'type': self.vuln_type,
            'offset': self.field_offset,
            'field': self.field_type.name,
            'risk': self.risk_level,
            'description': self.description
        }


class StructFieldTracker:
    """
    Structure Field Tracker

    Usage:
        tracker = StructFieldTracker(binary_data, image_base)

        # Analyze structure accesses in a function
        accesses, vulns = tracker.analyze_function(
            func_addr=0x1000,
            tainted_regs={'rcx', 'rdx'}
        )

        for vuln in vulns:
            print(f"Field vulnerability @ 0x{vuln.addr:x}: {vuln.description}")
    """

    # Sensitive offsets (common structure layouts)
    SENSITIVE_OFFSETS = {
        0: FieldType.VTABLE_PTR,    # C++ VTable pointer
        # Windows-specific
        0x18: FieldType.SIZE_FIELD,  # Size field in some structures
        0x28: FieldType.DATA_PTR,    # Data pointer in some structures
    }

    # Indicators of common length field names
    LENGTH_FIELD_INDICATORS = {
        'length', 'len', 'size', 'count', 'num', 'cb', 'cch', 'dw'
    }

    def __init__(self, binary_data: bytes, image_base: int,
                 arch: str = "x64", pe=None):
        """
        Initialize the structure tracker

        Args:
            binary_data: Binary data
            image_base: Image base address
            arch: Architecture
            pe: pefile object
        """
        self.binary_data = binary_data
        self.image_base = image_base
        self.arch = arch
        self.pe = pe
        self.ptr_size = 8 if arch == "x64" else 4

        # Tracking state
        self.structs: Dict[str, StructInfo] = {}
        self.field_accesses: List[FieldAccess] = []
        self.vulnerabilities: List[FieldVulnerability] = []

        # Import capstone
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            from capstone.x86 import X86_OP_REG, X86_OP_MEM
            mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
            self.md = Cs(CS_ARCH_X86, mode)
            self.md.detail = True
            self.X86_OP_REG = X86_OP_REG
            self.X86_OP_MEM = X86_OP_MEM
            self.have_capstone = True
        except ImportError:
            self.have_capstone = False

    def analyze_function(self, func_addr: int,
                          tainted_regs: Set[str] = None,
                          max_instructions: int = 1000) -> Tuple[List[FieldAccess], List[FieldVulnerability]]:
        """
        Analyze structure accesses within a function

        Args:
            func_addr: Function address
            tainted_regs: Tainted registers
            max_instructions: Maximum instructions to analyze

        Returns:
            (List of field accesses, List of vulnerabilities)
        """
        if not self.have_capstone:
            return [], []

        tainted_regs = tainted_regs or set()
        self.field_accesses = []
        self.vulnerabilities = []

        try:
            rva = func_addr - self.image_base
            if self.pe:
                offset = self.pe.get_offset_from_rva(rva)
            else:
                offset = rva

            if offset is None or offset < 0:
                return [], []

            code = self.binary_data[offset:offset + max_instructions * 15]

            for i, insn in enumerate(self.md.disasm(code, func_addr)):
                if i >= max_instructions:
                    break

                # Analyze memory access
                access = self._analyze_memory_access(insn, tainted_regs)
                if access:
                    self.field_accesses.append(access)

                    # Detect vulnerability
                    vuln = self._check_field_vulnerability(access)
                    if vuln:
                        self.vulnerabilities.append(vuln)

                # Update taint state (simplified)
                self._update_taint_state(insn, tainted_regs)

                if insn.mnemonic in ('ret', 'retn'):
                    break

        except Exception as e:
            pass

        return self.field_accesses, self.vulnerabilities

    def _analyze_memory_access(self, insn, tainted_regs: Set[str]) -> Optional[FieldAccess]:
        """Analyze memory access of a single instruction"""
        if insn.mnemonic == 'lea':
            return self._analyze_lea(insn, tainted_regs)
        elif insn.mnemonic == 'mov':
            return self._analyze_mov(insn, tainted_regs)
        return None

    def _analyze_lea(self, insn, tainted_regs: Set[str]) -> Optional[FieldAccess]:
        """Analyze lea instruction"""
        if len(insn.operands) < 2:
            return None

        dst = insn.operands[0]
        src = insn.operands[1]

        if dst.type != self.X86_OP_REG or src.type != self.X86_OP_MEM:
            return None

        base_reg = insn.reg_name(src.mem.base).lower() if src.mem.base else None
        if not base_reg:
            return None

        offset = src.mem.disp
        dst_reg = insn.reg_name(dst.reg).lower()

        # Classify field type
        field_type, is_sensitive = self._classify_field(offset)

        return FieldAccess(
            addr=insn.address,
            access_type=AccessType.LEA,
            base_reg=base_reg,
            offset=offset,
            size=self.ptr_size,
            value_reg=dst_reg,
            instruction=f"{insn.mnemonic} {insn.op_str}",
            is_base_tainted=base_reg in tainted_regs,
            is_value_tainted=False,
            field_type=field_type,
            is_sensitive=is_sensitive
        )

    def _analyze_mov(self, insn, tainted_regs: Set[str]) -> Optional[FieldAccess]:
        """Analyze mov instruction"""
        if len(insn.operands) < 2:
            return None

        dst = insn.operands[0]
        src = insn.operands[1]

        # mov reg, [base+offset] - Read
        if dst.type == self.X86_OP_REG and src.type == self.X86_OP_MEM:
            base_reg = insn.reg_name(src.mem.base).lower() if src.mem.base else None
            if not base_reg:
                return None

            offset = src.mem.disp
            dst_reg = insn.reg_name(dst.reg).lower()
            field_type, is_sensitive = self._classify_field(offset)

            return FieldAccess(
                addr=insn.address,
                access_type=AccessType.READ,
                base_reg=base_reg,
                offset=offset,
                size=dst.size,
                value_reg=dst_reg,
                instruction=f"{insn.mnemonic} {insn.op_str}",
                is_base_tainted=base_reg in tainted_regs,
                is_value_tainted=False,
                field_type=field_type,
                is_sensitive=is_sensitive
            )

        # mov [base+offset], reg - Write
        if dst.type == self.X86_OP_MEM and src.type == self.X86_OP_REG:
            base_reg = insn.reg_name(dst.mem.base).lower() if dst.mem.base else None
            if not base_reg:
                return None

            offset = dst.mem.disp
            src_reg = insn.reg_name(src.reg).lower()
            field_type, is_sensitive = self._classify_field(offset)

            return FieldAccess(
                addr=insn.address,
                access_type=AccessType.WRITE,
                base_reg=base_reg,
                offset=offset,
                size=src.size,
                value_reg=src_reg,
                instruction=f"{insn.mnemonic} {insn.op_str}",
                is_base_tainted=base_reg in tainted_regs,
                is_value_tainted=src_reg in tainted_regs,
                field_type=field_type,
                is_sensitive=is_sensitive
            )

        return None

    def _classify_field(self, offset: int) -> Tuple[FieldType, bool]:
        """Classify field based on offset"""
        # Check known sensitive offsets
        if offset in self.SENSITIVE_OFFSETS:
            return self.SENSITIVE_OFFSETS[offset], True

        # VTable pointer is usually at offset 0
        if offset == 0:
            return FieldType.VTABLE_PTR, True

        # Small offsets may be function pointers
        if 0 < offset < 0x100 and offset % self.ptr_size == 0:
            # Possible method pointer
            return FieldType.FUNC_PTR, True

        return FieldType.UNKNOWN, False

    def _check_field_vulnerability(self, access: FieldAccess) -> Optional[FieldVulnerability]:
        """Detect field-related vulnerabilities"""
        # Writing to VTable pointer
        if access.access_type == AccessType.WRITE and access.field_type == FieldType.VTABLE_PTR:
            if access.is_value_tainted:
                return FieldVulnerability(
                    addr=access.addr,
                    vuln_type="VTABLE_OVERWRITE",
                    field_offset=access.offset,
                    field_type=access.field_type,
                    description="Tainted data written to VTable pointer, possible control flow hijacking",
                    risk_level="Critical",
                    taint_source=access.value_reg
                )

        # Writing to function pointer
        if access.access_type == AccessType.WRITE and access.field_type == FieldType.FUNC_PTR:
            if access.is_value_tainted:
                return FieldVulnerability(
                    addr=access.addr,
                    vuln_type="FUNC_PTR_OVERWRITE",
                    field_offset=access.offset,
                    field_type=access.field_type,
                    description="Tainted data written to function pointer field",
                    risk_level="Critical",
                    taint_source=access.value_reg
                )

        # Writing to size/length field
        if access.access_type == AccessType.WRITE and access.field_type in (FieldType.SIZE_FIELD, FieldType.LENGTH_FIELD):
            if access.is_value_tainted:
                return FieldVulnerability(
                    addr=access.addr,
                    vuln_type="SIZE_FIELD_TAINT",
                    field_offset=access.offset,
                    field_type=access.field_type,
                    description="Tainted data written to size field, possible integer overflow or buffer overflow",
                    risk_level="High",
                    taint_source=access.value_reg
                )

        return None

    def _update_taint_state(self, insn, tainted_regs: Set[str]):
        """Update taint state (simplified)"""
        if insn.mnemonic != 'mov':
            return

        if len(insn.operands) < 2:
            return

        dst = insn.operands[0]
        src = insn.operands[1]

        # mov reg, reg - propagate taint
        if dst.type == self.X86_OP_REG and src.type == self.X86_OP_REG:
            src_reg = insn.reg_name(src.reg).lower()
            dst_reg = insn.reg_name(dst.reg).lower()

            if src_reg in tainted_regs:
                tainted_regs.add(dst_reg)
            elif dst_reg in tainted_regs:
                tainted_regs.discard(dst_reg)

    def get_sensitive_writes(self) -> List[FieldAccess]:
        """Get writes to sensitive fields"""
        return [a for a in self.field_accesses
                if a.access_type == AccessType.WRITE and a.is_sensitive]

    def get_tainted_writes(self) -> List[FieldAccess]:
        """Get writes of tainted data"""
        return [a for a in self.field_accesses
                if a.access_type == AccessType.WRITE and a.is_value_tainted]
