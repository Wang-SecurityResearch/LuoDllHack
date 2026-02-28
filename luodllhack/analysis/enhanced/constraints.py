# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/constraints.py

Constraint Collection and Propagation - Phase 3.1

Core Capabilities:
    1. Collect path constraints (branch conditions)
    2. Track value constraints (bounds checks)
    3. Propagate constraints (cross-instruction/cross-function)
    4. Simplify and solve constraints

Constraint Types:
    - Path Constraint: Conditions that must be met to reach a certain point
    - Value Constraint: Range limits on variable values
    - Relation Constraint: Relationships between variables

Usage:
    - Determine if a vulnerability path is reachable
    - Calculate input constraints
    - Generate precise test cases
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple, Any, Union
from enum import Enum, auto
from abc import ABC, abstractmethod


class ConstraintOp(Enum):
    """Constraint Operator"""
    # Comparison
    EQ = "=="           # Equal
    NE = "!="           # Not equal
    LT = "<"            # Less than
    LE = "<="           # Less than or equal
    GT = ">"            # Greater than
    GE = ">="           # Greater than or equal
    # Logical
    AND = "&&"
    OR = "||"
    NOT = "!"
    # Bitwise
    BAND = "&"          # Bitwise AND
    BOR = "|"           # Bitwise OR
    XOR = "^"
    # Arithmetic
    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"


class ConstraintType(Enum):
    """Constraint Type"""
    PATH = auto()       # Path constraint (branch condition)
    VALUE = auto()      # Value constraint (bounds)
    LENGTH = auto()     # Length constraint
    RELATION = auto()   # Relation constraint


@dataclass
class Constraint:
    """Base Constraint"""
    constraint_type: ConstraintType
    addr: int                       # Address where the constraint originated
    expression: str                 # Constraint expression (human-readable)
    symbolic_expr: Any = None       # Symbolic expression (for solver)
    is_satisfiable: Optional[bool] = None
    # Involved variables
    variables: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            'type': self.constraint_type.name,
            'addr': f'0x{self.addr:x}',
            'expression': self.expression,
            'satisfiable': self.is_satisfiable,
            'variables': list(self.variables)
        }


@dataclass
class PathConstraint(Constraint):
    """Path Constraint"""
    branch_taken: bool = True       # Whether the branch was taken
    is_loop: bool = False           # Whether it is a loop condition

    def __post_init__(self) -> None:
        self.constraint_type = ConstraintType.PATH


@dataclass
class ValueConstraint(Constraint):
    """Value Constraint"""
    variable: str = ""
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    possible_values: Set[int] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.constraint_type = ConstraintType.VALUE


@dataclass
class LengthConstraint(Constraint):
    """Length Constraint"""
    buffer_reg: str = ""
    length_reg: str = ""
    max_length: Optional[int] = None
    checked: bool = False           # Whether a bounds check occurred

    def __post_init__(self) -> None:
        self.constraint_type = ConstraintType.LENGTH


@dataclass
class ConstraintSet:
    """Constraint Set"""
    path_constraints: List[PathConstraint] = field(default_factory=list)
    value_constraints: List[ValueConstraint] = field(default_factory=list)
    length_constraints: List[LengthConstraint] = field(default_factory=list)
    # Aggregated
    all_constraints: List[Constraint] = field(default_factory=list)
    is_satisfiable: Optional[bool] = None

    def add(self, constraint: Constraint) -> None:
        """Add a constraint"""
        self.all_constraints.append(constraint)

        if isinstance(constraint, PathConstraint):
            self.path_constraints.append(constraint)
        elif isinstance(constraint, ValueConstraint):
            self.value_constraints.append(constraint)
        elif isinstance(constraint, LengthConstraint):
            self.length_constraints.append(constraint)

    def to_dict(self) -> dict:
        return {
            'total': len(self.all_constraints),
            'path': len(self.path_constraints),
            'value': len(self.value_constraints),
            'length': len(self.length_constraints),
            'satisfiable': self.is_satisfiable,
            'constraints': [c.to_dict() for c in self.all_constraints]
        }


class ConstraintCollector:
    """
    Constraint Collector

    Usage:
        collector = ConstraintCollector()

        # Collect constraints during analysis
        collector.collect_branch(addr, condition, taken=True)
        collector.collect_bounds_check(addr, reg, max_val)

        # Get constraint set
        constraints = collector.get_constraints()

        # Check satisfiability
        if collector.is_satisfiable():
            print("Path is reachable")
    """

    # Mapping of conditional jumps and conditions
    JUMP_CONDITIONS = {
        # Unsigned comparison
        'ja': (ConstraintOp.GT, False),   # Greater than (unsigned)
        'jae': (ConstraintOp.GE, False),  # Greater than or equal (unsigned)
        'jb': (ConstraintOp.LT, False),   # Less than (unsigned)
        'jbe': (ConstraintOp.LE, False),  # Less than or equal (unsigned)
        # Signed comparison
        'jg': (ConstraintOp.GT, True),    # Greater than (signed)
        'jge': (ConstraintOp.GE, True),   # Greater than or equal (signed)
        'jl': (ConstraintOp.LT, True),    # Less than (signed)
        'jle': (ConstraintOp.LE, True),   # Less than or equal (signed)
        # Equality
        'je': (ConstraintOp.EQ, None),
        'jz': (ConstraintOp.EQ, None),
        'jne': (ConstraintOp.NE, None),
        'jnz': (ConstraintOp.NE, None),
    }

    def __init__(self) -> None:
        """Initialize the constraint collector"""
        self.constraints = ConstraintSet()
        # Current comparison state (to associate cmp with jxx)
        self.last_cmp: Optional[Dict] = None
        # Current value ranges for variables
        self.variable_ranges: Dict[str, Tuple[Optional[int], Optional[int]]] = {}

    def collect_compare(self, addr: int, op1: str, op2: Union[str, int],
                        instruction: str = ""):
        """
        Collect comparison instruction

        Args:
            addr: Instruction address
            op1: Operand 1 (usually a register)
            op2: Operand 2 (register or immediate)
            instruction: Full instruction string
        """
        self.last_cmp = {
            'addr': addr,
            'op1': op1,
            'op2': op2,
            'instruction': instruction
        }

    def collect_branch(self, addr: int, jump_type: str, taken: bool = True) -> None:
        """
        Collect branch constraint

        Args:
            addr: Jump instruction address
            jump_type: Jump type (ja, jb, je, etc.)
            taken: Whether the branch was taken
        """
        if not self.last_cmp:
            return

        if jump_type not in self.JUMP_CONDITIONS:
            return

        op, is_signed = self.JUMP_CONDITIONS[jump_type]
        cmp = self.last_cmp

        # Construct constraint expression
        if taken:
            expr = f"{cmp['op1']} {op.value} {cmp['op2']}"
        else:
            # Negate
            negated_op = self._negate_op(op)
            expr = f"{cmp['op1']} {negated_op.value} {cmp['op2']}"

        constraint = PathConstraint(
            constraint_type=ConstraintType.PATH,
            addr=addr,
            expression=expr,
            branch_taken=taken,
            variables={cmp['op1']} if isinstance(cmp['op1'], str) else set()
        )

        self.constraints.add(constraint)

        # Update variable range
        if isinstance(cmp['op2'], int):
            self._update_variable_range(cmp['op1'], op, cmp['op2'], taken)

    def collect_bounds_check(self, addr: int, reg: str, max_value: int,
                             is_effective: bool = True):
        """
        Collect bounds check constraint

        Args:
            addr: Check address
            reg: Checked register
            max_value: Maximum value
            is_effective: Whether the check is effective
        """
        constraint = LengthConstraint(
            constraint_type=ConstraintType.LENGTH,
            addr=addr,
            expression=f"{reg} <= {max_value}",
            buffer_reg=reg,
            max_length=max_value,
            checked=is_effective,
            variables={reg}
        )

        self.constraints.add(constraint)

        # Update variable range
        if is_effective:
            self._update_variable_range(reg, ConstraintOp.LE, max_value, True)

    def collect_value_constraint(self, addr: int, variable: str,
                                  min_val: int = None, max_val: int = None):
        """
        Collect value constraint

        Args:
            addr: Address where the constraint originated
            variable: Variable name
            min_val: Minimum value
            max_val: Maximum value
        """
        parts = []
        if min_val is not None:
            parts.append(f"{variable} >= {min_val}")
        if max_val is not None:
            parts.append(f"{variable} <= {max_val}")

        expr = " && ".join(parts) if parts else f"{variable}"

        constraint = ValueConstraint(
            constraint_type=ConstraintType.VALUE,
            addr=addr,
            expression=expr,
            variable=variable,
            min_value=min_val,
            max_value=max_val,
            variables={variable}
        )

        self.constraints.add(constraint)

    def _negate_op(self, op: ConstraintOp) -> ConstraintOp:
        """Negate an operator"""
        negations = {
            ConstraintOp.EQ: ConstraintOp.NE,
            ConstraintOp.NE: ConstraintOp.EQ,
            ConstraintOp.LT: ConstraintOp.GE,
            ConstraintOp.LE: ConstraintOp.GT,
            ConstraintOp.GT: ConstraintOp.LE,
            ConstraintOp.GE: ConstraintOp.LT,
        }
        return negations.get(op, op)

    def _update_variable_range(self, var: str, op: ConstraintOp,
                                value: int, taken: bool):
        """Update variable range"""
        current = self.variable_ranges.get(var, (None, None))
        min_val, max_val = current

        if taken:
            if op == ConstraintOp.LT:
                max_val = min(max_val, value - 1) if max_val else value - 1
            elif op == ConstraintOp.LE:
                max_val = min(max_val, value) if max_val else value
            elif op == ConstraintOp.GT:
                min_val = max(min_val, value + 1) if min_val else value + 1
            elif op == ConstraintOp.GE:
                min_val = max(min_val, value) if min_val else value
            elif op == ConstraintOp.EQ:
                min_val = max_val = value

        self.variable_ranges[var] = (min_val, max_val)

    def get_constraints(self) -> ConstraintSet:
        """Get all constraints"""
        return self.constraints

    def get_variable_range(self, var: str) -> Tuple[Optional[int], Optional[int]]:
        """Get variable range"""
        return self.variable_ranges.get(var, (None, None))

    def is_satisfiable(self) -> bool:
        """
        Check if constraints are satisfiable

        Simplified version: only checks for range contradictions
        Full version should use an SMT solver like Z3
        """
        for var, (min_val, max_val) in self.variable_ranges.items():
            if min_val is not None and max_val is not None:
                if min_val > max_val:
                    self.constraints.is_satisfiable = False
                    return False

        self.constraints.is_satisfiable = True
        return True

    def generate_test_values(self) -> Dict[str, int]:
        """
        Generate test values satisfying constraints

        Returns:
            variable -> test_value mapping
        """
        values = {}

        for var, (min_val, max_val) in self.variable_ranges.items():
            if min_val is not None and max_val is not None:
                # Use midpoint
                values[var] = (min_val + max_val) // 2
            elif min_val is not None:
                values[var] = min_val
            elif max_val is not None:
                values[var] = max_val
            else:
                values[var] = 0x41414141  # Default test value

        return values

    def clear(self) -> None:
        """Clear constraints"""
        self.constraints = ConstraintSet()
        self.last_cmp = None
        self.variable_ranges.clear()

    def to_smt2(self) -> str:
        """
        Export to SMT-LIB2 format

        Can be solved using Z3
        """
        lines = ["; Auto-generated by LuoDllHack Constraint Collector"]
        lines.append("(set-logic QF_BV)")

        # Declare variables
        declared = set()
        for c in self.constraints.all_constraints:
            for var in c.variables:
                if var not in declared:
                    lines.append(f"(declare-const {var} (_ BitVec 64))")
                    declared.add(var)

        # Add constraints
        for i, c in enumerate(self.constraints.all_constraints):
            lines.append(f"; Constraint {i} @ {c.addr:#x}")
            # Simplified conversion (actual implementation requires more complex logic)
            lines.append(f"; {c.expression}")

        lines.append("(check-sat)")
        lines.append("(get-model)")

        return "\n".join(lines)
