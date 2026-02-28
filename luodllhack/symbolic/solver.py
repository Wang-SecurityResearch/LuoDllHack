# -*- coding: utf-8 -*-
"""
luodllhack/symbolic/solver.py - 漏洞利用约束求解器

专门用于求解触发漏洞的具体输入:
- 缓冲区溢出: 求解所需的最小输入长度
- 格式化字符串: 求解控制特定内存的格式串
- 整数溢出: 求解导致溢出的操作数
"""

from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import struct
import logging

try:
    import claripy
    HAVE_CLARIPY = True
except ImportError:
    HAVE_CLARIPY = False
    claripy = None

from .executor import VulnType, PathState, SymbolicVariable, CollectedConstraint

# 导入配置
try:
    from luodllhack.core.config import default_config, LuoDllHackConfig
    HAVE_CONFIG = True
except ImportError:
    HAVE_CONFIG = False
    default_config = None
    LuoDllHackConfig = None

logger = logging.getLogger(__name__)


class SolveStatus(Enum):
    """求解状态"""
    SUCCESS = auto()        # 成功求解
    UNSAT = auto()          # 不可满足
    TIMEOUT = auto()        # 超时
    ERROR = auto()          # 错误
    PARTIAL = auto()        # 部分求解


@dataclass
class SolverResult:
    """求解结果"""
    status: SolveStatus
    inputs: Dict[str, bytes]        # 符号变量 -> 具体值
    vuln_type: VulnType
    target_address: int
    constraints_used: int
    solve_time_ms: float = 0.0
    description: str = ""
    payload_hint: Optional[bytes] = None  # 建议的 payload

    def to_dict(self) -> Dict:
        return {
            'status': self.status.name,
            'inputs': {k: v.hex() if v else None for k, v in self.inputs.items()},
            'vuln_type': self.vuln_type.name,
            'target': f'0x{self.target_address:x}',
            'constraints_used': self.constraints_used,
            'solve_time_ms': self.solve_time_ms,
            'description': self.description,
            'payload_hint': self.payload_hint.hex() if self.payload_hint else None
        }


@dataclass
class BufferOverflowParams:
    """缓冲区溢出参数"""
    buffer_size: int
    target_offset: Optional[int] = None     # 目标偏移 (如返回地址)
    target_value: Optional[int] = None      # 目标值
    padding_byte: int = 0x41                # 填充字节 ('A')
    null_terminate: bool = True             # 是否需要空终止


@dataclass
class FormatStringParams:
    """格式化字符串参数"""
    target_addr: int                        # 要写入的地址
    target_value: int                       # 要写入的值
    stack_offset: int = 6                   # 栈偏移
    is_64bit: bool = True


@dataclass
class IntegerOverflowParams:
    """整数溢出参数"""
    bit_width: int = 32                     # 位宽
    operation: str = 'add'                  # 操作: add, mul, sub
    target_result: Optional[int] = None     # 期望的溢出后结果


class ExploitSolver:
    """
    漏洞利用求解器

    专门处理各类漏洞的约束求解:
    1. 收集路径约束
    2. 添加漏洞特定约束
    3. 求解具体输入
    4. 生成 payload 建议

    用法:
        solver = ExploitSolver()

        # 从 PathState 求解缓冲区溢出
        params = BufferOverflowParams(buffer_size=64, target_offset=72)
        result = solver.solve_buffer_overflow(path_state, params)

        if result.status == SolveStatus.SUCCESS:
            print(f"Payload: {result.payload_hint.hex()}")
    """

    def __init__(self, timeout_ms: int = None, config: 'LuoDllHackConfig' = None):
        if not HAVE_CLARIPY:
            raise ImportError("claripy is required: pip install claripy")

        # 使用配置
        self.config = config or (default_config if HAVE_CONFIG else None)

        # 从配置获取超时 (秒 -> 毫秒)
        if timeout_ms is not None:
            self.timeout_ms = timeout_ms
        elif self.config:
            self.timeout_ms = self.config.symbolic_timeout * 1000
        else:
            self.timeout_ms = 30000

        # 从配置获取是否启用约束求解
        if self.config:
            self.solve_enabled = self.config.symbolic_solve_constraints
            self.max_states = self.config.symbolic_max_states
        else:
            self.solve_enabled = True
            self.max_states = 100

        self._solver = claripy.Solver()

    def solve_buffer_overflow(self, path_state: PathState,
                               params: BufferOverflowParams) -> SolverResult:
        """
        求解缓冲区溢出漏洞

        Args:
            path_state: 路径状态
            params: 溢出参数

        Returns:
            求解结果
        """
        import time
        start_time = time.time()

        # 检查是否启用约束求解
        if not self.solve_enabled:
            return SolverResult(
                status=SolveStatus.ERROR,
                inputs={},
                vuln_type=VulnType.BUFFER_OVERFLOW,
                target_address=0,
                constraints_used=0,
                description="Constraint solving is disabled (symbolic_solve_constraints=false)"
            )

        if not path_state.is_satisfiable or path_state.final_state is None:
            return SolverResult(
                status=SolveStatus.UNSAT,
                inputs={},
                vuln_type=VulnType.BUFFER_OVERFLOW,
                target_address=0,
                constraints_used=0,
                description="Path is not satisfiable"
            )

        state = path_state.final_state
        solver = state.solver

        # 找到输入相关的符号变量
        input_vars = {n: v for n, v in path_state.symbolic_vars.items()
                      if v.source in ('arg', 'input')}

        if not input_vars:
            return SolverResult(
                status=SolveStatus.ERROR,
                inputs={},
                vuln_type=VulnType.BUFFER_OVERFLOW,
                target_address=0,
                constraints_used=0,
                description="No input variables found"
            )

        # 构造溢出 payload
        payload_size = params.buffer_size + 8  # 至少溢出 8 字节

        if params.target_offset:
            payload_size = max(payload_size, params.target_offset + 8)

        # 尝试求解
        inputs = {}
        for name, sym_var in input_vars.items():
            try:
                # 如果符号变量足够大，添加约束
                if sym_var.size_bytes >= payload_size:
                    # 约束前 N 字节为填充
                    bvs = sym_var.bitvec
                    for i in range(min(params.buffer_size, sym_var.size_bytes)):
                        byte_offset = sym_var.size_bits - 8 - (i * 8)
                        if byte_offset >= 0:
                            byte_val = bvs[byte_offset + 7:byte_offset]
                            solver.add(byte_val == params.padding_byte)

                # 求解
                concrete = solver.eval(sym_var.bitvec, cast_to=bytes)
                inputs[name] = concrete

            except Exception as e:
                logger.warning(f"Failed to solve {name}: {e}")
                inputs[name] = None

        # 生成 payload 建议
        payload = self._generate_overflow_payload(params)

        elapsed_ms = (time.time() - start_time) * 1000

        return SolverResult(
            status=SolveStatus.SUCCESS if any(inputs.values()) else SolveStatus.PARTIAL,
            inputs=inputs,
            vuln_type=VulnType.BUFFER_OVERFLOW,
            target_address=path_state.final_state.addr if path_state.final_state else 0,
            constraints_used=path_state.get_constraint_count(),
            solve_time_ms=elapsed_ms,
            description=f"Buffer overflow with {params.buffer_size} byte buffer",
            payload_hint=payload
        )

    def _generate_overflow_payload(self, params: BufferOverflowParams) -> bytes:
        """生成溢出 payload"""
        payload = bytes([params.padding_byte]) * params.buffer_size

        if params.target_offset and params.target_value:
            # 填充到目标偏移
            padding_needed = params.target_offset - params.buffer_size
            if padding_needed > 0:
                payload += bytes([params.padding_byte]) * padding_needed

            # 添加目标值 (小端序)
            payload += struct.pack('<Q', params.target_value)

        if params.null_terminate:
            payload += b'\x00'

        return payload

    def solve_format_string(self, path_state: PathState,
                             params: FormatStringParams) -> SolverResult:
        """
        求解格式化字符串漏洞

        Args:
            path_state: 路径状态
            params: 格式串参数

        Returns:
            求解结果
        """
        import time
        start_time = time.time()

        # 检查是否启用约束求解
        if not self.solve_enabled:
            return SolverResult(
                status=SolveStatus.ERROR,
                inputs={},
                vuln_type=VulnType.FORMAT_STRING,
                target_address=params.target_addr,
                constraints_used=0,
                description="Constraint solving is disabled (symbolic_solve_constraints=false)"
            )

        if not path_state.is_satisfiable or path_state.final_state is None:
            return SolverResult(
                status=SolveStatus.UNSAT,
                inputs={},
                vuln_type=VulnType.FORMAT_STRING,
                target_address=params.target_addr,
                constraints_used=0,
                description="Path is not satisfiable"
            )

        state = path_state.final_state
        solver = state.solver

        # 找到格式串参数
        input_vars = {n: v for n, v in path_state.symbolic_vars.items()
                      if v.source in ('arg', 'input')}

        inputs = {}
        for name, sym_var in input_vars.items():
            try:
                # 添加格式串约束
                bvs = sym_var.bitvec
                size = sym_var.size_bits

                # 约束前两字节为 '%' 和有效的格式说明符
                if size >= 16:
                    byte0 = bvs[size-1:size-8]
                    byte1 = bvs[size-9:size-16]

                    # '%n' 或 '%s' 或 '%x'
                    solver.add(byte0 == ord('%'))
                    # 让求解器选择具体的格式字符

                concrete = solver.eval(sym_var.bitvec, cast_to=bytes)
                inputs[name] = concrete

            except Exception as e:
                logger.warning(f"Failed to solve {name}: {e}")
                inputs[name] = None

        # 生成格式串 payload
        payload = self._generate_format_string_payload(params)

        elapsed_ms = (time.time() - start_time) * 1000

        return SolverResult(
            status=SolveStatus.SUCCESS if any(inputs.values()) else SolveStatus.PARTIAL,
            inputs=inputs,
            vuln_type=VulnType.FORMAT_STRING,
            target_address=params.target_addr,
            constraints_used=path_state.get_constraint_count(),
            solve_time_ms=elapsed_ms,
            description=f"Format string to write at 0x{params.target_addr:x}",
            payload_hint=payload
        )

    def _generate_format_string_payload(self, params: FormatStringParams) -> bytes:
        """生成格式化字符串 payload"""
        # 基本的 %n 写入 payload
        # 这是一个简化版本，实际利用需要更复杂的计算

        if params.is_64bit:
            addr_fmt = struct.pack('<Q', params.target_addr)
        else:
            addr_fmt = struct.pack('<I', params.target_addr)

        # 构造格式串
        # %[offset]$n 直接写入
        fmt_str = f"%{params.stack_offset}$n".encode()

        # 实际的 payload 需要：
        # 1. 计算要写入的值需要多少字符
        # 2. 使用 %c 或 %x 来控制输出长度
        # 3. 可能需要分多次写入 (每次写一个字节)

        payload = addr_fmt + fmt_str

        return payload

    def solve_integer_overflow(self, path_state: PathState,
                                params: IntegerOverflowParams) -> SolverResult:
        """
        求解整数溢出漏洞

        Args:
            path_state: 路径状态
            params: 溢出参数

        Returns:
            求解结果
        """
        import time
        start_time = time.time()

        # 检查是否启用约束求解
        if not self.solve_enabled:
            return SolverResult(
                status=SolveStatus.ERROR,
                inputs={},
                vuln_type=VulnType.INTEGER_OVERFLOW,
                target_address=0,
                constraints_used=0,
                description="Constraint solving is disabled (symbolic_solve_constraints=false)"
            )

        if not path_state.is_satisfiable or path_state.final_state is None:
            return SolverResult(
                status=SolveStatus.UNSAT,
                inputs={},
                vuln_type=VulnType.INTEGER_OVERFLOW,
                target_address=0,
                constraints_used=0,
                description="Path is not satisfiable"
            )

        state = path_state.final_state
        solver = state.solver

        # 找到数值参数
        input_vars = {n: v for n, v in path_state.symbolic_vars.items()
                      if v.source in ('arg', 'input')}

        # 获取前两个参数作为操作数
        var_names = list(input_vars.keys())[:2]
        if len(var_names) < 2:
            return SolverResult(
                status=SolveStatus.ERROR,
                inputs={},
                vuln_type=VulnType.INTEGER_OVERFLOW,
                target_address=0,
                constraints_used=0,
                description="Need at least 2 input variables for integer overflow"
            )

        var1 = input_vars[var_names[0]]
        var2 = input_vars[var_names[1]]

        # 添加溢出约束
        bvs1 = var1.bitvec
        bvs2 = var2.bitvec

        if params.operation == 'add':
            # a + b 溢出: (a + b) < a 或 (a + b) < b
            result = bvs1 + bvs2
            overflow = claripy.Or(
                claripy.ULT(result, bvs1),
                claripy.ULT(result, bvs2)
            )
            solver.add(overflow)

        elif params.operation == 'mul':
            # a * b 溢出: (a * b) / a != b (当 a != 0)
            result = bvs1 * bvs2
            # 简化: 要求结果小于某个操作数 (当另一个 > 1)
            solver.add(claripy.UGT(bvs1, 1))
            solver.add(claripy.UGT(bvs2, 1))
            solver.add(claripy.ULT(result, bvs1))

        elif params.operation == 'sub':
            # a - b 下溢: b > a 导致结果变成很大的正数
            solver.add(claripy.UGT(bvs2, bvs1))

        # 求解
        inputs = {}
        try:
            for name, sym_var in input_vars.items():
                concrete = solver.eval(sym_var.bitvec, cast_to=bytes)
                inputs[name] = concrete
        except Exception as e:
            logger.warning(f"Failed to solve: {e}")

        elapsed_ms = (time.time() - start_time) * 1000

        return SolverResult(
            status=SolveStatus.SUCCESS if any(inputs.values()) else SolveStatus.UNSAT,
            inputs=inputs,
            vuln_type=VulnType.INTEGER_OVERFLOW,
            target_address=path_state.final_state.addr if path_state.final_state else 0,
            constraints_used=path_state.get_constraint_count(),
            solve_time_ms=elapsed_ms,
            description=f"Integer overflow via {params.operation} operation"
        )

    def solve_from_constraints(self, constraints: List[Any],
                                symbolic_vars: Dict[str, SymbolicVariable],
                                vuln_type: VulnType = VulnType.BUFFER_OVERFLOW) -> SolverResult:
        """
        直接从约束列表求解

        Args:
            constraints: claripy 约束列表
            symbolic_vars: 符号变量字典
            vuln_type: 漏洞类型

        Returns:
            求解结果
        """
        import time
        start_time = time.time()

        # 检查是否启用约束求解
        if not self.solve_enabled:
            return SolverResult(
                status=SolveStatus.ERROR,
                inputs={},
                vuln_type=vuln_type,
                target_address=0,
                constraints_used=0,
                description="Constraint solving is disabled (symbolic_solve_constraints=false)"
            )

        solver = claripy.Solver()

        # 添加所有约束
        for c in constraints:
            solver.add(c)

        if not solver.satisfiable():
            return SolverResult(
                status=SolveStatus.UNSAT,
                inputs={},
                vuln_type=vuln_type,
                target_address=0,
                constraints_used=len(constraints),
                description="Constraints are unsatisfiable"
            )

        # 求解
        inputs = {}
        for name, sym_var in symbolic_vars.items():
            try:
                concrete = solver.eval(sym_var.bitvec, cast_to=bytes)
                inputs[name] = concrete
            except Exception as e:
                logger.warning(f"Failed to solve {name}: {e}")
                inputs[name] = None

        elapsed_ms = (time.time() - start_time) * 1000

        return SolverResult(
            status=SolveStatus.SUCCESS if any(inputs.values()) else SolveStatus.PARTIAL,
            inputs=inputs,
            vuln_type=vuln_type,
            target_address=0,
            constraints_used=len(constraints),
            solve_time_ms=elapsed_ms,
            description="Solved from raw constraints"
        )

    def minimize_input(self, result: SolverResult,
                        target_var: str) -> Optional[bytes]:
        """
        最小化输入 (找到触发漏洞的最小输入)

        Args:
            result: 之前的求解结果
            target_var: 要最小化的变量名

        Returns:
            最小化后的输入值
        """
        if result.status != SolveStatus.SUCCESS:
            return None

        if target_var not in result.inputs:
            return None

        original = result.inputs[target_var]
        if not original:
            return None

        # 简单的最小化: 找到最后一个非零字节
        min_len = len(original)
        for i in range(len(original) - 1, -1, -1):
            if original[i] != 0:
                min_len = i + 1
                break

        return original[:min_len]
