# -*- coding: utf-8 -*-
"""
luodllhack/symbolic/executor.py - 增强的符号执行引擎

提供真正的约束收集与路径分析能力:
- ConstraintCollector: 在符号执行过程中收集路径约束
- EnhancedSymbolicExecutor: 增强的执行器，支持漏洞特定约束
- 智能路径剪枝与优先级排序
"""

from typing import Dict, List, Set, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum, auto
import logging
import time

try:
    import angr
    import claripy
    from angr import BP_AFTER, BP_BEFORE
    from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCStdcall
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False
    angr = None
    claripy = None
    BP_AFTER = BP_BEFORE = None

logger = logging.getLogger(__name__)

# 从统一类型定义导入 VulnType
from luodllhack.core.types import VulnType

# 导入路径剪枝策略
try:
    from .pruning import (
        SmartPathPruner, PruningStrategy,
        VulnGuidedPrioritizer, ConstraintOptimizer
    )
    HAVE_PRUNING = True
except ImportError:
    HAVE_PRUNING = False
    SmartPathPruner = None
    PruningStrategy = None


@dataclass
class CollectedConstraint:
    """收集的约束"""
    address: int                    # 产生约束的地址
    constraint: Any                 # claripy 约束对象
    constraint_str: str             # 约束的字符串表示
    is_branch: bool                 # 是否是分支条件
    branch_taken: bool = True       # 分支是否被采取

    def to_dict(self) -> Dict:
        return {
            'address': f'0x{self.address:x}',
            'constraint': self.constraint_str,
            'is_branch': self.is_branch,
            'branch_taken': self.branch_taken
        }


@dataclass
class SymbolicVariable:
    """符号变量"""
    name: str
    bitvec: Any                     # claripy.BVS
    size_bits: int
    source: str                     # 'arg', 'memory', 'input'
    arg_index: Optional[int] = None
    memory_addr: Optional[int] = None

    @property
    def size_bytes(self) -> int:
        return self.size_bits // 8


@dataclass
class PathState:
    """路径状态"""
    path_id: int
    constraints: List[CollectedConstraint]
    symbolic_vars: Dict[str, SymbolicVariable]
    final_state: Any                # angr state
    reached_target: bool = False
    is_satisfiable: bool = True

    def get_constraint_count(self) -> int:
        return len(self.constraints)


class ConstraintCollector:
    """
    约束收集器

    在符号执行过程中收集所有路径约束，支持:
    - 分支条件收集
    - 内存访问约束
    - API 调用参数约束
    """

    def __init__(self):
        self.constraints: List[CollectedConstraint] = []
        self.branch_history: List[Tuple[int, bool]] = []
        self._state_constraints_map: Dict[int, List[CollectedConstraint]] = {}

    def reset(self):
        """重置收集器"""
        self.constraints.clear()
        self.branch_history.clear()
        self._state_constraints_map.clear()

    def collect_constraint(self, state):
        """
        约束收集回调 (用于 state.inspect breakpoint)
        """
        if not hasattr(state, 'inspect') or state.inspect.added_constraints is None:
            return

        added = state.inspect.added_constraints
        if not added:
            return

        for constraint in added:
            cc = CollectedConstraint(
                address=state.addr,
                constraint=constraint,
                constraint_str=str(constraint),
                is_branch=False
            )
            self.constraints.append(cc)

            # 按状态 ID 分组
            state_id = id(state)
            if state_id not in self._state_constraints_map:
                self._state_constraints_map[state_id] = []
            self._state_constraints_map[state_id].append(cc)

    def collect_branch(self, state):
        """
        分支收集回调
        """
        if not hasattr(state, 'inspect'):
            return

        guard = state.inspect.exit_guard
        target = state.inspect.exit_target

        if guard is not None and not guard.is_true() and not guard.is_false():
            cc = CollectedConstraint(
                address=state.addr,
                constraint=guard,
                constraint_str=str(guard),
                is_branch=True,
                branch_taken=True  # 将在后续更新
            )
            self.constraints.append(cc)
            self.branch_history.append((state.addr, True))

    def get_constraints_for_state(self, state) -> List[CollectedConstraint]:
        """获取特定状态的约束"""
        state_id = id(state)
        return self._state_constraints_map.get(state_id, [])

    def get_path_constraints(self) -> List[Any]:
        """获取所有路径约束 (claripy 对象)"""
        return [c.constraint for c in self.constraints if c.constraint is not None]

    def get_branch_constraints(self) -> List[CollectedConstraint]:
        """获取所有分支约束"""
        return [c for c in self.constraints if c.is_branch]


class EnhancedSymbolicExecutor:
    """
    增强的符号执行引擎

    特点:
    1. 真正的约束收集 (不仅仅是探索)
    2. 漏洞特定的约束生成
    3. 支持从污点分析 sink 出发的反向分析

    用法:
        executor = EnhancedSymbolicExecutor("target.dll")

        # 探索并收集约束
        path_states = executor.explore_with_constraints(func_addr, target_addr)

        # 为特定漏洞类型添加约束
        executor.add_vuln_constraints(VulnType.BUFFER_OVERFLOW, buffer_size=64)

        # 求解
        result = executor.solve_for_input()
    """

    # Windows x64 参数寄存器
    X64_ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
    # Windows x86 栈参数偏移 (stdcall)
    X86_ARG_OFFSETS = [0x4, 0x8, 0xC, 0x10]

    def __init__(self, binary_path: str, auto_load_libs: bool = False,
                 enable_pruning: bool = True):
        if not HAVE_ANGR:
            raise ImportError("angr is required: pip install angr")

        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # 加载项目
        self.project = angr.Project(
            str(self.binary_path),
            auto_load_libs=auto_load_libs,
            use_sim_procedures=True
        )

        self.arch = self.project.arch
        self.is_64bit = self.arch.bits == 64

        # 约束收集器
        self.collector = ConstraintCollector()

        # 符号变量
        self.symbolic_vars: Dict[str, SymbolicVariable] = {}

        # 路径状态
        self.path_states: List[PathState] = []

        # 漏洞特定约束
        self.vuln_constraints: List[Any] = []

        # 当前分析的函数信息
        self.current_func_addr: int = 0
        self.current_func_name: str = ""

        # 路径剪枝器 (增强功能)
        self.enable_pruning = enable_pruning and HAVE_PRUNING
        self.pruner: Optional['SmartPathPruner'] = None
        if self.enable_pruning:
            self.pruner = SmartPathPruner(
                strategies=[
                    PruningStrategy.LOOP_BOUND,
                    PruningStrategy.VULN_GUIDED,
                    PruningStrategy.DEPTH_LIMITED,
                    PruningStrategy.SIMILARITY_MERGE
                ],
                max_loop_iterations=3,
                max_path_depth=500,
                max_active_states=50
            )

    def create_symbolic_args(self, num_args: int = 4,
                             arg_sizes: List[int] = None) -> List[Any]:
        """
        创建符号化的函数参数

        Args:
            num_args: 参数数量
            arg_sizes: 各参数的字节大小

        Returns:
            符号参数列表
        """
        if arg_sizes is None:
            ptr_size = 8 if self.is_64bit else 4
            arg_sizes = [ptr_size] * num_args

        symbolic_args = []
        for i, size in enumerate(arg_sizes[:num_args]):
            name = f"arg{i}"
            bvs = claripy.BVS(name, size * 8)

            self.symbolic_vars[name] = SymbolicVariable(
                name=name,
                bitvec=bvs,
                size_bits=size * 8,
                source='arg',
                arg_index=i
            )
            symbolic_args.append(bvs)

        return symbolic_args

    def create_symbolic_buffer(self, name: str, size: int) -> Any:
        """
        创建符号化的缓冲区

        Args:
            name: 缓冲区名称
            size: 字节大小

        Returns:
            符号缓冲区
        """
        bvs = claripy.BVS(name, size * 8)

        self.symbolic_vars[name] = SymbolicVariable(
            name=name,
            bitvec=bvs,
            size_bits=size * 8,
            source='input'
        )

        return bvs

    def _setup_constraint_collection(self, state):
        """设置约束收集断点"""
        # 收集所有添加的约束
        state.inspect.b('constraints', when=BP_AFTER,
                        action=self.collector.collect_constraint)

        # 收集分支条件
        state.inspect.b('exit', when=BP_BEFORE,
                        action=self.collector.collect_branch)

    def explore_with_constraints(self, func_addr: int,
                                  target_addr: int = 0,
                                  max_steps: int = 2000,
                                  timeout: int = 120) -> List[PathState]:
        """
        探索函数并收集路径约束 (增强版 - 支持路径剪枝)

        Args:
            func_addr: 函数起始地址
            target_addr: 目标地址 (0 表示探索所有路径)
            max_steps: 最大步数
            timeout: 超时秒数

        Returns:
            探索到的路径状态列表
        """
        self.collector.reset()
        self.symbolic_vars.clear()
        self.path_states.clear()
        self.current_func_addr = func_addr

        # 重置剪枝器
        if self.pruner:
            self.pruner.reset()
            if target_addr:
                self.pruner.set_targets({target_addr})

        # 创建符号参数
        symbolic_args = self.create_symbolic_args()

        # 设置调用约定
        if self.is_64bit:
            cc = SimCCMicrosoftAMD64(self.project.arch)
        else:
            cc = SimCCStdcall(self.project.arch)

        # 创建初始状态
        state = self.project.factory.call_state(
            func_addr,
            *symbolic_args,
            cc=cc
        )

        # 设置约束收集
        self._setup_constraint_collection(state)

        # 创建模拟管理器
        simgr = self.project.factory.simulation_manager(state)

        # 探索 (使用增强的剪枝策略)
        start_time = time.time()
        step_count = 0

        try:
            while step_count < max_steps:
                # 检查超时
                if time.time() - start_time > timeout:
                    logger.info(f"Exploration timeout after {step_count} steps")
                    break

                # 检查是否还有活跃状态
                if not simgr.active:
                    break

                # 应用路径剪枝
                if self.pruner and len(simgr.active) > 1:
                    simgr.active = self.pruner.prune_and_prioritize(simgr.active)

                # 检查是否已找到目标
                if target_addr and hasattr(simgr, 'found') and simgr.found:
                    if len(simgr.found) >= 10:
                        logger.info(f"Found {len(simgr.found)} paths to target")
                        break

                # 执行一步
                try:
                    simgr.step()
                    step_count += 1
                except Exception as e:
                    logger.debug(f"Step error: {e}")
                    break

                # 移动到达目标的状态
                if target_addr:
                    for s in list(simgr.active):
                        if s.addr == target_addr:
                            simgr.active.remove(s)
                            if not hasattr(simgr, 'found'):
                                simgr.stashes['found'] = []
                            simgr.found.append(s)

        except Exception as e:
            logger.warning(f"Exploration error: {e}")

        # 记录剪枝统计
        if self.pruner:
            stats = self.pruner.get_stats()
            logger.info(f"Pruning stats: {stats}")

        # 收集路径状态
        path_id = 0

        # 处理到达目标的状态
        for s in simgr.found if hasattr(simgr, 'found') else []:
            ps = PathState(
                path_id=path_id,
                constraints=self.collector.get_constraints_for_state(s),
                symbolic_vars=self.symbolic_vars.copy(),
                final_state=s,
                reached_target=True,
                is_satisfiable=s.solver.satisfiable()
            )
            self.path_states.append(ps)
            path_id += 1

        # 处理终止状态
        for s in simgr.deadended:
            ps = PathState(
                path_id=path_id,
                constraints=self.collector.get_constraints_for_state(s),
                symbolic_vars=self.symbolic_vars.copy(),
                final_state=s,
                reached_target=False,
                is_satisfiable=s.solver.satisfiable()
            )
            self.path_states.append(ps)
            path_id += 1

        return self.path_states

    def add_vuln_constraints(self, vuln_type: VulnType,
                              state: Any = None,
                              **kwargs) -> List[Any]:
        """
        添加漏洞特定的约束

        Args:
            vuln_type: 漏洞类型
            state: angr 状态 (可选)
            **kwargs: 漏洞特定参数

        Returns:
            添加的约束列表
        """
        constraints = []

        if vuln_type == VulnType.BUFFER_OVERFLOW:
            # 缓冲区溢出: input_len > buffer_size
            buffer_size = kwargs.get('buffer_size', 64)
            input_var = kwargs.get('input_var')

            if input_var and input_var in self.symbolic_vars:
                sym_var = self.symbolic_vars[input_var]
                # 约束: 输入长度大于缓冲区
                # 这里简化为要求输入至少有 buffer_size + 1 个非零字节
                # 实际实现需要更复杂的字符串长度建模

        elif vuln_type == VulnType.FORMAT_STRING:
            # 格式化字符串: 输入包含 %n, %s 等
            input_var = kwargs.get('input_var')

            if input_var and input_var in self.symbolic_vars:
                sym_var = self.symbolic_vars[input_var]
                bvs = sym_var.bitvec

                # 约束: 包含 '%' (0x25) 和 'n' (0x6e) 或 's' (0x73)
                if sym_var.size_bits >= 16:
                    # 前两个字节是 "%n" 或 "%s"
                    byte0 = bvs[sym_var.size_bits-1:sym_var.size_bits-8]
                    byte1 = bvs[sym_var.size_bits-9:sym_var.size_bits-16]

                    fmt_n = claripy.And(byte0 == 0x25, byte1 == 0x6e)
                    fmt_s = claripy.And(byte0 == 0x25, byte1 == 0x73)

                    constraint = claripy.Or(fmt_n, fmt_s)
                    constraints.append(constraint)

        elif vuln_type == VulnType.INTEGER_OVERFLOW:
            # 整数溢出: 两个值相加/相乘导致溢出
            var1 = kwargs.get('var1')
            var2 = kwargs.get('var2')

            if var1 in self.symbolic_vars and var2 in self.symbolic_vars:
                bvs1 = self.symbolic_vars[var1].bitvec
                bvs2 = self.symbolic_vars[var2].bitvec

                # 约束: a + b 溢出 (结果小于任一操作数)
                sum_val = bvs1 + bvs2
                overflow_constraint = claripy.Or(
                    claripy.ULT(sum_val, bvs1),
                    claripy.ULT(sum_val, bvs2)
                )
                constraints.append(overflow_constraint)

        elif vuln_type == VulnType.COMMAND_INJECTION:
            # 命令注入: 输入包含 shell 元字符
            input_var = kwargs.get('input_var')

            if input_var and input_var in self.symbolic_vars:
                sym_var = self.symbolic_vars[input_var]
                bvs = sym_var.bitvec

                # 约束: 包含 ';', '|', '&' 等
                if sym_var.size_bits >= 8:
                    for offset in range(0, min(sym_var.size_bits, 64), 8):
                        byte_val = bvs[sym_var.size_bits-1-offset:sym_var.size_bits-8-offset]

                        shell_chars = claripy.Or(
                            byte_val == ord(';'),
                            byte_val == ord('|'),
                            byte_val == ord('&'),
                            byte_val == ord('`')
                        )
                        constraints.append(shell_chars)
                        break  # 只需要一个位置包含即可

        self.vuln_constraints.extend(constraints)

        # 如果提供了状态，直接添加约束
        if state is not None:
            for c in constraints:
                state.solver.add(c)

        return constraints

    def solve_for_input(self, path_state: PathState = None,
                        additional_constraints: List[Any] = None) -> Optional[Dict[str, bytes]]:
        """
        求解具体输入值

        Args:
            path_state: 要求解的路径状态
            additional_constraints: 额外约束

        Returns:
            符号变量到具体值的映射，或 None
        """
        if path_state is None:
            # 使用第一个可满足的路径
            for ps in self.path_states:
                if ps.is_satisfiable:
                    path_state = ps
                    break

        if path_state is None or path_state.final_state is None:
            return None

        state = path_state.final_state
        solver = state.solver

        # 添加额外约束
        if additional_constraints:
            for c in additional_constraints:
                solver.add(c)

        # 添加漏洞约束
        for c in self.vuln_constraints:
            solver.add(c)

        # 检查可满足性
        if not solver.satisfiable():
            return None

        # 求解各符号变量
        result = {}
        for name, sym_var in path_state.symbolic_vars.items():
            try:
                concrete = solver.eval(sym_var.bitvec, cast_to=bytes)
                result[name] = concrete
            except Exception as e:
                logger.warning(f"Failed to solve {name}: {e}")
                result[name] = None

        return result

    def get_path_to_target(self, target_addr: int) -> Optional[PathState]:
        """
        获取到达目标地址的路径

        Args:
            target_addr: 目标地址

        Returns:
            到达目标的路径状态，或 None
        """
        for ps in self.path_states:
            if ps.reached_target:
                return ps
        return None

    def get_satisfiable_paths(self) -> List[PathState]:
        """获取所有可满足的路径"""
        return [ps for ps in self.path_states if ps.is_satisfiable]

    def get_constraint_summary(self) -> Dict:
        """获取约束摘要"""
        summary = {
            'total_constraints': len(self.collector.constraints),
            'branch_constraints': len(self.collector.get_branch_constraints()),
            'paths_explored': len(self.path_states),
            'satisfiable_paths': len(self.get_satisfiable_paths()),
            'symbolic_vars': list(self.symbolic_vars.keys()),
            'vuln_constraints': len(self.vuln_constraints)
        }

        # 添加剪枝统计
        if self.pruner:
            summary['pruning_stats'] = self.pruner.get_stats()

        return summary

    def configure_pruner(self,
                         max_loop_iterations: int = None,
                         max_path_depth: int = None,
                         max_active_states: int = None,
                         similarity_threshold: float = None):
        """
        配置路径剪枝器参数

        Args:
            max_loop_iterations: 最大循环迭代次数
            max_path_depth: 最大路径深度
            max_active_states: 最大活跃状态数
            similarity_threshold: 路径相似度阈值
        """
        if not self.pruner:
            return

        if max_loop_iterations is not None:
            self.pruner.max_loop_iterations = max_loop_iterations
        if max_path_depth is not None:
            self.pruner.max_path_depth = max_path_depth
        if max_active_states is not None:
            self.pruner.max_active_states = max_active_states
        if similarity_threshold is not None:
            self.pruner.merger.similarity_threshold = similarity_threshold

    def set_vuln_targets(self, target_addrs: Set[int],
                         call_graph: Dict[int, Set[int]] = None):
        """
        设置漏洞目标地址 (用于漏洞导向剪枝)

        Args:
            target_addrs: 目标地址集合 (危险 API 调用点)
            call_graph: 调用图 {caller_addr: {callee_addrs}}
        """
        if not self.pruner:
            return

        self.pruner.set_targets(target_addrs)
        if call_graph:
            self.pruner.set_call_graph(call_graph)

    def get_pruning_stats(self) -> Dict:
        """获取剪枝统计信息"""
        if not self.pruner:
            return {'enabled': False}

        return {
            'enabled': True,
            **self.pruner.get_stats()
        }
