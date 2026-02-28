# -*- coding: utf-8 -*-
"""
luodllhack/symbolic/bridge.py - 污点分析到符号执行的桥接

将污点分析的结果转换为符号执行的输入:
- TaintPath → SymbolicConstraints
- TaintSink → ExploitTarget
- 验证污点路径的可达性
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
import logging

try:
    import claripy
    HAVE_CLARIPY = True
except ImportError:
    HAVE_CLARIPY = False
    claripy = None

from .executor import (
    EnhancedSymbolicExecutor, VulnType, PathState,
    SymbolicVariable, CollectedConstraint
)
from .solver import ExploitSolver, SolverResult, SolveStatus, BufferOverflowParams

logger = logging.getLogger(__name__)


@dataclass
class TaintPathInfo:
    """污点路径信息 (从 disasm.dataflow 导入)"""
    source_addr: int
    sink_addr: int
    path: List[int]
    tainted_regs: Set[str]
    vuln_type: str
    api_name: str
    tainted_args: List[int]
    func_name: str = ""
    confidence: float = 0.0


@dataclass
class BridgeResult:
    """桥接结果"""
    taint_path: TaintPathInfo
    is_reachable: bool
    path_state: Optional[PathState]
    solver_result: Optional[SolverResult]
    verification_status: str
    details: str = ""

    def to_dict(self) -> Dict:
        return {
            'source': f'0x{self.taint_path.source_addr:x}',
            'sink': f'0x{self.taint_path.sink_addr:x}',
            'is_reachable': self.is_reachable,
            'verification': self.verification_status,
            'solver_result': self.solver_result.to_dict() if self.solver_result else None,
            'details': self.details
        }


class TaintSymbolicBridge:
    """
    污点分析到符号执行的桥接器

    功能:
    1. 将 TaintSink/TaintPath 转换为符号执行目标
    2. 使用符号执行验证污点路径可达性
    3. 求解触发漏洞的具体输入

    用法:
        bridge = TaintSymbolicBridge("target.dll")

        # 从污点分析结果创建桥接
        for sink in taint_sinks:
            result = bridge.verify_and_solve(sink, func_addr)
            if result.is_reachable and result.solver_result:
                print(f"Exploit input: {result.solver_result.inputs}")
    """

    # 漏洞类型映射
    VULN_TYPE_MAP = {
        'BUFFER_OVERFLOW': VulnType.BUFFER_OVERFLOW,
        'FORMAT_STRING': VulnType.FORMAT_STRING,
        'COMMAND_INJECTION': VulnType.COMMAND_INJECTION,
        'INTEGER_OVERFLOW': VulnType.INTEGER_OVERFLOW,
        'DOUBLE_FREE': VulnType.DOUBLE_FREE,
        'USE_AFTER_FREE': VulnType.USE_AFTER_FREE,
        'PATH_TRAVERSAL': VulnType.PATH_TRAVERSAL,
    }

    # 默认缓冲区大小估计
    DEFAULT_BUFFER_SIZES = {
        'strcpy': 256,
        'strcat': 256,
        'sprintf': 512,
        'gets': 128,
        'memcpy': 256,
        'lstrcpyA': 256,
        'lstrcpyW': 512,
    }

    def __init__(self, binary_path: str, auto_load_libs: bool = False):
        self.binary_path = Path(binary_path)
        self.executor = EnhancedSymbolicExecutor(str(binary_path), auto_load_libs)
        self.solver = ExploitSolver()

        # 验证结果缓存
        self._cache: Dict[Tuple[int, int], BridgeResult] = {}

    def taint_sink_to_path_info(self, sink: Any) -> TaintPathInfo:
        """
        将 TaintSink 对象转换为 TaintPathInfo

        Args:
            sink: TaintSink 对象 (来自 disasm.dataflow)

        Returns:
            TaintPathInfo
        """
        # 处理字典格式
        if isinstance(sink, dict):
            return TaintPathInfo(
                source_addr=sink.get('source_addr', 0),
                sink_addr=sink.get('addr', sink.get('address', 0)),
                path=sink.get('taint_path', []),
                tainted_regs=set(sink.get('tainted_regs', [])),
                vuln_type=sink.get('sink_type', sink.get('vuln_type', '')),
                api_name=sink.get('api_name', ''),
                tainted_args=sink.get('tainted_args', []),
                func_name=sink.get('func_name', ''),
                confidence=sink.get('confidence', 0.5)
            )

        # 处理 dataclass 格式
        return TaintPathInfo(
            source_addr=getattr(sink, 'source_addr', 0),
            sink_addr=getattr(sink, 'addr', 0),
            path=getattr(sink, 'taint_path', []),
            tainted_regs=set(getattr(sink, 'tainted_regs', [])),
            vuln_type=getattr(sink, 'sink_type', ''),
            api_name=getattr(sink, 'api_name', ''),
            tainted_args=getattr(sink, 'tainted_args', []),
            func_name=getattr(sink, 'func_name', ''),
            confidence=getattr(sink, 'confidence', 0.5)
        )

    def verify_path_reachability(self, func_addr: int,
                                   target_addr: int,
                                   max_steps: int = 2000) -> Tuple[bool, Optional[PathState]]:
        """
        验证从函数入口到目标地址的可达性

        Args:
            func_addr: 函数入口地址
            target_addr: 目标地址 (sink)
            max_steps: 最大探索步数

        Returns:
            (是否可达, 路径状态)
        """
        cache_key = (func_addr, target_addr)
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            return cached.is_reachable, cached.path_state

        try:
            # 使用符号执行探索
            path_states = self.executor.explore_with_constraints(
                func_addr, target_addr, max_steps
            )

            # 检查是否有路径到达目标
            for ps in path_states:
                if ps.reached_target and ps.is_satisfiable:
                    return True, ps

            # 检查是否有任何接近目标的路径
            for ps in path_states:
                if ps.is_satisfiable:
                    # 可能没有精确到达，但有可满足的路径
                    return True, ps

            return False, None

        except Exception as e:
            logger.warning(f"Path verification failed: {e}")
            return False, None

    def verify_and_solve(self, taint_sink: Any,
                          func_addr: int,
                          max_steps: int = 2000) -> BridgeResult:
        """
        验证污点路径并求解触发输入

        Args:
            taint_sink: TaintSink 对象或字典
            func_addr: 函数入口地址
            max_steps: 最大探索步数

        Returns:
            BridgeResult
        """
        # 转换为统一格式
        path_info = self.taint_sink_to_path_info(taint_sink)

        # 检查缓存
        cache_key = (func_addr, path_info.sink_addr)
        if cache_key in self._cache:
            return self._cache[cache_key]

        # 验证可达性
        is_reachable, path_state = self.verify_path_reachability(
            func_addr, path_info.sink_addr, max_steps
        )

        if not is_reachable or path_state is None:
            result = BridgeResult(
                taint_path=path_info,
                is_reachable=False,
                path_state=None,
                solver_result=None,
                verification_status='UNREACHABLE',
                details=f"Could not find path from 0x{func_addr:x} to 0x{path_info.sink_addr:x}"
            )
            self._cache[cache_key] = result
            return result

        # 获取漏洞类型
        vuln_type = self.VULN_TYPE_MAP.get(
            path_info.vuln_type,
            VulnType.BUFFER_OVERFLOW
        )

        # 根据漏洞类型求解
        solver_result = None

        if vuln_type == VulnType.BUFFER_OVERFLOW:
            # 估计缓冲区大小
            buffer_size = self.DEFAULT_BUFFER_SIZES.get(path_info.api_name, 256)

            params = BufferOverflowParams(
                buffer_size=buffer_size,
                target_offset=buffer_size + 8,  # 假设返回地址在 buffer + 8
            )
            solver_result = self.solver.solve_buffer_overflow(path_state, params)

        elif vuln_type == VulnType.FORMAT_STRING:
            from .solver import FormatStringParams
            params = FormatStringParams(
                target_addr=0,  # 需要用户指定
                target_value=0,
                is_64bit=self.executor.is_64bit
            )
            solver_result = self.solver.solve_format_string(path_state, params)

        elif vuln_type == VulnType.INTEGER_OVERFLOW:
            from .solver import IntegerOverflowParams
            params = IntegerOverflowParams(
                bit_width=64 if self.executor.is_64bit else 32,
                operation='add'
            )
            solver_result = self.solver.solve_integer_overflow(path_state, params)

        else:
            # 通用求解
            constraints = [c.constraint for c in path_state.constraints if c.constraint]
            solver_result = self.solver.solve_from_constraints(
                constraints,
                path_state.symbolic_vars,
                vuln_type
            )

        # 构建结果
        verification_status = 'VERIFIED' if solver_result and solver_result.status == SolveStatus.SUCCESS else 'PARTIAL'

        result = BridgeResult(
            taint_path=path_info,
            is_reachable=True,
            path_state=path_state,
            solver_result=solver_result,
            verification_status=verification_status,
            details=f"Path verified with {path_state.get_constraint_count()} constraints"
        )

        self._cache[cache_key] = result
        return result

    def batch_verify(self, taint_sinks: List[Any],
                      func_addr: int,
                      max_per_sink: int = 1000) -> List[BridgeResult]:
        """
        批量验证多个污点路径

        Args:
            taint_sinks: TaintSink 列表
            func_addr: 函数入口地址
            max_per_sink: 每个 sink 的最大探索步数

        Returns:
            验证结果列表
        """
        results = []

        for sink in taint_sinks:
            try:
                result = self.verify_and_solve(sink, func_addr, max_per_sink)
                results.append(result)
            except Exception as e:
                logger.warning(f"Verification failed for sink: {e}")
                path_info = self.taint_sink_to_path_info(sink)
                results.append(BridgeResult(
                    taint_path=path_info,
                    is_reachable=False,
                    path_state=None,
                    solver_result=None,
                    verification_status='ERROR',
                    details=str(e)
                ))

        return results

    def get_exploit_inputs(self, results: List[BridgeResult]) -> List[Dict]:
        """
        从验证结果中提取漏洞利用输入

        Args:
            results: 验证结果列表

        Returns:
            可用于利用的输入列表
        """
        exploits = []

        for result in results:
            if not result.is_reachable or not result.solver_result:
                continue

            if result.solver_result.status not in (SolveStatus.SUCCESS, SolveStatus.PARTIAL):
                continue

            exploit = {
                'vuln_type': result.taint_path.vuln_type,
                'api_name': result.taint_path.api_name,
                'func_name': result.taint_path.func_name,
                'sink_addr': result.taint_path.sink_addr,
                'inputs': result.solver_result.inputs,
                'payload_hint': result.solver_result.payload_hint,
                'confidence': result.taint_path.confidence,
                'verification': result.verification_status
            }
            exploits.append(exploit)

        # 按置信度排序
        exploits.sort(key=lambda x: x['confidence'], reverse=True)

        return exploits

    def generate_exploit_summary(self, results: List[BridgeResult]) -> str:
        """
        生成漏洞利用摘要

        Args:
            results: 验证结果列表

        Returns:
            摘要文本
        """
        lines = [
            "=" * 60,
            "TAINT-SYMBOLIC BRIDGE ANALYSIS SUMMARY",
            "=" * 60,
            ""
        ]

        total = len(results)
        reachable = sum(1 for r in results if r.is_reachable)
        verified = sum(1 for r in results if r.verification_status == 'VERIFIED')

        lines.append(f"Total sinks analyzed: {total}")
        lines.append(f"Reachable paths: {reachable}")
        lines.append(f"Fully verified: {verified}")
        lines.append("")

        # 按漏洞类型分组
        by_type: Dict[str, List[BridgeResult]] = {}
        for r in results:
            vtype = r.taint_path.vuln_type
            if vtype not in by_type:
                by_type[vtype] = []
            by_type[vtype].append(r)

        for vtype, type_results in by_type.items():
            lines.append(f"\n{vtype}:")
            for r in type_results[:5]:  # 每类最多显示 5 个
                status = "✓" if r.verification_status == 'VERIFIED' else "○" if r.is_reachable else "✗"
                lines.append(f"  {status} {r.taint_path.api_name} @ 0x{r.taint_path.sink_addr:x}")

                if r.solver_result and r.solver_result.payload_hint:
                    hint = r.solver_result.payload_hint[:16].hex()
                    lines.append(f"      Payload: {hint}...")

        return "\n".join(lines)

    def clear_cache(self):
        """清空缓存"""
        self._cache.clear()
        self.executor.collector.reset()
