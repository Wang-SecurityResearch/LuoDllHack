# -*- coding: utf-8 -*-
"""
luodllhack/symbolic/angr_executor.py - 基于 angr 的符号执行引擎

基于 angr 的符号执行，用于:
1. 生成触发漏洞的具体输入
2. 验证污点分析路径的可达性
3. 探索程序状态空间

这是真正的符号执行，不是模板填充。
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
import struct

try:
    import angr
    import claripy
    from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCStdcall
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False
    angr = None
    claripy = None

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False


@dataclass
class SymbolicInput:
    """符号输入"""
    name: str
    size: int  # 字节数
    bitvec: Any  # claripy.BVS
    concrete_value: Optional[bytes] = None

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'size': self.size,
            'concrete': self.concrete_value.hex() if self.concrete_value else None
        }


@dataclass
class PathConstraint:
    """路径约束"""
    address: int
    condition: str  # 约束的字符串表示
    is_satisfiable: bool = True

    def to_dict(self) -> Dict:
        return {
            'address': f'0x{self.address:x}',
            'condition': self.condition,
            'satisfiable': self.is_satisfiable
        }


@dataclass
class ExploitInput:
    """漏洞利用输入"""
    vuln_type: str
    target_address: int
    func_name: str
    inputs: Dict[str, bytes]  # 参数名 -> 具体值
    path_constraints: List[PathConstraint]
    confidence: float
    description: str = ""

    def to_dict(self) -> Dict:
        return {
            'vuln_type': self.vuln_type,
            'target': f'0x{self.target_address:x}',
            'func_name': self.func_name,
            'inputs': {k: v.hex() for k, v in self.inputs.items()},
            'constraints': [c.to_dict() for c in self.path_constraints],
            'confidence': self.confidence,
            'description': self.description
        }


class SymbolicExecutor:
    """
    真正的符号执行引擎

    用法:
        executor = SymbolicExecutor("target.dll")

        # 从函数入口探索
        result = executor.explore_function(0x10001000, "VulnFunc")

        # 生成触发输入
        exploit_inputs = executor.generate_exploit_inputs(taint_sinks)
    """

    # 危险 API 和其参数位置
    DANGEROUS_APIS = {
        # 缓冲区溢出
        'strcpy': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},
        'strcat': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},
        'sprintf': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},
        'gets': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},
        'memcpy': {'sink_args': [0, 2], 'vuln_type': 'BUFFER_OVERFLOW'},
        'memmove': {'sink_args': [0, 2], 'vuln_type': 'BUFFER_OVERFLOW'},
        'lstrcpyA': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},
        'lstrcpyW': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},
        'lstrcatA': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},
        'lstrcatW': {'sink_args': [0], 'vuln_type': 'BUFFER_OVERFLOW'},

        # 格式化字符串
        'printf': {'sink_args': [0], 'vuln_type': 'FORMAT_STRING'},
        'sprintf': {'sink_args': [1], 'vuln_type': 'FORMAT_STRING'},
        'fprintf': {'sink_args': [1], 'vuln_type': 'FORMAT_STRING'},
        'snprintf': {'sink_args': [2], 'vuln_type': 'FORMAT_STRING'},
        'wprintf': {'sink_args': [0], 'vuln_type': 'FORMAT_STRING'},

        # 命令注入
        'system': {'sink_args': [0], 'vuln_type': 'COMMAND_INJECTION'},
        'WinExec': {'sink_args': [0], 'vuln_type': 'COMMAND_INJECTION'},
        'ShellExecuteA': {'sink_args': [2, 3], 'vuln_type': 'COMMAND_INJECTION'},
        'ShellExecuteW': {'sink_args': [2, 3], 'vuln_type': 'COMMAND_INJECTION'},
        'CreateProcessA': {'sink_args': [0, 1], 'vuln_type': 'COMMAND_INJECTION'},
        'CreateProcessW': {'sink_args': [0, 1], 'vuln_type': 'COMMAND_INJECTION'},
    }

    def __init__(self, binary_path: str, auto_load_libs: bool = False):
        """
        初始化符号执行引擎

        Args:
            binary_path: 二进制文件路径
            auto_load_libs: 是否自动加载依赖库
        """
        if not HAVE_ANGR:
            raise ImportError("angr is required: pip install angr")

        self.binary_path = Path(binary_path)

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # 加载二进制
        self.project = angr.Project(
            str(self.binary_path),
            auto_load_libs=auto_load_libs,
            use_sim_procedures=True
        )

        self.arch = self.project.arch
        self.is_64bit = self.arch.bits == 64

        # 符号输入追踪
        self.symbolic_inputs: List[SymbolicInput] = []

        # 路径探索结果
        self.explored_paths: List[List[int]] = []
        self.path_constraints: List[PathConstraint] = []

        # 危险 API 调用点
        self.dangerous_calls: List[Dict] = []

        # 设置 SimProcedures 来 hook 危险函数
        self._setup_hooks()

    def _setup_hooks(self):
        """设置函数钩子"""
        for api_name, info in self.DANGEROUS_APIS.items():
            try:
                # 创建 hook 来追踪危险 API 调用
                self.project.hook_symbol(
                    api_name,
                    self._make_api_hook(api_name, info),
                    replace=True
                )
            except Exception:
                pass  # 符号不存在

    def _make_api_hook(self, api_name: str, info: Dict):
        """创建 API hook"""
        sink_args = info['sink_args']
        vuln_type = info['vuln_type']

        class DangerousAPIHook(angr.SimProcedure):
            def run(hook_self, *args):
                # 记录调用
                call_info = {
                    'api': api_name,
                    'vuln_type': vuln_type,
                    'address': hook_self.state.addr,
                    'args': [],
                    'tainted_args': []
                }

                for i, arg in enumerate(args):
                    if arg is not None:
                        call_info['args'].append(str(arg))
                        # 检查参数是否是符号化的
                        if arg.symbolic:
                            call_info['tainted_args'].append(i)

                # 如果危险参数是符号化的，记录漏洞
                for sink_idx in sink_args:
                    if sink_idx < len(args):
                        if args[sink_idx] is not None and args[sink_idx].symbolic:
                            self.dangerous_calls.append(call_info)
                            break

                # 返回 0
                return hook_self.state.solver.BVV(0, hook_self.state.arch.bits)

        return DangerousAPIHook

    def create_symbolic_input(self, name: str, size: int) -> Any:
        """
        创建符号输入

        Args:
            name: 输入名称
            size: 字节大小

        Returns:
            claripy 符号位向量
        """
        bvs = claripy.BVS(name, size * 8)
        self.symbolic_inputs.append(SymbolicInput(
            name=name,
            size=size,
            bitvec=bvs
        ))
        return bvs

    def create_symbolic_state(self, func_addr: int,
                              arg_sizes: List[int] = None) -> Any:
        """
        创建符号化的初始状态

        Args:
            func_addr: 函数地址
            arg_sizes: 各参数的字节大小

        Returns:
            angr 状态
        """
        if arg_sizes is None:
            arg_sizes = [8, 8, 8, 8] if self.is_64bit else [4, 4, 4, 4]

        # 创建符号参数
        symbolic_args = []
        for i, size in enumerate(arg_sizes):
            arg = self.create_symbolic_input(f"arg{i}", size)
            symbolic_args.append(arg)

        # 设置调用约定
        if self.is_64bit:
            cc = SimCCMicrosoftAMD64(self.project.arch)
        else:
            cc = SimCCStdcall(self.project.arch)

        # 创建调用状态
        state = self.project.factory.call_state(
            func_addr,
            *symbolic_args,
            cc=cc
        )

        # 添加一些基本约束
        for sym_input in self.symbolic_inputs:
            # 约束输入为可打印 ASCII 或特定范围
            # 这有助于生成更有意义的输入
            pass  # 不添加过多约束，保持通用性

        return state

    def explore_function(self, func_addr: int, func_name: str = "",
                         max_steps: int = 1000,
                         timeout: int = 60) -> Dict:
        """
        探索函数的执行路径

        Args:
            func_addr: 函数地址
            func_name: 函数名
            max_steps: 最大步数
            timeout: 超时秒数

        Returns:
            探索结果
        """
        self.dangerous_calls.clear()
        self.symbolic_inputs.clear()

        result = {
            'func_addr': func_addr,
            'func_name': func_name,
            'paths_explored': 0,
            'dangerous_calls': [],
            'symbolic_inputs': [],
            'errors': []
        }

        try:
            # 创建初始状态
            state = self.create_symbolic_state(func_addr)

            # 创建模拟管理器
            simgr = self.project.factory.simulation_manager(state)

            # 探索
            simgr.run(n=max_steps)

            # 收集结果
            result['paths_explored'] = len(simgr.deadended) + len(simgr.active)

            # 记录危险调用
            result['dangerous_calls'] = self.dangerous_calls.copy()

            # 记录符号输入
            result['symbolic_inputs'] = [
                inp.to_dict() for inp in self.symbolic_inputs
            ]

            # 尝试具体化输入
            for state in simgr.deadended:
                self._try_concretize_inputs(state)

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def _try_concretize_inputs(self, state) -> bool:
        """尝试将符号输入具体化"""
        try:
            for sym_input in self.symbolic_inputs:
                if sym_input.concrete_value is None:
                    # 获取一个可能的具体值
                    concrete = state.solver.eval(sym_input.bitvec, cast_to=bytes)
                    sym_input.concrete_value = concrete
            return True
        except Exception:
            return False

    def find_path_to_address(self, start_addr: int, target_addr: int,
                             max_steps: int = 2000) -> Optional[Dict]:
        """
        查找到达目标地址的路径

        Args:
            start_addr: 起始地址
            target_addr: 目标地址
            max_steps: 最大步数

        Returns:
            路径信息或 None
        """
        try:
            state = self.create_symbolic_state(start_addr)
            simgr = self.project.factory.simulation_manager(state)

            # 使用探索技术找到目标
            simgr.explore(find=target_addr, num_find=1, n=max_steps)

            if simgr.found:
                found_state = simgr.found[0]

                # 提取路径约束
                constraints = []
                for c in found_state.solver.constraints:
                    constraints.append(PathConstraint(
                        address=0,  # angr 约束不直接关联地址
                        condition=str(c),
                        is_satisfiable=True
                    ))

                # 具体化输入
                self._try_concretize_inputs(found_state)

                return {
                    'found': True,
                    'target': target_addr,
                    'constraints': constraints,
                    'inputs': {
                        inp.name: inp.concrete_value
                        for inp in self.symbolic_inputs
                        if inp.concrete_value
                    }
                }

            return {'found': False, 'target': target_addr}

        except Exception as e:
            return {'found': False, 'target': target_addr, 'error': str(e)}

    def generate_exploit_inputs(self, taint_sinks: List[Dict],
                                func_addr: int = 0,
                                func_name: str = "") -> List[ExploitInput]:
        """
        为污点分析发现的 sink 生成触发输入

        Args:
            taint_sinks: 污点分析的 sink 列表
            func_addr: 函数地址
            func_name: 函数名

        Returns:
            漏洞利用输入列表
        """
        exploit_inputs = []

        for sink in taint_sinks:
            sink_addr = sink.get('addr', sink.get('address', 0))
            api_name = sink.get('api_name', '')
            sink_type = sink.get('sink_type', sink.get('vuln_type', ''))
            tainted_args = sink.get('tainted_args', [])

            # 查找从函数入口到 sink 的路径
            if func_addr:
                path_result = self.find_path_to_address(func_addr, sink_addr)

                if path_result and path_result.get('found'):
                    exploit_input = ExploitInput(
                        vuln_type=sink_type,
                        target_address=sink_addr,
                        func_name=func_name,
                        inputs=path_result.get('inputs', {}),
                        path_constraints=path_result.get('constraints', []),
                        confidence=0.8 if path_result.get('inputs') else 0.5,
                        description=self._generate_exploit_description(
                            sink_type, api_name, tainted_args
                        )
                    )
                    exploit_inputs.append(exploit_input)
                else:
                    # 无法找到路径，但仍报告
                    exploit_input = ExploitInput(
                        vuln_type=sink_type,
                        target_address=sink_addr,
                        func_name=func_name,
                        inputs={},
                        path_constraints=[],
                        confidence=0.3,
                        description=f"Path to {api_name} could not be verified symbolically"
                    )
                    exploit_inputs.append(exploit_input)

        return exploit_inputs

    def _generate_exploit_description(self, vuln_type: str,
                                      api_name: str,
                                      tainted_args: List[int]) -> str:
        """生成漏洞利用描述"""
        if vuln_type == 'BUFFER_OVERFLOW':
            return (f"Buffer overflow via {api_name}(). "
                    f"Tainted arguments at positions {tainted_args} "
                    f"can overflow the destination buffer.")
        elif vuln_type == 'FORMAT_STRING':
            return (f"Format string vulnerability via {api_name}(). "
                    f"User-controlled format string at position {tainted_args}.")
        elif vuln_type == 'COMMAND_INJECTION':
            return (f"Command injection via {api_name}(). "
                    f"Attacker-controlled command at position {tainted_args}.")
        else:
            return f"Potential {vuln_type} via {api_name}()"

    def generate_poc_code(self, exploit_input: ExploitInput) -> str:
        """
        生成 PoC 代码

        Args:
            exploit_input: 漏洞利用输入

        Returns:
            Python PoC 代码
        """
        lines = [
            "#!/usr/bin/env python3",
            '"""',
            f"PoC for {exploit_input.vuln_type} in {exploit_input.func_name}",
            f"Target address: 0x{exploit_input.target_address:x}",
            f"Generated by LuoDllHack Symbolic Executor",
            '"""',
            "",
            "import ctypes",
            "from ctypes import wintypes",
            "",
            "# Load the vulnerable DLL",
            f'dll = ctypes.CDLL(r"{self.binary_path}")',
            "",
            "# Exploit inputs (generated via symbolic execution)",
        ]

        for name, value in exploit_input.inputs.items():
            if value:
                # 格式化字节数据
                hex_str = value.hex()
                lines.append(f'{name} = bytes.fromhex("{hex_str}")')

        lines.extend([
            "",
            "# Trigger the vulnerability",
            f"# Call {exploit_input.func_name} with crafted inputs",
            f"# func = dll.{exploit_input.func_name}",
            "# func.argtypes = [...]  # Define argument types",
            "# func.restype = ...     # Define return type",
            "# result = func(*args)",
            "",
            f"# Description: {exploit_input.description}",
        ])

        return "\n".join(lines)

    def print_report(self, explore_result: Dict):
        """打印探索报告"""
        print("\n" + "=" * 60)
        print("SYMBOLIC EXECUTION REPORT")
        print("=" * 60)

        addr = explore_result.get('func_addr', 0)
        name = explore_result.get('func_name', 'unknown')
        print(f"\nFunction: {name} @ 0x{addr:x}")
        print(f"Paths explored: {explore_result.get('paths_explored', 0)}")

        dangerous = explore_result.get('dangerous_calls', [])
        if dangerous:
            print(f"\n[!] Dangerous API calls found: {len(dangerous)}")
            for call in dangerous[:10]:
                print(f"  - {call.get('api')} @ 0x{call.get('address', 0):x}")
                print(f"    Type: {call.get('vuln_type')}")
                print(f"    Tainted args: {call.get('tainted_args')}")
        else:
            print("\n[*] No dangerous API calls detected")

        inputs = explore_result.get('symbolic_inputs', [])
        if inputs:
            print(f"\nSymbolic inputs: {len(inputs)}")
            for inp in inputs:
                concrete = inp.get('concrete')
                if concrete:
                    print(f"  - {inp.get('name')}: {concrete}")

        errors = explore_result.get('errors', [])
        if errors:
            print(f"\nErrors: {len(errors)}")
            for err in errors:
                print(f"  - {err}")


def check_angr():
    """检查 angr 是否可用"""
    if HAVE_ANGR:
        print(f"[+] angr version: {angr.__version__}")
        return True
    else:
        print("[!] angr not available. Install with: pip install angr")
        return False


if __name__ == "__main__":
    check_angr()
