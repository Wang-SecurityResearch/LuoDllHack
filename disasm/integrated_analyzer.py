# -*- coding: utf-8 -*-
"""
disasm/integrated_analyzer.py - LuoDllHack v6.0 整合分析器

基于 Rizin 的统一漏洞分析入口，整合:
    1. Rizin 反汇编与 CFG
    2. Rizin 反编译 (Ghidra)
    3. 类型感知污点分析
    4. 动态行为验证 (Speakeasy)
    5. 符号执行 (angr)
    6. AI 辅助分析
    7. PoC 自动生成

作者: LuoDllHack Team
版本: 6.0.0
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

# =============================================================================
# 核心导入 - 基于 Rizin
# =============================================================================

from luodllhack.core import (
    # Rizin 核心
    RizinCore,
    HAVE_RIZIN,
    # 数据结构
    Function,
    BasicBlock,
    Instruction,
    Import,
    Export,
    # 漏洞类型
    VulnType,
    TaintPath,
    VulnFinding,
    DANGEROUS_SINKS,
    # 配置
    LuoDllHackConfig,
    default_config,
)

# =============================================================================
# 可选模块
# =============================================================================

# 动态验证
try:
    from luodllhack.verify import SpeakeasyVerifier, HAVE_SPEAKEASY
except ImportError:
    HAVE_SPEAKEASY = False
    SpeakeasyVerifier = None

# 符号执行
try:
    from luodllhack.symbolic import SymbolicExecutor, HAVE_ANGR
except ImportError:
    HAVE_ANGR = False
    SymbolicExecutor = None

# AI 分析
try:
    from luodllhack.ai import AIAnalyzer
    HAVE_AI = AIAnalyzer is not None
except ImportError:
    HAVE_AI = False
    AIAnalyzer = None

# PoC 生成
try:
    from luodllhack.exploit import PrecisePoCGenerator, PayloadBuilder, ExploitContext
    from luodllhack.exploit import VulnType as ExploitVulnType
    HAVE_EXPLOIT = True
except ImportError:
    HAVE_EXPLOIT = False
    PrecisePoCGenerator = None

# 污点分析
try:
    from luodllhack.analysis.taint import TaintEngine
    HAVE_TAINT = True
except ImportError:
    HAVE_TAINT = False
    TaintEngine = None

logger = logging.getLogger(__name__)


# =============================================================================
# 数据结构
# =============================================================================

class AnalysisPhase(Enum):
    """分析阶段"""
    STATIC_TAINT = "static_taint"       # 静态污点分析
    DYNAMIC_VERIFY = "dynamic_verify"   # 动态验证
    SYMBOLIC_EXEC = "symbolic_exec"     # 符号执行
    AI_ANALYSIS = "ai_analysis"         # AI 分析
    POC_GENERATION = "poc_generation"   # PoC 生成


@dataclass
class IntegratedFinding:
    """整合的漏洞发现"""
    # 基本信息
    vuln_type: str
    severity: str
    address: int
    func_name: str
    api_name: str

    # 分析结果
    static_confidence: float = 0.0
    dynamic_verified: bool = False
    dynamic_confidence: float = 0.0
    symbolic_reachable: bool = False

    # 详细信息
    taint_path: List[int] = field(default_factory=list)
    tainted_args: List[int] = field(default_factory=list)
    behavior_patterns: List[str] = field(default_factory=list)

    # 反编译代码 (新增)
    decompiled_code: str = ""

    # AI 分析
    ai_analysis: str = ""

    # PoC
    poc_generated: bool = False
    poc_code: str = ""
    payload: bytes = b""

    # 元数据
    cwe_id: str = ""
    description: str = ""

    @property
    def overall_confidence(self) -> float:
        """综合置信度"""
        conf = self.static_confidence * 0.3
        if self.dynamic_verified:
            conf += self.dynamic_confidence * 0.4
        if self.symbolic_reachable:
            conf += 0.2
        if self.poc_generated:
            conf += 0.1
        return min(conf, 1.0)

    @property
    def is_confirmed(self) -> bool:
        """是否已确认"""
        return self.overall_confidence >= 0.6 or self.dynamic_verified

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'address': f'0x{self.address:x}',
            'func_name': self.func_name,
            'api_name': self.api_name,
            'static_confidence': self.static_confidence,
            'dynamic_verified': self.dynamic_verified,
            'overall_confidence': self.overall_confidence,
            'is_confirmed': self.is_confirmed,
            'taint_path': [f'0x{a:x}' for a in self.taint_path],
            'decompiled_code': self.decompiled_code[:500] if self.decompiled_code else "",
            'cwe_id': self.cwe_id,
        }


# =============================================================================
# 整合分析器
# =============================================================================

class IntegratedAnalyzer:
    """
    LuoDllHack v6.0 整合分析器

    基于 Rizin 的统一漏洞分析入口。

    使用示例:
        analyzer = IntegratedAnalyzer("target.dll")
        findings = analyzer.analyze_all()
        analyzer.print_report()
    """

    def __init__(
        self,
        binary_path: str,
        enable_dynamic: bool = True,
        enable_symbolic: bool = False,
        enable_ai: bool = False,
        ai_api_key: str = None,
        config: LuoDllHackConfig = None,
    ):
        """
        初始化整合分析器

        参数:
            binary_path: 目标二进制路径
            enable_dynamic: 启用动态验证 (Speakeasy)
            enable_symbolic: 启用符号执行 (angr)
            enable_ai: 启用 AI 分析
            ai_api_key: AI API 密钥
            config: LuoDllHack 配置
        """
        self.binary_path = Path(binary_path)
        self.config = config or default_config

        if not self.binary_path.exists():
            raise FileNotFoundError(f"文件不存在: {binary_path}")

        if not HAVE_RIZIN:
            raise RuntimeError("Rizin 未安装，请运行: pip install rzpipe")

        # 初始化 Rizin 核心引擎
        logger.info(f"正在加载: {self.binary_path.name}")
        self.rz = RizinCore(str(self.binary_path), auto_analyze=True)

        # 初始化污点引擎 (基于 RizinCore)
        self.taint_engine = None
        if HAVE_TAINT:
            try:
                self.taint_engine = TaintEngine(self.rz, config=self.config)
            except Exception as e:
                logger.warning(f"污点引擎初始化失败: {e}")

        # 动态验证器
        self.verifier = None
        if enable_dynamic and HAVE_SPEAKEASY:
            try:
                timeout = self.config.verify_emulation_timeout if self.config else 30
                self.verifier = SpeakeasyVerifier(str(self.binary_path), timeout=timeout)
            except Exception as e:
                logger.warning(f"动态验证器初始化失败: {e}")

        # 符号执行器
        self.symbolic = None
        if enable_symbolic and HAVE_ANGR:
            try:
                self.symbolic = SymbolicExecutor(str(self.binary_path))
            except Exception as e:
                logger.warning(f"符号执行器初始化失败: {e}")

        # AI 分析器
        self.ai = None
        if enable_ai and HAVE_AI:
            try:
                self.ai = AIAnalyzer(self.rz, api_key=ai_api_key)
            except Exception as e:
                logger.warning(f"AI 分析器初始化失败: {e}")

        # PoC 生成器
        self.poc_generator = None
        if HAVE_EXPLOIT:
            try:
                self.poc_generator = PrecisePoCGenerator()
            except Exception as e:
                logger.warning(f"PoC 生成器初始化失败: {e}")

        # 结果存储
        self.findings: List[IntegratedFinding] = []

        logger.info(f"已加载: {self.rz.info.arch.name} {self.rz.bits}位")

    # =========================================================================
    # 分析方法
    # =========================================================================

    def analyze_function(
        self,
        func_addr: int,
        func_name: str,
        phases: List[AnalysisPhase] = None,
    ) -> List[IntegratedFinding]:
        """
        分析单个函数

        参数:
            func_addr: 函数地址
            func_name: 函数名
            phases: 分析阶段列表

        返回:
            漏洞发现列表
        """
        if phases is None:
            phases = [AnalysisPhase.STATIC_TAINT]
            if self.verifier:
                phases.append(AnalysisPhase.DYNAMIC_VERIFY)

        findings = []

        # 获取函数详细信息 (包括反编译)
        func = self.rz.analyze_function(func_addr)

        # 阶段 1: 静态污点分析
        if AnalysisPhase.STATIC_TAINT in phases:
            static_findings = self._static_analysis(func)
            for sf in static_findings:
                sf.decompiled_code = func.decompiled
                findings.append(sf)

        # 阶段 2: 动态验证
        if AnalysisPhase.DYNAMIC_VERIFY in phases and self.verifier:
            for finding in findings:
                self._dynamic_verify(finding)

        # 阶段 3: 符号执行
        if AnalysisPhase.SYMBOLIC_EXEC in phases and self.symbolic:
            for finding in findings:
                self._symbolic_verify(finding, func_addr)

        # 阶段 4: AI 分析
        if AnalysisPhase.AI_ANALYSIS in phases and self.ai:
            for finding in findings:
                if finding.is_confirmed:
                    self._ai_analyze(finding, func)

        # 阶段 5: PoC 生成
        if AnalysisPhase.POC_GENERATION in phases and self.poc_generator:
            for finding in findings:
                if finding.static_confidence >= 0.5:
                    self._generate_poc(finding, func_addr)

        self.findings.extend(findings)
        return findings

    def _static_analysis(self, func: Function) -> List[IntegratedFinding]:
        """静态污点分析"""
        findings = []

        # 使用污点引擎分析
        if self.taint_engine:
            try:
                taint_paths = self.taint_engine.analyze_function(func.address, func.name)
                for path in taint_paths:
                    finding = self._convert_taint_path(path, func.name)
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"污点分析失败: {e}")

        # 基于 Rizin 的简单危险 API 检测
        if not findings:
            findings = self._detect_dangerous_calls(func)

        return findings

    def _detect_dangerous_calls(self, func: Function) -> List[IntegratedFinding]:
        """检测危险 API 调用"""
        findings = []
        imports = self.rz.get_imports()

        for block in func.blocks:
            for insn in block.instructions:
                if insn.is_call and insn.call_target:
                    target = insn.call_target
                    if target in imports:
                        api_name = imports[target].name
                        api_bytes = api_name.encode() if isinstance(api_name, str) else api_name

                        if api_bytes in DANGEROUS_SINKS:
                            sink_info = DANGEROUS_SINKS[api_bytes]
                            finding = IntegratedFinding(
                                vuln_type=sink_info.get('vuln', VulnType.BUFFER_OVERFLOW).name,
                                severity=sink_info.get('severity', 'Medium'),
                                address=insn.address,
                                func_name=func.name,
                                api_name=api_name,
                                static_confidence=0.4,
                                cwe_id=sink_info.get('cwe', ''),
                            )
                            findings.append(finding)

        return findings

    def _convert_taint_path(self, path: TaintPath, func_name: str) -> IntegratedFinding:
        """转换污点路径为 Finding"""
        return IntegratedFinding(
            vuln_type=path.sink.vuln_type.name if hasattr(path.sink.vuln_type, 'name') else str(path.sink.vuln_type),
            severity=path.sink.severity,
            address=path.sink.addr,
            func_name=func_name,
            api_name=path.sink.api_name,
            static_confidence=path.confidence,
            taint_path=[step.addr for step in path.steps],
            tainted_args=[path.sink.tainted_arg_idx] if path.sink.tainted_arg_idx is not None else [],
            description=f"污点路径: {path.source.api_name} -> {path.sink.api_name}",
        )

    def _dynamic_verify(self, finding: IntegratedFinding):
        """动态验证"""
        try:
            result = self.verifier.verify(
                finding.address,
                finding.func_name,
                finding.vuln_type
            )
            finding.dynamic_verified = result.is_vulnerable
            finding.dynamic_confidence = result.confidence
            if hasattr(result, 'patterns'):
                finding.behavior_patterns = [p.description for p in result.patterns]
        except Exception as e:
            logger.debug(f"动态验证失败: {e}")

    def _symbolic_verify(self, finding: IntegratedFinding, func_addr: int):
        """符号执行验证"""
        try:
            result = self.symbolic.find_path_to_address(func_addr, finding.address)
            if result and result.get('found'):
                finding.symbolic_reachable = True
        except Exception as e:
            logger.debug(f"符号执行失败: {e}")

    def _ai_analyze(self, finding: IntegratedFinding, func: Function):
        """AI 分析"""
        try:
            # 使用反编译代码进行分析
            prompt = f"""分析以下函数中的潜在漏洞:

函数: {func.name}
漏洞类型: {finding.vuln_type}
地址: 0x{finding.address:x}

反编译代码:
{func.decompiled[:2000] if func.decompiled else '(无反编译结果)'}

请分析漏洞成因和利用可能性。"""

            result = self.ai.analyze(prompt)
            finding.ai_analysis = result
        except Exception as e:
            logger.debug(f"AI 分析失败: {e}")

    def _generate_poc(self, finding: IntegratedFinding, func_addr: int):
        """生成 PoC"""
        try:
            vuln_type_map = {
                'BUFFER_OVERFLOW': ExploitVulnType.BUFFER_OVERFLOW,
                'FORMAT_STRING': ExploitVulnType.FORMAT_STRING,
                'COMMAND_INJECTION': ExploitVulnType.COMMAND_INJECTION,
            }

            context = ExploitContext(
                dll_path=str(self.binary_path),
                func_name=finding.func_name,
                func_addr=func_addr,
                vuln_type=vuln_type_map.get(finding.vuln_type, ExploitVulnType.BUFFER_OVERFLOW),
                sink_api=finding.api_name,
                tainted_args=finding.tainted_args,
            )

            result = self.poc_generator.generate(context)
            finding.poc_generated = True
            finding.poc_code = result.code
            finding.payload = result.payload or b""
        except Exception as e:
            logger.debug(f"PoC 生成失败: {e}")

    # =========================================================================
    # 批量分析
    # =========================================================================

    def analyze_all(
        self,
        max_exports: int = 0,
        phases: List[AnalysisPhase] = None,
    ) -> List[IntegratedFinding]:
        """
        分析所有导出函数

        参数:
            max_exports: 最大导出数 (0 = 无限制)
            phases: 分析阶段

        返回:
            漏洞发现列表
        """
        self.findings.clear()
        exports = self.rz.get_exports()

        if max_exports > 0:
            exports = dict(list(exports.items())[:max_exports])

        total = len(exports)
        print(f"\n[*] 开始分析 {total} 个导出函数...")
        print("=" * 60)

        for i, (addr, exp) in enumerate(exports.items(), 1):
            print(f"\n[{i}/{total}] {exp.name} @ 0x{addr:x}")

            try:
                findings = self.analyze_function(addr, exp.name, phases)
                if findings:
                    confirmed = sum(1 for f in findings if f.is_confirmed)
                    print(f"  [!] 发现 {len(findings)} 个问题 ({confirmed} 个已确认)")
                else:
                    print(f"  [+] 无漏洞发现")
            except Exception as e:
                print(f"  [!] 分析错误: {e}")

        return self.findings

    def hunt_vulnerabilities(
        self,
        target_funcs: List[str] = None,
    ) -> List[IntegratedFinding]:
        """
        漏洞猎杀模式

        参数:
            target_funcs: 目标函数列表 (None = 全部)

        返回:
            漏洞发现列表
        """
        phases = [
            AnalysisPhase.STATIC_TAINT,
            AnalysisPhase.DYNAMIC_VERIFY,
        ]

        if target_funcs:
            exports = self.rz.get_exports()
            for name in target_funcs:
                for addr, exp in exports.items():
                    if exp.name == name:
                        self.analyze_function(addr, name, phases)
                        break
        else:
            self.analyze_all(phases=phases)

        return self.findings

    # =========================================================================
    # 报告
    # =========================================================================

    def print_report(self):
        """打印分析报告"""
        print("\n" + "=" * 70)
        print("LuoDllHack v6.0 漏洞分析报告")
        print("=" * 70)

        if not self.findings:
            print("\n[*] 未发现漏洞")
            return

        confirmed = [f for f in self.findings if f.is_confirmed]
        print(f"\n[!] 总计: {len(self.findings)} 个发现, {len(confirmed)} 个已确认")

        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (0 if f.is_confirmed else 1, severity_order.get(f.severity, 99))
        )

        for i, f in enumerate(sorted_findings, 1):
            status = "已确认" if f.is_confirmed else "待确认"
            icon = "!!!" if f.severity == 'Critical' else "!!"

            print(f"\n[{icon}] #{i} [{status}] {f.vuln_type}")
            print(f"    地址: 0x{f.address:x}")
            print(f"    函数: {f.func_name}")
            print(f"    API: {f.api_name}")
            print(f"    严重性: {f.severity}")
            print(f"    置信度: {f.overall_confidence:.0%}")

            if f.cwe_id:
                print(f"    CWE: {f.cwe_id}")
            if f.dynamic_verified:
                print(f"    动态验证: 已确认")
            if f.poc_generated:
                print(f"    PoC: 已生成")

    def print_capabilities(self):
        """打印分析能力"""
        print("\n" + "=" * 50)
        print("LuoDllHack v6.0 分析能力")
        print("=" * 50)

        capabilities = [
            ("Rizin 核心引擎", HAVE_RIZIN, "rzpipe"),
            ("反编译", True, "Ghidra/pdc"),
            ("污点分析", self.taint_engine is not None, "TaintEngine"),
            ("动态验证", self.verifier is not None, "Speakeasy"),
            ("符号执行", self.symbolic is not None, "angr"),
            ("AI 分析", self.ai is not None, "Gemini"),
            ("PoC 生成", self.poc_generator is not None, "luodllhack.exploit"),
        ]

        for name, available, dep in capabilities:
            status = "+" if available else "-"
            print(f"  [{status}] {name} ({dep})")

    def get_confirmed_findings(self) -> List[IntegratedFinding]:
        """获取已确认漏洞"""
        return [f for f in self.findings if f.is_confirmed]

    def export_json(self) -> List[Dict]:
        """导出 JSON"""
        return [f.to_dict() for f in self.findings]

    def close(self):
        """关闭分析器"""
        if self.rz:
            self.rz.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# =============================================================================
# 入口
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python -m disasm.integrated_analyzer <dll_path>")
        sys.exit(1)

    with IntegratedAnalyzer(sys.argv[1]) as analyzer:
        analyzer.print_capabilities()
        analyzer.analyze_all(max_exports=10)
        analyzer.print_report()
