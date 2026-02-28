# -*- coding: utf-8 -*-
"""
luodllhack/analysis/vuln_analyzer.py - Vulnerability Analyzer

Split from taint.py to provide a unified entry point for vulnerability analysis.
Includes improved 0day discovery capabilities.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING, Any
from collections import defaultdict

# Import type definitions from core.types
from luodllhack.core.types import (
    VulnType,
    SourceType,
    TaintSource,
    TaintSink,
    TaintStep,
    TaintPath,
    VulnFinding,
    CrossFunctionPath,
    ConfidenceFactor,
    ConfidenceScore,
    ScoredFinding,
    DANGEROUS_SINKS,
)
from luodllhack.core.utils import demangle_cpp_symbol, sanitize_filename

# Import confidence scorer
from .confidence import ConfidenceScorer, CONFIDENCE_WEIGHTS

# Import configuration
try:
    from luodllhack.core.config import default_config, LuoDllHackConfig
    HAVE_CONFIG = True
except ImportError:
    HAVE_CONFIG = False
    default_config = None
    LuoDllHackConfig = None

# =============================================================================
# Optional Dependency Detection
# =============================================================================

try:
    import angr
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False

# CFG/DataFlow is now integrated into RizinCore and no longer exists separately
HAVE_DATAFLOW = False


class VulnAnalyzer:
    """
    Vulnerability Analyzer - Unified Entry Point

    Integrates:
    1. TaintEngine (Core) - Based on RizinCore
    2. SymbolicEngine (Auxiliary)
    3. FuzzingModule (Pattern-based)
    4. [New] Cross-function analysis
    5. [Improved] 0day discovery capabilities
    """

    def __init__(self, binary_path: Path, config: 'LuoDllHackConfig' = None,
                 signature_file: Path = None) -> None:
        # Deferred imports to avoid circular dependencies
        from .taint import TaintEngine, SymbolicEngine, FuzzingModule
        from luodllhack.core import RizinCore

        self.binary_path = binary_path
        self.signature_file = Path(signature_file) if signature_file else None
        self.findings: List[VulnFinding] = []
        self.cross_function_findings: List[VulnFinding] = []

        # Configuration (Prioritize passed config, otherwise use global default)
        self.config = config or (default_config if HAVE_CONFIG else None)

        # Initialize RizinCore
        self.rz = RizinCore(str(binary_path))

        # Initialize engines (Pass RizinCore instance to TaintEngine)
        self.taint_engine = TaintEngine(self.rz, config=self.config)
        self.symbolic_engine: Optional[SymbolicEngine] = None
        self.fuzzing_module = FuzzingModule(binary_path)

        # Confidence Scorer
        self.confidence_scorer = ConfidenceScorer()
        self.scored_findings: List[ScoredFinding] = []

        # New: 0day discovery engines (Improved)
        self.neuro_symbolic_engine = None
        self.advanced_symbolic = None
        self.hybrid_engine = None
        self.vuln_miner = None

        # Initialize 0day discovery engines (with detailed diagnostics)
        self._init_0day_engines(binary_path, self.config)

        # Initialize symbolic execution and CFG analyzer
        self._init_symbolic_and_cfg(binary_path)

    def _init_0day_engines(self, binary_path: Path, config) -> None:
        """Initialize 0day discovery engines with detailed diagnostic information"""
        engines_status = {
            'neuro_symbolic': False,
            'advanced_symbolic': False,
            'hybrid_engine': False,
            'vuln_miner': False
        }

        try:
            from .neuro_symbolic import ZeroDayDiscoveryEngine
            self.neuro_symbolic_engine = ZeroDayDiscoveryEngine(binary_path, config)
            engines_status['neuro_symbolic'] = True
        except ImportError as e:
            self._log_engine_init_failure('neuro_symbolic', e)
        except Exception as e:
            self._log_engine_init_failure('neuro_symbolic', e, is_runtime=True)

        try:
            from ..symbolic.enhanced import AdvancedSymbolicExecutor
            self.advanced_symbolic = AdvancedSymbolicExecutor(binary_path, config)
            engines_status['advanced_symbolic'] = True
        except ImportError as e:
            self._log_engine_init_failure('advanced_symbolic', e)
        except Exception as e:
            self._log_engine_init_failure('advanced_symbolic', e, is_runtime=True)

        try:
            from ..exploit.intelligent_fuzzing import HybridAnalysisEngine
            self.hybrid_engine = HybridAnalysisEngine(binary_path, config)
            engines_status['hybrid_engine'] = True
        except ImportError as e:
            self._log_engine_init_failure('hybrid_engine', e)
        except Exception as e:
            self._log_engine_init_failure('hybrid_engine', e, is_runtime=True)

        try:
            from .pattern_learning import AdvancedVulnerabilityMiner
            self.vuln_miner = AdvancedVulnerabilityMiner(binary_path, config)
            engines_status['vuln_miner'] = True
        except ImportError as e:
            self._log_engine_init_failure('vuln_miner', e)
        except Exception as e:
            self._log_engine_init_failure('vuln_miner', e, is_runtime=True)

        # Aggregate diagnostics
        available = sum(1 for v in engines_status.values() if v)
        if available < 4:
            missing = [k for k, v in engines_status.items() if not v]
            print(f"[*] 0day capabilities: {available}/4 engines available (missing: {', '.join(missing)})")

    def _log_engine_init_failure(self, engine_name: str, error: Exception, is_runtime: bool = False) -> None:
        """Log engine initialization failure"""
        error_type = "runtime error" if is_runtime else "import error"
        # Print detailed information only in debug mode
        if self.config and getattr(self.config, 'debug', False):
            print(f"    [DEBUG] {engine_name} {error_type}: {error}")

    def _init_symbolic_and_cfg(self, binary_path: Path) -> None:
        """Initialize symbolic execution analyzer"""
        if HAVE_ANGR:
            try:
                from .taint import SymbolicEngine
                self.symbolic_engine = SymbolicEngine(binary_path)
            except Exception:
                pass

        # CFG analysis is integrated into RizinCore, no separate initialization needed

    def _analyze_with_cfg_dataflow(self, func_addr: int, func_name: str) -> List:
        """
        Taint analysis using RizinCore CFG analysis capabilities.

        Note: CFG/DataFlow is integrated into RizinCore; this method is kept as a placeholder.
        Actual analysis is performed by TaintEngine via RizinCore.
        """
        # CFG/DataFlow analysis is integrated into TaintEngine
        # Returns an empty list; actual analysis is done in TaintEngine.analyze_function
        return []

    def _convert_dataflow_sink_to_finding(self, sink: Any,
                                           func_name: str) -> Optional[VulnFinding]:
        """Convert DataFlow TaintSink to VulnFinding"""
        type_map = {
            'BUFFER_OVERFLOW': VulnType.BUFFER_OVERFLOW,
            'FORMAT_STRING': VulnType.FORMAT_STRING,
            'COMMAND_INJECTION': VulnType.COMMAND_INJECTION,
            'PATH_TRAVERSAL': VulnType.PATH_TRAVERSAL,
            'INTEGER_OVERFLOW': VulnType.INTEGER_OVERFLOW,
            'DOUBLE_FREE': VulnType.DOUBLE_FREE,
            'UNINITIALIZED_MEMORY': VulnType.UNINITIALIZED_MEMORY,
            'USE_AFTER_FREE': VulnType.USE_AFTER_FREE,
            'UNTRUSTED_POINTER_DEREFERENCE': VulnType.UNTRUSTED_POINTER_DEREFERENCE,
        }

        vuln_type = type_map.get(sink.sink_type, VulnType.BUFFER_OVERFLOW)

        source = TaintSource(
            type=SourceType.ARGUMENT,
            addr=sink.taint_path[0] if sink.taint_path else 0,
            api_name='ARGUMENT',
            tainted_location='reg:rcx'
        )

        sink_obj = TaintSink(
            vuln_type=vuln_type,
            severity='High' if sink.confidence >= 0.7 else 'Medium',
            addr=sink.addr,
            api_name=sink.api_name if isinstance(sink.api_name, str) else sink.api_name.decode(),
            tainted_arg_idx=sink.tainted_args[0] if sink.tainted_args else 0
        )

        steps = [TaintStep(addr=a, instruction='', effect='copy', from_loc='', to_loc='')
                 for a in sink.taint_path]
        taint_path = TaintPath(
            source=source,
            sink=sink_obj,
            steps=steps,
            confidence=sink.confidence,
            func_name=func_name
        )

        return VulnFinding(
            vuln_type=vuln_type,
            severity=sink_obj.severity,
            source=source,
            sink=sink_obj,
            taint_path=taint_path,
            cwe_id=self._get_cwe_for_type(vuln_type)
        )

    def _get_cwe_for_type(self, vuln_type: VulnType) -> Optional[str]:
        """Get the CWE ID corresponding to a vulnerability type"""
        cwe_map = {
            VulnType.BUFFER_OVERFLOW: 'CWE-120',
            VulnType.FORMAT_STRING: 'CWE-134',
            VulnType.COMMAND_INJECTION: 'CWE-78',
            VulnType.PATH_TRAVERSAL: 'CWE-22',
            VulnType.INTEGER_OVERFLOW: 'CWE-190',
            VulnType.USE_AFTER_FREE: 'CWE-416',
            VulnType.DOUBLE_FREE: 'CWE-415',
            VulnType.TYPE_CONFUSION: 'CWE-843',
            VulnType.OUT_OF_BOUNDS_READ: 'CWE-125',
            VulnType.OUT_OF_BOUNDS_WRITE: 'CWE-787',
            VulnType.UNINITIALIZED_MEMORY: 'CWE-908',
            VulnType.RACE_CONDITION: 'CWE-362',
            VulnType.UNTRUSTED_POINTER_DEREFERENCE: 'CWE-822',
        }
        return cwe_map.get(vuln_type)

    def analyze(self, exports: Dict[str, int],
                output_dir: Optional[Path] = None,
                enable_cross_function: bool = True) -> List[VulnFinding]:
        """
        Analyze all exported functions

        Args:
            exports: Dictionary of exported functions {name: address}
            output_dir: Output directory (uses config.output_dir if None)
            enable_cross_function: Whether to enable cross-function analysis

        Returns:
            List of discovered vulnerabilities
        """
        # Default to output directory from configuration
        if output_dir is None and self.config:
            output_dir = self.config.output_dir

        # Control cross-function analysis via taint_cross_function config
        if self.config:
            enable_cross_function = enable_cross_function and self.config.taint_cross_function

        print("\n" + "=" * 60)
        print("Vulnerability Analysis (Taint-Centric)")
        print("=" * 60)

        # Phase 1: Cross-function analysis
        if enable_cross_function:
            cross_paths = self.taint_engine.analyze_cross_function(exports)

            for path in cross_paths:
                taint_path = TaintPath(
                    source=path.source,
                    sink=path.sink,
                    steps=path.steps,
                    confidence=path.confidence,
                    func_name=path.entry_func
                )

                harness = self.fuzzing_module.generate_harness(taint_path, path.entry_func)
                seed = self._generate_cross_function_seed(path)

                finding = VulnFinding(
                    vuln_type=path.sink.vuln_type,
                    severity=path.sink.severity,
                    source=path.source,
                    sink=path.sink,
                    taint_path=taint_path,
                    harness_code=harness,
                    cwe_id=DANGEROUS_SINKS.get(path.sink.api_name.encode() if isinstance(path.sink.api_name, str) else path.sink.api_name, {}).get('cwe')
                )
                self.cross_function_findings.append(finding)
                self.findings.append(finding)

                if output_dir:
                    self._save_outputs(finding, path.entry_func, output_dir, seed)

        # Phase 2: Single-function analysis
        print("\n" + "=" * 60)
        print("Single-Function Analysis (RizinCore)")
        print("=" * 60)

        for name, addr in exports.items():
            display_name = demangle_cpp_symbol(name)
            print(f"\n[*] Analyzing: {display_name} @ 0x{addr:x}")
            if display_name != name:
                print(f"    (Mangled: {name})")

            # Engine 1: TaintEngine
            taint_paths = self.taint_engine.analyze_function(addr, name)

            # Engine 2: CFG + DataFlow
            dataflow_sinks = self._analyze_with_cfg_dataflow(addr, name)
            if dataflow_sinks:
                print(f"    [+] CFG DataFlow found {len(dataflow_sinks)} sink(s)")
                for df_sink in dataflow_sinks:
                    is_dup = any(p.sink.addr == df_sink.addr for p in taint_paths)
                    if not is_dup:
                        finding = self._convert_dataflow_sink_to_finding(df_sink, name)
                        if finding:
                            # Generate PoC and Harness for CFG discovery
                            trigger_input = None
                            if self.symbolic_engine:
                                print(f"        [*] Attempting symbolic solving for CFG finding...")
                                trigger_input = self.symbolic_engine.solve_trigger_input(finding.taint_path)
                                if trigger_input:
                                    finding.trigger_input = trigger_input
                                    print(f"        [+] Generated trigger input: {trigger_input[:32]}...")

                            harness = self.fuzzing_module.generate_harness(finding.taint_path, name)
                            finding.harness_code = harness
                            seed = self.fuzzing_module.generate_seed(finding.taint_path, name)

                            self.findings.append(finding)
                            print(f"        [!] {finding.vuln_type.name} @ 0x{df_sink.addr:x} (CFG)")

                            if output_dir:
                                self._save_outputs(finding, name, output_dir, seed)

            if not taint_paths and not dataflow_sinks:
                print("    [-] No taint paths found")
                continue

            if not taint_paths:
                continue

            print(f"    [+] Found {len(taint_paths)} taint path(s)")

            for path in taint_paths:
                if self._is_duplicate_finding(path):
                    print(f"    [*] Skipping duplicate: {path.sink.api_name}")
                    continue

                print(f"\n    [!] {path.sink.vuln_type.name} detected!")
                print(f"        Source: {path.source.api_name} @ 0x{path.source.addr:x}")
                print(f"        Sink: {path.sink.api_name} @ 0x{path.sink.addr:x}")
                print(f"        Confidence: {path.confidence * 100:.0f}%")

                if path.steps:
                    print("        Path:")
                    for step in path.steps[-5:]:
                        print(f"          0x{step.addr:x}: {step.instruction}")

                trigger_input = None
                if self.symbolic_engine:
                    print("    [*] Attempting symbolic solving...")
                    trigger_input = self.symbolic_engine.solve_trigger_input(path)
                    if trigger_input:
                        print(f"    [+] Generated trigger input: {trigger_input[:32]}...")

                harness = self.fuzzing_module.generate_harness(path, name)
                seed = self.fuzzing_module.generate_seed(path, name)

                finding = VulnFinding(
                    vuln_type=path.sink.vuln_type,
                    severity=path.sink.severity,
                    source=path.source,
                    sink=path.sink,
                    taint_path=path,
                    trigger_input=trigger_input,
                    harness_code=harness,
                    cwe_id=DANGEROUS_SINKS.get(path.sink.api_name.encode() if isinstance(path.sink.api_name, str) else path.sink.api_name, {}).get('cwe')
                )
                self.findings.append(finding)

                if output_dir:
                    self._save_outputs(finding, name, output_dir, seed)

            # Phase 2.5: Deep Analysis for High Potential Vulnerabilities
            self._run_deep_analysis(name, addr, taint_paths)

        # Phase 3: 0day Discovery (New improved feature)
        if self.vuln_miner:
            print("\n" + "=" * 60)
            print("Zero-Day Vulnerability Discovery")
            print("=" * 60)

            # Extract potential 0day vulnerabilities from traditional analysis results
            all_taint_paths = []
            for finding in self.findings:
                if hasattr(finding, 'taint_path') and finding.taint_path:
                    all_taint_paths.append(finding.taint_path)

            # Use pattern learning engine to discover new vulnerability patterns
            zero_day_paths = self.vuln_miner.mine_zero_day_vulnerabilities(all_taint_paths)

            for path in zero_day_paths:
                print(f"\n    [0DAY] Potential zero-day found at 0x{path.sink.addr:x}")
                print(f"           Type: {path.sink.vuln_type.name}")
                print(f"           Novelty: {path.confidence * 100:.0f}%")

                # Create 0day finding
                zero_day_finding = VulnFinding(
                    vuln_type=path.sink.vuln_type,
                    severity=path.sink.severity,
                    source=path.source,
                    sink=path.sink,
                    taint_path=path,
                    trigger_input=None,
                    harness_code=None,
                    cwe_id="CWE-000"  # Unknown CWE identifies new vulnerability
                )

                # Mark as 0day candidate
                if not hasattr(zero_day_finding, 'notes'):
                    zero_day_finding.notes = []
                zero_day_finding.notes.append("Zero-Day Candidate")

                self.findings.append(zero_day_finding)

        # Phase 4: Pattern Generation and Bad Character Detection (New improved feature)
        print("\n" + "=" * 60)
        print("Pattern Generation and Bad Character Detection")
        print("=" * 60)

        # Pattern generation and offset calculation for buffer overflow vulnerabilities
        from ..exploit.payload import PatternGenerator, BadCharFinder

        for finding in self.findings:
            if finding.vuln_type == VulnType.BUFFER_OVERFLOW:
                print(f"\n    [+] Processing buffer overflow at 0x{finding.sink.addr:x}")

                # Use pattern generation for precise offset calculation if buffer overflow
                if finding.taint_path:
                    buffer_size = 256  # Default buffer size
                    # Estimate buffer size based on taint path analysis
                    total_size = buffer_size + 32  # Extra space for positioning
                    pattern = PatternGenerator.create(total_size)

                    print(f"        Generated pattern for offset calculation: {len(pattern)} bytes")

                    # Add offset calculation logic here if needed
                    # usually done after triggering the vulnerability, but pattern can be generated beforehand
                    finding.notes = (getattr(finding, 'notes', None) or [])
                    finding.notes.append(f"Pattern generated for offset calculation: {len(pattern)} bytes")

                    # Generate more precise pattern payload if symbolic execution engine is available
                    if self.symbolic_engine:
                        try:
                            # Use symbolic engine to generate trigger input
                            trigger_input = self.symbolic_engine.solve_trigger_input(finding.taint_path)
                            if trigger_input:
                                # Attempt offset calculation from trigger input
                                finding.trigger_input = trigger_input
                                print(f"        Generated trigger input: {len(trigger_input)} bytes")
                        except Exception as e:
                            print(f"        Symbolic solving failed: {e}")

        # Bad character analysis for all findings (if Speakeasy is configured)
        try:
            import speakeasy
            from speakeasy import Speakeasy
            print(f"\n    [+] Speakeasy available, performing bad character analysis")

            for finding in self.findings:
                if finding.vuln_type in (VulnType.BUFFER_OVERFLOW, VulnType.FORMAT_STRING):
                    print(f"        Analyzing bad characters for {finding.vuln_type.name} at 0x{finding.sink.addr:x}")

                    # Create bad character finder and run detection
                    finder = BadCharFinder()
                    result = finder.detect(
                        finding.sink.addr,
                        str(self.binary_path),
                        list(range(256)),
                        speakeasy_timeout=30
                    )

                    if result.success:
                        print(f"        Bad chars detected: {len(result.detected_bad_chars)}")
                        finding.notes = (getattr(finding, 'notes', None) or [])
                        finding.notes.append(f"Bad chars detected: {len(result.detected_bad_chars)}")
                        if result.detected_bad_chars:
                            finding.notes.append(f"Bad chars: {[hex(c) for c in result.detected_bad_chars[:10]]}")
                    else:
                        print(f"        Bad char detection failed: {result.error}")
        except ImportError as e:
            print(f"\n    [-] Speakeasy not available: {e}")
        except Exception as e:
            print(f"\n    [-] Bad character analysis failed: {type(e).__name__}: {e}")

        self._print_summary()
        return self.findings

    def _run_deep_analysis(self, func_name: str, func_addr: int, taint_paths: List[TaintPath]) -> None:
        """Run deep analysis (LuoDllHack 2.0 core logic)"""
        # 1. Virtual table and indirect call semantic recovery (using RizinCore)
        try:
            # Analyze indirect calls via RizinCore
            func = self.rz.analyze_function(func_addr)
            if func:
                for block in func.blocks:
                    for insn in block.instructions:
                        # Detect indirect call instructions
                        if insn.mnemonic in ('call', 'jmp') and insn.type.name == 'CALL':
                            # Check if indirect call (via register or memory)
                            if any(r in str(insn.operands) for r in ['rax', 'rbx', 'rcx', 'rdx', 'eax', 'ebx', 'ecx', 'edx', '[', 'qword', 'dword']):
                                print(f"    [*] Deep Analysis: Found indirect call @ 0x{insn.address:x}: {insn.mnemonic} {insn.operands}")
        except Exception:
            pass

        # 2. Apply Z3 optimized solving to high-value paths
        if self.advanced_symbolic and taint_paths:
            for path in taint_paths[:3]:  # Deep constraint analysis on top three critical paths
                print(f"    [*] Applying LuoDllHack 2.0 Z3 Optimizations to 0x{path.sink.addr:x}...")
                # _solve_constraints integrated with pruning and concretization optimizations
                complex_analysis = self.advanced_symbolic.analyze_complex_constraints(path)
                if complex_analysis['suggest_manual_analysis']:
                    print(f"    [!] Identified complex 0-day potential (Complexity Score: {complex_analysis['constraint_complexity_score']})")

    def _is_duplicate_finding(self, path: TaintPath) -> bool:
        """Check if finding is a duplicate of an existing one"""
        for existing in self.findings:
            if (existing.sink.addr == path.sink.addr and
                existing.sink.api_name == path.sink.api_name):
                return True
        return False

    def _generate_cross_function_seed(self, path: CrossFunctionPath) -> bytes:
        """Generate seed for cross-function vulnerability"""
        vuln_type = path.sink.vuln_type

        if vuln_type == VulnType.BUFFER_OVERFLOW:
            return b'A' * 2048
        elif vuln_type == VulnType.FORMAT_STRING:
            return b'%x' * 30 + b'%n'
        elif vuln_type == VulnType.COMMAND_INJECTION:
            return b'test & calc.exe'
        elif vuln_type == VulnType.PATH_TRAVERSAL:
            return b'..\\..\\..\\..\\..\\windows\\system32\\config\\sam'
        else:
            return b'AAAA' * 256

    def _save_outputs(self, finding: VulnFinding, export_name: str,
                      output_dir: Path, seed: bytes) -> None:
        """Removed - PoC/Harness generation functionality deleted"""
        pass

    def _print_summary(self) -> None:
        """Print analysis summary"""
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)

        if not self.findings:
            print("  No vulnerabilities found")
            return

        by_severity: Dict[str, List[VulnFinding]] = defaultdict(list)
        for f in self.findings:
            by_severity[f.severity].append(f)

        print(f"  Total: {len(self.findings)} vulnerability(ies)")
        if self.cross_function_findings:
            print(f"    Cross-function: {len(self.cross_function_findings)}")
            print(f"    Single-function: {len(self.findings) - len(self.cross_function_findings)}")

        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev in by_severity:
                print(f"    {sev}: {len(by_severity[sev])}")

        if self.cross_function_findings:
            print("\n  Cross-Function Vulnerabilities:")
            for f in self.cross_function_findings:
                print(f"    [{f.severity}] {f.vuln_type.name}")
                print(f"           Entry: {f.source.api_name}")
                print(f"           Sink: {f.sink.api_name} @ 0x{f.sink.addr:x}")
                if f.cwe_id:
                    print(f"           CWE: {f.cwe_id}")

        single_func_findings = [f for f in self.findings if f not in self.cross_function_findings]
        if single_func_findings:
            print("\n  Single-Function Vulnerabilities:")
            for f in single_func_findings:
                print(f"    [{f.severity}] {f.vuln_type.name}")
                print(f"           {f.source.api_name} -> {f.sink.api_name}")
                if f.cwe_id:
                    print(f"           CWE: {f.cwe_id}")
                if f.trigger_input:
                    print(f"           PoC: Available ({len(f.trigger_input)} bytes)")

    def analyze_with_confidence(self, exports: Dict[str, int],
                                ai_report: Optional[Dict] = None,
                                output_dir: Optional[Path] = None,
                                enable_cross_function: bool = True,
                                top_n: int = 20) -> List[ScoredFinding]:
        """
        Analysis with confidence scoring (Recommended)
        """
        self.analyze(exports, output_dir, enable_cross_function)

        self.scored_findings = self.confidence_scorer.aggregate_and_rank(
            self.taint_engine,
            ai_report
        )

        self.confidence_scorer.print_ranked_report(top_n)
        return self.scored_findings

    def get_high_confidence_findings(self, threshold: float = 0.70) -> List[ScoredFinding]:
        """Get high confidence findings"""
        return [f for f in self.scored_findings if f.confidence.total_score >= threshold]

    def export_scored_report(self, output_path: Path = None) -> None:
        """
        Export confidence scoring report

        Args:
            output_path: Output path (defaults to config.output_dir/report.json if None)
        """
        # Default report output based on configuration
        if output_path is None and self.config:
            if self.config.output_report:
                output_path = self.config.output_dir / "vuln_report.json"
            else:
                print("[*] Report output disabled in config")
                return

        if output_path is None:
            output_path = Path("vuln_report.json")

        report = {
            "binary": str(self.binary_path),
            "total_findings": len(self.scored_findings),
            "findings": []
        }

        for finding in self.scored_findings:
            entry = {
                "rank": self.scored_findings.index(finding) + 1,
                "confidence_score": finding.confidence.total_score,
                "confidence_level": finding.confidence.level,
                "vuln_type": finding.vuln_type.name,
                "severity": finding.severity,
                "location": f"0x{finding.location:x}",
                "function": finding.func_name,
                "finding_type": finding.finding_type,
                "sources": finding.sources,
                "poc_path": finding.poc_path,
                "harness_path": finding.harness_path,
                "factors": finding.confidence.explanation
            }
            report["findings"].append(entry)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"[+] Exported confidence report to: {output_path}")

    def analyze_bidirectional(self, exports: Dict[str, int],
                               api_key: Optional[str] = None,
                               output_dir: Optional[Path] = None,
                               enable_cross_function: bool = True,
                               top_n: int = 20,
                               max_ai_steps: int = 30) -> List[ScoredFinding]:
        """
        Bidirectional cross-validation analysis (Highest accuracy)
        """
        print("\n" + "=" * 70)
        print(" BIDIRECTIONAL CROSS-VALIDATION ANALYSIS")
        print("=" * 70)

        # Phase 1: Algorithmic analysis
        print("\n[Phase 1] Running algorithmic analysis...")
        self.analyze(exports, output_dir, enable_cross_function)

        algo_summary = {
            "taint_paths": len(self.taint_engine.taint_paths),
            "memory_vulns": len(self.taint_engine.memory_findings),
            "integer_overflows": len(self.taint_engine.integer_overflow_findings),
            "total_findings": len(self.findings)
        }
        print(f"    Algorithm found: {algo_summary['total_findings']} potential vulnerabilities")

        # Phase 2: AI analysis
        ai_report = None
        try:
            from luodllhack.ai.agent import VulnHuntingAgent, ToolRegistry

            # Create Agent (Selects backend automatically)
            tool_registry = ToolRegistry(
                self.binary_path, self.taint_engine,
                signature_file=self.signature_file
            )
            tool_registry.set_algorithm_findings(self.taint_engine, self.cross_function_findings)

            agent = VulnHuntingAgent(
                binary_path=self.binary_path,
                api_key=api_key,
                tool_registry=tool_registry,
                config=self.config,
                signature_file=self.signature_file
            )

            if agent.is_ready:
                print(f"\n[Phase 2] Running AI analysis with {agent.backend_name} backend...")

                dangerous_apis = []
                for addr, name in self.taint_engine.import_map.items():
                    if name in DANGEROUS_SINKS:
                        dangerous_apis.append(name.decode() if isinstance(name, bytes) else name)

                # Convert Phase 1 findings to transmittable format
                phase1_findings = []
                for finding in self.findings:
                    # Resolve function name: Prioritize finding.func_name, then taint_path, then sink.api_name
                    func_name = None
                    if hasattr(finding, 'func_name') and finding.func_name:
                        func_name = finding.func_name
                    elif hasattr(finding, 'taint_path') and finding.taint_path:
                        func_name = getattr(finding.taint_path, 'func_name', None)
                    elif hasattr(finding, 'sink') and finding.sink:
                        # sink.api_name may be vulnerability description, not function name; use as backup
                        api_name = getattr(finding.sink, 'api_name', None)
                        # Use only if it looks like a function name
                        if api_name and not api_name.startswith(('UNINIT_', 'BUFFER_', 'FORMAT_')):
                            func_name = api_name

                    phase1_findings.append({
                        "vuln_type": finding.vuln_type.name if hasattr(finding.vuln_type, 'name') else str(finding.vuln_type),
                        "address": finding.sink.addr if hasattr(finding, 'sink') and finding.sink else None,
                        "function": func_name,
                        "severity": "High" if finding.vuln_type.name in ("BUFFER_OVERFLOW", "USE_AFTER_FREE", "DOUBLE_FREE") else "Medium",
                        "confidence": getattr(finding, 'confidence', 0.5),
                        "source": "algorithm",
                        "poc_path": getattr(finding, 'poc_path', None),
                        "harness_path": getattr(finding, 'harness_path', None),
                    })

                metadata = {
                    "binary_name": self.binary_path.name,
                    "arch": self.taint_engine.arch,
                    "algorithm_findings": algo_summary,
                    "algorithm_findings_detail": phase1_findings,  # Actual list of findings
                    "dangerous_imports": dangerous_apis[:20],
                    "total_exports": len(exports)
                }

                ai_report = agent.hunt(metadata, exports=exports, max_steps=max_ai_steps)

                # Store agent and orchestrator references for Phase 3 reports
                self.agent = agent
                self.orchestrator = getattr(agent, 'orchestrator', None)

                # Attempt to regenerate scored_findings to include AI review results if study complete and shared state exists
                final_shared_state = getattr(agent, 'final_shared_state', None)
                if final_shared_state:
                    try:
                        final_findings = final_shared_state.get_all_findings()

                        # Convert final findings to ScoredFinding format
                        updated_findings = []
                        for finding in final_findings:
                            # Check for false positive (multiple checks for robustness)
                            is_false_positive = getattr(finding, 'is_false_positive', False) or \
                                              finding.metadata.get('is_false_positive', False) or \
                                              (finding.status == "false_positive")
                            review_reasons = getattr(finding, 'false_positive_reason', None) or \
                                            finding.metadata.get('review_reasons', None)

                            # Determine vulnerability type
                            vuln_type_name = finding.vuln_type
                            vuln_type = VulnType.UNINITIALIZED_MEMORY  # Default value
                            try:
                                vuln_type = VulnType[vuln_type_name.upper()] if isinstance(vuln_type_name, str) else VulnType(vuln_type_name)
                            except (KeyError, ValueError):
                                pass  # Keep default

                            # Parse address
                            location = 0
                            if finding.address:
                                if isinstance(finding.address, str) and finding.address.startswith('0x'):
                                    location = int(finding.address, 16)
                                else:
                                    location = int(finding.address)

                            # Create confidence object
                            # Very low confidence if false positive; otherwise use discovery confidence
                            confidence_score = 0.01 if is_false_positive else (finding.confidence if finding.confidence else 0.5)
                            conf = ConfidenceScore(total_score=confidence_score)
                            conf.update_level()  # Ensure confidence level is set correctly

                            # Attempt to associate original finding for PoC path
                            matched_original = None
                            for f in self.findings:
                                if f.sink and f.sink.addr == location:
                                    matched_original = f
                                    break

                            # Create ScoredFinding
                            scored_finding = ScoredFinding(
                                finding_type="AI-Updated",
                                vuln_type=vuln_type,
                                severity=finding.severity or "Medium",
                                location=location,
                                func_name=finding.function or "unknown",
                                confidence=conf,
                                raw_finding=finding,
                                sources=[finding.discovered_by] if finding.discovered_by else ["ai_agent"],
                                ai_analysis=finding.evidence[0] if finding.evidence else "",
                                is_false_positive=is_false_positive,
                                review_reasons=review_reasons,
                                original_finding_id=finding.finding_id,  # Use original Finding ID
                                poc_path=getattr(finding, 'poc_path', None) or (matched_original.poc_path if matched_original else None),
                                harness_path=getattr(finding, 'harness_path', None) or (matched_original.harness_path if matched_original else None)
                            )

                            updated_findings.append(scored_finding)

                        # Replace original scored_findings if updated findings found
                        if updated_findings:
                            self.scored_findings = updated_findings
                            # Sync update ConfidenceScorer scored_findings
                            self.confidence_scorer.scored_findings = updated_findings
                            self._findings_updated_with_ai_review = True  # Mark updated with AI review results
                            print(f"    Updated {len(updated_findings)} findings with AI review results")
                    except Exception as e:
                        print(f"    Warning: Could not update findings with AI review results: {e}")
            else:
                print("\n[Phase 2] Skipped: No LLM backend available (check API key and dependencies)")

        except (ImportError, Exception) as e:
            print(f"\n[Phase 2] AI analysis failed: {e}")

        # Phase 2.5: 0day Discovery and Hybrid Validation (New improvement)
        print("\n[Phase 2.5] Zero-Day Discovery and Hybrid Validation...")

        # Diagnostic: Show available analysis engines
        engines_available = []
        if self.hybrid_engine:
            engines_available.append("hybrid_engine")
        if self.advanced_symbolic:
            engines_available.append("advanced_symbolic")
        if self.neuro_symbolic_engine:
            engines_available.append("neuro_symbolic")

        if not engines_available:
            print("    [SKIP] No 0day analysis engines available")
            print("    Hint: Check if angr/z3 dependencies are installed correctly")
        else:
            print(f"    Available engines: {', '.join(engines_available)}")

        if self.hybrid_engine:
            try:
                # Extract high-priority paths for further validation
                taint_paths_for_hybrid = []
                for finding in self.findings:
                    if hasattr(finding, 'taint_path') and finding.taint_path:
                        taint_paths_for_hybrid.append(finding.taint_path)

                print(f"    Input paths for hybrid analysis: {len(taint_paths_for_hybrid)}")

                if taint_paths_for_hybrid:
                    # Deep validation using hybrid analysis engine
                    confirmed_paths = self.hybrid_engine.hybrid_analysis(taint_paths_for_hybrid)

                    print(f"    Hybrid analysis confirmed {len(confirmed_paths)} paths")

                    # Display symbolic execution stats (if available)
                    if hasattr(self.hybrid_engine, 'stats'):
                        stats = self.hybrid_engine.stats
                        print(f"    Symbolic execution stats:")
                        print(f"      - Explored paths: {stats.get('explored_paths', 0)}")
                        print(f"      - Solved paths: {stats.get('solved_paths', 0)}")
                        print(f"      - Pruned paths: {stats.get('pruned_paths', 0)}")
                        print(f"      - Constraint failures: {stats.get('constraint_failures', 0)}")

                    # Create new ScoredFindings for confirmed paths
                    for path in confirmed_paths:
                        # Increase confidence for confirmed paths
                        path.confidence = min(0.95, path.confidence + 0.2)
                else:
                    print("    No taint paths available for hybrid analysis")

            except Exception as e:
                print(f"    Hybrid analysis failed: {e}")
                import traceback
                if self.config and getattr(self.config, 'debug', False):
                    traceback.print_exc()

        # Phase 3: Confidence Score Aggregation
        print("\n[Phase 3] Aggregating and scoring findings...")

        ai_report_dict = None
        if ai_report:
            ai_report_dict = {
                "vulnerabilities": [
                    {
                        "type": v.get("type", "UNKNOWN"),
                        "address": v.get("address", 0),
                        "severity": v.get("severity", "Medium"),
                        "function": v.get("function", ""),
                        "description": v.get("description", "")
                    }
                    for v in (ai_report.vulnerabilities if hasattr(ai_report, 'vulnerabilities')
                              else ai_report.get('vulnerabilities', []))
                ]
            }

        # Aggregation and scoring done only if no AI-updated findings exist
        if not hasattr(self, '_findings_updated_with_ai_review'):
            self.scored_findings = self.confidence_scorer.aggregate_and_rank(
                self.taint_engine,
                ai_report_dict,
                extra_findings=self.findings
            )

        # Sync AI review results to ScoredFinding objects if orchestrator exists
        if hasattr(self, 'agent') and self.agent:
            print(f"    [DEBUG] Starting AI review sync: {len(self.scored_findings)} scored findings to update")
            try:
                # Prioritize final shared state (if available), then orchestrator's shared state
                shared_state = getattr(self.agent, 'final_shared_state', None)
                if shared_state is None and hasattr(self, 'orchestrator') and self.orchestrator:
                    shared_state = self.orchestrator._shared_state
                elif shared_state is None:
                    print(f"    [DEBUG] No shared state available for sync")
                    pass

                if shared_state:
                    # Get latest finding information from shared state
                    shared_findings = shared_state.get_all_findings()
                    print(f"    [DEBUG] Retrieved {len(shared_findings)} findings from shared state")

                    # Create mapping for quick lookup in shared state
                    shared_finding_map = {}
                    for shared_finding in shared_findings:
                        # Primary matching key: Finding ID
                        finding_id_key = shared_finding.finding_id
                        shared_finding_map[finding_id_key] = shared_finding

                        # Fallback keys: Address and function name matching
                        addr_str = str(shared_finding.address) if shared_finding.address else ""
                        addr_int = 0
                        if shared_finding.address:
                            try:
                                # Handle both hex and decimal strings
                                if isinstance(shared_finding.address, str) and shared_finding.address.startswith('0x'):
                                    addr_int = int(shared_finding.address, 16)
                                else:
                                    addr_int = int(shared_finding.address)
                            except ValueError:
                                pass

                        func_name = shared_finding.function or ""

                        # Multi-format keys to improve matching success
                        key1 = f"{addr_str}:{func_name}"
                        key2 = f"{addr_int}:{func_name}"
                        key3 = f"{addr_str}:"
                        key4 = f"{addr_int}:"

                        shared_finding_map[key1] = shared_finding
                        shared_finding_map[key2] = shared_finding
                        shared_finding_map[key3] = shared_finding
                        shared_finding_map[key4] = shared_finding

                    # Update review status of ScoredFinding objects
                    matched_count = 0
                    fp_count = 0
                    for scored_finding in self.scored_findings:
                        # Attempt matching by original finding ID first
                        matched_finding = None
                        if scored_finding.original_finding_id:
                            matched_finding = shared_finding_map.get(scored_finding.original_finding_id)

                        # If no ID match, attempt address and function name matching
                        if not matched_finding:
                            location_str_key = f"{scored_finding.location}:{scored_finding.func_name}"
                            location_hex_key = f"0x{scored_finding.location:x}:{scored_finding.func_name}"
                            location_plain_addr = f"{scored_finding.location}:"
                            location_hex_addr = f"0x{scored_finding.location:x}:"

                            matched_finding = (shared_finding_map.get(location_str_key) or
                                             shared_finding_map.get(location_hex_key) or
                                             shared_finding_map.get(location_plain_addr) or
                                             shared_finding_map.get(location_hex_addr))

                        if matched_finding:
                            matched_count += 1
                            # Check for false positive (multiple checks for robustness)
                            is_fp = getattr(matched_finding, 'is_false_positive', False) or \
                                   matched_finding.metadata.get('is_false_positive', False) or \
                                   (matched_finding.status == "false_positive")
                            review_reasons = getattr(matched_finding, 'false_positive_reason', None) or \
                                            matched_finding.metadata.get('review_reasons')

                            # Update ScoredFinding object
                            scored_finding.is_false_positive = is_fp
                            scored_finding.review_reasons = review_reasons

                            # Propagate PoC path
                            if getattr(matched_finding, 'poc_path', None):
                                scored_finding.poc_path = matched_finding.poc_path
                            if getattr(matched_finding, 'harness_path', None):
                                scored_finding.harness_path = matched_finding.harness_path

                            # Propagate confidence and factors (if validated)
                            if matched_finding.status in ["verified", "validated", "exploited"] or \
                               (not is_fp and matched_finding.confidence > 0.7):
                                if hasattr(scored_finding, 'confidence'):
                                    # Boost confidence
                                    scored_finding.confidence.total_score = max(scored_finding.confidence.total_score, matched_finding.confidence)
                                    scored_finding.confidence.factors[ConfidenceFactor.AI_CONFIRMED] = True
                                    scored_finding.confidence.update_level()

                            # If false positive, mark but keep original confidence for reports
                            if is_fp:
                                fp_count += 1
                                if hasattr(scored_finding, 'confidence'):
                                    # Save original confidence for report display
                                    scored_finding.original_confidence = scored_finding.confidence.total_score
                                    # Moderate confidence reduction instead of setting to near-zero (multiply by 0.3)
                                    # Keeps it in the report but lower in ranking
                                    scored_finding.confidence.total_score *= 0.3
                                    scored_finding.confidence.update_level()
                                print(f"    [DEBUG] Marked finding at 0x{scored_finding.location:x} as false positive (confidence: {scored_finding.original_confidence:.2f} -> {scored_finding.confidence.total_score:.2f})")

                    print(f"    [DEBUG] Sync completed: {matched_count}/{len(self.scored_findings)} findings matched, {fp_count} marked as false positives")
                else:
                    print(f"    [DEBUG] No shared state to sync from")

            except Exception as e:
                print(f"    Warning: Could not sync AI review results: {e}")
                import traceback
                traceback.print_exc()

        # Print header for integrated report (using scored_findings as unified source)
        self._print_unified_report_header()

        self.confidence_scorer.print_ranked_report(top_n)

        cross_validated = sum(1 for f in self.scored_findings
                              if f.confidence.factors.get(ConfidenceFactor.AI_CONFIRMED, False))

        # Statistics for 0day discovery
        zero_day_count = sum(1 for f in self.findings
                           if hasattr(f, 'notes') and "Zero-Day Candidate" in (getattr(f, 'notes', []) or []))

        print(f"\n[Summary]")
        print(f"    Total findings: {len(self.scored_findings)}")
        print(f"    Cross-validated (AI + Algorithm): {cross_validated}")
        print(f"    Zero-day candidates: {zero_day_count}")
        print(f"    High confidence (>=70%): {len(self.get_high_confidence_findings(0.70))}")

        return self.scored_findings

    def _print_unified_report_header(self) -> None:
        """
        Print unified report header, taking scored_findings as the authoritative source.
        Resolves inconsistencies between initial AI Agent reports and final confidence reports.
        """
        print("\n" + "=" * 60)
        print("Unified Vulnerability Report (After AI Review)")
        print("=" * 60)

        # Segregate valid findings and false positives
        valid_findings = [f for f in self.scored_findings if not getattr(f, 'is_false_positive', False)]
        false_positives = [f for f in self.scored_findings if getattr(f, 'is_false_positive', False)]

        # Determine risk level based on valid findings
        risk_level = "None"
        if valid_findings:
            severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
            max_severity = max(
                (getattr(f, 'severity', 'Low') for f in valid_findings),
                key=lambda s: severity_order.get(s, 0),
                default='None'
            )
            risk_level = max_severity

        # Confidence distribution statistics
        high_conf = len([f for f in valid_findings if f.confidence.total_score >= 0.70])
        medium_conf = len([f for f in valid_findings if 0.40 <= f.confidence.total_score < 0.70])
        low_conf = len([f for f in valid_findings if f.confidence.total_score < 0.40])

        print(f"\nRisk Level: {risk_level}")
        print(f"Valid Findings: {len(valid_findings)}")
        print(f"False Positives (filtered): {len(false_positives)}")
        print(f"\nConfidence Distribution:")
        print(f"    High (>=70%): {high_conf}")
        print(f"    Medium (40-70%): {medium_conf}")
        print(f"    Low (<40%): {low_conf}")
