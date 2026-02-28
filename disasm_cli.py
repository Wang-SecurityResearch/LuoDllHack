#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LuoDllHack - Automated Vulnerability Mining & Exploitation Framework v5.2.0

Unified command-line entry point, integrating three core capabilities:
1. Vulnerability Hunting - hunt (ReAct Agent Network architecture)
2. Vulnerability Verification - verify (Speakeasy emulator)
3. DLL Hijacking - proxy/compile

v5.2 Architecture:
- ReAct + Agent Network: Decentralized multi-agent collaboration
- Agent Autonomous Reasoning: Think-Act-Observe cycle
- MCP-style Tools: Standardized tool calling interface

Usage:
    python disasm_cli.py target.dll --hunt           # Automated vulnerability hunting
    python disasm_cli.py target.dll --hunt --focus FUNC  # Focused analysis
    python disasm_cli.py target.dll --verify 0x1234 DOUBLE_FREE  # Verify vulnerability
    python disasm_cli.py target.dll --checksec       # Security feature check
    python disasm_cli.py target.dll --proxy          # Generate proxy DLL
    python disasm_cli.py --info                      # Show capability information
"""

import sys
import os
import argparse
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

# 设置 Rizin 路径 (如果未在 PATH 中)
def _setup_rizin_path():
    """检查并设置 Rizin 路径"""
    # 检查是否已有 rizin
    import shutil
    if shutil.which("rizin"):
        return

    # 尝试常见位置
    common_paths = [
        os.environ.get("RIZIN_PATH", ""),
        r"D:\Cutter-v2.4.1-Windows-x86_64",
        r"C:\Program Files\Cutter",
        r"C:\Program Files\rizin",
        os.path.expanduser("~/.local/bin"),
        "/usr/local/bin",
    ]

    for path in common_paths:
        if path and os.path.isdir(path):
            rizin_exe = os.path.join(path, "rizin.exe" if sys.platform == "win32" else "rizin")
            if os.path.isfile(rizin_exe):
                os.environ["PATH"] = path + os.pathsep + os.environ.get("PATH", "")
                return

_setup_rizin_path()


def create_parser():
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="luodllhack",
        description="LuoDllHack - Automated Vulnerability Mining & Exploitation Framework v5.2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s target.dll --hunt              # Automated vulnerability hunting (ReAct Agent Network)
  %(prog)s target.dll --hunt --hunt-no-ai # Algorithm analysis only
  %(prog)s target.dll --hunt --focus FunctionName  # Focused analysis
  %(prog)s target.dll --hunt --signature-file functions.json  # Use external signatures
  %(prog)s target.dll --verify 0x18001000 DOUBLE_FREE  # Verify vulnerability
  %(prog)s target.dll --checksec          # Security feature check
  %(prog)s target.dll --ai-func 0x18001000  # AI analysis of function
  %(prog)s target.dll --proxy             # Generate proxy DLL
  %(prog)s --info                         # Show capability information

ReAct Agent Network (v5.2):
  Decentralized Agent autonomous collaboration: Analyzer / Verifier / Exploiter / Validator / Critic
  Each Agent uses Think-Act-Observe cycle for independent reasoning

Vulnerability Types (--verify): All 21 types supported
  Memory: BUFFER_OVERFLOW, HEAP_OVERFLOW, DOUBLE_FREE, USE_AFTER_FREE,
         NULL_DEREFERENCE, OUT_OF_BOUNDS_READ, OUT_OF_BOUNDS_WRITE,
         UNINITIALIZED_MEMORY, TYPE_CONFUSION, CONTROL_FLOW_HIJACK
  Integer: INTEGER_OVERFLOW, INTEGER_UNDERFLOW
  Injection: FORMAT_STRING, COMMAND_INJECTION, PATH_TRAVERSAL
  Info: INFO_DISCLOSURE, MEMORY_LEAK
  Other: RACE_CONDITION, STACK_EXHAUSTION, DESERIALIZATION, PRIVILEGE_ESCALATION
"""
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target file path (DLL/EXE)"
    )

    # Vulnerability Hunting
    hunt = parser.add_argument_group("Vulnerability Hunting")
    hunt.add_argument(
        "--hunt",
        action="store_true",
        help="Automated vulnerability hunting (Algorithm + AI analysis)"
    )
    hunt.add_argument(
        "--hunt-max-steps",
        type=int,
        default=30,
        metavar="N",
        help="AI maximum reasoning steps (Default: 30)"
    )
    hunt.add_argument(
        "--hunt-focus",
        metavar="FUNC",
        help="Focus analysis on a specific exported function"
    )
    hunt.add_argument(
        "--hunt-output",
        choices=["console", "json", "html"],
        default="console",
        help="Output format (Default: console)"
    )
    hunt.add_argument(
        "--hunt-no-ai",
        action="store_true",
        help="Run algorithm analysis only, skip AI Agents"
    )
    hunt.add_argument(
        "--signature-file",
        metavar="FILE",
        help="Path to external signature file (Cutter/rizin's functions.json)"
    )

    # Pattern Generation and Bad Character Detection
    pattern_badchar = parser.add_argument_group("Pattern Generation & Bad Character Detection")
    pattern_badchar.add_argument(
        "--generate-pattern",
        action="store_true",
        help="Generate pattern payload for precise EIP control location"
    )
    pattern_badchar.add_argument(
        "--pattern-length",
        type=int,
        default=2048,
        metavar="N",
        help="Pattern payload length (Default: 2048)"
    )
    pattern_badchar.add_argument(
        "--detect-bad-chars",
        action="store_true",
        help="Detect bad characters in target DLL"
    )
    pattern_badchar.add_argument(
        "--bad-char-range",
        type=str,
        default="0-255",
        help="Bad character detection range (Default: 0-255)"
    )

    # Vulnerability Verification
    verify = parser.add_argument_group("Vulnerability Verification")
    verify.add_argument(
        "--verify",
        nargs=2,
        metavar=("ADDR", "TYPE"),
        help="Verify vulnerability at specified address (requires Speakeasy)"
    )
    verify.add_argument(
        "--verify-func",
        metavar="NAME",
        help="Specify function name (used with --verify)"
    )
    verify.add_argument(
        "--verify-trigger",
        action="store_true",
        help="Generate trigger test case (used with --verify)"
    )

    # Security Analysis
    security = parser.add_argument_group("Security Analysis")
    security.add_argument(
        "--checksec",
        action="store_true",
        help="Check binary security features (ASLR/DEP/CFG, etc.)"
    )

    # AI Analysis
    ai = parser.add_argument_group("AI Analysis")
    ai.add_argument(
        "--ai-func",
        metavar="ADDR",
        help="Analyze function at specified address using AI"
    )
    ai.add_argument(
        "--api-key",
        metavar="KEY",
        help="Gemini API Key (or set GEMINI_API_KEY environment variable)"
    )

    # DLL Proxy
    proxy = parser.add_argument_group("DLL Proxy")
    proxy.add_argument(
        "--proxy",
        action="store_true",
        help="Generate proxy DLL"
    )
    proxy.add_argument(
        "--compile",
        action="store_true",
        help="Compile proxy DLL"
    )

    # DLL Hijacking Scan
    hijack = parser.add_argument_group("DLL Hijacking Scan")
    hijack.add_argument(
        "--hijack-scan",
        action="store_true",
        help="Scan for DLL hijacking vulnerabilities"
    )
    hijack.add_argument(
        "--hijack-recursive",
        action="store_true",
        help="Recursively scan subdirectories"
    )
    hijack.add_argument(
        "--hijack-skip-system",
        action="store_true",
        default=True,
        help="Skip system protected directories (Default: Yes)"
    )
    hijack.add_argument(
        "--hijack-include-system",
        action="store_true",
        help="Include system directories (overrides --hijack-skip-system)"
    )
    hijack.add_argument(
        "--hijack-risk",
        choices=["all", "critical", "high", "medium", "low"],
        default="all",
        help="Filter risk level (Default: all)"
    )
    hijack.add_argument(
        "--hijack-csv",
        metavar="FILE",
        help="Export CSV report"
    )
    hijack.add_argument(
        "--hijack-threads",
        type=int,
        default=4,
        metavar="N",
        help="Parallel threads (Default: 4)"
    )
    hijack.add_argument(
        "--hijack-gen",
        action="store_true",
        help="Automatically generate hijacking PoC (used with --hijack-scan)"
    )
    hijack.add_argument(
        "--hijack-payload",
        choices=["messagebox", "calc", "cmd", "shellcode", "none"],
        default="messagebox",
        help="PoC payload type (Default: messagebox)"
    )
    hijack.add_argument(
        "--hijack-ai",
        action="store_true",
        help="AI analysis of trigger scenarios (requires --api-key)"
    )
    hijack.add_argument(
        "--hijack-max",
        type=int,
        default=5,
        metavar="N",
        help="Maximum generation count (Default: 5)"
    )

    # Output
    output = parser.add_argument_group("Output Options")
    output.add_argument(
        "-o", "--output",
        metavar="DIR",
        type=Path,
        default=Path.cwd(),
        help="Output directory (Default: current directory)"
    )
    output.add_argument(
        "--report",
        metavar="FILE",
        type=Path,
        help="Export report to file"
    )

    # Config
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--config",
        metavar="FILE",
        type=Path,
        help="Load YAML configuration file"
    )

    # Other
    other = parser.add_argument_group("Other")
    other.add_argument(
        "--info",
        action="store_true",
        help="Show LuoDllHack capability information"
    )
    other.add_argument(
        "-v", "--version",
        action="store_true",
        help="Show version information"
    )

    return parser


def show_info():
    """显示能力信息"""
    try:
        import luodllhack
        luodllhack.print_banner()

        caps = luodllhack.get_capabilities()

        print("\n[*] 能力状态:")
        print("\n  漏洞挖掘 (analysis):")
        for name, available in caps['analysis'].items():
            status = "OK" if available else "N/A"
            print(f"    {name}: {status}")

        # 显示增强分析模块状态
        print("\n  增强分析 (enhanced):")
        try:
            from luodllhack.analysis import HAVE_ENHANCED
            if HAVE_ENHANCED:
                print("    边界检查检测: OK")
                print("    清洗函数识别: OK")
                print("    间接调用追踪: OK")
                print("    回调函数分析: OK")
                print("    约束收集: OK")
            else:
                print("    状态: N/A")
        except ImportError:
            print("    状态: N/A")

        # [新增] 显示0day发现能力状态
        print("\n  0day发现能力 (zeroday):")
        for name, available in caps['zeroday'].items():
            status = "OK" if available else "N/A"
            print(f"    {name}: {status}")

        print("\n  漏洞验证 (verify):")
        for name, available in caps['verify'].items():
            status = "OK" if available else "N/A"
            print(f"    {name}: {status}")

        print("\n  DLL劫持 (dll_hijack):")
        for name, available in caps['dll_hijack'].items():
            status = "OK" if available else "N/A"
            print(f"    {name}: {status}")

        print("\n  AI分析 (ai):")
        for name, available in caps['ai'].items():
            status = "OK" if available else "N/A"
            print(f"    {name}: {status}")

        # [v5.2] 显示 Agent Network 能力
        print("\n  ReAct Agent Network (v5.2):")
        try:
            from luodllhack.ai.agents import (
                HAVE_NETWORK_AGENT,
                HAVE_MULTI_AGENT,
                NetworkRunner,
                NetworkAgent,
                AgentRegistry,
                MessageBus,
            )
            print(f"    框架可用: {'OK' if HAVE_NETWORK_AGENT else 'N/A'}")
            print(f"    NetworkRunner: {'OK' if NetworkRunner else 'N/A'}")
            print(f"    NetworkAgent: {'OK' if NetworkAgent else 'N/A'}")
            print(f"    AgentRegistry: {'OK' if AgentRegistry else 'N/A'}")
            print(f"    MessageBus: {'OK' if MessageBus else 'N/A'}")

            # 显示Agent状态
            try:
                from luodllhack.ai.agents import (
                    AnalyzerAgent,
                    ExploiterAgent,
                    CriticAgent,
                    ValidationAgent,
                )
                print("    专业Agent:")
                agent_info = [
                    ('AnalyzerAgent', AnalyzerAgent, '分析'),
                    ('ExploiterAgent', ExploiterAgent, '利用'),
                    ('CriticAgent', CriticAgent, '质检'),
                    ('ValidationAgent', ValidationAgent, '校验'),
                ]
                for name, cls, desc in agent_info:
                    status = "OK" if cls else "N/A"
                    print(f"      {name}({desc}): {status}")
            except ImportError:
                print("    专业Agent: 部分不可用")

            # 显示后端支持
            print("    LLM后端:")
            try:
                from luodllhack.ai.agents import (
                    GeminiBackend,
                    OpenAIBackend,
                    OllamaBackend,
                    AnthropicBackend,
                )
                backends = [
                    ('Gemini', GeminiBackend),
                    ('OpenAI', OpenAIBackend),
                    ('Ollama', OllamaBackend),
                    ('Anthropic', AnthropicBackend),
                ]
                for name, cls in backends:
                    status = "OK" if cls else "N/A"
                    print(f"      {name}: {status}")
            except ImportError:
                print("      状态: 部分不可用")

            # 显示工具适配器
            print("    MCP工具适配器:")
            try:
                from luodllhack.ai.tools.adapters import RizinTools, TaintTools
                print(f"      RizinTools: {'OK' if RizinTools else 'N/A'}")
                print(f"      TaintTools: {'OK' if TaintTools else 'N/A'}")
            except ImportError:
                print("      状态: 不可用")

        except ImportError as e:
            print(f"    状态: N/A ({e})")

    except ImportError as e:
        print(f"[-] 无法加载 luodllhack 模块: {e}")


def run_hunt(target_path: Path, output_dir: Path, api_key: str = None,
             max_steps: int = 30, focus_func: str = None,
             output_format: str = "console", no_ai: bool = False,
             config = None, generate_pattern: bool = False,
             pattern_length: int = 2048, detect_bad_chars: bool = False,
             bad_char_range: str = "0-255", signature_file: str = None):
    """Run automated vulnerability hunting (ReAct Agent Network)"""
    import time
    start_time = time.time()

    try:
        print(f"\n{'='*60}")
        print(f"  LuoDllHack Vulnerability Hunting v5.2 (ReAct Agent Network)")
        print(f"{'='*60}")
        print(f"[*] Target: {target_path}")
        print(f"[*] Mode: {'Algorithm Analysis' if no_ai else 'ReAct Agent Network'}")
        print(f"[*] Output Directory: {output_dir}")
        if not no_ai:
            print(f"[*] Max Reasoning Steps: {max_steps}")
        if focus_func:
            print(f"[*] Focus Function: {focus_func}")

        if no_ai:
            # Algorithm Analysis Mode - use VulnAnalyzer
            from luodllhack.analysis import VulnAnalyzer

            print("\n[Phase 1/3] Initializing analysis engine...")
            sig_file = Path(signature_file) if signature_file else None
            if sig_file:
                print(f"[*] Signature File: {sig_file}")
            analyzer = VulnAnalyzer(target_path, config=config, signature_file=sig_file)

            # Parse exported functions
            print("[Phase 2/3] Parsing exported functions...")
            exports = {}
            for exp in analyzer.rz.get_exports().values():
                if exp.name:
                    exports[exp.name] = exp.address

            if not exports:
                print("[-] No exported functions found")
                return

            # Filter focus function
            if focus_func:
                if focus_func in exports:
                    exports = {focus_func: exports[focus_func]}
                    print(f"[*] Focused on function: {focus_func}")
                else:
                    print(f"[-] Function not found: {focus_func}")
                    print(f"[*] Available functions: {', '.join(list(exports.keys())[:10])}...")
                    return

            print(f"[*] Found {len(exports)} exported functions")

            # Run algorithm analysis
            print(f"\n[Phase 3/3] Executing algorithm analysis...")
            findings = analyzer.analyze_bidirectional(
                exports=exports,
                api_key=None,
                output_dir=output_dir,
                enable_cross_function=True,
                max_ai_steps=0
            )

            elapsed = time.time() - start_time
            _print_hunt_results(findings, elapsed, target_path, output_dir, output_format)

        else:
            # ReAct Agent Network Mode
            from luodllhack.ai.agents import NetworkRunner, NetworkConfig
            from luodllhack.core import RizinCore

            print("\n[Phase 1/3] Initializing Agent Network...")

            # Create configuration
            network_config = NetworkConfig()
            if config:
                network_config = NetworkConfig.from_luodllhack_config(config)
            network_config.max_react_iterations = max_steps
            if api_key:
                network_config.llm_api_key = api_key

            # Create and start NetworkRunner
            runner = NetworkRunner(target_path, network_config)

            # Parse exported functions
            print("[Phase 2/3] Parsing exported functions...")
            rz = RizinCore(str(target_path))
            exports = {}
            for exp in rz.get_exports().values():
                if exp.name:
                    exports[exp.name] = exp.address

            if not exports:
                print("[-] No exported functions found")
                return

            # Filter focus function
            if focus_func:
                if focus_func in exports:
                    exports = {focus_func: exports[focus_func]}
                    print(f"[*] Focused on function: {focus_func}")
                else:
                    print(f"[-] Function not found: {focus_func}")
                    print(f"[*] Available functions: {', '.join(list(exports.keys())[:10])}...")
                    return

            print(f"[*] Found {len(exports)} exported functions")

            # Run Agent Network analysis
            print(f"\n[Phase 3/3] Executing ReAct Agent Network analysis...")
            try:
                runner.start()
                result = runner.run_analysis(exports=exports, focus_function=focus_func)
            finally:
                runner.stop()

            elapsed = time.time() - start_time

            # Output results
            _print_network_results(result, elapsed, target_path, output_dir, output_format)

        # Handle pattern generation and bad character detection
        if generate_pattern or detect_bad_chars:
            _handle_pattern_badchar_tasks(
                target_path, output_dir, None,
                generate_pattern, pattern_length,
                detect_bad_chars, bad_char_range
            )

    except ImportError as e:
        print(f"[-] Module unavailable: {e}")
        import traceback
        traceback.print_exc()
    except KeyboardInterrupt:
        print(f"\n[!] Analysis interrupted by user")
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        import traceback
        traceback.print_exc()


def _handle_pattern_badchar_tasks(target_path: Path, output_dir: Path,
                                 analyzer, generate_pattern: bool,
                                 pattern_length: int, detect_bad_chars: bool,
                                 bad_char_range: str):
    """Handle pattern generation and bad character detection tasks"""
    print(f"\n{'='*60}")
    print("Pattern Generation and Bad Character Detection")
    print("="*60)

    if generate_pattern:
        print(f"[*] Generating pattern payload of length {pattern_length}...")
        try:
            from luodllhack.exploit.payload import PatternGenerator

            pattern = PatternGenerator.create(pattern_length)
            pattern_path = output_dir / f"{target_path.stem}_pattern.txt"
            pattern_path.write_text(pattern.decode('latin1', errors='ignore'))
            print(f"[+] Pattern payload saved: {pattern_path}")

            # If there are discovered buffer overflows, try to calculate offset
            if hasattr(analyzer, 'findings'):
                for finding in analyzer.findings:
                    if hasattr(finding, 'vuln_type') and finding.vuln_type.name == 'BUFFER_OVERFLOW':
                        print(f"[*] Found Buffer Overflow: {finding.sink.api_name} @ 0x{finding.sink.addr:x}")

        except Exception as e:
            print(f"[-] Pattern generation failed: {e}")

    if detect_bad_chars:
        print(f"[*] Detecting bad chars in range: {bad_char_range}...")
        try:
            from luodllhack.exploit.payload import BadCharFinder
            import re

            # Parse range
            if '-' in bad_char_range:
                start, end = map(int, bad_char_range.split('-'))
                test_range = range(start, end + 1)
            else:
                # Single value
                test_range = range(int(bad_char_range), int(bad_char_range) + 1)

            # Create bad char finder
            finder = BadCharFinder()
            result = finder.detect(0x1000, str(target_path), test_range, speakeasy_timeout=60)

            if result.success:
                bad_chars_path = output_dir / f"{target_path.stem}_bad_chars.txt"
                with open(bad_chars_path, 'w') as f:
                    f.write("Detected Bad Characters (hex):\n")
                    for bad_char in result.detected_bad_chars:
                        f.write(f"0x{bad_char:02x}\n")
                    f.write(f"\nSafe Characters Count: {len(result.safe_chars)}\n")
                    f.write(f"Total Tested: {result.total_tested}\n")

                print(f"[+] Bad character detection complete, results saved: {bad_chars_path}")
                print(f"    Bad characters detected: {len(result.detected_bad_chars)}")
                print(f"    Safe characters: {len(result.safe_chars)}")
            else:
                print(f"[-] Bad character detection failed: {result.error}")

        except ImportError:
            print(f"[-] Speakeasy unavailable, skipping bad character detection")
        except Exception as e:
            print(f"[-] Bad character detection failed: {e}")


def _print_hunt_results(findings, elapsed: float, target_path: Path,
                        output_dir: Path, output_format: str):
    """Print vulnerability hunting results"""
    print(f"\n{'='*60}")
    print(f"  Analysis Complete (Time: {elapsed:.1f}s)")
    print(f"{'='*60}")
    print(f"[+] Found {len(findings)} potential vulnerabilities")

    high_conf = [f for f in findings if f.confidence.total_score >= 0.70]
    medium_conf = [f for f in findings if 0.40 <= f.confidence.total_score < 0.70]
    low_conf = [f for f in findings if f.confidence.total_score < 0.40]

    print(f"\n[Stats] High Confidence: {len(high_conf)} | Medium Confidence: {len(medium_conf)} | Low Confidence: {len(low_conf)}")

    if high_conf:
        print(f"\n[!] High Confidence Findings (Priority):")
        for f in high_conf[:10]:
            print(f"    ● {f.vuln_type.name} @ 0x{f.location:x} ({f.confidence.level})")

    if medium_conf:
        print(f"\n[*] Medium Confidence Findings (Review recommended):")
        for f in medium_conf[:5]:
            print(f"    ○ {f.vuln_type.name} @ 0x{f.location:x} (Confidence: {f.confidence.total_score:.0%})")

    # JSON/HTML Output
    if output_format == "json":
        import json
        report = {
            "target": str(target_path),
            "analysis_time": elapsed,
            "total_findings": len(findings),
            "high_confidence": len(high_conf),
            "findings": [
                {"type": f.vuln_type.name, "location": hex(f.location),
                 "confidence": f.confidence.total_score, "level": f.confidence.level}
                for f in findings
            ]
        }
        json_path = output_dir / f"{target_path.stem}_report.json"
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"\n[*] JSON report saved: {json_path}")

    elif output_format == "html":
        html_path = output_dir / f"{target_path.stem}_report.html"
        _generate_html_report(html_path, target_path, findings, elapsed)
        print(f"\n[*] HTML report saved: {html_path}")


def _generate_html_report(html_path: Path, target_path: Path, findings, elapsed: float):
    """Generate HTML report"""
    high_conf = [f for f in findings if f.confidence.total_score >= 0.70]

    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>LuoDllHack Analysis Report - {target_path.name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .stat {{ display: inline-block; padding: 10px 20px; margin: 5px; background: #f5f5f5; border-radius: 5px; }}
        .high {{ background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>LuoDllHack Analysis Report</h1>
    <p><strong>Target:</strong> {target_path.name}</p>
    <p><strong>Analysis Time:</strong> {elapsed:.1f}s</p>
    <div class="stat">Total Findings: {len(findings)}</div>
    <div class="stat" style="background:#ffcdd2">High Confidence: {len(high_conf)}</div>
    <h2>High Confidence Findings</h2>
'''
    for f in high_conf[:20]:
        html += f'''    <div class="high">
        <strong>{f.vuln_type.name}</strong> @ 0x{f.location:x}<br>
        Confidence: {f.confidence.total_score:.0%} ({f.confidence.level})
    </div>\n'''
    html += '</body></html>'
    html_path.write_text(html, encoding='utf-8')


def _print_network_results(result: dict, elapsed: float, target_path: Path,
                           output_dir: Path, output_format: str):
    """Print Agent Network analysis results"""
    print(f"\n{'='*60}")
    print(f"  Analysis Complete (Time: {elapsed:.1f}s)")
    print(f"{'='*60}")

    findings = result.get("findings", [])
    summary = result.get("summary", {})

    print(f"[+] Found {len(findings)} potential vulnerabilities")

    # Stats by severity
    by_severity = summary.get("by_severity", {})
    print(f"\n[Stats] Critical: {by_severity.get('Critical', 0)} | "
          f"High: {by_severity.get('High', 0)} | "
          f"Medium: {by_severity.get('Medium', 0)} | "
          f"Low: {by_severity.get('Low', 0)}")

    # Display Agents used
    agents_used = result.get("agents_used", [])
    if agents_used:
        print(f"[*] Agents Used: {', '.join(agents_used)}")

    # Display high severity findings
    critical_high = [f for f in findings if f.get("severity") in ("Critical", "High")]
    if critical_high:
        print(f"\n[!] High Risk Findings (Priority):")
        for f in critical_high[:10]:
            addr = f.get("address", 0)
            addr_str = f"0x{addr:x}" if isinstance(addr, int) else str(addr)
            print(f"    [!] {f.get('vuln_type', 'UNKNOWN')} @ {addr_str}")
            print(f"        Severity: {f.get('severity', 'Unknown')}")
            print(f"        Confidence: {f.get('confidence', 0):.0%}")
            if f.get("sink_api"):
                print(f"        Dangerous API: {f.get('sink_api')}")
            if f.get("function"):
                print(f"        Function: {f.get('function')}")
            if f.get("cwe_id"):
                print(f"        CWE: {f.get('cwe_id')}")

    # Display medium findings
    medium = [f for f in findings if f.get("severity") == "Medium"]
    if medium:
        print(f"\n[*] Medium Risk Findings (Review recommended):")
        for f in medium[:5]:
            addr = f.get("address", 0)
            addr_str = f"0x{addr:x}" if isinstance(addr, int) else str(addr)
            print(f"    [*] {f.get('vuln_type', 'UNKNOWN')} @ {addr_str} "
                  f"(Confidence: {f.get('confidence', 0):.0%})")

    # JSON/HTML output
    if output_format == "json":
        import json
        json_path = output_dir / f"{target_path.stem}_network_report.json"
        json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        print(f"\n[*] JSON report saved: {json_path}")

    elif output_format == "html":
        html_path = output_dir / f"{target_path.stem}_network_report.html"
        _generate_network_html_report(html_path, target_path, result, elapsed)
        print(f"\n[*] HTML report saved: {html_path}")


def _generate_network_html_report(html_path: Path, target_path: Path,
                                   result: dict, elapsed: float):
    """Generate Agent Network HTML report"""
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    by_severity = summary.get("by_severity", {})

    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>LuoDllHack Agent Network Analysis Report - {target_path.name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .stat {{ display: inline-block; padding: 10px 20px; margin: 5px; background: #f5f5f5; border-radius: 5px; }}
        .critical {{ background: #ffebee; border-left: 4px solid #d32f2f; padding: 10px; margin: 10px 0; }}
        .high {{ background: #fff3e0; border-left: 4px solid #f57c00; padding: 10px; margin: 10px 0; }}
        .medium {{ background: #fff8e1; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>LuoDllHack Agent Network Analysis Report</h1>
    <p><strong>Target:</strong> {target_path.name}</p>
    <p><strong>Analysis Time:</strong> {elapsed:.1f}s</p>
    <p><strong>Architecture:</strong> ReAct Agent Network</p>
    <div class="stat">Total Findings: {len(findings)}</div>
    <div class="stat" style="background:#ffcdd2">Critical: {by_severity.get('Critical', 0)}</div>
    <div class="stat" style="background:#ffe0b2">High: {by_severity.get('High', 0)}</div>
    <div class="stat" style="background:#fff9c4">Medium: {by_severity.get('Medium', 0)}</div>
    <h2>Vulnerability Findings</h2>
'''
    for f in findings[:30]:
        severity = f.get("severity", "Medium")
        css_class = severity.lower() if severity in ("Critical", "High", "Medium") else "medium"
        addr = f.get("address", 0)
        addr_str = f"0x{addr:x}" if isinstance(addr, int) else str(addr)
        html += f'''    <div class="{css_class}">
        <strong>{f.get('vuln_type', 'UNKNOWN')}</strong> @ {addr_str}<br>
        Severity: {severity} | Confidence: {f.get('confidence', 0):.0%}<br>
        {f"Dangerous API: {f.get('sink_api')}<br>" if f.get('sink_api') else ""}
        {f"Function: {f.get('function')}<br>" if f.get('function') else ""}
    </div>
'''
    html += '</body></html>'
    html_path.write_text(html, encoding='utf-8')


def run_verify(target_path: Path, addr_str: str, vuln_type: str,
               func_name: str = "", trigger: bool = False):
    """Run vulnerability verification"""
    try:
        from luodllhack.verify import SpeakeasyVerifier, HAVE_SPEAKEASY

        if not HAVE_SPEAKEASY:
            print("[-] Speakeasy unavailable")
            print("    Install: pip install speakeasy-emulator")
            return

        # Parse address
        try:
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str, 16)
        except ValueError:
            print(f"[-] Invalid address: {addr_str}")
            return

        vuln_type = vuln_type.upper()
        # All 21 vulnerability types
        valid_types = [
            # Memory
            'BUFFER_OVERFLOW', 'HEAP_OVERFLOW', 'DOUBLE_FREE', 'USE_AFTER_FREE',
            'NULL_DEREFERENCE', 'OUT_OF_BOUNDS_READ', 'OUT_OF_BOUNDS_WRITE',
            'UNINITIALIZED_MEMORY', 'TYPE_CONFUSION', 'CONTROL_FLOW_HIJACK',
            # Integer
            'INTEGER_OVERFLOW', 'INTEGER_UNDERFLOW',
            # Injection
            'FORMAT_STRING', 'COMMAND_INJECTION', 'PATH_TRAVERSAL',
            # Information
            'INFO_DISCLOSURE', 'MEMORY_LEAK',
            # Other
            'RACE_CONDITION', 'STACK_EXHAUSTION', 'DESERIALIZATION', 'PRIVILEGE_ESCALATION',
        ]
        if vuln_type not in valid_types:
            print(f"[-] Invalid vulnerability type: {vuln_type}")
            print(f"    Supported types:")
            print(f"      Memory: BUFFER_OVERFLOW, HEAP_OVERFLOW, DOUBLE_FREE, USE_AFTER_FREE, ...")
            print(f"      Integer: INTEGER_OVERFLOW, INTEGER_UNDERFLOW")
            print(f"      Injection: FORMAT_STRING, COMMAND_INJECTION, PATH_TRAVERSAL")
            print(f"      Info: INFO_DISCLOSURE, MEMORY_LEAK")
            print(f"    Use --help to see complete list")
            return

        print(f"\n{'='*60}")
        print(f"  LuoDllHack Vulnerability Verification (Speakeasy)")
        print(f"{'='*60}")
        print(f"[*] Target: {target_path}")
        print(f"[*] Address: 0x{addr:x}")
        print(f"[*] Type: {vuln_type}")
        if func_name:
            print(f"[*] Function: {func_name}")
        print(f"[*] Trigger Test: {'On' if trigger else 'Off'}")

        verifier = SpeakeasyVerifier(target_path)
        result = verifier.verify(addr, vuln_type, func_name, trigger=trigger)

        print(f"\n{'='*60}")
        print(f"  Verification Results")
        print(f"{'='*60}")
        print(f"[*] Verification Status: {'Confirmed ✓' if result.verified else 'Not confirmed'}")
        print(f"[*] Confidence: {result.confidence:.0%}")

        if result.analysis:
            print(f"\n[Analysis Report]")
            print(result.analysis)

        if result.events:
            print(f"\n[Detection Events] ({len(result.events)} total)")
            for i, event in enumerate(result.events[:5], 1):
                print(f"  {i}. {event.vuln_type} @ 0x{event.address:x}")

    except ImportError as e:
        print(f"[-] Module unavailable: {e}")
    except Exception as e:
        print(f"[-] Verification failed: {e}")
        import traceback
        traceback.print_exc()


def run_checksec(target_path: Path, api_key: str = None):
    """Run security check"""
    import os
    try:
        from luodllhack.ai.security import SecurityAnalyzer

        print(f"\n{'='*60}")
        print(f"  LuoDllHack Security Check")
        print(f"{'='*60}")
        print(f"[*] Target: {target_path}")

        # Set API Key
        original_key = os.environ.get("GEMINI_API_KEY")
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key

        try:
            analyzer = SecurityAnalyzer(target_path)
            analyzer.analyze()
        finally:
            # Restore environment variable
            if original_key is None:
                os.environ.pop("GEMINI_API_KEY", None)
            else:
                os.environ["GEMINI_API_KEY"] = original_key

    except ImportError as e:
        print(f"[-] SecurityAnalyzer unavailable: {e}")
    except Exception as e:
        print(f"[-] Check failed: {e}")


def run_ai_func(target_path: Path, addr_str: str, api_key: str = None):
    """Analyze function using AI"""
    import os
    try:
        from luodllhack.core import RizinCore
        from luodllhack.ai.analyzer import AIAnalyzer

        # Parse address
        try:
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str, 16)
        except ValueError:
            print(f"[-] Invalid address: {addr_str}")
            return

        print(f"\n{'='*60}")
        print(f"  LuoDllHack AI Function Analysis")
        print(f"{'='*60}")
        print(f"[*] Target: {target_path}")
        print(f"[*] Address: 0x{addr:x}")

        rz = RizinCore(str(target_path))
        ai = AIAnalyzer(rz, api_key=api_key or os.environ.get("GEMINI_API_KEY", ""))

        if not ai.is_available():
            print("[-] AI unavailable, please set GEMINI_API_KEY or use --api-key")
            return

        print("[*] Analyzing...")
        result = ai.analyze_function(addr)

        if "error" in result:
            print(f"[-] Error: {result['error']}")
        else:
            print(f"\n{result.get('analysis', 'No results')}")

    except ImportError as e:
        print(f"[-] Module unavailable: {e}")
    except Exception as e:
        print(f"[-] Analysis failed: {e}")


def run_hijack_scan(target_path: Path, recursive: bool = False,
                    skip_system: bool = True, risk_filter: str = "all",
                    csv_output: str = None, threads: int = 4,
                    generate_poc: bool = False, payload: str = "messagebox",
                    max_gen: int = 5, output_dir: Path = None,
                    use_ai: bool = False, api_key: str = None):
    """Run DLL Hijacking scan"""
    try:
        from luodllhack.dll_hijack.scanner import HijackScanner, RiskLevel, analyze_exploitation_trigger

        print(f"\n{'='*60}")
        print(f"  DLL Hijacking Vulnerability Scan")
        print(f"{'='*60}")
        print(f"[*] Scan path: {target_path}")
        print(f"[*] Recursive scan: {'Yes' if recursive else 'No'}")
        print(f"[*] Skip system directories: {'Yes' if skip_system else 'No'}")
        print(f"[*] Parallel threads: {threads}")
        if generate_poc:
            print(f"[*] Generate PoC: Yes (Payload: {payload})")

        # Risk filter
        risk_filter_set = None
        if risk_filter != "all":
            risk_map = {
                "critical": {RiskLevel.CRITICAL},
                "high": {RiskLevel.CRITICAL, RiskLevel.HIGH},
                "medium": {RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM},
                "low": {RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW},
            }
            risk_filter_set = risk_map.get(risk_filter)

        # Progress callback
        def progress(current, total, filename):
            percent = int(current / total * 100)
            print(f"\r[*] Progress: {current}/{total} ({percent}%) - {filename[:40]:<40}", end="", flush=True)

        # Execute scan
        scanner = HijackScanner(skip_system=skip_system, max_workers=threads)
        results, summary = scanner.scan(
            str(target_path),
            recursive=recursive,
            risk_filter=risk_filter_set,
            progress_callback=progress
        )

        print()  # Newline

        # Print report
        scanner.print_report(results, summary, show_low_risk=(risk_filter == "low"), verbose=True)

        # AI Trigger analysis (only if AI is enabled)
        if use_ai:
            print(f"\n{'='*60}")
            print(f"  AI Trigger Scenario Analysis")
            print(f"{'='*60}")
            vuln_count = 0
            ai_status_shown = False
            for result in results:
                if result.high_risk_count > 0 or result.medium_risk_count > 0:
                    exploit_info = analyze_exploitation_trigger(result, use_ai=True, api_key=api_key)
                    # Show AI status (once only)
                    if not ai_status_shown:
                        ai_status = exploit_info.get('ai_status', 'unknown')
                        print(f"[*] AI Status: {ai_status}")
                        ai_status_shown = True
                        if 'unavailable' in ai_status:
                            print("[!] AI unavailable, skipping trigger analysis")
                            break
                    if exploit_info['vulnerabilities'] and 'ai_analysis' in exploit_info:
                        vuln_count += 1
                        print(f"\n{'='*60}")
                        print(f"[{vuln_count}] {result.path.name}")
                        print(f"{'='*60}")
                        print(f"    Directory: {result.path.parent}")
                        print(f"    Architecture: {exploit_info['architecture']}")
                        print(f"    Writable: {'Yes' if exploit_info['dir_writable'] else 'No'}")
                        if exploit_info.get('version_info'):
                            print(f"    Version: {exploit_info['version_info']}")

                        # Show AI global analysis
                        print(f"\n  [AI Analysis Results]")
                        print("-" * 58)
                        for line in exploit_info['ai_analysis'].split('\n'):
                            print(f"  {line}")
                        print("-" * 58)
            if vuln_count == 0 and ai_status_shown and 'unavailable' not in ai_status:
                print("\n  No exploitable targets found")

        # CSV Export
        if csv_output:
            scanner.export_csv(results, csv_output, include_no_risk=False)
            print(f"[+] CSV report exported: {csv_output}")

        # Generate PoC
        if generate_poc:
            _run_hijack_gen(target_path, output_dir or Path.cwd() / "hijack_poc",
                          risk_filter, payload, max_gen)

    except ImportError as e:
        print(f"[-] Module unavailable: {e}")
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        import traceback
        traceback.print_exc()


def _run_hijack_gen(target_path: Path, output_dir: Path,
                   risk_filter: str, payload: str, max_gen: int):
    """Generate DLL Hijacking PoC"""
    try:
        from luodllhack.dll_hijack.hijack_gen import HijackGenerator
        from luodllhack.dll_hijack.scanner import RiskLevel

        print(f"\n{'='*60}")
        print(f"  DLL Hijacking PoC Generation")
        print(f"{'='*60}")

        risk_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "all": RiskLevel.HIGH,  # Default generate HIGH and above
        }
        min_risk = risk_map.get(risk_filter, RiskLevel.HIGH)

        generator = HijackGenerator(payload_type=payload)
        results = generator.generate_all(
            str(target_path),
            str(output_dir),
            min_risk=min_risk,
            max_targets=max_gen
        )

        success_count = sum(1 for r in results if r.success)
        print(f"\n[*] Generation Result: {success_count}/{len(results)} success")
        print(f"[*] Output Directory: {output_dir}")

        for r in results:
            status = "[+]" if r.success else "[-]"
            print(f"{status} {r.target.dll_name}: {r.target.risk_level.name}")
            if r.success:
                for f in r.files:
                    print(f"      {f.name}")
            else:
                print(f"      Error: {r.error}")

    except ImportError as e:
        print(f"[-] Module unavailable: {e}")
    except Exception as e:
        print(f"[-] Generation failed: {e}")
        import traceback
        traceback.print_exc()


def run_proxy(target_path: Path, output_dir: Path, compile_dll: bool = False):
    """Generate proxy DLL"""
    try:
        from luodllhack.dll_hijack import ProxyGenerator

        print(f"[*] Target: {target_path}")
        print("[*] Generating proxy DLL...")

        generator = ProxyGenerator()

        if compile_dll:
            result = generator.generate_and_compile(target_path, output_dir)
        else:
            result = generator.generate(target_path, output_dir)

        if result['success']:
            print(f"[+] Proxy DLL generated successfully")
            for f in result.get('files', []):
                print(f"    - {f}")
        else:
            print(f"[-] Generation failed: {result.get('errors', [])}")

    except ImportError as e:
        print(f"[-] Module unavailable: {e}")
    except Exception as e:
        print(f"[-] Generation failed: {e}")


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Show version
    if args.version:
        try:
            import luodllhack
            print(f"LuoDllHack v{luodllhack.__version__}")
        except ImportError:
            print("LuoDllHack v5.2.0")
        return

    # Show capability information
    if args.info:
        show_info()
        return

    # Load configuration file
    config = None
    if args.config:
        try:
            from luodllhack.core.config import load_config
            config = load_config(str(args.config))
            print(f"[*] Configuration loaded: {args.config}")

            # Validate config
            errors = config.validate()
            if errors:
                print("[!] Configuration warnings:")
                for err in errors:
                    print(f"    - {err}")

            # Setup logging from config
            try:
                from luodllhack.core.logging import setup_logging_from_config
                setup_logging_from_config(config)
            except ImportError:
                pass
        except Exception as e:
            print(f"[-] Failed to load configuration: {e}")
            return

    # DLL Hijacking Scan (can be a directory or file, handled separately)
    if args.hijack_scan:
        if not args.target:
            print("[-] Please specify a scan path")
            return
        target = Path(args.target)
        if not target.exists() and '*' not in args.target:
            print(f"[-] Path does not exist: {target}")
            return
        skip_system = args.hijack_skip_system and not args.hijack_include_system
        run_hijack_scan(
            target,
            recursive=args.hijack_recursive,
            skip_system=skip_system,
            risk_filter=args.hijack_risk,
            csv_output=args.hijack_csv,
            threads=args.hijack_threads,
            generate_poc=args.hijack_gen,
            payload=args.hijack_payload,
            max_gen=args.hijack_max,
            output_dir=args.output,
            use_ai=args.hijack_ai,
            api_key=args.api_key
        )
        return

    # Operations below require a target file
    if not args.target:
        parser.print_help()
        return

    target = Path(args.target)
    if not target.exists():
        print(f"[-] File does not exist: {target}")
        return

    # If configuration is loaded, use output_dir from config
    output_dir = args.output
    if config and args.output == Path.cwd():
        output_dir = config.output_dir

    # Automated vulnerability hunting (ReAct Agent Network)
    if args.hunt:
        run_hunt(
            target,
            output_dir,
            api_key=args.api_key,
            max_steps=args.hunt_max_steps,
            focus_func=args.hunt_focus,
            output_format=args.hunt_output,
            no_ai=args.hunt_no_ai,
            config=config,
            generate_pattern=args.generate_pattern,
            pattern_length=args.pattern_length,
            detect_bad_chars=args.detect_bad_chars,
            bad_char_range=args.bad_char_range,
            signature_file=args.signature_file
        )
        return

    # Vulnerability Verification
    if args.verify:
        addr, vuln_type = args.verify
        run_verify(
            target, addr, vuln_type,
            func_name=args.verify_func or "",
            trigger=args.verify_trigger
        )
        return

    # Security Analysis
    if args.checksec:
        run_checksec(target, api_key=args.api_key)
        return

    # AI Function Analysis
    if args.ai_func:
        run_ai_func(target, args.ai_func, api_key=args.api_key)
        return

    # DLL Proxy Generation
    if args.proxy:
        run_proxy(target, args.output, args.compile)
        return

    # No operation specified, show help
    parser.print_help()


if __name__ == "__main__":
    main()
