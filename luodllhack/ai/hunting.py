# -*- coding: utf-8 -*-
"""
luodllhack/ai/hunting.py
AI-driven Vulnerability Mining Agent

Core Class:
- VulnHuntingAgent: Main Agent, coordinates tools and LLM for vulnerability mining

Architecture:
    VulnHuntingAgent
        ├── ToolRegistry (Tool Registration)
        ├── ReActLoop (Reasoning-Action Loop)
        ├── ReportGenerator (Report Generation)
        └── LLM Backend (LLM Interface)
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, TYPE_CHECKING

# Core module imports
from .tools import ToolRegistry, ToolResultType, AgentState, VulnReport
from .react import TokenManager, ReActLoop
from .report import ReportGenerator
from .compat import DEPS, HAVE_GENAI, HAVE_VULN_ANALYSIS, HAVE_CONFIG

# Conditional imports
if HAVE_GENAI:
    import google.generativeai as genai
else:
    genai = None

if HAVE_VULN_ANALYSIS:
    from luodllhack.analysis.taint import TaintEngine
else:
    TaintEngine = None

if HAVE_CONFIG:
    from luodllhack.core.config import default_config, LuoDllHackConfig
else:
    default_config = None
    LuoDllHackConfig = None

# Multi-backend support
try:
    from .agents.llm_backend import create_backend_from_config, LLMBackend
    HAVE_MULTI_BACKEND = True
except ImportError:
    HAVE_MULTI_BACKEND = False
    create_backend_from_config = None
    LLMBackend = None

# Agent Network Framework (v5.2)
try:
    from .agents import (
        NetworkRunner, NetworkConfig,
        SharedState, MessageBus,
        ExploiterAgent, CriticAgent, ValidationAgent,
        create_pool_from_config, AnalysisContext, Finding, TaskAssignment,
        HAVE_MULTI_AGENT,
    )
except ImportError:
    HAVE_MULTI_AGENT = False
    NetworkRunner = None

# Prompt optimization module
try:
    from .prompts import VulnPatternDB, LayeredPromptBuilder
    HAVE_PROMPTS = True
except ImportError:
    HAVE_PROMPTS = False
    VulnPatternDB = None


class VulnHuntingAgent:
    """
    AI-driven Vulnerability Mining Agent

    Uses ReAct (Reason + Act) pattern:
    1. Observe: Observe current state
    2. Think: Reason about the next action
    3. Act: Call tools to perform analysis
    4. Repeat: Until vulnerabilities are found or limits are reached
    """

    def __init__(
        self,
        binary_path: Path,
        api_key: str = None,
        tool_registry: ToolRegistry = None,
        config: 'LuoDllHackConfig' = None,
        signature_file: Path = None
    ):
        """
        Initialize AI Vulnerability Mining Agent

        Args:
            binary_path: Target binary file path
            api_key: API Key (optional)
            tool_registry: Custom tool registry
            config: LuoDllHack configuration instance
            signature_file: External signature file path (Cutter/rizin functions.json)
        """
        self.signature_file = Path(signature_file) if signature_file else None
        self.binary_path = Path(binary_path)
        self.config = config or (default_config if HAVE_CONFIG else None)

        # API Key
        if api_key:
            self.api_key = api_key
        elif self.config and hasattr(self.config, 'ai_api_key'):
            self.api_key = self.config.ai_api_key
        else:
            self.api_key = os.environ.get("GEMINI_API_KEY", "")

        # Model parameters
        if self.config:
            self.model_name = getattr(self.config, 'ai_model', 'gemini-2.0-flash')
            self.temperature = getattr(self.config, 'ai_temperature', 0.1)
            self.max_tokens = getattr(self.config, 'ai_max_tokens', 8192)
        else:
            self.model_name = 'gemini-2.0-flash'
            self.temperature = 0.1
            self.max_tokens = 8192

        # Initialize Taint Engine
        self.taint_engine = None
        if HAVE_VULN_ANALYSIS:
            try:
                self.taint_engine = TaintEngine(
                    binary_path, config=self.config, signature_file=self.signature_file
                )
            except Exception as e:
                print(f"[!] Failed to init TaintEngine: {e}")

        # Tool registry
        if tool_registry:
            self.tools = tool_registry
            if self.tools.taint_engine is None:
                self.tools.taint_engine = self.taint_engine
            # Pass signature file to tool registry
            if self.signature_file and hasattr(self.tools, 'signature_file'):
                self.tools.signature_file = self.signature_file
        else:
            self.tools = ToolRegistry(
                binary_path, self.taint_engine, signature_file=self.signature_file
            )

        # LLM Backend
        self.model = None
        self.llm_backend = None
        self._use_legacy_genai = False

        # Prefer multi-backend system
        if HAVE_MULTI_BACKEND and self.config:
            backend_type = getattr(self.config, 'ai_backend', 'gemini')
            self.llm_backend = create_backend_from_config(self.config)
            if self.llm_backend and self.llm_backend.is_available():
                print(f"    [LLM] Using backend: {backend_type}")
            else:
                print(f"    [LLM] Backend {backend_type} not available")
                self.llm_backend = None

        # Fallback to direct Gemini
        if self.llm_backend is None and HAVE_GENAI and self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(
                self.model_name,
                tools=self.tools.get_tool_declarations(),
                generation_config=genai.GenerationConfig(
                    temperature=self.temperature,
                    max_output_tokens=self.max_tokens
                )
            )
            self._use_legacy_genai = True
            print("    [LLM] Using legacy Gemini backend")

        # Pass LLM backend to tools
        if self.llm_backend:
            self.tools.llm_backend = self.llm_backend
            self.tools.config = self.config

        # Agent state
        self.state = AgentState()
        self.report = VulnReport()
        self.exports = {}

        # Orchestrator related (for multi-agent mode)
        self.final_shared_state = None

    @property
    def is_ready(self) -> bool:
        """Check if Agent is ready"""
        if self.llm_backend:
            return self.llm_backend.is_available()
        return self.model is not None

    @property
    def backend_name(self) -> str:
        """Get current backend name"""
        if self.llm_backend:
            return self.llm_backend.backend_type.value
        elif self.model:
            return "gemini (legacy)"
        return "none"

    def hunt(
        self,
        metadata: Dict[str, Any],
        exports: Dict[str, int] = None,
        max_steps: int = 30
    ) -> VulnReport:
        """
        Execute Vulnerability Mining

        Args:
            metadata: Basic security analysis metadata
            exports: Exported functions {name: address}
            max_steps: Maximum reasoning steps

        Returns:
            Structured vulnerability report
        """
        self.state = AgentState(max_steps=max_steps)
        self.exports = exports or {}

        print("\n" + "=" * 60)
        print("AI-Driven Vulnerability Hunting")
        print("=" * 60)

        # Show architectural information
        if self.taint_engine:
            arch_info = self.taint_engine.get_arch_info()
            print(f"[*] DLL Architecture: {arch_info['dll_arch']}")
            if not arch_info.get('compatible', True):
                print(f"[!] WARNING: {arch_info.get('message', 'Arch mismatch')}")

        # Check mode
        if self._is_multi_agent_enabled() and self._is_orchestrator_available():
            print("[*] Multi-agent mode enabled")
            return self._hunt_with_orchestrator(metadata, exports, max_steps)

        if not self.is_ready:
            print("[!] LLM not available, running tool-only analysis")
            return self._fallback_analysis(metadata, exports)

        if not self.model:
            print("[!] Single-agent mode requires legacy Gemini backend")
            return self._fallback_analysis(metadata, exports)

        # Single Agent mode - ReAct loop
        chat = self.model.start_chat(history=[])
        system_prompt = self._build_system_prompt(metadata, exports)

        react_loop = ReActLoop(
            tools=self.tools,
            state=self.state,
            report=self.report,
            send_message_func=self._send_message_with_retry,
            agent_name="primary"
        )

        react_loop.run(chat, system_prompt)

        # Generate report
        generator = ReportGenerator(self.state, self.report)
        return generator.finalize()

    def _is_multi_agent_enabled(self) -> bool:
        """Check if multi-agent mode is enabled"""
        if not HAVE_MULTI_AGENT:
            return False
        if self.config:
            return getattr(self.config, 'ai_multi_agent', False)
        return False

    def _is_orchestrator_available(self) -> bool:
        """Check if NetworkRunner is available"""
        return NetworkRunner is not None and HAVE_MULTI_AGENT

    def _hunt_with_orchestrator(
        self,
        metadata: Dict[str, Any],
        exports: Dict[str, int],
        max_steps: int
    ) -> VulnReport:
        """Use NetworkRunner for vulnerability mining (v5.2)"""
        print("[*] Starting Agent Network analysis...")

        # Create configuration
        network_config = NetworkConfig()
        if self.config:
            network_config = NetworkConfig.from_luodllhack_config(self.config)
        network_config.max_react_iterations = max_steps

        # Create NetworkRunner
        runner = NetworkRunner(self.binary_path, network_config)

        try:
            runner.start()
            result = runner.run_analysis(exports=exports)

            findings = result.get("findings", [])
            print(f"\n[+] Analysis completed:")
            print(f"    Total findings: {len(findings)}")

            # Convert findings to report format
            for f in findings:
                self.state.findings.append({
                    "type": f.get("vuln_type", "UNKNOWN"),
                    "address": f.get("address"),
                    "severity": f.get("severity", "Medium"),
                    "confidence": f.get("confidence", 0.5),
                    "function": f.get("function"),
                    "sink_api": f.get("sink_api"),
                })

            self.final_shared_state = runner.shared_state

        except Exception as e:
            print(f"[!] NetworkRunner error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            runner.stop()

        generator = ReportGenerator(self.state, self.report)
        return generator.finalize()

    def _fallback_analysis(self, metadata: Dict, exports: Dict = None) -> VulnReport:
        """Fallback analysis when no LLM is available"""
        print("[*] Running fallback tool-based analysis...")

        # Check dangerous imports
        result = self.tools.call_tool("check_dangerous_imports", {})
        if result.status == ToolResultType.SUCCESS:
            for api in result.data.get("dangerous_apis", []):
                if api.get("vuln_type"):
                    self.state.findings.append({
                        "type": "dangerous_import",
                        "api": api["api"],
                        "vuln_type": api["vuln_type"],
                        "severity": api["severity"]
                    })

        # Cross-function analysis
        if exports:
            result = self.tools.call_tool("analyze_cross_function", {"exports": exports})
            if result.status == ToolResultType.SUCCESS:
                for vuln in result.data.get("vulnerabilities", []):
                    self.state.findings.append({
                        "type": "cross_function",
                        "entry": vuln["entry_function"],
                        "call_chain": vuln["call_chain"],
                        "vuln_type": vuln["sink"]["vuln_type"],
                        "severity": vuln["sink"]["severity"]
                    })

        generator = ReportGenerator(self.state, self.report)
        return generator.finalize()

    def _send_message_with_retry(self, chat: Any, message: str, max_retries: int = 3) -> Any:
        """Send message and handle rate limits"""
        retries = 0
        while retries <= max_retries:
            try:
                return chat.send_message(message)
            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "ResourceExhausted" in error_str:
                    if retries == max_retries:
                        raise Exception(f"Max retries exceeded: {e}")

                    retry_delay = 30.0
                    match = re.search(r"retry in (\d+(\.\d+)?)s", error_str)
                    if match:
                        retry_delay = float(match.group(1)) + 2.0

                    print(f"\n[!] Rate limit. Retrying in {retry_delay:.1f}s... ({retries+1}/{max_retries})")
                    time.sleep(retry_delay)
                    retries += 1
                else:
                    raise

    def _build_system_prompt(self, metadata: Dict, exports: Dict = None) -> str:
        """Build system prompt"""
        exports_info = ""
        if exports:
            total = len(exports)
            max_exports = 60
            if self.config and hasattr(self.config, "ai_max_exports_in_prompt"):
                max_exports = int(getattr(self.config, "ai_max_exports_in_prompt", 60))

            exports_info = f"\nExported Functions ({total} total):\n"
            for i, (name, addr) in enumerate(sorted(exports.items())):
                if i >= max_exports:
                    exports_info += f"  ... Omitted {total - max_exports} more ...\n"
                    break
                exports_info += f"  - {name}: 0x{addr:x}\n"

        metadata_str = json.dumps(metadata, indent=2, ensure_ascii=False)

        # Algorithm Findings
        algo_context = ""
        if hasattr(self.tools, 'algorithm_findings') and self.tools.algorithm_findings:
            all_findings = []
            for key in ["taint_paths", "memory_vulns", "integer_overflows"]:
                findings = self.tools.algorithm_findings.get(key, [])
                if isinstance(findings, list):
                    all_findings.extend(findings)

            if all_findings:
                algo_context = "\n[CRITICAL] Pre-discovered following potential vulnerabilities:\n"
                for f in all_findings[:10]:
                    vtype = f.get('vuln_type', 'UNKNOWN')
                    addr = f.get('sink_addr', f.get('vuln_addr', 'N/A'))
                    algo_context += f"- {vtype} @ {addr}\n"

        return f"""You are a top-tier binary security researcher.

Target: {self.binary_path.name}
{exports_info}

Metadata:
{metadata_str}
{algo_context}

=== Available Tools ===
1. disassemble_function - Disassemble
2. analyze_taint_flow - Taint Analysis
3. check_dangerous_imports - Dangerous API Check
4. deep_verify_vulnerability - Deep Verification
5. verify_all_dangerous_imports - Batch Verification
6. generate_poc - Generate PoC
7. verify_poc - Verify PoC

=== Analysis Flow ===
1. Quick Scan: verify_all_dangerous_imports
2. Deep Analysis: disassemble_function + analyze_taint_flow
3. Verification: deep_verify_vulnerability
4. PoC: generate_poc + verify_poc

Reply with "[ANALYSIS_COMPLETE]" when finished.
"""

    def validate_report_consistency(self, scored_findings: List = None) -> List[str]:
        """Validate report consistency"""
        generator = ReportGenerator(self.state, self.report)
        return generator.validate_consistency(scored_findings)


# =============================================================================
# Convenience Functions
# =============================================================================

def run_ai_hunt(
    dll_path: Path,
    metadata: Dict,
    exports: Dict[str, int] = None,
    config=None,
    signature_file: Path = None
) -> VulnReport:
    """
    Convenience function: Run AI vulnerability mining

    Args:
        dll_path: Target DLL path
        metadata: Metadata dictionary
        exports: Exported functions dictionary {name: address}
        config: LuoDllHack configuration instance
        signature_file: External signature file path (Cutter/rizin functions.json)
    """
    agent = VulnHuntingAgent(dll_path, config=config, signature_file=signature_file)
    return agent.hunt(metadata, exports)
