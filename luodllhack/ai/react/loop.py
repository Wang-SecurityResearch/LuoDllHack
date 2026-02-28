# -*- coding: utf-8 -*-
"""
luodllhack/ai/react/loop.py
ReAct (Reason + Act) Loop Implementation

Provides:
- ReActLoop: Reasoning-action loop executor
- Response processing and tool calls
- Step management and auto-extension
"""

import json
import re
import time
import logging
from typing import Dict, List, Any, Optional, Callable, TYPE_CHECKING

from .token_manager import TokenManager
from ..tools.types import ToolResultType, AgentState, VulnReport

if TYPE_CHECKING:
    from ..tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class ReActLoop:
    """
    ReAct Loop Executor

    Workflow:
    1. Observe: Observe current state
    2. Think: LLM reasons about the next step
    3. Act: Call tools for execution
    4. Repeat: Until completion or limit reached
    """

    # Hard limit to prevent infinite loops
    ABSOLUTE_MAX_STEPS = 60

    def __init__(
        self,
        tools: 'ToolRegistry',
        state: AgentState,
        report: VulnReport,
        send_message_func: Callable[[Any, str], Any],
        agent_name: str = "primary"
    ):
        """
        Initialize ReAct loop

        Args:
            tools: Tool registry
            state: Agent state
            report: Vulnerability report
            send_message_func: Function to send message to LLM
            agent_name: Agent name (for logging)
        """
        self.tools = tools
        self.state = state
        self.report = report
        self.send_message = send_message_func
        self.agent_name = agent_name

        # Finding extractors (extendable)
        self._finding_extractors: Dict[str, Callable] = {}
        self._register_default_extractors()

    def run(self, chat: Any, system_prompt: str) -> VulnReport:
        """
        Execute ReAct loop

        Args:
            chat: LLM chat object
            system_prompt: System prompt

        Returns:
            Vulnerability report
        """
        print("\n[*] Starting ReAct loop...")

        while not self.state.should_stop and self.state.current_step < self.state.max_steps:
            self.state.current_step += 1
            print(f"\n--- Step {self.state.current_step}/{self.state.max_steps} ---")

            try:
                if self.state.current_step == 1:
                    response = self.send_message(chat, system_prompt)
                else:
                    last_result = self.state.observations[-1] if self.state.observations else "Continue analysis"
                    last_result = TokenManager.truncate_text(last_result, max_tokens=8000)
                    response = self.send_message(chat, last_result)

                self._process_response(response)

            except Exception as e:
                print(f"[!] Error in step {self.state.current_step}: {e}")
                self.state.observations.append(f"Error: {e}")
                logger.exception(f"ReAct loop error at step {self.state.current_step}")

            # Check step limits and auto-extension
            self._check_auto_extend()

        return self.report

    def _check_auto_extend(self) -> None:
        """Check if step count needs auto-extension"""
        if self.state.should_stop:
            return

        if self.state.current_step < self.state.max_steps:
            return

        # Check if extension is possible
        if self.state.max_steps >= self.ABSOLUTE_MAX_STEPS:
            print(f"\n[!] Reached absolute maximum steps ({self.ABSOLUTE_MAX_STEPS}), stopping analysis.")
            return

        last_action = self.state.actions[-1] if self.state.actions else None
        should_extend = False
        reason = ""

        if last_action:
            tool = last_action.get("tool", "")
            result = last_action.get("result", "")

            if tool == "generate_poc":
                should_extend = True
                reason = "PoC generated but not verified"
            elif tool == "analyze_taint_flow" and result == "success":
                should_extend = True
                reason = "Active taint analysis in progress"
            elif tool == "deep_verify_vulnerability" and result == "success":
                should_extend = True
                reason = "Deep verification in progress"

        if should_extend:
            extension = 10
            self.state.max_steps = min(
                self.state.max_steps + extension,
                self.ABSOLUTE_MAX_STEPS
            )
            print(f"\n[*] Auto-extending analysis steps (+{extension}) [Reason: {reason}]")
            print(f"    New max steps: {self.state.max_steps}")
        else:
            print(f"\n[!] Reached maximum steps ({self.state.max_steps}), stopping analysis.")

    def _process_response(self, response: Any) -> None:
        """Process LLM response"""
        if not response.candidates or not response.candidates[0].content.parts:
            return

        for part in response.candidates[0].content.parts:
            # Handle text response
            if hasattr(part, 'text') and part.text:
                self._handle_text_response(part.text)

            # Handle function call
            if hasattr(part, 'function_call') and part.function_call:
                self._handle_function_call(part.function_call)

    def _handle_text_response(self, text: str) -> None:
        """Handle text response"""
        display_text = text
        if len(display_text) > 4000:
            print(f"[LLM:{self.agent_name}] {display_text[:4000]}... (truncated)")
        else:
            print(f"[LLM:{self.agent_name}] {display_text}")

        # Check if complete
        if "[ANALYSIS_COMPLETE]" in text:
            self.state.should_stop = True
            self._extract_findings_from_text(text)

    def _handle_function_call(self, fc: Any) -> None:
        """Handle function call"""
        print(f"[Tool Call:{self.agent_name}] {fc.name}")

        # Parse arguments
        args = {}
        if fc.args:
            for key, value in fc.args.items():
                args[key] = value

        # Call tool
        result = self.tools.call_tool(fc.name, args)

        # Record action
        self.state.actions.append({
            "agent": self.agent_name,
            "tool": fc.name,
            "args": args,
            "result": result.status.value
        })

        # Format results
        if result.status == ToolResultType.SUCCESS:
            result_str = TokenManager.summarize_tool_result(fc.name, result.data, max_chars=2200)
            print(f"[Tool Result] Success ({result.execution_time:.2f}s)")
            self._check_for_findings(fc.name, result.data)
        else:
            result_str = f"Error: {result.error}"
            print(f"[Tool Result] {result_str}")

        # Token management
        self._manage_tokens(result_str)

        # Record observations
        self.state.observations.append(result_str)
        self.report.analysis_trace.append({
            "step": self.state.current_step,
            "agent": self.agent_name,
            "tool": fc.name,
            "result_summary": str(result.data)[:200] if result.data else result.error
        })

    def _manage_tokens(self, result_str: str) -> None:
        """Manage token usage"""
        result_tokens = TokenManager.estimate_tokens(result_str)
        self.state.token_used += result_tokens

        if self.state.token_used > self.state.token_budget:
            print(f"[Token] Budget exceeded ({self.state.token_used}/{self.state.token_budget}), truncating...")
            self.state.observations = TokenManager.truncate_observations(
                self.state.observations,
                self.state.token_budget // 2
            )
            self.state.token_used = sum(
                TokenManager.estimate_tokens(obs)
                for obs in self.state.observations
            )
            print(f"[Token] After truncation: {self.state.token_used} tokens")

    def _register_default_extractors(self) -> None:
        """Register default finding extractors"""
        self._finding_extractors = {
            "analyze_taint_flow": self._extract_taint_findings,
            "analyze_cross_function": self._extract_cross_function_findings,
            "generate_poc": self._extract_poc,
            "verify_poc": self._extract_poc_verification,
            "deep_verify_vulnerability": self._extract_deep_verify_findings,
            "verify_all_dangerous_imports": self._extract_batch_verify_findings,
            "analyze_pointer_lifecycle": self._extract_lifecycle_findings,
            "symbolic_explore": self._extract_symbolic_findings,
        }

    def _check_for_findings(self, tool_name: str, result: Any) -> None:
        """Check for vulnerability findings in tool results"""
        if not result:
            return

        if isinstance(result, dict) and result.get("error"):
            return

        extractor = self._finding_extractors.get(tool_name)
        if extractor:
            extractor(result)

    def _extract_taint_findings(self, result: Dict) -> None:
        """Extract taint analysis findings"""
        if result.get("taint_paths_found", 0) > 0:
            for path in result.get("paths", []):
                self.state.findings.append({
                    "type": "taint_path",
                    "vuln_type": path["sink"]["vuln_type"],
                    "severity": path["sink"]["severity"],
                    "sink_api": path["sink"]["api"],
                    "sink_address": path["sink"].get("address"),
                    "confidence": path["confidence"],
                    "source": "analyze_taint_flow"
                })

    def _extract_cross_function_findings(self, result: Dict) -> None:
        """Extract cross-function analysis findings"""
        if result.get("cross_function_vulns", 0) > 0:
            for vuln in result.get("vulnerabilities", []):
                self.state.findings.append({
                    "type": "cross_function",
                    "entry": vuln["entry_function"],
                    "call_chain": vuln["call_chain"],
                    "vuln_type": vuln["sink"]["vuln_type"],
                    "severity": vuln["sink"]["severity"],
                    "confidence": vuln.get("confidence", 0.5),
                    "source": "analyze_cross_function"
                })

    def _extract_poc(self, result: Dict) -> None:
        """Extract PoC code"""
        if result.get("poc_code"):
            self.report.poc_code = result.get("poc_code")

    def _extract_poc_verification(self, result: Dict) -> None:
        """Extract PoC verification results"""
        crashed = result.get("crashed", False)
        is_false_positive = result.get("is_false_positive", False)

        if crashed:
            if is_false_positive:
                # False positive: crash address equals input parameter, indicating signature error
                self.report.poc_verified = False
                reason = result.get("false_positive_reason", "unknown")
                self.state.findings.append({
                    "type": "false_positive",
                    "reason": reason,
                    "warning": result.get("warning", ""),
                    "crash_address": result.get("crash_address"),
                    "source": "verify_poc"
                })
                print(f"[!] PoC verification: FALSE POSITIVE detected - {reason}")
            else:
                # Genuine crash
                self.report.poc_verified = True
                print("[+] PoC verification: genuine crash confirmed")

    def _extract_deep_verify_findings(self, result: Dict) -> None:
        """Extract deep verification findings"""
        if result.get("is_likely_exploitable"):
            self.state.findings.append({
                "type": "deep_verified",
                "vuln_type": result.get("vuln_type"),
                "sink_address": result.get("sink_address"),
                "confidence": result.get("confidence_score", 0),
                "confidence_level": result.get("confidence_level"),
                "severity": "High" if result.get("confidence_score", 0) >= 0.7 else "Medium",
                "evidence": result.get("evidence", []),
                "source": "deep_verify_vulnerability"
            })

    def _extract_batch_verify_findings(self, result: Dict) -> None:
        """Extract batch verification findings"""
        for item in result.get("results", []):
            if item.get("is_likely_exploitable"):
                self.state.findings.append({
                    "type": "batch_verified",
                    "vuln_type": item.get("vuln_type"),
                    "sink_api": item.get("api"),
                    "sink_address": item.get("address"),
                    "confidence": item.get("confidence_score", 0),
                    "severity": "High" if item.get("confidence_score", 0) >= 0.7 else "Medium",
                    "cwe": item.get("cwe"),
                    "source": "verify_all_dangerous_imports"
                })

    def _extract_lifecycle_findings(self, result: Dict) -> None:
        """Extract lifecycle analysis findings"""
        for anomaly in result.get("anomalies", []):
            self.state.findings.append({
                "type": "lifecycle_anomaly",
                "vuln_type": anomaly.get("type", "memory_corruption"),
                "severity": anomaly.get("severity", "High"),
                "description": anomaly.get("description"),
                "confidence": 0.6,
                "source": "analyze_pointer_lifecycle"
            })

    def _extract_symbolic_findings(self, result: Dict) -> None:
        """Extract symbolic execution findings"""
        if result.get("solved_inputs"):
            self.state.findings.append({
                "type": "symbolic_confirmed",
                "func_address": result.get("func_address"),
                "target_sink": result.get("target_sink"),
                "paths_found": result.get("paths_found", 0),
                "solved_inputs": result.get("solved_inputs"),
                "confidence": 0.8,
                "severity": "High",
                "source": "symbolic_explore"
            })

    def _extract_findings_from_text(self, text: str) -> None:
        """Extract findings from LLM text"""
        # Attempt to extract JSON blocks
        json_pattern = r'```json\s*(.*?)\s*```'
        matches = re.findall(json_pattern, text, re.DOTALL)

        for match in matches:
            try:
                block = json.loads(match)
                if 'vuln_type' in block or 'confirmed' in block:
                    self.state.findings.append({
                        'type': 'ai_structured',
                        'vuln_type': block.get('vuln_type', 'UNKNOWN'),
                        'cwe_id': block.get('cwe_id', ''),
                        'function': block.get('function', ''),
                        'address': block.get('address', ''),
                        'confidence': block.get('confidence', 0.5),
                        'root_cause': block.get('root_cause', ''),
                        'trigger_condition': block.get('trigger_condition', ''),
                        'evidence': block.get('evidence', []),
                        'source': 'ai_text_extraction'
                    })
            except json.JSONDecodeError:
                continue

        # Fallback: Keyword matching for risk level
        if "Critical" in text:
            self.report.risk_level = "Critical"
        elif "High" in text:
            self.report.risk_level = "High"
        elif "Medium" in text:
            self.report.risk_level = "Medium"

        if "easy" in text.lower():
            self.report.exploitability = "Easy"
        elif "medium" in text.lower():
            self.report.exploitability = "Medium"
