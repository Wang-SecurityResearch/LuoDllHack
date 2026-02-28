# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/analyzer_agent.py
Analyzer Agent - Attack Surface Discovery and Initial Taint Analysis

Responsibilities:
    - Scanning for dangerous API imports
    - Initial taint analysis
    - Identifying high-risk functions
    - Discovering potential attack vectors

Implemented based on NetworkAgent with ReAct + P2P communication.
"""

import json
import logging
from typing import Dict, List, Any, Optional

from .network_agent import (
    NetworkAgent,
    ReActState,
    ReActAction,
    ReActActionType,
)
from .base import (
    AgentCapability,
    TaskAssignment,
    AgentResult,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Prompt Templates
# =============================================================================

ANALYZER_SYSTEM_PROMPT = """You are a security vulnerability analyzer agent in a decentralized agent network.

Your role is to:
1. Discover attack surfaces in binary files
2. Identify dangerous API usage
3. Perform initial taint analysis
4. Find potential vulnerability entry points

You have access to the following tools:
{tools}

Available agents for collaboration:
{agents}

Current Task: {task_description}
Binary: {binary_path}

Instructions:
- Start by checking dangerous imports
- Analyze functions that use dangerous APIs
- Track data flow from inputs to sinks
- Share significant findings with the network
- Delegate deep analysis to specialized agents when needed
"""

THINK_PROMPT = """Based on the current state, think about what to do next.

Context:
{context}

Task: {task_type}
Parameters: {parameters}

Recent findings: {findings_count}
Iterations: {iteration}/{max_iterations}

What should be your next action? Consider:
1. What information do you still need?
2. Are there dangerous APIs to check?
3. Should you delegate to other agents?
4. Is it time to provide final answer?

Think step by step:"""


# =============================================================================
# AnalyzerAgent
# =============================================================================

class AnalyzerAgent(NetworkAgent):
    """
    Analyzer Agent

    Inherited from NetworkAgent, uses ReAct loop and P2P communication.

    Capabilities:
        - DISCOVERY: Discover attack surface
        - TAINT_ANALYSIS: Initial taint analysis

    Task types handled:
        - scan_dangerous_imports: Scan for dangerous APIs
        - analyze_exports: Analyze exported functions
        - initial_taint_scan: Initial taint scanning
        - find_attack_surface: Find attack surface
    """

    def __init__(self, agent_id: str, *args, **kwargs):
        # Set default capabilities
        capabilities = kwargs.pop("capabilities", [
            AgentCapability.DISCOVERY,
            AgentCapability.TAINT_ANALYSIS
        ])

        super().__init__(
            agent_id=agent_id,
            capabilities=capabilities,
            *args,
            **kwargs
        )

        # Mapping of task types to confidence
        self._task_confidence = {
            "scan_dangerous_imports": 0.95,
            "analyze_exports": 0.85,
            "analyze_export_batch": 0.85,
            "initial_taint_scan": 0.90,
            "find_attack_surface": 0.95,
            "batch_verify_imports": 0.90,
        }

        # Analysis status
        self._analyzed_functions: set = set()
        self._dangerous_apis_found: List[Dict] = []

    @property
    def role(self) -> str:
        return "analyzer"

    def can_handle(self, task: TaskAssignment) -> float:
        """Determine if task can be handled"""
        return self._task_confidence.get(task.task_type, 0.0)

    def _get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        if self.tools is None:
            return []

        # Get tool names from tool registry
        if hasattr(self.tools, 'tool_schemas'):
            return [t["name"] for t in self.tools.tool_schemas]
        elif hasattr(self.tools, 'list_tools'):
            return self.tools.list_tools()
        return []

    def _think(self, state: ReActState, task: TaskAssignment) -> str:
        """
        ReAct Thinking Stage

        Use LLM to analyze the current state and decide the next step
        """
        # Build prompt
        tools = self._get_available_tools()
        tools_str = ", ".join(tools) if tools else "No tools available"

        # Get other Agents
        other_agents = []
        if self.agent_registry:
            other_agents = [
                a for a in self.agent_registry.get_all_agents()
                if a != self.agent_id
            ]
        agents_str = ", ".join(other_agents) if other_agents else "None"

        prompt = THINK_PROMPT.format(
            context=state.get_context(),
            task_type=task.task_type,
            parameters=json.dumps(task.parameters, default=str),
            findings_count=len(state.findings),
            iteration=state.iteration,
            max_iterations=state.max_iterations,
        )

        # Call LLM
        response = self.call_llm(prompt)

        if response is None:
            return "Unable to think. Will try a default action."

        return response.text if hasattr(response, 'text') else str(response)

    # =========================================================================
    # Task Handlers (Optional override of process_task)
    # =========================================================================

    def process_task(self, task: TaskAssignment) -> AgentResult:
        """
        Process Task

        Simple tasks are processed directly, complex tasks use ReAct loop
        """
        # Simple tasks: process directly
        if task.task_type == "scan_dangerous_imports":
            return self._scan_dangerous_imports(task)
        elif task.task_type == "check_dangerous_imports":
            return self._check_dangerous_imports(task)
        elif task.task_type in ("analyze_exports", "analyze_export_batch"):
            return self._analyze_exports(task)
        elif task.task_type == "initial_taint_scan":
            return self._initial_taint_scan(task)
        elif task.task_type == "find_attack_surface":
            return self._find_attack_surface(task)

        # Complex tasks: use ReAct loop
        return super().process_task(task)

    # =========================================================================
    # Specific Task Implementations
    # =========================================================================

    def _scan_dangerous_imports(self, task: TaskAssignment) -> AgentResult:
        """Scan for dangerous API imports"""
        max_apis = task.parameters.get("max_apis", 20)

        # Use check_dangerous_imports tool
        result = self.call_tool("check_dangerous_imports", {})

        findings = []
        next_tasks = []

        # MCPToolResult has success and data attributes
        if result and result.success and result.data:
            data = result.data
            dangerous_imports = data.get("dangerous_imports", []) if isinstance(data, dict) else []

            for item in dangerous_imports[:max_apis]:
                severity = item.get("severity", "Medium")
                confidence = 0.7 if severity == "Critical" else 0.5

                finding = {
                    "vuln_type": item.get("vuln_type", "UNKNOWN"),
                    "severity": severity,
                    "confidence": confidence,
                    "address": item.get("address"),
                    "sink_api": item.get("name"),
                    "cwe_id": item.get("cwe", ""),
                    "evidence": [f"Dangerous API import: {item.get('name')}"],
                }

                findings.append(finding)

                # Share finding
                self.share_finding(finding)

                # Delegate deep verification
                if confidence >= 0.6 and self.agent_registry:
                    verifier = self.agent_registry.select_best_for_capability(
                        AgentCapability.VERIFICATION
                    )
                    if verifier:
                        next_tasks.append(TaskAssignment.create(
                            task_type="deep_verify",
                            parameters={
                                "address": finding["address"],
                                "vuln_type": finding["vuln_type"],
                                "api": item.get("name"),
                                "delegated_from": self.agent_id,
                            },
                            priority=7
                        ))

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=findings,
                next_tasks=next_tasks,
                metadata={
                    "total_imports": data.get("total_imports", 0),
                    "dangerous_count": data.get("dangerous_count", 0),
                    "findings_count": len(findings),
                }
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error=f"Tool call failed: {result.error if result else 'no result'}"
        )

    def _check_dangerous_imports(self, task: TaskAssignment) -> AgentResult:
        """Check for dangerous imports"""
        result = self.call_tool("check_dangerous_imports", {})

        if result and result.success and result.data:
            data = result.data
            dangerous = data.get("dangerous_imports", []) if isinstance(data, dict) else []
            self._dangerous_apis_found = dangerous

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                artifacts={"dangerous_imports": dangerous},
                metadata={"count": len(dangerous)}
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error=f"Failed to check dangerous imports: {result.error if result else 'no result'}"
        )

    def _analyze_exports(self, task: TaskAssignment) -> AgentResult:
        """Analyze exported functions"""
        exports = task.parameters.get("exports", {})

        findings = []
        analyzed_count = 0

        for name, addr in exports.items():
            # Skip already analyzed
            if addr in self._analyzed_functions:
                continue

            # Execute taint analysis
            result = self.call_tool("analyze_taint_flow", {
                "func_address": addr,
                "func_name": name
            })

            analyzed_count += 1
            self._analyzed_functions.add(addr)

            if result and result.success and result.data:
                data = result.data
                paths = data.get("paths", []) if isinstance(data, dict) else []
                for path in paths:
                    confidence = path.get("confidence", 0)
                    if confidence >= 0.5:
                        sink = path.get("sink", {})
                        finding = {
                            "vuln_type": sink.get("vuln_type", "UNKNOWN"),
                            "severity": sink.get("severity", "Medium"),
                            "confidence": confidence,
                            "address": sink.get("address"),
                            "function": name,
                            "sink_api": sink.get("api"),
                            "evidence": [
                                f"Taint path: {path.get('source', {}).get('type', 'unknown')} -> {sink.get('api', 'unknown')}"
                            ],
                        }
                        findings.append(finding)
                        self.share_finding(finding)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            findings=findings,
            metadata={
                "exports_analyzed": analyzed_count,
                "findings_count": len(findings),
            }
        )

    def _initial_taint_scan(self, task: TaskAssignment) -> AgentResult:
        """Initial taint scan"""
        func_address = task.parameters.get("func_address")
        func_name = task.parameters.get("func_name", "unknown")

        if not func_address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing func_address parameter"
            )

        result = self.call_tool("analyze_taint_flow", {
            "func_address": func_address,
            "func_name": func_name
        })

        findings = []
        paths_found = 0

        if result and result.success and result.data:
            data = result.data
            paths = data.get("paths", []) if isinstance(data, dict) else []
            paths_found = data.get("taint_paths_found", len(paths)) if isinstance(data, dict) else 0

            for path in paths:
                if path.get("confidence", 0) >= 0.4:
                    sink = path.get("sink", {})
                    finding = {
                        "vuln_type": sink.get("vuln_type"),
                        "severity": sink.get("severity"),
                        "confidence": path.get("confidence"),
                        "address": sink.get("address"),
                        "function": func_name,
                        "sink_api": sink.get("api"),
                        "evidence": [f"Taint path found with {len(path.get('steps', []))} steps"],
                    }
                    findings.append(finding)
                    self.share_finding(finding)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            findings=findings,
            metadata={"paths_found": paths_found}
        )

    def _find_attack_surface(self, task: TaskAssignment) -> AgentResult:
        """Find attack surface"""
        # Check for dangerous imports
        imports_result = self.call_tool("check_dangerous_imports", {})

        findings = []
        attack_vectors = []

        if imports_result and imports_result.success and imports_result.data:
            data = imports_result.data
            dangerous_imports = data.get("dangerous_imports", []) if isinstance(data, dict) else []
            for api in dangerous_imports:
                attack_vectors.append({
                    "type": "dangerous_import",
                    "api": api.get("name"),
                    "vuln_type": api.get("vuln_type"),
                    "severity": api.get("severity", "Medium"),
                })

        # Request assistance from other Agents in the network
        next_tasks = []

        # If there is a Verifier Agent, delegate verification of high-risk APIs
        if self.agent_registry and attack_vectors:
            verifier = self.agent_registry.select_best_for_capability(
                AgentCapability.VERIFICATION
            )
            if verifier:
                for vector in attack_vectors[:5]:  # Delegate at most 5
                    next_tasks.append(TaskAssignment.create(
                        task_type="verify_dangerous_api",
                        parameters={
                            "api": vector["api"],
                            "vuln_type": vector["vuln_type"],
                        },
                        priority=6
                    ))

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            findings=findings,
            next_tasks=next_tasks,
            artifacts={"attack_vectors": attack_vectors},
            metadata={
                "vectors_found": len(attack_vectors),
            }
        )


