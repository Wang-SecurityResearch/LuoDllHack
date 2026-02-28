# -*- coding: utf-8 -*-
"""
luodllhack/ai/react/network_loop.py
Networked ReAct Loop - Supports Agent Network actions

Extends standard ReAct loop to support:
- tool_call: Call local tools
- delegate: Delegate tasks to other agents
- request_help: Broadcast collaboration requests
- final_answer: Finish and return findings
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, TYPE_CHECKING

from .token_manager import TokenManager
from ..tools.types import ToolResultType, AgentState, VulnReport

if TYPE_CHECKING:
    from ..tools.registry import ToolRegistry
    from ..agents.network_agent import NetworkAgent
    from ..agents.registry import AgentRegistry

logger = logging.getLogger(__name__)


# =============================================================================
# Action Types
# =============================================================================

class NetworkActionType(str, Enum):
    """Network ReAct Action Types"""
    TOOL_CALL = "tool_call"           # Call local tool
    DELEGATE = "delegate"             # Delegate task
    REQUEST_HELP = "request_help"     # Request help
    FINAL_ANSWER = "final_answer"     # Final answer
    WAIT_RESPONSE = "wait_response"   # Wait for response
    SHARE_FINDING = "share_finding"   # Share finding


@dataclass
class NetworkAction:
    """Network Action"""
    action_type: NetworkActionType
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    target_agent: Optional[str] = None
    content: Optional[str] = None
    finding: Optional[Dict[str, Any]] = None
    wait_for: Optional[str] = None  # Request ID to wait for
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkReActState:
    """Networked ReAct State"""
    # Standard ReAct state
    current_step: int = 0
    max_steps: int = 20
    should_stop: bool = False
    token_used: int = 0
    token_budget: int = 100000

    # Thought/Action/Observation history
    thoughts: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)

    # Findings
    findings: List[Dict[str, Any]] = field(default_factory=list)

    # Network state
    pending_delegations: Dict[str, str] = field(default_factory=dict)  # task_id -> agent_id
    pending_help_requests: Dict[str, Dict] = field(default_factory=dict)
    received_responses: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# NetworkReActLoop
# =============================================================================

class NetworkReActLoop:
    """
    Networked ReAct Loop

    Supports:
    - Local tool calls
    - Task delegation
    - Collaboration requests
    - Finding sharing
    """

    ABSOLUTE_MAX_STEPS = 60

    def __init__(
        self,
        tools: 'ToolRegistry',
        agent: 'NetworkAgent',
        agent_registry: Optional['AgentRegistry'] = None,
        report: Optional[VulnReport] = None,
        send_message_func: Callable[[Any, str], Any] = None,
        agent_name: str = "network_agent"
    ):
        """
        Initialize networked ReAct loop

        Args:
            tools: Tool registry
            agent: Network Agent
            agent_registry: Agent registry center
            report: Vulnerability report
            send_message_func: Send message function
            agent_name: Agent name
        """
        self.tools = tools
        self.agent = agent
        self.agent_registry = agent_registry
        self.report = report or VulnReport(binary_path="", exports=[])
        self.send_message = send_message_func
        self.agent_name = agent_name

        # Action parsers
        self._action_parsers: Dict[str, Callable] = {
            "tool_call": self._parse_tool_call,
            "delegate": self._parse_delegate,
            "request_help": self._parse_request_help,
            "final_answer": self._parse_final_answer,
            "share_finding": self._parse_share_finding,
        }

    def run(self, chat: Any, system_prompt: str) -> VulnReport:
        """
        Execute networked ReAct loop

        Args:
            chat: LLM chat object
            system_prompt: System prompt

        Returns:
            Vulnerability report
        """
        state = NetworkReActState()
        print(f"\n[*] Starting Network ReAct loop ({self.agent_name})...")

        while not state.should_stop and state.current_step < state.max_steps:
            state.current_step += 1
            print(f"\n--- Step {state.current_step}/{state.max_steps} ({self.agent_name}) ---")

            try:
                # 1. Think - Call LLM to reason
                if state.current_step == 1:
                    prompt = self._build_initial_prompt(system_prompt, state)
                else:
                    prompt = self._build_step_prompt(state)

                response = self.send_message(chat, prompt)
                thought = self._extract_thought(response)
                self.state.thoughts.append(thought)
                print(f"[Think] {thought[:500]}...")

                # 2. Decide Action - Parse action
                action = self._parse_action(response, state)
                state.actions.append({
                    "step": state.current_step,
                    "type": action.action_type.value,
                    "tool": action.tool_name,
                    "target": action.target_agent,
                })

                # 3. Act - Execute action
                observation = self._execute_action(action, state)
                state.observations.append(observation)
                print(f"[Observe] {observation[:500]}...")

                # 4. Check findings
                self._check_for_findings(action, state)

                # 5. Check completion
                if action.action_type == NetworkActionType.FINAL_ANSWER:
                    state.should_stop = True

            except Exception as e:
                logger.exception(f"Network ReAct error at step {state.current_step}")
                state.observations.append(f"Error: {e}")

            # Token management
            self._manage_tokens(state)

            # Auto-extension
            self._check_auto_extend(state)

        # Finalize report
        self._finalize_report(state)
        return self.report

    def _build_initial_prompt(self, system_prompt: str, state: NetworkReActState) -> str:
        """Build initial prompt"""
        # Get available Agent info
        available_agents = ""
        if self.agent_registry:
            agents = self.agent_registry.get_all_agent_info()
            agent_list = [
                f"  - {a.agent_id} ({a.role}): {[c.value for c in a.capabilities]}"
                for a in agents if a.agent_id != self.agent.agent_id
            ]
            if agent_list:
                available_agents = "\n".join(agent_list)
            else:
                available_agents = "  No other agents available"

        # Get tool info
        tool_names = [t["name"] for t in self.tools.tool_schemas]
        tools_str = ", ".join(tool_names)

        return f"""{system_prompt}

## Network Capabilities

You are part of a decentralized agent network. You can:

1. **Call Tools**: Use local analysis tools
   Action: {{"type": "tool_call", "tool": "tool_name", "arguments": {{...}}}}

2. **Delegate Tasks**: Send sub-tasks to other agents
   Action: {{"type": "delegate", "target": "agent_id", "task": "description", "parameters": {{...}}}}

3. **Request Help**: Broadcast a help request to all agents
   Action: {{"type": "request_help", "request": "what you need help with", "capabilities_needed": ["capability1"]}}

4. **Share Findings**: Share a vulnerability finding with the network
   Action: {{"type": "share_finding", "finding": {{...}}}}

5. **Final Answer**: Complete analysis and return results
   Action: {{"type": "final_answer", "summary": "...", "findings": [...]}}

## Available Tools
{tools_str}

## Available Agents
{available_agents}

## Instructions
- Analyze the target systematically
- Use tools to gather evidence
- Delegate specialized tasks to appropriate agents
- Share significant findings with the network
- Provide final answer when analysis is complete
"""

    def _build_step_prompt(self, state: NetworkReActState) -> str:
        """Build step prompt"""
        # Recent observations
        last_obs = state.observations[-1] if state.observations else "No observations yet"
        last_obs = TokenManager.truncate_text(last_obs, max_tokens=4000)

        # Pending responses
        pending_info = ""
        if state.pending_delegations:
            pending_info += f"\nPending delegations: {list(state.pending_delegations.keys())}"
        if state.pending_help_requests:
            pending_info += f"\nPending help requests: {list(state.pending_help_requests.keys())}"
        if state.received_responses:
            pending_info += f"\nReceived responses: {json.dumps(state.received_responses, default=str)[:1000]}"

        return f"""Previous observation:
{last_obs}
{pending_info}

Current findings count: {len(state.findings)}

Think about what to do next, then provide your action as a JSON object.
"""

    def _extract_thought(self, response: Any) -> str:
        """Extract thought from response"""
        if not response:
            return "Unable to process"

        if hasattr(response, 'candidates') and response.candidates:
            for part in response.candidates[0].content.parts:
                if hasattr(part, 'text') and part.text:
                    return part.text

        if hasattr(response, 'text'):
            return response.text

        return str(response)

    def _parse_action(self, response: Any, state: NetworkReActState) -> NetworkAction:
        """Parse response as action"""
        # Check function call
        if hasattr(response, 'candidates') and response.candidates:
            for part in response.candidates[0].content.parts:
                if hasattr(part, 'function_call') and part.function_call:
                    fc = part.function_call
                    return NetworkAction(
                        action_type=NetworkActionType.TOOL_CALL,
                        tool_name=fc.name,
                        tool_args={k: v for k, v in fc.args.items()} if fc.args else {}
                    )

        # Try parsing JSON from text
        text = self._extract_thought(response)
        try:
            match = re.search(r'\{[\s\S]*\}', text)
            if match:
                data = json.loads(match.group())
                action_type = data.get("type", "tool_call")

                if action_type in self._action_parsers:
                    return self._action_parsers[action_type](data)

        except (json.JSONDecodeError, ValueError) as e:
            logger.debug(f"Failed to parse action JSON: {e}")

        # Default to continue analysis
        return NetworkAction(action_type=NetworkActionType.TOOL_CALL)

    def _parse_tool_call(self, data: Dict) -> NetworkAction:
        """Parse tool call"""
        return NetworkAction(
            action_type=NetworkActionType.TOOL_CALL,
            tool_name=data.get("tool"),
            tool_args=data.get("arguments", {})
        )

    def _parse_delegate(self, data: Dict) -> NetworkAction:
        """Parse task delegation"""
        return NetworkAction(
            action_type=NetworkActionType.DELEGATE,
            target_agent=data.get("target"),
            content=data.get("task"),
            metadata={
                "parameters": data.get("parameters", {}),
                "priority": data.get("priority", 5),
            }
        )

    def _parse_request_help(self, data: Dict) -> NetworkAction:
        """Parse help request"""
        return NetworkAction(
            action_type=NetworkActionType.REQUEST_HELP,
            content=data.get("request"),
            metadata={
                "capabilities_needed": data.get("capabilities_needed", []),
            }
        )

    def _parse_final_answer(self, data: Dict) -> NetworkAction:
        """Parse final answer"""
        return NetworkAction(
            action_type=NetworkActionType.FINAL_ANSWER,
            content=data.get("summary"),
            finding=data.get("findings")
        )

    def _parse_share_finding(self, data: Dict) -> NetworkAction:
        """Parse finding sharing"""
        return NetworkAction(
            action_type=NetworkActionType.SHARE_FINDING,
            finding=data.get("finding")
        )

    def _execute_action(self, action: NetworkAction, state: NetworkReActState) -> str:
        """Execute action"""
        if action.action_type == NetworkActionType.TOOL_CALL:
            return self._execute_tool_call(action)

        elif action.action_type == NetworkActionType.DELEGATE:
            return self._execute_delegate(action, state)

        elif action.action_type == NetworkActionType.REQUEST_HELP:
            return self._execute_request_help(action, state)

        elif action.action_type == NetworkActionType.SHARE_FINDING:
            return self._execute_share_finding(action)

        elif action.action_type == NetworkActionType.FINAL_ANSWER:
            return f"Analysis complete. Summary: {action.content}"

        return "Unknown action type"

    def _execute_tool_call(self, action: NetworkAction) -> str:
        """Execute tool call"""
        if not action.tool_name:
            return "Error: No tool specified"

        print(f"[Tool Call] {action.tool_name}")
        result = self.tools.call_tool(action.tool_name, action.tool_args)

        if result.status == ToolResultType.SUCCESS:
            result_str = TokenManager.summarize_tool_result(
                action.tool_name, result.data, max_chars=2200
            )
            print(f"[Tool Result] Success ({result.execution_time:.2f}s)")
            return result_str
        else:
            return f"Error: {result.error}"

    def _execute_delegate(self, action: NetworkAction, state: NetworkReActState) -> str:
        """Execute task delegation"""
        target = action.target_agent
        if not target:
            return "Error: No target agent specified"

        if not self.agent_registry:
            return "Error: No agent registry available"

        # Check if target Agent exists
        agent_info = self.agent_registry.get_agent(target)
        if not agent_info:
            return f"Error: Agent {target} not found"

        if not agent_info.is_available():
            return f"Error: Agent {target} is not available"

        # Send delegation via NetworkAgent
        import uuid
        task_id = f"del-{uuid.uuid4().hex[:8]}"

        # Simulate delegation (actually via MessageBus)
        state.pending_delegations[task_id] = target
        print(f"[Delegate] Task {task_id} -> {target}")

        return f"Task delegated to {target}. Task ID: {task_id}. Waiting for result..."

    def _execute_request_help(self, action: NetworkAction, state: NetworkReActState) -> str:
        """Execute help request"""
        import uuid
        request_id = f"help-{uuid.uuid4().hex[:8]}"

        state.pending_help_requests[request_id] = {
            "content": action.content,
            "capabilities": action.metadata.get("capabilities_needed", []),
            "created_at": time.time(),
        }

        print(f"[Help Request] {request_id}: {action.content}")
        return f"Help request broadcast. Request ID: {request_id}. Waiting for responses..."

    def _execute_share_finding(self, action: NetworkAction) -> str:
        """Execute finding sharing"""
        if not action.finding:
            return "Error: No finding to share"

        # Share via NetworkAgent
        self.agent.share_finding(action.finding)
        print(f"[Share Finding] {action.finding.get('vuln_type', 'Unknown')}")

        return f"Finding shared with network: {json.dumps(action.finding)[:200]}..."

    def _check_for_findings(self, action: NetworkAction, state: NetworkReActState) -> None:
        """Check and record findings"""
        if action.action_type == NetworkActionType.FINAL_ANSWER:
            if action.finding:
                if isinstance(action.finding, list):
                    state.findings.extend(action.finding)
                else:
                    state.findings.append(action.finding)

        elif action.action_type == NetworkActionType.SHARE_FINDING:
            if action.finding:
                state.findings.append(action.finding)

    def _manage_tokens(self, state: NetworkReActState) -> None:
        """Manage token usage"""
        total_tokens = sum(
            TokenManager.estimate_tokens(obs)
            for obs in state.observations
        )
        state.token_used = total_tokens

        if state.token_used > state.token_budget:
            print(f"[Token] Budget exceeded, truncating...")
            state.observations = TokenManager.truncate_observations(
                state.observations,
                state.token_budget // 2
            )

    def _check_auto_extend(self, state: NetworkReActState) -> None:
        """Check if auto-extension is needed"""
        if state.should_stop:
            return

        if state.current_step < state.max_steps:
            return

        if state.max_steps >= self.ABSOLUTE_MAX_STEPS:
            print(f"\n[!] Reached absolute max steps ({self.ABSOLUTE_MAX_STEPS})")
            return

        # If there are pending delegations, extend
        if state.pending_delegations:
            extension = 5
            state.max_steps = min(state.max_steps + extension, self.ABSOLUTE_MAX_STEPS)
            print(f"\n[*] Extended steps (+{extension}) for pending delegations")

    def _finalize_report(self, state: NetworkReActState) -> None:
        """Finalize report"""
        self.report.findings = state.findings
        self.report.analysis_trace = state.actions

        # Set risk level
        if any(f.get("severity") == "Critical" for f in state.findings):
            self.report.risk_level = "Critical"
        elif any(f.get("severity") == "High" for f in state.findings):
            self.report.risk_level = "High"
        elif state.findings:
            self.report.risk_level = "Medium"
        else:
            self.report.risk_level = "Low"
