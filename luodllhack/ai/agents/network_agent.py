# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/network_agent.py
Networked Agent Base Class - ReAct + P2P Communication

Features:
    - ReAct Loop (Think-Act-Observe)
    - P2P Task Negotiation
    - Decentralized Collaboration
    - Independent LLM Instances
"""

import asyncio
import json
import logging
import time
import uuid
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Set, TYPE_CHECKING

from .base import (
    BaseAgent,
    AgentCapability,
    AgentMessage,
    MessageType,
    TaskAssignment,
    TaskStatus,
    AgentResult,
)

if TYPE_CHECKING:
    from .message_bus import MessageBus
    from .shared_state import SharedState
    from .registry import AgentRegistry

logger = logging.getLogger(__name__)


# =============================================================================
# Network Message Types
# =============================================================================

class NetworkMessageType(str, Enum):
    """Message types between networked Agents"""
    # Task negotiation
    TASK_OFFER = "task_offer"           # Task offered
    TASK_ACCEPT = "task_accept"         # Task accepted
    TASK_REJECT = "task_reject"         # Task rejected
    TASK_CONFIRM = "task_confirm"       # Allocation confirmed
    TASK_RESULT = "task_result"         # Task result
    TASK_CANCEL = "task_cancel"         # Task cancelled

    # Collaboration request
    HELP_REQUEST = "help_request"       # Requesting help
    HELP_OFFER = "help_offer"           # Offering help
    HELP_ACCEPT = "help_accept"         # Accepting help

    # Discovery sharing
    FINDING_BROADCAST = "finding_broadcast"  # Broadcast discovery
    FINDING_CONFIRM = "finding_confirm"      # Confirm discovery
    FINDING_DISPUTE = "finding_dispute"      # Dispute discovery

    # State sync
    STATE_SYNC = "state_sync"           # State synchronization
    HEARTBEAT = "heartbeat"             # Heartbeat

    # Registration/Discovery
    REGISTER = "register"               # Agent registration
    UNREGISTER = "unregister"           # Agent unregistration
    CAPABILITY_QUERY = "capability_query"    # Capability query
    CAPABILITY_RESPONSE = "capability_response"  # Capability response


# =============================================================================
# ReAct Action Types
# =============================================================================

class ReActActionType(str, Enum):
    """ReAct Action Types"""
    TOOL_CALL = "tool_call"             # Call local tool
    DELEGATE = "delegate"               # Delegate task to other Agent
    REQUEST_HELP = "request_help"       # Broadcast collaboration request
    FINAL_ANSWER = "final_answer"       # Finish and return discoveries
    THINK = "think"                     # Continue thinking
    WAIT = "wait"                       # Wait for other Agents


@dataclass
class ReActAction:
    """ReAct Action"""
    action_type: ReActActionType
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    target_agent: Optional[str] = None
    content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.action_type.value,
            "tool": self.tool_name,
            "arguments": self.tool_args,
            "target": self.target_agent,
            "content": self.content,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReActAction":
        return cls(
            action_type=ReActActionType(data.get("type", "think")),
            tool_name=data.get("tool"),
            tool_args=data.get("arguments", {}),
            target_agent=data.get("target"),
            content=data.get("content"),
            metadata=data.get("metadata", {})
        )


@dataclass
class ReActState:
    """ReAct Loop State"""
    thoughts: List[str] = field(default_factory=list)
    actions: List[ReActAction] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 15
    is_complete: bool = False
    final_answer: Optional[str] = None

    def add_thought(self, thought: str) -> None:
        self.thoughts.append(thought)

    def add_action(self, action: ReActAction) -> None:
        self.actions.append(action)

    def add_observation(self, observation: Dict[str, Any]) -> None:
        self.observations.append(observation)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)

    def get_context(self, max_history: int = 5) -> str:
        """Get context summary"""
        context_parts = []

        # Recent thoughts
        recent_thoughts = self.thoughts[-max_history:]
        if recent_thoughts:
            context_parts.append(f"Recent thoughts: {recent_thoughts}")

        # Recent actions and observations
        for i in range(max(0, len(self.actions) - max_history), len(self.actions)):
            action = self.actions[i]
            obs = self.observations[i] if i < len(self.observations) else {}
            context_parts.append(
                f"Step {i+1}: Action={action.action_type.value}, "
                f"Result={str(obs)[:200]}"
            )

        # Current discoveries
        if self.findings:
            context_parts.append(f"Findings so far: {len(self.findings)} items")

        return "\n".join(context_parts)


# =============================================================================
# Task Negotiation State
# =============================================================================

@dataclass
class TaskNegotiation:
    """Task Negotiation State"""
    task: TaskAssignment
    offered_to: Set[str] = field(default_factory=set)
    accepted_by: Optional[str] = None
    confirmed: bool = False
    created_at: float = field(default_factory=time.time)
    timeout: float = 30.0  # Negotiation timeout

    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.timeout


# =============================================================================
# NetworkAgent Base Class
# =============================================================================

class NetworkAgent(BaseAgent):
    """
    Networked Agent Base Class

    Supports:
    - ReAct Loop (Think-Act-Observe)
    - P2P Task Negotiation
    - Decentralized Collaboration
    - Independent LLM Instances

    Subclasses must implement:
    - role: Agent role
    - can_handle: Capability matching
    - _think: ReAct thinking stage
    - _get_available_tools: List of available tools
    """

    def __init__(
        self,
        agent_id: str,
        capabilities: List[AgentCapability],
        tool_registry: Any,
        message_bus: "MessageBus",
        shared_state: "SharedState",
        llm_pool: Any,
        agent_registry: Optional["AgentRegistry"] = None,
        config: Optional[Any] = None,
        max_react_iterations: int = 15,
        **kwargs
    ):
        """
        Initialize NetworkAgent

        Args:
            agent_id: Unique identifier
            capabilities: List of capabilities
            tool_registry: Tool registry
            message_bus: Message bus
            shared_state: Shared state
            llm_pool: LLM client pool (independent instance)
            agent_registry: Agent registry (optional)
            config: Configuration object
            max_react_iterations: Maximum number of ReAct iterations
        """
        super().__init__(
            agent_id=agent_id,
            capabilities=capabilities,
            tool_registry=tool_registry,
            message_bus=message_bus,
            shared_state=shared_state,
            llm_pool=llm_pool,
            config=config,
            **kwargs
        )

        self.agent_registry = agent_registry
        self.max_react_iterations = max_react_iterations

        # Task negotiation state
        self._pending_negotiations: Dict[str, TaskNegotiation] = {}
        self._delegated_tasks: Dict[str, str] = {}  # task_id -> target_agent

        # Help request state
        self._help_requests: Dict[str, Dict[str, Any]] = {}
        self._help_responses: Dict[str, List[Dict[str, Any]]] = {}

        # Discovery cache
        self._local_findings: List[Dict[str, Any]] = []
        self._shared_findings: Dict[str, Dict[str, Any]] = {}

        # Network statistics
        self._network_stats = {
            "tasks_delegated": 0,
            "tasks_received": 0,
            "help_requests_sent": 0,
            "help_requests_answered": 0,
            "findings_shared": 0,
            "findings_received": 0,
        }

        # Subscribe to network messages
        self._subscribe_network_messages()

        logger.info(
            f"NetworkAgent {self.agent_id} initialized with "
            f"capabilities: {[c.value for c in self.capabilities]}"
        )

    # =========================================================================
    # Abstract Methods
    # =========================================================================

    @abstractmethod
    def _think(self, state: ReActState, task: TaskAssignment) -> str:
        """
        ReAct Thinking Stage - Implemented by subclasses

        Args:
            state: ReAct state
            task: Current task

        Returns:
            Thinking result text
        """
        pass

    @abstractmethod
    def _get_available_tools(self) -> List[str]:
        """
        Get list of available tools - Implemented by subclasses

        Returns:
            List of tool names
        """
        pass

    # =========================================================================
    # ReAct Loop
    # =========================================================================

    def process_task(self, task: TaskAssignment) -> AgentResult:
        """
        Process task - Using ReAct loop

        Args:
            task: Task assignment

        Returns:
            Execution result
        """
        logger.info(f"Agent {self.agent_id} processing task {task.task_id} with ReAct")
        start_time = time.time()

        # Initialize ReAct state
        state = ReActState(max_iterations=self.max_react_iterations)

        try:
            # ReAct Loop
            while not state.is_complete and state.iteration < state.max_iterations:
                state.iteration += 1
                logger.debug(
                    f"Agent {self.agent_id} ReAct iteration "
                    f"{state.iteration}/{state.max_iterations}"
                )

                # 1. Think
                thought = self._think(state, task)
                state.add_thought(thought)
                logger.debug(f"Thought: {thought[:200]}...")

                # 2. Decide Action
                action = self._decide_action(thought, state, task)
                state.add_action(action)
                logger.info(
                    f"Agent {self.agent_id} action: {action.action_type.value}"
                )

                # 3. Act - Execute Action
                observation = self._execute_action(action, state, task)
                state.add_observation(observation)

                # 4. Check completion
                if action.action_type == ReActActionType.FINAL_ANSWER:
                    state.is_complete = True
                    state.final_answer = action.content

            # Build result
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=state.findings,
                artifacts={
                    "react_trace": {
                        "thoughts": state.thoughts,
                        "actions": [a.to_dict() for a in state.actions],
                        "observations": state.observations,
                        "final_answer": state.final_answer,
                    }
                },
                execution_time=time.time() - start_time,
                metadata={
                    "iterations": state.iteration,
                    "completed": state.is_complete,
                }
            )

        except Exception as e:
            logger.error(f"Agent {self.agent_id} ReAct error: {e}")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
                artifacts={
                    "react_trace": {
                        "thoughts": state.thoughts,
                        "actions": [a.to_dict() for a in state.actions],
                        "observations": state.observations,
                    }
                }
            )

    def _decide_action(
        self,
        thought: str,
        state: ReActState,
        task: TaskAssignment
    ) -> ReActAction:
        """
        Decide action based on thinking result

        Args:
            thought: Thinking result
            state: ReAct state
            task: Current task

        Returns:
            Action to be executed
        """
        # Build action decision prompt
        tools = self._get_available_tools()
        prompt = self._build_action_prompt(thought, tools, state)

        # Call LLM to decide action
        response = self.call_llm(prompt)

        if response is None:
            return ReActAction(action_type=ReActActionType.THINK)

        # Parse LLM response
        return self._parse_action_response(response, tools)

    def _build_action_prompt(
        self,
        thought: str,
        tools: List[str],
        state: ReActState
    ) -> str:
        """Build action decision prompt"""
        tools_str = ", ".join(tools) if tools else "No tools available"

        # Get known other Agents
        other_agents = []
        if self.agent_registry:
            other_agents = [
                a for a in self.agent_registry.get_all_agents()
                if a != self.agent_id
            ]
        agents_str = ", ".join(other_agents) if other_agents else "No other agents"

        return f"""Based on your thought, decide the next action.

Thought: {thought}

Available Tools: {tools_str}
Available Agents for delegation: {agents_str}

Context:
{state.get_context()}

Respond with a JSON object:
{{
    "type": "tool_call|delegate|request_help|final_answer",
    "tool": "tool_name",  // if type is tool_call
    "arguments": {{}},     // tool arguments
    "target": "agent_id", // if type is delegate
    "content": "..."      // if type is final_answer or request_help
}}
"""

    def _parse_action_response(
        self,
        response: Any,
        available_tools: List[str]
    ) -> ReActAction:
        """Parse LLM response into ReActAction"""
        # Check if there is a tool call
        if hasattr(response, 'has_tool_calls') and response.has_tool_calls:
            tc = response.tool_calls[0]
            return ReActAction(
                action_type=ReActActionType.TOOL_CALL,
                tool_name=tc.name,
                tool_args=tc.arguments if hasattr(tc, 'arguments') else {}
            )

        # Try to parse JSON
        text = response.text if hasattr(response, 'text') else str(response)
        try:
            import re
            match = re.search(r'\{[\s\S]*\}', text)
            if match:
                data = json.loads(match.group())
                return ReActAction.from_dict(data)
        except (json.JSONDecodeError, ValueError):
            pass

        # Return continue thinking as default
        return ReActAction(
            action_type=ReActActionType.THINK,
            content=text
        )

    def _execute_action(
        self,
        action: ReActAction,
        state: ReActState,
        task: TaskAssignment
    ) -> Dict[str, Any]:
        """
        Execute action

        Args:
            action: Action to be executed
            state: ReAct state
            task: Current task

        Returns:
            Observation result
        """
        if action.action_type == ReActActionType.TOOL_CALL:
            return self._execute_tool_call(action)

        elif action.action_type == ReActActionType.DELEGATE:
            return self._execute_delegate(action, task)

        elif action.action_type == ReActActionType.REQUEST_HELP:
            return self._execute_help_request(action, task)

        elif action.action_type == ReActActionType.FINAL_ANSWER:
            return {"status": "completed", "answer": action.content}

        elif action.action_type == ReActActionType.THINK:
            return {"status": "thinking", "thought": action.content}

        elif action.action_type == ReActActionType.WAIT:
            return {"status": "waiting"}

        return {"status": "unknown_action"}

    def _execute_tool_call(self, action: ReActAction) -> Dict[str, Any]:
        """Execute tool call"""
        if not action.tool_name:
            return {"success": False, "error": "No tool specified"}

        try:
            result = self.call_tool(action.tool_name, action.tool_args)
            return {
                "success": True,
                "tool": action.tool_name,
                "result": result
            }
        except Exception as e:
            return {
                "success": False,
                "tool": action.tool_name,
                "error": str(e)
            }

    def _execute_delegate(
        self,
        action: ReActAction,
        task: TaskAssignment
    ) -> Dict[str, Any]:
        """Execute task delegation"""
        target = action.target_agent
        if not target:
            return {"success": False, "error": "No target agent specified"}

        # Create sub-task
        sub_task = TaskAssignment.create(
            task_type=f"delegated_{task.task_type}",
            parameters={
                **task.parameters,
                "delegated_from": self.agent_id,
                "original_task_id": task.task_id,
                "delegation_content": action.content,
            },
            priority=task.priority
        )

        # Send task offer
        self._offer_task(sub_task, target)
        self._delegated_tasks[sub_task.task_id] = target
        self._network_stats["tasks_delegated"] += 1

        return {
            "success": True,
            "delegated_to": target,
            "sub_task_id": sub_task.task_id,
            "status": "waiting_for_acceptance"
        }

    def _execute_help_request(
        self,
        action: ReActAction,
        task: TaskAssignment
    ) -> Dict[str, Any]:
        """Execute help request"""
        request_id = f"help-{uuid.uuid4().hex[:8]}"

        # Broadcast help request
        msg = AgentMessage.create(
            msg_type=MessageType.BROADCAST,
            sender=self.agent_id,
            receiver=None,
            payload={
                "network_type": NetworkMessageType.HELP_REQUEST.value,
                "request_id": request_id,
                "task_id": task.task_id,
                "content": action.content,
                "capabilities_needed": list(action.metadata.get("capabilities", [])),
            },
            priority=7
        )
        self.message_bus.publish(msg)

        # Record request
        self._help_requests[request_id] = {
            "task_id": task.task_id,
            "content": action.content,
            "created_at": time.time(),
        }
        self._help_responses[request_id] = []
        self._network_stats["help_requests_sent"] += 1

        return {
            "success": True,
            "request_id": request_id,
            "status": "broadcast_sent"
        }

    # =========================================================================
    # Task Negotiation
    # =========================================================================

    def _offer_task(self, task: TaskAssignment, target: str) -> None:
        """
        Provide task to designated Agent

        Args:
            task: Task
            target: Target Agent ID
        """
        negotiation = TaskNegotiation(task=task)
        negotiation.offered_to.add(target)
        self._pending_negotiations[task.task_id] = negotiation

        msg = AgentMessage.create(
            msg_type=MessageType.REQUEST,
            sender=self.agent_id,
            receiver=target,
            payload={
                "network_type": NetworkMessageType.TASK_OFFER.value,
                "task_id": task.task_id,
                "task_type": task.task_type,
                "parameters": task.parameters,
                "priority": task.priority,
            },
            priority=task.priority
        )
        self.message_bus.publish(msg)

    def _broadcast_task_offer(self, task: TaskAssignment) -> None:
        """
        Broadcast task offer (looking for Agents willing to accept)

        Args:
            task: Task
        """
        negotiation = TaskNegotiation(task=task)
        self._pending_negotiations[task.task_id] = negotiation

        msg = AgentMessage.create(
            msg_type=MessageType.BROADCAST,
            sender=self.agent_id,
            receiver=None,
            payload={
                "network_type": NetworkMessageType.TASK_OFFER.value,
                "task_id": task.task_id,
                "task_type": task.task_type,
                "parameters": task.parameters,
                "priority": task.priority,
            },
            priority=task.priority
        )
        self.message_bus.publish(msg)

    def _handle_task_offer(self, message: AgentMessage) -> None:
        """Handle received task offer"""
        payload = message.payload
        task_id = payload.get("task_id")
        task_type = payload.get("task_type")
        parameters = payload.get("parameters", {})
        priority = payload.get("priority", 5)

        # Create task object
        task = TaskAssignment(
            task_id=task_id,
            task_type=task_type,
            parameters=parameters,
            priority=priority
        )

        # Check if can handle
        confidence = self.can_handle(task)

        if confidence > 0:
            # Send acceptance message
            accept_msg = AgentMessage.create(
                msg_type=MessageType.RESPONSE,
                sender=self.agent_id,
                receiver=message.sender,
                payload={
                    "network_type": NetworkMessageType.TASK_ACCEPT.value,
                    "task_id": task_id,
                    "confidence": confidence,
                },
                priority=priority + 1
            )
            self.message_bus.publish(accept_msg)
            self._network_stats["tasks_received"] += 1
        else:
            # Send rejection message
            reject_msg = AgentMessage.create(
                msg_type=MessageType.RESPONSE,
                sender=self.agent_id,
                receiver=message.sender,
                payload={
                    "network_type": NetworkMessageType.TASK_REJECT.value,
                    "task_id": task_id,
                    "reason": "Cannot handle this task type",
                },
                priority=priority
            )
            self.message_bus.publish(reject_msg)

    def _handle_task_accept(self, message: AgentMessage) -> None:
        """Handle task accepted message"""
        payload = message.payload
        task_id = payload.get("task_id")
        confidence = payload.get("confidence", 0)

        negotiation = self._pending_negotiations.get(task_id)
        if not negotiation:
            return

        # If not confirmed yet, select this Agent
        if not negotiation.confirmed:
            negotiation.accepted_by = message.sender
            negotiation.confirmed = True

            # Send confirmation message
            confirm_msg = AgentMessage.create(
                msg_type=MessageType.REQUEST,
                sender=self.agent_id,
                receiver=message.sender,
                payload={
                    "network_type": NetworkMessageType.TASK_CONFIRM.value,
                    "task_id": task_id,
                },
                priority=negotiation.task.priority + 2
            )
            self.message_bus.publish(confirm_msg)

    def _handle_task_confirm(self, message: AgentMessage) -> None:
        """Handle task confirmed message"""
        payload = message.payload
        task_id = payload.get("task_id")

        # Start processing task
        # Get task information from original offer...
        logger.info(f"Agent {self.agent_id} confirmed to handle task {task_id}")

    def _handle_task_result(self, message: AgentMessage) -> None:
        """Handle task result message"""
        payload = message.payload
        task_id = payload.get("task_id")
        result = payload.get("result")

        # Remove from delegated tasks
        if task_id in self._delegated_tasks:
            del self._delegated_tasks[task_id]

        logger.info(f"Agent {self.agent_id} received result for delegated task {task_id}")

    # =========================================================================
    # Discovery Sharing
    # =========================================================================

    def share_finding(self, finding: Dict[str, Any]) -> None:
        """
        Share discovery to all Agents

        Args:
            finding: Discovery data
        """
        finding_id = f"finding-{uuid.uuid4().hex[:8]}"
        finding["finding_id"] = finding_id
        finding["discovered_by"] = self.agent_id
        finding["timestamp"] = time.time()

        # Save locally
        self._local_findings.append(finding)

        # Broadcast
        msg = AgentMessage.create(
            msg_type=MessageType.BROADCAST,
            sender=self.agent_id,
            receiver=None,
            payload={
                "network_type": NetworkMessageType.FINDING_BROADCAST.value,
                "finding": finding,
            },
            priority=8
        )
        self.message_bus.publish(msg)
        self._network_stats["findings_shared"] += 1

    def _handle_finding_broadcast(self, message: AgentMessage) -> None:
        """Handle discovery broadcast"""
        finding = message.payload.get("finding", {})
        finding_id = finding.get("finding_id")

        if finding_id and finding_id not in self._shared_findings:
            self._shared_findings[finding_id] = finding
            self._network_stats["findings_received"] += 1
            logger.info(
                f"Agent {self.agent_id} received finding {finding_id} "
                f"from {message.sender}"
            )

    # =========================================================================
    # Message Subscription
    # =========================================================================

    def _subscribe_network_messages(self) -> None:
        """Subscribe to network messages"""
        # Override _handle_broadcast to handle network messages
        pass

    def _handle_broadcast(self, message: AgentMessage) -> None:
        """Handle broadcast messages"""
        payload = message.payload
        network_type = payload.get("network_type")

        if network_type == NetworkMessageType.TASK_OFFER.value:
            self._handle_task_offer(message)
        elif network_type == NetworkMessageType.HELP_REQUEST.value:
            self._handle_help_request_message(message)
        elif network_type == NetworkMessageType.FINDING_BROADCAST.value:
            self._handle_finding_broadcast(message)
        else:
            # Call parent class to handle
            super()._handle_broadcast(message)

    def _handle_request(self, message: AgentMessage) -> None:
        """Handle request message"""
        payload = message.payload
        network_type = payload.get("network_type")

        if network_type == NetworkMessageType.TASK_OFFER.value:
            self._handle_task_offer(message)
        elif network_type == NetworkMessageType.TASK_CONFIRM.value:
            self._handle_task_confirm(message)
        else:
            # Call parent class to handle
            super()._handle_request(message)

    def _handle_response(self, message: AgentMessage) -> None:
        """Handle response message"""
        payload = message.payload
        network_type = payload.get("network_type")

        if network_type == NetworkMessageType.TASK_ACCEPT.value:
            self._handle_task_accept(message)
        elif network_type == NetworkMessageType.TASK_REJECT.value:
            self._handle_task_reject(message)
        elif network_type == NetworkMessageType.TASK_RESULT.value:
            self._handle_task_result(message)
        elif network_type == NetworkMessageType.HELP_OFFER.value:
            self._handle_help_offer(message)
        else:
            # Call parent class to handle
            super()._handle_response(message)

    def _handle_task_reject(self, message: AgentMessage) -> None:
        """Handle task rejected message"""
        payload = message.payload
        task_id = payload.get("task_id")
        reason = payload.get("reason", "Unknown")
        logger.debug(
            f"Agent {self.agent_id}: task {task_id} rejected by "
            f"{message.sender}: {reason}"
        )

    def _handle_help_request_message(self, message: AgentMessage) -> None:
        """Handle help request message"""
        payload = message.payload
        request_id = payload.get("request_id")
        content = payload.get("content")
        capabilities_needed = payload.get("capabilities_needed", [])

        # Check if can provide help
        can_help = False
        if capabilities_needed:
            for cap in capabilities_needed:
                try:
                    cap_enum = AgentCapability(cap)
                    if cap_enum in self.capabilities:
                        can_help = True
                        break
                except ValueError:
                    pass
        else:
            # No capacity specified, can try to help by default
            can_help = True

        if can_help:
            # Send help offer
            offer_msg = AgentMessage.create(
                msg_type=MessageType.RESPONSE,
                sender=self.agent_id,
                receiver=message.sender,
                payload={
                    "network_type": NetworkMessageType.HELP_OFFER.value,
                    "request_id": request_id,
                    "capabilities": [c.value for c in self.capabilities],
                },
                priority=6
            )
            self.message_bus.publish(offer_msg)
            self._network_stats["help_requests_answered"] += 1

    def _handle_help_offer(self, message: AgentMessage) -> None:
        """Handle help offer message"""
        payload = message.payload
        request_id = payload.get("request_id")
        capabilities = payload.get("capabilities", [])

        if request_id in self._help_responses:
            self._help_responses[request_id].append({
                "agent_id": message.sender,
                "capabilities": capabilities,
            })

    # =========================================================================
    # Status Query
    # =========================================================================

    def get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics information"""
        return {
            **self._network_stats,
            "pending_negotiations": len(self._pending_negotiations),
            "delegated_tasks": len(self._delegated_tasks),
            "help_requests": len(self._help_requests),
            "local_findings": len(self._local_findings),
            "shared_findings": len(self._shared_findings),
        }

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all discoveries (local + shared)"""
        all_findings = list(self._local_findings)
        for finding_id, finding in self._shared_findings.items():
            if finding not in all_findings:
                all_findings.append(finding)
        return all_findings
