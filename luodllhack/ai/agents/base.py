# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/base.py
Agent Base Class and Core Data Structures

Definitions:
    - AgentCapability: Agent capability enumeration
    - AgentMessage: Communication message between Agents
    - TaskAssignment: Task assignment
    - AgentResult: Task result
    - BaseAgent: Agent abstract base class

Communication Model:
    Agent supports two task processing modes:

    1. Direct Call Mode (Used by Orchestrator):
       Orchestrator.executor -> agent.process_task() -> returns AgentResult
       - Synchronous execution, result returned directly
       - Does not go through the internal task queue

    2. Message Bus Mode (Independent use or collaboration):
       MessageBus -> agent._task_queue -> internal loop processing -> _notify_result
       - Asynchronous execution, result returned via MessageBus
       - Supports collaboration between Agents

See: communication.py for complete communication protocol definitions
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Union, TYPE_CHECKING
from queue import Queue, Empty
import threading
import time
import uuid
import logging

if TYPE_CHECKING:
    from .message_bus import MessageBus
    from .shared_state import SharedState
    from .llm_backend import LLMBackend


from .prompt_engineering import PromptTemplate

logger = logging.getLogger(__name__)


# =============================================================================
# Enumerations
# =============================================================================

class AgentCapability(Enum):
    """Enumeration of Agent capabilities, used for task matching"""
    DISCOVERY = "discovery"           # Discover attack points
    TAINT_ANALYSIS = "taint"          # Data flow tracking
    VERIFICATION = "verification"     # Reduce false positives
    EXPLOITATION = "exploitation"     # PoC generation
    VALIDATION = "validation"         # Dynamic validation
    REVIEW = "review"                 # Quality review


class MessageType(str, Enum):
    """Message types"""
    TASK = "task"                     # Task assignment
    RESULT = "result"                 # Task result
    REQUEST = "request"               # P2P request
    RESPONSE = "response"             # Request response
    BROADCAST = "broadcast"           # Broadcast message
    HEARTBEAT = "heartbeat"           # Heartbeat
    SHUTDOWN = "shutdown"             # Shutdown signal
    ACK = "ack"                       # Message acknowledgment


class TaskStatus(str, Enum):
    """Task status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class AgentMessage:
    """Communication message between Agents"""
    msg_id: str
    msg_type: MessageType
    sender: str                       # Agent ID
    receiver: Optional[str]           # Agent ID or None (broadcast)
    payload: Dict[str, Any]
    priority: int = 5                 # 1-10, higher is more priority
    timestamp: float = field(default_factory=time.time)
    requires_ack: bool = False
    correlation_id: Optional[str] = None  # Used for request-response correlation
    ttl: float = 300.0                # Message time-to-live (seconds)

    @classmethod
    def create(
        cls,
        msg_type: MessageType,
        sender: str,
        payload: Dict[str, Any],
        receiver: Optional[str] = None,
        priority: int = 5,
        correlation_id: Optional[str] = None,
        requires_ack: bool = False
    ) -> "AgentMessage":
        """Factory method to create a message"""
        return cls(
            msg_id=f"msg-{uuid.uuid4().hex[:12]}",
            msg_type=msg_type,
            sender=sender,
            receiver=receiver,
            payload=payload,
            priority=priority,
            correlation_id=correlation_id,
            requires_ack=requires_ack
        )

    def is_expired(self) -> bool:
        """Check if message is expired"""
        return time.time() - self.timestamp > self.ttl


@dataclass
class TaskAssignment:
    """Task assignment"""
    task_id: str
    task_type: str
    parameters: Dict[str, Any]
    priority: int = 5                 # 1-10
    status: TaskStatus = TaskStatus.PENDING
    deadline: Optional[float] = None  # Unix timestamp
    dependencies: List[str] = field(default_factory=list)  # Dependency task_ids
    assigned_to: Optional[str] = None  # Agent ID
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3

    @classmethod
    def create(
        cls,
        task_type: str,
        parameters: Dict[str, Any],
        priority: int = 5,
        dependencies: List[str] = None
    ) -> "TaskAssignment":
        """Factory method to create a task"""
        return cls(
            task_id=f"task-{uuid.uuid4().hex[:12]}",
            task_type=task_type,
            parameters=parameters,
            priority=priority,
            dependencies=dependencies or []
        )

    def can_retry(self) -> bool:
        """Check if retry is possible"""
        return self.retry_count < self.max_retries

    def is_overdue(self) -> bool:
        """Check if overdue"""
        if self.deadline is None:
            return False
        return time.time() > self.deadline


@dataclass
class AgentResult:
    """Agent task execution result"""
    task_id: str
    agent_id: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)  # PoC code, constraints, etc.
    next_tasks: List[TaskAssignment] = field(default_factory=list)  # Follow-up tasks
    messages: List[AgentMessage] = field(default_factory=list)  # Messages to be sent
    execution_time: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding"""
        self.findings.append(finding)

    def add_next_task(
        self,
        task_type: str,
        parameters: Dict[str, Any],
        priority: int = 5
    ) -> None:
        """Add a follow-up task"""
        task = TaskAssignment.create(task_type, parameters, priority)
        self.next_tasks.append(task)

    def set_artifact(self, key: str, value: Any) -> None:
        """Set an artifact"""
        self.artifacts[key] = value


# =============================================================================
# Agent Base Class
# =============================================================================

from .memory import AgentMemory

class BaseAgent(ABC):
    """
    Agent Abstract Base Class

    All concrete Agents must implement:
        - role: Role name
        - can_handle: Determine if task can be handled
        - process_task: Process task

    Lifecycle:
        1. __init__: Initialization
        2. start: Start background thread
        3. process_task: Process task (loop)
        4. stop: Shutdown
    """

    def __init__(
        self,
        agent_id: str,
        capabilities: List[AgentCapability],
        tool_registry: Any,
        message_bus: "MessageBus",
        shared_state: "SharedState",
        llm_pool: Any,  # LLMClientPool - Required
        config: Optional[Any] = None,
        max_concurrent_tasks: int = 3
    ):
        """
        Initialize Agent (Unified Version)

        Args:
            agent_id: Unique identifier
            capabilities: List of capabilities
            tool_registry: Tool registry
            message_bus: Message bus
            shared_state: Shared state
            llm_pool: LLM client pool (required)
            config: Configuration object
            max_concurrent_tasks: Maximum number of concurrent tasks
        """
        self.agent_id = agent_id
        self.capabilities = set(capabilities)
        self.tools = tool_registry
        self.message_bus = message_bus
        self.shared_state = shared_state
        self.llm_pool = llm_pool
        self.config = config

        # Function Calling support
        self._tool_definitions: List[Dict[str, Any]] = []

        # Async LLM support (enabled by default)
        self._async_llm = None
        self._init_async_llm()

        # Collaboration support (enabled by default)
        self._pending_help_requests: Dict[str, Any] = {}
        self._help_responses: Dict[str, List] = {}
        self._shared_knowledge: List = []
        self._collaboration_stats = {
            "help_requests_sent": 0,
            "help_responses_received": 0,
            "help_requests_answered": 0,
            "knowledge_shared": 0,
            "knowledge_received": 0
        }

        # Memory learned support (enabled by default)
        self.memory = AgentMemory()
        self._enable_learning = True

        # ReAct mode support
        self.max_react_iterations = 10  # Maximum number of ReAct iterations

        # Internal state
        self._running = False
        self._task_queue: Queue[TaskAssignment] = Queue()
        self._pending_results: Dict[str, AgentResult] = {}
        self._response_events: Dict[str, threading.Event] = {}
        self._response_data: Dict[str, Optional[Dict]] = {}
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None

        # Concurrent processing
        self._executor: Optional[Any] = None
        self._active_futures: Dict[Any, TaskAssignment] = {}
        self._max_concurrent_tasks = max_concurrent_tasks

        # Statistics
        self._stats = {
            "tasks_processed": 0,
            "tasks_succeeded": 0,
            "tasks_failed": 0,
            "total_execution_time": 0.0,
            "start_time": None,
        }

        # Subscribe to messages
        self.message_bus.subscribe(self.agent_id, self._on_message)

        logger.info(f"Agent {self.agent_id} initialized with capabilities: {[c.value for c in self.capabilities]}")

    @property
    @abstractmethod
    def role(self) -> str:
        """Return Agent role name"""
        pass

    @abstractmethod
    def can_handle(self, task: TaskAssignment) -> float:
        """
        Determine if task can be handled

        Args:
            task: Task assignment

        Returns:
            Confidence level 0-1, 0 means cannot handle
        """
        pass

    @abstractmethod
    def process_task(self, task: TaskAssignment) -> AgentResult:
        """
        Process task

        Args:
            task: Task assignment

        Returns:
            Execution result
        """
        pass

    # =========================================================================
    # Lifecycle Management
    # =========================================================================

    def start(self, concurrent: bool = False) -> None:
        """
        Start Agent background processing thread

        Args:
            concurrent: Whether to enable concurrent task processing
        """
        if self._running:
            logger.warning(f"Agent {self.agent_id} is already running")
            return

        self._running = True
        self._stats["start_time"] = time.time()

        # If concurrent is enabled, create a thread pool
        if concurrent:
            from concurrent.futures import ThreadPoolExecutor
            self._executor = ThreadPoolExecutor(
                max_workers=self._max_concurrent_tasks,
                thread_name_prefix=f"Agent-{self.agent_id}"
            )
            logger.info(f"Agent {self.agent_id} starting with concurrent processing (workers={self._max_concurrent_tasks})")
            self._thread = threading.Thread(
                target=self._run_loop_concurrent,
                name=f"Agent-{self.agent_id}-dispatcher",
                daemon=True
            )
        else:
            logger.info(f"Agent {self.agent_id} starting with sequential processing")
            self._thread = threading.Thread(
                target=self._run_loop,
                name=f"Agent-{self.agent_id}",
                daemon=True
            )

        self._thread.start()
        logger.info(f"Agent {self.agent_id} started")

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop Agent

        Args:
            timeout: Timeout for waiting for the thread to end
        """
        if not self._running:
            return

        self._running = False

        # Shutdown thread pool
        if self._executor:
            logger.info(f"Agent {self.agent_id} shutting down executor")
            self._executor.shutdown(wait=timeout > 0, cancel_futures=not timeout)
            self._executor = None

        # Unsubscribe
        self.message_bus.unsubscribe(self.agent_id)

        # Wait for thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        # Save memory
        if self.memory and self._enable_learning:
            try:
                from pathlib import Path
                memory_path = Path(f".luodllhack/memory/{self.agent_id}_memory.json")
                self.memory.save(memory_path)
            except Exception as e:
                logger.error(f"Failed to save memory: {e}")

        logger.info(f"Agent {self.agent_id} stopped. Stats: {self._stats}")

    def is_running(self) -> bool:
        """Check if Agent is running"""
        return self._running

    # =========================================================================
    # Task Processing
    # =========================================================================

    def assign_task(self, task: TaskAssignment) -> None:
        """
        Assign task to queue

        Args:
            task: Task
        """
        task.assigned_to = self.agent_id
        self._task_queue.put(task)
        logger.debug(f"Agent {self.agent_id} received task {task.task_id}")

    def get_pending_task_count(self) -> int:
        """Get pending task count"""
        # Includes tasks in queue and active tasks
        active_count = len(self._active_futures) if self._active_futures else 0
        return self._task_queue.qsize() + active_count

    def get_completed_results(self) -> List[AgentResult]:
        """
        Get completed task results and clear them

        Returns:
            List of completed AgentResult
        """
        with self._lock:
            results = list(self._pending_results.values())
            self._pending_results.clear()
        return results

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings

        Returns:
            List of findings
        """
        findings = []
        with self._lock:
            for result in self._pending_results.values():
                if result.findings:
                    findings.extend(result.findings)
        return findings

    def get_network_stats(self) -> Dict[str, Any]:
        """
        Get network statistics information

        Returns:
            Statistics information dictionary
        """
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "tasks_processed": self._stats.get("tasks_processed", 0),
            "tasks_succeeded": self._stats.get("tasks_succeeded", 0),
            "tasks_failed": self._stats.get("tasks_failed", 0),
        }

    def _run_loop(self) -> None:
        """Main processing loop"""
        while self._running:
            try:
                # Wait for task with timeout, allowing check of _running flag
                task = self._task_queue.get(timeout=1.0)

                # Update task status
                task.status = TaskStatus.IN_PROGRESS
                task.started_at = time.time()

                # Process task
                start_time = time.time()
                try:
                    result = self.process_task(task)
                    result.execution_time = time.time() - start_time

                    # Update statistics
                    self._stats["tasks_processed"] += 1
                    self._stats["total_execution_time"] += result.execution_time
                    if result.success:
                        self._stats["tasks_succeeded"] += 1
                        task.status = TaskStatus.COMPLETED
                    else:
                        self._stats["tasks_failed"] += 1
                        task.status = TaskStatus.FAILED

                except Exception as e:
                    logger.error(f"Agent {self.agent_id} error processing task {task.task_id}: {e}")
                    result = AgentResult(
                        task_id=task.task_id,
                        agent_id=self.agent_id,
                        success=False,
                        error=str(e),
                        execution_time=time.time() - start_time
                    )
                    self._stats["tasks_failed"] += 1
                    task.status = TaskStatus.FAILED

                task.completed_at = time.time()

                # Store result
                with self._lock:
                    self._pending_results[task.task_id] = result

                # Notify Orchestrator
                self._notify_result(task.task_id, result)

                # Process follow-up tasks and messages in result
                self._process_result_actions(result)

                # Learn from results (if memory enabled)
                if self.memory and self._enable_learning:
                    try:
                        self.memory.add_experience(task, result)
                    except Exception as e:
                        logger.error(f"Failed to add experience to memory: {e}")

            except Empty:
                continue
            except Exception as e:
                logger.error(f"Agent {self.agent_id} loop error: {e}")

    def _run_loop_concurrent(self) -> None:
        """
        Concurrent task processing loop

        Use ThreadPoolExecutor to process multiple tasks concurrently
        """
        logger.info(f"Agent {self.agent_id} concurrent loop started")

        while self._running:
            try:
                # Submit new tasks (if free workers available)
                while len(self._active_futures) < self._max_concurrent_tasks:
                    try:
                        task = self._task_queue.get(timeout=0.1)
                        future = self._executor.submit(self._process_task_wrapper, task)
                        with self._lock:
                            self._active_futures[future] = task
                        logger.debug(f"Submitted task {task.task_id} to executor")
                    except Empty:
                        break

                # Check completed tasks
                done_futures = [f for f in self._active_futures if f.done()]
                for future in done_futures:
                    with self._lock:
                        task = self._active_futures.pop(future)

                    try:
                        result = future.result()
                        self._notify_result(task.task_id, result)
                        self._process_result_actions(result)

                        # Learn from result
                        if self.memory and self._enable_learning:
                            self.memory.add_experience(task, result)

                    except Exception as e:
                        logger.error(f"Task {task.task_id} failed: {e}")

                # Small sleep to avoid busy waiting
                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Agent {self.agent_id} concurrent loop error: {e}")

    def _process_task_wrapper(self, task: TaskAssignment) -> AgentResult:
        """
        Task processing wrapper (for concurrent execution)

        Args:
            task: Task

        Returns:
            Execution result
        """
        task.status = TaskStatus.IN_PROGRESS
        task.started_at = time.time()

        start_time = time.time()
        try:
            result = self.process_task(task)
            result.execution_time = time.time() - start_time

            # Update statistical info
            with self._lock:
                self._stats["tasks_processed"] += 1
                self._stats["total_execution_time"] += result.execution_time
                if result.success:
                    self._stats["tasks_succeeded"] += 1
                    task.status = TaskStatus.COMPLETED
                else:
                    self._stats["tasks_failed"] += 1
                    task.status = TaskStatus.FAILED

            task.completed_at = time.time()

            # Store result
            with self._lock:
                self._pending_results[task.task_id] = result

            return result

        except Exception as e:
            logger.error(f"Agent {self.agent_id} error processing task {task.task_id}: {e}")
            result = AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=str(e),
                execution_time=time.time() - start_time
            )

            with self._lock:
                self._stats["tasks_failed"] += 1

            task.status = TaskStatus.FAILED
            task.completed_at = time.time()

            return result

    def _notify_result(self, task_id: str, result: AgentResult) -> None:
        """
        Notify task completion via MessageBus

        Note: This method is only used in message bus mode (when tasks are assigned via MessageBus).
        When Orchestrator uses ParallelExecutor to directly call process_task(),
        results are collected via executor.wait_for_all(), bypassing this method.

        This notification is mainly used for:
        - Logging/Monitoring
        - Collaboration scenarios between Agents
        - Independent use cases other than Orchestrator
        """
        msg = AgentMessage.create(
            msg_type=MessageType.RESULT,
            sender=self.agent_id,
            receiver="orchestrator",
            payload={
                "task_id": task_id,
                "success": result.success,
                "findings_count": len(result.findings),
                "next_tasks_count": len(result.next_tasks),
                "execution_time": result.execution_time,
                "error": result.error,
            },
            priority=7
        )
        self.message_bus.publish(msg)

    def _process_result_actions(self, result: AgentResult) -> None:
        """Process follow-up actions in the result"""
        # Send messages
        for msg in result.messages:
            self.message_bus.publish(msg)

        # Broadcast findings
        for finding in result.findings:
            self.broadcast_finding(finding)

    # =========================================================================
    # Message Handling
    # =========================================================================

    def _on_message(self, message: AgentMessage) -> None:
        """
        Process received messages

        Args:
            message: Message
        """
        if message.is_expired():
            logger.debug(f"Agent {self.agent_id} ignoring expired message {message.msg_id}")
            return

        if message.msg_type == MessageType.TASK:
            self._handle_task_message(message)
            # If ACK is required, send confirmation
            if message.requires_ack:
                self._send_ack(message, success=True)
        elif message.msg_type == MessageType.REQUEST:
            self._handle_request(message)
        elif message.msg_type == MessageType.RESPONSE:
            self._handle_response(message)
        elif message.msg_type == MessageType.BROADCAST:
            self._handle_broadcast(message)
        elif message.msg_type == MessageType.ACK:
            self._handle_ack(message)
        elif message.msg_type == MessageType.SHUTDOWN:
            self.stop()

    def _handle_task_message(self, message: AgentMessage) -> None:
        """Handle task message"""
        try:
            task_data = message.payload
            task = TaskAssignment(
                task_id=task_data.get("task_id", f"task-{uuid.uuid4().hex[:8]}"),
                task_type=task_data["task_type"],
                parameters=task_data.get("parameters", {}),
                priority=task_data.get("priority", 5),
                dependencies=task_data.get("dependencies", [])
            )
            self.assign_task(task)
        except Exception as e:
            logger.error(f"Agent {self.agent_id} failed to parse task message: {e}")

    def _handle_request(self, message: AgentMessage) -> None:
        """
        Handle request message

        Subclasses can override to implement custom request processing
        """
        request_type = message.payload.get("request_type")
        data = message.payload.get("data", {})

        response_payload = self._process_request(request_type, data)

        # Send response
        response = AgentMessage.create(
            msg_type=MessageType.RESPONSE,
            sender=self.agent_id,
            receiver=message.sender,
            payload=response_payload,
            correlation_id=message.correlation_id
        )
        self.message_bus.publish(response)

    def _process_request(self, request_type: str, data: Dict) -> Dict:
        """
        Process request, subclasses can override

        Args:
            request_type: Request type
            data: Request data

        Returns:
            Response data
        """
        if request_type == "get_status":
            return {
                "agent_id": self.agent_id,
                "role": self.role,
                "running": self._running,
                "pending_tasks": self.get_pending_task_count(),
                "stats": self._stats.copy()
            }
        elif request_type == "get_capabilities":
            return {
                "capabilities": [c.value for c in self.capabilities]
            }
        else:
            return {"error": f"Unknown request type: {request_type}"}

    def _handle_response(self, message: AgentMessage) -> None:
        """Handle response message"""
        correlation_id = message.correlation_id
        if correlation_id and correlation_id in self._response_events:
            with self._lock:
                self._response_data[correlation_id] = message.payload
                self._response_events[correlation_id].set()

    def _handle_broadcast(self, message: AgentMessage) -> None:
        """
        Handle broadcast message

        Subclasses can override to implement custom broadcast handling
        """
        # No special handling by default
        pass

    def _handle_ack(self, message: AgentMessage) -> None:
        """
        Handle ACK message

        Args:
            message: ACK message
        """
        # Delegate to MessageBus for processing
        if self.message_bus:
            self.message_bus.handle_ack(message)

    def _send_ack(
        self,
        original_message: AgentMessage,
        success: bool = True,
        error: Optional[str] = None
    ) -> None:
        """
        Send ACK confirmation

        Args:
            original_message: Original message
            success: Whether processing was successful
            error: Error message
        """
        if not self.message_bus:
            return

        self.message_bus.send_ack(
            original_msg_id=original_message.msg_id,
            sender=self.agent_id,
            receiver=original_message.sender,
            success=success,
            error=error
        )

    # =========================================================================
    # Communication between Agents
    # =========================================================================

    def request_from_peer(
        self,
        target_agent: str,
        request_type: str,
        data: Dict[str, Any],
        timeout: float = 30.0
    ) -> Optional[Dict[str, Any]]:
        """
        Send request to other Agent and wait for response

        Args:
            target_agent: Target Agent ID
            request_type: Request type
            data: Request data
            timeout: Timeout period (seconds)

        Returns:
            Response data, or None if timed out
        """
        correlation_id = f"req-{self.agent_id}-{uuid.uuid4().hex[:8]}"

        # Create response event
        response_event = threading.Event()
        with self._lock:
            self._response_events[correlation_id] = response_event
            self._response_data[correlation_id] = None

        # Send request
        request = AgentMessage.create(
            msg_type=MessageType.REQUEST,
            sender=self.agent_id,
            receiver=target_agent,
            payload={"request_type": request_type, "data": data},
            correlation_id=correlation_id,
            requires_ack=True
        )
        self.message_bus.publish(request)

        # Wait for response
        received = response_event.wait(timeout=timeout)

        # Get and cleanup
        with self._lock:
            response = self._response_data.pop(correlation_id, None)
            self._response_events.pop(correlation_id, None)

        if not received:
            logger.warning(f"Agent {self.agent_id} request to {target_agent} timed out")
            return None

        return response

    def broadcast_finding(self, finding: Dict[str, Any]) -> None:
        """
        Broadcast vulnerability finding to all Agents

        Args:
            finding: Discovery data
        """
        msg = AgentMessage.create(
            msg_type=MessageType.BROADCAST,
            sender=self.agent_id,
            receiver=None,  # Broadcast
            payload={"type": "finding", "finding": finding},
            priority=8
        )
        self.message_bus.publish(msg)

    def send_to_peer(
        self,
        target_agent: str,
        msg_type: MessageType,
        payload: Dict[str, Any],
        priority: int = 5
    ) -> None:
        """
        Send message to other Agents

        Args:
            target_agent: Target Agent ID
            msg_type: Message type
            payload: Message content
            priority: Priority
        """
        msg = AgentMessage.create(
            msg_type=msg_type,
            sender=self.agent_id,
            receiver=target_agent,
            payload=payload,
            priority=priority
        )
        self.message_bus.publish(msg)

    def send_collaboration_request(
        self,
        request_type: str,
        payload: Dict[str, Any],
        target_agent: Optional[str] = None,
        timeout: float = 60.0
    ) -> Optional[Dict[str, Any]]:
        """
        Send collaboration request

        Uses unified communication protocol to send collaboration requests between Agents.
        See: CollaborationType in communication.py

        Args:
            request_type: Collaboration type (request_data, share_finding, request_verify, etc.)
            payload: Request data
            target_agent: Target Agent (None for broadcast)
            timeout: Timeout period

        Returns:
            Response data, or None if timed out or broadcast
        """
        from .communication import CollaborationType

        # Validate request type
        valid_types = [t.value for t in CollaborationType]
        if request_type not in valid_types:
            logger.warning(f"Unknown collaboration type: {request_type}")

        # Broadcast requests do not need response
        if target_agent is None:
            msg = AgentMessage.create(
                msg_type=MessageType.BROADCAST,
                sender=self.agent_id,
                receiver=None,
                payload={
                    "collaboration_type": request_type,
                    "data": payload
                },
                priority=6
            )
            self.message_bus.publish(msg)
            return None

        # Point-to-point request
        return self.request_from_peer(
            target_agent=target_agent,
            request_type=f"collaboration:{request_type}",
            data=payload,
            timeout=timeout
        )

    # =========================================================================
    # Tool Invocation
    # =========================================================================

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Invoke registered tools

        Args:
            tool_name: Tool name
            arguments: Arguments

        Returns:
            Tool return result
        """
        if self.tools is None:
            logger.error(f"Agent {self.agent_id} has no tool registry")
            return None

        try:
            logger.info(f"Agent {self.agent_id} calling tool: {tool_name}")
            result = self.tools.call_tool(tool_name, arguments)
            logger.info(f"Agent {self.agent_id} tool {tool_name} returned: {type(result).__name__}")
            return result
        except Exception as e:
            logger.error(f"Agent {self.agent_id} tool call failed: {tool_name} - {e}")
            return None

    # =========================================================================
    # LLM Invocation
    # =========================================================================

    def call_llm(
        self,
        prompt: Union[str, PromptTemplate],
        tools: List[Dict] = None,
        max_retries: int = 3
    ) -> Optional[Any]:
        """
        Invoke LLM (using pool)

        Args:
            prompt: Prompt or template
            tools: Tool definitions
            max_retries: Maximum number of retries

        Returns:
            LLM response
        """
        if not self.llm_pool:
            logger.error(f"Agent {self.agent_id} has no LLM pool")
            return None

        # Process PromptTemplate
        if isinstance(prompt, PromptTemplate):
            try:
                prompt_str = prompt.format()
            except Exception as e:
                logger.error(f"Failed to format prompt template: {e}")
                return None
        else:
            prompt_str = prompt

        try:
            return self.llm_pool.generate(prompt_str, tools=tools)
        except Exception as e:
            logger.error(f"Agent {self.agent_id} LLM call failed: {e}")
            return None

    def _init_async_llm(self) -> None:
        """
        Initialize asynchronous LLM support
        """
        # Asynchronous LLM support is currently left empty, can be extended as needed
        # For now, async LLM support is not implemented
        pass

    def register_tool_for_llm(
        self,
        tool_name: str,
        description: str,
        parameters: Dict[str, Any]
    ) -> None:
        """
        Register tool for LLM function calling use

        Args:
            tool_name: Tool name
            description: Tool description
            parameters: Parameter definitions (JSON Schema format)
        """
        tool_def = {
            "name": tool_name,
            "description": description,
            "parameters": parameters
        }
        self._tool_definitions.append(tool_def)
        logger.debug(f"Agent {self.agent_id} registered tool for LLM: {tool_name}")

    def call_llm_with_tools(
        self,
        prompt: str,
        max_iterations: int = 5,
        system_prompt: Optional[str] = None
    ) -> Optional[Any]:
        """
        Invoke LLM and support tool invocation loop

        LLM can actively call registered tools, Agent automatically executes and returns result to LLM

        Args:
            prompt: User prompt
            max_iterations: Maximum number of iterations (preventing infinite loops)
            system_prompt: System prompt (optional)

        Returns:
            Final LLM response
        """
        if not self._tool_definitions:
            logger.warning(f"Agent {self.agent_id} has no registered tools for LLM")
            return self.call_llm(prompt)

        logger.info(f"Agent {self.agent_id} starting LLM tool calling loop with {len(self._tool_definitions)} tools")

        # Build initial messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        for iteration in range(max_iterations):
            logger.debug(f"Agent {self.agent_id} LLM iteration {iteration + 1}/{max_iterations}")

            # Invoke LLM
            response = self.call_llm(prompt, tools=self._tool_definitions)

            if response is None:
                logger.error(f"Agent {self.agent_id} LLM returned None")
                return None

            # Check if there are tool calls
            if hasattr(response, 'has_tool_calls') and response.has_tool_calls:
                logger.info(f"Agent {self.agent_id} LLM requested {len(response.tool_calls)} tool calls")

                # Execute all tool calls
                tool_results = []
                for tool_call in response.tool_calls:
                    tool_name = tool_call.name
                    tool_args = tool_call.arguments

                    logger.info(f"Agent {self.agent_id} executing tool: {tool_name}")

                    try:
                        result = self.call_tool(tool_name, tool_args)
                        tool_results.append({
                            "tool_call_id": tool_call.call_id if hasattr(tool_call, 'call_id') else None,
                            "tool_name": tool_name,
                            "result": result
                        })
                    except Exception as e:
                        logger.error(f"Agent {self.agent_id} tool {tool_name} failed: {e}")
                        tool_results.append({
                            "tool_call_id": tool_call.call_id if hasattr(tool_call, 'call_id') else None,
                            "tool_name": tool_name,
                            "error": str(e)
                        })

                # Add tool results to prompt to continue dialogue
                tool_results_str = "\n".join([
                    f"Tool: {r['tool_name']}\nResult: {r.get('result', r.get('error'))}"
                    for r in tool_results
                ])
                prompt = f"{prompt}\n\nTool Results:\n{tool_results_str}\n\nBased on these results, what's your final answer?"

            else:
                # No tool calls, return final answer
                logger.info(f"Agent {self.agent_id} LLM returned final answer")
                return response

        logger.warning(f"Agent {self.agent_id} reached max iterations ({max_iterations})")
        return response

    # =========================================================================
    # Status Query
    # =========================================================================

    def get_state_snapshot(self) -> Dict[str, Any]:
        """Get shared state snapshot"""
        return self.shared_state.get_snapshot()

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics information"""
        stats = self._stats.copy()
        if stats["start_time"]:
            stats["uptime"] = time.time() - stats["start_time"]
        return stats



    # =========================================================================
    # ReAct Mode
    # =========================================================================

    def register_tool_for_llm(self, tool_name: str, description: str, parameters: dict):
        """Register tool for LLM to use via function calling"""
        self._tool_definitions.append({
            "name": tool_name,
            "description": description,
            "parameters": parameters
        })

    def process_task_with_react(self, task: "TaskAssignment") -> "AgentResult":
        """Process task with ReAct framework, implementing Think-Act-Observe loop"""
        import json
        logger.info(f"Agent {self.agent_id} starting ReAct loop for task {task.task_id}")

        # Initialize context
        tools_names = [t['name'] for t in self._tool_definitions]
        tools_desc = ', '.join(tools_names) if tools_names else "No tools registered"

        context = f"Task: {task.task_type}\nParameters: {json.dumps(task.parameters, indent=2)}\nTools: {tools_desc}"
        thoughts, actions, observations = [], [], []

        for iteration in range(self.max_react_iterations):
            # THINK: Analyze current situation
            history = ""
            if thoughts:
                for i in range(max(0, len(thoughts) - 3), len(thoughts)):
                    act_type = actions[i]['type'] if i < len(actions) else 'N/A'
                    history += f"Step {i+1}: Thought={thoughts[i][:100]}... Action={act_type}\n"

            prompt = f"{context}\n\nHistory:\n{history or 'First step'}\n\nThink: What should I do next?"
            response = self.call_llm(prompt)
            thought = response.text if response and response.text else "Unable to think"
            thoughts.append(thought)

            # DECIDE ACTION: Determine next move
            prompt = f"""Thought: {thought}\n\nDecide action (JSON): {{"type": "tool_call|final_answer", "tool": "name", "arguments": {{}}, "content": "answer"}}"""
            response = self.call_llm(prompt, tools=self._tool_definitions)

            action = {"type": "final_answer", "content": response.text if response else "No answer"}

            if hasattr(response, 'has_tool_calls') and response.has_tool_calls:
                tc = response.tool_calls[0]
                action = {"type": "tool_call", "tool": tc.name, "arguments": tc.arguments}
            else:
                try:
                    import re
                    match = re.search(r'\{[\s\S]*\}', response.text if response else "")
                    if match:
                        action = json.loads(match.group())
                except:
                    pass

            if action["type"] == "final_answer":
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=True,
                    findings=[],
                    artifacts={
                        "react_trace": {
                            "thoughts": thoughts,
                            "actions": actions,
                            "observations": observations,
                            "answer": action.get("content", "")
                        }
                    },
                    metadata={"iterations": len(thoughts)}
                )

            # EXECUTE ACTION: Execute determined action
            actions.append(action)
            if action["type"] == "tool_call":
                try:
                    result = self.call_tool(action["tool"], action.get("arguments", {}))
                    observation = {"success": True, "tool": action["tool"], "result": result}
                except Exception as e:
                    observation = {"success": False, "tool": action["tool"], "error": str(e)}
            else:
                observation = {"type": "no_action"}
            observations.append(observation)

            # Update context
            context = context + f"\n\nLatest: Thought={thought[:100]}... Action={action['type']} Observation={str(observation)[:100]}..."

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error=f"ReAct timeout after {self.max_react_iterations} iterations",
            artifacts={
                "react_trace": {
                    "thoughts": thoughts,
                    "actions": actions,
                    "observations": observations
                }
            },
            metadata={"iterations": len(thoughts), "timeout": True}
        )