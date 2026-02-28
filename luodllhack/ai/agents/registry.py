# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/registry.py
Agent Registry - Service Discovery and Capability Matching

Features:
    - Agent Registration and Unregistration
    - Capability Querying and Matching
    - Load Balancing
    - Health Checking
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Callable, TYPE_CHECKING

from .base import AgentCapability, AgentMessage, MessageType

if TYPE_CHECKING:
    from .network_agent import NetworkAgent
    from .message_bus import MessageBus

logger = logging.getLogger(__name__)


# =============================================================================
# Agent Information
# =============================================================================

@dataclass
class AgentInfo:
    """Agent Registration Information"""
    agent_id: str
    role: str
    capabilities: Set[AgentCapability]
    status: str = "active"          # active, busy, offline
    current_load: int = 0           # Current number of tasks
    max_load: int = 3               # Maximum number of tasks
    last_heartbeat: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_available(self) -> bool:
        """Check if available"""
        return self.status == "active" and self.current_load < self.max_load

    def is_healthy(self, timeout: float = 60.0) -> bool:
        """Check health status"""
        return time.time() - self.last_heartbeat < timeout

    def update_heartbeat(self) -> None:
        """Update heartbeat"""
        self.last_heartbeat = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "capabilities": [c.value for c in self.capabilities],
            "status": self.status,
            "current_load": self.current_load,
            "max_load": self.max_load,
            "last_heartbeat": self.last_heartbeat,
            "metadata": self.metadata,
        }


# =============================================================================
# AgentRegistry - Service Discovery
# =============================================================================

class AgentRegistry:
    """
    Agent Registry

    Provides:
    - Agent Registration/Unregistration
    - Capability querying
    - Load balancing selection
    - Health checking

    Usage Example:
        registry = AgentRegistry()
        registry.register(agent)

        # Find Agents with a specific capability
        agents = registry.find_by_capability(AgentCapability.DISCOVERY)

        # Select the Agent with the lowest load
        best = registry.select_best_for_capability(AgentCapability.VERIFICATION)
    """

    def __init__(
        self,
        message_bus: Optional["MessageBus"] = None,
        heartbeat_timeout: float = 60.0,
        health_check_interval: float = 30.0
    ):
        """
        Initialize Registry

        Args:
            message_bus: Message bus (for broadcasting registration events)
            heartbeat_timeout: Heartbeat timeout duration
            health_check_interval: Health check interval
        """
        self.message_bus = message_bus
        self.heartbeat_timeout = heartbeat_timeout
        self.health_check_interval = health_check_interval

        # Agent storage
        self._agents: Dict[str, AgentInfo] = {}
        self._lock = threading.RLock()

        # Capability index
        self._capability_index: Dict[AgentCapability, Set[str]] = {}

        # Event callbacks
        self._on_register_callbacks: List[Callable[[str], None]] = []
        self._on_unregister_callbacks: List[Callable[[str], None]] = []
        self._on_status_change_callbacks: List[Callable[[str, str], None]] = []

        # Health check thread
        self._running = False
        self._health_check_thread: Optional[threading.Thread] = None

        logger.info("AgentRegistry initialized")

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def start(self) -> None:
        """Start health check"""
        if self._running:
            return

        self._running = True
        self._health_check_thread = threading.Thread(
            target=self._health_check_loop,
            name="AgentRegistry-HealthCheck",
            daemon=True
        )
        self._health_check_thread.start()
        logger.info("AgentRegistry health check started")

    def stop(self) -> None:
        """Stop health check"""
        self._running = False
        if self._health_check_thread:
            self._health_check_thread.join(timeout=5.0)
        logger.info("AgentRegistry stopped")

    # =========================================================================
    # Registration Management
    # =========================================================================

    def register(
        self,
        agent: "NetworkAgent",
        metadata: Dict[str, Any] = None
    ) -> None:
        """
        Register Agent

        Args:
            agent: Agent instance
            metadata: Additional metadata
        """
        info = AgentInfo(
            agent_id=agent.agent_id,
            role=agent.role,
            capabilities=set(agent.capabilities),
            metadata=metadata or {}
        )
        self.register_info(info)

    def register_info(self, info: AgentInfo) -> None:
        """
        Register Agent Information

        Args:
            info: Agent information
        """
        with self._lock:
            self._agents[info.agent_id] = info

            # Update capability index
            for cap in info.capabilities:
                if cap not in self._capability_index:
                    self._capability_index[cap] = set()
                self._capability_index[cap].add(info.agent_id)

        # Trigger callbacks
        for callback in self._on_register_callbacks:
            try:
                callback(info.agent_id)
            except Exception as e:
                logger.error(f"Register callback error: {e}")

        # Broadcast registration event
        if self.message_bus:
            msg = AgentMessage.create(
                msg_type=MessageType.BROADCAST,
                sender="registry",
                payload={
                    "event": "agent_registered",
                    "agent_id": info.agent_id,
                    "role": info.role,
                    "capabilities": [c.value for c in info.capabilities],
                }
            )
            self.message_bus.publish(msg)

        logger.info(f"Agent {info.agent_id} registered with capabilities: {[c.value for c in info.capabilities]}")

    def unregister(self, agent_id: str) -> None:
        """
        Unregister Agent

        Args:
            agent_id: Agent ID
        """
        with self._lock:
            info = self._agents.pop(agent_id, None)
            if info:
                # Remove from capability index
                for cap in info.capabilities:
                    if cap in self._capability_index:
                        self._capability_index[cap].discard(agent_id)

        if info:
            # Trigger callbacks
            for callback in self._on_unregister_callbacks:
                try:
                    callback(agent_id)
                except Exception as e:
                    logger.error(f"Unregister callback error: {e}")

            # Broadcast unregistration event
            if self.message_bus:
                msg = AgentMessage.create(
                    msg_type=MessageType.BROADCAST,
                    sender="registry",
                    payload={
                        "event": "agent_unregistered",
                        "agent_id": agent_id,
                    }
                )
                self.message_bus.publish(msg)

            logger.info(f"Agent {agent_id} unregistered")

    # =========================================================================
    # Query
    # =========================================================================

    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Get Agent information"""
        with self._lock:
            return self._agents.get(agent_id)

    def get_all_agents(self) -> List[str]:
        """Get all Agent IDs"""
        with self._lock:
            return list(self._agents.keys())

    def get_all_agent_info(self) -> List[AgentInfo]:
        """Get all Agent information"""
        with self._lock:
            return list(self._agents.values())

    def find_by_capability(
        self,
        capability: AgentCapability,
        only_available: bool = True
    ) -> List[str]:
        """
        Find Agents with a specific capability

        Args:
            capability: Capability
            only_available: Return only available Agents

        Returns:
            List of Agent IDs
        """
        with self._lock:
            agent_ids = self._capability_index.get(capability, set()).copy()

            if only_available:
                return [
                    aid for aid in agent_ids
                    if aid in self._agents and self._agents[aid].is_available()
                ]
            return list(agent_ids)

    def find_by_capabilities(
        self,
        capabilities: List[AgentCapability],
        match_all: bool = False,
        only_available: bool = True
    ) -> List[str]:
        """
        Find Agents with multiple capabilities

        Args:
            capabilities: List of capabilities
            match_all: Whether to match all capabilities
            only_available: Return only available Agents

        Returns:
            List of Agent IDs
        """
        if not capabilities:
            return self.get_all_agents()

        with self._lock:
            if match_all:
                # Must match all capabilities
                result = None
                for cap in capabilities:
                    agents = self._capability_index.get(cap, set())
                    if result is None:
                        result = agents.copy()
                    else:
                        result &= agents
                result = result or set()
            else:
                # Match any capability
                result = set()
                for cap in capabilities:
                    result |= self._capability_index.get(cap, set())

            if only_available:
                return [
                    aid for aid in result
                    if aid in self._agents and self._agents[aid].is_available()
                ]
            return list(result)

    def find_by_role(self, role: str) -> List[str]:
        """
        Find Agents by specific role

        Args:
            role: Role name

        Returns:
            List of Agent IDs
        """
        with self._lock:
            return [
                aid for aid, info in self._agents.items()
                if info.role == role
            ]

    # =========================================================================
    # Load Balancing
    # =========================================================================

    def select_best_for_capability(
        self,
        capability: AgentCapability
    ) -> Optional[str]:
        """
        Select the best Agent to handle tasks of a specific capability (load balancing)

        Args:
            capability: Capability

        Returns:
            Agent ID or None
        """
        candidates = self.find_by_capability(capability, only_available=True)
        if not candidates:
            return None

        # Select the one with lowest load
        with self._lock:
            best = min(
                candidates,
                key=lambda aid: self._agents[aid].current_load
            )
            return best

    def select_best_for_task(
        self,
        task_type: str,
        required_capabilities: List[AgentCapability] = None
    ) -> Optional[str]:
        """
        Select the best Agent to handle a task

        Args:
            task_type: Task type
            required_capabilities: Required capabilities

        Returns:
            Agent ID or None
        """
        if required_capabilities:
            candidates = self.find_by_capabilities(
                required_capabilities,
                match_all=True,
                only_available=True
            )
        else:
            candidates = [
                aid for aid, info in self._agents.items()
                if info.is_available()
            ]

        if not candidates:
            return None

        # Select the one with lowest load
        with self._lock:
            best = min(
                candidates,
                key=lambda aid: self._agents[aid].current_load
            )
            return best

    # =========================================================================
    # Status Update
    # =========================================================================

    def update_status(self, agent_id: str, status: str) -> None:
        """
        Update Agent status

        Args:
            agent_id: Agent ID
            status: New status
        """
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                old_status = info.status
                info.status = status

        if info and old_status != status:
            # Trigger callbacks
            for callback in self._on_status_change_callbacks:
                try:
                    callback(agent_id, status)
                except Exception as e:
                    logger.error(f"Status change callback error: {e}")

    def update_load(self, agent_id: str, load: int) -> None:
        """
        Update Agent load

        Args:
            agent_id: Agent ID
            load: Current load
        """
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                info.current_load = load

    def increment_load(self, agent_id: str) -> None:
        """Increase Agent load"""
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                info.current_load += 1

    def decrement_load(self, agent_id: str) -> None:
        """Decrease Agent load"""
        with self._lock:
            info = self._agents.get(agent_id)
            if info and info.current_load > 0:
                info.current_load -= 1

    def update_heartbeat(self, agent_id: str) -> None:
        """
        Update heartbeat

        Args:
            agent_id: Agent ID
        """
        with self._lock:
            info = self._agents.get(agent_id)
            if info:
                info.update_heartbeat()

    # =========================================================================
    # Health Check
    # =========================================================================

    def _health_check_loop(self) -> None:
        """Health check loop"""
        while self._running:
            try:
                self._check_health()
            except Exception as e:
                logger.error(f"Health check error: {e}")

            time.sleep(self.health_check_interval)

    def _check_health(self) -> None:
        """Perform health check"""
        unhealthy = []

        with self._lock:
            for agent_id, info in self._agents.items():
                if not info.is_healthy(self.heartbeat_timeout):
                    unhealthy.append(agent_id)

        # Mark unhealthy Agents
        for agent_id in unhealthy:
            logger.warning(f"Agent {agent_id} appears unhealthy (no heartbeat)")
            self.update_status(agent_id, "offline")

    def get_healthy_agents(self) -> List[str]:
        """Get list of healthy Agents"""
        with self._lock:
            return [
                aid for aid, info in self._agents.items()
                if info.is_healthy(self.heartbeat_timeout)
            ]

    # =========================================================================
    # Event Callbacks
    # =========================================================================

    def on_register(self, callback: Callable[[str], None]) -> None:
        """Register Agent registration event callback"""
        self._on_register_callbacks.append(callback)

    def on_unregister(self, callback: Callable[[str], None]) -> None:
        """Register Agent unregistration event callback"""
        self._on_unregister_callbacks.append(callback)

    def on_status_change(self, callback: Callable[[str, str], None]) -> None:
        """Register status change event callback"""
        self._on_status_change_callbacks.append(callback)

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics info"""
        with self._lock:
            total = len(self._agents)
            available = sum(1 for info in self._agents.values() if info.is_available())
            healthy = sum(1 for info in self._agents.values() if info.is_healthy(self.heartbeat_timeout))
            total_load = sum(info.current_load for info in self._agents.values())

            capabilities_count = {
                cap.value: len(agents)
                for cap, agents in self._capability_index.items()
            }

            return {
                "total_agents": total,
                "available_agents": available,
                "healthy_agents": healthy,
                "total_load": total_load,
                "capabilities": capabilities_count,
            }

    def get_status_summary(self) -> Dict[str, List[str]]:
        """Get Agent list grouped by status"""
        with self._lock:
            summary: Dict[str, List[str]] = {}
            for agent_id, info in self._agents.items():
                if info.status not in summary:
                    summary[info.status] = []
                summary[info.status].append(agent_id)
            return summary
