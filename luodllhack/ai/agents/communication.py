# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/communication.py
Unified Communication Protocol - Clearly defines communication models and responsibility boundaries

## Communication Model Design

This module addresses the original "dual-track problem":
- Old Path 1: Orchestrator -> ParallelExecutor -> agent.process_task() -> executor result
- Old Path 2: agent._notify_result() -> MessageBus -> Orchestrator._handle_message()

New Unified Model:
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Division of Communication Responsibilities            │
│─────────────────────────────────────────────────────────────────────────────│
│  DirectExecution                      │  MessageBus (Message Bus)           │
│  ─────────────────────────────       │  ─────────────────────────          │
│  • Task distribution and execution    │  • Collaboration requests between    │
│  • Synchronous wait for results       │    Agents                           │
│  • Timeout and retry control          │  • Broadcast notifications (finds,  │
│  • Result collection                  │    status changes)                  │
│                                      │  • Asynchronous event notification  │
│                                      │  • Heartbeat and health checks      │
│                                      │  • Data sharing requests between    │
│                                      │    Agents                           │
└─────────────────────────────────────────────────────────────────────────────┘

## Core Principles

1. **Single Responsibility**: Task results are returned via only one path (DirectExecution)
2. **Clear Boundaries**: MessageBus is only used for inter-Agent collaboration, not for task result transmission
3. **Message Acknowledgment**: Important messages support ACK mechanism to ensure reliability
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Any, Optional, Callable, List, TypeVar, Generic
import time
import uuid
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Communication Channel Types
# =============================================================================

class CommunicationChannel(Enum):
    """Communication channel types"""
    DIRECT = "direct"           # Direct execution (synchronous task)
    MESSAGE_BUS = "message_bus"  # Message bus (asynchronous collaboration)


class CollaborationType(Enum):
    """Inter-agent collaboration types - only through MessageBus"""
    REQUEST_DATA = "request_data"           # Request data from other Agents
    SHARE_FINDING = "share_finding"         # Share findings (e.g., new vulnerabilities)
    REQUEST_VERIFICATION = "request_verify"  # Request verification
    NOTIFY_STATUS = "notify_status"         # Status notification
    BROADCAST_DISCOVERY = "broadcast_disc"   # Broadcast discovery


# =============================================================================
# Message Acknowledgment (ACK) Mechanism
# =============================================================================

class AckStatus(Enum):
    """Acknowledgment status"""
    PENDING = "pending"         # Waiting for acknowledgment
    RECEIVED = "received"       # Received
    PROCESSED = "processed"     # Processed
    FAILED = "failed"           # Processing failed
    TIMEOUT = "timeout"         # Timed out


@dataclass
class MessageAck:
    """Message acknowledgment"""
    message_id: str
    status: AckStatus
    receiver: str
    timestamp: float = field(default_factory=time.time)
    error_message: Optional[str] = None

    @classmethod
    def received(cls, message_id: str, receiver: str) -> "MessageAck":
        """Create receive acknowledgment"""
        return cls(
            message_id=message_id,
            status=AckStatus.RECEIVED,
            receiver=receiver
        )

    @classmethod
    def processed(cls, message_id: str, receiver: str) -> "MessageAck":
        """Create processing completion acknowledgment"""
        return cls(
            message_id=message_id,
            status=AckStatus.PROCESSED,
            receiver=receiver
        )

    @classmethod
    def failed(cls, message_id: str, receiver: str, error: str) -> "MessageAck":
        """Create failure acknowledgment"""
        return cls(
            message_id=message_id,
            status=AckStatus.FAILED,
            receiver=receiver,
            error_message=error
        )


# =============================================================================
# Collaboration Request (Communication between Agents)
# =============================================================================

@dataclass
class CollaborationRequest:
    """
    Collaboration request between Agents

    Used for data requests, verification requests, etc., between Agents.
    Transmitted via MessageBus, does not affect the main task execution flow.
    """
    request_id: str
    request_type: CollaborationType
    source_agent: str
    target_agent: Optional[str]  # None means broadcast
    payload: Dict[str, Any]
    priority: int = 5
    requires_response: bool = True
    timeout: float = 60.0
    created_at: float = field(default_factory=time.time)

    @classmethod
    def create(
        cls,
        request_type: CollaborationType,
        source_agent: str,
        payload: Dict[str, Any],
        target_agent: Optional[str] = None,
        priority: int = 5,
        requires_response: bool = True,
        timeout: float = 60.0
    ) -> "CollaborationRequest":
        """Create collaboration request"""
        return cls(
            request_id=f"collab-{uuid.uuid4().hex[:12]}",
            request_type=request_type,
            source_agent=source_agent,
            target_agent=target_agent,
            payload=payload,
            priority=priority,
            requires_response=requires_response,
            timeout=timeout
        )

    def is_broadcast(self) -> bool:
        """Check if it is a broadcast request"""
        return self.target_agent is None

    def is_expired(self) -> bool:
        """Check if timed out"""
        return time.time() - self.created_at > self.timeout


@dataclass
class CollaborationResponse:
    """Collaboration response"""
    response_id: str
    request_id: str  # Associated request ID
    source_agent: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    @classmethod
    def success_response(
        cls,
        request_id: str,
        source_agent: str,
        data: Dict[str, Any]
    ) -> "CollaborationResponse":
        """Create successful response"""
        return cls(
            response_id=f"resp-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            source_agent=source_agent,
            success=True,
            data=data
        )

    @classmethod
    def error_response(
        cls,
        request_id: str,
        source_agent: str,
        error: str
    ) -> "CollaborationResponse":
        """Create error response"""
        return cls(
            response_id=f"resp-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            source_agent=source_agent,
            success=False,
            error=error
        )


# =============================================================================
# Communication Protocol Interface
# =============================================================================

T = TypeVar('T')


class CommunicationProtocol(ABC):
    """
    Communication Protocol Abstract Base Class

    Defines standard interfaces for communication between Agents, ensuring consistency in communication behavior.
    """

    @abstractmethod
    def send_collaboration_request(
        self,
        request: CollaborationRequest
    ) -> Optional[CollaborationResponse]:
        """
        Send collaboration request

        Args:
            request: Collaboration request

        Returns:
            If requires_response=True, returns response; otherwise returns None
        """
        pass

    @abstractmethod
    def handle_collaboration_request(
        self,
        request: CollaborationRequest
    ) -> CollaborationResponse:
        """
        Process received collaboration request

        Args:
            request: Received request

        Returns:
            Response
        """
        pass

    @abstractmethod
    def broadcast_finding(
        self,
        finding_type: str,
        finding_data: Dict[str, Any]
    ) -> None:
        """
        Broadcast finding

        Args:
            finding_type: Discovery type
            finding_data: Discovery data
        """
        pass


# =============================================================================
# Communication Router - Decides which channel to use
# =============================================================================

class CommunicationRouter:
    """
    Communication Router

    Automatically selects the correct communication channel based on message type, ensuring separation of duties.
    """

    # Task related message types - Use direct execution
    DIRECT_EXECUTION_TYPES = {
        "task_dispatch",
        "task_result",
        "task_retry",
        "task_cancel",
    }

    # Collaboration related message types - Use MessageBus
    MESSAGE_BUS_TYPES = {
        "collaboration_request",
        "collaboration_response",
        "broadcast_finding",
        "status_notification",
        "heartbeat",
        "agent_discovery",
    }

    @classmethod
    def get_channel(cls, message_type: str) -> CommunicationChannel:
        """
        Get the channel the message should use

        Args:
            message_type: Message type

        Returns:
            Recommended communication channel
        """
        if message_type in cls.DIRECT_EXECUTION_TYPES:
            return CommunicationChannel.DIRECT
        elif message_type in cls.MESSAGE_BUS_TYPES:
            return CommunicationChannel.MESSAGE_BUS
        else:
            # Default to MessageBus
            logger.warning(f"Unknown message type: {message_type}, using MESSAGE_BUS")
            return CommunicationChannel.MESSAGE_BUS

    @classmethod
    def should_use_message_bus(cls, message_type: str) -> bool:
        """Check if MessageBus should be used"""
        return cls.get_channel(message_type) == CommunicationChannel.MESSAGE_BUS

    @classmethod
    def should_use_direct_execution(cls, message_type: str) -> bool:
        """Check if direct execution should be used"""
        return cls.get_channel(message_type) == CommunicationChannel.DIRECT


# =============================================================================
# Pending Message Tracker
# =============================================================================

@dataclass
class PendingMessage:
    """Message waiting for confirmation"""
    message_id: str
    sent_at: float
    timeout: float
    callback: Optional[Callable[[MessageAck], None]] = None
    retries: int = 0
    max_retries: int = 3


class PendingMessageTracker:
    """
    Pending message tracker

    Tracks messages that need confirmation, handles timeout and retries.
    """

    def __init__(self):
        self._pending: Dict[str, PendingMessage] = {}

    def track(
        self,
        message_id: str,
        timeout: float = 30.0,
        callback: Optional[Callable[[MessageAck], None]] = None,
        max_retries: int = 3
    ) -> None:
        """Start tracking message"""
        self._pending[message_id] = PendingMessage(
            message_id=message_id,
            sent_at=time.time(),
            timeout=timeout,
            callback=callback,
            max_retries=max_retries
        )

    def confirm(self, ack: MessageAck) -> bool:
        """
        Confirm message

        Returns:
            True if message exists and is confirmed, False otherwise
        """
        if ack.message_id not in self._pending:
            return False

        pending = self._pending.pop(ack.message_id)
        if pending.callback:
            pending.callback(ack)
        return True

    def get_expired(self) -> List[PendingMessage]:
        """Get all timed out messages"""
        now = time.time()
        expired = []
        for msg in self._pending.values():
            if now - msg.sent_at > msg.timeout:
                expired.append(msg)
        return expired

    def remove(self, message_id: str) -> Optional[PendingMessage]:
        """Remove tracked message"""
        return self._pending.pop(message_id, None)

    def get_retry_candidates(self) -> List[PendingMessage]:
        """Get timeout messages that can be retried"""
        expired = self.get_expired()
        return [msg for msg in expired if msg.retries < msg.max_retries]

    def mark_retry(self, message_id: str) -> bool:
        """Mark message as retried"""
        if message_id in self._pending:
            self._pending[message_id].retries += 1
            self._pending[message_id].sent_at = time.time()
            return True
        return False


# =============================================================================
# Export
# =============================================================================

__all__ = [
    # Enumerations
    'CommunicationChannel',
    'CollaborationType',
    'AckStatus',
    # Data classes
    'MessageAck',
    'CollaborationRequest',
    'CollaborationResponse',
    'PendingMessage',
    # Protocols and utilities
    'CommunicationProtocol',
    'CommunicationRouter',
    'PendingMessageTracker',
]
