# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/message_bus.py
Message Bus - Communication channel between Agents

Features:
    - Priority message queue
    - Publish-subscribe pattern
    - Point-to-point communication
    - Broadcast support
    - Message history record
"""

import threading
from queue import PriorityQueue, Empty
from typing import Dict, List, Callable, Optional, Set
from dataclasses import dataclass, field
import time
import logging

from .base import AgentMessage, MessageType

logger = logging.getLogger(__name__)


@dataclass(order=True)
class PrioritizedMessage:
    """
    Prioritized Message Wrapper

    Used for PriorityQueue sorting:
    - priority: Priority (inverted to implement max-heap)
    - timestamp: Timestamp (same priority sorted by time)
    - message: Actual message (not involved in comparison)
    """
    priority: int
    timestamp: float
    message: AgentMessage = field(compare=False)

    @classmethod
    def wrap(cls, message: AgentMessage) -> "PrioritizedMessage":
        """Wrap message"""
        return cls(
            priority=-message.priority,  # Invert to implement max-heap
            timestamp=message.timestamp,
            message=message
        )


class MessageBus:
    """
    Message Bus

    Provides asynchronous communication capabilities between Agents:
    - subscribe/unsubscribe: Subscribe/Unsubscribe
    - publish: Publish messages
    - Automatic message dispatching via background thread

    Usage Example:
        bus = MessageBus()
        bus.start()

        # Subscribe to messages
        bus.subscribe("agent-1", lambda msg: print(msg))

        # Publish a message
        bus.publish(AgentMessage(...))

        bus.stop()
    """

    def __init__(self, max_queue_size: int = 10000, history_size: int = 1000):
        """
        Initialize Message Bus

        Args:
            max_queue_size: Maximum queue size
            history_size: Maximum number of history records
        """
        self._max_queue_size = max_queue_size
        self._history_size = history_size

        # Subscriber management
        self._subscribers: Dict[str, List[Callable[[AgentMessage], None]]] = {}
        self._topic_subscribers: Dict[str, List[Callable[[AgentMessage], None]]] = {}

        # Message queue
        self._message_queue: PriorityQueue = PriorityQueue(maxsize=max_queue_size)

        # Thread safety
        self._lock = threading.RLock()
        self._running = False
        self._dispatch_thread: Optional[threading.Thread] = None

        # Message history
        self._history: List[AgentMessage] = []

        # ACK Tracking - tracks messages requiring confirmation
        self._pending_acks: Dict[str, AgentMessage] = {}  # msg_id -> message
        self._ack_callbacks: Dict[str, Callable] = {}     # msg_id -> callback
        self._ack_timeout = 30.0  # Default ACK timeout

        # Statistics
        self._stats = {
            "messages_published": 0,
            "messages_dispatched": 0,
            "messages_dropped": 0,
            "dispatch_errors": 0,
            "acks_received": 0,
            "acks_timeout": 0,
        }

    def start(self) -> None:
        """Start message dispatching"""
        if self._running:
            logger.warning("MessageBus is already running")
            return

        self._running = True
        self._dispatch_thread = threading.Thread(
            target=self._dispatch_loop,
            name="MessageBus-Dispatch",
            daemon=True
        )
        self._dispatch_thread.start()
        logger.info("MessageBus started")

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop message dispatching

        Args:
            timeout: Timeout duration for waiting for the thread to end
        """
        if not self._running:
            return

        self._running = False

        if self._dispatch_thread and self._dispatch_thread.is_alive():
            self._dispatch_thread.join(timeout=timeout)

        logger.info(f"MessageBus stopped. Stats: {self._stats}")

    def is_running(self) -> bool:
        """Check if running"""
        return self._running

    # =========================================================================
    # Subscription Management
    # =========================================================================

    def subscribe(
        self,
        subscriber_id: str,
        callback: Callable[[AgentMessage], None]
    ) -> None:
        """
        Subscribe to messages

        The subscriber will receive all messages sent to this ID

        Args:
            subscriber_id: Subscriber ID
            callback: Callback function
        """
        with self._lock:
            if subscriber_id not in self._subscribers:
                self._subscribers[subscriber_id] = []
            if callback not in self._subscribers[subscriber_id]:
                self._subscribers[subscriber_id].append(callback)
                logger.debug(f"Subscriber {subscriber_id} added")

    def subscribe_topic(
        self,
        topic: str,
        callback: Callable[[AgentMessage], None]
    ) -> None:
        """
        Subscribe to topic

        Topic subscription is used to receive specific types of broadcast messages

        Args:
            topic: Topic name
            callback: Callback function
        """
        with self._lock:
            if topic not in self._topic_subscribers:
                self._topic_subscribers[topic] = []
            if callback not in self._topic_subscribers[topic]:
                self._topic_subscribers[topic].append(callback)

    def unsubscribe(
        self,
        subscriber_id: str,
        callback: Callable[[AgentMessage], None] = None
    ) -> None:
        """
        Unsubscribe

        Args:
            subscriber_id: Subscriber ID
            callback: Callback function to remove; removes all if None
        """
        with self._lock:
            if subscriber_id in self._subscribers:
                if callback:
                    try:
                        self._subscribers[subscriber_id].remove(callback)
                    except ValueError:
                        pass
                    # If no callbacks left, delete subscriber
                    if not self._subscribers[subscriber_id]:
                        del self._subscribers[subscriber_id]
                else:
                    del self._subscribers[subscriber_id]
                logger.debug(f"Subscriber {subscriber_id} removed")

    def unsubscribe_topic(
        self,
        topic: str,
        callback: Callable[[AgentMessage], None] = None
    ) -> None:
        """
        Unsubscribe from topic

        Args:
            topic: Topic name
            callback: Callback function to remove
        """
        with self._lock:
            if topic in self._topic_subscribers:
                if callback:
                    try:
                        self._topic_subscribers[topic].remove(callback)
                    except ValueError:
                        pass
                else:
                    del self._topic_subscribers[topic]

    def get_subscribers(self) -> Set[str]:
        """Get all subscriber IDs"""
        with self._lock:
            return set(self._subscribers.keys())

    # =========================================================================
    # Message Publishing
    # =========================================================================

    def publish(self, message: AgentMessage) -> bool:
        """
        Publish message

        Args:
            message: Message

        Returns:
            Whether successfully queued
        """
        try:
            prioritized = PrioritizedMessage.wrap(message)
            self._message_queue.put_nowait(prioritized)
            self._stats["messages_published"] += 1
            logger.debug(f"Message {message.msg_id} published from {message.sender}")
            return True
        except Exception as e:
            self._stats["messages_dropped"] += 1
            logger.warning(f"Failed to publish message: {e}")
            return False

    def publish_sync(
        self,
        message: AgentMessage,
        timeout: float = 5.0
    ) -> bool:
        """
        Publish message synchronously (blocks until queued)

        Args:
            message: Message
            timeout: Timeout duration

        Returns:
            Whether successfully queued
        """
        try:
            prioritized = PrioritizedMessage.wrap(message)
            self._message_queue.put(prioritized, timeout=timeout)
            self._stats["messages_published"] += 1
            return True
        except Exception as e:
            self._stats["messages_dropped"] += 1
            logger.warning(f"Failed to publish message (sync): {e}")
            return False

    # =========================================================================
    # Message Dispatching
    # =========================================================================

    def _dispatch_loop(self) -> None:
        """Message dispatch loop"""
        while self._running:
            try:
                # Get message with timeout
                prioritized = self._message_queue.get(timeout=0.1)
                message = prioritized.message

                # Check if message has expired
                if message.is_expired():
                    logger.debug(f"Message {message.msg_id} expired, dropping")
                    continue

                # Record history
                self._add_to_history(message)

                # Dispatch message
                self._dispatch_message(message)

                self._stats["messages_dispatched"] += 1

            except Empty:
                continue
            except Exception as e:
                self._stats["dispatch_errors"] += 1
                logger.error(f"Dispatch error: {e}")

    def _dispatch_message(self, message: AgentMessage) -> None:
        """
        Dispatch a single message

        Args:
            message: Message
        """
        # Dispatch to specific receiver
        if message.receiver:
            self._dispatch_to_subscriber(message.receiver, message)

        # Broadcast message dispatched to everyone (except sender)
        if message.msg_type == MessageType.BROADCAST or message.receiver is None:
            self._dispatch_broadcast(message)

    def _dispatch_to_subscriber(
        self,
        subscriber_id: str,
        message: AgentMessage
    ) -> None:
        """
        Dispatch to specific subscriber

        Args:
            subscriber_id: Subscriber ID
            message: Message
        """
        with self._lock:
            callbacks = self._subscribers.get(subscriber_id, []).copy()

        for callback in callbacks:
            try:
                callback(message)
            except Exception as e:
                logger.error(f"Callback error for {subscriber_id}: {e}")

    def _dispatch_broadcast(self, message: AgentMessage) -> None:
        """
        Broadcast dispatch

        Args:
            message: Message
        """
        with self._lock:
            # Get all subscribers (except sender)
            all_subscribers = {
                sid: cbs.copy()
                for sid, cbs in self._subscribers.items()
                if sid != message.sender
            }

        for subscriber_id, callbacks in all_subscribers.items():
            for callback in callbacks:
                try:
                    callback(message)
                except Exception as e:
                    logger.error(f"Broadcast callback error for {subscriber_id}: {e}")

    # =========================================================================
    # History Records
    # =========================================================================

    def _add_to_history(self, message: AgentMessage) -> None:
        """Add to history record"""
        with self._lock:
            self._history.append(message)
            if len(self._history) > self._history_size:
                self._history = self._history[-self._history_size:]

    def get_history(
        self,
        limit: int = 100,
        msg_type: MessageType = None,
        sender: str = None
    ) -> List[AgentMessage]:
        """
        Get message history

        Args:
            limit: Maximum quantity
            msg_type: Filter message type
            sender: Filter sender

        Returns:
            Message list
        """
        with self._lock:
            history = self._history.copy()

        # Filter
        if msg_type:
            history = [m for m in history if m.msg_type == msg_type]
        if sender:
            history = [m for m in history if m.sender == sender]

        return history[-limit:]

    def clear_history(self) -> None:
        """Clear history records"""
        with self._lock:
            self._history.clear()

    # =========================================================================
    # Statistics and Monitoring
    # =========================================================================

    def get_stats(self) -> Dict:
        """Get statistics information"""
        return {
            **self._stats,
            "queue_size": self._message_queue.qsize(),
            "subscribers_count": len(self._subscribers),
            "history_size": len(self._history),
        }

    def get_queue_size(self) -> int:
        """Get current queue size"""
        return self._message_queue.qsize()

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    def broadcast(
        self,
        sender: str,
        payload: Dict,
        priority: int = 5
    ) -> bool:
        """
        Convenience broadcast method

        Args:
            sender: Sender ID
            payload: Message content
            priority: Priority

        Returns:
            Whether successful
        """
        msg = AgentMessage.create(
            msg_type=MessageType.BROADCAST,
            sender=sender,
            payload=payload,
            priority=priority
        )
        return self.publish(msg)

    def send_task(
        self,
        sender: str,
        receiver: str,
        task_type: str,
        parameters: Dict,
        priority: int = 5
    ) -> bool:
        """
        Convenience method for sending tasks

        Args:
            sender: Sender ID
            receiver: Receiver ID
            task_type: Task type
            parameters: Task parameters
            priority: Priority

        Returns:
            Whether successful
        """
        msg = AgentMessage.create(
            msg_type=MessageType.TASK,
            sender=sender,
            receiver=receiver,
            payload={
                "task_type": task_type,
                "parameters": parameters,
                "priority": priority
            },
            priority=priority
        )
        return self.publish(msg)

    # =========================================================================
    # ACK Message Confirmation
    # =========================================================================

    def publish_with_ack(
        self,
        message: AgentMessage,
        callback: Optional[Callable[[str, bool], None]] = None,
        timeout: float = None
    ) -> bool:
        """
        Publish message that requires confirmation

        Args:
            message: Message (requires_ack should be True)
            callback: ACK callback function (msg_id, success)
            timeout: ACK timeout duration

        Returns:
            Whether successfully queued
        """
        # Ensure requires_ack is set
        message.requires_ack = True

        with self._lock:
            self._pending_acks[message.msg_id] = message
            if callback:
                self._ack_callbacks[message.msg_id] = callback

        return self.publish(message)

    def send_ack(
        self,
        original_msg_id: str,
        sender: str,
        receiver: str,
        success: bool = True,
        error: Optional[str] = None
    ) -> bool:
        """
        Send ACK confirmation message

        Args:
            original_msg_id: Original message ID
            sender: ACK sender
            receiver: ACK receiver (original message sender)
            success: Whether successfully processed
            error: Error result

        Returns:
            Whether successfully sent
        """
        ack_msg = AgentMessage.create(
            msg_type=MessageType.ACK,
            sender=sender,
            receiver=receiver,
            payload={
                "original_msg_id": original_msg_id,
                "success": success,
                "error": error
            },
            priority=9  # ACK High priority
        )
        return self.publish(ack_msg)

    def handle_ack(self, message: AgentMessage) -> None:
        """
        Handle received ACK message

        Args:
            message: ACK message
        """
        original_msg_id = message.payload.get("original_msg_id")
        success = message.payload.get("success", True)

        if not original_msg_id:
            logger.warning(f"ACK message missing original_msg_id: {message.msg_id}")
            return

        with self._lock:
            # Remove message pending confirmation
            if original_msg_id in self._pending_acks:
                del self._pending_acks[original_msg_id]
                self._stats["acks_received"] += 1

            # Invoke callback
            callback = self._ack_callbacks.pop(original_msg_id, None)

        if callback:
            try:
                callback(original_msg_id, success)
            except Exception as e:
                logger.error(f"ACK callback error: {e}")

    def check_ack_timeouts(self) -> List[str]:
        """
        Check for ACK timeouts

        Returns:
            List of timed-out message IDs
        """
        import time
        now = time.time()
        timed_out = []

        with self._lock:
            for msg_id, message in list(self._pending_acks.items()):
                if now - message.timestamp > self._ack_timeout:
                    timed_out.append(msg_id)
                    del self._pending_acks[msg_id]
                    self._stats["acks_timeout"] += 1

                    # Invoke timeout callback
                    callback = self._ack_callbacks.pop(msg_id, None)
                    if callback:
                        try:
                            callback(msg_id, False)
                        except Exception as e:
                            logger.error(f"ACK timeout callback error: {e}")

        return timed_out

    def get_pending_acks(self) -> List[str]:
        """Get list of message IDs pending confirmation"""
        with self._lock:
            return list(self._pending_acks.keys())
