# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/llm_pool.py
LLM Client Pool - Manages multiple LLM client instances and supports parallel calls

Features:
    - Client reuse
    - Connection pool management
    - Automatic retries
    - Rate limit handling
"""

import threading
from queue import Queue, Empty
from typing import Optional, List, Dict, Any, TYPE_CHECKING
from dataclasses import dataclass
import time
import logging

from .llm_backend import (
    LLMBackend,
    LLMResponse,
    BackendType,
    create_backend,
    create_backend_from_config
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class PoolStats:
    """Pool statistical information"""
    total_clients: int = 0
    available_clients: int = 0
    borrowed_clients: int = 0
    total_requests: int = 0
    total_errors: int = 0
    total_retries: int = 0
    avg_latency: float = 0.0


class LLMClientPool:
    """
    LLM Client Pool

    Manages multiple LLM backend instances and supports parallel Agent calls.

    Features:
    - Client reuse, reducing initialization overhead
    - Automatic expansion and contraction
    - Rate limit handling and retries
    - Statistical monitoring

    Usage example:
        pool = LLMClientPool.from_config(config, pool_size=3)

        # Get client
        with pool.acquire() as client:
            response = client.generate("Hello")

        # Or manual management
        client = pool.borrow()
        try:
            response = client.generate("Hello")
        finally:
            pool.return_client(client)
    """

    def __init__(
        self,
        backend_type: BackendType,
        pool_size: int = 3,
        max_retries: int = 3,
        retry_delay: float = 30.0,
        **backend_kwargs
    ):
        """
        Initialize client pool

        Args:
            backend_type: LLM backend type
            pool_size: Pool size
            max_retries: Maximum number of retries
            retry_delay: Retry delay (seconds)
            **backend_kwargs: Backend initialization parameters
        """
        self._backend_type = backend_type
        self._pool_size = pool_size
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._backend_kwargs = backend_kwargs

        # Client pool
        self._pool: Queue[LLMBackend] = Queue(maxsize=pool_size)
        self._all_clients: List[LLMBackend] = []
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            "total_requests": 0,
            "total_errors": 0,
            "total_retries": 0,
            "total_latency": 0.0,
        }

        # Initialize client
        self._initialize_pool()

    def _initialize_pool(self) -> None:
        """Initialize client pool"""
        logger.info(f"Initializing LLM pool with {self._pool_size} clients ({self._backend_type.value})")

        for i in range(self._pool_size):
            client = create_backend(self._backend_type, **self._backend_kwargs)
            if client and client.is_available():
                self._pool.put(client)
                self._all_clients.append(client)
                logger.debug(f"Client {i+1}/{self._pool_size} initialized")
            else:
                logger.warning(f"Failed to initialize client {i+1}/{self._pool_size}")

        actual_size = self._pool.qsize()
        if actual_size == 0:
            logger.error("No clients available in pool!")
        else:
            logger.info(f"LLM pool initialized with {actual_size} clients")

    @classmethod
    def from_config(cls, config: Any, pool_size: int = None) -> "LLMClientPool":
        """
        Create client pool from configuration

        Args:
            config: LuoDllHackConfig configuration object
            pool_size: Pool size (optional, default read from configuration)

        Returns:
            Client pool instance
        """
        backend_type = BackendType(getattr(config, "ai_backend", "gemini"))
        pool_size = pool_size or getattr(config, "ai_agent_pool_size", 3)

        # Get configuration based on backend type
        kwargs = {
            "model": getattr(config, "ai_model", "gemini-2.5-flash"),
            "temperature": getattr(config, "ai_temperature", 0.1),
            "max_tokens": getattr(config, "ai_max_tokens", 8192),
        }

        if backend_type == BackendType.GEMINI:
            kwargs["api_key"] = getattr(config, "ai_api_key", "") or ""

        elif backend_type == BackendType.OPENAI:
            kwargs["api_key"] = getattr(config, "ai_openai_api_key", "") or ""
            kwargs["model"] = getattr(config, "ai_openai_model", "gpt-4")
            base_url = getattr(config, "ai_openai_base_url", None)
            if base_url:
                kwargs["base_url"] = base_url

        elif backend_type == BackendType.OLLAMA:
            kwargs["model"] = getattr(config, "ai_ollama_model", "llama3")
            kwargs["base_url"] = getattr(config, "ai_ollama_base_url", "http://localhost:11434")
            # Ollama does not require api_key
            kwargs.pop("api_key", None)

        elif backend_type == BackendType.ANTHROPIC:
            kwargs["api_key"] = getattr(config, "ai_anthropic_api_key", "") or ""
            kwargs["model"] = getattr(config, "ai_anthropic_model", "claude-3-opus-20240229")

        return cls(backend_type, pool_size, **kwargs)

    # =========================================================================
    # Client Acquisition and Return
    # =========================================================================

    def borrow(self, timeout: float = 30.0) -> Optional[LLMBackend]:
        """
        Borrow a client

        Args:
            timeout: Waiting timeout (seconds)

        Returns:
            LLM client, or None if timeout occurs
        """
        try:
            client = self._pool.get(timeout=timeout)
            logger.debug(f"Client borrowed, {self._pool.qsize()} remaining")
            return client
        except Empty:
            logger.warning("No client available in pool")
            return None

    def return_client(self, client: LLMBackend) -> None:
        """
        Return a client

        Args:
            client: LLM client
        """
        if client in self._all_clients:
            try:
                self._pool.put_nowait(client)
                logger.debug(f"Client returned, {self._pool.qsize()} available")
            except Exception:
                pass  # Pool is full, ignore

    def acquire(self, timeout: float = 30.0) -> "PooledClient":
        """
        Acquire a pooled client (context manager)

        Args:
            timeout: Waiting timeout

        Returns:
            PooledClient context manager
        """
        return PooledClient(self, timeout)

    # =========================================================================
    # Convenience Methods (with auto-retry)
    # =========================================================================

    def generate(
        self,
        prompt: str,
        tools: List[Dict] = None,
        system_prompt: str = None,
        timeout: float = 30.0
    ) -> LLMResponse:
        """
        Generate response (with auto-retry and client rotation)

        Args:
            prompt: User prompt
            tools: Tool definitions
            system_prompt: System prompt
            timeout: Client acquisition timeout

        Returns:
            LLM response
        """
        return self._execute_with_client_rotation(
            lambda client: client.generate(prompt, tools, system_prompt),
            timeout
        )

    def chat(
        self,
        messages: List,
        tools: List[Dict] = None,
        timeout: float = 30.0
    ) -> LLMResponse:
        """
        Multi-turn dialogue (with auto-retry and client rotation)

        Args:
            messages: Message history
            tools: Tool definitions
            timeout: Client acquisition timeout

        Returns:
            LLM response
        """
        return self._execute_with_client_rotation(
            lambda client: client.chat(messages, tools),
            timeout
        )

    def _execute_with_client_rotation(
        self,
        func,
        timeout: float = 30.0
    ) -> LLMResponse:
        """
        Retry execution with client rotation

        Key improvement: Return the current client and borrow a new client for retry when a connection error occurs.
        Avoid continuous retry on a bad connection.
        """
        self._stats["total_requests"] += 1

        # Retryable error types
        retryable_errors = [
            "429", "rate", "quota",  # Rate limit
            "connection", "timeout", "connect",  # Connection problem
            "network", "unreachable",  # Network problem
            "temporarily", "unavailable",  # Temporarily unavailable
        ]

        # Connection related errors (need to change client)
        connection_errors = ["connection", "timeout", "connect", "network", "unreachable"]

        last_error = None
        current_client = None

        for attempt in range(self._max_retries):
            # Borrow a new client on each retry (on connection error) or reuse current client (on other errors)
            if current_client is None:
                current_client = self.borrow(timeout)
                if not current_client:
                    return LLMResponse(error="No client available")

            try:
                start_time = time.time()
                response = func(current_client)
                self._stats["total_latency"] += time.time() - start_time

                if response.is_error:
                    error_str = response.error.lower()
                    is_retryable = any(e in error_str for e in retryable_errors)
                    is_connection_error = any(e in error_str for e in connection_errors)

                    if is_retryable and attempt < self._max_retries - 1:
                        self._stats["total_retries"] += 1

                        # Connection error: return current client, borrow new one next loop
                        if is_connection_error:
                            self.return_client(current_client)
                            current_client = None
                            wait_time = min(5.0 * (attempt + 1), 15.0)
                            logger.warning(f"Connection error: {response.error}, rotating client and retrying in {wait_time}s (attempt {attempt+1}/{self._max_retries})")
                        else:
                            # Non-connection error (e.g., rate limit): keep current client
                            wait_time = self._retry_delay * (attempt + 1)
                            logger.warning(f"Retryable error: {response.error}, retrying in {wait_time}s (attempt {attempt+1}/{self._max_retries})")

                        time.sleep(wait_time)
                        last_error = response.error
                        continue

                # Success or non-retryable error, return client and return response
                self.return_client(current_client)
                return response

            except Exception as e:
                self._stats["total_errors"] += 1
                error_str = str(e).lower()
                is_retryable = any(err in error_str for err in retryable_errors)
                is_connection_error = any(err in error_str for err in connection_errors)

                if is_retryable and attempt < self._max_retries - 1:
                    self._stats["total_retries"] += 1

                    # Connection error: Return current client, borrow a new one next loop
                    if is_connection_error:
                        self.return_client(current_client)
                        current_client = None
                        wait_time = min(5.0 * (attempt + 1), 15.0)
                        logger.warning(f"Connection exception: {e}, rotating client and retrying in {wait_time}s (attempt {attempt+1}/{self._max_retries})")
                    else:
                        wait_time = self._retry_delay * (attempt + 1)
                        logger.warning(f"Retryable exception: {e}, retrying in {wait_time}s (attempt {attempt+1}/{self._max_retries})")

                    time.sleep(wait_time)
                    last_error = str(e)
                else:
                    # Non-retryable error
                    if current_client:
                        self.return_client(current_client)
                    logger.error(f"LLM call failed: {e}")
                    return LLMResponse(error=str(e))

        # All retries failed
        if current_client:
            self.return_client(current_client)
        return LLMResponse(error=f"Max retries ({self._max_retries}) exceeded. Last error: {last_error}")

    # =========================================================================
    # Statistics and Management
    # =========================================================================

    def get_stats(self) -> PoolStats:
        """Get pool statistics"""
        with self._lock:
            total = len(self._all_clients)
            available = self._pool.qsize()
            avg_latency = 0.0
            if self._stats["total_requests"] > 0:
                avg_latency = self._stats["total_latency"] / self._stats["total_requests"]

            return PoolStats(
                total_clients=total,
                available_clients=available,
                borrowed_clients=total - available,
                total_requests=self._stats["total_requests"],
                total_errors=self._stats["total_errors"],
                total_retries=self._stats["total_retries"],
                avg_latency=avg_latency
            )

    def available_count(self) -> int:
        """Get number of available clients"""
        return self._pool.qsize()

    def is_available(self) -> bool:
        """Check if any client is available"""
        return self._pool.qsize() > 0

    def resize(self, new_size: int) -> None:
        """
        Adjust pool size

        Args:
            new_size: New pool size
        """
        with self._lock:
            current_size = len(self._all_clients)

            if new_size > current_size:
                # Expansion
                for i in range(new_size - current_size):
                    client = create_backend(self._backend_type, **self._backend_kwargs)
                    if client and client.is_available():
                        self._pool.put(client)
                        self._all_clients.append(client)
                logger.info(f"Pool expanded from {current_size} to {len(self._all_clients)}")

            elif new_size < current_size:
                # Contraction (remove idle ones only)
                removed = 0
                while self._pool.qsize() > new_size and removed < (current_size - new_size):
                    try:
                        client = self._pool.get_nowait()
                        self._all_clients.remove(client)
                        removed += 1
                    except Empty:
                        break
                logger.info(f"Pool shrunk from {current_size} to {len(self._all_clients)}")

            self._pool_size = new_size

    def shutdown(self) -> None:
        """Shut down the pool"""
        with self._lock:
            # Empty the queue
            while not self._pool.empty():
                try:
                    self._pool.get_nowait()
                except Empty:
                    break

            self._all_clients.clear()
            logger.info("LLM pool shutdown")


class PooledClient:
    """
    Pooled client context manager

    Automatically manages the borrowing and returning of clients.

    Usage example:
        with pool.acquire() as client:
            if client:
                response = client.generate("Hello")
    """

    def __init__(self, pool: LLMClientPool, timeout: float = 30.0):
        self._pool = pool
        self._timeout = timeout
        self._client: Optional[LLMBackend] = None

    def __enter__(self) -> Optional[LLMBackend]:
        self._client = self._pool.borrow(self._timeout)
        return self._client

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            self._pool.return_client(self._client)
        return False


# =============================================================================
# Convenience Factory Function
# =============================================================================

def create_pool_from_config(config: Any) -> Optional[LLMClientPool]:
    """
    Create LLM client pool from configuration

    Args:
        config: LuoDllHackConfig configuration object

    Returns:
        LLMClientPool instance, or None if failed
    """
    try:
        return LLMClientPool.from_config(config)
    except Exception as e:
        logger.error(f"Failed to create LLM pool: {e}")
        return None
