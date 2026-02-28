# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/__init__.py
ReAct + Agent Network Framework

Architecture:
    AgentRegistry (Service Discovery)
        └── NetworkAgent (Networked Agent Base Class)
            ├── AnalyzerAgent (Analysis)
            ├── VerifierAgent (Verification)
            ├── ExploiterAgent (Exploitation)
            ├── ValidatorAgent (Validation)
            └── CriticAgent (QA/Criticism)
    MessageBus (P2P Communication)
    SharedState (Distributed State)
"""

from .base import (
    # Enum types
    AgentCapability,
    MessageType,
    TaskStatus,
    # Data classes
    AgentMessage,
    TaskAssignment,
    AgentResult,
    # Base classes
    BaseAgent,
)

from .message_bus import MessageBus

from .shared_state import (
    Finding,
    AnalysisContext,
    SharedState,
)

from .llm_backend import (
    LLMResponse,
    LLMBackend,
    BackendType,
    GeminiBackend,
    OpenAIBackend,
    OllamaBackend,
    AnthropicBackend,
    create_backend,
    create_backend_from_config,
)

from .llm_pool import (
    LLMClientPool,
    PooledClient,
    PoolStats,
    create_pool_from_config,
)

# v2: NetworkAgent Architecture
try:
    from .network_agent import (
        NetworkAgent,
        NetworkMessageType,
        ReActActionType,
        ReActAction,
        ReActState,
        TaskNegotiation,
    )
    from .registry import (
        AgentRegistry,
        AgentInfo,
    )
    HAVE_NETWORK_AGENT = True
except ImportError as e:
    print(f"[!] Warning: Failed to import NetworkAgent: {e}")
    NetworkAgent = None
    AgentRegistry = None
    HAVE_NETWORK_AGENT = False

# Concrete Agent Implementations
try:
    from .analyzer_agent import AnalyzerAgent
    from .exploiter import ExploiterAgent
    from .critic import CriticAgent
    from .validation import ValidationAgent
except BaseException as e:
    print(f"[!] Warning: Failed to import agents: {e}")
    AnalyzerAgent = None
    ExploiterAgent = None
    CriticAgent = None
    ValidationAgent = None

# Network Runner
from .network_runner import (
    NetworkRunner,
    NetworkConfig,
    create_network_runner,
)

# Availability check
HAVE_MULTI_AGENT = True

__all__ = [
    # Enumerations
    "AgentCapability",
    "MessageType",
    "TaskStatus",
    "NetworkMessageType",
    "ReActActionType",
    # Data Classes
    "AgentMessage",
    "TaskAssignment",
    "AgentResult",
    "Finding",
    "AnalysisContext",
    "ReActAction",
    "ReActState",
    "TaskNegotiation",
    "AgentInfo",
    "NetworkConfig",
    # Core Classes
    "BaseAgent",
    "NetworkAgent",
    "MessageBus",
    "SharedState",
    "AgentRegistry",
    "NetworkRunner",
    # LLM Backends
    "BackendType",
    "LLMResponse",
    "LLMBackend",
    "GeminiBackend",
    "OpenAIBackend",
    "OllamaBackend",
    "AnthropicBackend",
    "create_backend",
    "create_backend_from_config",
    # LLM Client Pool
    "LLMClientPool",
    "PooledClient",
    "PoolStats",
    "create_pool_from_config",
    # Concrete Agents
    "AnalyzerAgent",
    "ExploiterAgent",
    "CriticAgent",
    "ValidationAgent",
    # Factory Functions
    "create_network_runner",
    # Flags
    "HAVE_MULTI_AGENT",
    "HAVE_NETWORK_AGENT",
]
