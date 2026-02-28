# -*- coding: utf-8 -*-
"""
luodllhack/ai/compat.py
Dependency Compatibility Check Module

Centralized management of detection and import of all optional dependencies to avoid redundant conditional imports across modules.
"""

from dataclasses import dataclass, field
from typing import Optional, Any, Dict, Type
import importlib


@dataclass
class DependencyStatus:
    """Dependency status detection result"""

    # LLM Backend
    genai: bool = False              # google.generativeai
    multi_backend: bool = False      # luodllhack.ai.agents.llm_backend

    # Core Analysis Modules
    vuln_analysis: bool = False      # luodllhack.analysis.taint
    capstone: bool = False           # capstone disassembly

    # Enhanced Analysis Modules
    bounds_checker: bool = False     # luodllhack.analysis.enhanced.bounds_checker
    lifecycle: bool = False          # luodllhack.memory.lifecycle
    symbolic: bool = False           # luodllhack.symbolic.executor
    signature: bool = False          # luodllhack.analysis.signature_extractor

    # Core Tools
    core_utils: bool = False         # luodllhack.core.utils
    config: bool = False             # luodllhack.core.config
    prompts: bool = False            # luodllhack.ai.prompts

    # Multi-Agent Framework
    multi_agent: bool = False        # luodllhack.ai.agents

    # Exploit Module
    exploit: bool = False            # luodllhack.exploit

    # Cached imported modules
    _modules: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def detect(cls) -> 'DependencyStatus':
        """Detect availability of all dependencies"""
        status = cls()

        # LLM Backend
        status.genai = cls._try_import('google.generativeai')
        status.multi_backend = cls._try_import('luodllhack.ai.agents.llm_backend')

        # Core Analysis Modules
        status.vuln_analysis = cls._try_import('luodllhack.analysis.taint')
        status.capstone = cls._try_import('capstone')

        # Enhanced Analysis Modules
        status.bounds_checker = cls._try_import('luodllhack.analysis.enhanced.bounds_checker')
        status.lifecycle = cls._try_import('luodllhack.memory.lifecycle')
        status.symbolic = cls._try_import('luodllhack.symbolic.executor')
        status.signature = cls._try_import('luodllhack.analysis.signature_extractor')

        # Core Tools
        status.core_utils = cls._try_import('luodllhack.core.utils')
        status.config = cls._try_import('luodllhack.core.config')
        status.prompts = cls._try_import('luodllhack.ai.prompts')

        # Multi-Agent Framework
        status.multi_agent = cls._try_import('luodllhack.ai.agents')

        # Exploit Module
        status.exploit = cls._try_import('luodllhack.exploit')

        return status

    @staticmethod
    def _try_import(module_name: str) -> bool:
        """Attempt to import module"""
        try:
            importlib.import_module(module_name)
            return True
        except ImportError:
            return False

    def get_module(self, module_name: str) -> Optional[Any]:
        """Get imported module (with caching)"""
        if module_name in self._modules:
            return self._modules[module_name]

        try:
            module = importlib.import_module(module_name)
            self._modules[module_name] = module
            return module
        except ImportError:
            return None

    @property
    def ai_agent_ready(self) -> bool:
        """Check if AI Agent is available"""
        return (self.genai or self.multi_backend) and self.vuln_analysis


# Global singleton - detected during module load
DEPS = DependencyStatus.detect()


# =============================================================================
# Convenience Import Functions
# =============================================================================

def get_genai():
    """Get google.generativeai module"""
    if DEPS.genai:
        return DEPS.get_module('google.generativeai')
    return None


def get_taint_engine():
    """Get TaintEngine class"""
    if DEPS.vuln_analysis:
        module = DEPS.get_module('luodllhack.analysis.taint')
        if module:
            return getattr(module, 'TaintEngine', None)
    return None


def get_capstone():
    """Get capstone module"""
    if DEPS.capstone:
        return DEPS.get_module('capstone')
    return None


def get_config():
    """Get configuration module"""
    if DEPS.config:
        module = DEPS.get_module('luodllhack.core.config')
        if module:
            return getattr(module, 'default_config', None), getattr(module, 'LuoDllHackConfig', None)
    return None, None


def get_llm_backend_factory():
    """Get LLM backend factory function"""
    if DEPS.multi_backend:
        module = DEPS.get_module('luodllhack.ai.agents.llm_backend')
        if module:
            return getattr(module, 'create_backend_from_config', None)
    return None


def get_multi_agent_components():
    """Get Agent Network framework components (v5.2)"""
    if DEPS.multi_agent:
        module = DEPS.get_module('luodllhack.ai.agents')
        if module:
            return {
                'NetworkRunner': getattr(module, 'NetworkRunner', None),
                'NetworkConfig': getattr(module, 'NetworkConfig', None),
                'SharedState': getattr(module, 'SharedState', None),
                'MessageBus': getattr(module, 'MessageBus', None),
                'AgentRegistry': getattr(module, 'AgentRegistry', None),
                'AnalyzerAgent': getattr(module, 'AnalyzerAgent', None),
                'ExploiterAgent': getattr(module, 'ExploiterAgent', None),
                'CriticAgent': getattr(module, 'CriticAgent', None),
                'ValidationAgent': getattr(module, 'ValidationAgent', None),
            }
    return {}


# =============================================================================
# Fallback Implementations
# =============================================================================

def parse_address(addr_input) -> int:
    """
    Parse address (with fallback implementation)

    Preferentially use luodllhack.core.utils.parse_address,
    if unavailable then use the local implementation.
    """
    if DEPS.core_utils:
        module = DEPS.get_module('luodllhack.core.utils')
        if module and hasattr(module, 'parse_address'):
            return module.parse_address(addr_input)

    # Fallback implementation
    if isinstance(addr_input, str):
        addr_str = addr_input.strip()
        if addr_str.lower().startswith("0x"):
            return int(addr_str, 16)
        return int(addr_str)
    return int(addr_input)


def safe_parse_address(addr_input) -> tuple:
    """
    Safely parse address, returns (address_int, error_message)

    Returns:
        (int, None) - Success
        (None, str) - Failure, return error message
    """
    if addr_input is None:
        return None, "Address is None"

    # Handle potential dictionary input (AI may pass it)
    if isinstance(addr_input, dict):
        addr_input = addr_input.get('address', addr_input.get('value', str(addr_input)))

    try:
        addr = parse_address(addr_input)
        if not isinstance(addr, int):
            return None, f"Invalid address type: {type(addr)}"
        return addr, None
    except (ValueError, TypeError) as e:
        return None, f"Failed to parse address '{addr_input}': {e}"


# =============================================================================
# Backward Compatible Flag Variables
# =============================================================================

# These variables remain for backward compatibility, but DEPS.xxx is recommended
HAVE_GENAI = DEPS.genai
HAVE_MULTI_BACKEND = DEPS.multi_backend
HAVE_VULN_ANALYSIS = DEPS.vuln_analysis
HAVE_CAPSTONE = DEPS.capstone
HAVE_BOUNDS_CHECKER = DEPS.bounds_checker
HAVE_LIFECYCLE = DEPS.lifecycle
HAVE_SYMBOLIC = DEPS.symbolic
HAVE_SIGNATURE = DEPS.signature
HAVE_CORE_UTILS = DEPS.core_utils
HAVE_CONFIG = DEPS.config
HAVE_PROMPTS = DEPS.prompts
HAVE_MULTI_AGENT = DEPS.multi_agent
HAVE_EXPLOIT = DEPS.exploit
HAVE_AI_AGENT = DEPS.ai_agent_ready
